//! Red del operador: busqueda en el relay, handshake SPAKE2, canal de control cifrado y video.
//!
//! Corre en un runtime de tokio propio. Todos los pasos tienen plazo: conexion y busqueda
//! en el relay, respuesta al hello y veredicto del host. La espera de la aprobacion local no tiene
//! plazo aqui: la acota la cuenta regresiva de la UI (`PendingApproval`).
//!
//! Modo desatendido (`host_key` presente): el handshake es el del canal E2E desatendido
//! (`OperatorUnattendedHandshake`): hello y respuesta en claro, firma verificada con la clave fijada
//! del servicio, contrasena en el registro n.o 0 y veredicto generico en el registro n.o 0 de vuelta.
//! No hay `PendingApproval` ni `ApprovalResult`: tras `Granted` la sesion sigue igual, pero los
//! monitores llegan en el primer `DisplayTopologyChanged` y el video y la entrada solo empiezan
//! a partir de ahi.
//!
//! Stream 0 (bidireccional): control y entrada en registros `SecureChannel`, con `Ping` cada
//! segundo tras la aprobacion (heartbeat del host y RTT). La entrada solo se envia despues de
//! `ApprovalResult { granted: true }`. Video: los streams unidireccionales se aceptan solo tras la
//! aprobacion; cada registro se abre con `VideoStreamOpener` y se entrega a un `VideoSink`.
//! Cualquier error de video o de canal cierra la sesion.
//!
//! Solo depende de `awawa-protocol`, `awawa-relay` y `tokio` (la prueba E2E del relay incluye
//! este archivo por ruta con un sumidero de video simulado).

use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::unattended_channel::VerifyingKey;
use awawa_protocol::{
    ClientToHostMessage, DisconnectReason, HandshakeError, HostAuthReply, HostToClientMessage,
    MAX_CTRL_FRAME, MonitorDescriptor, OperatorConnectionRequest, OperatorHandshake,
    OperatorSession, OperatorUnattendedHandshake, PakeHelloReply, RemoteInputCommand,
    SecureChannel, UnattendedChannelError, UnattendedHelloReply, VIDEO_RECORD_PREFIX_LEN,
    VIDEO_STREAM_PREAMBLE_LEN, VideoOpener, VideoPacketHeader, decode_message, encode_message,
};
use awawa_relay::{ClientError, RelayClient, RelayError, RelayPin, RelayedSender, VideoStreams};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Plazo para conectar con el relay y emparejar.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Plazo de cada respuesta del host durante el handshake.
pub const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// Periodo del `Ping` (el host corta la entrada tras 3 s sin `Ping`).
pub const PING_INTERVAL: Duration = Duration::from_secs(1);
/// Texto plano maximo por registro de control (cabecera 8 + etiqueta 16 dentro de la trama).
pub const MAX_CONTROL_PLAINTEXT: usize = MAX_CTRL_FRAME - 24;

/// Eventos hacia la UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    AwaitingApproval {
        timeout_secs: u16,
        sas: String,
    },
    Approved {
        monitors: Vec<MonitorDescriptor>,
    },
    /// Modo desatendido: el servicio concedio el acceso. Huella de la sesion para comparar.
    UnattendedGranted {
        fingerprint: [u8; 8],
    },
    Rejected {
        reason: String,
    },
    TopologyChanged {
        monitors: Vec<MonitorDescriptor>,
    },
    Rtt(Duration),
    /// El host suspendio video y entrada (escritorio seguro/UAC/bloqueo).
    LocalApprovalRequired,
    /// El host reanudo.
    LocalApprovalCleared,
    Disconnected {
        reason: String,
    },
}

/// Destino del video ya descifrado (decodificacion y composicion).
pub trait VideoSink: Send {
    /// Monitores negociados (aprobacion o cambio de topologia). `Err` cierra la sesion.
    fn set_monitors(&mut self, monitors: &[MonitorDescriptor]) -> Result<(), String>;
    /// Un paquete autenticado. `Err` (payload invalido o fuera de tope) cierra la sesion.
    fn packet(&mut self, header: &VideoPacketHeader, payload: &[u8]) -> Result<(), String>;
}

/// Datos de conexion ya validados por el formulario.
pub struct OperatorNetConfig {
    pub relay_addr: SocketAddr,
    pub pin: RelayPin,
    pub request: OperatorConnectionRequest,
    /// Clave Ed25519 fijada del servicio: con ella el acceso es desatendido (`request` aporta el
    /// ID y el nombre); sin ella, el flujo bajo demanda.
    pub host_key: Option<VerifyingKey>,
    /// Contrasena tecleada; quien la entrega decide como se borra al soltarla (`Zeroizing`).
    pub password: Box<dyn std::ops::Deref<Target = String> + Send>,
    pub sink: Box<dyn VideoSink>,
    /// Despierta la UI cuando hay eventos.
    pub wake: Arc<dyn Fn() + Send + Sync>,
}

enum Command {
    Input(RemoteInputCommand),
    Disconnect,
}

/// Sesion de red del operador. Al soltarla se cierra la conexion.
pub struct OperatorNet {
    events: std_mpsc::Receiver<NetEvent>,
    commands: mpsc::UnboundedSender<Command>,
    runtime: Option<Runtime>,
}

type SharedSink = Arc<Mutex<Box<dyn VideoSink>>>;

struct Emitter {
    events: std_mpsc::Sender<NetEvent>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Emitter {
    fn emit(&self, event: NetEvent) {
        let _ = self.events.send(event);
        (self.wake)();
    }
}

impl OperatorNet {
    pub fn start(config: OperatorNetConfig) -> Self {
        let (events_tx, events) = std_mpsc::channel();
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let emitter = Emitter {
            events: events_tx,
            wake: config.wake.clone(),
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("operator-net")
            .build();
        let runtime = match runtime {
            Ok(runtime) => {
                runtime.spawn(async move {
                    let reason = run(config, commands_rx, &emitter).await;
                    if let Some(reason) = reason {
                        emitter.emit(NetEvent::Disconnected { reason });
                    }
                });
                Some(runtime)
            }
            Err(e) => {
                emitter.emit(NetEvent::Disconnected {
                    reason: format!("no se pudo iniciar la red: {e}"),
                });
                None
            }
        };
        Self {
            events,
            commands,
            runtime,
        }
    }

    /// Sesion que no pudo arrancar: solo informa el motivo.
    pub fn failed(reason: String) -> Self {
        let (events_tx, events) = std_mpsc::channel();
        let (commands, _) = mpsc::unbounded_channel();
        let _ = events_tx.send(NetEvent::Disconnected { reason });
        Self {
            events,
            commands,
            runtime: None,
        }
    }

    pub fn send_input(&self, command: RemoteInputCommand) {
        let _ = self.commands.send(Command::Input(command));
    }

    pub fn disconnect(&self) {
        let _ = self.commands.send(Command::Disconnect);
    }

    pub fn poll_event(&self) -> Option<NetEvent> {
        self.events.try_recv().ok()
    }
}

impl Drop for OperatorNet {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Disconnect);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

fn relay_error_text(e: &ClientError) -> String {
    match e {
        ClientError::Relay(RelayError::NotFound) => {
            "El ID no existe o no esta disponible en el relay.".to_string()
        }
        ClientError::Relay(RelayError::RateLimited) => {
            "Demasiados intentos desde este equipo; espere un minuto.".to_string()
        }
        ClientError::Timeout => "El relay no respondio a tiempo.".to_string(),
        other => format!("No se pudo conectar con el relay: {other}"),
    }
}

/// Recibe la siguiente trama del handshake, con plazo.
async fn recv_step(stream: &mut awawa_relay::RelayedStream) -> Result<Vec<u8>, String> {
    match timeout(HANDSHAKE_STEP_TIMEOUT, stream.recv_frame()).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err("El cliente cerro la conexion.".to_string()),
        Err(_) => Err("El cliente no respondio a tiempo.".to_string()),
    }
}

const INVALID_REPLY: &str = "Respuesta invalida del cliente.";

/// Copia la contrasena a un buffer que se borra al soltarlo. Este archivo no depende de `zeroize`
/// (lo incluye por ruta la prueba E2E): el tipo `Zeroizing<String>` lo fija `send_password`.
fn wiped<T: Default + std::ops::DerefMut<Target = String>>(src: &str) -> T {
    let mut out = T::default();
    out.reserve_exact(src.len());
    out.push_str(src);
    out
}

/// Handshake del canal E2E desatendido contra la clave fijada. La contrasena viaja sin normalizar
/// y solo dentro del registro cifrado; todos los fallos son genericos.
async fn unattended_handshake(
    stream: &mut awawa_relay::RelayedStream,
    request: &OperatorConnectionRequest,
    password: Box<dyn std::ops::Deref<Target = String> + Send>,
    key: &VerifyingKey,
) -> Result<awawa_protocol::OperatorUnattendedSession, String> {
    const PREPARE: &str = "No se pudo preparar la solicitud.";
    let (handshake, hello) = OperatorUnattendedHandshake::start(
        request.target_session_id.raw_u32(),
        &request.operator_display_name,
        key,
    )
    .map_err(|_| PREPARE.to_string())?;
    let hello = encode_message(&hello).map_err(|_| PREPARE.to_string())?;
    if stream.send_frame(&hello).await.is_err() {
        return Err("El cliente cerro la conexion.".to_string());
    }
    let reply = decode_message::<UnattendedHelloReply>(&recv_step(stream).await?)
        .map_err(|_| INVALID_REPLY.to_string())?;
    // Si la firma o la clave fijada no cuadran, se aborta aqui: la contrasena no sale.
    let pending = handshake.handle_reply(&reply).map_err(|e| match e {
        UnattendedChannelError::UnsupportedProtocolVersion { .. } => {
            "Versión no compatible.".to_string()
        }
        UnattendedChannelError::InvalidSignature => {
            "La identidad del equipo no coincide con la clave fijada.".to_string()
        }
        _ => INVALID_REPLY.to_string(),
    })?;
    let (awaiting, record) = pending
        .send_password(wiped(&password))
        .map_err(|_| PREPARE.to_string())?;
    drop(password);
    if stream.send_frame(&record).await.is_err() {
        return Err("El cliente cerro la conexion.".to_string());
    }
    let record = recv_step(stream).await?;
    awaiting.finish(&record).map_err(|e| match e {
        UnattendedChannelError::Rejected {
            retry_after: Some(wait),
        } => format!(
            "Autenticación rechazada; reintente en {} s.",
            wait.as_secs().max(1)
        ),
        UnattendedChannelError::Rejected { retry_after: None } => {
            "Autenticación rechazada.".to_string()
        }
        _ => INVALID_REPLY.to_string(),
    })
}

/// Devuelve el motivo de cierre para la UI, o `None` si ya se informo (rechazo o revocacion).
async fn run(
    config: OperatorNetConfig,
    mut commands: mpsc::UnboundedReceiver<Command>,
    emitter: &Emitter,
) -> Option<String> {
    let OperatorNetConfig {
        relay_addr,
        pin,
        request,
        host_key,
        password,
        sink,
        ..
    } = config;
    let client = match RelayClient::new(relay_addr, pin) {
        Ok(client) => client,
        Err(e) => return Some(relay_error_text(&e)),
    };
    let mut stream = match timeout(
        CONNECT_TIMEOUT,
        client.connect_operator(request.target_session_id),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Some(relay_error_text(&e)),
        Err(_) => return Some("El relay no respondio a tiempo.".to_string()),
    };

    // Handshake: la contrasena solo entra al handshake y se borra al terminar este bloque.
    let unattended = host_key.is_some();
    let (sas, mut channel, video, fingerprint) = if let Some(key) = host_key {
        match unattended_handshake(&mut stream, &request, password, &key).await {
            Ok(session) => (
                session.sas,
                session.channel,
                session.video,
                Some(session.fingerprint),
            ),
            Err(reason) => return Some(reason),
        }
    } else {
        let session = {
            let (handshake, hello) = match OperatorHandshake::start(&request, &password) {
                Ok(pair) => pair,
                Err(_) => return Some("Contrasena invalida.".to_string()),
            };
            drop(password);
            let Ok(hello) = encode_message(&hello) else {
                return Some("No se pudo preparar la solicitud.".to_string());
            };
            if stream.send_frame(&hello).await.is_err() {
                return Some("El cliente cerro la conexion.".to_string());
            }
            let reply = match recv_step(&mut stream).await {
                Ok(bytes) => match decode_message::<PakeHelloReply>(&bytes) {
                    Ok(reply) => reply,
                    Err(_) => return Some(INVALID_REPLY.to_string()),
                },
                Err(e) => return Some(e),
            };
            let (verdict, confirm) = match handshake.handle_hello_reply(&reply) {
                Ok(pair) => pair,
                Err(HandshakeError::UnsupportedProtocolVersion { supported }) => {
                    return Some(format!(
                        "El cliente usa otra version del protocolo ({supported})."
                    ));
                }
                Err(_) => return Some(INVALID_REPLY.to_string()),
            };
            let Ok(confirm) = encode_message(&confirm) else {
                return Some("No se pudo preparar la confirmacion.".to_string());
            };
            if stream.send_frame(&confirm).await.is_err() {
                return Some("El cliente cerro la conexion.".to_string());
            }
            let reply = match recv_step(&mut stream).await {
                Ok(bytes) => match decode_message::<HostAuthReply>(&bytes) {
                    Ok(reply) => reply,
                    Err(_) => return Some(INVALID_REPLY.to_string()),
                },
                Err(e) => return Some(e),
            };
            match verdict.finish(&reply) {
                Ok(session) => session,
                Err(HandshakeError::Rejected { .. }) => {
                    return Some("ID o contrasena incorrectos.".to_string());
                }
                Err(_) => return Some("El cliente no pudo demostrar la clave.".to_string()),
            }
        };
        let OperatorSession {
            sas,
            channel,
            video,
        } = session;
        (sas, channel, video, None)
    };
    if let Some(fingerprint) = fingerprint {
        emitter.emit(NetEvent::UnattendedGranted { fingerprint });
    }

    let streams = stream.video_streams();
    let (mut sender, mut receiver) = stream.into_split();
    // El receptor no es seguro de cancelar: vive en su propia tarea.
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<Vec<u8>>(64);
    let reader = tokio::spawn(async move {
        while let Ok(record) = receiver.recv_frame().await {
            if ctl_tx.send(record).await.is_err() {
                break;
            }
        }
    });

    let sink: SharedSink = Arc::new(Mutex::new(sink));
    let (video_failed_tx, mut video_failed_rx) = mpsc::unbounded_channel::<String>();
    let mut video_opener = Some(video);
    let mut approved = false;
    // Con el host en escritorio seguro no se envia entrada (el host tambien la descarta).
    let mut paused = false;
    let started = Instant::now();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut seq = 0u64;

    let outcome = loop {
        tokio::select! {
            record = ctl_rx.recv() => {
                let Some(record) = record else {
                    break Some("Se perdio la conexion con el cliente.".to_string());
                };
                let Ok(plain) = channel.open(&record) else {
                    break Some("Canal de control alterado: sesion cerrada.".to_string());
                };
                let Ok(msg) = decode_message::<HostToClientMessage>(&plain) else {
                    break Some("Mensaje invalido del cliente.".to_string());
                };
                match msg {
                    HostToClientMessage::PendingApproval { timeout_secs, .. } if !unattended => {
                        emitter.emit(NetEvent::AwaitingApproval { timeout_secs, sas: sas.to_string() });
                    }
                    HostToClientMessage::ApprovalResult { granted: true, monitors, .. } if !unattended => {
                        if approved {
                            continue;
                        }
                        if let Err(e) = lock_sink(&sink).set_monitors(&monitors) {
                            break Some(e);
                        }
                        approved = true;
                        emitter.emit(NetEvent::Approved { monitors });
                        // El video se acepta solo a partir de aqui.
                        if let Some(opener) = video_opener.take() {
                            tokio::spawn(read_video(streams.clone(), opener, sink.clone(), video_failed_tx.clone()));
                        }
                    }
                    HostToClientMessage::ApprovalResult { granted: false, reason, .. } if !unattended => {
                        emitter.emit(NetEvent::Rejected { reason: reason.unwrap_or_default() });
                        break None;
                    }
                    HostToClientMessage::SessionRevoked { reason } => {
                        emitter.emit(NetEvent::Disconnected { reason });
                        break None;
                    }
                    HostToClientMessage::DisplayTopologyChanged { monitors } if approved => {
                        if let Err(e) = lock_sink(&sink).set_monitors(&monitors) {
                            break Some(e);
                        }
                        emitter.emit(NetEvent::TopologyChanged { monitors });
                    }
                    // Desatendido: no hay `ApprovalResult`; los monitores llegan en el primer aviso de
                    // topologia y a partir de ahi empiezan el video y la entrada.
                    HostToClientMessage::DisplayTopologyChanged { monitors } if unattended => {
                        if let Err(e) = lock_sink(&sink).set_monitors(&monitors) {
                            break Some(e);
                        }
                        approved = true;
                        emitter.emit(NetEvent::Approved { monitors });
                        if let Some(opener) = video_opener.take() {
                            tokio::spawn(read_video(streams.clone(), opener, sink.clone(), video_failed_tx.clone()));
                        }
                    }
                    HostToClientMessage::LocalApprovalRequired if approved => {
                        paused = true;
                        emitter.emit(NetEvent::LocalApprovalRequired);
                    }
                    HostToClientMessage::LocalApprovalCleared if approved => {
                        paused = false;
                        emitter.emit(NetEvent::LocalApprovalCleared);
                    }
                    HostToClientMessage::Pong { client_mono_us, .. } => {
                        let now_us = started.elapsed().as_micros() as u64;
                        emitter.emit(NetEvent::Rtt(Duration::from_micros(now_us.saturating_sub(client_mono_us))));
                    }
                    // La forma del puntero no se dibuja todavia en el visor.
                    _ => {}
                }
            }
            command = commands.recv() => match command {
                Some(Command::Input(cmd)) => {
                    // Antes de la aprobacion no sale ningun evento de entrada.
                    if approved && !paused && !send_control(&mut sender, &mut channel, &to_wire(cmd)).await {
                        break Some("Se perdio la conexion con el cliente.".to_string());
                    }
                }
                Some(Command::Disconnect) | None => {
                    let bye = ClientToHostMessage::Disconnect { reason: DisconnectReason::UserRequested };
                    send_control(&mut sender, &mut channel, &bye).await;
                    break None;
                }
            },
            _ = ping.tick(), if approved || unattended => {
                seq += 1;
                let msg = ClientToHostMessage::Ping { seq, client_mono_us: started.elapsed().as_micros() as u64 };
                if !send_control(&mut sender, &mut channel, &msg).await {
                    break Some("Se perdio la conexion con el cliente.".to_string());
                }
            }
            failed = video_failed_rx.recv() => {
                if let Some(reason) = failed {
                    break Some(reason);
                }
            }
        }
    };
    reader.abort();
    sender.finish().await;
    sender.close();
    client.close();
    outcome
}

fn lock_sink(sink: &SharedSink) -> std::sync::MutexGuard<'_, Box<dyn VideoSink>> {
    sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Comando de entrada al mensaje de red. El host recalcula el punto del clic con el ultimo
/// `PointerMove` (no confia en coordenadas del operador).
fn to_wire(cmd: RemoteInputCommand) -> ClientToHostMessage {
    match cmd {
        RemoteInputCommand::MoveCursor { norm_x, norm_y } => ClientToHostMessage::PointerMove {
            norm_x,
            norm_y,
            monitor_id: None,
        },
        RemoteInputCommand::MouseButton { button, state, .. } => {
            ClientToHostMessage::PointerButton { button, state }
        }
        RemoteInputCommand::MouseWheel { delta_x, delta_y } => {
            ClientToHostMessage::PointerWheel { delta_x, delta_y }
        }
        RemoteInputCommand::Keyboard {
            scancode,
            extended,
            unicode_char,
            state,
        } => ClientToHostMessage::KeyboardEvent {
            scancode,
            extended,
            unicode_fallback: unicode_char,
            state,
        },
    }
}

async fn send_control(
    sender: &mut RelayedSender,
    channel: &mut SecureChannel,
    msg: &ClientToHostMessage,
) -> bool {
    let Ok(plain) = encode_message(msg) else {
        return false;
    };
    if plain.len() > MAX_CONTROL_PLAINTEXT {
        return false;
    }
    let Ok(record) = channel.seal(&plain) else {
        return false;
    };
    sender.send_frame(&record).await.is_ok()
}

/// Lee los streams de video en orden; cualquier error de registro cierra la sesion.
async fn read_video(
    streams: VideoStreams,
    mut opener: VideoOpener,
    sink: SharedSink,
    failed: mpsc::UnboundedSender<String>,
) {
    while let Ok(mut stream) = streams.accept().await {
        let mut preamble = [0u8; VIDEO_STREAM_PREAMBLE_LEN];
        if stream.read_exact(&mut preamble).await.is_err() {
            continue;
        }
        let mut stream_opener = match opener.accept_stream(preamble) {
            Ok(o) => o,
            Err(e) => {
                let _ = failed.send(format!("Video rechazado: {e:?}"));
                return;
            }
        };
        loop {
            let mut prefix = [0u8; VIDEO_RECORD_PREFIX_LEN];
            // Fin limpio del stream entre registros: se pasa al siguiente.
            if stream.read_exact(&mut prefix).await.is_err() {
                break;
            }
            let len = match stream_opener.record_len(&prefix) {
                Ok(len) => len,
                Err(e) => {
                    let _ = failed.send(format!("Video rechazado: {e:?}"));
                    return;
                }
            };
            let mut record = vec![0u8; len];
            record[..VIDEO_RECORD_PREFIX_LEN].copy_from_slice(&prefix);
            if stream
                .read_exact(&mut record[VIDEO_RECORD_PREFIX_LEN..])
                .await
                .is_err()
            {
                let _ = failed.send("Video truncado: sesion cerrada.".to_string());
                return;
            }
            let (header, payload) = match stream_opener.open(&record) {
                Ok(opened) => opened,
                Err(e) => {
                    let _ = failed.send(format!("Video rechazado: {e:?}"));
                    return;
                }
            };
            if let Err(e) = lock_sink(&sink).packet(&header, &payload) {
                let _ = failed.send(e);
                return;
            }
        }
    }
}
