//! Red del host: registro en el relay, handshake por cable, canal de control cifrado y video.
//!
//! Corre en un runtime de tokio propio (hilo aparte de la UI). Ciclo:
//!
//! 1. Registra en el relay el ID que publica la UI (`HostNet::set_session_id`). Ante
//!    `SessionIdTaken` (ID ocupado por otro o por un registro previo nuestro que el relay aun no
//!    libero) avisa a la UI, que genera un ID nuevo, y reintenta con espera creciente.
//! 2. Al emparejar lee el `PakeHello` (con plazo) y lo entrega a la UI (`NetEvent::OperatorHello`).
//!    La UI pasa sus credenciales con `AuthHandle::authenticate` desde un hilo propio; el handshake
//!    corre aqui con plazo y `abort()` si el operador no confirma. Un solo handshake a la vez: el
//!    siguiente emparejamiento solo se acepta al terminar esta sesion.
//! 3. Con el handshake valido, la sesion queda pendiente del clic local. La decision llega por la
//!    `SessionGate`: `Active` (Aceptar) envia `ApprovalResult` con los monitores y arranca el video;
//!    `Closed` envia el rechazo o `SessionRevoked` y cierra.
//! 4. Stream 0 (bidireccional): control y entrada en registros `SecureChannel`. Streams
//!    unidireccionales: video sellado con `VideoStreamSealer`. Sin sesion aprobada en la compuerta
//!    no se captura ni se inyecta nada.
//!
//! Solo depende de `awawa-protocol`, `awawa-relay`, `tokio` y `crate::gate` (la prueba E2E del
//! relay incluye este archivo por ruta con fuentes de video y entrada simuladas).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};

use awawa_protocol::{
    ApprovedActiveSession, ClientToHostMessage, ConsentError, DesktopSessionMonitor,
    HostAuthenticated, HostToClientMessage, InputDesktopKind, MAX_CTRL_FRAME, MonitorDescriptor,
    NormalizedPoint, PROTOCOL_VERSION, PakeConfirm, PakeHello, PakeHelloReply, PendingLocalConsent,
    RemoteInputCommand, SecureChannel, SessionId, VideoCodec, VideoPacketHeader, VideoSealer,
    VirtualDesktopBounds, WaitingForRequest, WireError, decode_message, encode_message,
};
use awawa_relay::{
    ClientError, RelayClient, RelayError, RelayPin, RelayedSender, RelayedStream, VideoStreams,
};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::gate::{GateStatus, SessionGate};

/// Plazo para recibir el `PakeHello` tras emparejar.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Plazo para que la UI entregue sus credenciales al handshake.
pub const HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);
/// Plazo para recibir la confirmacion SPAKE2 del operador (despues: `abort()`).
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(15);
/// Plazo total que la UI espera el resultado del handshake (cubre los dos anteriores).
pub const AUTH_RESULT_TIMEOUT: Duration = Duration::from_secs(25);
/// Periodo del dead-man switch de la entrada (<= 250 ms).
pub const HEARTBEAT_TICK: Duration = Duration::from_millis(250);
/// Periodo del sondeo del escritorio de entrada (escritorio seguro).
pub const DESKTOP_PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// Periodo de la revision de la topologia de monitores.
pub const TOPOLOGY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Tiempo maximo sin un fotograma valido (fallos de captura o desajustes de topologia seguidos)
/// antes de revocar la sesion con `SessionRevoked`.
pub const CAPTURE_FAILURE_LIMIT: Duration = Duration::from_secs(3);
/// Segundos que el operador ve en su cuenta regresiva (los del modal local).
pub const PENDING_APPROVAL_SECS: u16 = 60;
/// Espera inicial y maxima entre reintentos de registro.
pub const RETRY_MIN: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(30);
/// Texto plano maximo por registro de control: la trama cifrada (cabecera 8 + etiqueta 16) no
/// puede pasar de `MAX_CTRL_FRAME`.
pub const MAX_CONTROL_PLAINTEXT: usize = MAX_CTRL_FRAME - 24;

/// Resultado del handshake que recibe la UI.
pub type AuthOutcome = Result<PendingLocalConsent, (WaitingForRequest, ConsentError)>;

/// Eventos hacia la UI.
#[derive(Debug)]
pub enum NetEvent {
    Connecting,
    Registered,
    /// El relay no responde o rechazo el registro (se reintenta solo).
    Unreachable,
    /// El ID esta ocupado en el relay: la UI debe generar uno nuevo.
    SessionIdTaken,
    /// Un operador emparejo y envio su hello. `name` no esta saneado.
    OperatorHello {
        name: String,
        auth: AuthHandle,
    },
    /// La sesion del operador termino (desconexion, error de protocolo o fin del canal).
    OperatorGone,
}

/// Entrega las credenciales del host al handshake de red y espera el resultado.
pub struct AuthHandle {
    waiting_tx: oneshot::Sender<WaitingForRequest>,
    result_rx: std_mpsc::Receiver<AuthOutcome>,
}

impl AuthHandle {
    /// Bloquea hasta `AUTH_RESULT_TIMEOUT` (llamar fuera del hilo de la UI). `None` si la red
    /// no devolvio las credenciales (se pierden: la UI genera otras).
    pub fn authenticate(self, waiting: WaitingForRequest) -> Option<AuthOutcome> {
        if let Err(waiting) = self.waiting_tx.send(waiting) {
            return Some(Err((
                waiting,
                ConsentError::MalformedHandshake("el operador cerro la conexion"),
            )));
        }
        self.result_rx.recv_timeout(AUTH_RESULT_TIMEOUT).ok()
    }
}

impl std::fmt::Debug for AuthHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthHandle").finish_non_exhaustive()
    }
}

/// Paquete de video ya codificado de un monitor.
pub struct SourcePacket {
    /// Payload `ZstdDirtyTiles`; vacio si solo cambio el puntero.
    pub payload: Vec<u8>,
    /// Dimensiones del fotograma capturado: deben coincidir con el monitor anunciado.
    pub width: u32,
    pub height: u32,
    /// Forma del puntero en BGRA (`CursorShapeUpdate`), si cambio.
    pub cursor: Option<HostToClientMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// Windows muestra el escritorio seguro (UAC, Winlogon): no se captura.
    SecureDesktop,
    Failed(String),
}

/// Fuente de video del host (captura + codificacion). Vive en el hilo de captura.
pub trait VideoSource {
    fn monitors(&mut self) -> Vec<MonitorDescriptor>;
    /// Escritorio que recibe la entrada ahora mismo.
    fn probe_input_desktop(&mut self) -> InputDesktopKind;
    /// Captura y codifica el siguiente fotograma del monitor; exige la sesion aprobada.
    /// `Ok(None)` si no hubo cambios.
    fn next_packet(
        &mut self,
        session: &ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        monitor_index: u8,
        keyframe: bool,
    ) -> Result<Option<SourcePacket>, SourceError>;
}

/// Crea la fuente de video de una sesion (en el hilo de captura).
pub type VideoSourceFactory = Arc<dyn Fn() -> Result<Box<dyn VideoSource>, String> + Send + Sync>;

/// Configuracion de la red del host.
pub struct HostNetConfig {
    pub relay_addr: SocketAddr,
    pub pin: RelayPin,
    pub gate: SessionGate,
    pub video: VideoSourceFactory,
    /// `true` si una ventana protegida del host tiene el foco: el teclado remoto se descarta.
    pub keyboard_blocked: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Despierta la UI cuando hay eventos.
    pub wake: Arc<dyn Fn() + Send + Sync>,
}

/// Red del host en marcha. Al soltarla se detiene el runtime.
pub struct HostNet {
    events: std_mpsc::Receiver<NetEvent>,
    session_id: watch::Sender<Option<SessionId>>,
    runtime: Option<Runtime>,
}

#[derive(Clone)]
struct Shared {
    events: std_mpsc::Sender<NetEvent>,
    gate: SessionGate,
    video: VideoSourceFactory,
    keyboard_blocked: Arc<dyn Fn() -> bool + Send + Sync>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Shared {
    fn emit(&self, event: NetEvent) {
        let _ = self.events.send(event);
        (self.wake)();
    }
}

impl HostNet {
    pub fn start(config: HostNetConfig) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("host-net")
            .build()
            .map_err(|e| e.to_string())?;
        let (events_tx, events) = std_mpsc::channel();
        let (session_id, id_rx) = watch::channel(None);
        let shared = Shared {
            events: events_tx,
            gate: config.gate,
            video: config.video,
            keyboard_blocked: config.keyboard_blocked,
            wake: config.wake,
        };
        let (addr, pin) = (config.relay_addr, config.pin);
        runtime.spawn(async move { registration_loop(addr, pin, id_rx, shared).await });
        Ok(Self {
            events,
            session_id,
            runtime: Some(runtime),
        })
    }

    pub fn poll_event(&self) -> Option<NetEvent> {
        self.events.try_recv().ok()
    }

    /// ID que el host debe tener registrado en el relay.
    pub fn set_session_id(&self, id: SessionId) {
        self.session_id.send_if_modified(|current| {
            if *current == Some(id) {
                false
            } else {
                *current = Some(id);
                true
            }
        });
    }
}

impl Drop for HostNet {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

async fn registration_loop(
    addr: SocketAddr,
    pin: RelayPin,
    mut id_rx: watch::Receiver<Option<SessionId>>,
    shared: Shared,
) {
    let client = match RelayClient::new(addr, pin) {
        Ok(client) => client,
        Err(_) => {
            shared.emit(NetEvent::Unreachable);
            return;
        }
    };
    let mut backoff = RETRY_MIN;
    loop {
        let current = *id_rx.borrow_and_update();
        let Some(id) = current else {
            if id_rx.changed().await.is_err() {
                return;
            }
            continue;
        };
        shared.emit(NetEvent::Connecting);
        match client.register_host(id).await {
            Ok(registration) => {
                backoff = RETRY_MIN;
                shared.emit(NetEvent::Registered);
                tokio::select! {
                    paired = registration.wait_for_operator() => match paired {
                        Ok(stream) => run_session(stream, &shared).await,
                        // Caduco sin operador: se registra de nuevo.
                        Err(ClientError::Relay(RelayError::Expired)) => {}
                        Err(_) => {
                            shared.emit(NetEvent::Unreachable);
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(RETRY_MAX);
                        }
                    },
                    // ID nuevo (revocacion o regeneracion): soltar el registro libera el slot.
                    changed = id_rx.changed() => if changed.is_err() { return },
                }
            }
            Err(ClientError::Relay(RelayError::SessionIdTaken)) => {
                shared.emit(NetEvent::SessionIdTaken);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
            Err(_) => {
                shared.emit(NetEvent::Unreachable);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
        }
    }
}

/// Lo que queda en la red tras un handshake valido.
struct Authenticated {
    channel: SecureChannel,
    video: VideoSealer,
    sas: [u8; 6],
}

/// Envia un mensaje del handshake (en claro, ligado al transcript) ya serializado.
async fn send_plain(stream: &mut RelayedStream, encoded: Result<Vec<u8>, WireError>) -> bool {
    match encoded {
        Ok(bytes) => stream.send_frame(&bytes).await.is_ok(),
        Err(_) => false,
    }
}

/// Handshake del host sobre el stream emparejado. Siempre devuelve las credenciales a la UI.
async fn authenticate(
    stream: &mut RelayedStream,
    hello: &PakeHello,
    waiting_rx: oneshot::Receiver<WaitingForRequest>,
    result_tx: std_mpsc::Sender<AuthOutcome>,
) -> Option<Authenticated> {
    // La UI ignora la solicitud si no esta esperando (modal abierto o sesion activa).
    let waiting = match timeout(HANDOFF_TIMEOUT, waiting_rx).await {
        Ok(Ok(waiting)) => waiting,
        _ => return None,
    };
    let fail = |waiting, err| {
        let _ = result_tx.send(Err((waiting, err)));
        None
    };
    let (authenticating, challenge) = match waiting.accept_operator_hello(hello) {
        Ok(pair) => pair,
        Err((waiting, err)) => {
            if let ConsentError::UnsupportedProtocolVersion(_) = err {
                let reply = PakeHelloReply::UnsupportedProtocolVersion {
                    supported: PROTOCOL_VERSION,
                };
                send_plain(stream, encode_message(&reply)).await;
            }
            return fail(waiting, err);
        }
    };
    if !send_plain(
        stream,
        encode_message(&PakeHelloReply::Challenge(challenge)),
    )
    .await
    {
        return fail(
            authenticating.abort(),
            ConsentError::MalformedHandshake("canal cerrado"),
        );
    }
    let confirm = match timeout(CONFIRM_TIMEOUT, stream.recv_frame()).await {
        Ok(Ok(bytes)) => decode_message::<PakeConfirm>(&bytes).ok(),
        _ => None,
    };
    let Some(confirm) = confirm else {
        // Sin confirmacion el operador no aprendio nada de la contrasena: no cuenta intento.
        return fail(
            authenticating.abort(),
            ConsentError::MalformedHandshake("sin confirmacion a tiempo"),
        );
    };
    match authenticating.verify_operator_confirmation(&confirm, Instant::now()) {
        Err((waiting, err, reply)) => {
            send_plain(stream, encode_message(&reply)).await;
            fail(waiting, err)
        }
        Ok(HostAuthenticated {
            pending,
            reply,
            channel,
            video,
        }) => {
            if !send_plain(stream, encode_message(&reply)).await {
                // Sin veredicto entregado no hay sesion: vuelve a esperar con contrasena nueva.
                return match pending.reject_locally() {
                    Ok(waiting) => fail(waiting, ConsentError::MalformedHandshake("canal cerrado")),
                    Err(_) => None,
                };
            }
            let sas = pending.sas().as_bytes();
            result_tx.send(Ok(pending)).ok()?;
            Some(Authenticated {
                channel,
                video,
                sas,
            })
        }
    }
}

/// Sella y envia un mensaje de control. `false` si el canal fallo o el mensaje excede el tope.
async fn send_control(
    sender: &mut RelayedSender,
    channel: &mut SecureChannel,
    msg: &HostToClientMessage,
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

/// Mensajes del hilo de captura hacia la sesion.
enum CaptureOut {
    Started(Vec<MonitorDescriptor>),
    Control(HostToClientMessage),
    LocalApprovalRequired,
    LocalApprovalCleared,
    Failed(String),
}

struct VideoPacket {
    header: VideoPacketHeader,
    payload: Vec<u8>,
}

async fn run_session(mut stream: RelayedStream, shared: &Shared) {
    shared.gate.reset();
    let hello = match timeout(HELLO_TIMEOUT, stream.recv_frame()).await {
        Ok(Ok(bytes)) => decode_message::<PakeHello>(&bytes).ok(),
        _ => None,
    };
    let Some(hello) = hello else {
        stream.close();
        return;
    };
    let (waiting_tx, waiting_rx) = oneshot::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    shared.emit(NetEvent::OperatorHello {
        name: hello.operator_display_name.clone(),
        auth: AuthHandle {
            waiting_tx,
            result_rx,
        },
    });
    let Some(auth) = authenticate(&mut stream, &hello, waiting_rx, result_tx).await else {
        stream.finish().await;
        stream.close();
        return;
    };
    let Authenticated {
        mut channel,
        video,
        sas,
    } = auth;

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

    let pending = HostToClientMessage::PendingApproval {
        timeout_secs: PENDING_APPROVAL_SECS,
        session_fingerprint_short: sas,
    };
    let mut alive = send_control(&mut sender, &mut channel, &pending).await;

    let mut status = shared.gate.subscribe();
    // La decision pudo llegar antes de suscribirse: se revisa el valor actual en la primera vuelta.
    status.mark_changed();
    let mut decided_active = false;
    let mut bounds: Option<VirtualDesktopBounds> = None;
    let mut pointer_px = (0i32, 0i32);
    let (capture_tx, mut capture_rx) = mpsc::unbounded_channel::<CaptureOut>();
    let mut go_tx: Option<std_mpsc::Sender<()>> = None;
    let mut video = Some(video);
    let mut heartbeat = tokio::time::interval(HEARTBEAT_TICK);
    let mut revoked_reason: Option<String> = None;

    while alive {
        tokio::select! {
            changed = status.changed() => {
                if changed.is_err() {
                    break;
                }
                let current = *status.borrow_and_update();
                match current {
                    GateStatus::Active if !decided_active => {
                        decided_active = true;
                        let (tx, rx) = std_mpsc::channel();
                        go_tx = Some(tx);
                        let (packets_tx, packets_rx) = mpsc::channel::<VideoPacket>(4);
                        spawn_capture(shared.clone(), capture_tx.clone(), packets_tx, rx);
                        if let Some(sealer) = video.take() {
                            tokio::spawn(write_video(streams.clone(), sealer, packets_rx, shared.gate.clone(), capture_tx.clone()));
                        }
                    }
                    GateStatus::Closed => {
                        let msg = if decided_active {
                            HostToClientMessage::SessionRevoked {
                                reason: revoked_reason.take().unwrap_or_else(|| "El usuario local revoco el control.".to_string()),
                            }
                        } else {
                            HostToClientMessage::ApprovalResult {
                                granted: false,
                                reason: Some("El usuario local rechazo la solicitud.".to_string()),
                                monitors: Vec::new(),
                            }
                        };
                        send_control(&mut sender, &mut channel, &msg).await;
                        break;
                    }
                    _ => {}
                }
            }
            out = capture_rx.recv() => match out {
                Some(CaptureOut::Started(monitors)) => {
                    bounds = VirtualDesktopBounds::from_monitors(&monitors);
                    let msg = HostToClientMessage::ApprovalResult { granted: true, reason: None, monitors };
                    alive = send_control(&mut sender, &mut channel, &msg).await;
                    if let Some(go) = &go_tx {
                        let _ = go.send(());
                    }
                }
                Some(CaptureOut::Control(msg)) => {
                    if let HostToClientMessage::DisplayTopologyChanged { monitors } = &msg {
                        bounds = VirtualDesktopBounds::from_monitors(monitors);
                    }
                    // Un mensaje que no cabe (p. ej. un cursor enorme) se omite; el resto sigue.
                    if !send_control(&mut sender, &mut channel, &msg).await && channel.is_closed() {
                        alive = false;
                    }
                }
                Some(CaptureOut::LocalApprovalRequired) => {
                    // Captura y entrada ya estan suspendidas en la compuerta; se avisa al operador.
                    alive = send_control(&mut sender, &mut channel, &HostToClientMessage::LocalApprovalRequired).await;
                }
                Some(CaptureOut::LocalApprovalCleared) => {
                    alive = send_control(&mut sender, &mut channel, &HostToClientMessage::LocalApprovalCleared).await;
                }
                Some(CaptureOut::Failed(reason)) => {
                    revoked_reason = Some(format!("Captura no disponible: {reason}"));
                    shared.gate.revoke("Captura no disponible", Instant::now());
                }
                None => {}
            },
            record = ctl_rx.recv() => {
                let Some(record) = record else {
                    break;
                };
                let Ok(plain) = channel.open(&record) else {
                    break;
                };
                let Ok(msg) = decode_message::<ClientToHostMessage>(&plain) else {
                    break;
                };
                if !handle_operator_message(msg, &mut sender, &mut channel, shared, bounds.as_ref(), &mut pointer_px).await {
                    break;
                }
            }
            _ = heartbeat.tick(), if decided_active => {
                shared.gate.tick_heartbeat(Instant::now());
            }
        }
    }

    // Fin de la sesion por cualquier motivo: si seguia activa se revoca (libera teclas).
    shared.gate.revoke("Operador desconectado", Instant::now());
    shared.gate.decline();
    drop(go_tx);
    reader.abort();
    sender.finish().await;
    sender.close();
    shared.emit(NetEvent::OperatorGone);
}

/// `false` si la sesion debe terminar.
async fn handle_operator_message(
    msg: ClientToHostMessage,
    sender: &mut RelayedSender,
    channel: &mut SecureChannel,
    shared: &Shared,
    bounds: Option<&VirtualDesktopBounds>,
    pointer_px: &mut (i32, i32),
) -> bool {
    let now = Instant::now();
    let command = match msg {
        ClientToHostMessage::Ping {
            seq,
            client_mono_us,
        } => {
            shared.gate.record_ping(now);
            let pong = HostToClientMessage::Pong {
                seq,
                client_mono_us,
            };
            return send_control(sender, channel, &pong).await;
        }
        ClientToHostMessage::Disconnect { .. } => return false,
        ClientToHostMessage::ControlRequest { .. } => return true,
        ClientToHostMessage::PointerMove { norm_x, norm_y, .. } => {
            if let Some(b) = bounds {
                *pointer_px = b.denormalize_point(NormalizedPoint {
                    x: norm_x,
                    y: norm_y,
                });
            }
            RemoteInputCommand::MoveCursor { norm_x, norm_y }
        }
        ClientToHostMessage::PointerButton { button, state } => RemoteInputCommand::MouseButton {
            button,
            state,
            target_x: pointer_px.0,
            target_y: pointer_px.1,
        },
        ClientToHostMessage::PointerWheel { delta_x, delta_y } => {
            RemoteInputCommand::MouseWheel { delta_x, delta_y }
        }
        ClientToHostMessage::KeyboardEvent {
            scancode,
            extended,
            unicode_fallback,
            state,
        } => {
            // Con una ventana protegida en primer plano se descartan las pulsaciones; las
            // liberaciones pasan para no dejar teclas pegadas.
            if state == awawa_protocol::KeyState::Down && (shared.keyboard_blocked)() {
                return true;
            }
            RemoteInputCommand::Keyboard {
                scancode,
                extended,
                unicode_char: unicode_fallback,
                state,
            }
        }
    };
    // Sin sesion aprobada (o suspendida) la compuerta lo descarta.
    let _ = shared.gate.dispatch(&command, now);
    true
}

fn spawn_capture(
    shared: Shared,
    out: mpsc::UnboundedSender<CaptureOut>,
    packets: mpsc::Sender<VideoPacket>,
    go: std_mpsc::Receiver<()>,
) {
    let _ = thread::Builder::new()
        .name("host-capture".to_string())
        .spawn(move || capture_loop(shared, out, packets, go));
}

fn capture_loop(
    shared: Shared,
    out: mpsc::UnboundedSender<CaptureOut>,
    packets: mpsc::Sender<VideoPacket>,
    go: std_mpsc::Receiver<()>,
) {
    let mut source = match (shared.video)() {
        Ok(source) => source,
        Err(e) => {
            let _ = out.send(CaptureOut::Failed(e));
            return;
        }
    };
    let mut monitors = source.monitors();
    if monitors.is_empty() {
        let _ = out.send(CaptureOut::Failed("sin monitores".to_string()));
        return;
    }
    let _ = out.send(CaptureOut::Started(monitors.clone()));
    // Ningun fotograma sale antes de que el operador reciba `ApprovalResult`.
    if go.recv().is_err() {
        return;
    }
    let started = Instant::now();
    let mut frame_seq = 0u64;
    let mut keyframe = vec![true; monitors.len()];
    let mut last_probe: Option<Instant> = None;
    let mut last_topology = Instant::now();
    // Desde cuando la captura no entrega un fotograma valido (fallos o desajustes seguidos).
    let mut failing_since: Option<Instant> = None;
    while shared.gate.is_active() {
        if last_probe.is_none_or(|t| t.elapsed() >= DESKTOP_PROBE_INTERVAL) {
            last_probe = Some(Instant::now());
            let change = shared
                .gate
                .observe_input_desktop(source.probe_input_desktop());
            if change.local_approval_required {
                let _ = out.send(CaptureOut::LocalApprovalRequired);
            }
            if change.resumed {
                keyframe.iter_mut().for_each(|k| *k = true);
                let _ = out.send(CaptureOut::LocalApprovalCleared);
            }
        }
        if !shared.gate.capture_allowed() {
            failing_since = None;
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        if last_topology.elapsed() >= TOPOLOGY_CHECK_INTERVAL {
            last_topology = Instant::now();
            refresh_topology(source.as_mut(), &mut monitors, &mut keyframe, &out);
        }
        let mut produced = false;
        let mut refresh = false;
        let mut failure: Option<String> = None;
        for (slot, monitor) in monitors.iter().enumerate() {
            let index = monitor.index;
            let force = keyframe[slot];
            let Some(result) = shared.gate.with_session(|session, desktop| {
                source.next_packet(session, desktop, index, force)
            }) else {
                return;
            };
            match result {
                Ok(Some(packet)) => {
                    if let Some(cursor) = packet.cursor {
                        let _ = out.send(CaptureOut::Control(cursor));
                    }
                    if packet.payload.is_empty() {
                        continue;
                    }
                    // Nunca sale un fotograma que no coincida con la topologia anunciada: el
                    // modo de video cambio antes de anunciarlo (p. ej. tras ACCESS_LOST).
                    if (packet.width, packet.height) != (monitor.width_px, monitor.height_px) {
                        refresh = true;
                        failure = Some(format!(
                            "fotograma de {}x{} en un monitor de {}x{}",
                            packet.width, packet.height, monitor.width_px, monitor.height_px
                        ));
                        break;
                    }
                    keyframe[slot] = false;
                    produced = true;
                    let Ok(payload_len) = u32::try_from(packet.payload.len()) else {
                        continue;
                    };
                    frame_seq += 1;
                    let header = VideoPacketHeader {
                        frame_seq,
                        capture_ts_us: started.elapsed().as_micros() as u64,
                        monitor_index: index,
                        codec: VideoCodec::ZstdDirtyTiles,
                        is_keyframe: force,
                        payload_len,
                    };
                    let packet = VideoPacket {
                        header,
                        payload: packet.payload,
                    };
                    if packets.blocking_send(packet).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(SourceError::SecureDesktop) => {
                    let change = shared
                        .gate
                        .observe_input_desktop(InputDesktopKind::SecureOrOther);
                    if change.local_approval_required {
                        let _ = out.send(CaptureOut::LocalApprovalRequired);
                    }
                    break;
                }
                Err(SourceError::Failed(reason)) => {
                    // Monitor desaparecido, cambio de modo o fallo del backend: se re-evalua la
                    // topologia ya mismo y se fuerza fotograma clave.
                    refresh = true;
                    failure = Some(reason);
                    break;
                }
            }
        }
        if refresh {
            last_topology = Instant::now();
            refresh_topology(source.as_mut(), &mut monitors, &mut keyframe, &out);
            keyframe.iter_mut().for_each(|k| *k = true);
        }
        match failure {
            Some(reason) => {
                let since = *failing_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= CAPTURE_FAILURE_LIMIT {
                    let _ = out.send(CaptureOut::Failed(reason));
                    return;
                }
            }
            None if produced => failing_since = None,
            None => {}
        }
        if !produced {
            thread::sleep(Duration::from_millis(15));
        }
    }
}

/// Vuelve a leer los monitores y, si cambiaron, anuncia `DisplayTopologyChanged` (antes que
/// cualquier fotograma de la topologia nueva) y fuerza fotograma clave en todos.
fn refresh_topology(
    source: &mut dyn VideoSource,
    monitors: &mut Vec<MonitorDescriptor>,
    keyframe: &mut Vec<bool>,
    out: &mpsc::UnboundedSender<CaptureOut>,
) {
    let current = source.monitors();
    if current.is_empty() || current == *monitors {
        return;
    }
    *monitors = current;
    *keyframe = vec![true; monitors.len()];
    let msg = HostToClientMessage::DisplayTopologyChanged {
        monitors: monitors.clone(),
    };
    let _ = out.send(CaptureOut::Control(msg));
}

/// Escribe el video en un stream unidireccional: preambulo y registros sellados.
/// Si el stream falla con la sesion activa, avisa a la sesion, que la revoca (`SessionRevoked`).
async fn write_video(
    streams: VideoStreams,
    sealer: VideoSealer,
    packets: mpsc::Receiver<VideoPacket>,
    gate: SessionGate,
    out: mpsc::UnboundedSender<CaptureOut>,
) {
    if let Err(reason) = write_video_inner(streams, sealer, packets, &gate).await
        && gate.is_active()
    {
        let _ = out.send(CaptureOut::Failed(reason));
    }
}

async fn write_video_inner(
    streams: VideoStreams,
    mut sealer: VideoSealer,
    mut packets: mpsc::Receiver<VideoPacket>,
    gate: &SessionGate,
) -> Result<(), String> {
    let mut current = None;
    while let Some(packet) = packets.recv().await {
        // Un fotograma capturado justo antes de revocar no sale.
        if !gate.is_active() {
            return Ok(());
        }
        if current.is_none() {
            let stream_sealer = sealer.open_stream().map_err(|e| format!("video: {e:?}"))?;
            let mut stream = streams.open().await.map_err(|e| format!("video: {e}"))?;
            stream
                .write_all(&stream_sealer.preamble())
                .await
                .map_err(|e| format!("video: {e}"))?;
            current = Some((stream, stream_sealer));
        }
        let Some((stream, stream_sealer)) = current.as_mut() else {
            return Ok(());
        };
        let Ok(record) = stream_sealer.seal(&packet.header, &packet.payload) else {
            // Contador agotado o payload fuera de tope: se descarta y se abre otro stream.
            current = None;
            continue;
        };
        if !gate.is_active() {
            return Ok(());
        }
        stream
            .write_all(&record)
            .await
            .map_err(|e| format!("video: {e}"))?;
    }
    if let Some((mut stream, _)) = current {
        stream.finish().await;
    }
    Ok(())
}
