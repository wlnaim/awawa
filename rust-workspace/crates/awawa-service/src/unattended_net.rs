//! Red del acceso desatendido: registro en el relay, canal E2E con la clave Ed25519 del servicio,
//! autenticacion con la contrasena del administrador, sesion de control y cierre ordenado del
//! agente de sesion.
//!
//! El servicio (SYSTEM) es dueno de la conexion al relay, de la identidad, del handshake, de la
//! autenticacion, del `SecureChannel` y del `VideoSealer`; no captura ni inyecta.
//! El agente, lanzado con el token del usuario, recibe por la pipe ([`crate::agent_pipe`]) solo
//! datos en claro de la maquina local.
//!
//! Ciclo ([`UnattendedService::run`]):
//! 1. Registra el ID persistente. Tras cada emparejamiento y al caducar el TTL vuelve a
//!    registrarse; ante `SessionIdTaken` espera con retroceso y reintenta el MISMO ID. Mientras
//!    hay una sesion no hay registro: el relay no empareja a nadie mas (una sesion a la vez).
//! 2. `UnattendedHello` (claro) -> `UnattendedHelloReply` (claro). Version incompatible: responde
//!    y cierra sin contar intento. ID equivocado o efimero invalido: cierra sin responder.
//! 3. Registro cifrado n.º 0 con la contrasena -> [`ServiceAuth::authenticate`] (audita cada
//!    intento) -> registro n.º 0 con `UnattendedAuthReply` generico. `Rejected`: envia y cierra.
//! 4. `Granted`: fija la sesion de consola y el SID de su usuario, crea la pipe con DACL para ese
//!    SID, lanza el agente, comprueba que el cliente de la pipe es exactamente el PID lanzado y
//!    envia al operador `DisplayTopologyChanged` con los monitores del agente antes de cualquier
//!    fotograma. No hay `ApprovalResult` ni modal local: la autorizacion es la contrasena.
//! 5. Sesion: entrada del operador -> agente (solo si el monitor la permite), video del agente ->
//!    `VideoStreamSealer` en streams unidireccionales, eventos `WTS_*`, sondeos del escritorio y
//!    revalidacion cada [`Timings::revalidate`] (generacion vigente, sesion de consola y SID).
//! 6. Fin: aviso `SessionRevoked` al operador, `Stop` al agente (libera teclas y sale) y
//!    `TerminateProcess` solo si no salio en [`Timings::agent_exit`].
//!
//! Origen para el throttle: el relay no expone la IP del operador y la huella de sesion cambia en
//! cada intento, mientras que el nombre lo elige el atacante. Se usa el valor fijo
//! [`THROTTLE_SOURCE`]: el bloqueo por origen se comporta como uno global (3 fallos bloquean a
//! todos 30 s, con retroceso). Un atacante no puede esquivarlo cambiando de nombre; el coste es
//! que puede bloquear temporalmente a un operador legitimo.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, sanitize_audit_text};
use awawa_protocol::desktop_session::{EndReason, MonitorAction, OperatorNotice};
use awawa_protocol::unattended::{
    PasswordKdf, UnattendedAuthenticator, UnattendedError, UnattendedStatus,
};
use awawa_protocol::unattended_channel::SigningKey;
use awawa_protocol::{
    ClientToHostMessage, HostToClientMessage, InputDesktopKind, MAX_CTRL_FRAME, SecureChannel,
    ServiceAuthOutcome, ServiceAwaitingPassword, SessionId, UnattendedHello, UnattendedVerdict,
    VideoSealer, decode_message, encode_message,
};
use awawa_relay::{
    ClientError, RelayClient, RelayError, RelayedSender, RelayedStream, VideoStreams,
};
use tokio::io::{AsyncRead, AsyncWrite, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::agent_pipe::{
    AgentFrame, AgentPipeServer, AgentToService, AgentVideo, ServiceToAgent, recv_from_agent,
    send_to_agent,
};
use crate::dpapi_store::VerifierFileStore;
use crate::session_tracker::{SessionTracker, TrackerStep, authorizable_session};
use crate::unattended_auth::{ServiceAuthError, authenticate_unattended, current_status};
use crate::winutil::unix_ms_now;

/// Origen con el que se limita y audita cada intento (ver el comentario del modulo).
pub const THROTTLE_SOURCE: &str = "relay";
/// Espera inicial y maxima entre reintentos de registro.
pub const RETRY_MIN: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(30);
/// Texto plano maximo por registro de control (cabecera 8 + etiqueta 16).
pub const MAX_CONTROL_PLAINTEXT: usize = MAX_CTRL_FRAME - 24;

/// Plazos de la sesion. `Default` son los de produccion.
#[derive(Debug, Clone, Copy)]
pub struct Timings {
    /// Plazo para recibir `UnattendedHello` tras emparejar.
    pub hello: Duration,
    /// Plazo para recibir el registro con la contrasena.
    pub password: Duration,
    /// Plazo para que el agente lanzado se conecte a la pipe y anuncie sus monitores.
    pub agent_connect: Duration,
    /// Periodo de la revalidacion (generacion, sesion de consola y SID): 2 s.
    pub revalidate: Duration,
    /// Plazo del cierre ordenado: tras pedir `Stop`, el agente tiene este tiempo para liberar
    /// teclas y salir antes de `TerminateProcess` (5 s).
    pub agent_exit: Duration,
    /// Plazo de cada escritura en la pipe.
    pub pipe_write: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            hello: Duration::from_secs(10),
            password: Duration::from_secs(30),
            agent_connect: Duration::from_secs(15),
            revalidate: Duration::from_secs(2),
            agent_exit: Duration::from_secs(5),
            pipe_write: Duration::from_secs(2),
        }
    }
}

/// Auditoria compartida entre el autenticador y la sesion.
pub type SharedAudit = Arc<Mutex<dyn AuditSink + Send>>;

/// Eventos del SCM hacia la red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent {
    /// `SERVICE_CONTROL_SESSIONCHANGE`.
    Wts { event_type: u32, session_id: u32 },
    /// `SERVICE_CONTROL_STOP`.
    Stop,
}

/// Autenticador del servicio. Cada llamada a `authenticate` deja exactamente un registro de
/// auditoria sin la contrasena.
pub trait ServiceAuth: Send + 'static {
    fn authenticate(&mut self, operator: &str, source: &str, password: &str) -> UnattendedVerdict;
    /// Estado vigente de la credencial (para la revalidacion).
    fn current_status(&mut self) -> UnattendedStatus;
}

/// Autenticador de produccion: recarga el verificador del disco en cada intento
/// ([`authenticate_unattended`]) con el limitador persistente del proceso.
pub struct StoreAuth {
    pub store: VerifierFileStore,
    pub authenticator: UnattendedAuthenticator,
    pub kdf: Box<dyn PasswordKdf + Send>,
    pub audit: SharedAudit,
}

impl ServiceAuth for StoreAuth {
    fn authenticate(&mut self, operator: &str, source: &str, password: &str) -> UnattendedVerdict {
        let mut sink = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        let result = authenticate_unattended(
            &self.store,
            &mut self.authenticator,
            &mut *sink,
            operator,
            source,
            password,
            self.kdf.as_ref(),
            Instant::now(),
        );
        match result {
            Ok(authorization) => UnattendedVerdict::from_result(&Ok(authorization)),
            Err(ServiceAuthError::Auth(e)) => UnattendedVerdict::from_result(&Err(e)),
            // Verificador rechazado o auditoria imposible: rechazo generico (falla cerrado).
            Err(ServiceAuthError::Store(_) | ServiceAuthError::Audit(_)) => {
                UnattendedVerdict::from_result(&Err(UnattendedError::UnattendedDisabled))
            }
        }
    }

    fn current_status(&mut self) -> UnattendedStatus {
        current_status(&self.store).unwrap_or(UnattendedStatus::NotConfigured)
    }
}

/// Proceso del agente lanzado.
pub trait AgentProcess: Send + 'static {
    fn pid(&self) -> u32;
    fn has_exited(&mut self) -> bool;
    /// `TerminateProcess`: solo tras el plazo del cierre ordenado.
    fn terminate(&mut self);
}

/// Pipe de una sesion creada y aun sin cliente.
pub trait PipeAcceptor: Send + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn name(&self) -> &str;
    /// Espera al cliente; devuelve la pipe y el PID del proceso cliente.
    fn accept(self) -> impl Future<Output = io::Result<(Self::Stream, u32)>> + Send;
}

/// Lo que el servicio necesita de Windows para la sesion (simulable en pruebas).
pub trait AgentPlatform: Send + 'static {
    type Acceptor: PipeAcceptor;
    type Process: AgentProcess;
    /// `WTSGetActiveConsoleSessionId`; `None` sin consola.
    fn active_console_session(&mut self) -> Option<u32>;
    /// SID del usuario de la sesion (desde su token).
    fn session_user_sid(&mut self, session_id: u32) -> Option<String>;
    fn create_pipe(&mut self, user_sid: &str) -> io::Result<Self::Acceptor>;
    fn launch_agent(&mut self, session_id: u32, pipe_name: &str) -> Result<Self::Process, String>;
}

/// Plataforma real: pipe con DACL y `launch_session_agent` (solo como SYSTEM).
pub struct WindowsPlatform {
    pub agent_exe: PathBuf,
}

/// Agente real lanzado con `CreateProcessAsUserW`.
pub struct WindowsAgent(Option<crate::agent_launcher::ProcessHandle>);

impl AgentProcess for WindowsAgent {
    fn pid(&self) -> u32 {
        self.0.as_ref().map_or(0, |p| p.pid())
    }

    fn has_exited(&mut self) -> bool {
        self.0.as_ref().is_none_or(|p| p.wait_exit(Duration::ZERO))
    }

    fn terminate(&mut self) {
        if let Some(process) = self.0.take() {
            crate::agent_launcher::terminate(process);
        }
    }
}

impl PipeAcceptor for AgentPipeServer {
    type Stream = tokio::net::windows::named_pipe::NamedPipeServer;

    fn name(&self) -> &str {
        AgentPipeServer::name(self)
    }

    fn accept(self) -> impl Future<Output = io::Result<(Self::Stream, u32)>> + Send {
        AgentPipeServer::accept(self)
    }
}

impl AgentPlatform for WindowsPlatform {
    type Acceptor = AgentPipeServer;
    type Process = WindowsAgent;

    fn active_console_session(&mut self) -> Option<u32> {
        authorizable_session(crate::agent_launcher::active_console_session())
    }

    fn session_user_sid(&mut self, session_id: u32) -> Option<String> {
        crate::agent_launcher::session_user_sid(session_id).ok()
    }

    fn create_pipe(&mut self, user_sid: &str) -> io::Result<Self::Acceptor> {
        crate::agent_pipe::create_agent_pipe(user_sid)
    }

    fn launch_agent(&mut self, session_id: u32, pipe_name: &str) -> Result<Self::Process, String> {
        crate::agent_launcher::launch_session_agent(
            session_id,
            &self.agent_exe,
            &["--pipe", pipe_name],
        )
        .map(|p| WindowsAgent(Some(p)))
        .map_err(|e| e.to_string())
    }
}

/// Servicio desatendido en red.
pub struct UnattendedService<A: ServiceAuth, P: AgentPlatform> {
    /// ID persistente (9 digitos) con el que se registra y que exige en el hello.
    pub target_id: u32,
    pub identity: SigningKey,
    pub auth: Arc<Mutex<A>>,
    pub platform: P,
    pub audit: SharedAudit,
    pub events: mpsc::UnboundedReceiver<ServiceEvent>,
    pub timings: Timings,
    tracker: SessionTracker,
    stopping: bool,
}

/// Motivo de fin de una sesion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// Fin decidido por el monitor (evento de Windows, revocacion, parada): ya auditado.
    Tracker(EndReason),
    /// Fin por un motivo ajeno a Windows (operador, kill-switch, agente): se audita al cerrar.
    Service(EndReason),
}

impl Exit {
    fn reason(self) -> EndReason {
        match self {
            Self::Tracker(r) | Self::Service(r) => r,
        }
    }
}

const OPERATOR_GONE: Exit = Exit::Service(EndReason::OperatorDisconnected);
const AGENT_FAILED: Exit = Exit::Service(EndReason::AgentFailed);

fn end_text(reason: EndReason) -> &'static str {
    match reason {
        EndReason::CredentialRevoked => "La contrasena desatendida cambio o fue revocada.",
        EndReason::SessionSwitched => {
            "Cambio la sesion o el usuario de Windows; hay que autenticarse otra vez."
        }
        EndReason::ConsoleDisconnect | EndReason::RemoteDisconnect | EndReason::SessionLogoff => {
            "La sesion de Windows termino o se desconecto."
        }
        EndReason::ServiceStopping => "El servicio de acceso desatendido se detuvo.",
        EndReason::LocalKillSwitch => "El usuario local revoco el control.",
        EndReason::OperatorDisconnected => "El operador se desconecto.",
        EndReason::AgentFailed => "El agente de sesion no esta disponible.",
        EndReason::ForeignPipeClient => "No se pudo iniciar el agente de sesion.",
    }
}

/// Lo fijado al autenticar.
struct Pinned {
    windows_session: u32,
    user_sid: String,
    operator: String,
    fingerprint: [u8; 8],
}

impl<A: ServiceAuth, P: AgentPlatform> UnattendedService<A, P> {
    pub fn new(
        target_id: u32,
        identity: SigningKey,
        auth: Arc<Mutex<A>>,
        platform: P,
        audit: SharedAudit,
        events: mpsc::UnboundedReceiver<ServiceEvent>,
        timings: Timings,
    ) -> Self {
        Self {
            target_id,
            identity,
            auth,
            platform,
            audit,
            events,
            timings,
            tracker: SessionTracker::new(),
            stopping: false,
        }
    }

    fn audit(&self, event: AuditEvent, pinned: Option<&Pinned>) {
        let record = match pinned {
            Some(p) => AuditRecord::new(unix_ms_now(), event, &p.operator)
                .with_operator_fingerprint(p.fingerprint)
                .with_source(THROTTLE_SOURCE)
                .with_windows_session_id(p.windows_session),
            None => AuditRecord::new(unix_ms_now(), event, "service"),
        };
        let mut sink = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        let _ = sink.write_record(&record);
    }

    /// Evento con el servicio inactivo. `true` si hay que parar.
    fn idle_event(&mut self, event: Option<ServiceEvent>) -> bool {
        match event {
            None | Some(ServiceEvent::Stop) => {
                self.stopping = true;
                true
            }
            // Sin sesion activa los eventos de Windows no producen transiciones.
            Some(ServiceEvent::Wts { .. }) => false,
        }
    }

    /// Espera `delay` atendiendo eventos. `true` si llego la parada.
    async fn pause(&mut self, delay: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + delay;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return false,
                event = self.events.recv() => if self.idle_event(event) { return true },
            }
        }
    }

    /// Bucle de registro y sesiones hasta `ServiceEvent::Stop`.
    pub async fn run(mut self, client: &RelayClient) {
        let Ok(id) = SessionId::parse(&self.target_id.to_string()) else {
            return;
        };
        let mut backoff = RETRY_MIN;
        while !self.stopping {
            let registered = tokio::select! {
                r = client.register_host(id) => r,
                event = self.events.recv() => {
                    self.idle_event(event);
                    continue;
                }
            };
            match registered {
                Ok(registration) => {
                    backoff = RETRY_MIN;
                    let paired = {
                        let wait = registration.wait_for_operator();
                        tokio::pin!(wait);
                        loop {
                            tokio::select! {
                                paired = &mut wait => break Some(paired),
                                event = self.events.recv() => if self.idle_event(event) { break None },
                            }
                        }
                    };
                    match paired {
                        None => return,
                        Some(Ok(stream)) => self.serve(stream).await,
                        // Caduco sin operador: se registra de nuevo.
                        Some(Err(ClientError::Relay(RelayError::Expired))) => {}
                        Some(Err(_)) => {
                            if self.pause(backoff).await {
                                return;
                            }
                            backoff = (backoff * 2).min(RETRY_MAX);
                        }
                    }
                }
                // ID ocupado (registro previo aun no liberado): el ID es persistente, se espera.
                Err(_) => {
                    if self.pause(backoff).await {
                        return;
                    }
                    backoff = (backoff * 2).min(RETRY_MAX);
                }
            }
        }
    }

    /// Atiende un operador emparejado: handshake, autenticacion y, si se concede, la sesion.
    pub async fn serve(&mut self, mut stream: RelayedStream) {
        let hello = match timeout(self.timings.hello, stream.recv_frame()).await {
            Ok(Ok(bytes)) => decode_message::<UnattendedHello>(&bytes).ok(),
            _ => None,
        };
        let Some(hello) = hello else {
            stream.close();
            return;
        };
        let awaiting =
            match ServiceAwaitingPassword::respond(&hello, self.target_id, &self.identity) {
                Ok((awaiting, reply)) => {
                    let sent = match encode_message(&reply) {
                        Ok(bytes) => stream.send_frame(&bytes).await.is_ok(),
                        Err(_) => false,
                    };
                    if !sent {
                        stream.close();
                        return;
                    }
                    awaiting
                }
                Err((_, reply)) => {
                    // Version incompatible: se responde y se cierra sin contar intento. ID equivocado
                    // o efimero invalido: se cierra sin responder.
                    if let Some(reply) = reply
                        && let Ok(bytes) = encode_message(&reply)
                    {
                        let _ = stream.send_frame(&bytes).await;
                        stream.finish().await;
                    }
                    stream.close();
                    return;
                }
            };
        // Sin contrasena a tiempo (p. ej. el operador aborto por clave fijada distinta) no hay
        // intento: no se llama al autenticador.
        let record = match timeout(self.timings.password, stream.recv_frame()).await {
            Ok(Ok(record)) => record,
            _ => {
                stream.close();
                return;
            }
        };
        let operator = sanitize_audit_text(awaiting.operator_display_name());
        let fingerprint = awaiting.fingerprint();
        let console = self.platform.active_console_session();
        let pinned = console.and_then(|session| {
            self.platform
                .session_user_sid(session)
                .map(|user_sid| Pinned {
                    windows_session: session,
                    user_sid,
                    operator: operator.clone(),
                    fingerprint,
                })
        });
        let has_console = pinned.is_some();
        let auth = self.auth.clone();
        let audit = self.audit.clone();
        let op = operator.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            awaiting.handle_password_record(&record, |password| {
                if !has_console {
                    // Sin sesion de consola autorizable no se puede conceder: rechazo generico,
                    // auditado como un intento fallido (no se ejecuta el KDF).
                    let line = AuditRecord::new(unix_ms_now(), AuditEvent::AuthFailed, &op)
                        .with_source(THROTTLE_SOURCE);
                    let _ = audit
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .write_record(&line);
                    return UnattendedVerdict::Rejected { retry_after: None };
                }
                auth.lock().unwrap_or_else(|p| p.into_inner()).authenticate(
                    &op,
                    THROTTLE_SOURCE,
                    password,
                )
            })
        })
        .await;
        let session = match outcome {
            Ok(Ok(ServiceAuthOutcome::Granted {
                session,
                reply_record,
            })) => {
                if stream.send_frame(&reply_record).await.is_err() {
                    stream.close();
                    return;
                }
                session
            }
            Ok(Ok(ServiceAuthOutcome::Rejected { reply_record, .. })) => {
                let _ = stream.send_frame(&reply_record).await;
                stream.finish().await;
                stream.close();
                return;
            }
            _ => {
                stream.close();
                return;
            }
        };
        let Some(pinned) = pinned else {
            stream.close();
            return;
        };
        self.run_session(
            stream,
            session.channel,
            session.video,
            session.generation,
            pinned,
        )
        .await;
    }

    async fn run_session(
        &mut self,
        stream: RelayedStream,
        channel: SecureChannel,
        sealer: VideoSealer,
        generation: u32,
        pinned: Pinned,
    ) {
        let streams = stream.video_streams();
        let (sender, mut receiver) = stream.into_split();
        // Todo lo que va al operador pasa por un escritor propio con cola acotada: el bucle de la
        // sesion (revalidacion, eventos WTS, parada, agente) nunca espera al operador.
        let (mut out, writer) = OperatorOut::spawn(sender, channel);
        match self.tracker.start_session(
            pinned.windows_session,
            Some(generation),
            InputDesktopKind::Default,
        ) {
            Ok(step) => {
                if let Some(event) = step.audit {
                    self.audit(event, Some(&pinned));
                }
            }
            Err(_) => {
                let msg = HostToClientMessage::SessionRevoked {
                    reason: "Ya hay una sesion desatendida activa.".to_string(),
                };
                out.send(&msg);
                drop(out);
                self.flush_writer(writer).await;
                return;
            }
        }

        // Agente: pipe para el SID fijado, lanzamiento y comprobacion del PID del cliente.
        let started = self.start_agent(&pinned, generation).await;
        let (pipe_write, mut process, mut agent_rx, monitors) = match started {
            Ok(parts) => parts,
            Err((reason, process)) => {
                // Fallo del agente o PID ajeno en la pipe: queda auditado con su motivo.
                let step = self.tracker.end(reason);
                if let Some(event) = step.audit {
                    self.audit(event, Some(&pinned));
                }
                let msg = HostToClientMessage::SessionRevoked {
                    reason: end_text(reason).to_string(),
                };
                out.send(&msg);
                drop(out);
                if let Some(mut process) = process {
                    process.terminate();
                }
                self.flush_writer(writer).await;
                return;
            }
        };
        let mut pipe_write = pipe_write;

        // El operador recibe los monitores antes de cualquier fotograma (no hay ApprovalResult).
        let video_allowed = agent_rx.video_allowed.clone();
        let mut alive = out.send(&HostToClientMessage::DisplayTopologyChanged { monitors });
        if alive {
            alive = self
                .to_agent(&mut pipe_write, &ServiceToAgent::StartVideo)
                .await;
            video_allowed.store(true, Ordering::SeqCst);
        }
        let (video_fail_tx, mut video_fail_rx) = mpsc::unbounded_channel::<String>();
        let video_task = tokio::spawn(write_video(
            streams,
            sealer,
            agent_rx.video.take(),
            video_allowed.clone(),
            video_fail_tx,
        ));

        // El receptor de control no es seguro de cancelar: vive en su propia tarea.
        let (ctl_tx, mut ctl_rx) = mpsc::channel::<Vec<u8>>(64);
        let reader = tokio::spawn(async move {
            while let Ok(record) = receiver.recv_frame().await {
                if ctl_tx.send(record).await.is_err() {
                    break;
                }
            }
        });

        let mut revalidate = tokio::time::interval(self.timings.revalidate);
        revalidate.tick().await;
        let mut exit = if alive { None } else { Some(OPERATOR_GONE) };
        while exit.is_none() {
            tokio::select! {
                record = ctl_rx.recv() => {
                    let msg = record
                        .and_then(|r| out.channel.open(&r).ok())
                        .and_then(|plain| decode_message::<ClientToHostMessage>(&plain).ok());
                    exit = match msg {
                        None | Some(ClientToHostMessage::Disconnect { .. }) => Some(OPERATOR_GONE),
                        Some(msg) => self.operator_message(msg, &mut out, &mut pipe_write).await,
                    };
                }
                frame = agent_rx.messages.recv() => {
                    exit = match frame {
                        None => Some(AGENT_FAILED),
                        Some(msg) => self.agent_message(msg, &pinned, &mut out, &mut pipe_write, &video_allowed).await,
                    };
                }
                event = self.events.recv() => {
                    let step = match event {
                        Some(ServiceEvent::Wts { event_type, session_id }) => self.tracker.on_wts_event(event_type, session_id),
                        None | Some(ServiceEvent::Stop) => {
                            self.stopping = true;
                            self.tracker.stop()
                        }
                    };
                    exit = self.apply_step(step, &pinned, &mut out, &mut pipe_write, &video_allowed).await;
                }
                _ = revalidate.tick() => {
                    let auth = self.auth.clone();
                    let status = tokio::task::spawn_blocking(move || {
                        auth.lock().unwrap_or_else(|p| p.into_inner()).current_status()
                    })
                    .await
                    .unwrap_or(UnattendedStatus::NotConfigured);
                    let mut step = self.tracker.revalidate(status);
                    if self.tracker.is_active() {
                        let console = self.platform.active_console_session();
                        let sid = console.and_then(|s| self.platform.session_user_sid(s));
                        if console != Some(pinned.windows_session) || sid.as_deref() != Some(pinned.user_sid.as_str()) {
                            step = self.tracker.session_switched();
                        }
                    }
                    exit = self.apply_step(step, &pinned, &mut out, &mut pipe_write, &video_allowed).await;
                }
                Some(()) = agent_rx.keyframe_needed.recv() => {
                    if !self.to_agent(&mut pipe_write, &ServiceToAgent::KeyframeRequest).await {
                        exit = Some(AGENT_FAILED);
                    }
                }
                failure = video_fail_rx.recv() => {
                    if failure.is_some() {
                        exit = Some(AGENT_FAILED);
                    }
                }
            }
        }

        // Una escritura en la pipe falla si el agente ya salio tras avisar: un `KillSwitch` que ya
        // estaba en camino manda sobre ese fallo (el kill-switch se audita siempre como tal).
        if exit == Some(AGENT_FAILED) {
            let drain = async {
                while let Some(msg) = agent_rx.messages.recv().await {
                    if msg == AgentToService::KillSwitch {
                        return true;
                    }
                }
                false
            };
            if matches!(timeout(self.timings.pipe_write, drain).await, Ok(true)) {
                exit = Some(Exit::Service(EndReason::LocalKillSwitch));
            }
        }

        // Cierre: nada mas sale hacia el operador; aviso, parada ordenada del agente y cierre.
        video_allowed.store(false, Ordering::SeqCst);
        let exit = exit.unwrap_or(OPERATOR_GONE);
        let reason = end_text(exit.reason()).to_string();
        if let Exit::Service(end) = exit {
            // Motivo ajeno a Windows: el monitor se cierra aqui y se audita `SessionEnded`.
            let step = self.tracker.end(end);
            if let Some(event) = step.audit {
                self.audit(event, Some(&pinned));
            }
        }
        if !matches!(exit, Exit::Tracker(_) | OPERATOR_GONE) {
            out.send(&HostToClientMessage::SessionRevoked {
                reason: reason.clone(),
            });
        }
        // Sin mas envios: el escritor entrega lo que quede mientras el agente se detiene. La
        // parada del agente no depende de que el operador lea.
        drop(out);
        // Nada mas de video hacia el operador, aunque el escritor estuviera atascado.
        video_task.abort();
        self.stop_agent(
            &mut pipe_write,
            &mut agent_rx.messages,
            &mut process,
            reason,
        )
        .await;
        reader.abort();
        self.flush_writer(writer).await;
    }

    /// Espera al escritor de control como mucho `Timings::revalidate` y lo aborta despues.
    async fn flush_writer(&self, mut writer: tokio::task::JoinHandle<()>) {
        if timeout(self.timings.revalidate, &mut writer).await.is_err() {
            writer.abort();
        }
    }

    /// Crea la pipe, lanza el agente, comprueba el PID del cliente y espera sus monitores.
    #[allow(clippy::type_complexity)]
    async fn start_agent(
        &mut self,
        pinned: &Pinned,
        generation: u32,
    ) -> Result<
        (
            WriteHalf<<P::Acceptor as PipeAcceptor>::Stream>,
            P::Process,
            AgentRx,
            Vec<awawa_protocol::MonitorDescriptor>,
        ),
        (EndReason, Option<P::Process>),
    > {
        let unavailable = || EndReason::AgentFailed;
        let acceptor = self
            .platform
            .create_pipe(&pinned.user_sid)
            .map_err(|_| (unavailable(), None))?;
        let process = self
            .platform
            .launch_agent(pinned.windows_session, acceptor.name())
            .map_err(|_| (unavailable(), None))?;
        let accepted = timeout(self.timings.agent_connect, acceptor.accept()).await;
        let pipe = match accepted {
            Ok(Ok((pipe, client_pid))) if client_pid == process.pid() => pipe,
            // Otro proceso se conecto a la pipe: se cierra (al soltarla) y se termina el agente
            // propio.
            Ok(Ok(_)) => return Err((EndReason::ForeignPipeClient, Some(process))),
            // Nadie a tiempo o error de la pipe.
            _ => return Err((unavailable(), Some(process))),
        };
        let (read_half, mut write_half) = tokio::io::split(pipe);
        let mut rx = AgentRx::spawn(read_half);
        let start = ServiceToAgent::Start {
            service_id: self.target_id,
            operator_display_name: pinned.operator.clone(),
            session_fingerprint: pinned.fingerprint,
            generation,
        };
        if !self.to_agent(&mut write_half, &start).await {
            return Err((unavailable(), Some(process)));
        }
        match timeout(self.timings.agent_connect, rx.messages.recv()).await {
            Ok(Some(AgentToService::Started { monitors })) if !monitors.is_empty() => {
                Ok((write_half, process, rx, monitors))
            }
            _ => Err((unavailable(), Some(process))),
        }
    }

    async fn to_agent<W: AsyncWrite + Unpin>(&self, w: &mut W, msg: &ServiceToAgent) -> bool {
        matches!(
            timeout(self.timings.pipe_write, send_to_agent(w, msg)).await,
            Ok(Ok(()))
        )
    }

    /// Pide al agente que libere teclas y salga; `TerminateProcess` solo tras el plazo.
    async fn stop_agent<W: AsyncWrite + Unpin>(
        &self,
        pipe: &mut W,
        messages: &mut mpsc::Receiver<AgentToService>,
        process: &mut P::Process,
        reason: String,
    ) {
        let deadline = tokio::time::Instant::now() + self.timings.agent_exit;
        let _ = timeout(
            self.timings.agent_exit,
            send_to_agent(pipe, &ServiceToAgent::Stop { reason }),
        )
        .await;
        let mut pipe_open = true;
        loop {
            if process.has_exited() {
                return;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // `Stopped` o el cierre de la pipe indican que el agente esta saliendo.
            let wait = remaining.min(Duration::from_millis(50));
            if pipe_open {
                if let Ok(None) = timeout(wait, messages.recv()).await {
                    pipe_open = false;
                }
            } else {
                tokio::time::sleep(wait).await;
            }
        }
        process.terminate();
    }

    async fn operator_message<W: AsyncWrite + Unpin>(
        &mut self,
        msg: ClientToHostMessage,
        out: &mut OperatorOut,
        pipe: &mut W,
    ) -> Option<Exit> {
        match msg {
            ClientToHostMessage::Ping {
                seq,
                client_mono_us,
            } => {
                let pong = HostToClientMessage::Pong {
                    seq,
                    client_mono_us,
                };
                if !out.send(&pong) {
                    return Some(OPERATOR_GONE);
                }
                if !self.to_agent(pipe, &ServiceToAgent::OperatorPing).await {
                    return Some(AGENT_FAILED);
                }
                None
            }
            ClientToHostMessage::ControlRequest { .. } | ClientToHostMessage::Disconnect { .. } => {
                None
            }
            input => {
                // Suspendida (bloqueo, escritorio seguro): la entrada se descarta aqui y en el agente.
                if self.tracker.input_allowed()
                    && !self.to_agent(pipe, &ServiceToAgent::Input(input)).await
                {
                    return Some(AGENT_FAILED);
                }
                None
            }
        }
    }

    async fn agent_message<W: AsyncWrite + Unpin>(
        &mut self,
        msg: AgentToService,
        pinned: &Pinned,
        out: &mut OperatorOut,
        pipe: &mut W,
        video_allowed: &AtomicBool,
    ) -> Option<Exit> {
        match msg {
            AgentToService::Started { .. } => None,
            AgentToService::Control(
                msg @ (HostToClientMessage::CursorShapeUpdate { .. }
                | HostToClientMessage::DisplayTopologyChanged { .. }),
            ) => {
                if !self.tracker.capture_allowed() {
                    return None;
                }
                // Un aviso del agente que no cabe en un registro es un fallo del agente.
                if encode_message(&msg).map_or(true, |p| p.len() > MAX_CONTROL_PLAINTEXT) {
                    return Some(AGENT_FAILED);
                }
                if !out.send(&msg) {
                    return Some(OPERATOR_GONE);
                }
                None
            }
            // Cualquier otro mensaje de control del agente se descarta.
            AgentToService::Control(_) => None,
            AgentToService::InputDesktop(kind) => {
                let step = self.tracker.on_probe(kind.into());
                self.apply_step(step, pinned, out, pipe, video_allowed)
                    .await
            }
            AgentToService::KillSwitch => Some(Exit::Service(EndReason::LocalKillSwitch)),
            AgentToService::Failed { .. } => Some(AGENT_FAILED),
            AgentToService::Stopped => Some(AGENT_FAILED),
        }
    }

    /// Aplica un paso del monitor: auditoria, aviso al operador y orden al agente.
    async fn apply_step<W: AsyncWrite + Unpin>(
        &mut self,
        step: TrackerStep,
        pinned: &Pinned,
        out: &mut OperatorOut,
        pipe: &mut W,
        video_allowed: &AtomicBool,
    ) -> Option<Exit> {
        if let Some(event) = step.audit {
            self.audit(event, Some(pinned));
        }
        let mut ended = None;
        for action in step.actions {
            match action {
                MonitorAction::StopCapture => video_allowed.store(false, Ordering::SeqCst),
                MonitorAction::ReleaseHeldInput | MonitorAction::DropQueuedInput => {}
                MonitorAction::NotifyOperator(
                    OperatorNotice::LocalApprovalRequired | OperatorNotice::SessionLocked,
                ) => {
                    // Captura y entrada se detienen y se liberan las teclas en el agente.
                    let suspended = self.to_agent(pipe, &ServiceToAgent::Suspend).await;
                    if !out.send(&HostToClientMessage::LocalApprovalRequired) {
                        return Some(OPERATOR_GONE);
                    }
                    if !suspended {
                        return Some(AGENT_FAILED);
                    }
                }
                MonitorAction::NotifyOperator(OperatorNotice::Resumed) => {
                    if !out.send(&HostToClientMessage::LocalApprovalCleared) {
                        return Some(OPERATOR_GONE);
                    }
                }
                MonitorAction::ResumeCapture { force_keyframe } => {
                    video_allowed.store(true, Ordering::SeqCst);
                    if !self
                        .to_agent(pipe, &ServiceToAgent::Resume { force_keyframe })
                        .await
                    {
                        return Some(AGENT_FAILED);
                    }
                }
                MonitorAction::NotifyOperator(OperatorNotice::SessionEnded { reason }) => {
                    let msg = HostToClientMessage::SessionRevoked {
                        reason: end_text(reason).to_string(),
                    };
                    out.send(&msg);
                    ended = Some(Exit::Tracker(reason));
                }
                MonitorAction::TerminateAgent => {
                    // El cierre ordenado lo hace `run_session` al salir del bucle.
                    if ended.is_none() {
                        ended = Some(Exit::Tracker(EndReason::ServiceStopping));
                    }
                }
            }
        }
        ended
    }
}

/// Lectura de la pipe del agente: el video va directo al escritor (solo si esta permitido) y el
/// resto a la sesion.
struct AgentRx {
    messages: mpsc::Receiver<AgentToService>,
    video: Option<mpsc::Receiver<AgentVideo>>,
    video_allowed: Arc<AtomicBool>,
    /// Aviso (coalescido) de que se descarto un fotograma: el agente debe enviar uno clave.
    keyframe_needed: mpsc::Receiver<()>,
}

/// Fotogramas en cola entre el lector de la pipe y el escritor de video. Si el operador no
/// consume video la cola se llena y el lector descarta (antes de sellar: sin huecos de contador)
/// en vez de esperar, de modo que los avisos del agente siguen llegando.
pub const SERVICE_VIDEO_QUEUE: usize = 4;

impl AgentRx {
    fn spawn<R: AsyncRead + Unpin + Send + 'static>(mut read: R) -> Self {
        let (msg_tx, messages) = mpsc::channel(64);
        let (video_tx, video) = mpsc::channel(SERVICE_VIDEO_QUEUE);
        let (keyframe_tx, keyframe_needed) = mpsc::channel(1);
        let video_allowed = Arc::new(AtomicBool::new(false));
        let allowed = video_allowed.clone();
        tokio::spawn(async move {
            while let Ok(frame) = recv_from_agent(&mut read).await {
                match frame {
                    AgentFrame::Video(v) => {
                        // Fuera de `Streaming` (o antes de anunciar los monitores) no sale video.
                        // Nunca se espera al escritor de video: con la cola llena (o el escritor
                        // ya terminado) el fotograma se descarta y se pide uno clave.
                        if allowed.load(Ordering::SeqCst) && video_tx.try_send(v).is_err() {
                            let _ = keyframe_tx.try_send(());
                        }
                    }
                    AgentFrame::Message(m) => {
                        if msg_tx.send(m).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            messages,
            video: Some(video),
            video_allowed,
            keyframe_needed,
        }
    }
}

/// Registros de control en cola hacia el operador. Con la cola llena (el operador no lee) el
/// bucle nunca espera: los mensajes efimeros (`Pong`, cursor) se descartan y cualquier otro
/// cierra la sesion como `OperatorDisconnected`. El ultimo hueco queda reservado para el aviso
/// terminal (`SessionRevoked`), que asi siempre se encola.
pub const CONTROL_QUEUE: usize = 32;

/// Canal de control hacia el operador: sella en orden y encola sin esperar.
struct OperatorOut {
    channel: SecureChannel,
    tx: mpsc::Sender<Vec<u8>>,
}

impl OperatorOut {
    /// Arranca el escritor dedicado, que es el unico que espera al operador.
    fn spawn(
        mut sender: RelayedSender,
        channel: SecureChannel,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CONTROL_QUEUE);
        let writer = tokio::spawn(async move {
            while let Some(record) = rx.recv().await {
                if sender.send_frame(&record).await.is_err() {
                    break;
                }
            }
            sender.finish().await;
            sender.close();
        });
        (Self { channel, tx }, writer)
    }

    /// Sella y encola sin esperar. `false` si el operador ya no es utilizable (canal roto o cola
    /// llena con un mensaje no descartable) o si el mensaje no cabe en un registro (nunca se
    /// omite en silencio: el llamador cierra la sesion).
    fn send(&mut self, msg: &HostToClientMessage) -> bool {
        let Ok(plain) = encode_message(msg) else {
            return false;
        };
        if plain.len() > MAX_CONTROL_PLAINTEXT {
            return false;
        }
        let terminal = matches!(msg, HostToClientMessage::SessionRevoked { .. });
        // Solo el aviso terminal puede ocupar el ultimo hueco.
        if !terminal && self.tx.capacity() <= 1 {
            return matches!(
                msg,
                HostToClientMessage::Pong { .. } | HostToClientMessage::CursorShapeUpdate { .. }
            );
        }
        // Primero el hueco en la cola y despues el sellado: un mensaje descartado no consume
        // contador y el operador no ve huecos en la secuencia.
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                return matches!(
                    msg,
                    HostToClientMessage::Pong { .. }
                        | HostToClientMessage::CursorShapeUpdate { .. }
                );
            }
            Err(mpsc::error::TrySendError::Closed(())) => return false,
        };
        match self.channel.seal(&plain) {
            Ok(record) => {
                permit.send(record);
                true
            }
            Err(_) => false,
        }
    }
}

/// Escribe el video del agente en streams unidireccionales sellados.
async fn write_video(
    streams: VideoStreams,
    mut sealer: VideoSealer,
    packets: Option<mpsc::Receiver<AgentVideo>>,
    allowed: Arc<AtomicBool>,
    failed: mpsc::UnboundedSender<String>,
) {
    let Some(mut packets) = packets else {
        return;
    };
    let mut current = None;
    while let Some(packet) = packets.recv().await {
        // Un fotograma que llego justo antes de suspender o cerrar no sale.
        if !allowed.load(Ordering::SeqCst) {
            continue;
        }
        if current.is_none() {
            let Ok(stream_sealer) = sealer.open_stream() else {
                let _ = failed.send("video: sellador agotado".to_string());
                return;
            };
            let opened = match streams.open().await {
                Ok(mut stream) => stream
                    .write_all(&stream_sealer.preamble())
                    .await
                    .map(|()| stream),
                Err(e) => Err(e),
            };
            match opened {
                Ok(stream) => current = Some((stream, stream_sealer)),
                Err(e) => {
                    let _ = failed.send(format!("video: {e}"));
                    return;
                }
            }
        }
        let Some((stream, stream_sealer)) = current.as_mut() else {
            continue;
        };
        let Ok(record) = stream_sealer.seal(&packet.header, &packet.payload) else {
            current = None;
            continue;
        };
        // Lo sellado se escribe siempre: omitirlo dejaria un hueco en el contador del stream y el
        // operador cerraria la sesion. La suspension se aplica antes de sellar (arriba); el fin
        // de la sesion aborta esta tarea.
        if let Err(e) = stream.write_all(&record).await {
            let _ = failed.send(format!("video: {e}"));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_ops::AdminOps;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};
    use awawa_protocol::audit::MemoryAuditSink;
    use awawa_protocol::unattended::KdfError;

    struct FastKdf;
    impl PasswordKdf for FastKdf {
        fn derive(
            &self,
            password: &[u8],
            salt: &[u8; 16],
            _params: awawa_protocol::unattended::VerifierKdfParams,
            out: &mut [u8; 32],
        ) -> Result<(), KdfError> {
            for (i, o) in out.iter_mut().enumerate() {
                *o = password[i % password.len()] ^ salt[i % 16];
            }
            Ok(())
        }
    }

    /// El autenticador de produccion: veredicto generico y un registro por intento.
    #[test]
    fn store_auth_audita_cada_intento_y_responde_generico() {
        let tmp = TempDir::new("storeauth");
        let dir = safe_dir(&tmp);
        let store = VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        );
        let memory = Arc::new(Mutex::new(MemoryAuditSink::new()));
        let audit: SharedAudit = memory.clone();
        let mut auth = StoreAuth {
            store: store.clone(),
            authenticator: UnattendedAuthenticator::default(),
            kdf: Box::new(FastKdf),
            audit,
        };
        let good = "clave-desatendida-1";
        // Sin configurar.
        assert_eq!(
            auth.authenticate("op", THROTTLE_SOURCE, good),
            UnattendedVerdict::Rejected { retry_after: None }
        );
        let mut admin_sink = MemoryAuditSink::new();
        AdminOps {
            store: &store,
            kdf: &FastKdf,
            sink: &mut admin_sink,
            operator: "admin:test",
        }
        .set_password(good)
        .unwrap();
        assert_eq!(
            auth.current_status(),
            UnattendedStatus::Enabled { generation: 1 }
        );
        assert_eq!(
            auth.authenticate("op", THROTTLE_SOURCE, good),
            UnattendedVerdict::Granted { generation: 1 }
        );
        for _ in 0..3 {
            assert_eq!(
                auth.authenticate("op", THROTTLE_SOURCE, "otra-clave-larga"),
                UnattendedVerdict::Rejected { retry_after: None }
            );
        }
        assert!(matches!(
            auth.authenticate("op", THROTTLE_SOURCE, good),
            UnattendedVerdict::Rejected {
                retry_after: Some(_)
            }
        ));
        let lines = memory.lock().unwrap().lines.clone();
        assert_eq!(lines.len(), 6, "un registro por intento");
        assert!(lines.iter().all(|l| l.contains("\"source\":\"relay\"")));
        assert!(lines.last().unwrap().contains("auth_throttled"));
        assert!(!lines.join("\n").contains(good));
    }

    #[test]
    fn textos_de_fin_por_motivo() {
        assert!(end_text(EndReason::CredentialRevoked).contains("revocada"));
        assert!(end_text(EndReason::SessionSwitched).contains("autenticarse otra vez"));
    }

    /// Canal de control real del servicio (handshake en memoria con la API publica).
    fn service_channel() -> SecureChannel {
        use awawa_protocol::OperatorUnattendedHandshake;
        let identity = SigningKey::from_bytes(&[5u8; 32]);
        let (operator, hello) =
            OperatorUnattendedHandshake::start(123_456_789, "op", &identity.verifying_key())
                .unwrap();
        let (service, reply) =
            ServiceAwaitingPassword::respond(&hello, 123_456_789, &identity).unwrap();
        let pending = operator.handle_reply(&reply).unwrap();
        let (_awaiting, record) = pending
            .send_password(zeroize::Zeroizing::new("clave".to_string()))
            .unwrap();
        match service
            .handle_password_record(&record, |_| UnattendedVerdict::Granted { generation: 1 })
            .unwrap()
        {
            ServiceAuthOutcome::Granted { session, .. } => session.channel,
            ServiceAuthOutcome::Rejected { .. } => unreachable!(),
        }
    }

    /// El ultimo hueco de la cola queda para el aviso terminal; los efimeros se descartan,
    /// los demas cierran la sesion, y un mensaje demasiado grande nunca se omite en silencio.
    #[test]
    fn la_cola_de_control_reserva_hueco_para_el_aviso_terminal() {
        let (tx, mut rx) = mpsc::channel(CONTROL_QUEUE);
        let mut out = OperatorOut {
            channel: service_channel(),
            tx,
        };
        let pong = HostToClientMessage::Pong {
            seq: 1,
            client_mono_us: 2,
        };
        for _ in 0..CONTROL_QUEUE - 1 {
            assert!(out.send(&pong));
        }
        // Queda un hueco: solo para el aviso terminal.
        assert!(out.send(&pong), "el Pong se descarta sin cerrar");
        assert!(
            !out.send(&HostToClientMessage::LocalApprovalRequired),
            "un aviso no descartable sin hueco cierra la sesion"
        );
        assert!(out.send(&HostToClientMessage::SessionRevoked {
            reason: "fin".to_string()
        }));
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, CONTROL_QUEUE);
        let huge = HostToClientMessage::SessionRevoked {
            reason: "x".repeat(MAX_CONTROL_PLAINTEXT + 1),
        };
        assert!(
            !out.send(&huge),
            "demasiado grande: no se omite en silencio"
        );
    }
}
