//! Logica del agente de sesion, separada de la UI y de los backends de Windows.
//!
//! El agente no tiene claves: la red, el canal E2E y el sellado del video son del servicio. Por la
//! pipe ([`awawa_service::agent_pipe`]) recibe ordenes y devuelve monitores, fotogramas ya
//! codificados, cursor, topologia, sondeos del escritorio de entrada y el kill-switch.
//!
//! - Sin `Start` no hay sesion en la compuerta: ni captura ni entrada. El primer mensaje debe ser
//!   `Start`; cualquier otro cierra el agente (falla cerrado).
//! - Con `Start` construye la sesion con `ApprovedActiveSession::for_session_agent` y la activa en
//!   la `SessionGate` de awawa-host (incluida por ruta), que aplica el escritorio seguro, el
//!   heartbeat (`OperatorPing`), la guardia de ventanas protegidas y la liberacion de teclas.
//! - La captura corre en su hilo, sondea el escritorio de entrada cada 250 ms y envia cada sondeo
//!   al servicio (su monitor necesita sondeos seguidos para reanudar). No sale ningun fotograma
//!   antes de `StartVideo`.
//! - `Suspend` libera teclas y detiene captura y entrada; `Resume` reanuda con fotograma clave;
//!   `Stop` revoca (libera teclas), confirma con `Stopped` y sale.
//! - El kill-switch revoca la compuerta al instante desde el hilo que lo detecta, avisa con
//!   `KillSwitch` y el agente sale sin esperar a la UI.
//! - Avisos que no caben: un `CursorShapeUpdate` que no cabe en una trama de la pipe o en un
//!   registro del canal hacia el operador se omite antes de encolarlo (como en el host) y la sesion
//!   sigue con la forma anterior. Cualquier otro aviso (`Started`, `InputDesktop`,
//!   `DisplayTopologyChanged`, `KillSwitch`, `Failed`, `Stopped`) no se omite: se envia un `Failed`
//!   corto en su lugar y la sesion termina.
//! - Si el escritor de la pipe termina (error de escritura) la sesion termina: el bucle revoca la
//!   compuerta (libera teclas) y sale; la captura avisa con `Failed` en lugar de salir en silencio.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use awawa_protocol::consent_fsm::SessionAgentGrant;
use awawa_protocol::{
    ApprovedActiveSession, ClientToHostMessage, HostToClientMessage, InputDesktopKind, KeyState,
    MonitorDescriptor, NormalizedPoint, RemoteInputCommand, SessionId, VideoCodec,
    VideoPacketHeader, VirtualDesktopBounds, encode_message,
};
use awawa_service::agent_pipe::{
    AgentToService, AgentVideo, MAX_AGENT_CONTROL_FRAME, PIPE_PREFIX, ServiceToAgent,
    recv_from_service, send_to_service, send_video,
};
use awawa_service::unattended_net::MAX_CONTROL_PLAINTEXT;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::gate::SessionGate;
use crate::net::{SourceError, VideoSource, VideoSourceFactory};

/// Periodo del sondeo del escritorio de entrada.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// Periodo del dead-man switch de la entrada.
pub const HEARTBEAT_TICK: Duration = Duration::from_millis(250);
/// Periodo de la revision de la topologia de monitores.
pub const TOPOLOGY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Tiempo maximo sin un fotograma valido antes de declarar la captura no disponible.
pub const CAPTURE_FAILURE_LIMIT: Duration = Duration::from_secs(3);
/// Plazo para recibir `Start` tras conectar a la pipe.
pub const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Plazo para que el banner pinte su primer cuadro con el atajo global armado una vez recibido
/// `Start`. Si vence, el agente envia `Failed` y no hay sesion.
pub const UI_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Lo que muestra el banner.
#[derive(Debug, Clone, Default)]
pub struct BannerInfo {
    /// Nombre del operador (ya saneado por el servicio); `None` hasta recibir `Start`.
    pub operator: Option<String>,
    pub started_at: Option<Instant>,
}

/// Parada local pedida desde la UI o el atajo global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalStop {
    /// Boton "Revocar control ahora", atajo global o intento de cerrar/minimizar el banner.
    KillSwitch,
    /// No se pudo registrar ningun atajo global: sin kill-switch completo no hay sesion.
    HotkeyUnavailable,
}

/// Kill-switch clonable: revoca la compuerta al instante (desde cualquier hilo) y avisa al bucle.
#[derive(Clone)]
pub struct KillSwitch {
    gate: SessionGate,
    tx: mpsc::UnboundedSender<LocalStop>,
    fired: Arc<AtomicBool>,
}

/// Lado del bucle del kill-switch: el aviso y una marca persistente que se pone ANTES de revocar,
/// de modo que una activacion posterior de la compuerta la ve y no queda activa.
pub struct LocalStopRx {
    rx: mpsc::UnboundedReceiver<LocalStop>,
    fired: Arc<AtomicBool>,
}

impl LocalStopRx {
    pub async fn recv(&mut self) -> Option<LocalStop> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Result<LocalStop, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// `true` si el kill-switch se pulso alguna vez.
    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl KillSwitch {
    pub fn new(gate: SessionGate) -> (Self, LocalStopRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let fired = Arc::new(AtomicBool::new(false));
        (
            Self {
                gate,
                tx,
                fired: fired.clone(),
            },
            LocalStopRx { rx, fired },
        )
    }

    pub fn trigger(&self, why: LocalStop) {
        // Primero la marca persistente y la marca atomica de la compuerta: video y entrada se
        // detienen ya, y una activacion que llegue despues no deja la compuerta activa.
        self.fired.store(true, Ordering::SeqCst);
        self.gate
            .revoke("El usuario local revoco el control", Instant::now());
        let _ = self.tx.send(why);
    }
}

/// Configuracion del agente.
pub struct AgentConfig {
    pub gate: SessionGate,
    pub video: VideoSourceFactory,
    /// `true` si una ventana protegida (el banner) tiene el foco: se descartan las pulsaciones.
    pub keyboard_blocked: Arc<dyn Fn() -> bool + Send + Sync>,
    pub banner: Arc<Mutex<BannerInfo>>,
    pub local_stop: LocalStopRx,
    /// `true` cuando el banner pinto su primer cuadro con el atajo global armado. Sin esa senal
    /// no se activa la compuerta ni se anuncian monitores.
    pub ui_ready: watch::Receiver<bool>,
    /// Plazo para esa senal tras recibir `Start` ([`UI_READY_TIMEOUT`] en produccion).
    pub ui_ready_timeout: Duration,
}

/// Motivo de salida del agente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentExit {
    /// El primer mensaje no fue `Start` (o no llego): sin sesion.
    NoStart,
    /// El servicio pidio `Stop`.
    Stopped,
    KillSwitch,
    /// La pipe se cerro.
    PipeClosed,
    Failed(String),
}

impl AgentExit {
    pub fn code(&self) -> i32 {
        match self {
            Self::Stopped | Self::KillSwitch => 0,
            Self::NoStart => 3,
            Self::PipeClosed => 4,
            Self::Failed(_) => 5,
        }
    }
}

/// Abre la pipe del servicio con `GENERIC_READ | FILE_WRITE_DATA` (la DACL no concede mas al
/// usuario), E/S solapada para tokio y calidad de servicio de solo identificacion: el servidor no
/// puede suplantar al usuario.
pub fn open_service_pipe(name: &str) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_WRITE_DATA: u32 = 0x2;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    let valid = name.len() == PIPE_PREFIX.len() + 32
        && name.starts_with(PIPE_PREFIX)
        && name[PIPE_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit());
    if !valid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "nombre de pipe invalido",
        ));
    }
    std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | FILE_WRITE_DATA)
        .custom_flags(FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
        .open(name)
}

/// Salidas del hilo de captura.
enum CaptureOut {
    Started(Vec<MonitorDescriptor>),
    Control(HostToClientMessage),
    Probe(InputDesktopKind),
    Failed(String),
}

/// Fotogramas en cola hacia la pipe. Con la cola llena (el servicio u operador no consumen) se
/// descarta el fotograma y se pide uno clave; los avisos nunca se descartan.
pub const VIDEO_QUEUE: usize = 2;
/// Plazo para entregar los ultimos avisos (`Stopped`, `KillSwitch`, `Failed`) al salir.
pub const FINAL_FLUSH: Duration = Duration::from_secs(2);

/// Escritor propio de la pipe: el bucle del agente nunca espera a la pipe.
struct AgentOut {
    messages: mpsc::UnboundedSender<AgentToService>,
    video: mpsc::Sender<AgentVideo>,
}

impl AgentOut {
    fn spawn<W>(mut write: W) -> (Self, tokio::task::JoinHandle<()>)
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (messages, mut messages_rx) = mpsc::unbounded_channel::<AgentToService>();
        let (video, mut video_rx) = mpsc::channel::<AgentVideo>(VIDEO_QUEUE);
        let writer = tokio::spawn(async move {
            let mut video_open = true;
            loop {
                tokio::select! {
                    // Los avisos tienen prioridad sobre el video.
                    biased;
                    message = messages_rx.recv() => {
                        let Some(message) = message else { break };
                        if send_to_service(&mut write, &message).await.is_err() {
                            break;
                        }
                    }
                    frame = video_rx.recv(), if video_open => match frame {
                        Some(frame) => {
                            if send_video(&mut write, &frame).await.is_err() {
                                break;
                            }
                        }
                        None => video_open = false,
                    },
                }
            }
        });
        (Self { messages, video }, writer)
    }

    /// Encola un aviso. Devuelve `Some(salida)` si la sesion debe terminar:
    /// - el escritor de la pipe ya termino (cola cerrada): `PipeClosed`;
    /// - el aviso no cabe y no se puede omitir: se encola un `Failed` corto en su lugar.
    ///
    /// Un `CursorShapeUpdate` que no cabe se omite (como en el host) y la sesion sigue.
    fn send(&self, message: AgentToService) -> Option<AgentExit> {
        if !fits(&message) {
            if matches!(
                message,
                AgentToService::Control(HostToClientMessage::CursorShapeUpdate { .. })
            ) {
                return self.messages.is_closed().then_some(AgentExit::PipeClosed);
            }
            let reason = OVERSIZED_NOTICE.to_string();
            let _ = self.messages.send(AgentToService::Failed {
                reason: reason.clone(),
            });
            return Some(AgentExit::Failed(reason));
        }
        self.messages
            .send(message)
            .is_err()
            .then_some(AgentExit::PipeClosed)
    }
}

/// Motivo de la revocacion cuando un aviso no se pudo entregar al servicio.
const WRITER_LOST: &str = "Canal con el servicio no disponible";

/// Motivo del `Failed` que sustituye a un aviso que no cabe y no se puede omitir.
const OVERSIZED_NOTICE: &str = "aviso del agente demasiado grande";

/// `true` si el aviso cabe en una trama de la pipe y, si lleva un mensaje para el operador, en un
/// registro del canal (el servicio terminaria la sesion con uno mayor).
fn fits(message: &AgentToService) -> bool {
    let pipe = encode_message(message).is_ok_and(|b| b.len() < MAX_AGENT_CONTROL_FRAME);
    match message {
        AgentToService::Control(msg) => {
            pipe && encode_message(msg).is_ok_and(|b| b.len() <= MAX_CONTROL_PLAINTEXT)
        }
        _ => pipe,
    }
}

/// Ejecuta el agente sobre la pipe hasta que la sesion termine.
pub async fn run_agent<S>(pipe: S, mut cfg: AgentConfig) -> AgentExit
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut read, write) = tokio::io::split(pipe);
    // El lector no es seguro de cancelar: vive en su propia tarea.
    let (orders_tx, mut orders) = mpsc::channel::<ServiceToAgent>(64);
    let reader = tokio::spawn(async move {
        while let Ok(order) = recv_from_service(&mut read).await {
            if orders_tx.send(order).await.is_err() {
                break;
            }
        }
    });
    let (out, writer) = AgentOut::spawn(write);
    let exit = session(&mut cfg, &mut orders, &out).await;
    // En cualquier salida la compuerta queda revocada (idempotente) y la captura se detiene.
    cfg.gate.revoke("Fin del agente", Instant::now());
    // Ultimos avisos: se entregan con plazo; el video pendiente se descarta.
    drop(out);
    let mut writer = writer;
    if timeout(FINAL_FLUSH, &mut writer).await.is_err() {
        writer.abort();
    }
    reader.abort();
    exit
}

async fn session(
    cfg: &mut AgentConfig,
    orders: &mut mpsc::Receiver<ServiceToAgent>,
    out: &AgentOut,
) -> AgentExit {
    let first = tokio::select! {
        order = timeout(START_TIMEOUT, orders.recv()) => order.ok().flatten(),
        stop = cfg.local_stop.recv() => return local_exit(out, stop),
    };
    let Some(ServiceToAgent::Start {
        service_id,
        operator_display_name,
        session_fingerprint,
        generation,
    }) = first
    else {
        return AgentExit::NoStart;
    };
    let Ok(session_id) = SessionId::parse(&service_id.to_string()) else {
        return AgentExit::NoStart;
    };
    // El banner tiene que estar visible y el atajo global armado antes de activar nada. Mientras
    // tanto la entrada que llegue se descarta.
    let deadline = tokio::time::Instant::now() + cfg.ui_ready_timeout;
    loop {
        if *cfg.ui_ready.borrow_and_update() {
            break;
        }
        tokio::select! {
            changed = cfg.ui_ready.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
            order = orders.recv() => match order {
                None => return AgentExit::PipeClosed,
                Some(ServiceToAgent::Stop { .. }) => {
                    out.send(AgentToService::Stopped);
                    return AgentExit::Stopped;
                }
                Some(_) => {}
            },
            stop = cfg.local_stop.recv() => return local_exit(out, stop),
        }
    }
    if !*cfg.ui_ready.borrow() {
        let reason = "banner o atajo global no disponibles".to_string();
        out.send(AgentToService::Failed {
            reason: reason.clone(),
        });
        return AgentExit::Failed(reason);
    }
    let now = Instant::now();
    let grant = SessionAgentGrant::from_service_pipe(
        generation,
        operator_display_name.clone(),
        session_fingerprint,
    );
    if cfg.local_stop.fired() {
        return local_exit(out, cfg.local_stop.try_recv().ok());
    }
    cfg.gate.activate(
        ApprovedActiveSession::for_session_agent(grant, session_id, now, None),
        now,
    );
    // Un kill-switch pulsado entre la comprobacion anterior y `activate` dejo su marca antes de
    // intentar revocar: se revoca aqui y no se anuncia nada.
    if cfg.local_stop.fired() {
        cfg.gate
            .revoke("El usuario local revoco el control", Instant::now());
        return local_exit(out, cfg.local_stop.try_recv().ok());
    }
    {
        let mut banner = cfg.banner.lock().unwrap_or_else(|p| p.into_inner());
        banner.operator = Some(operator_display_name);
        banner.started_at = Some(now);
    }

    let suspended = Arc::new(AtomicBool::new(false));
    let keyframe = Arc::new(AtomicBool::new(false));
    let (go_tx, go_rx) = std_mpsc::channel::<()>();
    let (capture_tx, mut capture_rx) = mpsc::unbounded_channel::<CaptureOut>();
    {
        let gate = cfg.gate.clone();
        let video = cfg.video.clone();
        let packets = out.video.clone();
        let suspended = suspended.clone();
        let keyframe = keyframe.clone();
        let _ = thread::Builder::new()
            .name("agent-capture".to_string())
            .spawn(move || {
                capture_loop(gate, video, capture_tx, packets, go_rx, suspended, keyframe)
            });
    }

    let mut go = Some(go_tx);
    let mut bounds: Option<VirtualDesktopBounds> = None;
    let mut pointer_px = (0i32, 0i32);
    let mut heartbeat = tokio::time::interval(HEARTBEAT_TICK);
    let mut capture_running = true;
    loop {
        tokio::select! {
            order = orders.recv() => {
                let Some(order) = order else {
                    return AgentExit::PipeClosed;
                };
                match order {
                    ServiceToAgent::Start { .. } => {}
                    ServiceToAgent::StartVideo => {
                        if let Some(go) = go.take() {
                            let _ = go.send(());
                        }
                    }
                    ServiceToAgent::KeyframeRequest => keyframe.store(true, Ordering::SeqCst),
                    ServiceToAgent::Input(msg) => {
                        if !suspended.load(Ordering::SeqCst)
                            && let Some(cmd) = to_command(msg, bounds.as_ref(), &mut pointer_px)
                        {
                            let blocked = matches!(cmd, RemoteInputCommand::Keyboard { state: KeyState::Down, .. })
                                && (cfg.keyboard_blocked)();
                            if !blocked {
                                // Sin sesion o suspendida, la compuerta la descarta.
                                let _ = cfg.gate.dispatch(&cmd, Instant::now());
                            }
                        }
                    }
                    ServiceToAgent::OperatorPing => cfg.gate.record_ping(Instant::now()),
                    ServiceToAgent::Suspend => {
                        suspended.store(true, Ordering::SeqCst);
                        // Detiene captura y entrada en la compuerta y libera lo retenido.
                        cfg.gate.observe_input_desktop(InputDesktopKind::SecureOrOther);
                    }
                    ServiceToAgent::Resume { force_keyframe } => {
                        if force_keyframe {
                            keyframe.store(true, Ordering::SeqCst);
                        }
                        suspended.store(false, Ordering::SeqCst);
                    }
                    ServiceToAgent::Stop { reason } => {
                        cfg.gate.revoke(&reason, Instant::now());
                        out.send(AgentToService::Stopped);
                        return AgentExit::Stopped;
                    }
                }
            }
            captured = capture_rx.recv(), if capture_running => {
                let notice = match captured {
                    Some(CaptureOut::Started(monitors)) => {
                        bounds = VirtualDesktopBounds::from_monitors(&monitors);
                        Some(AgentToService::Started { monitors })
                    }
                    Some(CaptureOut::Control(msg)) => {
                        if let HostToClientMessage::DisplayTopologyChanged { monitors } = &msg {
                            bounds = VirtualDesktopBounds::from_monitors(monitors);
                        }
                        Some(AgentToService::Control(msg))
                    }
                    Some(CaptureOut::Probe(kind)) => Some(AgentToService::InputDesktop(kind.into())),
                    Some(CaptureOut::Failed(reason)) => {
                        cfg.gate.revoke("Captura no disponible", Instant::now());
                        out.send(AgentToService::Failed { reason: reason.clone() });
                        return AgentExit::Failed(reason);
                    }
                    // El hilo de captura termino (compuerta cerrada): se espera la orden del servicio.
                    None => {
                        capture_running = false;
                        None
                    }
                };
                if let Some(exit) = notice.and_then(|notice| out.send(notice)) {
                    cfg.gate.revoke(WRITER_LOST, Instant::now());
                    return exit;
                }
            }
            // El escritor de la pipe termino: sin canal hacia el servicio no hay sesion.
            _ = out.messages.closed() => {
                cfg.gate.revoke(WRITER_LOST, Instant::now());
                return AgentExit::PipeClosed;
            }
            _ = heartbeat.tick() => {
                cfg.gate.tick_heartbeat(Instant::now());
            }
            stop = cfg.local_stop.recv() => return local_exit(out, stop),
        }
    }
}

/// Salida por kill-switch o por falta de atajo global (la compuerta ya esta revocada).
fn local_exit(out: &AgentOut, stop: Option<LocalStop>) -> AgentExit {
    match stop {
        Some(LocalStop::HotkeyUnavailable) => {
            let reason = "atajo global de revocacion no disponible".to_string();
            out.send(AgentToService::Failed {
                reason: reason.clone(),
            });
            AgentExit::Failed(reason)
        }
        Some(LocalStop::KillSwitch) | None => {
            out.send(AgentToService::KillSwitch);
            AgentExit::KillSwitch
        }
    }
}

/// Traduce la entrada del operador a un comando (las demas variantes se descartan).
fn to_command(
    msg: ClientToHostMessage,
    bounds: Option<&VirtualDesktopBounds>,
    pointer_px: &mut (i32, i32),
) -> Option<RemoteInputCommand> {
    Some(match msg {
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
        } => RemoteInputCommand::Keyboard {
            scancode,
            extended,
            unicode_char: unicode_fallback,
            state,
        },
        ClientToHostMessage::ControlRequest { .. }
        | ClientToHostMessage::Ping { .. }
        | ClientToHostMessage::Disconnect { .. } => return None,
    })
}

fn capture_loop(
    gate: SessionGate,
    video: VideoSourceFactory,
    out: mpsc::UnboundedSender<CaptureOut>,
    packets: mpsc::Sender<AgentVideo>,
    go: std_mpsc::Receiver<()>,
    suspended: Arc<AtomicBool>,
    keyframe_request: Arc<AtomicBool>,
) {
    let mut source = match video() {
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
    // Ningun fotograma antes de que el operador tenga los monitores (`StartVideo`).
    if go.recv().is_err() {
        return;
    }
    let started = Instant::now();
    let mut frame_seq = 0u64;
    let mut keyframe = vec![true; monitors.len()];
    let mut last_probe: Option<Instant> = None;
    let mut last_topology = Instant::now();
    let mut failing_since: Option<Instant> = None;
    while gate.is_active() {
        if last_probe.is_none_or(|t| t.elapsed() >= PROBE_INTERVAL) {
            last_probe = Some(Instant::now());
            let kind = source.probe_input_desktop();
            if gate.observe_input_desktop(kind).resumed {
                keyframe.iter_mut().for_each(|k| *k = true);
            }
            let _ = out.send(CaptureOut::Probe(kind));
        }
        if keyframe_request.swap(false, Ordering::SeqCst) {
            keyframe.iter_mut().for_each(|k| *k = true);
        }
        if suspended.load(Ordering::SeqCst) || !gate.capture_allowed() {
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
            let Some(result) = gate.with_session(|session, desktop| {
                // Bajo el candado de la compuerta: si entre la comprobacion de arriba y aqui llego
                // una suspension (orden del servicio o escritorio seguro), no se llama a la fuente.
                if suspended.load(Ordering::SeqCst) || !desktop.capture_allowed() {
                    return None;
                }
                Some(source.next_packet(session, desktop, index, force))
            }) else {
                return;
            };
            let Some(result) = result else {
                break;
            };
            match result {
                Ok(Some(packet)) => {
                    if let Some(cursor) = packet.cursor {
                        let _ = out.send(CaptureOut::Control(cursor));
                    }
                    if packet.payload.is_empty() {
                        continue;
                    }
                    if (packet.width, packet.height) != (monitor.width_px, monitor.height_px) {
                        refresh = true;
                        failure = Some(format!(
                            "fotograma de {}x{} en un monitor de {}x{}",
                            packet.width, packet.height, monitor.width_px, monitor.height_px
                        ));
                        break;
                    }
                    let Ok(payload_len) = u32::try_from(packet.payload.len()) else {
                        continue;
                    };
                    keyframe[slot] = false;
                    produced = true;
                    frame_seq += 1;
                    let header = VideoPacketHeader {
                        frame_seq,
                        capture_ts_us: started.elapsed().as_micros() as u64,
                        monitor_index: index,
                        codec: VideoCodec::ZstdDirtyTiles,
                        is_keyframe: force,
                        payload_len,
                    };
                    // Un fotograma capturado justo antes de suspender no sale.
                    if suspended.load(Ordering::SeqCst) {
                        break;
                    }
                    let video = AgentVideo {
                        header,
                        payload: packet.payload,
                    };
                    // Nunca se espera a la pipe: con la cola llena el fotograma se descarta y el
                    // siguiente de ese monitor sera clave (sin el, el operador no podria
                    // reconstruir la imagen).
                    match packets.try_send(video) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            keyframe[slot] = true;
                            thread::sleep(Duration::from_millis(15));
                        }
                        // El escritor de la pipe termino: se avisa al bucle de la sesion en lugar
                        // de salir en silencio.
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            let _ = out.send(CaptureOut::Failed(
                                "escritor de la pipe cerrado".to_string(),
                            ));
                            return;
                        }
                    }
                }
                Ok(None) => {}
                Err(SourceError::SecureDesktop) => {
                    gate.observe_input_desktop(InputDesktopKind::SecureOrOther);
                    let _ = out.send(CaptureOut::Probe(InputDesktopKind::SecureOrOther));
                    break;
                }
                Err(SourceError::Failed(reason)) => {
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

/// Relee los monitores y, si cambiaron, anuncia `DisplayTopologyChanged` antes de cualquier
/// fotograma de la topologia nueva.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::InputSink;
    use crate::net::SourcePacket;
    use awawa_protocol::{DesktopSessionMonitor, SessionRevocation};
    use awawa_service::agent_pipe::{AgentFrame, ProbeKind, recv_from_agent, send_to_agent};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

    const STEP: Duration = Duration::from_secs(5);

    #[derive(Default)]
    struct InputLog {
        dispatched: Vec<RemoteInputCommand>,
        released: usize,
        flushed: usize,
        pings: usize,
    }

    /// Despachador simulado con las mismas comprobaciones que el real (monitor y sesion).
    struct SimInput(Arc<Mutex<InputLog>>);

    impl InputSink for SimInput {
        fn enable_heartbeat(&mut self, _now: Instant) {}
        fn record_ping(&mut self, _now: Instant) {
            self.0.lock().unwrap().pings += 1;
        }
        fn tick_heartbeat(&mut self, _s: &mut ApprovedActiveSession, _now: Instant) -> bool {
            false
        }
        fn dispatch(
            &mut self,
            session: &mut ApprovedActiveSession,
            desktop: &DesktopSessionMonitor,
            cmd: &RemoteInputCommand,
        ) -> Result<(), String> {
            if !desktop.input_allowed() {
                return Err("suspendida".to_string());
            }
            session
                .authorize_remote_input(cmd)
                .map_err(|e| format!("{e:?}"))?;
            self.0.lock().unwrap().dispatched.push(cmd.clone());
            Ok(())
        }
        fn release_held_input(&mut self, session: &mut ApprovedActiveSession) {
            let n = session.drain_held_input_releases().len();
            self.0.lock().unwrap().released += n;
        }
        fn flush_revocation_releases(&mut self, revocation: &SessionRevocation) {
            self.0.lock().unwrap().flushed += revocation.pending_release_commands.len();
        }
    }

    /// Fuente de video simulada: un monitor y un fotograma por llamada.
    struct SimVideo {
        captures: Arc<Mutex<usize>>,
    }

    fn monitors() -> Vec<MonitorDescriptor> {
        vec![MonitorDescriptor {
            index: 0,
            is_primary: true,
            origin_x: 0,
            origin_y: 0,
            width_px: 8,
            height_px: 4,
            dpi_scale_percent: 100,
        }]
    }

    impl VideoSource for SimVideo {
        fn monitors(&mut self) -> Vec<MonitorDescriptor> {
            monitors()
        }
        fn probe_input_desktop(&mut self) -> InputDesktopKind {
            InputDesktopKind::Default
        }
        fn next_packet(
            &mut self,
            session: &ApprovedActiveSession,
            desktop: &DesktopSessionMonitor,
            _monitor_index: u8,
            _keyframe: bool,
        ) -> Result<Option<SourcePacket>, SourceError> {
            assert!(desktop.capture_allowed() && session.can_capture_desktop());
            *self.captures.lock().unwrap() += 1;
            thread::sleep(Duration::from_millis(20));
            Ok(Some(SourcePacket {
                payload: vec![1, 2, 3],
                width: 8,
                height: 4,
                cursor: None,
            }))
        }
    }

    struct Rig {
        service_r: ReadHalf<DuplexStream>,
        service_w: WriteHalf<DuplexStream>,
        gate: SessionGate,
        kill: KillSwitch,
        input: Arc<Mutex<InputLog>>,
        captures: Arc<Mutex<usize>>,
        banner: Arc<Mutex<BannerInfo>>,
        agent: tokio::task::JoinHandle<AgentExit>,
        ui_ready_tx: watch::Sender<bool>,
    }

    fn rig() -> Rig {
        rig_with_ui(true)
    }

    fn rig_with_ui(ready: bool) -> Rig {
        let (agent_end, service_end) = tokio::io::duplex(1 << 20);
        let input = Arc::new(Mutex::new(InputLog::default()));
        let gate = SessionGate::new(Box::new(SimInput(input.clone())));
        let (kill, local_stop) = KillSwitch::new(gate.clone());
        let captures = Arc::new(Mutex::new(0));
        let cap = captures.clone();
        let video: VideoSourceFactory = Arc::new(move || {
            Ok(Box::new(SimVideo {
                captures: cap.clone(),
            }) as Box<dyn VideoSource>)
        });
        let banner = Arc::new(Mutex::new(BannerInfo::default()));
        let (ui_ready_tx, ui_ready) = watch::channel(ready);
        let agent = tokio::spawn(run_agent(
            agent_end,
            AgentConfig {
                gate: gate.clone(),
                video,
                keyboard_blocked: Arc::new(|| false),
                banner: banner.clone(),
                local_stop,
                ui_ready,
                ui_ready_timeout: Duration::from_millis(400),
            },
        ));
        let (service_r, service_w) = tokio::io::split(service_end);
        Rig {
            service_r,
            service_w,
            gate,
            kill,
            input,
            captures,
            banner,
            agent,
            ui_ready_tx,
        }
    }

    impl Rig {
        async fn send(&mut self, order: ServiceToAgent) {
            send_to_agent(&mut self.service_w, &order).await.unwrap();
        }

        async fn next(&mut self) -> AgentFrame {
            timeout(STEP, recv_from_agent(&mut self.service_r))
                .await
                .unwrap()
                .unwrap()
        }

        /// Siguiente mensaje que no sea video ni sondeo.
        async fn next_message(&mut self) -> AgentToService {
            loop {
                match self.next().await {
                    AgentFrame::Message(AgentToService::InputDesktop(_)) | AgentFrame::Video(_) => {
                    }
                    AgentFrame::Message(m) => return m,
                }
            }
        }

        async fn next_video(&mut self) -> AgentVideo {
            loop {
                if let AgentFrame::Video(v) = self.next().await {
                    return v;
                }
            }
        }

        async fn start(&mut self) {
            self.send(ServiceToAgent::Start {
                service_id: 123_456_789,
                operator_display_name: "Tecnico".to_string(),
                session_fingerprint: [1; 8],
                generation: 3,
            })
            .await;
            assert_eq!(
                self.next_message().await,
                AgentToService::Started {
                    monitors: monitors()
                }
            );
            assert!(self.gate.is_active());
        }

        async fn exit(&mut self) -> AgentExit {
            timeout(STEP, &mut self.agent).await.unwrap().unwrap()
        }
    }

    fn key(state: KeyState) -> ServiceToAgent {
        ServiceToAgent::Input(ClientToHostMessage::KeyboardEvent {
            scancode: 0x1E,
            extended: false,
            unicode_fallback: None,
            state,
        })
    }

    /// Liberaciones entregadas al revocar. Si la captura tenia el candado de la compuerta, la
    /// revocacion se completa al soltarlo (unos ms despues de la marca atomica).
    async fn flushed(r: &Rig) -> usize {
        for _ in 0..50 {
            let n = r.input.lock().unwrap().flushed;
            if n > 0 {
                return n;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        0
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sin_start_no_hay_captura_ni_entrada() {
        let mut r = rig();
        r.send(key(KeyState::Down)).await;
        assert_eq!(r.exit().await, AgentExit::NoStart);
        let input = r.input.lock().unwrap();
        assert!(input.dispatched.is_empty());
        assert_eq!(*r.captures.lock().unwrap(), 0);
        assert!(!r.gate.is_active());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_habilita_captura_y_entrada_solo_tras_start_video() {
        let mut r = rig();
        r.start().await;
        assert_eq!(
            r.banner.lock().unwrap().operator.as_deref(),
            Some("Tecnico")
        );
        settle().await;
        assert_eq!(
            *r.captures.lock().unwrap(),
            0,
            "sin StartVideo no se captura"
        );
        r.send(ServiceToAgent::StartVideo).await;
        let video = r.next_video().await;
        assert!(video.header.is_keyframe);
        assert_eq!(video.payload, vec![1, 2, 3]);
        r.send(key(KeyState::Down)).await;
        r.send(ServiceToAgent::OperatorPing).await;
        settle().await;
        {
            let input = r.input.lock().unwrap();
            assert_eq!(input.dispatched.len(), 1);
            assert_eq!(input.pings, 1);
        }
        r.send(ServiceToAgent::Stop {
            reason: "fin".to_string(),
        })
        .await;
        assert_eq!(r.next_message().await, AgentToService::Stopped);
        assert!(!r.gate.is_active());
        assert_eq!(flushed(&r).await, 1, "la tecla retenida se libera");
        assert_eq!(r.exit().await, AgentExit::Stopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn suspend_libera_y_detiene_resume_reanuda_con_fotograma_clave() {
        let mut r = rig();
        r.start().await;
        r.send(ServiceToAgent::StartVideo).await;
        r.next_video().await;
        r.send(key(KeyState::Down)).await;
        r.send(ServiceToAgent::Suspend).await;
        settle().await;
        assert_eq!(
            r.input.lock().unwrap().released,
            1,
            "Suspend libera las teclas"
        );
        // Suspendida: sin fotogramas nuevos ni entrada.
        while timeout(
            Duration::from_millis(100),
            recv_from_agent(&mut r.service_r),
        )
        .await
        .is_ok()
        {}
        let before = *r.captures.lock().unwrap();
        r.send(key(KeyState::Down)).await;
        settle().await;
        assert_eq!(*r.captures.lock().unwrap(), before);
        assert_eq!(r.input.lock().unwrap().dispatched.len(), 1);
        // El servicio reanuda: fotograma clave.
        r.send(ServiceToAgent::Resume {
            force_keyframe: true,
        })
        .await;
        let video = r.next_video().await;
        assert!(video.header.is_keyframe);
        r.send(ServiceToAgent::Stop {
            reason: "fin".to_string(),
        })
        .await;
        assert_eq!(r.exit().await, AgentExit::Stopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_switch_revoca_al_instante_y_avisa() {
        let mut r = rig();
        r.start().await;
        r.send(ServiceToAgent::StartVideo).await;
        r.next_video().await;
        r.send(key(KeyState::Down)).await;
        settle().await;
        r.kill.trigger(LocalStop::KillSwitch);
        // La compuerta cae en el mismo hilo del kill-switch, sin esperar al bucle.
        assert!(!r.gate.is_active());
        assert_eq!(r.next_message().await, AgentToService::KillSwitch);
        assert_eq!(flushed(&r).await, 1);
        assert_eq!(r.exit().await, AgentExit::KillSwitch);
    }

    fn start_order() -> ServiceToAgent {
        ServiceToAgent::Start {
            service_id: 123_456_789,
            operator_display_name: "Tecnico".to_string(),
            session_fingerprint: [1; 8],
            generation: 3,
        }
    }

    /// `Start` antes de que el banner este pintado con el atajo armado: ni captura ni entrada
    /// hasta la senal; la entrada recibida mientras tanto se descarta.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_antes_del_banner_no_activa_hasta_la_senal() {
        let mut r = rig_with_ui(false);
        r.send(start_order()).await;
        r.send(key(KeyState::Down)).await;
        r.send(ServiceToAgent::StartVideo).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!r.gate.is_active());
        assert!(r.input.lock().unwrap().dispatched.is_empty());
        assert_eq!(*r.captures.lock().unwrap(), 0);
        assert!(
            timeout(
                Duration::from_millis(100),
                recv_from_agent(&mut r.service_r)
            )
            .await
            .is_err(),
            "sin senal no se anuncian monitores"
        );
        r.ui_ready_tx.send(true).unwrap();
        assert_eq!(
            r.next_message().await,
            AgentToService::Started {
                monitors: monitors()
            }
        );
        assert!(r.gate.is_active());
        assert!(
            r.input.lock().unwrap().dispatched.is_empty(),
            "la tecla previa se descarto"
        );
        r.send(ServiceToAgent::Stop {
            reason: "fin".to_string(),
        })
        .await;
        assert_eq!(r.exit().await, AgentExit::Stopped);
    }

    /// Sin la senal de la UI dentro del plazo: `Failed` y nunca hay sesion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sin_banner_a_tiempo_no_hay_sesion() {
        let mut r = rig_with_ui(false);
        r.send(start_order()).await;
        assert!(matches!(
            r.next_message().await,
            AgentToService::Failed { .. }
        ));
        assert!(matches!(r.exit().await, AgentExit::Failed(_)));
        assert!(!r.gate.is_active());
        assert_eq!(*r.captures.lock().unwrap(), 0);
    }

    /// Un kill-switch pulsado antes de activar deja su marca: la compuerta no queda
    /// activa ni se anuncian monitores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_switch_antes_de_activar_no_deja_la_compuerta_activa() {
        let mut r = rig_with_ui(false);
        r.send(start_order()).await;
        settle().await;
        r.kill.trigger(LocalStop::KillSwitch);
        r.ui_ready_tx.send(true).unwrap();
        assert_eq!(r.next_message().await, AgentToService::KillSwitch);
        assert_eq!(r.exit().await, AgentExit::KillSwitch);
        assert!(!r.gate.is_active());
        assert_eq!(*r.captures.lock().unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sin_atajo_global_no_hay_sesion() {
        let mut r = rig();
        r.kill.trigger(LocalStop::HotkeyUnavailable);
        assert!(matches!(
            r.next_message().await,
            AgentToService::Failed { .. }
        ));
        assert!(matches!(r.exit().await, AgentExit::Failed(_)));
        assert!(r.input.lock().unwrap().dispatched.is_empty());
    }

    /// Agente en proceso sobre la pipe real del servicio (DACL, PID y modo de apertura reales),
    /// con backends simulados.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agente_sobre_la_pipe_real_del_servicio() {
        use tokio::net::windows::named_pipe::NamedPipeClient;
        let sid = awawa_service::identity::current_user_sid_string().unwrap();
        let server = awawa_service::agent_pipe::create_agent_pipe(&sid).unwrap();
        let name = server.name().to_string();
        let accept = tokio::spawn(server.accept());
        let file = open_service_pipe(&name).unwrap();
        // SAFETY: manejador de pipe recien abierto con FILE_FLAG_OVERLAPPED; pasa a ser de tokio.
        let client = unsafe {
            use std::os::windows::io::IntoRawHandle;
            NamedPipeClient::from_raw_handle(file.into_raw_handle()).unwrap()
        };
        let (pipe, pid) = accept.await.unwrap().unwrap();
        assert_eq!(pid, std::process::id());

        let input = Arc::new(Mutex::new(InputLog::default()));
        let gate = SessionGate::new(Box::new(SimInput(input.clone())));
        let (_kill, local_stop) = KillSwitch::new(gate.clone());
        let video: VideoSourceFactory = Arc::new(|| {
            Ok(Box::new(SimVideo {
                captures: Arc::new(Mutex::new(0)),
            }) as Box<dyn VideoSource>)
        });
        let agent = tokio::spawn(run_agent(
            client,
            AgentConfig {
                gate: gate.clone(),
                video,
                keyboard_blocked: Arc::new(|| false),
                banner: Arc::new(Mutex::new(BannerInfo::default())),
                local_stop,
                ui_ready: watch::channel(true).1,
                ui_ready_timeout: UI_READY_TIMEOUT,
            },
        ));
        let (mut sr, mut sw) = tokio::io::split(pipe);
        send_to_agent(
            &mut sw,
            &ServiceToAgent::Start {
                service_id: 123_456_789,
                operator_display_name: "Tecnico".to_string(),
                session_fingerprint: [1; 8],
                generation: 1,
            },
        )
        .await
        .unwrap();
        let mut got_started = false;
        let mut got_video = false;
        let mut got_probe = false;
        send_to_agent(&mut sw, &ServiceToAgent::StartVideo)
            .await
            .unwrap();
        while !(got_started && got_video && got_probe) {
            match timeout(STEP, recv_from_agent(&mut sr))
                .await
                .unwrap()
                .unwrap()
            {
                AgentFrame::Message(AgentToService::Started { .. }) => got_started = true,
                AgentFrame::Message(AgentToService::InputDesktop(ProbeKind::Default)) => {
                    got_probe = true
                }
                AgentFrame::Video(_) => got_video = true,
                other => panic!("inesperado: {other:?}"),
            }
        }
        send_to_agent(
            &mut sw,
            &ServiceToAgent::Stop {
                reason: "fin".to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            timeout(STEP, agent).await.unwrap().unwrap(),
            AgentExit::Stopped
        );
        assert!(!gate.is_active());
    }

    fn cursor(bytes: usize) -> HostToClientMessage {
        HostToClientMessage::CursorShapeUpdate {
            cursor_hash: 7,
            hotspot_x: 0,
            hotspot_y: 0,
            width: 256,
            height: 256,
            bgra_zstd: Some(vec![0x5A; bytes]),
        }
    }

    /// Un cursor que no cabe (en la pipe o en un registro hacia el operador) se omite sin
    /// matar al escritor; un aviso que no se puede omitir se sustituye por un `Failed` corto.
    #[tokio::test]
    async fn aviso_que_no_cabe_se_omite_o_se_convierte_en_failed() {
        let (agent_end, service_end) = tokio::io::duplex(1 << 20);
        let (_agent_r, agent_w) = tokio::io::split(agent_end);
        let (mut service_r, _service_w) = tokio::io::split(service_end);
        let (out, writer) = AgentOut::spawn(agent_w);
        // Mayor que un registro del canal pero menor que la trama de la pipe.
        let near = cursor(65_505);
        assert!(encode_message(&near).unwrap().len() > MAX_CONTROL_PLAINTEXT);
        let near = AgentToService::Control(near);
        assert!(encode_message(&near).unwrap().len() < MAX_AGENT_CONTROL_FRAME);
        assert_eq!(out.send(near), None);
        assert_eq!(out.send(AgentToService::Control(cursor(70_000))), None);
        let small = AgentToService::Control(cursor(16));
        assert_eq!(out.send(small.clone()), None);
        assert_eq!(
            timeout(STEP, recv_from_agent(&mut service_r))
                .await
                .unwrap()
                .unwrap(),
            AgentFrame::Message(small),
            "los cursores grandes no se enviaron y el escritor sigue vivo"
        );
        let exit = out.send(AgentToService::Failed {
            reason: "x".repeat(70_000),
        });
        assert_eq!(exit, Some(AgentExit::Failed(OVERSIZED_NOTICE.to_string())));
        assert_eq!(
            timeout(STEP, recv_from_agent(&mut service_r))
                .await
                .unwrap()
                .unwrap(),
            AgentFrame::Message(AgentToService::Failed {
                reason: OVERSIZED_NOTICE.to_string()
            })
        );
        assert!(!writer.is_finished());
        drop(out);
        timeout(STEP, writer).await.unwrap().unwrap();
    }

    /// Pipe cuyas escrituras fallan a voluntad (la lectura sigue): el escritor del agente muere.
    struct FailingWrites {
        inner: DuplexStream,
        fail: Arc<AtomicBool>,
    }

    impl tokio::io::AsyncRead for FailingWrites {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FailingWrites {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.fail.load(Ordering::SeqCst) {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Si el escritor de la pipe muere, la sesion no queda zombi: la compuerta se revoca
    /// (la tecla retenida se libera), el agente sale y la entrada posterior no se despacha.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn escritor_muerto_revoca_y_sale() {
        let (agent_end, service_end) = tokio::io::duplex(1 << 20);
        let fail = Arc::new(AtomicBool::new(false));
        let input = Arc::new(Mutex::new(InputLog::default()));
        let gate = SessionGate::new(Box::new(SimInput(input.clone())));
        let (_kill, local_stop) = KillSwitch::new(gate.clone());
        let video: VideoSourceFactory = Arc::new(|| {
            Ok(Box::new(SimVideo {
                captures: Arc::new(Mutex::new(0)),
            }) as Box<dyn VideoSource>)
        });
        let mut agent = tokio::spawn(run_agent(
            FailingWrites {
                inner: agent_end,
                fail: fail.clone(),
            },
            AgentConfig {
                gate: gate.clone(),
                video,
                keyboard_blocked: Arc::new(|| false),
                banner: Arc::new(Mutex::new(BannerInfo::default())),
                local_stop,
                ui_ready: watch::channel(true).1,
                ui_ready_timeout: STEP,
            },
        ));
        let (mut sr, mut sw) = tokio::io::split(service_end);
        send_to_agent(&mut sw, &start_order()).await.unwrap();
        send_to_agent(&mut sw, &ServiceToAgent::StartVideo)
            .await
            .unwrap();
        loop {
            let frame = timeout(STEP, recv_from_agent(&mut sr))
                .await
                .unwrap()
                .unwrap();
            if matches!(frame, AgentFrame::Video(_)) {
                break;
            }
        }
        send_to_agent(&mut sw, &key(KeyState::Down)).await.unwrap();
        settle().await;
        assert_eq!(input.lock().unwrap().dispatched.len(), 1);
        // La siguiente escritura (video o sondeo) falla y el escritor termina.
        fail.store(true, Ordering::SeqCst);
        let exit = timeout(STEP, &mut agent).await.unwrap().unwrap();
        assert!(
            matches!(exit, AgentExit::PipeClosed | AgentExit::Failed(_)),
            "{exit:?}"
        );
        assert!(!gate.is_active());
        let released = {
            let mut n = 0;
            for _ in 0..50 {
                n = input.lock().unwrap().flushed;
                if n > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            n
        };
        assert_eq!(released, 1, "la tecla retenida se libera");
        let _ = send_to_agent(&mut sw, &key(KeyState::Down)).await;
        settle().await;
        assert_eq!(input.lock().unwrap().dispatched.len(), 1);
    }

    /// Un `Failed` cuyo motivo no cabe se sustituye por uno corto (el servicio lo recibe).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_que_no_cabe_llega_como_failed_corto() {
        let (agent_end, service_end) = tokio::io::duplex(1 << 20);
        let gate = SessionGate::new(Box::new(SimInput(Arc::new(
            Mutex::new(InputLog::default()),
        ))));
        let (_kill, local_stop) = KillSwitch::new(gate.clone());
        let video: VideoSourceFactory = Arc::new(|| Err("x".repeat(70_000)));
        let agent = tokio::spawn(run_agent(
            agent_end,
            AgentConfig {
                gate: gate.clone(),
                video,
                keyboard_blocked: Arc::new(|| false),
                banner: Arc::new(Mutex::new(BannerInfo::default())),
                local_stop,
                ui_ready: watch::channel(true).1,
                ui_ready_timeout: STEP,
            },
        ));
        let (mut sr, mut sw) = tokio::io::split(service_end);
        send_to_agent(&mut sw, &start_order()).await.unwrap();
        assert_eq!(
            timeout(STEP, recv_from_agent(&mut sr))
                .await
                .unwrap()
                .unwrap(),
            AgentFrame::Message(AgentToService::Failed {
                reason: OVERSIZED_NOTICE.to_string()
            })
        );
        assert!(matches!(
            timeout(STEP, agent).await.unwrap().unwrap(),
            AgentExit::Failed(_)
        ));
        assert!(!gate.is_active());
    }

    #[test]
    fn nombres_de_pipe_ajenos_se_rechazan_antes_de_abrir() {
        for bad in [
            r"\\.\pipe\otra",
            r"\\server\pipe\Awawa.agent.00000000000000000000000000000000",
            &format!("{PIPE_PREFIX}zz000000000000000000000000000000"),
        ] {
            assert_eq!(
                open_service_pipe(bad).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput,
                "{bad}"
            );
        }
    }
}
