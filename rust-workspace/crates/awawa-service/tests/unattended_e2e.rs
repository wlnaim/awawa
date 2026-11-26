//! Prueba E2E del acceso desatendido por un relay real en loopback, con la logica
//! de red del servicio (`UnattendedService`), autenticador, lanzador y agente simulados, y un
//! operador escrito con la API de `awawa-protocol` (`OperatorUnattendedHandshake`).
//!
//! Cubre: bloqueo/desbloqueo, desconexiones, cierre de sesion, cambio
//! de sesion o de usuario, parada del servicio y cambio/revocacion de la contrasena, el escritorio
//! seguro, las respuestas genericas e identicas, la clave fijada distinta, el kill-switch,
//! la comprobacion del PID de la pipe y el cierre ordenado del agente.
#![cfg(target_os = "windows")]

// Agente real (logica del binario `awawa-session-agent`) con la compuerta de awawa-host,
// incluidos por ruta como en el binario, para probarlo contra el servicio real.
#[path = "../src/bin/awawa-session-agent/agent.rs"]
#[allow(dead_code)]
mod agent;
#[path = "../../awawa-host/src/gate.rs"]
#[allow(dead_code)]
mod gate;
#[path = "../../awawa-host/src/net.rs"]
#[allow(dead_code)]
mod net;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, MemoryAuditSink};
use awawa_protocol::unattended::{
    KdfError, PasswordKdf, UnattendedAuthenticator, UnattendedCredentialState, UnattendedError,
    UnattendedStatus,
};
use awawa_protocol::unattended_channel::{SigningKey, VerifyingKey};
use awawa_protocol::{
    ClientToHostMessage, HostToClientMessage, KeyState, MonitorDescriptor,
    OperatorUnattendedHandshake, OperatorUnattendedSession, SessionId, UnattendedChannelError,
    UnattendedHelloReply, UnattendedVerdict, VIDEO_RECORD_PREFIX_LEN, VideoCodec,
    VideoPacketHeader, decode_message, encode_message,
};
use awawa_relay::{
    RelayClient, RelayConfig, RelayHandle, RelayIdentity, RelayPin, RelayServer, RelayedStream,
};
use awawa_service::agent_pipe::{
    AgentToService, AgentVideo, MAX_AGENT_CONTROL_FRAME, ProbeKind, ServiceToAgent,
    recv_from_service, send_to_service, send_video,
};
use awawa_service::session_events::{
    WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF, WTS_SESSION_UNLOCK,
};
use awawa_service::unattended_net::{
    AgentPlatform, AgentProcess, MAX_CONTROL_PLAINTEXT, PipeAcceptor, ServiceAuth, ServiceEvent,
    SharedAudit, Timings, UnattendedService,
};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use zeroize::Zeroizing;

const TARGET: u32 = 123_456_789;
const PW: &str = "Clave-Desatendida-2026";
const WIN_SESSION: u32 = 2;
const USER_SID: &str = "S-1-5-21-1-2-3-1001";
const STEP: Duration = Duration::from_secs(5);

// ------------------------------------------------------------------ autenticador simulado

struct FastKdf;
impl PasswordKdf for FastKdf {
    fn derive(
        &self,
        pw: &[u8],
        salt: &[u8; 16],
        _params: awawa_protocol::unattended::VerifierKdfParams,
        out: &mut [u8; 32],
    ) -> Result<(), KdfError> {
        for (i, o) in out.iter_mut().enumerate() {
            *o = pw[i % pw.len()] ^ salt[i % 16];
        }
        Ok(())
    }
}

/// Autenticador real del dominio con KDF rapido y credencial en memoria; audita como el de
/// produccion (un registro por intento, sin la contrasena).
struct SimAuth {
    inner: UnattendedAuthenticator,
    audit: Arc<Mutex<MemoryAuditSink>>,
    calls: Arc<AtomicUsize>,
}

impl ServiceAuth for SimAuth {
    fn authenticate(&mut self, operator: &str, source: &str, password: &str) -> UnattendedVerdict {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self
            .inner
            .authenticate(source, password, &FastKdf, Instant::now());
        let event = match &result {
            Ok(_) => AuditEvent::AuthSucceeded,
            Err(UnattendedError::Throttled { retry_after, .. }) => AuditEvent::AuthThrottled {
                retry_after_secs: retry_after.as_secs().max(1),
            },
            Err(_) => AuditEvent::AuthFailed,
        };
        let record = AuditRecord::new(0, event, operator).with_source(source);
        self.audit.lock().unwrap().write_record(&record).unwrap();
        UnattendedVerdict::from_result(&result)
    }

    fn current_status(&mut self) -> UnattendedStatus {
        self.inner.credentials().status()
    }
}

// ------------------------------------------------------------------ plataforma simulada

/// Extremo del agente simulado que recibe la prueba.
struct AgentConn {
    pipe: DuplexStream,
    exited: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    pipe_name: String,
    session: u32,
}

#[derive(Clone)]
struct PlatformState {
    console: Arc<Mutex<Option<u32>>>,
    sid: Arc<Mutex<String>>,
    pipe_sids: Arc<Mutex<Vec<String>>>,
    wrong_client_pid: Arc<AtomicBool>,
}

struct SimPlatform {
    state: PlatformState,
    agents: mpsc::UnboundedSender<AgentConn>,
    pending: Option<(String, oneshot::Sender<(DuplexStream, u32)>)>,
    next_pid: u32,
}

struct SimAcceptor {
    name: String,
    rx: oneshot::Receiver<(DuplexStream, u32)>,
}

impl PipeAcceptor for SimAcceptor {
    type Stream = DuplexStream;
    fn name(&self) -> &str {
        &self.name
    }
    async fn accept(self) -> std::io::Result<(DuplexStream, u32)> {
        self.rx
            .await
            .map_err(|_| std::io::Error::other("sin cliente"))
    }
}

struct SimProcess {
    pid: u32,
    exited: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
}

impl AgentProcess for SimProcess {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn has_exited(&mut self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }
    fn terminate(&mut self) {
        self.terminated.store(true, Ordering::SeqCst);
        self.exited.store(true, Ordering::SeqCst);
    }
}

impl AgentPlatform for SimPlatform {
    type Acceptor = SimAcceptor;
    type Process = SimProcess;

    fn active_console_session(&mut self) -> Option<u32> {
        *self.state.console.lock().unwrap()
    }
    fn session_user_sid(&mut self, _session: u32) -> Option<String> {
        Some(self.state.sid.lock().unwrap().clone())
    }
    fn create_pipe(&mut self, user_sid: &str) -> std::io::Result<SimAcceptor> {
        self.state
            .pipe_sids
            .lock()
            .unwrap()
            .push(user_sid.to_string());
        let (tx, rx) = oneshot::channel();
        let name = format!(r"\\.\pipe\sim.{}", self.next_pid);
        self.pending = Some((name.clone(), tx));
        Ok(SimAcceptor { name, rx })
    }
    fn launch_agent(&mut self, session: u32, pipe_name: &str) -> Result<SimProcess, String> {
        let (name, tx) = self.pending.take().ok_or("sin pipe")?;
        assert_eq!(name, pipe_name);
        self.next_pid += 1;
        let pid = self.next_pid;
        let (service_end, agent_end) = tokio::io::duplex(1 << 20);
        let client_pid = if self.state.wrong_client_pid.load(Ordering::SeqCst) {
            pid + 1000
        } else {
            pid
        };
        let _ = tx.send((service_end, client_pid));
        let exited = Arc::new(AtomicBool::new(false));
        let terminated = Arc::new(AtomicBool::new(false));
        let _ = self.agents.send(AgentConn {
            pipe: agent_end,
            exited: exited.clone(),
            terminated: terminated.clone(),
            pipe_name: name,
            session,
        });
        Ok(SimProcess {
            pid,
            exited,
            terminated,
        })
    }
}

// ------------------------------------------------------------------ arnes

struct Harness {
    relay_addr: SocketAddr,
    pin: RelayPin,
    relay: RelayHandle,
    key: VerifyingKey,
    auth: Arc<Mutex<SimAuth>>,
    calls: Arc<AtomicUsize>,
    audit: Arc<Mutex<MemoryAuditSink>>,
    state: PlatformState,
    agents: mpsc::UnboundedReceiver<AgentConn>,
    events: mpsc::UnboundedSender<ServiceEvent>,
    service: tokio::task::JoinHandle<()>,
}

fn monitors() -> Vec<MonitorDescriptor> {
    vec![MonitorDescriptor {
        index: 0,
        is_primary: true,
        origin_x: 0,
        origin_y: 0,
        width_px: 64,
        height_px: 32,
        dpi_scale_percent: 100,
    }]
}

async fn start() -> Harness {
    let identity = RelayIdentity::generate().unwrap();
    let pin = identity.pin();
    let config = RelayConfig {
        lookup_attempts_per_minute: NonZeroU32::new(1000).unwrap(),
        register_attempts_per_minute: NonZeroU32::new(1000).unwrap(),
        ..RelayConfig::default()
    };
    let server = RelayServer::bind("127.0.0.1:0".parse().unwrap(), &identity, config).unwrap();
    let relay_addr = server.local_addr().unwrap();
    let relay = server.handle();
    tokio::spawn(server.run());

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let key = signing.verifying_key();
    let audit = Arc::new(Mutex::new(MemoryAuditSink::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut credentials = UnattendedCredentialState::not_configured();
    credentials.configure(PW, &FastKdf).unwrap();
    let auth = Arc::new(Mutex::new(SimAuth {
        inner: UnattendedAuthenticator::new(credentials),
        audit: audit.clone(),
        calls: calls.clone(),
    }));
    let state = PlatformState {
        console: Arc::new(Mutex::new(Some(WIN_SESSION))),
        sid: Arc::new(Mutex::new(USER_SID.to_string())),
        pipe_sids: Arc::new(Mutex::new(Vec::new())),
        wrong_client_pid: Arc::new(AtomicBool::new(false)),
    };
    let (agents_tx, agents) = mpsc::unbounded_channel();
    let platform = SimPlatform {
        state: state.clone(),
        agents: agents_tx,
        pending: None,
        next_pid: 4000,
    };
    let (events, events_rx) = mpsc::unbounded_channel();
    let shared: SharedAudit = audit.clone();
    let timings = Timings {
        hello: STEP,
        password: STEP,
        agent_connect: STEP,
        revalidate: Duration::from_millis(100),
        agent_exit: Duration::from_millis(400),
        pipe_write: STEP,
    };
    let service = UnattendedService::new(
        TARGET,
        signing,
        auth.clone(),
        platform,
        shared,
        events_rx,
        timings,
    );
    let client_pin = pin.clone();
    let service = tokio::spawn(async move {
        let client = RelayClient::new(relay_addr, client_pin).unwrap();
        service.run(&client).await;
        client.close();
    });
    Harness {
        relay_addr,
        pin,
        relay,
        key,
        auth,
        calls,
        audit,
        state,
        agents,
        events,
        service,
    }
}

impl Harness {
    async fn wait_registered(&self) {
        let deadline = Instant::now() + STEP;
        while self.relay.waiting_slots() == 0 {
            assert!(Instant::now() < deadline, "el servicio no se registro");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn audit_lines(&self) -> Vec<String> {
        self.audit.lock().unwrap().lines.clone()
    }

    /// Conecta un operador y recorre el handshake. Devuelve la sesion o el error del canal y la
    /// longitud del registro con el veredicto (si llego).
    async fn operator(&self, key: &VerifyingKey, password: &str) -> Operator {
        self.operator_opts(key, password, true).await
    }

    /// Como `operator`; con `read_video = false` el operador nunca acepta el stream de video.
    async fn operator_opts(
        &self,
        key: &VerifyingKey,
        password: &str,
        read_video: bool,
    ) -> Operator {
        self.wait_registered().await;
        let client = RelayClient::new(self.relay_addr, self.pin.clone()).unwrap();
        let mut stream = client
            .connect_operator(SessionId::parse(&TARGET.to_string()).unwrap())
            .await
            .unwrap();
        let (handshake, hello) =
            OperatorUnattendedHandshake::start(TARGET, "Tecnico\u{7}", key).unwrap();
        stream
            .send_frame(&encode_message(&hello).unwrap())
            .await
            .unwrap();
        let reply: UnattendedHelloReply = decode_message(&recv(&mut stream).await).unwrap();
        let pending = match handshake.handle_reply(&reply) {
            Ok(p) => p,
            Err(e) => {
                // Clave fijada distinta: se aborta sin enviar la contrasena.
                stream.close();
                return Operator {
                    client,
                    stream,
                    result: Err(e),
                    record_len: 0,
                    video_rx: None,
                };
            }
        };
        let (awaiting, record) = pending
            .send_password(Zeroizing::new(password.to_string()))
            .unwrap();
        stream.send_frame(&record).await.unwrap();
        let verdict = recv(&mut stream).await;
        let result = awaiting.finish(&verdict);
        let video_rx = result
            .as_ref()
            .ok()
            .filter(|_| read_video)
            .map(|_| spawn_video_reader(&stream));
        Operator {
            client,
            stream,
            result,
            record_len: verdict.len(),
            video_rx,
        }
    }

    /// Operador autenticado con su agente ya iniciado (monitores anunciados y video autorizado).
    async fn session(&mut self) -> (Operator, Agent) {
        let mut op = self.operator(&self.key.clone(), PW).await;
        assert!(op.result.is_ok(), "{:?}", op.result.as_ref().err());
        let conn = timeout(STEP, self.agents.recv()).await.unwrap().unwrap();
        assert_eq!(conn.session, WIN_SESSION);
        assert!(conn.pipe_name.starts_with(r"\\.\pipe\"));
        let mut agent = Agent::new(conn);
        match agent.next().await {
            ServiceToAgent::Start {
                operator_display_name,
                generation,
                ..
            } => {
                assert_eq!(operator_display_name, "Tecnico", "nombre saneado");
                assert!(generation >= 1);
            }
            other => panic!("se esperaba Start: {other:?}"),
        }
        agent
            .send(AgentToService::Started {
                monitors: monitors(),
            })
            .await;
        // Sin ApprovalResult: el primer mensaje tras Granted es la topologia.
        assert_eq!(
            op.ctl().await,
            HostToClientMessage::DisplayTopologyChanged {
                monitors: monitors()
            }
        );
        assert_eq!(agent.next().await, ServiceToAgent::StartVideo);
        (op, agent)
    }
}

async fn recv(stream: &mut RelayedStream) -> Vec<u8> {
    timeout(STEP, stream.recv_frame()).await.unwrap().unwrap()
}

fn spawn_video_reader(
    stream: &RelayedStream,
) -> mpsc::UnboundedReceiver<(VideoPacketHeader, Vec<u8>)> {
    let streams = stream.video_streams();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let Ok(mut uni) = streams.accept().await else {
            return;
        };
        let mut preamble = [0u8; 4];
        if uni.read_exact(&mut preamble).await.is_err() {
            return;
        }
        let _ = tx.send((
            VideoPacketHeader {
                frame_seq: 0,
                capture_ts_us: 0,
                monitor_index: 255,
                codec: VideoCodec::ZstdDirtyTiles,
                is_keyframe: false,
                payload_len: 0,
            },
            preamble.to_vec(),
        ));
        loop {
            let mut prefix = vec![0u8; VIDEO_RECORD_PREFIX_LEN];
            if uni.read_exact(&mut prefix).await.is_err() {
                return;
            }
            let header = VideoPacketHeader::from_bytes(&prefix[4..]).unwrap();
            let mut rest = vec![0u8; header.payload_len as usize + 16];
            if uni.read_exact(&mut rest).await.is_err() {
                return;
            }
            prefix.extend_from_slice(&rest);
            let _ = tx.send((header, prefix));
        }
    });
    rx
}

struct Operator {
    client: RelayClient,
    stream: RelayedStream,
    result: Result<OperatorUnattendedSession, UnattendedChannelError>,
    record_len: usize,
    video_rx: Option<mpsc::UnboundedReceiver<(VideoPacketHeader, Vec<u8>)>>,
}

impl Operator {
    fn session(&mut self) -> &mut OperatorUnattendedSession {
        self.result.as_mut().unwrap()
    }

    async fn ctl(&mut self) -> HostToClientMessage {
        let record = recv(&mut self.stream).await;
        let plain = self.session().channel.open(&record).unwrap();
        decode_message(&plain).unwrap()
    }

    async fn send(&mut self, msg: &ClientToHostMessage) {
        let plain = encode_message(msg).unwrap();
        let record = self.session().channel.seal(&plain).unwrap();
        self.stream.send_frame(&record).await.unwrap();
    }

    /// Siguiente fotograma descifrado.
    async fn video(&mut self) -> (VideoPacketHeader, Vec<u8>) {
        let rx = self.video_rx.as_mut().unwrap();
        let (_, preamble) = timeout(STEP, rx.recv()).await.unwrap().unwrap();
        let mut opener = self
            .result
            .as_mut()
            .unwrap()
            .video
            .accept_stream(preamble.try_into().unwrap())
            .unwrap();
        let (_, record) = timeout(STEP, rx.recv()).await.unwrap().unwrap();
        opener.open(&record).unwrap()
    }

    /// `true` si el relay cerro el control (el servicio termino la conexion).
    async fn closed(&mut self) -> bool {
        matches!(timeout(STEP, self.stream.recv_frame()).await, Ok(Err(_)))
    }
}

struct Agent {
    r: ReadHalf<DuplexStream>,
    w: WriteHalf<DuplexStream>,
    exited: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
}

impl Agent {
    fn new(conn: AgentConn) -> Self {
        let (r, w) = tokio::io::split(conn.pipe);
        Self {
            r,
            w,
            exited: conn.exited,
            terminated: conn.terminated,
        }
    }

    async fn next(&mut self) -> ServiceToAgent {
        timeout(STEP, recv_from_service(&mut self.r))
            .await
            .unwrap()
            .unwrap()
    }

    async fn send(&mut self, msg: AgentToService) {
        send_to_service(&mut self.w, &msg).await.unwrap();
    }

    async fn frame(&mut self, seq: u64, payload: &[u8]) {
        let video = AgentVideo {
            header: VideoPacketHeader {
                frame_seq: seq,
                capture_ts_us: seq * 10,
                monitor_index: 0,
                codec: VideoCodec::ZstdDirtyTiles,
                is_keyframe: true,
                payload_len: payload.len() as u32,
            },
            payload: payload.to_vec(),
        };
        send_video(&mut self.w, &video).await.unwrap();
    }

    /// Agente obediente: ante `Stop` confirma y sale.
    async fn obey_stop(&mut self) -> String {
        loop {
            if let ServiceToAgent::Stop { reason } = self.next().await {
                self.send(AgentToService::Stopped).await;
                self.exited.store(true, Ordering::SeqCst);
                return reason;
            }
        }
    }
}

fn key_down() -> ClientToHostMessage {
    ClientToHostMessage::KeyboardEvent {
        scancode: 0x1E,
        extended: false,
        unicode_fallback: None,
        state: KeyState::Down,
    }
}

/// Espera un `SessionRevoked` (saltando avisos previos) y devuelve el motivo.
async fn revoked(op: &mut Operator) -> String {
    loop {
        if let HostToClientMessage::SessionRevoked { reason } = op.ctl().await {
            return reason;
        }
    }
}

fn count(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|l| l.contains(needle)).count()
}

// ------------------------------------------------------------------ pruebas

/// Registro con ID persistente -> clave fijada -> contrasena -> video y entrada por el agente ->
/// cambio de generacion -> `SessionRevoked` y cierre ordenado -> nuevo registro con el mismo ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_sesion_completa_y_revocacion_por_generacion() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    assert_eq!(
        h.state.pipe_sids.lock().unwrap().as_slice(),
        [USER_SID.to_string()]
    );

    // Video: lo que el agente entrega llega cifrado por un stream uni y se abre con la clave E2E.
    agent.frame(1, b"tiles-zstd").await;
    let (header, payload) = op.video().await;
    assert_eq!(
        (header.frame_seq, payload.as_slice()),
        (1, b"tiles-zstd".as_slice())
    );

    // Entrada y ping.
    op.send(&key_down()).await;
    assert_eq!(agent.next().await, ServiceToAgent::Input(key_down()));
    op.send(&ClientToHostMessage::Ping {
        seq: 9,
        client_mono_us: 77,
    })
    .await;
    assert_eq!(
        op.ctl().await,
        HostToClientMessage::Pong {
            seq: 9,
            client_mono_us: 77
        }
    );
    assert_eq!(agent.next().await, ServiceToAgent::OperatorPing);

    // El administrador cambia la contrasena: en <= 2 s (aqui 100 ms) la sesion termina.
    h.auth
        .lock()
        .unwrap()
        .inner
        .credentials_mut()
        .rotate("Otra-Clave-Desatendida-1", &FastKdf)
        .unwrap();
    let reason = revoked(&mut op).await;
    assert!(reason.contains("revocada"), "{reason}");
    agent.obey_stop().await;
    assert!(op.closed().await);
    assert!(
        !agent.terminated.load(Ordering::SeqCst),
        "salio solo: sin TerminateProcess"
    );

    let lines = h.audit_lines();
    assert_eq!(count(&lines, "auth_succeeded"), 1);
    assert_eq!(count(&lines, "session_started"), 1);
    assert_eq!(count(&lines, "credential_revoked"), 1);
    assert!(!lines.join("\n").contains(PW));
    // Re-registro tras el emparejamiento, con el mismo ID.
    h.wait_registered().await;
    drop(op.client);
}

/// Contrasena invalida, acceso revocado y bloqueo: misma respuesta (salvo el tiempo de espera),
/// mismo tamano de registro y un registro de auditoria por intento.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rechazos_genericos_e_identicos() {
    let h = start().await;
    let invalid = h.operator(&h.key, "Contrasena-Incorrecta-1").await;
    assert!(matches!(
        invalid.result,
        Err(UnattendedChannelError::Rejected { retry_after: None })
    ));
    for _ in 0..2 {
        let again = h.operator(&h.key, "Contrasena-Incorrecta-1").await;
        assert_eq!(again.record_len, invalid.record_len);
    }
    // Cuarto intento (aun con la clave correcta): bloqueado, solo difiere el tiempo de espera.
    let throttled = h.operator(&h.key, PW).await;
    match &throttled.result {
        Err(UnattendedChannelError::Rejected {
            retry_after: Some(d),
        }) => assert!(*d >= Duration::from_secs(1)),
        other => panic!("se esperaba bloqueo: {other:?}"),
    }
    // Revocado (otro servicio para no arrastrar el bloqueo): misma respuesta y mismo tamano.
    let h2 = start().await;
    h2.auth
        .lock()
        .unwrap()
        .inner
        .credentials_mut()
        .revoke()
        .unwrap();
    let revoked = h2.operator(&h2.key, PW).await;
    assert_eq!(
        format!("{:?}", revoked.result.as_ref().err()),
        format!("{:?}", invalid.result.as_ref().err())
    );
    assert_eq!(revoked.record_len, invalid.record_len);

    let lines = h.audit_lines();
    assert_eq!(lines.len(), 4, "un registro por intento: {lines:?}");
    assert_eq!(count(&lines, "auth_failed"), 3);
    assert_eq!(count(&lines, "auth_throttled"), 1);
    assert!(
        lines
            .iter()
            .all(|l| l.contains("\"source\":\"relay\"") && l.contains("\"operator\":\"Tecnico\""))
    );
    let lines2 = h2.audit_lines();
    assert_eq!(count(&lines2, "auth_failed"), 1);
    assert!(!lines.join("\n").contains("Incorrecta") && !lines2.join("\n").contains(PW));
}

/// Con otra clave fijada el operador aborta antes de enviar la contrasena: no hay intento.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clave_fijada_distinta_aborta_sin_enviar_la_contrasena() {
    let h = start().await;
    let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let op = h.operator(&other, PW).await;
    assert!(matches!(
        op.result,
        Err(UnattendedChannelError::InvalidSignature)
    ));
    drop(op);
    // El servicio vuelve a registrarse sin haber llamado al autenticador ni auditado intentos.
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.wait_registered().await;
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    assert!(h.audit_lines().is_empty());
}

/// Kill-switch del banner: el agente avisa, el operador recibe `SessionRevoked` y el agente sale.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_y_desconexion_del_operador_terminan_auditados() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    agent.send(AgentToService::KillSwitch).await;
    assert_eq!(
        revoked(&mut op).await,
        "El usuario local revoco el control."
    );
    agent.obey_stop().await;
    assert!(op.closed().await);
    assert!(!agent.terminated.load(Ordering::SeqCst));
    h.wait_registered().await;
    assert_eq!(count(&h.audit_lines(), "local_kill_switch"), 1);

    // El operador se desconecta: parada ordenada del agente y fin auditado con su motivo.
    let (op, mut agent) = h.session().await;
    drop(op);
    assert!(agent.obey_stop().await.contains("operador"));
    h.wait_registered().await;
    assert_eq!(count(&h.audit_lines(), "operator_disconnected"), 1);
}

/// Bloqueo y desbloqueo: suspension con aviso, entrada descartada y reanudacion solo
/// tras el desbloqueo y dos sondeos `Default`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fila_bloqueo_y_desbloqueo() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    h.events
        .send(ServiceEvent::Wts {
            event_type: WTS_SESSION_LOCK,
            session_id: WIN_SESSION,
        })
        .unwrap();
    assert_eq!(agent.next().await, ServiceToAgent::Suspend);
    assert_eq!(op.ctl().await, HostToClientMessage::LocalApprovalRequired);
    // Suspendida: la entrada no llega al agente; los sondeos Default no reanudan sin desbloqueo.
    op.send(&key_down()).await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    // Sondeos y eventos llegan por canales distintos: las pausas fijan el orden de la prueba.
    tokio::time::sleep(Duration::from_millis(150)).await;
    h.events
        .send(ServiceEvent::Wts {
            event_type: WTS_SESSION_UNLOCK,
            session_id: WIN_SESSION,
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    assert_eq!(op.ctl().await, HostToClientMessage::LocalApprovalCleared);
    assert_eq!(
        agent.next().await,
        ServiceToAgent::Resume {
            force_keyframe: true
        }
    );
    op.send(&key_down()).await;
    assert_eq!(
        agent.next().await,
        ServiceToAgent::Input(key_down()),
        "la tecla del bloqueo se descarto"
    );
    let lines = h.audit_lines();
    assert_eq!(count(&lines, "session_suspended"), 1);
    assert!(lines.iter().any(|l| l.contains("session_locked")));
    assert_eq!(count(&lines, "session_resumed"), 1);
}

/// Escritorio seguro (UAC) detectado por el agente: suspension, aviso y reanudacion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn escritorio_seguro_suspende_y_reanuda() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::SecureOrOther))
        .await;
    assert_eq!(agent.next().await, ServiceToAgent::Suspend);
    assert_eq!(op.ctl().await, HostToClientMessage::LocalApprovalRequired);
    // Un fotograma que llega suspendido no sale hacia el operador.
    agent.frame(1, b"no-debe-salir").await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    agent
        .send(AgentToService::InputDesktop(ProbeKind::Default))
        .await;
    assert_eq!(op.ctl().await, HostToClientMessage::LocalApprovalCleared);
    assert_eq!(
        agent.next().await,
        ServiceToAgent::Resume {
            force_keyframe: true
        }
    );
    agent.frame(2, b"clave").await;
    let (header, payload) = op.video().await;
    assert_eq!(
        (header.frame_seq, payload.as_slice()),
        (2, b"clave".as_slice())
    );
    assert!(h.audit_lines().iter().any(|l| l.contains("secure_desktop")));
}

/// Desconexion de consola, desconexion remota y cierre de sesion terminan la sesion
/// (aviso, auditoria con motivo y cierre ordenado); el servicio se vuelve a registrar cada vez.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filas_desconexiones_y_cierre_de_sesion() {
    let mut h = start().await;
    for (code, reason) in [
        (WTS_CONSOLE_DISCONNECT, "console_disconnect"),
        (WTS_REMOTE_DISCONNECT, "remote_disconnect"),
        (WTS_SESSION_LOGOFF, "session_logoff"),
    ] {
        let (mut op, mut agent) = h.session().await;
        h.events
            .send(ServiceEvent::Wts {
                event_type: code,
                session_id: WIN_SESSION,
            })
            .unwrap();
        assert!(revoked(&mut op).await.contains("termino"));
        agent.obey_stop().await;
        assert!(op.closed().await);
        assert_eq!(count(&h.audit_lines(), reason), 1, "{reason}");
    }
}

/// Cambio de sesion de consola (otra sesion conecta) o de usuario (otro SID en la
/// misma sesion): `SessionSwitched`, sin seguir al usuario nuevo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filas_cambio_de_sesion_y_de_usuario() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    h.events
        .send(ServiceEvent::Wts {
            event_type: WTS_CONSOLE_CONNECT,
            session_id: WIN_SESSION + 5,
        })
        .unwrap();
    assert!(revoked(&mut op).await.contains("autenticarse otra vez"));
    agent.obey_stop().await;

    let (mut op, mut agent) = h.session().await;
    *h.state.sid.lock().unwrap() = "S-1-5-21-1-2-3-2002".to_string();
    assert!(revoked(&mut op).await.contains("autenticarse otra vez"));
    agent.obey_stop().await;
    assert_eq!(count(&h.audit_lines(), "session_switched"), 2);
}

/// Parada del servicio con sesion activa; el agente que no obedece se termina con
/// `TerminateProcess` solo despues del plazo del cierre ordenado.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fila_parada_del_servicio_y_terminate_tras_plazo() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    let stopped_at = Instant::now();
    h.events.send(ServiceEvent::Stop).unwrap();
    assert!(revoked(&mut op).await.contains("se detuvo"));
    // El agente recibe Stop pero no sale.
    assert!(matches!(agent.next().await, ServiceToAgent::Stop { .. }));
    timeout(STEP, &mut h.service).await.unwrap().unwrap();
    assert!(agent.terminated.load(Ordering::SeqCst));
    assert!(
        stopped_at.elapsed() >= Duration::from_millis(400),
        "TerminateProcess solo tras el plazo"
    );
    assert_eq!(count(&h.audit_lines(), "service_stopping"), 1);
}

/// La pipe la abrio otro proceso (PID distinto del lanzado): no hay sesion y el agente propio se
/// termina. Sin consola autorizable: rechazo generico sin llamar al autenticador.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pid_ajeno_en_la_pipe_y_sin_consola() {
    let mut h = start().await;
    h.state.wrong_client_pid.store(true, Ordering::SeqCst);
    let mut op = h.operator(&h.key.clone(), PW).await;
    assert!(op.result.is_ok());
    let conn = timeout(STEP, h.agents.recv()).await.unwrap().unwrap();
    assert_eq!(
        revoked(&mut op).await,
        "No se pudo iniciar el agente de sesion."
    );
    assert!(conn.terminated.load(Ordering::SeqCst));
    // El PID ajeno queda auditado como fin de la sesion con su motivo.
    h.wait_registered().await;
    assert_eq!(count(&h.audit_lines(), "foreign_pipe_client"), 1);

    *h.state.console.lock().unwrap() = None;
    let calls = h.calls.load(Ordering::SeqCst);
    let rejected = h.operator(&h.key.clone(), PW).await;
    assert!(matches!(
        rejected.result,
        Err(UnattendedChannelError::Rejected { retry_after: None })
    ));
    assert_eq!(h.calls.load(Ordering::SeqCst), calls);
    assert_eq!(count(&h.audit_lines(), "auth_failed"), 1);
}

/// Respuesta a una version incompatible: se responde sin contar intento.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_incompatible_no_cuenta_intento() {
    let h = start().await;
    h.wait_registered().await;
    let client = RelayClient::new(h.relay_addr, h.pin.clone()).unwrap();
    let mut stream = client
        .connect_operator(SessionId::parse(&TARGET.to_string()).unwrap())
        .await
        .unwrap();
    let (_hs, mut hello) = OperatorUnattendedHandshake::start(TARGET, "x", &h.key).unwrap();
    hello.protocol_version = 99;
    stream
        .send_frame(&encode_message(&hello).unwrap())
        .await
        .unwrap();
    let reply: UnattendedHelloReply = decode_message(&recv(&mut stream).await).unwrap();
    assert!(matches!(
        reply,
        UnattendedHelloReply::UnsupportedProtocolVersion { .. }
    ));
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    assert!(h.audit_lines().is_empty());
}

/// El administrador revoca la contrasena (no la cambia): fin con `credential_revoked`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocar_la_contrasena_termina_la_sesion() {
    let mut h = start().await;
    let (mut op, mut agent) = h.session().await;
    h.auth
        .lock()
        .unwrap()
        .inner
        .credentials_mut()
        .revoke()
        .unwrap();
    assert!(revoked(&mut op).await.contains("revocada"));
    agent.obey_stop().await;
    assert!(op.closed().await);
    assert_eq!(count(&h.audit_lines(), "credential_revoked"), 1);
    assert_eq!(count(&h.audit_lines(), "operator_disconnected"), 0);
}

/// Agente simulado que drena sus ordenes; marca el instante del `Stop` y sale al recibirlo.
fn drain_agent(agent: Agent) -> (WriteHalf<DuplexStream>, Arc<Mutex<Option<Instant>>>) {
    let Agent {
        mut r, w, exited, ..
    } = agent;
    let stop_at = Arc::new(Mutex::new(None));
    let mark = stop_at.clone();
    tokio::spawn(async move {
        while let Ok(order) = recv_from_service(&mut r).await {
            if matches!(order, ServiceToAgent::Stop { .. }) {
                *mark.lock().unwrap() = Some(Instant::now());
                exited.store(true, Ordering::SeqCst);
            }
        }
    });
    (w, stop_at)
}

/// Operador autenticado que inunda de `Ping` y nunca lee el control: la cola hacia el operador
/// se llena (los `Pong` se descartan) sin bloquear el bucle de la sesion.
async fn flood_without_reading(op: &mut Operator) {
    for seq in 0..20_000u64 {
        let plain = encode_message(&ClientToHostMessage::Ping {
            seq,
            client_mono_us: 0,
        })
        .unwrap();
        let record = op.session().channel.seal(&plain).unwrap();
        match timeout(Duration::from_secs(3), op.stream.send_frame(&record)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
    }
}

fn frame(seq: u64) -> AgentVideo {
    AgentVideo {
        header: VideoPacketHeader {
            frame_seq: seq,
            capture_ts_us: seq,
            monitor_index: 0,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: 4,
        },
        payload: b"abcd".to_vec(),
    }
}

/// Cota de los cierres: revalidacion + cierre ordenado del agente (100 + 400 ms en el arnes),
/// con margen para el planificador.
const CLOSE_BOUND: Duration = Duration::from_millis(100 + 400 + 400);

/// Con un operador que no lee el control, cambiar la contrasena termina la sesion a
/// tiempo, sin video posterior y auditada como `credential_revoked`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operador_que_no_lee_no_bloquea_la_revocacion() {
    let mut h = start().await;
    let (mut op, agent) = h.session().await;
    let (mut w, stop_at) = drain_agent(agent);
    send_video(&mut w, &frame(1)).await.unwrap();
    let mut video_rx = op.video_rx.take().unwrap();
    for _ in 0..2 {
        timeout(STEP, video_rx.recv()).await.unwrap().unwrap();
    }
    flood_without_reading(&mut op).await;

    let revoked_at = Instant::now();
    h.auth
        .lock()
        .unwrap()
        .inner
        .credentials_mut()
        .rotate("Otra-Clave-Desatendida-1", &FastKdf)
        .unwrap();
    let deadline = revoked_at + CLOSE_BOUND;
    while stop_at.lock().unwrap().is_none() {
        assert!(Instant::now() < deadline, "sin Stop al agente a tiempo");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Ningun fotograma sale despues de la revocacion.
    for seq in 2..12 {
        let _ = timeout(Duration::from_millis(200), send_video(&mut w, &frame(seq))).await;
    }
    assert!(
        timeout(Duration::from_millis(500), video_rx.recv())
            .await
            .map_or(true, |v| v.is_none()),
        "video despues de la revocacion"
    );
    let lines = h.audit_lines();
    assert_eq!(count(&lines, "credential_revoked"), 1, "{lines:?}");
    assert_eq!(count(&lines, "operator_disconnected"), 0, "{lines:?}");
}

/// Con un operador que no lee el control, la parada del servicio termina a tiempo y se
/// audita como `service_stopping`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operador_que_no_lee_no_bloquea_la_parada() {
    let mut h = start().await;
    let (mut op, agent) = h.session().await;
    let (_w, stop_at) = drain_agent(agent);
    flood_without_reading(&mut op).await;
    let stopped_at = Instant::now();
    h.events.send(ServiceEvent::Stop).unwrap();
    timeout(CLOSE_BOUND, &mut h.service)
        .await
        .expect("el servicio no termino a tiempo")
        .unwrap();
    assert!(stopped_at.elapsed() <= CLOSE_BOUND);
    assert!(stop_at.lock().unwrap().is_some(), "el agente recibio Stop");
    let lines = h.audit_lines();
    assert_eq!(count(&lines, "service_stopping"), 1, "{lines:?}");
    assert_eq!(count(&lines, "operator_disconnected"), 0, "{lines:?}");
}

// ------------------------------------------------------------------ agente real

#[derive(Default)]
struct RealLog {
    dispatched: usize,
    released: usize,
    flushed: usize,
    ticks: usize,
}

/// Despachador simulado con las mismas comprobaciones que el real.
struct RealInput(Arc<Mutex<RealLog>>);

impl gate::InputSink for RealInput {
    fn enable_heartbeat(&mut self, _now: Instant) {}
    fn record_ping(&mut self, _now: Instant) {}
    fn tick_heartbeat(
        &mut self,
        _s: &mut awawa_protocol::ApprovedActiveSession,
        _now: Instant,
    ) -> bool {
        self.0.lock().unwrap().ticks += 1;
        false
    }
    fn dispatch(
        &mut self,
        session: &mut awawa_protocol::ApprovedActiveSession,
        desktop: &awawa_protocol::DesktopSessionMonitor,
        cmd: &awawa_protocol::RemoteInputCommand,
    ) -> Result<(), String> {
        if !desktop.input_allowed() {
            return Err("suspendida".to_string());
        }
        session
            .authorize_remote_input(cmd)
            .map_err(|e| format!("{e:?}"))?;
        self.0.lock().unwrap().dispatched += 1;
        Ok(())
    }
    fn release_held_input(&mut self, session: &mut awawa_protocol::ApprovedActiveSession) {
        let n = session.drain_held_input_releases().len();
        self.0.lock().unwrap().released += n;
    }
    fn flush_revocation_releases(&mut self, revocation: &awawa_protocol::SessionRevocation) {
        self.0.lock().unwrap().flushed += revocation.pending_release_commands.len();
    }
}

/// Fuente simulada: fotogramas de `bytes` bytes, escritorio seguro a voluntad y, si `cursor` no
/// es cero, un `CursorShapeUpdate` con ese tamano comprimido en el siguiente fotograma.
struct RealVideo {
    bytes: usize,
    secure: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    produced: Arc<AtomicUsize>,
}

impl net::VideoSource for RealVideo {
    fn monitors(&mut self) -> Vec<MonitorDescriptor> {
        monitors()
    }
    fn probe_input_desktop(&mut self) -> awawa_protocol::InputDesktopKind {
        if self.secure.load(Ordering::SeqCst) {
            awawa_protocol::InputDesktopKind::SecureOrOther
        } else {
            awawa_protocol::InputDesktopKind::Default
        }
    }
    fn next_packet(
        &mut self,
        _session: &awawa_protocol::ApprovedActiveSession,
        _desktop: &awawa_protocol::DesktopSessionMonitor,
        _monitor_index: u8,
        _keyframe: bool,
    ) -> Result<Option<net::SourcePacket>, net::SourceError> {
        std::thread::sleep(Duration::from_millis(5));
        self.produced.fetch_add(1, Ordering::SeqCst);
        let cursor = match self.cursor.swap(0, Ordering::SeqCst) {
            0 => None,
            bytes => Some(big_cursor(bytes)),
        };
        Ok(Some(net::SourcePacket {
            payload: vec![0xAB; self.bytes],
            width: 64,
            height: 32,
            cursor,
        }))
    }
}

struct RealAgent {
    gate: gate::SessionGate,
    kill: agent::KillSwitch,
    log: Arc<Mutex<RealLog>>,
    task: tokio::task::JoinHandle<agent::AgentExit>,
    terminated: Arc<AtomicBool>,
    secure: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    produced: Arc<AtomicUsize>,
    /// Con `true`, las escrituras del agente en la pipe fallan (su escritor muere).
    fail_writes: Arc<AtomicBool>,
}

/// Pipe del agente cuyas escrituras fallan a voluntad; la lectura sigue.
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

impl tokio::io::AsyncWrite for FailingWrites {
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

/// Cursor de 256x256 con `bytes` bytes comprimidos.
fn big_cursor(bytes: usize) -> HostToClientMessage {
    HostToClientMessage::CursorShapeUpdate {
        cursor_hash: 7,
        hotspot_x: 0,
        hotspot_y: 0,
        width: 256,
        height: 256,
        bgra_zstd: Some(vec![0x5A; bytes]),
    }
}

fn spawn_real_agent(conn: AgentConn, frame_bytes: usize) -> RealAgent {
    let log = Arc::new(Mutex::new(RealLog::default()));
    let gate = gate::SessionGate::new(Box::new(RealInput(log.clone())));
    let (kill, local_stop) = agent::KillSwitch::new(gate.clone());
    let secure = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicUsize::new(0));
    let produced = Arc::new(AtomicUsize::new(0));
    let (sec, cur, prod) = (secure.clone(), cursor.clone(), produced.clone());
    let video: net::VideoSourceFactory = Arc::new(move || {
        Ok(Box::new(RealVideo {
            bytes: frame_bytes,
            secure: sec.clone(),
            cursor: cur.clone(),
            produced: prod.clone(),
        }) as Box<dyn net::VideoSource>)
    });
    let cfg = agent::AgentConfig {
        gate: gate.clone(),
        video,
        keyboard_blocked: Arc::new(|| false),
        banner: Arc::new(Mutex::new(agent::BannerInfo::default())),
        local_stop,
        ui_ready: tokio::sync::watch::channel(true).1,
        ui_ready_timeout: STEP,
    };
    let exited = conn.exited.clone();
    let terminated = conn.terminated.clone();
    let fail_writes = Arc::new(AtomicBool::new(false));
    let pipe = FailingWrites {
        inner: conn.pipe,
        fail: fail_writes.clone(),
    };
    let task = tokio::spawn(async move {
        let exit = agent::run_agent(pipe, cfg).await;
        exited.store(true, Ordering::SeqCst);
        exit
    });
    RealAgent {
        gate,
        kill,
        log,
        task,
        terminated,
        secure,
        cursor,
        produced,
        fail_writes,
    }
}

/// Liberaciones entregadas al revocar. Si la captura tenia el candado de la compuerta, la
/// revocacion se completa al soltarlo (milisegundos despues de la marca atomica).
async fn real_flushed(ra: &RealAgent) -> usize {
    for _ in 0..50 {
        let n = ra.log.lock().unwrap().flushed;
        if n > 0 {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    0
}

/// Sesion con el agente real y una tecla retenida.
async fn real_session(
    h: &mut Harness,
    frame_bytes: usize,
    read_video: bool,
) -> (Operator, RealAgent) {
    let mut op = h.operator_opts(&h.key.clone(), PW, read_video).await;
    assert!(op.result.is_ok(), "{:?}", op.result.as_ref().err());
    let conn = timeout(STEP, h.agents.recv()).await.unwrap().unwrap();
    let ra = spawn_real_agent(conn, frame_bytes);
    assert!(matches!(
        op.ctl().await,
        HostToClientMessage::DisplayTopologyChanged { .. }
    ));
    op.send(&key_down()).await;
    let t0 = Instant::now();
    while ra.log.lock().unwrap().dispatched == 0 {
        assert!(t0.elapsed() < STEP, "la tecla no llego al agente");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (op, ra)
}

/// El operador no consume video (el transporte se llena); el dead-man sigue haciendo tics y
/// al cambiar la contrasena el agente libera la tecla, confirma `Stopped` y sale solo, sin
/// `TerminateProcess`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agente_real_operador_no_lee_video_y_revocacion() {
    let mut h = start().await;
    let (mut op, mut ra) = real_session(&mut h, 48 * 1024, false).await;
    // Tiempo para llenar los buferes del video hacia el operador.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ticks = ra.log.lock().unwrap().ticks;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(
        ra.log.lock().unwrap().ticks >= ticks + 2,
        "el dead-man sigue haciendo tics"
    );
    let at = Instant::now();
    h.auth
        .lock()
        .unwrap()
        .inner
        .credentials_mut()
        .rotate("Otra-Clave-Desatendida-1", &FastKdf)
        .unwrap();
    let exit = timeout(CLOSE_BOUND, &mut ra.task)
        .await
        .expect("el agente no salio a tiempo")
        .unwrap();
    assert_eq!(exit, agent::AgentExit::Stopped, "a los {:?}", at.elapsed());
    assert!(!ra.gate.is_active());
    assert_eq!(real_flushed(&ra).await, 1, "la tecla retenida se libera");
    assert!(revoked(&mut op).await.contains("revocada"));
    h.wait_registered().await;
    assert!(
        !ra.terminated.load(Ordering::SeqCst),
        "sin TerminateProcess"
    );
    assert_eq!(count(&h.audit_lines(), "credential_revoked"), 1);
}

/// Kill-switch con el video atascado: auditado como `local_kill_switch` y con
/// `SessionRevoked` al operador.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agente_real_kill_switch_con_video_atascado() {
    let mut h = start().await;
    let (mut op, mut ra) = real_session(&mut h, 48 * 1024, false).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    ra.kill.trigger(agent::LocalStop::KillSwitch);
    assert!(!ra.gate.is_active(), "la compuerta cae al instante");
    assert_eq!(
        revoked(&mut op).await,
        "El usuario local revoco el control."
    );
    let exit = timeout(CLOSE_BOUND, &mut ra.task).await.unwrap().unwrap();
    assert_eq!(exit, agent::AgentExit::KillSwitch);
    assert_eq!(real_flushed(&ra).await, 1);
    h.wait_registered().await;
    assert_eq!(count(&h.audit_lines(), "local_kill_switch"), 1);
}

/// Escritorio seguro repetido con video en curso; el operador abre cada registro con el
/// abridor real, en orden, sin huecos de contador.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agente_real_escritorio_seguro_sin_huecos_de_video() {
    for _ in 0..2 {
        let mut h = start().await;
        let (mut op, mut ra) = real_session(&mut h, 64 * 1024, true).await;
        let mut video_rx = op.video_rx.take().unwrap();
        let preamble = timeout(STEP, video_rx.recv()).await.unwrap().unwrap().1;
        let mut opener = op
            .session()
            .video
            .accept_stream(preamble.try_into().unwrap())
            .unwrap();
        let mut opened = 0usize;
        let mut drain = |video_rx: &mut mpsc::UnboundedReceiver<(VideoPacketHeader, Vec<u8>)>,
                         opened: &mut usize| {
            while let Ok((_, record)) = video_rx.try_recv() {
                opener.open(&record).expect("registro de video en orden");
                *opened += 1;
            }
        };
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            ra.secure.store(true, Ordering::SeqCst);
            loop {
                if op.ctl().await == HostToClientMessage::LocalApprovalRequired {
                    break;
                }
            }
            drain(&mut video_rx, &mut opened);
            tokio::time::sleep(Duration::from_millis(100)).await;
            ra.secure.store(false, Ordering::SeqCst);
            loop {
                if op.ctl().await == HostToClientMessage::LocalApprovalCleared {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            drain(&mut video_rx, &mut opened);
        }
        assert!(opened > 4, "llego video tras cada reanudacion ({opened})");
        ra.kill.trigger(agent::LocalStop::KillSwitch);
        let _ = timeout(CLOSE_BOUND, &mut ra.task).await;
    }
}

/// Siguiente aviso de control (saltando cursores) en `wait`, o `None`.
async fn next_notice(op: &mut Operator, wait: Duration) -> Option<HostToClientMessage> {
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(Ok(record)) = timeout(left, op.stream.recv_frame()).await else {
            return None;
        };
        let plain = op.session().channel.open(&record).unwrap();
        match decode_message(&plain).unwrap() {
            HostToClientMessage::CursorShapeUpdate { .. } => {}
            msg => return Some(msg),
        }
    }
    None
}

/// Un cursor que no cabe en la trama de la pipe (70 000 bytes) o en un registro hacia el
/// operador (justo por encima del tope del registro) se omite en el agente: la sesion sigue sana
/// (la captura continua, el escritorio seguro suspende, libera la tecla y avisa, y la entrada no se
/// despacha mientras dura), el operador no recibe ese cursor y el kill-switch se audita como tal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agente_real_cursor_que_no_cabe_se_omite_y_la_sesion_sigue() {
    let near = big_cursor(65_505);
    assert!(encode_message(&near).unwrap().len() > MAX_CONTROL_PLAINTEXT);
    let piped = encode_message(&AgentToService::Control(near)).unwrap();
    assert!(piped.len() < MAX_AGENT_CONTROL_FRAME, "cabe en la pipe");

    let mut h = start().await;
    let (mut op, mut ra) = real_session(&mut h, 8 * 1024, true).await;
    for bytes in [70_000, 65_505] {
        ra.cursor.store(bytes, Ordering::SeqCst);
        let t0 = Instant::now();
        while ra.cursor.load(Ordering::SeqCst) != 0 {
            assert!(t0.elapsed() < STEP, "la fuente no emitio el cursor");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let before = ra.produced.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            ra.produced.load(Ordering::SeqCst) > before + 5,
            "la captura sigue tras el cursor de {bytes} bytes"
        );
        assert!(!ra.task.is_finished(), "el agente sigue vivo");
        assert!(ra.gate.is_active());
    }
    // Nada llego al operador: ni los cursores que no caben ni un aviso de fin.
    assert!(
        timeout(Duration::from_millis(300), op.stream.recv_frame())
            .await
            .is_err(),
        "el operador no recibe control"
    );

    // Escritorio seguro: suspende, libera la tecla retenida y avisa; la entrada no se despacha.
    ra.secure.store(true, Ordering::SeqCst);
    assert_eq!(
        next_notice(&mut op, STEP).await,
        Some(HostToClientMessage::LocalApprovalRequired)
    );
    let t0 = Instant::now();
    while ra.log.lock().unwrap().released == 0 {
        assert!(t0.elapsed() < STEP, "la tecla retenida se libera");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let dispatched = ra.log.lock().unwrap().dispatched;
    op.send(&key_down()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ra.log.lock().unwrap().dispatched, dispatched);
    ra.secure.store(false, Ordering::SeqCst);
    assert_eq!(
        next_notice(&mut op, STEP).await,
        Some(HostToClientMessage::LocalApprovalCleared)
    );

    ra.kill.trigger(agent::LocalStop::KillSwitch);
    assert_eq!(
        revoked(&mut op).await,
        "El usuario local revoco el control."
    );
    let exit = timeout(CLOSE_BOUND, &mut ra.task).await.unwrap().unwrap();
    assert_eq!(exit, agent::AgentExit::KillSwitch);
    h.wait_registered().await;
    let lines = h.audit_lines();
    assert_eq!(count(&lines, "local_kill_switch"), 1, "{lines:?}");
    assert_eq!(count(&lines, "agent_failed"), 0, "{lines:?}");
    assert!(!ra.terminated.load(Ordering::SeqCst));
}

/// Si el escritor de la pipe del agente muere, la sesion no queda zombi: el agente revoca
/// (la tecla retenida se libera) y sale, y el servicio, al cerrarse la pipe, termina la sesion con
/// `agent_failed` auditado y `SessionRevoked` al operador. La entrada posterior no se despacha.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agente_real_escritor_muerto_termina_auditado() {
    let mut h = start().await;
    let (mut op, mut ra) = real_session(&mut h, 8 * 1024, true).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    ra.fail_writes.store(true, Ordering::SeqCst);
    let exit = timeout(STEP, &mut ra.task).await.unwrap().unwrap();
    assert!(
        matches!(
            exit,
            agent::AgentExit::PipeClosed | agent::AgentExit::Failed(_)
        ),
        "{exit:?}"
    );
    assert!(!ra.gate.is_active());
    assert_eq!(real_flushed(&ra).await, 1, "la tecla retenida se libera");
    assert_eq!(
        revoked(&mut op).await,
        "El agente de sesion no esta disponible."
    );
    let dispatched = ra.log.lock().unwrap().dispatched;
    if let Ok(record) = op
        .session()
        .channel
        .seal(&encode_message(&key_down()).unwrap())
    {
        let _ = op.stream.send_frame(&record).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ra.log.lock().unwrap().dispatched, dispatched);
    h.wait_registered().await;
    let lines = h.audit_lines();
    assert_eq!(count(&lines, "agent_failed"), 1, "{lines:?}");
}
