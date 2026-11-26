//! Prueba E2E en loopback: relay real + red real del host y del operador, con
//! backends de captura y entrada simulados y sin GUI.
//!
//! Secuencia: registro -> handshake -> aprobacion simulada -> video -> entrada -> revocacion.
//! El host y el operador se incluyen por ruta (`awawa-host/src/{gate,net}.rs` y
//! `awawa-operator/src/net.rs`): son los mismos archivos que compilan los binarios.
//!
//! Acceso desatendido: la red real del operador contra un servicio falso construido con la
//! API publica del canal desatendido (`ServiceAwaitingPassword`) y el `VideoSealer` de la sesion.

#![allow(dead_code)]

#[path = "../../awawa-host/src/gate.rs"]
mod gate;
#[path = "../../awawa-host/src/net.rs"]
mod host_net;
#[path = "../../awawa-operator/src/net.rs"]
mod operator_net;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::unattended_channel::{SigningKey, VerifyingKey};
use awawa_protocol::{
    ApprovedActiveSession, ButtonState, ClientToHostMessage, ConsentError, DesktopSessionMonitor,
    HostToClientMessage, InputDesktopKind, KeyState, MonitorDescriptor, MouseButton,
    OperatorConnectionRequest, RemoteInputCommand, ScopedCapabilities, ServiceAuthOutcome,
    ServiceAwaitingPassword, SessionId, SessionRevocation, UnattendedHello, UnattendedVerdict,
    VideoCodec, VideoPacketHeader, WaitingForRequest, decode_message, encode_message,
};
use awawa_relay::{RelayClient, RelayConfig, RelayIdentity, RelayPin, RelayServer};
use tokio::runtime::Runtime;

use gate::{InputSink, SessionGate};
use host_net::{
    HostNet, HostNetConfig, NetEvent as HostEvent, SourceError, SourcePacket, VideoSource,
};
use operator_net::{NetEvent as OpEvent, OperatorNet, OperatorNetConfig, VideoSink};

const WAIT: Duration = Duration::from_secs(10);

struct Relay {
    runtime: Runtime,
    addr: SocketAddr,
    pin: RelayPin,
}

fn start_relay() -> Relay {
    let runtime = Runtime::new().unwrap();
    let identity = RelayIdentity::generate().unwrap();
    let server = runtime.block_on(async {
        RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            &identity,
            RelayConfig::default(),
        )
        .unwrap()
    });
    let addr = server.local_addr().unwrap();
    runtime.spawn(server.run());
    Relay {
        runtime,
        addr,
        pin: identity.pin(),
    }
}

/// Registro compartido de lo que llega a los backends simulados.
#[derive(Default)]
struct Log {
    dispatched: Vec<RemoteInputCommand>,
    released: Vec<RemoteInputCommand>,
    heartbeat_enabled: bool,
    captures: usize,
    packets: Vec<(VideoPacketHeader, Vec<u8>)>,
    monitors: Vec<MonitorDescriptor>,
}

type SharedLog = Arc<Mutex<Log>>;

/// Despachador simulado con la misma compuerta que el real: escritorio y consentimiento.
struct SimInput(SharedLog);

impl InputSink for SimInput {
    fn enable_heartbeat(&mut self, _now: Instant) {
        self.0.lock().unwrap().heartbeat_enabled = true;
    }
    fn record_ping(&mut self, _now: Instant) {}
    fn tick_heartbeat(&mut self, _session: &mut ApprovedActiveSession, _now: Instant) -> bool {
        false
    }
    fn dispatch(
        &mut self,
        session: &mut ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        cmd: &RemoteInputCommand,
    ) -> Result<(), String> {
        if !desktop.input_allowed() {
            return Err("escritorio suspendido".to_string());
        }
        session
            .authorize_remote_input(cmd)
            .map_err(|e| format!("{e:?}"))?;
        self.0.lock().unwrap().dispatched.push(cmd.clone());
        Ok(())
    }
    fn release_held_input(&mut self, session: &mut ApprovedActiveSession) {
        let releases = session.drain_held_input_releases();
        self.0.lock().unwrap().released.extend(releases);
    }
    fn flush_revocation_releases(&mut self, revocation: &SessionRevocation) {
        self.0
            .lock()
            .unwrap()
            .released
            .extend(revocation.pending_release_commands.iter().cloned());
    }
}

fn monitor() -> MonitorDescriptor {
    MonitorDescriptor {
        index: 0,
        is_primary: true,
        origin_x: 0,
        origin_y: 0,
        width_px: 64,
        height_px: 32,
        dpi_scale_percent: 100,
    }
}

/// Captura simulada: un "fotograma" cada 20 ms; solo puede producirlo con la sesion aprobada.
/// Topologia de la captura simulada. `captured` es lo que entrega el backend; `announced` lo que
/// devuelve `monitors()`, que puede ir por detras (como DXGI tras ACCESS_LOST).
struct SimTopology {
    captured: Vec<MonitorDescriptor>,
    announced: Vec<MonitorDescriptor>,
    fail: bool,
}

type SharedTopology = Arc<Mutex<SimTopology>>;

struct SimSource {
    log: SharedLog,
    secure_desktop: Arc<AtomicBool>,
    topology: SharedTopology,
    n: u32,
}

impl VideoSource for SimSource {
    fn monitors(&mut self) -> Vec<MonitorDescriptor> {
        self.topology.lock().unwrap().announced.clone()
    }
    fn probe_input_desktop(&mut self) -> InputDesktopKind {
        if self.secure_desktop.load(Ordering::SeqCst) {
            InputDesktopKind::SecureOrOther
        } else {
            InputDesktopKind::Default
        }
    }
    fn next_packet(
        &mut self,
        session: &ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        monitor_index: u8,
        keyframe: bool,
    ) -> Result<Option<SourcePacket>, SourceError> {
        assert!(session.can_capture_desktop() && desktop.capture_allowed());
        std::thread::sleep(Duration::from_millis(20));
        let (fail, current) = {
            let t = self.topology.lock().unwrap();
            let m = t
                .captured
                .iter()
                .find(|m| m.index == monitor_index)
                .cloned();
            (t.fail, m)
        };
        if fail {
            return Err(SourceError::Failed("backend caido".to_string()));
        }
        let Some(m) = current else {
            return Err(SourceError::Failed("monitor desaparecido".to_string()));
        };
        self.n += 1;
        self.log.lock().unwrap().captures += 1;
        let tag = if keyframe { "key" } else { "delta" };
        Ok(Some(SourcePacket {
            payload: format!("{tag}-{}x{}-{}", m.width_px, m.height_px, self.n).into_bytes(),
            width: m.width_px,
            height: m.height_px,
            cursor: None,
        }))
    }
}

struct SimSink(SharedLog);

impl VideoSink for SimSink {
    fn set_monitors(&mut self, monitors: &[MonitorDescriptor]) -> Result<(), String> {
        self.0.lock().unwrap().monitors = monitors.to_vec();
        Ok(())
    }
    fn packet(&mut self, header: &VideoPacketHeader, payload: &[u8]) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .packets
            .push((*header, payload.to_vec()));
        Ok(())
    }
}

struct Host {
    net: HostNet,
    gate: SessionGate,
    log: SharedLog,
    secure_desktop: Arc<AtomicBool>,
    keyboard_blocked: Arc<AtomicBool>,
    topology: SharedTopology,
}

fn start_host(relay: &Relay) -> Host {
    let log = SharedLog::default();
    let gate = SessionGate::new(Box::new(SimInput(log.clone())));
    let secure_desktop = Arc::new(AtomicBool::new(false));
    let keyboard_blocked = Arc::new(AtomicBool::new(false));
    let (source_log, flag) = (log.clone(), secure_desktop.clone());
    let blocked = keyboard_blocked.clone();
    let topology = Arc::new(Mutex::new(SimTopology {
        captured: vec![monitor()],
        announced: vec![monitor()],
        fail: false,
    }));
    let source_topology = topology.clone();
    let net = HostNet::start(HostNetConfig {
        relay_addr: relay.addr,
        pin: relay.pin.clone(),
        gate: gate.clone(),
        video: Arc::new(move || {
            Ok(Box::new(SimSource {
                log: source_log.clone(),
                secure_desktop: flag.clone(),
                topology: source_topology.clone(),
                n: 0,
            }) as Box<dyn VideoSource>)
        }),
        keyboard_blocked: Arc::new(move || blocked.load(Ordering::SeqCst)),
        wake: Arc::new(|| {}),
    })
    .unwrap();
    Host {
        net,
        gate,
        log,
        secure_desktop,
        keyboard_blocked,
        topology,
    }
}

fn start_operator(relay: &Relay, id: SessionId, password: &str) -> (OperatorNet, SharedLog) {
    start_operator_with(relay, id, password, None)
}

fn start_operator_with(
    relay: &Relay,
    id: SessionId,
    password: &str,
    host_key: Option<VerifyingKey>,
) -> (OperatorNet, SharedLog) {
    let log = SharedLog::default();
    let net = OperatorNet::start(OperatorNetConfig {
        relay_addr: relay.addr,
        pin: relay.pin.clone(),
        request: OperatorConnectionRequest {
            target_session_id: id,
            operator_display_name: "Operador E2E".to_string(),
            operator_ed25519_fingerprint: [7; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        },
        host_key,
        password: Box::new(Box::new(password.to_string())),
        sink: Box::new(SimSink(log.clone())),
        wake: Arc::new(|| {}),
    });
    (net, log)
}

fn wait_host(host: &Host, mut pick: impl FnMut(HostEvent) -> Option<HostEvent>) -> HostEvent {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(event) = host.net.poll_event()
            && let Some(found) = pick(event)
        {
            return found;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("el host no emitio el evento esperado a tiempo");
}

fn wait_op(op: &OperatorNet, mut pick: impl FnMut(&OpEvent) -> bool) -> OpEvent {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(event) = op.poll_event()
            && pick(&event)
        {
            return event;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("el operador no emitio el evento esperado a tiempo");
}

fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("no se cumplio a tiempo: {what}");
}

fn registered(event: HostEvent) -> Option<HostEvent> {
    matches!(event, HostEvent::Registered).then_some(event)
}

/// Registra el host con credenciales nuevas y conecta un operador con `password`. Devuelve el
/// resultado del handshake del lado del host.
fn handshake(
    relay: &Relay,
    host: &Host,
    password: Option<&str>,
) -> (
    Result<awawa_protocol::PendingLocalConsent, (WaitingForRequest, ConsentError)>,
    OperatorNet,
    SharedLog,
) {
    let waiting = WaitingForRequest::start_client_reception().unwrap();
    let id = waiting.session_id();
    let real = waiting.display_password();
    host.net.set_session_id(id);
    wait_host(host, registered);
    let (op, op_log) = start_operator(relay, id, password.unwrap_or(&real));
    let HostEvent::OperatorHello { name, auth } = wait_host(host, |e| {
        matches!(e, HostEvent::OperatorHello { .. }).then_some(e)
    }) else {
        unreachable!()
    };
    assert_eq!(name, "Operador E2E");
    // La UI real lo hace desde un hilo propio; aqui el hilo de la prueba hace de UI.
    let outcome = auth
        .authenticate(waiting)
        .expect("la red devuelve las credenciales");
    (outcome, op, op_log)
}

#[test]
fn register_handshake_approve_video_input_and_revoke() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (outcome, op, op_log) = handshake(&relay, &host, None);
    let pending = outcome.expect("contrasena correcta");

    // Pendiente de aprobacion: el operador ve el mismo SAS que el modal local.
    let OpEvent::AwaitingApproval { timeout_secs, sas } =
        wait_op(&op, |e| matches!(e, OpEvent::AwaitingApproval { .. }))
    else {
        unreachable!()
    };
    assert_eq!(timeout_secs, 60);
    assert_eq!(sas, pending.sas().to_string());

    // Antes de aprobar: ni fotogramas ni eventos de entrada.
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 100,
        norm_y: 100,
    });
    std::thread::sleep(Duration::from_millis(400));
    {
        let log = host.log.lock().unwrap();
        assert_eq!(log.captures, 0, "sin captura antes de aprobar");
        assert!(log.dispatched.is_empty(), "sin entrada antes de aprobar");
    }
    assert!(op_log.lock().unwrap().packets.is_empty());

    // Aprobacion simulada (el clic en Aceptar del modal pasados 1,5 s).
    let session = pending
        .approve_locally(Instant::now() + Duration::from_millis(1600), None)
        .expect("aprobacion dentro de plazo");
    host.gate.activate(session, Instant::now());
    assert!(host.log.lock().unwrap().heartbeat_enabled);

    let OpEvent::Approved { monitors } = wait_op(&op, |e| matches!(e, OpEvent::Approved { .. }))
    else {
        unreachable!()
    };
    assert_eq!(monitors, vec![monitor()]);
    assert_eq!(op_log.lock().unwrap().monitors, vec![monitor()]);

    // Video: el primer paquete es clave y llega descifrado y autenticado.
    wait_until(|| op_log.lock().unwrap().packets.len() >= 3, "video");
    {
        let log = op_log.lock().unwrap();
        let (first, payload) = &log.packets[0];
        assert!(first.is_keyframe);
        assert_eq!(first.monitor_index, 0);
        assert!(payload.starts_with(b"key-"));
        assert!(
            log.packets
                .windows(2)
                .all(|w| w[0].0.frame_seq < w[1].0.frame_seq)
        );
    }
    wait_op(&op, |e| matches!(e, OpEvent::Rtt(_)));

    // Entrada: movimiento, clic (el host calcula el punto) y tecla mantenida.
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 65_535,
        norm_y: 0,
    });
    op.send_input(RemoteInputCommand::MouseButton {
        button: MouseButton::Left,
        state: ButtonState::Pressed,
        target_x: -999,
        target_y: -999,
    });
    op.send_input(RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state: KeyState::Down,
    });
    wait_until(|| host.log.lock().unwrap().dispatched.len() == 3, "entrada");
    {
        let log = host.log.lock().unwrap();
        assert_eq!(
            log.dispatched[1],
            RemoteInputCommand::MouseButton {
                button: MouseButton::Left,
                state: ButtonState::Pressed,
                target_x: 63,
                target_y: 0,
            },
            "el punto del clic sale del ultimo movimiento, no del operador"
        );
    }

    // Revocacion: detiene video y entrada y libera la tecla y el boton retenidos.
    assert!(
        host.gate
            .revoke("Revocado por el usuario local (boton)", Instant::now())
    );
    // Si la captura tiene el candado, la liberacion se completa en cuanto lo suelta.
    wait_until(
        || host.log.lock().unwrap().released.len() >= 2,
        "liberacion de tecla y boton",
    );
    let released = host.log.lock().unwrap().released.clone();
    assert!(released.contains(&RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state: KeyState::Up,
    }));
    assert!(released.iter().any(|c| matches!(
        c,
        RemoteInputCommand::MouseButton {
            state: ButtonState::Released,
            ..
        }
    )));
    let OpEvent::Disconnected { reason } =
        wait_op(&op, |e| matches!(e, OpEvent::Disconnected { .. }))
    else {
        unreachable!()
    };
    assert!(reason.contains("revoco"), "{reason}");
    wait_host(&host, |e| matches!(e, HostEvent::OperatorGone).then_some(e));

    let (captures, packets) = (
        host.log.lock().unwrap().captures,
        op_log.lock().unwrap().packets.len(),
    );
    op.send_input(RemoteInputCommand::Keyboard {
        scancode: 0x1F,
        extended: false,
        unicode_char: None,
        state: KeyState::Down,
    });
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        host.log.lock().unwrap().captures,
        captures,
        "captura detenida"
    );
    assert_eq!(
        op_log.lock().unwrap().packets.len(),
        packets,
        "video detenido"
    );
    assert_eq!(
        host.log.lock().unwrap().dispatched.len(),
        3,
        "entrada detenida"
    );

    // Tras revocar, el host se registra de nuevo con un ID nuevo.
    let next = WaitingForRequest::start_client_reception().unwrap();
    host.net.set_session_id(next.session_id());
    wait_host(&host, registered);
}

#[test]
fn wrong_password_never_reaches_the_modal_or_the_backends() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (outcome, op, op_log) = handshake(&relay, &host, Some("WRONG-PASS2"));
    let Err((_waiting, err)) = outcome else {
        panic!("la contrasena equivocada no debe autenticar");
    };
    assert!(matches!(err, ConsentError::InvalidPassword { .. }));
    let OpEvent::Disconnected { reason } =
        wait_op(&op, |e| matches!(e, OpEvent::Disconnected { .. }))
    else {
        unreachable!()
    };
    assert!(reason.contains("incorrectos"), "{reason}");
    let log = host.log.lock().unwrap();
    assert_eq!((log.captures, log.dispatched.len()), (0, 0));
    assert!(op_log.lock().unwrap().packets.is_empty());
}

#[test]
fn local_rejection_reaches_the_operator() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (outcome, op, _op_log) = handshake(&relay, &host, None);
    let pending = outcome.unwrap();
    wait_op(&op, |e| matches!(e, OpEvent::AwaitingApproval { .. }));
    let _waiting = pending.reject_locally().unwrap();
    host.gate.decline();
    wait_op(&op, |e| matches!(e, OpEvent::Rejected { .. }));
    assert_eq!(host.log.lock().unwrap().captures, 0);
}

#[test]
fn secure_desktop_suspends_video_and_input_until_it_goes_away() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (outcome, op, op_log) = handshake(&relay, &host, None);
    let session = outcome
        .unwrap()
        .approve_locally(Instant::now() + Duration::from_millis(1600), None)
        .unwrap();
    host.gate.activate(session, Instant::now());
    wait_op(&op, |e| matches!(e, OpEvent::Approved { .. }));
    wait_until(|| !op_log.lock().unwrap().packets.is_empty(), "video");
    op.send_input(RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state: KeyState::Down,
    });
    wait_until(|| host.log.lock().unwrap().dispatched.len() == 1, "tecla");

    host.secure_desktop.store(true, Ordering::SeqCst);
    wait_op(&op, |e| matches!(e, OpEvent::LocalApprovalRequired));
    wait_until(
        || !host.log.lock().unwrap().released.is_empty(),
        "liberacion al entrar al escritorio seguro",
    );
    std::thread::sleep(Duration::from_millis(100));
    let (captures, packets) = (
        host.log.lock().unwrap().captures,
        op_log.lock().unwrap().packets.len(),
    );
    op.send_input(RemoteInputCommand::Keyboard {
        scancode: 0x1F,
        extended: false,
        unicode_char: None,
        state: KeyState::Down,
    });
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(host.log.lock().unwrap().captures, captures, "sin captura");
    assert_eq!(op_log.lock().unwrap().packets.len(), packets, "sin video");
    assert_eq!(host.log.lock().unwrap().dispatched.len(), 1, "sin entrada");

    host.secure_desktop.store(false, Ordering::SeqCst);
    wait_op(&op, |e| matches!(e, OpEvent::LocalApprovalCleared));
    wait_until(
        || op_log.lock().unwrap().packets.len() > packets,
        "video al volver al escritorio del usuario",
    );
    let resumed = op_log.lock().unwrap().packets[packets].0;
    assert!(resumed.is_keyframe, "se reanuda con fotograma clave");
}

#[test]
fn an_id_taken_in_the_relay_is_reported_to_the_ui() {
    let relay = start_relay();
    let waiting = WaitingForRequest::start_client_reception().unwrap();
    let id = waiting.session_id();
    // Otro registro ocupa el ID antes que el host.
    let squatter = relay.runtime.block_on(async {
        let client = RelayClient::new(relay.addr, relay.pin.clone()).unwrap();
        let registration = client.register_host(id).await.unwrap();
        (client, registration)
    });
    let host = start_host(&relay);
    host.net.set_session_id(id);
    wait_host(&host, |e| {
        matches!(e, HostEvent::SessionIdTaken).then_some(e)
    });
    // La UI genera otro ID y la red lo registra tras la espera.
    let fresh = WaitingForRequest::start_client_reception().unwrap();
    host.net.set_session_id(fresh.session_id());
    wait_host(&host, registered);
    let _runtime = relay.runtime.enter();
    drop(squatter);
}

#[test]
fn remote_key_presses_are_dropped_while_a_protected_window_has_focus() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (outcome, op, _op_log) = handshake(&relay, &host, None);
    let session = outcome
        .unwrap()
        .approve_locally(Instant::now() + Duration::from_millis(1600), None)
        .unwrap();
    host.gate.activate(session, Instant::now());
    wait_op(&op, |e| matches!(e, OpEvent::Approved { .. }));
    let key = |state| RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state,
    };
    op.send_input(key(KeyState::Down));
    wait_until(|| host.log.lock().unwrap().dispatched.len() == 1, "tecla");

    // El banner o el modal tienen el foco: las pulsaciones se descartan, las liberaciones pasan.
    host.keyboard_blocked.store(true, Ordering::SeqCst);
    op.send_input(key(KeyState::Up));
    op.send_input(key(KeyState::Down));
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 10,
        norm_y: 10,
    });
    wait_until(
        || host.log.lock().unwrap().dispatched.len() == 3,
        "liberacion y movimiento",
    );
    let log = host.log.lock().unwrap();
    assert_eq!(log.dispatched[1], key(KeyState::Up));
    assert!(matches!(
        log.dispatched[2],
        RemoteInputCommand::MoveCursor { .. }
    ));
}

fn approved_session(relay: &Relay, host: &Host) -> (OperatorNet, SharedLog) {
    let (outcome, op, op_log) = handshake(relay, host, None);
    let session = outcome
        .unwrap()
        .approve_locally(Instant::now() + Duration::from_millis(1600), None)
        .unwrap();
    host.gate.activate(session, Instant::now());
    wait_op(&op, |e| matches!(e, OpEvent::Approved { .. }));
    wait_until(|| !op_log.lock().unwrap().packets.is_empty(), "video");
    (op, op_log)
}

fn mon(index: u8, origin_x: i32, w: u32, h: u32) -> MonitorDescriptor {
    MonitorDescriptor {
        index,
        is_primary: index == 0,
        origin_x,
        origin_y: 0,
        width_px: w,
        height_px: h,
        dpi_scale_percent: 100,
    }
}

#[test]
fn mode_and_monitor_changes_keep_the_session_and_restart_with_keyframes() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (op, op_log) = approved_session(&relay, &host);

    let mut previous = vec![monitor()];
    let steps = [
        vec![mon(0, 0, 128, 64)],
        vec![mon(0, 0, 32, 16)],
        vec![mon(0, 0, 32, 16), mon(1, 32, 48, 24)],
    ];
    for topology in steps {
        let mark = op_log.lock().unwrap().packets.len();
        // El backend cambia de modo antes de que `monitors()` lo refleje (como tras ACCESS_LOST).
        host.topology.lock().unwrap().captured = topology.clone();
        std::thread::sleep(Duration::from_millis(300));
        host.topology.lock().unwrap().announced = topology.clone();

        let expected = topology.clone();
        wait_op(
            &op,
            |e| matches!(e, OpEvent::TopologyChanged { monitors } if *monitors == expected),
        );
        for m in &topology {
            let key = format!("key-{}x{}-", m.width_px, m.height_px);
            wait_until(
                || {
                    op_log.lock().unwrap().packets[mark..]
                        .iter()
                        .any(|(h, p)| h.monitor_index == m.index && p.starts_with(key.as_bytes()))
                },
                "fotograma clave de la topologia nueva",
            );
            if previous.contains(m) {
                continue;
            }
            // Ningun parcial de un monitor nuevo o con otro modo antes de su fotograma clave.
            let dims = format!("{}x{}-", m.width_px, m.height_px);
            let log = op_log.lock().unwrap();
            let first = log.packets[mark..]
                .iter()
                .find(|(h, p)| h.monitor_index == m.index && contains(p, dims.as_bytes()))
                .unwrap();
            assert!(
                first.0.is_keyframe,
                "{:?}",
                String::from_utf8_lossy(&first.1)
            );
        }
        assert_eq!(op_log.lock().unwrap().monitors, topology);
        previous = topology;
    }

    // La sesion sigue viva: la entrada llega.
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 1,
        norm_y: 1,
    });
    wait_until(
        || !host.log.lock().unwrap().dispatched.is_empty(),
        "entrada tras los cambios",
    );
    assert!(host.gate.is_active());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn persistent_capture_failure_revokes_the_session_with_a_reason() {
    let relay = start_relay();
    let host = start_host(&relay);
    let (op, _op_log) = approved_session(&relay, &host);
    host.topology.lock().unwrap().fail = true;
    let deadline = Instant::now() + WAIT;
    let reason = loop {
        assert!(Instant::now() < deadline, "la sesion debia revocarse");
        if let Some(OpEvent::Disconnected { reason }) = op.poll_event() {
            break reason;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(reason.contains("Captura no disponible"), "{reason}");
    assert!(!host.gate.is_active(), "entrada deshabilitada");
    assert!(host.gate.take_revocation().is_some());
}

// ---------------------------------------------------------------------------------------------
// Acceso desatendido
// ---------------------------------------------------------------------------------------------

const UNATTENDED_ID: &str = "482-910-337";
const UNATTENDED_PASSWORD: &str = " clave larga - Persistente 77 ";

/// Que responde el servicio falso al veredicto de la contrasena.
#[derive(Clone, Copy)]
enum Verdict {
    Grant,
    Reject(Option<Duration>),
}

/// Lo que observa el servicio falso.
#[derive(Default)]
struct ServiceLog {
    /// Registros con la contrasena que llegaron al servicio.
    password_records: usize,
    /// Contrasena tal como la vio el autenticador.
    password_seen: Option<String>,
    /// Mensajes de control del operador tras `Granted`.
    control: Vec<ClientToHostMessage>,
    /// Fotogramas enviados.
    frames_sent: usize,
    /// Huella de sesion del servicio.
    fingerprint: Option<[u8; 8]>,
}

type SharedServiceLog = Arc<Mutex<ServiceLog>>;

fn service_identity() -> SigningKey {
    SigningKey::from_bytes(&[41u8; 32])
}

fn other_identity() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// Servicio falso: se registra en el relay, responde al hello con la identidad dada, autentica con
/// `verdict` y, si concede, anuncia la topologia, envia un fotograma y lee la entrada del operador.
fn start_fake_service(
    relay: &Relay,
    identity: SigningKey,
    verdict: Verdict,
) -> (SharedServiceLog, SessionId) {
    let id = SessionId::parse(UNATTENDED_ID).unwrap();
    let log = SharedServiceLog::default();
    let (addr, pin) = (relay.addr, relay.pin.clone());
    let task_log = log.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    relay.runtime.spawn(async move {
        let client = RelayClient::new(addr, pin).unwrap();
        let registration = client.register_host(id).await.unwrap();
        ready_tx.send(()).unwrap();
        let mut stream = registration.wait_for_operator().await.unwrap();
        let hello: UnattendedHello = decode_message(&stream.recv_frame().await.unwrap()).unwrap();
        let (awaiting, reply) = ServiceAwaitingPassword::respond(&hello, id.raw_u32(), &identity)
            .map_err(|(e, _)| e)
            .unwrap();
        stream
            .send_frame(&encode_message(&reply).unwrap())
            .await
            .unwrap();
        // Si el operador aborta (clave fijada distinta) no llega ningun registro.
        let Ok(record) = stream.recv_frame().await else {
            return;
        };
        {
            let mut l = task_log.lock().unwrap();
            l.password_records += 1;
            l.fingerprint = Some(awaiting.fingerprint());
        }
        let seen = task_log.clone();
        let outcome = awaiting
            .handle_password_record(&record, move |password| {
                seen.lock().unwrap().password_seen = Some(password.to_string());
                match verdict {
                    Verdict::Grant => UnattendedVerdict::Granted { generation: 1 },
                    Verdict::Reject(retry_after) => UnattendedVerdict::Rejected { retry_after },
                }
            })
            .unwrap();
        match outcome {
            ServiceAuthOutcome::Rejected { reply_record, .. } => {
                stream.send_frame(&reply_record).await.unwrap();
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ServiceAuthOutcome::Granted {
                session,
                reply_record,
            } => {
                stream.send_frame(&reply_record).await.unwrap();
                let streams = stream.video_streams();
                let (mut sender, mut receiver) = stream.into_split();
                let mut channel = session.channel;
                let topology = HostToClientMessage::DisplayTopologyChanged {
                    monitors: vec![monitor()],
                };
                let record = channel.seal(&encode_message(&topology).unwrap()).unwrap();
                sender.send_frame(&record).await.unwrap();

                let mut sealer = session.video;
                let mut stream_sealer = sealer.open_stream().unwrap();
                let mut video = streams.open().await.unwrap();
                video.write_all(&stream_sealer.preamble()).await.unwrap();
                let payload = b"key-64x32-unattended".to_vec();
                let header = VideoPacketHeader {
                    frame_seq: 1,
                    capture_ts_us: 0,
                    monitor_index: 0,
                    codec: VideoCodec::ZstdDirtyTiles,
                    is_keyframe: true,
                    payload_len: payload.len() as u32,
                };
                let sealed = stream_sealer.seal(&header, &payload).unwrap();
                video.write_all(&sealed).await.unwrap();
                task_log.lock().unwrap().frames_sent += 1;

                while let Ok(record) = receiver.recv_frame().await {
                    let Ok(plain) = channel.open(&record) else {
                        break;
                    };
                    let Ok(msg) = decode_message::<ClientToHostMessage>(&plain) else {
                        break;
                    };
                    if let ClientToHostMessage::Ping {
                        seq,
                        client_mono_us,
                    } = msg
                    {
                        let pong = HostToClientMessage::Pong {
                            seq,
                            client_mono_us,
                        };
                        let record = channel.seal(&encode_message(&pong).unwrap()).unwrap();
                        let _ = sender.send_frame(&record).await;
                    }
                    task_log.lock().unwrap().control.push(msg);
                }
            }
        }
    });
    ready_rx
        .recv_timeout(WAIT)
        .expect("el servicio no se registro");
    (log, id)
}

fn disconnected_reason(op: &OperatorNet) -> String {
    let OpEvent::Disconnected { reason } =
        wait_op(op, |e| matches!(e, OpEvent::Disconnected { .. }))
    else {
        unreachable!()
    };
    reason
}

#[test]
fn unattended_session_delivers_video_and_input_after_granted() {
    let relay = start_relay();
    let (service, id) = start_fake_service(&relay, service_identity(), Verdict::Grant);
    let (op, op_log) = start_operator_with(
        &relay,
        id,
        UNATTENDED_PASSWORD,
        Some(service_identity().verifying_key()),
    );

    // Sin `AwaitingApproval`: el acceso se concede con la contrasena y la huella coincide.
    let OpEvent::UnattendedGranted { fingerprint } =
        wait_op(&op, |e| matches!(e, OpEvent::UnattendedGranted { .. }))
    else {
        unreachable!()
    };
    wait_until(
        || service.lock().unwrap().fingerprint == Some(fingerprint),
        "huella de sesion igual en ambos extremos",
    );
    // La contrasena llega sin normalizar (espacios y guiones incluidos).
    assert_eq!(
        service.lock().unwrap().password_seen.as_deref(),
        Some(UNATTENDED_PASSWORD)
    );
    let OpEvent::Approved { monitors } = wait_op(&op, |e| matches!(e, OpEvent::Approved { .. }))
    else {
        unreachable!()
    };
    assert_eq!(monitors, vec![monitor()]);

    // Video: llega descifrado y autenticado.
    wait_until(|| !op_log.lock().unwrap().packets.is_empty(), "fotograma");
    {
        let log = op_log.lock().unwrap();
        let (header, payload) = &log.packets[0];
        assert!(header.is_keyframe);
        assert_eq!(payload, b"key-64x32-unattended");
    }
    wait_op(&op, |e| matches!(e, OpEvent::Rtt(_)));

    // Entrada: llega al servicio por el canal cifrado.
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 100,
        norm_y: 200,
    });
    op.send_input(RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state: KeyState::Down,
    });
    wait_until(
        || {
            let l = service.lock().unwrap();
            l.control
                .iter()
                .any(|m| matches!(m, ClientToHostMessage::PointerMove { norm_x: 100, .. }))
                && l.control
                    .iter()
                    .any(|m| matches!(m, ClientToHostMessage::KeyboardEvent { scancode: 0x1E, .. }))
        },
        "entrada en el servicio",
    );
}

#[test]
fn unattended_wrong_password_gives_a_generic_error_without_video_or_input() {
    let relay = start_relay();
    let (service, id) = start_fake_service(&relay, service_identity(), Verdict::Reject(None));
    let (op, op_log) = start_operator_with(
        &relay,
        id,
        "contrasena equivocada",
        Some(service_identity().verifying_key()),
    );
    let reason = disconnected_reason(&op);
    assert!(reason.contains("Autenticación rechazada"), "{reason}");
    assert!(!reason.contains("reintente"), "{reason}");
    assert!(!reason.contains("equivocada"), "{reason}");
    op.send_input(RemoteInputCommand::MoveCursor {
        norm_x: 1,
        norm_y: 1,
    });
    std::thread::sleep(Duration::from_millis(300));
    let log = op_log.lock().unwrap();
    assert!(log.packets.is_empty() && log.monitors.is_empty());
    let service = service.lock().unwrap();
    assert!(service.control.is_empty());
    assert_eq!(service.frames_sent, 0);
}

#[test]
fn unattended_throttled_rejection_reports_retry_after() {
    let relay = start_relay();
    let (_service, id) = start_fake_service(
        &relay,
        service_identity(),
        Verdict::Reject(Some(Duration::from_secs(37))),
    );
    let (op, _log) = start_operator_with(
        &relay,
        id,
        UNATTENDED_PASSWORD,
        Some(service_identity().verifying_key()),
    );
    let reason = disconnected_reason(&op);
    assert!(reason.contains("Autenticación rechazada"), "{reason}");
    assert!(reason.contains("reintente en 37 s"), "{reason}");
}

#[test]
fn unattended_pinned_key_mismatch_aborts_before_sending_the_password() {
    let relay = start_relay();
    // El servicio firma con otra identidad que la fijada en el operador.
    let (service, id) = start_fake_service(&relay, other_identity(), Verdict::Grant);
    let (op, op_log) = start_operator_with(
        &relay,
        id,
        UNATTENDED_PASSWORD,
        Some(service_identity().verifying_key()),
    );
    let reason = disconnected_reason(&op);
    assert_eq!(
        reason,
        "La identidad del equipo no coincide con la clave fijada."
    );
    std::thread::sleep(Duration::from_millis(300));
    let service = service.lock().unwrap();
    assert_eq!(
        service.password_records, 0,
        "el servicio nunca recibe el registro"
    );
    assert!(service.password_seen.is_none());
    assert_eq!(service.frames_sent, 0);
    assert!(op_log.lock().unwrap().packets.is_empty());
}
