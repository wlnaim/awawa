//! Pruebas de la compuerta de sesion (`gate`) sin red ni backends reales.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use awawa_protocol::{
    ApprovedActiveSession, ButtonState, DesktopSessionMonitor, InputDesktopKind, KeyState,
    MouseButton, OperatorConnectionRequest, RemoteInputCommand, ScopedCapabilities,
    SessionRevocation, WaitingForRequest, run_in_memory_handshake,
};

use crate::gate::{GateStatus, InputSink, SessionGate};

#[derive(Default)]
pub(crate) struct Log {
    pub dispatched: Vec<RemoteInputCommand>,
    pub released: Vec<RemoteInputCommand>,
    pub heartbeat_enabled: bool,
}

pub(crate) struct RecordingSink(Arc<StdMutex<Log>>);

impl InputSink for RecordingSink {
    fn enable_heartbeat(&mut self, _now: Instant) {
        self.0.lock().unwrap().heartbeat_enabled = true;
    }
    fn record_ping(&mut self, _now: Instant) {}
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

/// Compuerta con un despachador que solo registra lo que recibe.
pub(crate) fn recording_gate() -> (SessionGate, Arc<StdMutex<Log>>) {
    let log = Arc::new(StdMutex::new(Log::default()));
    (SessionGate::new(Box::new(RecordingSink(log.clone()))), log)
}

fn approved(t0: Instant) -> ApprovedActiveSession {
    let waiting = WaitingForRequest::start_client_reception().unwrap();
    let password = waiting.display_password();
    let req = OperatorConnectionRequest {
        target_session_id: waiting.session_id(),
        operator_display_name: "Operador".into(),
        operator_ed25519_fingerprint: [0; 8],
        requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
    };
    let (host, _) = run_in_memory_handshake(waiting, &req, &password, t0).unwrap();
    host.pending
        .approve_locally(t0 + Duration::from_millis(1500), None)
        .unwrap()
}

fn key(state: KeyState) -> RemoteInputCommand {
    RemoteInputCommand::Keyboard {
        scancode: 0x1E,
        extended: false,
        unicode_char: None,
        state,
    }
}

#[test]
fn nothing_reaches_the_sink_before_activation() {
    let log = Arc::new(StdMutex::new(Log::default()));
    let gate = SessionGate::new(Box::new(RecordingSink(log.clone())));
    assert!(gate.dispatch(&key(KeyState::Down), Instant::now()).is_err());
    assert!(gate.with_session(|_, _| ()).is_none());
    assert!(!gate.capture_allowed());
    assert!(log.lock().unwrap().dispatched.is_empty());
}

#[test]
fn revocation_stops_input_and_flushes_held_keys() {
    let t0 = Instant::now();
    let log = Arc::new(StdMutex::new(Log::default()));
    let gate = SessionGate::new(Box::new(RecordingSink(log.clone())));
    let mut status = gate.subscribe();
    gate.activate(approved(t0), t0);
    assert_eq!(*status.borrow_and_update(), GateStatus::Active);
    assert!(log.lock().unwrap().heartbeat_enabled);
    gate.dispatch(&key(KeyState::Down), t0).unwrap();
    let press = RemoteInputCommand::MouseButton {
        button: MouseButton::Left,
        state: ButtonState::Pressed,
        target_x: 10,
        target_y: 10,
    };
    gate.dispatch(&press, t0).unwrap();

    assert!(gate.revoke("prueba", t0 + Duration::from_secs(2)));
    assert_eq!(*status.borrow_and_update(), GateStatus::Closed);
    assert!(!gate.revoke("otra vez", t0), "una sola revocacion");
    let released = log.lock().unwrap().released.clone();
    assert_eq!(released.len(), 2, "tecla y boton liberados: {released:?}");
    assert!(gate.dispatch(&key(KeyState::Down), t0).is_err());
    assert!(gate.with_session(|_, _| ()).is_none());
    assert_eq!(gate.take_revocation().unwrap().reason, "prueba");
}

#[test]
fn secure_desktop_suspends_releases_and_resumes_after_two_default_polls() {
    let t0 = Instant::now();
    let log = Arc::new(StdMutex::new(Log::default()));
    let gate = SessionGate::new(Box::new(RecordingSink(log.clone())));
    gate.activate(approved(t0), t0);
    gate.dispatch(&key(KeyState::Down), t0).unwrap();

    let change = gate.observe_input_desktop(InputDesktopKind::SecureOrOther);
    assert!(change.local_approval_required);
    assert!(
        !gate
            .observe_input_desktop(InputDesktopKind::SecureOrOther)
            .local_approval_required,
        "un solo aviso por transicion"
    );
    assert!(!gate.capture_allowed());
    assert_eq!(log.lock().unwrap().released.len(), 1);
    assert!(gate.dispatch(&key(KeyState::Up), t0).is_err());

    assert!(
        !gate
            .observe_input_desktop(InputDesktopKind::Default)
            .resumed
    );
    assert!(
        gate.observe_input_desktop(InputDesktopKind::Default)
            .resumed
    );
    assert!(gate.capture_allowed());
    assert!(
        !gate
            .observe_input_desktop(InputDesktopKind::Default)
            .resumed,
        "un solo aviso de reanudacion"
    );
}

#[test]
fn decline_closes_only_without_an_active_session() {
    let t0 = Instant::now();
    let gate = SessionGate::new(Box::new(RecordingSink(Arc::default())));
    let status = gate.subscribe();
    gate.decline();
    assert_eq!(*status.borrow(), GateStatus::Closed);
    gate.reset();
    assert_eq!(*status.borrow(), GateStatus::Idle);
    gate.activate(approved(t0), t0);
    gate.decline();
    assert_eq!(*status.borrow(), GateStatus::Active);
}

#[test]
fn a_capture_holding_the_lock_does_not_block_revocation_or_ui_updates() {
    let t0 = Instant::now();
    let (gate, log) = recording_gate();
    gate.activate(approved(t0), t0);
    gate.dispatch(&key(KeyState::Down), t0).unwrap();

    // Simula un `AcquireNextFrame` colgado: la captura retiene el candado hasta que se le avise.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let capture_gate = gate.clone();
    let capture = std::thread::spawn(move || {
        capture_gate.with_session(|_, _| {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        })
    });
    entered_rx.recv().unwrap();

    let started = Instant::now();
    assert!(gate.revoke("prueba", t0 + Duration::from_secs(1)));
    gate.update_protected_rect(awawa_protocol::ProtectedRect {
        left: 0,
        top: 0,
        right: 10,
        bottom: 10,
        safety_margin_px: 8,
    });
    gate.record_ping(t0);
    assert!(!gate.tick_heartbeat(t0));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "nada de esto espera a la captura"
    );
    // La marca corta al instante: ni captura nueva ni entrada.
    assert!(!gate.is_active());
    assert!(gate.with_session(|_, _| ()).is_none());
    assert!(gate.dispatch(&key(KeyState::Up), t0).is_err());
    assert!(
        log.lock().unwrap().released.is_empty(),
        "aun retenida por la captura"
    );

    release_tx.send(()).unwrap();
    capture.join().unwrap();
    // Al soltar el candado la captura completa la revocacion y libera la tecla.
    assert_eq!(log.lock().unwrap().released, vec![key(KeyState::Up)]);
    assert_eq!(gate.take_revocation().unwrap().reason, "prueba");
    assert_eq!(*gate.subscribe().borrow(), GateStatus::Closed);
}

/// Backend de `SendInput` en memoria y compartido, detras del despachador real.
struct SharedBackend(Arc<StdMutex<Vec<RemoteInputCommand>>>);

impl input_win::PeripheralBackend for SharedBackend {
    fn inject_command(
        &mut self,
        cmd: &RemoteInputCommand,
    ) -> Result<(), input_win::InjectionError> {
        self.0.lock().unwrap().push(cmd.clone());
        Ok(())
    }
}

#[test]
fn heartbeat_expiry_releases_held_input_while_the_capture_keeps_the_lock() {
    let t0 = Instant::now();
    let injected = Arc::new(StdMutex::new(Vec::new()));
    // Despachador real: dead-man de 3 s (`HEARTBEAT_TIMEOUT`) con el reloj que se le pasa.
    let dispatcher = input_win::ConsentGatedInputDispatcher::new(SharedBackend(injected.clone()));
    let gate = SessionGate::new(Box::new(dispatcher));
    gate.activate(approved(t0), t0);
    gate.dispatch(&key(KeyState::Down), t0).unwrap();
    let press = RemoteInputCommand::MouseButton {
        button: MouseButton::Left,
        state: ButtonState::Pressed,
        target_x: 5,
        target_y: 5,
    };
    gate.dispatch(&press, t0).unwrap();

    // Captura que retiene el candado en bucle (pantalla activa: casi siempre ocupado).
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (capture_gate, capture_stop) = (gate.clone(), stop.clone());
    let capture = std::thread::spawn(move || {
        while !capture_stop.load(std::sync::atomic::Ordering::SeqCst) {
            capture_gate.with_session(|_, _| std::thread::sleep(Duration::from_millis(30)));
        }
    });

    // Sin pings: los tics de la red avanzan mas alla de 3 s.
    let started = Instant::now();
    let mut tick = t0;
    let released = loop {
        tick += Duration::from_millis(250);
        gate.tick_heartbeat(tick);
        let done = injected.lock().unwrap().len() >= 4;
        if done || started.elapsed() > Duration::from_secs(2) {
            break done;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    capture.join().unwrap();
    assert!(
        released,
        "el dead-man libera aunque la captura tenga el candado"
    );
    let log = injected.lock().unwrap();
    assert!(log.contains(&key(KeyState::Up)));
    assert!(log.iter().any(|c| matches!(
        c,
        RemoteInputCommand::MouseButton {
            state: ButtonState::Released,
            ..
        }
    )));
}
