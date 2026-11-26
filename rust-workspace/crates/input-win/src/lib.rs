//! # `input-win`
//!
//! Subsistema de inyección de Cursor y Teclado sobre Windows (`USER32!SendInput`).
//! La implementación FFI se conecta con `windows::Win32::UI::Input::KeyboardAndMouse::SendInput`;
//! este crate ya implementa la compuerta de autorización `ConsentGatedInputDispatcher` y la síntesis real
//! de `SendInput` para Windows x64 cuando se invoca explícitamente bajo sesión aprobada.
//! Toda inyección exige además que `DesktopSessionMonitor` esté en `Streaming`: nunca se inyecta
//! durante el escritorio seguro (UAC), con la sesión bloqueada ni tras finalizar la sesión.

mod guard;
mod heartbeat;
mod injector;
mod translate;

pub use guard::{PROTECTED_MARGIN_PX, ProtectedWindowGuard, SystemWindowProbe, WindowProbe};
pub use heartbeat::{HEARTBEAT_TIMEOUT, HeartbeatDeadMan};
pub use injector::{WindowsSendInputInjector, windows_input_dispatcher};
pub use translate::{
    INPUT_SIZE, TranslateError, translate_button, translate_command, translate_keyboard,
    translate_move, translate_wheel,
};

use std::time::Instant;

use awawa_protocol::{
    ApprovedActiveSession, ConsentError, DesktopSessionMonitor, RemoteInputCommand,
    SessionRevocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionError {
    ConsentRejected(ConsentError),
    /// El monitor de escritorio/sesión no está en `Streaming` (escritorio seguro, bloqueo o sesión finalizada).
    SuspendedByDesktopState,
    /// Quedan liberaciones de teclas/botones sin entregar al SO: no se aceptan comandos nuevos del operador.
    PendingReleasesUnflushed,
    OsSendInputBlockedOrFailed(u32),
    /// El clic cae sobre (o junto a) una ventana protegida de la UI del host.
    ProtectedWindowHit,
    /// El comando no se puede traducir a `INPUT` (p. ej. tecla sin scancode ni carácter).
    InvalidCommand,
    /// Pasaron más de 3 s sin `Ping`: no se aceptan comandos hasta recibir uno nuevo.
    HeartbeatExpired,
}

pub trait PeripheralBackend {
    fn inject_command(&mut self, cmd: &RemoteInputCommand) -> Result<(), InjectionError>;
}

/// Despachador que exige `&mut ApprovedActiveSession` antes de permitir cualquier comando al SO.
pub struct ConsentGatedInputDispatcher<B: PeripheralBackend> {
    backend: B,
    /// Liberaciones que el SO rechazó (p. ej. con el escritorio seguro activo); se reintentan.
    pending_releases: Vec<RemoteInputCommand>,
    /// Dead-man switch por heartbeat; `None` mientras no se active con `enable_heartbeat`.
    heartbeat: Option<HeartbeatDeadMan>,
}

impl<B: PeripheralBackend> ConsentGatedInputDispatcher<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            pending_releases: Vec::new(),
            heartbeat: None,
        }
    }

    /// Activa el dead-man switch: 3 s sin `record_ping` ⇒ `tick_heartbeat` libera todo.
    pub fn enable_heartbeat(&mut self, now: Instant) {
        self.heartbeat = Some(HeartbeatDeadMan::new(now));
    }

    /// Registra un `Ping` del operador (reanuda la entrada si el heartbeat había expirado).
    pub fn record_ping(&mut self, now: Instant) {
        if let Some(hb) = self.heartbeat.as_mut() {
            hb.record_ping(now);
        }
    }

    /// Debe llamarlo el temporizador del host. Si el silencio alcanza el límite libera teclas y botones
    /// retenidos (con reintento) y devuelve `true` una sola vez por expiración.
    pub fn tick_heartbeat(&mut self, session: &mut ApprovedActiveSession, now: Instant) -> bool {
        let expired = self
            .heartbeat
            .as_mut()
            .is_some_and(|hb| hb.poll_expired(now));
        if expired {
            self.release_held_input(session);
        }
        expired
    }

    pub fn dispatch_authorized(
        &mut self,
        session: &mut ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        cmd: &RemoteInputCommand,
    ) -> Result<(), InjectionError> {
        // Se comprueba antes de registrar el comando en el *Dead-Man Switch* de la sesión.
        if !desktop.input_allowed() {
            return Err(InjectionError::SuspendedByDesktopState);
        }
        if self.heartbeat.as_ref().is_some_and(|hb| hb.is_expired()) {
            return Err(InjectionError::HeartbeatExpired);
        }
        self.retry_pending_releases();
        if !self.pending_releases.is_empty() {
            return Err(InjectionError::PendingReleasesUnflushed);
        }
        session
            .authorize_remote_input(cmd)
            .map_err(InjectionError::ConsentRejected)?;
        self.backend.inject_command(cmd)
    }

    /// Ejecuta la limpieza *Dead-Man Switch* tras la revocación local o desconexión.
    /// Reintenta primero las liberaciones pendientes y las descarta tras el intento (la sesión termina).
    pub fn flush_revocation_releases(&mut self, revocation: &SessionRevocation) {
        for release_cmd in core::mem::take(&mut self.pending_releases) {
            let _ = self.backend.inject_command(&release_cmd);
        }
        for release_cmd in &revocation.pending_release_commands {
            let _ = self.backend.inject_command(release_cmd);
        }
    }

    /// Libera teclas y botones retenidos al suspender la sesión (`MonitorAction::ReleaseHeldInput`).
    /// Solo emite eventos de liberación, por lo que no depende del estado del monitor.
    /// Las liberaciones que el backend rechace quedan pendientes y se reintentan en la próxima llamada
    /// (la FSM vuelve a emitir `ReleaseHeldInput` al reanudar) y antes de cada comando del operador.
    pub fn release_held_input(&mut self, session: &mut ApprovedActiveSession) {
        self.retry_pending_releases();
        for release_cmd in session.drain_held_input_releases() {
            if self.backend.inject_command(&release_cmd).is_err() {
                self.pending_releases.push(release_cmd);
            }
        }
    }

    /// Número de liberaciones aún no entregadas al SO.
    pub fn pending_release_count(&self) -> usize {
        self.pending_releases.len()
    }

    fn retry_pending_releases(&mut self) {
        let pending = core::mem::take(&mut self.pending_releases);
        for release_cmd in pending {
            if self.backend.inject_command(&release_cmd).is_err() {
                self.pending_releases.push(release_cmd);
            }
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Backend en memoria para pruebas deterministas sin mover el cursor físico del desarrollador.
#[derive(Debug, Default)]
pub struct RecordedInputBackend {
    pub executed: Vec<RemoteInputCommand>,
}

impl PeripheralBackend for RecordedInputBackend {
    fn inject_command(&mut self, cmd: &RemoteInputCommand) -> Result<(), InjectionError> {
        self.executed.push(cmd.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::{
        DesktopEvent, InputDesktopKind, KeyState, OperatorConnectionRequest, ScopedCapabilities,
        WaitingForRequest, run_in_memory_handshake,
    };
    use std::time::{Duration, Instant};

    fn approved_session() -> (ApprovedActiveSession, Instant) {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let t0 = Instant::now();
        let req = OperatorConnectionRequest {
            target_session_id: waiting.session_id(),
            operator_display_name: "Soporte".to_string(),
            operator_ed25519_fingerprint: [1; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };
        let password = waiting.display_password();
        let session = run_in_memory_handshake(waiting, &req, &password, t0)
            .unwrap()
            .0
            .pending
            .approve_locally(t0 + Duration::from_secs(2), None)
            .unwrap();
        (session, t0)
    }

    fn key(scancode: u16, state: KeyState) -> RemoteInputCommand {
        RemoteInputCommand::Keyboard {
            scancode,
            extended: false,
            unicode_char: None,
            state,
        }
    }

    #[test]
    fn input_is_rejected_while_suspended_and_held_keys_are_released() {
        let (mut session, t0) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(RecordedInputBackend::default());
        let mut desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();

        // UAC: escritorio seguro -> rechazo explícito y liberación de Ctrl retenido.
        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::SecureOrOther));
        assert_eq!(
            dispatcher.dispatch_authorized(&mut session, &desktop, &key(0x2A, KeyState::Down)),
            Err(InjectionError::SuspendedByDesktopState)
        );
        dispatcher.release_held_input(&mut session);
        assert_eq!(
            dispatcher.backend().executed,
            vec![key(0x1D, KeyState::Down), key(0x1D, KeyState::Up)]
        );

        // Reanudación tras dos sondeos Default; el comando rechazado no quedó retenido.
        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        assert!(desktop.input_allowed());
        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x38, KeyState::Down))
            .unwrap();

        // Fin de sesión: rechazo, pero la limpieza por revocación sigue funcionando.
        desktop.handle(DesktopEvent::SessionSwitched);
        assert_eq!(
            dispatcher.dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down)),
            Err(InjectionError::SuspendedByDesktopState)
        );
        let revocation =
            session.revoke_immediately(t0 + Duration::from_secs(5), "cambio de sesion");
        assert_eq!(
            revocation.pending_release_commands,
            vec![key(0x38, KeyState::Up)]
        );
        dispatcher.flush_revocation_releases(&revocation);
        assert_eq!(
            dispatcher.backend().executed.last(),
            Some(&key(0x38, KeyState::Up))
        );
        assert_eq!(dispatcher.backend().executed.len(), 4);
    }

    /// Backend que falla mientras `failing` es verdadero (simula `SendInput` bloqueado por el escritorio seguro).
    #[derive(Default)]
    struct FlakyBackend {
        failing: bool,
        executed: Vec<RemoteInputCommand>,
    }

    impl PeripheralBackend for FlakyBackend {
        fn inject_command(&mut self, cmd: &RemoteInputCommand) -> Result<(), InjectionError> {
            if self.failing {
                return Err(InjectionError::OsSendInputBlockedOrFailed(5));
            }
            self.executed.push(cmd.clone());
            Ok(())
        }
    }

    #[test]
    fn failed_releases_during_uac_are_retried_on_resume_and_block_operator_input() {
        use awawa_protocol::MonitorAction;

        let (mut session, _) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(FlakyBackend::default());
        let mut desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();

        // Windows ya cambió al escritorio seguro: la liberación falla y queda pendiente.
        let actions = desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::SecureOrOther));
        assert!(actions.contains(&MonitorAction::ReleaseHeldInput));
        dispatcher.backend.failing = true;
        dispatcher.release_held_input(&mut session);
        assert_eq!(dispatcher.pending_release_count(), 1);

        // Vuelve a Default pero SendInput sigue fallando: comandos del operador rechazados.
        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        let resume = desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        assert_eq!(resume[0], MonitorAction::ReleaseHeldInput);
        assert_eq!(
            dispatcher.dispatch_authorized(&mut session, &desktop, &key(0x2A, KeyState::Down)),
            Err(InjectionError::PendingReleasesUnflushed)
        );
        assert_eq!(dispatcher.pending_release_count(), 1);

        // El backend vuelve a funcionar: ReleaseHeldInput de la reanudación entrega la liberación.
        dispatcher.backend.failing = false;
        dispatcher.release_held_input(&mut session);
        assert_eq!(dispatcher.pending_release_count(), 0);
        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x38, KeyState::Down))
            .unwrap();
        assert_eq!(
            dispatcher.backend.executed,
            vec![
                key(0x1D, KeyState::Down),
                key(0x1D, KeyState::Up),
                key(0x38, KeyState::Down),
            ]
        );

        // Los comandos rechazados no quedaron registrados como teclas retenidas.
        dispatcher.release_held_input(&mut session);
        assert_eq!(
            dispatcher.backend.executed.last(),
            Some(&key(0x38, KeyState::Up))
        );
        assert_eq!(dispatcher.backend.executed.len(), 4);
    }

    #[test]
    fn revocation_flush_retries_pending_releases_first_and_empties_queue() {
        let (mut session, t0) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(FlakyBackend::default());
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();
        dispatcher.backend.failing = true;
        dispatcher.release_held_input(&mut session);
        assert_eq!(dispatcher.pending_release_count(), 1);
        dispatcher.backend.failing = false;

        // Revocación con una tecla retenida adicional registrada directamente en la sesión.
        session
            .authorize_remote_input(&key(0x2A, KeyState::Down))
            .unwrap();
        let revocation = session.revoke_immediately(t0 + Duration::from_secs(5), "fin");
        dispatcher.flush_revocation_releases(&revocation);
        assert_eq!(dispatcher.pending_release_count(), 0);
        assert_eq!(
            dispatcher.backend.executed,
            vec![
                key(0x1D, KeyState::Down),
                key(0x1D, KeyState::Up),
                key(0x2A, KeyState::Up),
            ]
        );
    }

    #[test]
    fn revocation_flush_empties_queue_even_if_backend_keeps_failing() {
        let (mut session, t0) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(FlakyBackend::default());
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();
        dispatcher.backend.failing = true;
        dispatcher.release_held_input(&mut session);
        let revocation = session.revoke_immediately(t0 + Duration::from_secs(5), "fin");
        dispatcher.flush_revocation_releases(&revocation);
        assert_eq!(dispatcher.pending_release_count(), 0);
    }

    #[test]
    fn pending_releases_are_retried_before_operator_command() {
        let (mut session, _) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(FlakyBackend::default());
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();
        dispatcher.backend.failing = true;
        dispatcher.release_held_input(&mut session);
        dispatcher.backend.failing = false;

        // dispatch_authorized reintenta primero la cola y luego entrega el comando.
        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x2A, KeyState::Down))
            .unwrap();
        assert_eq!(
            dispatcher.backend.executed,
            vec![
                key(0x1D, KeyState::Down),
                key(0x1D, KeyState::Up),
                key(0x2A, KeyState::Down),
            ]
        );
    }

    #[test]
    fn heartbeat_silence_releases_everything_and_blocks_until_next_ping() {
        let (mut session, t0) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(RecordedInputBackend::default());
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);
        dispatcher.enable_heartbeat(t0);

        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();
        dispatcher.record_ping(t0 + Duration::from_secs(2));
        assert!(!dispatcher.tick_heartbeat(&mut session, t0 + Duration::from_secs(4)));

        // 3 s después del ultimo Ping: libera Ctrl una sola vez.
        assert!(dispatcher.tick_heartbeat(&mut session, t0 + Duration::from_secs(5)));
        assert!(!dispatcher.tick_heartbeat(&mut session, t0 + Duration::from_secs(6)));
        assert_eq!(
            dispatcher.backend().executed,
            vec![key(0x1D, KeyState::Down), key(0x1D, KeyState::Up)]
        );
        assert_eq!(
            dispatcher.dispatch_authorized(&mut session, &desktop, &key(0x2A, KeyState::Down)),
            Err(InjectionError::HeartbeatExpired)
        );

        // Un Ping nuevo reanuda; el comando rechazado no quedó retenido.
        dispatcher.record_ping(t0 + Duration::from_secs(7));
        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x38, KeyState::Down))
            .unwrap();
        dispatcher.release_held_input(&mut session);
        assert_eq!(dispatcher.backend().executed.len(), 4);
    }

    #[test]
    fn heartbeat_release_keeps_failed_releases_pending_for_retry() {
        let (mut session, t0) = approved_session();
        let mut dispatcher = ConsentGatedInputDispatcher::new(FlakyBackend::default());
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);
        dispatcher.enable_heartbeat(t0);
        dispatcher
            .dispatch_authorized(&mut session, &desktop, &key(0x1D, KeyState::Down))
            .unwrap();
        dispatcher.backend.failing = true;
        assert!(dispatcher.tick_heartbeat(&mut session, t0 + Duration::from_secs(3)));
        assert_eq!(dispatcher.pending_release_count(), 1);
    }
}
