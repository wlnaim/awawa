//! Máquina de estados del escritorio de entrada y de la sesión de Windows autorizada.
//!
//! El agente de sesión sondea el escritorio de entrada (`OpenInputDesktop` + `GetUserObjectInformationW`)
//! y el servicio traduce las notificaciones `WM_WTSSESSION_CHANGE` / `SERVICE_CONTROL_SESSIONCHANGE`
//! a [`DesktopEvent`]. Este monitor decide cuándo se permite capturar e inyectar:
//! - Escritorio seguro (UAC / Winlogon) o inaccesible -> suspensión con aviso de aprobación local requerida.
//! - Bloqueo de sesión -> suspensión (no existe desbloqueo remoto).
//! - Reanudación solo tras [`RESUME_CONSECUTIVE_DEFAULT_POLLS`] sondeos consecutivos en `Default`
//!   con la sesión desbloqueada.
//! - Desconexión, cierre de sesión, cambio de sesión o parada del servicio -> fin terminal (absorbente).
//!
//! En el escritorio seguro nunca se captura, nunca se inyecta y nunca se recolectan credenciales.

/// Sondeos consecutivos del escritorio de entrada en `Default` necesarios para reanudar.
pub const RESUME_CONSECUTIVE_DEFAULT_POLLS: u8 = 2;

/// Resultado de sondear el escritorio de entrada actual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDesktopKind {
    /// Escritorio interactivo del usuario (`winsta0\Default`).
    Default,
    /// Escritorio seguro (`Winlogon`, UAC) u otro escritorio distinto de `Default`.
    SecureOrOther,
    /// `OpenInputDesktop` falló (típico mientras el escritorio seguro está activo).
    Inaccessible,
}

/// Eventos observables del escritorio y de la sesión de Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopEvent {
    InputDesktop(InputDesktopKind),
    SessionLock,
    SessionUnlock,
    ConsoleDisconnect,
    RemoteDisconnect,
    SessionLogoff,
    /// La sesión activa cambió a otra sesión o a un SID de usuario distinto del autorizado.
    SessionSwitched,
    ServiceStopping,
    /// Un administrador cambió o revocó la contraseña desatendida con la sesión activa.
    CredentialRevoked,
}

/// Motivo de una suspensión temporal de captura y entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendReason {
    SecureDesktop,
    SessionLocked,
}

impl SuspendReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureDesktop => "secure_desktop",
            Self::SessionLocked => "session_locked",
        }
    }
}

/// Motivo de fin terminal de la sesión autorizada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    ConsoleDisconnect,
    RemoteDisconnect,
    SessionLogoff,
    SessionSwitched,
    ServiceStopping,
    CredentialRevoked,
    /// El usuario local pulso el kill-switch del banner del agente (boton o atajo global).
    LocalKillSwitch,
    /// El operador remoto se desconecto o cerro el canal.
    OperatorDisconnected,
    /// El agente de sesion fallo, no arranco o cerro la pipe.
    AgentFailed,
    /// Un proceso distinto del agente lanzado se conecto a la pipe de la sesion.
    ForeignPipeClient,
}

impl EndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConsoleDisconnect => "console_disconnect",
            Self::RemoteDisconnect => "remote_disconnect",
            Self::SessionLogoff => "session_logoff",
            Self::SessionSwitched => "session_switched",
            Self::ServiceStopping => "service_stopping",
            Self::CredentialRevoked => "credential_revoked",
            Self::LocalKillSwitch => "local_kill_switch",
            Self::OperatorDisconnected => "operator_disconnected",
            Self::AgentFailed => "agent_failed",
            Self::ForeignPipeClient => "foreign_pipe_client",
        }
    }
}

/// Estado observable del monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    Streaming,
    Suspended(SuspendReason),
    Ended(EndReason),
}

/// Avisos que se envían al operador remoto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorNotice {
    /// Windows cambió al escritorio seguro: se requiere aprobación de alguien frente al equipo.
    LocalApprovalRequired,
    /// La sesión de Windows se bloqueó; solo el usuario local puede desbloquearla.
    SessionLocked,
    /// Windows volvió al escritorio del usuario y la sesión se reanudó.
    Resumed,
    SessionEnded {
        reason: EndReason,
    },
}

/// Acciones que el host debe ejecutar, en orden, tras procesar un evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorAction {
    StopCapture,
    ReleaseHeldInput,
    DropQueuedInput,
    NotifyOperator(OperatorNotice),
    ResumeCapture { force_keyframe: bool },
    TerminateAgent,
}

/// Monitor de escritorio/sesión que gobierna la captura y la entrada remotas.
#[derive(Debug)]
pub struct DesktopSessionMonitor {
    state: MonitorState,
    session_locked: bool,
    consecutive_default_polls: u8,
}

impl DesktopSessionMonitor {
    /// Crea el monitor a partir del primer sondeo del escritorio de entrada.
    /// Si el primer sondeo no es `Default`, el monitor nace suspendido por escritorio seguro.
    pub fn new(initial_probe: InputDesktopKind) -> Self {
        match initial_probe {
            InputDesktopKind::Default => Self {
                state: MonitorState::Streaming,
                session_locked: false,
                consecutive_default_polls: RESUME_CONSECUTIVE_DEFAULT_POLLS,
            },
            InputDesktopKind::SecureOrOther | InputDesktopKind::Inaccessible => Self {
                state: MonitorState::Suspended(SuspendReason::SecureDesktop),
                session_locked: false,
                consecutive_default_polls: 0,
            },
        }
    }

    pub fn state(&self) -> MonitorState {
        self.state
    }

    /// Solo se permite capturar en `Streaming`.
    pub fn capture_allowed(&self) -> bool {
        self.state == MonitorState::Streaming
    }

    /// Solo se permite inyectar entrada en `Streaming`.
    pub fn input_allowed(&self) -> bool {
        self.state == MonitorState::Streaming
    }

    /// Procesa un evento y devuelve las acciones a ejecutar. `Ended` es absorbente.
    pub fn handle(&mut self, event: DesktopEvent) -> Vec<MonitorAction> {
        if matches!(self.state, MonitorState::Ended(_)) {
            return Vec::new();
        }

        match event {
            DesktopEvent::InputDesktop(InputDesktopKind::Default) => {
                if self.consecutive_default_polls < RESUME_CONSECUTIVE_DEFAULT_POLLS {
                    self.consecutive_default_polls += 1;
                }
                self.try_resume()
            }
            DesktopEvent::InputDesktop(
                InputDesktopKind::SecureOrOther | InputDesktopKind::Inaccessible,
            ) => {
                self.consecutive_default_polls = 0;
                match self.state {
                    MonitorState::Streaming => self.suspend(
                        SuspendReason::SecureDesktop,
                        OperatorNotice::LocalApprovalRequired,
                    ),
                    _ => Vec::new(),
                }
            }
            DesktopEvent::SessionLock => {
                self.session_locked = true;
                self.consecutive_default_polls = 0;
                match self.state {
                    MonitorState::Streaming => {
                        self.suspend(SuspendReason::SessionLocked, OperatorNotice::SessionLocked)
                    }
                    MonitorState::Suspended(SuspendReason::SecureDesktop) => {
                        // Captura y entrada ya están detenidas; solo cambia el motivo visible.
                        self.state = MonitorState::Suspended(SuspendReason::SessionLocked);
                        vec![MonitorAction::NotifyOperator(OperatorNotice::SessionLocked)]
                    }
                    _ => Vec::new(),
                }
            }
            DesktopEvent::SessionUnlock => {
                // El desbloqueo solo lo realiza el usuario local; se exige además ver `Default` de nuevo.
                self.session_locked = false;
                self.consecutive_default_polls = 0;
                Vec::new()
            }
            DesktopEvent::ConsoleDisconnect => self.end(EndReason::ConsoleDisconnect),
            DesktopEvent::RemoteDisconnect => self.end(EndReason::RemoteDisconnect),
            DesktopEvent::SessionLogoff => self.end(EndReason::SessionLogoff),
            DesktopEvent::SessionSwitched => self.end(EndReason::SessionSwitched),
            DesktopEvent::ServiceStopping => self.end(EndReason::ServiceStopping),
            DesktopEvent::CredentialRevoked => self.end(EndReason::CredentialRevoked),
        }
    }

    fn suspend(&mut self, reason: SuspendReason, notice: OperatorNotice) -> Vec<MonitorAction> {
        self.state = MonitorState::Suspended(reason);
        vec![
            MonitorAction::StopCapture,
            MonitorAction::ReleaseHeldInput,
            MonitorAction::DropQueuedInput,
            MonitorAction::NotifyOperator(notice),
        ]
    }

    fn try_resume(&mut self) -> Vec<MonitorAction> {
        let ready = !self.session_locked
            && self.consecutive_default_polls >= RESUME_CONSECUTIVE_DEFAULT_POLLS;
        if matches!(self.state, MonitorState::Suspended(_)) && ready {
            self.state = MonitorState::Streaming;
            // Reintenta liberar teclas/botones cuya liberación falló mientras el escritorio seguro estaba activo.
            return vec![
                MonitorAction::ReleaseHeldInput,
                MonitorAction::ResumeCapture {
                    force_keyframe: true,
                },
                MonitorAction::NotifyOperator(OperatorNotice::Resumed),
            ];
        }
        Vec::new()
    }

    fn end(&mut self, reason: EndReason) -> Vec<MonitorAction> {
        self.state = MonitorState::Ended(reason);
        vec![
            MonitorAction::StopCapture,
            MonitorAction::ReleaseHeldInput,
            MonitorAction::TerminateAgent,
            MonitorAction::NotifyOperator(OperatorNotice::SessionEnded { reason }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECURE: DesktopEvent = DesktopEvent::InputDesktop(InputDesktopKind::SecureOrOther);
    const DEFAULT: DesktopEvent = DesktopEvent::InputDesktop(InputDesktopKind::Default);

    fn suspend_actions(notice: OperatorNotice) -> Vec<MonitorAction> {
        vec![
            MonitorAction::StopCapture,
            MonitorAction::ReleaseHeldInput,
            MonitorAction::DropQueuedInput,
            MonitorAction::NotifyOperator(notice),
        ]
    }

    fn resume_actions() -> Vec<MonitorAction> {
        vec![
            MonitorAction::ReleaseHeldInput,
            MonitorAction::ResumeCapture {
                force_keyframe: true,
            },
            MonitorAction::NotifyOperator(OperatorNotice::Resumed),
        ]
    }

    #[test]
    fn uac_secure_desktop_suspends_and_resumes_after_two_default_polls() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        assert!(m.capture_allowed() && m.input_allowed());

        assert_eq!(
            m.handle(SECURE),
            suspend_actions(OperatorNotice::LocalApprovalRequired)
        );
        assert_eq!(
            m.state(),
            MonitorState::Suspended(SuspendReason::SecureDesktop)
        );
        assert!(!m.capture_allowed() && !m.input_allowed());

        // Sondeos repetidos del escritorio seguro no repiten acciones.
        assert!(m.handle(SECURE).is_empty());

        // Un solo sondeo Default no basta.
        assert!(m.handle(DEFAULT).is_empty());
        assert_eq!(
            m.state(),
            MonitorState::Suspended(SuspendReason::SecureDesktop)
        );

        // Rebote al escritorio seguro reinicia la cuenta.
        assert!(m.handle(SECURE).is_empty());
        assert!(m.handle(DEFAULT).is_empty());
        assert_eq!(m.handle(DEFAULT), resume_actions());
        assert_eq!(m.state(), MonitorState::Streaming);
        assert!(m.capture_allowed() && m.input_allowed());

        // Más sondeos Default en Streaming no producen acciones.
        assert!(m.handle(DEFAULT).is_empty());
    }

    #[test]
    fn inaccessible_desktop_is_treated_as_secure_desktop() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        let actions = m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Inaccessible));
        assert_eq!(
            actions,
            suspend_actions(OperatorNotice::LocalApprovalRequired)
        );
        assert!(!m.capture_allowed());
    }

    #[test]
    fn initial_non_default_probe_starts_suspended() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Inaccessible);
        assert_eq!(
            m.state(),
            MonitorState::Suspended(SuspendReason::SecureDesktop)
        );
        assert!(m.handle(DEFAULT).is_empty());
        assert_eq!(m.handle(DEFAULT), resume_actions());
    }

    #[test]
    fn lock_plus_uac_resumes_only_when_both_resolved() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        assert_eq!(
            m.handle(SECURE),
            suspend_actions(OperatorNotice::LocalApprovalRequired)
        );
        assert_eq!(
            m.handle(DesktopEvent::SessionLock),
            vec![MonitorAction::NotifyOperator(OperatorNotice::SessionLocked)]
        );
        assert_eq!(
            m.state(),
            MonitorState::Suspended(SuspendReason::SessionLocked)
        );

        // Default mientras sigue bloqueada: no reanuda.
        assert!(m.handle(DEFAULT).is_empty());
        assert!(m.handle(DEFAULT).is_empty());
        assert!(!m.capture_allowed());

        // Desbloqueo local: aún exige dos sondeos Default posteriores.
        assert!(m.handle(DesktopEvent::SessionUnlock).is_empty());
        assert!(m.handle(DEFAULT).is_empty());
        assert_eq!(m.handle(DEFAULT), resume_actions());
        assert_eq!(m.state(), MonitorState::Streaming);
    }

    #[test]
    fn session_lock_from_streaming_suspends_with_locked_notice() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        assert_eq!(
            m.handle(DesktopEvent::SessionLock),
            suspend_actions(OperatorNotice::SessionLocked)
        );
        // Pantalla de bloqueo = escritorio Winlogon: no cambia el motivo ni repite acciones.
        assert!(m.handle(SECURE).is_empty());
        assert_eq!(
            m.state(),
            MonitorState::Suspended(SuspendReason::SessionLocked)
        );
    }

    #[test]
    fn credential_revoked_ends_session_even_while_suspended() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        m.handle(DesktopEvent::SessionLock);
        let reason = EndReason::CredentialRevoked;
        assert_eq!(reason.as_str(), "credential_revoked");
        assert_eq!(
            m.handle(DesktopEvent::CredentialRevoked),
            vec![
                MonitorAction::StopCapture,
                MonitorAction::ReleaseHeldInput,
                MonitorAction::TerminateAgent,
                MonitorAction::NotifyOperator(OperatorNotice::SessionEnded { reason }),
            ]
        );
        assert_eq!(m.state(), MonitorState::Ended(reason));
        assert!(m.handle(DesktopEvent::SessionUnlock).is_empty());
        assert!(m.handle(DEFAULT).is_empty());
        assert!(m.handle(DEFAULT).is_empty());
        assert_eq!(m.state(), MonitorState::Ended(reason));
    }

    #[test]
    fn disconnect_logoff_switch_and_stop_are_terminal() {
        let cases = [
            (
                DesktopEvent::ConsoleDisconnect,
                EndReason::ConsoleDisconnect,
            ),
            (DesktopEvent::RemoteDisconnect, EndReason::RemoteDisconnect),
            (DesktopEvent::SessionLogoff, EndReason::SessionLogoff),
            (DesktopEvent::SessionSwitched, EndReason::SessionSwitched),
            (DesktopEvent::ServiceStopping, EndReason::ServiceStopping),
            (
                DesktopEvent::CredentialRevoked,
                EndReason::CredentialRevoked,
            ),
        ];
        for (event, reason) in cases {
            for initial in [InputDesktopKind::Default, InputDesktopKind::SecureOrOther] {
                let mut m = DesktopSessionMonitor::new(initial);
                assert_eq!(
                    m.handle(event),
                    vec![
                        MonitorAction::StopCapture,
                        MonitorAction::ReleaseHeldInput,
                        MonitorAction::TerminateAgent,
                        MonitorAction::NotifyOperator(OperatorNotice::SessionEnded { reason }),
                    ]
                );
                assert_eq!(m.state(), MonitorState::Ended(reason));

                // Absorbente: nada lo saca de Ended.
                for e in [DEFAULT, DEFAULT, DesktopEvent::SessionUnlock, SECURE, event] {
                    assert!(m.handle(e).is_empty());
                }
                assert_eq!(m.state(), MonitorState::Ended(reason));
                assert!(!m.capture_allowed() && !m.input_allowed());
            }
        }
    }

    #[test]
    fn motivos_de_fin_nuevos_tienen_nombre_propio_y_los_previos_no_cambian() {
        let all = [
            (EndReason::ConsoleDisconnect, "console_disconnect"),
            (EndReason::RemoteDisconnect, "remote_disconnect"),
            (EndReason::SessionLogoff, "session_logoff"),
            (EndReason::SessionSwitched, "session_switched"),
            (EndReason::ServiceStopping, "service_stopping"),
            (EndReason::CredentialRevoked, "credential_revoked"),
            (EndReason::LocalKillSwitch, "local_kill_switch"),
            (EndReason::OperatorDisconnected, "operator_disconnected"),
            (EndReason::AgentFailed, "agent_failed"),
            (EndReason::ForeignPipeClient, "foreign_pipe_client"),
        ];
        for (reason, name) in all {
            assert_eq!(reason.as_str(), name);
        }
    }
}
