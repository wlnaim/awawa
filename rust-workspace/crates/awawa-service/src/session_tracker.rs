//! Seguimiento (puro y comprobable) de la UNICA sesion remota activa del servicio.
//!
//! El servicio no mantiene un monitor de escritorio propio: el monitor nace al autenticarse una sesion
//! ([`SessionTracker::start_session`]) y muere cuando esa sesion termina. Sin sesion activa, los eventos de
//! Windows no producen transiciones ni auditoria de sesion. Con sesion activa, los eventos `WTS_*` se mapean
//! contra la sesion de Windows de ESA sesion y alimentan SU monitor. La parada de la sesion por cambio o
//! revocacion de la contrasena se decide en [`SessionTracker::revalidate`].
//!
//! El rastreador no termina procesos: ante `MonitorAction::TerminateAgent` el llamador hace el
//! cierre ordenado del agente (liberar teclas y salir; `TerminateProcess` solo tras un plazo).

use awawa_protocol::audit::AuditEvent;
use awawa_protocol::desktop_session::{
    DesktopEvent, DesktopSessionMonitor, EndReason, InputDesktopKind, MonitorAction, MonitorState,
};
use awawa_protocol::unattended::UnattendedStatus;

use crate::session_events::{audit_event_for_transition, map_wts_session_change};

/// Valor que devuelve `WTSGetActiveConsoleSessionId` cuando no hay sesion de consola.
pub const WTS_NO_SESSION: u32 = 0xFFFF_FFFF;

/// Normaliza un identificador de sesion de Windows: `0xFFFFFFFF` significa "ninguna sesion autorizable".
pub fn authorizable_session(raw: u32) -> Option<u32> {
    (raw != WTS_NO_SESSION).then_some(raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerError {
    /// El identificador de sesion de Windows es `0xFFFFFFFF` (sin consola).
    NoAuthorizableSession,
    /// Ya hay una sesion remota activa.
    AlreadyActive,
}

impl core::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoAuthorizableSession => write!(f, "no hay una sesion de Windows autorizable"),
            Self::AlreadyActive => write!(f, "ya hay una sesion remota activa"),
        }
    }
}

impl std::error::Error for TrackerError {}

/// Resultado de procesar un evento: acciones del monitor para el llamador y evento de auditoria (si hubo).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrackerStep {
    pub actions: Vec<MonitorAction>,
    pub audit: Option<AuditEvent>,
}

#[derive(Debug)]
struct ActiveSession {
    windows_session_id: u32,
    /// Generacion del verificador que la autorizo (`None` si fuera bajo demanda).
    grant_generation: Option<u32>,
    monitor: DesktopSessionMonitor,
}

/// Sesion remota activa (como maximo una) y su monitor.
#[derive(Debug, Default)]
pub struct SessionTracker {
    active: Option<ActiveSession>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    pub fn windows_session_id(&self) -> Option<u32> {
        self.active.as_ref().map(|a| a.windows_session_id)
    }

    pub fn state(&self) -> Option<MonitorState> {
        self.active.as_ref().map(|a| a.monitor.state())
    }

    pub fn capture_allowed(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| a.monitor.capture_allowed())
    }

    /// Registra una sesion recien autenticada con un monitor NUEVO. `grant_generation` es la generacion del
    /// verificador que la autorizo.
    pub fn start_session(
        &mut self,
        windows_session_id: u32,
        grant_generation: Option<u32>,
        initial_probe: InputDesktopKind,
    ) -> Result<TrackerStep, TrackerError> {
        let windows_session_id =
            authorizable_session(windows_session_id).ok_or(TrackerError::NoAuthorizableSession)?;
        if self.active.is_some() {
            return Err(TrackerError::AlreadyActive);
        }
        self.active = Some(ActiveSession {
            windows_session_id,
            grant_generation,
            monitor: DesktopSessionMonitor::new(initial_probe),
        });
        Ok(TrackerStep {
            actions: Vec::new(),
            audit: Some(AuditEvent::SessionStarted),
        })
    }

    pub fn input_allowed(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|a| a.monitor.input_allowed())
    }

    /// La consola paso a otra sesion de Windows o a otro usuario (comprobacion periodica del
    /// servicio): termina con `SessionSwitched`. No sigue al usuario nuevo.
    pub fn session_switched(&mut self) -> TrackerStep {
        self.apply(DesktopEvent::SessionSwitched)
    }

    /// Termina la sesion por un motivo que no es un evento de Windows (desconexion del operador,
    /// kill-switch local, fallo del agente, PID ajeno en la pipe) y devuelve su `SessionEnded`.
    /// Sin sesion activa no hace nada.
    pub fn end(&mut self, reason: EndReason) -> TrackerStep {
        if self.active.take().is_none() {
            return TrackerStep::default();
        }
        TrackerStep {
            actions: vec![
                MonitorAction::StopCapture,
                MonitorAction::ReleaseHeldInput,
                MonitorAction::DropQueuedInput,
                MonitorAction::TerminateAgent,
            ],
            audit: Some(AuditEvent::SessionEnded { reason }),
        }
    }

    /// Evento de cambio de sesion de Windows (`SERVICE_CONTROL_SESSIONCHANGE`).
    pub fn on_wts_event(&mut self, event_type: u32, event_session_id: u32) -> TrackerStep {
        let Some(active) = self.active.as_ref() else {
            return TrackerStep::default();
        };
        match map_wts_session_change(event_type, event_session_id, active.windows_session_id) {
            Some(event) => self.apply(event),
            None => TrackerStep::default(),
        }
    }

    /// Resultado de un sondeo del escritorio de entrada (lo realiza el agente en la sesion del usuario).
    pub fn on_probe(&mut self, probe: InputDesktopKind) -> TrackerStep {
        self.apply(DesktopEvent::InputDesktop(probe))
    }

    /// Parada del servicio: termina la sesion activa (si la hay).
    pub fn stop(&mut self) -> TrackerStep {
        self.apply(DesktopEvent::ServiceStopping)
    }

    /// Revalida la sesion frente al estado ACTUAL del verificador: si la contrasena que la autorizo fue
    /// cambiada o revocada (otra generacion o no habilitada) la sesion termina (corte de captura/entrada y
    /// del agente) con motivo `EndReason::CredentialRevoked`.
    pub fn revalidate(&mut self, status: UnattendedStatus) -> TrackerStep {
        let Some(active) = self.active.as_ref() else {
            return TrackerStep::default();
        };
        let current = match active.grant_generation {
            None => true,
            Some(g) => status == UnattendedStatus::Enabled { generation: g },
        };
        if current {
            TrackerStep::default()
        } else {
            self.apply(DesktopEvent::CredentialRevoked)
        }
    }

    fn apply(&mut self, event: DesktopEvent) -> TrackerStep {
        let Some(active) = self.active.as_mut() else {
            return TrackerStep::default();
        };
        let before = active.monitor.state();
        let actions = active.monitor.handle(event);
        let after = active.monitor.state();
        if matches!(after, MonitorState::Ended(_)) {
            self.active = None;
        }
        TrackerStep {
            actions,
            audit: audit_event_for_transition(before, after),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_events::{
        WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
    };
    use awawa_protocol::desktop_session::{EndReason, SuspendReason};

    const S: u32 = 2;

    fn started() -> SessionTracker {
        let mut t = SessionTracker::new();
        let step = t
            .start_session(S, Some(1), InputDesktopKind::Default)
            .unwrap();
        assert_eq!(step.audit, Some(AuditEvent::SessionStarted));
        t
    }

    #[test]
    fn lock_unlock_lock_unlock_audita_cada_suspension_y_reanuda() {
        let mut t = started();
        for round in 0..2 {
            let step = t.on_wts_event(WTS_SESSION_LOCK, S);
            assert_eq!(
                step.audit,
                Some(AuditEvent::SessionSuspended {
                    reason: SuspendReason::SessionLocked
                }),
                "ronda {round}"
            );
            assert!(!t.capture_allowed());
            // Sondeos Default mientras esta bloqueada no reanudan.
            assert_eq!(
                t.on_probe(InputDesktopKind::Default),
                TrackerStep::default()
            );
            assert_eq!(
                t.on_wts_event(WTS_SESSION_UNLOCK, S),
                TrackerStep::default()
            );
            assert_eq!(
                t.on_probe(InputDesktopKind::Default),
                TrackerStep::default()
            );
            let resumed = t.on_probe(InputDesktopKind::Default);
            assert_eq!(resumed.audit, Some(AuditEvent::SessionResumed));
            assert!(resumed.actions.contains(&MonitorAction::ResumeCapture {
                force_keyframe: true
            }));
            assert_eq!(t.state(), Some(MonitorState::Streaming));
        }
    }

    #[test]
    fn sin_sesion_activa_no_hay_transiciones() {
        let mut t = SessionTracker::new();
        for code in [
            WTS_SESSION_LOCK,
            WTS_SESSION_UNLOCK,
            WTS_CONSOLE_DISCONNECT,
            WTS_CONSOLE_CONNECT,
        ] {
            assert_eq!(t.on_wts_event(code, S), TrackerStep::default());
        }
        assert_eq!(
            t.on_probe(InputDesktopKind::SecureOrOther),
            TrackerStep::default()
        );
        assert_eq!(
            t.revalidate(UnattendedStatus::NotConfigured),
            TrackerStep::default()
        );
        assert_eq!(t.stop(), TrackerStep::default());
        assert!(!t.is_active() && t.state().is_none());
    }

    #[test]
    fn tras_ended_una_nueva_sesion_crea_monitor_nuevo() {
        let mut t = started();
        t.on_wts_event(WTS_SESSION_LOCK, S);
        let end = t.on_wts_event(WTS_CONSOLE_DISCONNECT, S);
        assert_eq!(
            end.audit,
            Some(AuditEvent::SessionEnded {
                reason: EndReason::ConsoleDisconnect
            })
        );
        assert!(end.actions.contains(&MonitorAction::TerminateAgent));
        assert!(!t.is_active());
        // El monitor anterior (bloqueado) no se arrastra: la nueva sesion nace en Streaming.
        t.start_session(7, Some(2), InputDesktopKind::Default)
            .unwrap();
        assert_eq!(t.state(), Some(MonitorState::Streaming));
        assert_eq!(t.windows_session_id(), Some(7));
        assert_eq!(
            t.start_session(8, Some(2), InputDesktopKind::Default),
            Err(TrackerError::AlreadyActive)
        );
    }

    #[test]
    fn sin_consola_no_es_sesion_autorizable() {
        let mut t = SessionTracker::new();
        assert_eq!(authorizable_session(WTS_NO_SESSION), None);
        assert_eq!(authorizable_session(0), Some(0));
        assert_eq!(
            t.start_session(WTS_NO_SESSION, Some(1), InputDesktopKind::Default),
            Err(TrackerError::NoAuthorizableSession)
        );
        assert!(!t.is_active());
    }

    #[test]
    fn eventos_de_otra_sesion_se_ignoran_salvo_connect_que_cambia_de_sesion() {
        let mut t = started();
        assert_eq!(t.on_wts_event(WTS_SESSION_LOCK, 9), TrackerStep::default());
        assert!(t.capture_allowed());
        let step = t.on_wts_event(WTS_CONSOLE_CONNECT, 9);
        assert_eq!(
            step.audit,
            Some(AuditEvent::SessionEnded {
                reason: EndReason::SessionSwitched
            })
        );
        assert!(!t.is_active());
    }

    #[test]
    fn uac_suspende_y_reanuda_en_la_sesion_activa() {
        let mut t = started();
        let step = t.on_probe(InputDesktopKind::SecureOrOther);
        assert_eq!(
            step.audit,
            Some(AuditEvent::SessionSuspended {
                reason: SuspendReason::SecureDesktop
            })
        );
        assert_eq!(t.on_probe(InputDesktopKind::Default).audit, None);
        assert_eq!(
            t.on_probe(InputDesktopKind::Default).audit,
            Some(AuditEvent::SessionResumed)
        );
    }

    #[test]
    fn revalidate_termina_la_sesion_si_la_contrasena_cambio_o_se_revoco() {
        let mut t = started(); // autorizada con la generacion 1
        assert_eq!(
            t.revalidate(UnattendedStatus::Enabled { generation: 1 }),
            TrackerStep::default()
        );
        assert!(t.is_active());

        let step = t.revalidate(UnattendedStatus::Enabled { generation: 2 });
        assert!(step.actions.contains(&MonitorAction::StopCapture));
        assert!(step.actions.contains(&MonitorAction::TerminateAgent));
        assert_eq!(
            step.audit,
            Some(AuditEvent::SessionEnded {
                reason: EndReason::CredentialRevoked
            })
        );
        assert!(!t.is_active());

        let mut t = started();
        let step = t.revalidate(UnattendedStatus::Revoked { generation: 2 });
        assert!(matches!(step.audit, Some(AuditEvent::SessionEnded { .. })));
        assert!(!t.is_active());

        let mut t = started();
        let step = t.revalidate(UnattendedStatus::NotConfigured);
        assert!(matches!(step.audit, Some(AuditEvent::SessionEnded { .. })));
    }

    #[test]
    fn cambio_de_usuario_o_sesion_y_fin_por_el_servicio_terminan_auditados() {
        let mut t = started();
        let step = t.session_switched();
        assert_eq!(
            step.audit,
            Some(AuditEvent::SessionEnded {
                reason: EndReason::SessionSwitched
            })
        );
        assert!(step.actions.contains(&MonitorAction::TerminateAgent));
        assert!(!t.is_active());
        let t = started();
        assert!(t.input_allowed());
        for reason in [
            EndReason::LocalKillSwitch,
            EndReason::OperatorDisconnected,
            EndReason::AgentFailed,
            EndReason::ForeignPipeClient,
        ] {
            let mut t = started();
            let step = t.end(reason);
            assert_eq!(step.audit, Some(AuditEvent::SessionEnded { reason }));
            assert!(step.actions.contains(&MonitorAction::TerminateAgent));
            assert!(!t.is_active());
            assert_eq!(t.end(reason), TrackerStep::default());
        }
    }

    #[test]
    fn parada_del_servicio_termina_la_sesion() {
        let mut t = started();
        let step = t.stop();
        assert_eq!(
            step.audit,
            Some(AuditEvent::SessionEnded {
                reason: EndReason::ServiceStopping
            })
        );
        assert!(!t.is_active());
    }
}
