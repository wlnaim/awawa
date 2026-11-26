//! Modelo de estados de la UI del operador (formulario -> espera -> visor -> fin).
//!
//! Logica pura con reloj inyectado. Garantiza que la UI solo muestra fotogramas y solo permite
//! enviar entrada despues de que el host anuncio la aprobacion local (`Approved`).

use std::time::Duration;

use awawa_protocol::{MonitorDescriptor, VirtualDesktopBounds};

use crate::countdown::Countdown;
use crate::form::sanitize_text;
use crate::stats::{FpsMeter, RttTracker};
use crate::transport::TransportEvent;
use crate::viewport::{MonitorSelection, ScaleMode};

/// Limite de caracteres de los textos que llegan del host (SAS, motivos).
const MAX_HOST_TEXT_CHARS: usize = 120;
const MAX_SAS_CHARS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Form,
    /// Esperando la aprobacion local. `sas` y `countdown` llegan con `AwaitingApproval`.
    Waiting {
        sas: Option<String>,
        countdown: Option<Countdown>,
    },
    Viewing,
    Ended {
        message: String,
    },
}

/// Resultado de `tick`: la UI debe cerrar la sesion de red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    Nothing,
    ApprovalTimedOut,
}

#[derive(Debug)]
pub struct SessionModel {
    phase: Phase,
    monitors: Vec<MonitorDescriptor>,
    desktop: Option<VirtualDesktopBounds>,
    pub selection: MonitorSelection,
    pub scale_mode: ScaleMode,
    fps: FpsMeter,
    rtt: RttTracker,
    /// El host pidio aprobacion local (escritorio seguro): el control esta en pausa.
    awaiting_local_approval: bool,
    /// La sesion es contra un equipo desatendido (sin aprobacion local).
    unattended: bool,
    /// Huella de la sesion desatendida, ya concedida por el servicio.
    fingerprint: Option<String>,
}

impl Default for SessionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionModel {
    pub fn new() -> Self {
        Self {
            phase: Phase::Form,
            monitors: Vec::new(),
            desktop: None,
            selection: MonitorSelection::All,
            scale_mode: ScaleMode::Fit,
            fps: FpsMeter::new(),
            rtt: RttTracker::new(),
            awaiting_local_approval: false,
            unattended: false,
            fingerprint: None,
        }
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    pub fn monitors(&self) -> &[MonitorDescriptor] {
        &self.monitors
    }

    pub fn desktop(&self) -> Option<&VirtualDesktopBounds> {
        self.desktop.as_ref()
    }

    /// Unica puerta para enviar entrada: solo con la sesion aprobada y sin pausa por escritorio
    /// seguro en el equipo remoto.
    pub fn can_send_input(&self) -> bool {
        matches!(self.phase, Phase::Viewing) && !self.awaiting_local_approval
    }

    /// `true` mientras el equipo remoto requiere aprobacion local (escritorio seguro).
    pub fn awaiting_local_approval(&self) -> bool {
        matches!(self.phase, Phase::Viewing) && self.awaiting_local_approval
    }

    /// El formulario valido inicio la conexion.
    pub fn begin_connect(&mut self) {
        self.reset_session_data();
        self.phase = Phase::Waiting {
            sas: None,
            countdown: None,
        };
    }

    /// Igual que `begin_connect`, para un equipo desatendido (no hay aprobacion ni cuenta regresiva).
    pub fn begin_connect_unattended(&mut self) {
        self.begin_connect();
        self.unattended = true;
    }

    pub fn is_unattended(&self) -> bool {
        self.unattended
    }

    /// Huella de la sesion desatendida, una vez concedido el acceso.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// El tecnico cancelo o se desconecto.
    pub fn user_disconnect(&mut self) {
        if matches!(self.phase, Phase::Waiting { .. } | Phase::Viewing) {
            self.end("Desconectado.");
        }
    }

    pub fn back_to_form(&mut self) {
        self.reset_session_data();
        self.phase = Phase::Form;
    }

    fn reset_session_data(&mut self) {
        self.monitors.clear();
        self.desktop = None;
        self.selection = MonitorSelection::All;
        self.fps.reset();
        self.rtt.reset();
        self.awaiting_local_approval = false;
        self.unattended = false;
        self.fingerprint = None;
    }

    fn end(&mut self, message: &str) {
        self.phase = Phase::Ended {
            message: message.to_string(),
        };
    }

    /// Aplica un evento del transporte. Devuelve `true` si es un fotograma aceptado (solo en el
    /// visor); cualquier fotograma fuera de ese estado se descarta.
    pub fn on_event(&mut self, event: &TransportEvent, now: Duration) -> bool {
        match (&mut self.phase, event) {
            (
                Phase::Waiting { sas, countdown },
                TransportEvent::AwaitingApproval {
                    timeout_secs,
                    sas: host_sas,
                },
            ) => {
                *sas = Some(sanitize_text(host_sas, MAX_SAS_CHARS));
                *countdown = Some(Countdown::start(now, *timeout_secs));
            }
            (Phase::Waiting { .. }, TransportEvent::UnattendedGranted { fingerprint }) => {
                if self.unattended {
                    self.fingerprint = Some(fingerprint.clone());
                }
            }
            (Phase::Waiting { .. }, TransportEvent::Approved { monitors }) => {
                match VirtualDesktopBounds::from_monitors(monitors) {
                    Some(desktop) => {
                        self.monitors = monitors.clone();
                        self.desktop = Some(desktop);
                        self.phase = Phase::Viewing;
                    }
                    None => self.end("El cliente informó una topología de monitores inválida."),
                }
            }
            (Phase::Waiting { .. }, TransportEvent::Rejected { reason }) => {
                let reason = sanitize_text(reason, MAX_HOST_TEXT_CHARS);
                if reason.is_empty() {
                    self.end("El cliente rechazó la solicitud.");
                } else {
                    self.end(&format!("El cliente rechazó la solicitud: {reason}"));
                }
            }
            (Phase::Viewing, TransportEvent::Frame(_)) => {
                self.fps.record_frame(now);
                return true;
            }
            (Phase::Viewing, TransportEvent::TopologyChanged { monitors }) => {
                match VirtualDesktopBounds::from_monitors(monitors) {
                    Some(desktop) => {
                        if let MonitorSelection::Monitor(i) = self.selection
                            && !monitors.iter().any(|m| m.index == i)
                        {
                            self.selection = MonitorSelection::All;
                        }
                        self.monitors = monitors.clone();
                        self.desktop = Some(desktop);
                    }
                    None => self.end("El cliente informó una topología de monitores inválida."),
                }
            }
            (Phase::Viewing, TransportEvent::LocalApprovalRequired) => {
                self.awaiting_local_approval = true;
            }
            (Phase::Viewing, TransportEvent::LocalApprovalCleared) => {
                self.awaiting_local_approval = false;
            }
            (Phase::Viewing, TransportEvent::Rtt(sample)) => self.rtt.record(*sample),
            (Phase::Waiting { .. } | Phase::Viewing, TransportEvent::Disconnected { reason }) => {
                let reason = sanitize_text(reason, MAX_HOST_TEXT_CHARS);
                if reason.is_empty() {
                    self.end("La sesión terminó.");
                } else {
                    self.end(&format!("La sesión terminó: {reason}"));
                }
            }
            _ => {}
        }
        false
    }

    /// Avance del reloj: vence la espera de aprobacion (el host rechaza por defecto).
    pub fn tick(&mut self, now: Duration) -> TickOutcome {
        if let Phase::Waiting {
            countdown: Some(c), ..
        } = &self.phase
            && c.is_expired(now)
        {
            self.end("Tiempo agotado: el cliente no aprobó la solicitud.");
            return TickOutcome::ApprovalTimedOut;
        }
        TickOutcome::Nothing
    }

    pub fn fps(&mut self, now: Duration) -> u32 {
        self.fps.fps(now)
    }

    pub fn rtt_ms(&self) -> Option<u32> {
        self.rtt.millis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::FrameUpdate;
    use capture_win::DecodedFrame;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn monitors() -> Vec<MonitorDescriptor> {
        vec![
            MonitorDescriptor {
                index: 0,
                is_primary: true,
                origin_x: 0,
                origin_y: 0,
                width_px: 1920,
                height_px: 1080,
                dpi_scale_percent: 100,
            },
            MonitorDescriptor {
                index: 1,
                is_primary: false,
                origin_x: 1920,
                origin_y: 0,
                width_px: 1920,
                height_px: 1080,
                dpi_scale_percent: 100,
            },
        ]
    }

    fn frame_event() -> TransportEvent {
        TransportEvent::Frame(FrameUpdate {
            frame: DecodedFrame::new(2, 2),
            dirty: Vec::new(),
        })
    }

    fn waiting_model() -> SessionModel {
        let mut m = SessionModel::new();
        m.begin_connect();
        m
    }

    fn viewing_model() -> SessionModel {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::Approved {
                monitors: monitors(),
            },
            ms(0),
        );
        m
    }

    #[test]
    fn starts_in_the_form_and_cannot_send_input() {
        let m = SessionModel::new();
        assert_eq!(*m.phase(), Phase::Form);
        assert!(!m.can_send_input());
    }

    #[test]
    fn connect_moves_to_waiting_without_input_or_frames() {
        let mut m = waiting_model();
        assert!(matches!(
            m.phase(),
            Phase::Waiting {
                sas: None,
                countdown: None
            }
        ));
        assert!(!m.can_send_input());
        assert!(!m.on_event(&frame_event(), ms(1)));
        assert!(matches!(m.phase(), Phase::Waiting { .. }));
    }

    #[test]
    fn awaiting_approval_sets_sanitized_sas_and_countdown() {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::AwaitingApproval {
                timeout_secs: 60,
                sas: "A7\u{202E}K29F".into(),
            },
            ms(1_000),
        );
        let Phase::Waiting { sas, countdown } = m.phase() else {
            panic!("se esperaba Waiting");
        };
        assert_eq!(sas.as_deref(), Some("A7K29F"));
        assert_eq!(countdown.unwrap().remaining_secs(ms(1_000)), 60);
    }

    #[test]
    fn input_is_only_allowed_after_approval() {
        let mut m = waiting_model();
        assert!(!m.can_send_input());
        m.on_event(
            &TransportEvent::Approved {
                monitors: monitors(),
            },
            ms(5),
        );
        assert_eq!(*m.phase(), Phase::Viewing);
        assert!(m.can_send_input());
        assert_eq!(m.monitors().len(), 2);
        let d = m.desktop().unwrap();
        assert_eq!((d.width, d.height), (3840, 1080));
    }

    #[test]
    fn approval_without_waiting_is_ignored() {
        let mut m = SessionModel::new();
        m.on_event(
            &TransportEvent::Approved {
                monitors: monitors(),
            },
            ms(0),
        );
        assert_eq!(*m.phase(), Phase::Form);
        assert!(!m.can_send_input());
    }

    #[test]
    fn approval_with_invalid_topology_ends_the_session() {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::Approved {
                monitors: Vec::new(),
            },
            ms(0),
        );
        assert!(matches!(m.phase(), Phase::Ended { .. }));
        assert!(!m.can_send_input());
    }

    #[test]
    fn rejection_ends_with_the_sanitized_reason() {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::Rejected {
                reason: "No\u{0007} autorizado".into(),
            },
            ms(0),
        );
        let Phase::Ended { message } = m.phase() else {
            panic!("se esperaba Ended");
        };
        assert!(message.ends_with("No autorizado"));
        assert!(!m.can_send_input());
    }

    #[test]
    fn countdown_expiry_ends_the_wait_once() {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::AwaitingApproval {
                timeout_secs: 60,
                sas: "ABC123".into(),
            },
            ms(0),
        );
        assert_eq!(m.tick(ms(59_999)), TickOutcome::Nothing);
        assert_eq!(m.tick(ms(60_000)), TickOutcome::ApprovalTimedOut);
        assert!(matches!(m.phase(), Phase::Ended { .. }));
        assert_eq!(m.tick(ms(61_000)), TickOutcome::Nothing);
    }

    #[test]
    fn tick_without_countdown_or_in_viewer_does_nothing() {
        let mut m = waiting_model();
        assert_eq!(m.tick(ms(1_000_000)), TickOutcome::Nothing);
        let mut v = viewing_model();
        assert_eq!(v.tick(ms(1_000_000)), TickOutcome::Nothing);
    }

    #[test]
    fn frames_count_for_fps_only_while_viewing() {
        let mut m = viewing_model();
        assert!(m.on_event(&frame_event(), ms(100)));
        assert!(m.on_event(&frame_event(), ms(200)));
        assert_eq!(m.fps(ms(300)), 2);
        assert_eq!(m.fps(ms(1_300)), 0);
    }

    #[test]
    fn rtt_samples_are_recorded_in_the_viewer_only() {
        let mut w = waiting_model();
        w.on_event(&TransportEvent::Rtt(ms(30)), ms(0));
        assert_eq!(w.rtt_ms(), None);
        let mut v = viewing_model();
        v.on_event(&TransportEvent::Rtt(ms(30)), ms(0));
        assert_eq!(v.rtt_ms(), Some(30));
    }

    #[test]
    fn topology_change_updates_the_desktop_and_drops_a_missing_monitor() {
        let mut m = viewing_model();
        m.selection = MonitorSelection::Monitor(1);
        let single = vec![monitors()[0].clone()];
        m.on_event(&TransportEvent::TopologyChanged { monitors: single }, ms(0));
        assert_eq!(*m.phase(), Phase::Viewing);
        assert_eq!(m.monitors().len(), 1);
        assert_eq!(m.desktop().unwrap().width, 1920);
        assert_eq!(m.selection, MonitorSelection::All);
        m.on_event(
            &TransportEvent::TopologyChanged {
                monitors: Vec::new(),
            },
            ms(1),
        );
        assert!(matches!(m.phase(), Phase::Ended { .. }));
    }

    #[test]
    fn local_approval_pauses_input_until_the_host_clears_it() {
        let mut m = viewing_model();
        assert!(m.can_send_input());
        m.on_event(&TransportEvent::LocalApprovalRequired, ms(0));
        assert!(m.awaiting_local_approval());
        assert!(!m.can_send_input(), "en pausa el operador no envia entrada");
        assert_eq!(*m.phase(), Phase::Viewing);
        m.on_event(&TransportEvent::LocalApprovalCleared, ms(1));
        assert!(!m.awaiting_local_approval());
        assert!(m.can_send_input());

        let mut w = waiting_model();
        w.on_event(&TransportEvent::LocalApprovalRequired, ms(0));
        assert!(!w.awaiting_local_approval(), "solo cuenta en el visor");
        m.on_event(&TransportEvent::LocalApprovalRequired, ms(2));
        m.user_disconnect();
        m.begin_connect();
        assert!(
            !m.awaiting_local_approval(),
            "una sesion nueva empieza sin pausa"
        );
    }

    #[test]
    fn unattended_session_goes_straight_to_viewing_with_its_fingerprint() {
        let mut m = SessionModel::new();
        m.begin_connect_unattended();
        assert!(m.is_unattended());
        assert!(m.fingerprint().is_none());
        m.on_event(
            &TransportEvent::UnattendedGranted {
                fingerprint: "0102-0304-0506-0708".into(),
            },
            ms(0),
        );
        assert_eq!(m.fingerprint(), Some("0102-0304-0506-0708"));
        assert!(!m.can_send_input(), "sin topologia todavia no hay entrada");
        m.on_event(
            &TransportEvent::Approved {
                monitors: monitors(),
            },
            ms(1),
        );
        assert_eq!(*m.phase(), Phase::Viewing);
        assert!(m.can_send_input());
        assert!(m.is_unattended());
        m.user_disconnect();
        m.back_to_form();
        assert!(!m.is_unattended());
        assert!(m.fingerprint().is_none());
    }

    #[test]
    fn on_demand_ignores_an_unattended_grant() {
        let mut m = waiting_model();
        m.on_event(
            &TransportEvent::UnattendedGranted {
                fingerprint: "0102-0304-0506-0708".into(),
            },
            ms(0),
        );
        assert!(!m.is_unattended());
        assert!(m.fingerprint().is_none());
    }

    #[test]
    fn host_disconnect_ends_and_blocks_input() {
        let mut m = viewing_model();
        m.on_event(
            &TransportEvent::Disconnected {
                reason: "Control revocado".into(),
            },
            ms(0),
        );
        assert!(matches!(m.phase(), Phase::Ended { .. }));
        assert!(!m.can_send_input());
        assert!(!m.on_event(&frame_event(), ms(1)));
    }

    #[test]
    fn user_disconnect_works_from_waiting_and_viewing() {
        let mut m = waiting_model();
        m.user_disconnect();
        assert!(matches!(m.phase(), Phase::Ended { .. }));
        let mut v = viewing_model();
        v.user_disconnect();
        assert!(!v.can_send_input());
    }

    #[test]
    fn back_to_form_clears_session_data() {
        let mut m = viewing_model();
        m.selection = MonitorSelection::Monitor(1);
        m.on_event(&TransportEvent::Rtt(ms(30)), ms(0));
        m.user_disconnect();
        m.back_to_form();
        assert_eq!(*m.phase(), Phase::Form);
        assert!(m.monitors().is_empty());
        assert!(m.desktop().is_none());
        assert_eq!(m.selection, MonitorSelection::All);
        assert_eq!(m.rtt_ms(), None);
    }

    #[test]
    fn a_new_connection_after_ending_starts_clean() {
        let mut m = viewing_model();
        m.user_disconnect();
        m.begin_connect();
        assert!(matches!(
            m.phase(),
            Phase::Waiting {
                sas: None,
                countdown: None
            }
        ));
        assert!(!m.can_send_input());
    }
}
