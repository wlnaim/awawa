//! Mapeo puro de las notificaciones de cambio de sesion (`WTS_*`, `SERVICE_CONTROL_SESSIONCHANGE`)
//! a eventos del monitor de escritorio, y de las transiciones del monitor a eventos de auditoria.

use awawa_protocol::audit::AuditEvent;
use awawa_protocol::desktop_session::{DesktopEvent, MonitorState};

pub const WTS_CONSOLE_CONNECT: u32 = 0x1;
pub const WTS_CONSOLE_DISCONNECT: u32 = 0x2;
pub const WTS_REMOTE_CONNECT: u32 = 0x3;
pub const WTS_REMOTE_DISCONNECT: u32 = 0x4;
pub const WTS_SESSION_LOGON: u32 = 0x5;
pub const WTS_SESSION_LOGOFF: u32 = 0x6;
pub const WTS_SESSION_LOCK: u32 = 0x7;
pub const WTS_SESSION_UNLOCK: u32 = 0x8;

/// Traduce un evento de sesion. Los eventos de la sesion autorizada (bloqueo, desconexion, cierre)
/// se mapean directamente; la conexion de OTRA sesion (cambio rapido de usuario) es `SessionSwitched`.
/// Cualquier otro evento de otra sesion, o codigos sin efecto (p. ej. `WTS_SESSION_LOGON`), es `None`.
pub fn map_wts_session_change(
    event_type: u32,
    event_session_id: u32,
    authorized_session_id: u32,
) -> Option<DesktopEvent> {
    let same = event_session_id == authorized_session_id;
    match event_type {
        WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT if !same => Some(DesktopEvent::SessionSwitched),
        WTS_SESSION_LOCK if same => Some(DesktopEvent::SessionLock),
        WTS_SESSION_UNLOCK if same => Some(DesktopEvent::SessionUnlock),
        WTS_CONSOLE_DISCONNECT if same => Some(DesktopEvent::ConsoleDisconnect),
        WTS_REMOTE_DISCONNECT if same => Some(DesktopEvent::RemoteDisconnect),
        WTS_SESSION_LOGOFF if same => Some(DesktopEvent::SessionLogoff),
        _ => None,
    }
}

/// Evento de auditoria correspondiente a un cambio de estado del monitor (`None` si no hubo transicion relevante).
pub fn audit_event_for_transition(before: MonitorState, after: MonitorState) -> Option<AuditEvent> {
    if before == after {
        return None;
    }
    match (before, after) {
        (MonitorState::Ended(_), _) => None,
        (_, MonitorState::Ended(reason)) => Some(AuditEvent::SessionEnded { reason }),
        (_, MonitorState::Suspended(reason)) => Some(AuditEvent::SessionSuspended { reason }),
        (MonitorState::Suspended(_), MonitorState::Streaming) => Some(AuditEvent::SessionResumed),
        (MonitorState::Streaming, MonitorState::Streaming) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::desktop_session::{
        DesktopSessionMonitor, EndReason, InputDesktopKind, MonitorAction, OperatorNotice,
        SuspendReason,
    };

    const AUTH: u32 = 2;
    const OTHER: u32 = 5;

    #[test]
    fn mapea_cada_codigo_de_la_sesion_autorizada() {
        assert_eq!(
            map_wts_session_change(0x7, AUTH, AUTH),
            Some(DesktopEvent::SessionLock)
        );
        assert_eq!(
            map_wts_session_change(0x8, AUTH, AUTH),
            Some(DesktopEvent::SessionUnlock)
        );
        assert_eq!(
            map_wts_session_change(0x2, AUTH, AUTH),
            Some(DesktopEvent::ConsoleDisconnect)
        );
        assert_eq!(
            map_wts_session_change(0x4, AUTH, AUTH),
            Some(DesktopEvent::RemoteDisconnect)
        );
        assert_eq!(
            map_wts_session_change(0x6, AUTH, AUTH),
            Some(DesktopEvent::SessionLogoff)
        );
    }

    #[test]
    fn conexion_de_otra_sesion_es_cambio_de_sesion() {
        assert_eq!(
            map_wts_session_change(0x1, OTHER, AUTH),
            Some(DesktopEvent::SessionSwitched)
        );
        assert_eq!(
            map_wts_session_change(0x3, OTHER, AUTH),
            Some(DesktopEvent::SessionSwitched)
        );
    }

    #[test]
    fn conexion_de_la_misma_sesion_no_hace_nada() {
        assert_eq!(map_wts_session_change(0x1, AUTH, AUTH), None);
        assert_eq!(map_wts_session_change(0x3, AUTH, AUTH), None);
    }

    #[test]
    fn eventos_de_otra_sesion_que_no_son_connect_se_ignoran() {
        for code in [0x2, 0x4, 0x6, 0x7, 0x8] {
            assert_eq!(
                map_wts_session_change(code, OTHER, AUTH),
                None,
                "codigo {code:#x}"
            );
        }
    }

    #[test]
    fn codigos_sin_efecto_se_ignoran() {
        for code in [0x0, WTS_SESSION_LOGON, 0x9, 0xA, 0xB, 0xC, 0xFF] {
            assert_eq!(
                map_wts_session_change(code, AUTH, AUTH),
                None,
                "codigo {code:#x}"
            );
        }
    }

    #[test]
    fn secuencia_lock_unlock_y_uac_alimenta_el_monitor() {
        let mut m = DesktopSessionMonitor::new(InputDesktopKind::Default);
        assert!(m.capture_allowed() && m.input_allowed());

        // UAC: el escritorio de entrada pasa a Winlogon.
        let actions = m.handle(DesktopEvent::InputDesktop(InputDesktopKind::SecureOrOther));
        assert_eq!(
            actions,
            vec![
                MonitorAction::StopCapture,
                MonitorAction::ReleaseHeldInput,
                MonitorAction::DropQueuedInput,
                MonitorAction::NotifyOperator(OperatorNotice::LocalApprovalRequired),
            ]
        );
        assert!(!m.capture_allowed() && !m.input_allowed());

        // Vuelve al escritorio del usuario: reanuda al segundo sondeo consecutivo.
        assert!(
            m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default))
                .is_empty()
        );
        assert_eq!(
            m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default)),
            vec![
                MonitorAction::ReleaseHeldInput,
                MonitorAction::ResumeCapture {
                    force_keyframe: true
                },
                MonitorAction::NotifyOperator(OperatorNotice::Resumed),
            ]
        );

        // Bloqueo de la sesion autorizada (via WTS) suspende; el sondeo Default no reanuda hasta desbloquear.
        let lock = map_wts_session_change(WTS_SESSION_LOCK, AUTH, AUTH).unwrap();
        let before = m.state();
        let actions = m.handle(lock);
        assert!(actions.contains(&MonitorAction::NotifyOperator(
            OperatorNotice::SessionLocked
        )));
        assert_eq!(
            audit_event_for_transition(before, m.state()),
            Some(AuditEvent::SessionSuspended {
                reason: SuspendReason::SessionLocked
            })
        );
        for _ in 0..3 {
            assert!(
                m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default))
                    .is_empty()
            );
        }
        assert!(!m.capture_allowed());

        let unlock = map_wts_session_change(WTS_SESSION_UNLOCK, AUTH, AUTH).unwrap();
        assert!(m.handle(unlock).is_empty());
        let before = m.state();
        assert!(
            m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default))
                .is_empty()
        );
        let actions = m.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        assert!(actions.contains(&MonitorAction::ResumeCapture {
            force_keyframe: true
        }));
        assert_eq!(
            audit_event_for_transition(before, m.state()),
            Some(AuditEvent::SessionResumed)
        );

        // Desconexion de consola termina la sesion.
        let disc = map_wts_session_change(WTS_CONSOLE_DISCONNECT, AUTH, AUTH).unwrap();
        let before = m.state();
        let actions = m.handle(disc);
        assert!(actions.contains(&MonitorAction::TerminateAgent));
        assert_eq!(
            audit_event_for_transition(before, m.state()),
            Some(AuditEvent::SessionEnded {
                reason: EndReason::ConsoleDisconnect
            })
        );
        assert!(m.handle(DesktopEvent::SessionUnlock).is_empty());
    }

    #[test]
    fn auditoria_sin_transicion_no_emite() {
        assert_eq!(
            audit_event_for_transition(MonitorState::Streaming, MonitorState::Streaming),
            None
        );
    }
}
