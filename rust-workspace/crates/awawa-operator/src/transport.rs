//! Frontera entre la UI y la red.
//!
//! La UI solo conoce este contrato: recibe `TransportEvent` y entrega `RemoteInputCommand` o la
//! orden de desconectar. La implementacion real es `relay_transport` (relay + handshake + canal
//! cifrado); la simulada (`sim`) solo existe en las pruebas.

use std::time::Duration;

use awawa_protocol::{MonitorDescriptor, RemoteInputCommand};
use capture_win::{DecodedFrame, DirtyRect};

use crate::form::ConnectionParams;

/// Maximo de rectangulos sucios acumulados al fusionar; por encima se sube el fotograma completo.
pub const MAX_PENDING_RECTS: usize = 32;

/// Fotograma ya decodificado y las regiones que cambiaron respecto del anterior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameUpdate {
    pub frame: DecodedFrame,
    pub dirty: Vec<DirtyRect>,
}

impl FrameUpdate {
    fn full_rect(&self) -> DirtyRect {
        DirtyRect {
            x: 0,
            y: 0,
            width: self.frame.width,
            height: self.frame.height,
        }
    }

    /// Fusiona una actualizacion pendiente con otra mas reciente: queda el fotograma nuevo y la
    /// union de las regiones sucias (o el fotograma completo si cambio el tamano o son demasiadas).
    /// Acota la cola de fotogramas cuando la UI no consume al ritmo del transporte.
    pub fn merge(mut self, newer: FrameUpdate) -> FrameUpdate {
        let same_size =
            self.frame.width == newer.frame.width && self.frame.height == newer.frame.height;
        let full = newer.full_rect();
        let mut dirty = if same_size {
            self.dirty.extend(newer.dirty);
            self.dirty
        } else {
            vec![full]
        };
        if dirty.len() > MAX_PENDING_RECTS {
            dirty = vec![full];
        }
        FrameUpdate {
            frame: newer.frame,
            dirty,
        }
    }
}

/// Eventos entrantes (host -> operador).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// El host espera la aprobacion local del usuario (`PendingApproval`).
    AwaitingApproval {
        timeout_secs: u16,
        sas: String,
    },
    /// El usuario aprobo (`ApprovalResult { granted: true }`) y estos son sus monitores.
    Approved {
        monitors: Vec<MonitorDescriptor>,
    },
    /// Modo desatendido: el servicio concedio el acceso; huella de la sesion (`xxxx-xxxx-xxxx-xxxx`).
    UnattendedGranted {
        fingerprint: String,
    },
    /// El usuario rechazo (`ApprovalResult { granted: false }`).
    Rejected {
        reason: String,
    },
    Frame(FrameUpdate),
    /// El host cambio sus monitores (`DisplayTopologyChanged`).
    TopologyChanged {
        monitors: Vec<MonitorDescriptor>,
    },
    /// El equipo remoto muestra el escritorio seguro: video y entrada en pausa.
    LocalApprovalRequired,
    /// El equipo remoto volvio al escritorio del usuario.
    LocalApprovalCleared,
    /// Muestra de RTT medida con `Ping`/`Pong`.
    Rtt(Duration),
    /// La sesion termino (`SessionRevoked`, caida del canal o cierre del host).
    Disconnected {
        reason: String,
    },
}

/// Canal con una sesion remota. Las llamadas no bloquean.
pub trait OperatorTransport {
    fn send_input(&mut self, command: RemoteInputCommand);
    fn disconnect(&mut self);
    fn poll_event(&mut self) -> Option<TransportEvent>;
}

/// Crea el transporte de una sesion a partir de los datos validados del formulario. Recibe el
/// contexto de egui para pedir repintado cuando lleguen eventos.
pub type TransportFactory =
    Box<dyn Fn(ConnectionParams, egui::Context) -> Box<dyn OperatorTransport>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32) -> DirtyRect {
        DirtyRect {
            x,
            y: 0,
            width: 1,
            height: 1,
        }
    }

    fn update(w: u32, h: u32, dirty: Vec<DirtyRect>) -> FrameUpdate {
        FrameUpdate {
            frame: DecodedFrame::new(w, h),
            dirty,
        }
    }

    #[test]
    fn merge_keeps_the_newest_frame_and_unions_dirty_rects() {
        let mut older = update(4, 4, vec![rect(0)]);
        older.frame.bgra[0] = 7;
        let newer = update(4, 4, vec![rect(1), rect(2)]);
        let merged = older.merge(newer.clone());
        assert_eq!(merged.frame, newer.frame);
        assert_eq!(merged.dirty, vec![rect(0), rect(1), rect(2)]);
    }

    #[test]
    fn merge_with_size_change_uploads_the_whole_frame() {
        let merged = update(4, 4, vec![rect(0)]).merge(update(8, 2, vec![rect(1)]));
        assert_eq!(
            merged.dirty,
            vec![DirtyRect {
                x: 0,
                y: 0,
                width: 8,
                height: 2
            }]
        );
    }

    #[test]
    fn merge_is_bounded_by_collapsing_to_the_full_frame() {
        let mut pending = update(64, 4, vec![rect(0)]);
        for i in 0..(MAX_PENDING_RECTS as u32 * 2) {
            pending = pending.merge(update(64, 4, vec![rect(i % 64)]));
            assert!(pending.dirty.len() <= MAX_PENDING_RECTS);
        }
    }
}
