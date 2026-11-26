//! Frontera de transporte del host.
//!
//! La UI solo conoce esta frontera: un flujo de eventos entrantes (`HostTransport::poll_event`) con
//! el estado del relay, las solicitudes de operador ya identificadas y la desconexion del operador,
//! y `set_session_id` para publicar el ID que debe quedar registrado en el relay.
//!
//! Una solicitud (`IncomingRequest`) trae el nombre y el origen declarados (sin autenticar) y la
//! operacion `authenticate`, que consume el `WaitingForRequest` del host y devuelve un
//! `PendingLocalConsent` real o el `WaitingForRequest` de vuelta. `RelayTransport` corre el
//! handshake SPAKE2 por la red (`net`); el controlador la invoca fuera del hilo de la UI. El
//! nombre que ve el usuario sale del handshake (`PendingLocalConsent`), junto con la huella, el
//! codigo SAS y los permisos. La unica salida exitosa es `PendingLocalConsent`: autenticar nunca
//! inicia el control.
//!
//! Sin `--relay`/`--relay-pin` validos el host queda con `DisconnectedTransport` (relay no
//! conectado). El transporte simulado existe solo en las pruebas.

#[cfg(test)]
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

use awawa_protocol::{ConsentError, PendingLocalConsent, SessionId, WaitingForRequest};
#[cfg(test)]
use awawa_protocol::{OperatorConnectionRequest, ScopedCapabilities, run_in_memory_handshake};

use crate::net::{HostNet, NetEvent};

/// Estado de la conexion con el relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayStatus {
    Disconnected,
    Connecting,
    Registered,
}

/// Resultado de autenticar una solicitud: la sesion pendiente de aprobacion local, o el
/// `WaitingForRequest` devuelto junto con el motivo.
pub type AuthenticateResult = Result<PendingLocalConsent, (WaitingForRequest, ConsentError)>;

type AuthenticateFn =
    Box<dyn FnOnce(WaitingForRequest, Instant) -> Option<AuthenticateResult> + Send>;

/// Solicitud de un operador que llego por el transporte.
pub struct IncomingRequest {
    /// Nombre declarado por el operador (sin sanear). No es el que se muestra: el modal usa el
    /// nombre del `PendingLocalConsent` que devuelve `authenticate`, saneado.
    pub operator_display_name: String,
    /// Origen de la conexion segun el transporte (sin sanear).
    pub origin: String,
    authenticate: AuthenticateFn,
}

impl IncomingRequest {
    pub fn new(
        operator_display_name: String,
        origin: String,
        authenticate: impl FnOnce(WaitingForRequest, Instant) -> Option<AuthenticateResult>
        + Send
        + 'static,
    ) -> Self {
        Self {
            operator_display_name,
            origin,
            authenticate: Box::new(authenticate),
        }
    }

    /// Ejecuta el handshake con las credenciales del host (puede bloquear: llamar fuera del hilo de
    /// la UI). `None` si el transporte no devolvio las credenciales a tiempo.
    pub fn authenticate(
        self,
        waiting: WaitingForRequest,
        now: Instant,
    ) -> Option<AuthenticateResult> {
        (self.authenticate)(waiting, now)
    }
}

impl std::fmt::Debug for IncomingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("operator_display_name", &self.operator_display_name)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum TransportEvent {
    Relay(RelayStatus),
    OperatorRequest(IncomingRequest),
    OperatorDisconnected,
    /// El relay rechazo el ID por ocupado: hay que generar uno nuevo.
    SessionIdTaken,
}

/// Fuente de eventos entrantes del host.
pub trait HostTransport {
    /// Siguiente evento pendiente, sin bloquear.
    fn poll_event(&mut self) -> Option<TransportEvent>;
    /// `true` si es una simulacion (la UI lo indica en pantalla).
    fn is_simulated(&self) -> bool;
    /// ID que debe quedar registrado en el relay.
    fn set_session_id(&mut self, _id: SessionId) {}
}

/// Transporte del relay real (`net::HostNet`).
pub struct RelayTransport {
    net: HostNet,
}

impl RelayTransport {
    pub fn new(net: HostNet) -> Self {
        Self { net }
    }
}

impl HostTransport for RelayTransport {
    fn poll_event(&mut self) -> Option<TransportEvent> {
        Some(match self.net.poll_event()? {
            NetEvent::Connecting => TransportEvent::Relay(RelayStatus::Connecting),
            NetEvent::Registered => TransportEvent::Relay(RelayStatus::Registered),
            NetEvent::Unreachable => TransportEvent::Relay(RelayStatus::Disconnected),
            NetEvent::SessionIdTaken => TransportEvent::SessionIdTaken,
            NetEvent::OperatorHello { name, auth } => TransportEvent::OperatorRequest(
                IncomingRequest::new(name, "via relay".to_string(), move |waiting, _now| {
                    auth.authenticate(waiting)
                }),
            ),
            NetEvent::OperatorGone => TransportEvent::OperatorDisconnected,
        })
    }

    fn is_simulated(&self) -> bool {
        false
    }

    fn set_session_id(&mut self, id: SessionId) {
        self.net.set_session_id(id);
    }
}

/// Transporte inexistente: faltan `--relay`/`--relay-pin` o no son validos.
#[derive(Debug, Default)]
pub struct DisconnectedTransport {
    announced: bool,
}

impl HostTransport for DisconnectedTransport {
    fn poll_event(&mut self) -> Option<TransportEvent> {
        if self.announced {
            return None;
        }
        self.announced = true;
        Some(TransportEvent::Relay(RelayStatus::Disconnected))
    }

    fn is_simulated(&self) -> bool {
        false
    }
}

/// Transporte simulado (solo pruebas): los eventos los inyecta `SimulationHandle`.
#[cfg(test)]
#[derive(Debug)]
pub struct SimulatedTransport {
    rx: Receiver<TransportEvent>,
    announced: bool,
}

/// Mando de la simulacion: representa al operador remoto.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct SimulationHandle {
    tx: Sender<TransportEvent>,
}

#[cfg(test)]
impl SimulatedTransport {
    pub fn new() -> (Self, SimulationHandle) {
        let (tx, rx) = mpsc::channel();
        (
            Self {
                rx,
                announced: false,
            },
            SimulationHandle { tx },
        )
    }
}

#[cfg(test)]
impl HostTransport for SimulatedTransport {
    fn poll_event(&mut self) -> Option<TransportEvent> {
        if !self.announced {
            self.announced = true;
            return Some(TransportEvent::Relay(RelayStatus::Registered));
        }
        self.rx.try_recv().ok()
    }

    fn is_simulated(&self) -> bool {
        true
    }
}

#[cfg(test)]
impl SimulationHandle {
    /// Simula que un operador que conoce `password` solicita el control. El handshake se ejecuta en
    /// memoria al autenticar (`run_in_memory_handshake`), asi que el resultado es un
    /// `PendingLocalConsent` real. Con una contrasena equivocada falla como en la red.
    pub fn request_operator(&self, operator_display_name: &str, password: &str) {
        let name = operator_display_name.to_string();
        let password = password.to_string();
        let request_name = name.clone();
        let request = IncomingRequest::new(
            name,
            "203.0.113.25:50321 (simulado, via relay)".to_string(),
            move |waiting, now| {
                let req = OperatorConnectionRequest {
                    target_session_id: waiting.session_id(),
                    operator_display_name: request_name,
                    operator_ed25519_fingerprint: [0x4A, 0x91, 0xC2, 0x08, 0x7F, 0xE3, 0x11, 0x5B],
                    requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
                };
                Some(
                    run_in_memory_handshake(waiting, &req, &password, now)
                        .map(|(authenticated, _operator)| authenticated.pending),
                )
            },
        );
        let _ = self.tx.send(TransportEvent::OperatorRequest(request));
    }

    /// Simula que el operador cierra su conexion.
    pub fn disconnect_operator(&self) {
        let _ = self.tx.send(TransportEvent::OperatorDisconnected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_transport_announces_the_relay_then_forwards_injected_events() {
        let (mut transport, handle) = SimulatedTransport::new();
        assert!(transport.is_simulated());
        assert!(matches!(
            transport.poll_event(),
            Some(TransportEvent::Relay(RelayStatus::Registered))
        ));
        assert!(transport.poll_event().is_none());
        handle.disconnect_operator();
        assert!(matches!(
            transport.poll_event(),
            Some(TransportEvent::OperatorDisconnected)
        ));
    }

    #[test]
    fn simulated_request_with_the_right_password_yields_a_real_pending_consent() {
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        handle.request_operator("Operador", &waiting.display_password());
        let Some(TransportEvent::OperatorRequest(request)) = transport.poll_event() else {
            panic!("se esperaba una solicitud");
        };
        let pending = request
            .authenticate(waiting, Instant::now())
            .unwrap()
            .expect("credenciales validas");
        assert_eq!(pending.operator_display_name(), "Operador");
    }

    #[test]
    fn simulated_request_with_a_wrong_password_returns_the_waiting_state() {
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        handle.request_operator("Operador", "WRONG-PASS2");
        let Some(TransportEvent::OperatorRequest(request)) = transport.poll_event() else {
            panic!("se esperaba una solicitud");
        };
        let Some(Err((_waiting, err))) = request.authenticate(waiting, Instant::now()) else {
            panic!("debe rechazar la contrasena");
        };
        assert!(matches!(err, ConsentError::InvalidPassword { .. }));
    }

    #[test]
    fn disconnected_transport_only_reports_the_relay_once() {
        let mut transport = DisconnectedTransport::default();
        assert!(!transport.is_simulated());
        assert!(matches!(
            transport.poll_event(),
            Some(TransportEvent::Relay(RelayStatus::Disconnected))
        ));
        assert!(transport.poll_event().is_none());
    }
}
