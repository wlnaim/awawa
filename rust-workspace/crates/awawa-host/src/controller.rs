//! Maquina de estados del host, sin dependencias de egui ni de Win32 (reloj inyectable).
//!
//! Fases: `Waiting` (ID y contrasena efimeros) -> `Authenticating` (handshake de red en un hilo
//! aparte, con plazo) -> `Pending` (modal de consentimiento) -> `Active` (banner + kill-switch).
//! La UI solo dibuja `view()` y reenvia acciones.
//!
//! Garantia de consentimiento: el UNICO sitio de este crate que crea un `ApprovedActiveSession`
//! es `HostController::accept`, que solo lo invoca desde la fase `Pending` cuando el modal esta
//! en `AcceptAvailability::Enabled` (pasados 1 500 ms, antes de 60 s y con el kill-switch armado).
//! `accept` solo lo llama el boton Aceptar, y entrega la sesion a la `SessionGate`, unica via de la
//! captura y la entrada. Ningun evento de transporte, temporizador ni senal de revocacion puede
//! llevar a `Active`.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use awawa_protocol::{
    CredentialsError, PendingLocalConsent, ProtectedRect, ScopedCapabilities, SessionId,
    SessionRevocation, WaitingForRequest,
};

use crate::consent_timer::{AcceptAvailability, ConsentModalTimer};
use crate::display_name::{sanitize_operator_name, sanitize_origin};
use crate::gate::SessionGate;
use crate::revocation::RevocationTrigger;
use crate::session_clock::SessionClock;
use crate::transport::{AuthenticateResult, RelayStatus, TransportEvent};

/// Plazo de la UI para el resultado del handshake; vencido, las credenciales se dan por perdidas.
const AUTHENTICATION_UI_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingState {
    pending: PendingLocalConsent,
    timer: ConsentModalTimer,
    name: String,
    origin: String,
}

struct ActiveState {
    clock: SessionClock,
    name: String,
}

struct AuthenticatingState {
    result: Receiver<Option<AuthenticateResult>>,
    origin: String,
    since: Instant,
    /// El operador se fue mientras corria el handshake: su resultado ya no abre el modal.
    operator_gone: bool,
}

enum Phase {
    Waiting(WaitingForRequest),
    Authenticating(AuthenticatingState),
    Pending(PendingState),
    Active(ActiveState),
    /// No se pudieron generar credenciales (fallo del CSPRNG del SO): el host no ofrece soporte.
    Faulted(String),
    /// Marcador durante una transicion; nunca es observable fuera de un metodo.
    Transition,
}

/// Lo que la UI puede leer de cada fase.
pub enum HostView<'a> {
    Waiting {
        id: String,
        password: String,
    },
    Authenticating,
    Pending {
        name: &'a str,
        origin: &'a str,
        fingerprint: String,
        sas: String,
        capabilities: ScopedCapabilities,
        timer: ConsentModalTimer,
    },
    Active {
        name: &'a str,
        clock: SessionClock,
    },
    Faulted(&'a str),
}

pub struct HostController {
    phase: Phase,
    relay: RelayStatus,
    notice: Option<String>,
    last_revocation: Option<SessionRevocation>,
    gate: SessionGate,
}

fn fresh_waiting() -> Phase {
    match WaitingForRequest::start_client_reception() {
        Ok(waiting) => Phase::Waiting(waiting),
        Err(e) => faulted(e),
    }
}

fn faulted(err: CredentialsError) -> Phase {
    Phase::Faulted(format!(
        "No se pudieron generar las credenciales de forma segura: {err:?}"
    ))
}

impl HostController {
    pub fn new(gate: SessionGate) -> Self {
        Self {
            phase: fresh_waiting(),
            relay: RelayStatus::Connecting,
            notice: None,
            last_revocation: None,
            gate,
        }
    }

    /// ID que debe estar registrado en el relay (solo mientras se espera una solicitud).
    pub fn session_id(&self) -> Option<SessionId> {
        match &self.phase {
            Phase::Waiting(w) => Some(w.session_id()),
            _ => None,
        }
    }

    pub fn view(&self) -> HostView<'_> {
        match &self.phase {
            Phase::Waiting(w) => HostView::Waiting {
                id: w.session_id().formatted(),
                password: w.display_password(),
            },
            Phase::Authenticating(_) => HostView::Authenticating,
            Phase::Pending(p) => HostView::Pending {
                name: &p.name,
                origin: &p.origin,
                fingerprint: p.pending.operator_fingerprint_hex(),
                sas: p.pending.sas().to_string(),
                capabilities: p.pending.requested_capabilities(),
                timer: p.timer,
            },
            Phase::Active(a) => HostView::Active {
                name: &a.name,
                clock: a.clock,
            },
            Phase::Faulted(msg) => HostView::Faulted(msg),
            Phase::Transition => HostView::Faulted("estado interno invalido"),
        }
    }

    pub fn relay_status(&self) -> &RelayStatus {
        &self.relay
    }

    pub fn is_pending(&self) -> bool {
        matches!(self.phase, Phase::Pending(_))
    }

    pub fn is_active(&self) -> bool {
        matches!(self.phase, Phase::Active(_))
    }

    pub fn is_waiting(&self) -> bool {
        matches!(self.phase, Phase::Waiting(_))
    }

    /// Aviso para el usuario local (p. ej. "solicitud rechazada"); se consume al leerlo.
    pub fn take_notice(&mut self) -> Option<String> {
        self.notice.take()
    }

    /// Ultima revocacion, con las liberaciones de teclas y botones pendientes que la revocacion
    /// entrega al despachador de entrada (`flush_revocation_releases`).
    pub fn take_revocation(&mut self) -> Option<SessionRevocation> {
        self.last_revocation.take()
    }

    /// "Regenerar": rota solo la contrasena efimera y conserva el ID.
    pub fn regenerate_credentials(&mut self) {
        if let Phase::Waiting(waiting) = &mut self.phase
            && let Err(e) = waiting.rotate_password()
        {
            self.phase = faulted(e);
        }
    }

    /// El modal se pinto en este cuadro: ancla la inhabilitacion de Aceptar al primer cuadro pintado.
    pub fn mark_modal_painted(&mut self, now: Instant) {
        if let Phase::Pending(p) = &mut self.phase {
            p.timer = p.timer.painted(now);
        }
    }

    /// Aplica un evento del transporte.
    pub fn on_event(&mut self, event: TransportEvent, now: Instant) {
        match event {
            TransportEvent::Relay(status) => self.relay = status,
            TransportEvent::OperatorRequest(request) => {
                // Un solo operador a la vez: con un modal abierto o una sesion activa se ignora.
                if !self.is_waiting() {
                    return;
                }
                let Phase::Waiting(waiting) = std::mem::replace(&mut self.phase, Phase::Transition)
                else {
                    return;
                };
                let origin = sanitize_origin(&request.origin);
                // El handshake de red puede tardar: corre fuera del hilo de la UI.
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(request.authenticate(waiting, now));
                });
                self.phase = Phase::Authenticating(AuthenticatingState {
                    result: rx,
                    origin,
                    since: now,
                    operator_gone: false,
                });
            }
            TransportEvent::SessionIdTaken => {
                // El relay tiene ese ID ocupado; se genera otro y la red reintenta.
                if self.is_waiting() {
                    self.phase = fresh_waiting();
                    self.notice =
                        Some("El ID estaba ocupado en el relay: se genero uno nuevo.".to_string());
                }
            }
            TransportEvent::OperatorDisconnected => match self.phase {
                // La red ya cerro esa sesion: no se avisa a la compuerta (podria cerrar la siguiente).
                Phase::Pending(_) => {
                    self.reject_pending("El operador se desconecto antes de la decision", false)
                }
                Phase::Active(_) => {
                    self.revoke(RevocationTrigger::OperatorDisconnected, now);
                }
                Phase::Authenticating(ref mut state) => state.operator_gone = true,
                _ => {}
            },
        }
    }

    /// Recoge el resultado del handshake si ya llego (o lo da por perdido tras el plazo).
    fn poll_authentication(&mut self, now: Instant) {
        let Phase::Authenticating(state) = &self.phase else {
            return;
        };
        let outcome = match state.result.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty)
                if now.saturating_duration_since(state.since) < AUTHENTICATION_UI_TIMEOUT =>
            {
                return;
            }
            Err(_) => None,
        };
        let Phase::Authenticating(state) = std::mem::replace(&mut self.phase, Phase::Transition)
        else {
            return;
        };
        match outcome {
            Some(Ok(pending)) if state.operator_gone => {
                self.notice = Some("El operador se desconecto antes de la decision.".to_string());
                self.phase = match pending.reject_locally() {
                    Ok(waiting) => Phase::Waiting(waiting),
                    Err(e) => faulted(e),
                };
            }
            Some(Ok(pending)) => {
                // El nombre mostrado es el ligado al handshake, saneado.
                let name = sanitize_operator_name(pending.operator_display_name());
                self.phase = Phase::Pending(PendingState {
                    pending,
                    timer: ConsentModalTimer::new(now),
                    name,
                    origin: state.origin,
                });
            }
            Some(Err((waiting, _err))) => {
                // Sin nombre ni detalle: no se molesta al usuario local por un intento no autenticado.
                self.notice =
                    Some("Se descarto un intento de conexion no autenticado.".to_string());
                self.phase = Phase::Waiting(waiting);
            }
            None => {
                // Las credenciales no volvieron del transporte: se generan otras.
                self.notice = Some("La solicitud no se completo a tiempo.".to_string());
                self.phase = fresh_waiting();
            }
        }
    }

    /// Bloquea hasta que termine el handshake en curso (pruebas).
    #[cfg(test)]
    pub fn wait_authentication(&mut self, now: Instant) {
        if let Phase::Authenticating(state) = &self.phase
            && let Ok(outcome) = state.result.recv_timeout(Duration::from_secs(10))
        {
            let (tx, rx) = mpsc::channel();
            let _ = tx.send(outcome);
            if let Phase::Authenticating(state) = &mut self.phase {
                state.result = rx;
            }
        }
        self.poll_authentication(now);
    }

    /// Avanza los temporizadores: al vencer los 60 s el modal se rechaza por defecto. Si otro hilo
    /// (atajo global o red) ya revoco la sesion, vuelve a la espera.
    pub fn tick(&mut self, now: Instant) {
        self.poll_authentication(now);
        if self.is_active() && !self.gate.is_active() {
            self.finish_revocation();
        }
        if let Phase::Pending(p) = &self.phase
            && p.timer.is_expired(now)
        {
            self.reject("Tiempo agotado: solicitud rechazada por defecto");
        }
    }

    /// Clic en **Aceptar**. Unico camino hacia `ApprovedActiveSession`.
    /// `banner_rect` es el rectangulo estimado del banner (pixeles fisicos) que protege el boton de revocar.
    /// Devuelve `true` si la sesion quedo activa.
    pub fn accept(
        &mut self,
        now: Instant,
        kill_switch_armed: bool,
        banner_rect: ProtectedRect,
    ) -> bool {
        let availability = match &self.phase {
            Phase::Pending(p) => p.timer.accept_availability(now, kill_switch_armed),
            _ => return false,
        };
        match availability {
            AcceptAvailability::Enabled => {}
            AcceptAvailability::Expired => {
                self.reject("Tiempo agotado: solicitud rechazada por defecto");
                return false;
            }
            // Boton inhabilitado: el clic no hace nada.
            AcceptAvailability::LockedByGracePeriod | AcceptAvailability::KillSwitchUnavailable => {
                return false;
            }
        }
        if !self.is_pending() {
            return false;
        }
        let Phase::Pending(state) = std::mem::replace(&mut self.phase, Phase::Transition) else {
            return false;
        };
        match state.pending.approve_locally(now, Some(banner_rect)) {
            Ok(session) => {
                self.gate.activate(session, now);
                self.phase = Phase::Active(ActiveState {
                    clock: SessionClock::start(now),
                    name: state.name,
                });
                true
            }
            Err((waiting, err)) => {
                self.notice = Some(format!("La aprobacion no se pudo completar ({err:?})"));
                self.phase = Phase::Waiting(waiting);
                false
            }
        }
    }

    /// Clic en **Rechazar** (o cierre del modal): rota la contrasena y vuelve a esperar.
    pub fn reject(&mut self, notice: &str) {
        self.reject_pending(notice, true);
    }

    /// Rechaza el modal; con `notify_net` la red envia el rechazo al operador y cierra.
    fn reject_pending(&mut self, notice: &str, notify_net: bool) {
        if !self.is_pending() {
            return;
        }
        let Phase::Pending(state) = std::mem::replace(&mut self.phase, Phase::Transition) else {
            return;
        };
        if notify_net {
            self.gate.decline();
        }
        match state.pending.reject_locally() {
            Ok(waiting) => {
                self.notice = Some(format!("{notice}. La contrasena se regenero."));
                self.phase = Phase::Waiting(waiting);
            }
            Err(e) => self.phase = faulted(e),
        }
    }

    /// Revoca la sesion activa. Sin sesion activa no hace nada. Despues de revocar se generan
    /// credenciales nuevas (las anteriores se consumieron al aprobar).
    pub fn revoke(&mut self, trigger: RevocationTrigger, now: Instant) {
        if !self.is_active() {
            return;
        }
        // Si el atajo (desde su hilo) o la red ya revocaron, la compuerta conserva esa revocacion.
        self.gate.revoke(trigger.reason(), now);
        self.finish_revocation();
    }

    /// Pasa de `Active` a `Waiting` con credenciales nuevas (ID y contrasena; la red re-registra el
    /// ID nuevo). Las liberaciones de teclas ya las entrego la compuerta al despachador.
    fn finish_revocation(&mut self) {
        if !self.is_active() {
            return;
        }
        self.last_revocation = self.gate.take_revocation();
        self.phase = fresh_waiting();
    }

    /// Actualiza el rectangulo protegido con el real de la ventana del banner.
    pub fn update_banner_rect(&mut self, rect: ProtectedRect) {
        if self.is_active() {
            self.gate.update_protected_rect(rect);
        }
    }

    /// Cierre de la aplicacion: rechaza el modal o revoca la sesion si los hay.
    pub fn shutdown(&mut self, now: Instant) {
        match self.phase {
            Phase::Pending(_) => self.reject("Aplicacion cerrada"),
            Phase::Active(_) => self.revoke(RevocationTrigger::MainWindowClosed, now),
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use super::*;
    use crate::banner_geometry::banner_layout;
    use crate::transport::{HostTransport, SimulatedTransport};

    /// Compuerta con un despachador que solo registra (sin entrada real).
    pub(crate) fn test_gate() -> SessionGate {
        crate::net_tests::recording_gate().0
    }

    pub(crate) fn new_controller() -> HostController {
        HostController::new(test_gate())
    }

    /// Entrega el evento y espera el handshake simulado.
    pub(crate) fn deliver(c: &mut HostController, event: TransportEvent, now: Instant) {
        c.on_event(event, now);
        c.wait_authentication(now);
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn rect() -> ProtectedRect {
        banner_layout(1920, 1.0).protected_rect
    }

    fn id_and_password(c: &HostController) -> (String, String) {
        match c.view() {
            HostView::Waiting { id, password } => (id, password),
            _ => panic!("se esperaba la fase Waiting"),
        }
    }

    /// Controlador con una solicitud valida ya autenticada: modal abierto en `t0`.
    fn pending_controller(t0: Instant) -> HostController {
        let mut c = new_controller();
        let (mut transport, handle) = SimulatedTransport::new();
        let (_, password) = id_and_password(&c);
        transport.poll_event();
        handle.request_operator("Operador de prueba", &password);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        assert!(c.is_pending());
        c.mark_modal_painted(t0);
        c
    }

    #[test]
    fn credentials_alone_never_start_control() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        // Ni el paso del tiempo ni eventos de transporte activan la sesion.
        c.tick(t0 + ms(2000));
        assert!(c.is_pending() && !c.is_active());
        c.on_event(
            TransportEvent::Relay(RelayStatus::Registered),
            t0 + ms(3000),
        );
        assert!(c.is_pending() && !c.is_active());
    }

    #[test]
    fn accept_before_1500_ms_does_nothing() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        assert!(!c.accept(t0 + ms(1499), true, rect()));
        assert!(c.is_pending());
        assert!(c.accept(t0 + ms(1500), true, rect()));
        assert!(c.is_active());
    }

    #[test]
    fn accept_requires_an_armed_kill_switch() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        assert!(!c.accept(t0 + ms(5000), false, rect()));
        assert!(c.is_pending());
        assert!(c.accept(t0 + ms(5000), true, rect()));
    }

    #[test]
    fn accept_after_the_timeout_rejects_and_rotates_the_password() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        assert!(!c.accept(t0 + ms(60_000), true, rect()));
        assert!(c.is_waiting());
        assert!(c.take_notice().unwrap().contains("regenero"));
    }

    #[test]
    fn modal_times_out_after_60_seconds_by_default_and_rotates_the_password() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (id_before, pw_before) = id_and_password(&c);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador", &pw_before);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        c.tick(t0 + ms(59_999));
        assert!(c.is_pending());
        c.tick(t0 + ms(60_000));
        assert!(c.is_waiting() && !c.is_active());
        let (id_after, pw_after) = id_and_password(&c);
        assert_eq!(id_after, id_before, "rechazar conserva el ID");
        assert_ne!(pw_after, pw_before, "rechazar rota la contrasena");
    }

    #[test]
    fn explicit_reject_rotates_the_password_and_waits_again() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (_, pw_before) = id_and_password(&c);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador", &pw_before);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        c.reject("Solicitud rechazada");
        assert!(c.is_waiting());
        assert_ne!(id_and_password(&c).1, pw_before);
    }

    #[test]
    fn wrong_password_never_opens_the_modal() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador", "WRONG-PASS2");
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        assert!(c.is_waiting());
        let notice = c.take_notice().expect("aviso generico");
        assert!(!notice.contains("Operador") && !notice.contains("InvalidPassword"));
    }

    #[test]
    fn accept_stays_locked_until_the_modal_has_been_painted() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (_, pw) = id_and_password(&c);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador", &pw);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        assert!(!c.accept(t0 + ms(10_000), true, rect()));
        c.mark_modal_painted(t0 + ms(10_000));
        assert!(!c.accept(t0 + ms(11_499), true, rect()));
        assert!(c.accept(t0 + ms(11_500), true, rect()));
    }

    #[test]
    fn a_second_request_during_the_modal_is_ignored() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Otro", "XXXX-XXXXXX");
        deliver(&mut c, transport.poll_event().unwrap(), t0 + ms(100));
        match c.view() {
            HostView::Pending { name, .. } => assert_eq!(name, "Operador de prueba"),
            _ => panic!("el modal original debe seguir abierto"),
        }
    }

    #[test]
    fn modal_shows_the_sanitized_operator_name_and_the_real_sas_and_capabilities() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (_, pw) = id_and_password(&c);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator(&format!("\u{202E}Admin\n{}", "x".repeat(300)), &pw);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        match c.view() {
            HostView::Pending {
                name,
                sas,
                capabilities,
                fingerprint,
                ..
            } => {
                assert!(name.starts_with("Admin x"));
                assert!(name.chars().count() <= crate::display_name::MAX_OPERATOR_NAME_CHARS);
                assert!(!name.contains('\u{202E}') && !name.contains('\n'));
                assert_eq!(sas.len(), 6);
                assert_eq!(
                    capabilities,
                    ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS
                );
                assert_eq!(fingerprint, "4A:91:C2:08:7F:E3:11:5B");
            }
            _ => panic!("modal esperado"),
        }
    }

    #[test]
    fn every_revocation_trigger_ends_the_session_and_returns_to_waiting() {
        for trigger in [
            RevocationTrigger::Button,
            RevocationTrigger::Hotkey,
            RevocationTrigger::BannerCloseRequested,
            RevocationTrigger::BannerMinimized,
            RevocationTrigger::MainWindowClosed,
            RevocationTrigger::OperatorDisconnected,
        ] {
            let t0 = Instant::now();
            let mut c = pending_controller(t0);
            assert!(c.accept(t0 + ms(2000), true, rect()));
            c.revoke(trigger, t0 + ms(9000));
            assert!(c.is_waiting(), "{trigger:?}");
            let rev = c.take_revocation().expect("revocacion registrada");
            assert_eq!(rev.reason, trigger.reason());
            assert_eq!(rev.duration, ms(7000));
        }
    }

    #[test]
    fn operator_disconnect_revokes_an_active_session_and_rejects_a_pending_modal() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        c.on_event(TransportEvent::OperatorDisconnected, t0 + ms(500));
        assert!(c.is_waiting());

        let mut c = pending_controller(t0);
        assert!(c.accept(t0 + ms(2000), true, rect()));
        c.on_event(TransportEvent::OperatorDisconnected, t0 + ms(3000));
        assert!(c.is_waiting());
        assert!(c.take_revocation().is_some());
    }

    #[test]
    fn revoking_without_an_active_session_is_a_no_op() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        c.revoke(RevocationTrigger::Hotkey, t0 + ms(2000));
        assert!(c.is_pending(), "el atajo no debe tocar un modal pendiente");
        assert!(c.take_revocation().is_none());
    }

    #[test]
    fn shutdown_rejects_a_pending_modal_and_revokes_an_active_session() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        c.shutdown(t0 + ms(100));
        assert!(c.is_waiting());

        let mut c = pending_controller(t0);
        assert!(c.accept(t0 + ms(2000), true, rect()));
        c.shutdown(t0 + ms(4000));
        assert!(c.is_waiting());
        assert_eq!(
            c.take_revocation().unwrap().reason,
            RevocationTrigger::MainWindowClosed.reason()
        );
    }

    #[test]
    fn regenerate_changes_the_credentials_only_while_waiting() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (id, pw) = id_and_password(&c);
        c.regenerate_credentials();
        let (id2, pw2) = id_and_password(&c);
        assert_eq!(id, id2, "regenerar conserva el ID");
        assert_ne!(pw, pw2, "regenerar rota la contrasena");

        let mut c = pending_controller(t0);
        c.regenerate_credentials();
        assert!(c.is_pending());
    }

    #[test]
    fn authentication_runs_off_the_ui_thread_and_a_disconnect_meanwhile_discards_it() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let (_, password) = id_and_password(&c);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let request = crate::transport::IncomingRequest::new(
            "Operador".to_string(),
            "via relay".to_string(),
            move |waiting, now| {
                // Simula la red: el handshake termina cuando la prueba lo permite.
                let _ = release_rx.recv();
                let req = awawa_protocol::OperatorConnectionRequest {
                    target_session_id: waiting.session_id(),
                    operator_display_name: "Operador".to_string(),
                    operator_ed25519_fingerprint: [0; 8],
                    requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
                };
                Some(
                    awawa_protocol::run_in_memory_handshake(waiting, &req, &password, now)
                        .map(|(host, _)| host.pending),
                )
            },
        );
        c.on_event(TransportEvent::OperatorRequest(request), t0);
        // `on_event` no espera al handshake: la UI sigue respondiendo.
        assert!(matches!(c.view(), HostView::Authenticating));
        c.on_event(TransportEvent::OperatorDisconnected, t0 + ms(10));
        release_tx.send(()).unwrap();
        c.wait_authentication(t0 + ms(20));
        assert!(c.is_waiting(), "sin operador no se abre el modal");
        assert!(c.take_notice().unwrap().contains("desconecto"));
    }

    #[test]
    fn id_taken_in_the_relay_regenerates_the_credentials_only_while_waiting() {
        let mut c = new_controller();
        let (id, _) = id_and_password(&c);
        c.on_event(TransportEvent::SessionIdTaken, Instant::now());
        let (id2, _) = id_and_password(&c);
        assert_ne!(id, id2);
        assert_eq!(c.session_id().unwrap().formatted(), id2);

        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        c.on_event(TransportEvent::SessionIdTaken, t0);
        assert!(c.is_pending());
        assert!(c.session_id().is_none());
    }

    #[test]
    fn revocation_from_another_thread_is_picked_up_by_tick() {
        let t0 = Instant::now();
        let gate = test_gate();
        let mut c = HostController::new(gate.clone());
        let (_, password) = id_and_password(&c);
        let (mut transport, handle) = SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador", &password);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        c.mark_modal_painted(t0);
        assert!(c.accept(t0 + ms(1500), true, rect()));
        assert!(gate.is_active());
        // El atajo global revoca en la compuerta desde su hilo, sin pasar por la UI.
        assert!(gate.revoke(RevocationTrigger::Hotkey.reason(), t0 + ms(2500)));
        c.tick(t0 + ms(2600));
        assert!(c.is_waiting());
        let rev = c.take_revocation().unwrap();
        assert_eq!(rev.reason, RevocationTrigger::Hotkey.reason());
        assert_eq!(rev.duration, ms(1000));
    }

    #[test]
    fn relay_status_follows_transport_events() {
        let mut c = new_controller();
        assert_eq!(*c.relay_status(), RelayStatus::Connecting);
        c.on_event(
            TransportEvent::Relay(RelayStatus::Registered),
            Instant::now(),
        );
        assert_eq!(*c.relay_status(), RelayStatus::Registered);
    }
}
