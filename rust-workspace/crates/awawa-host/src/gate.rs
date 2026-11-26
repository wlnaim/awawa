//! Compuerta compartida de la sesion activa: la unica via por la que la captura y la entrada
//! remota alcanzan el `ApprovedActiveSession`.
//!
//! El controlador de la UI la activa con la sesion que nace del clic en Aceptar
//! (`HostController::accept`); antes de eso no hay sesion dentro y ningun trabajador puede capturar
//! ni inyectar. Cualquiera puede revocarla (UI, atajo global desde su propio hilo, red): la marca
//! `active` cae primero, sin esperar el candado, de modo que el video y la entrada se detienen
//! aunque la captura tenga el candado tomado; despues se consume la sesion y se entregan al
//! despachador las liberaciones de teclas y botones (`flush_revocation_releases`).
//!
//! La captura retiene el candado durante `capture_authorized_frame`, que exige el prestamo de
//! `&ApprovedActiveSession` durante toda la llamada (incluida la espera de `AcquireNextFrame`).
//! Por eso la revocacion, el rectangulo del banner, el `Ping` y el tic del heartbeat no esperan
//! el candado: se anotan aparte y los aplica quien lo tenga (antes y despues de usarlo).
//!
//! Solo depende de `awawa-protocol` y `tokio` (la prueba E2E del relay la incluye por ruta).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use awawa_protocol::{
    ApprovedActiveSession, DesktopEvent, DesktopSessionMonitor, InputDesktopKind, MonitorAction,
    OperatorNotice, ProtectedRect, RemoteInputCommand, SessionRevocation,
};
use tokio::sync::watch;

/// Despachador de entrada con consentimiento (`ConsentGatedInputDispatcher` en produccion).
pub trait InputSink: Send {
    fn enable_heartbeat(&mut self, now: Instant);
    fn record_ping(&mut self, now: Instant);
    fn tick_heartbeat(&mut self, session: &mut ApprovedActiveSession, now: Instant) -> bool;
    /// `Err` con el motivo si el comando no llego al SO.
    fn dispatch(
        &mut self,
        session: &mut ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        cmd: &RemoteInputCommand,
    ) -> Result<(), String>;
    fn release_held_input(&mut self, session: &mut ApprovedActiveSession);
    fn flush_revocation_releases(&mut self, revocation: &SessionRevocation);
}

/// Estado visible para la red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// Sin decision: esperando solicitud o el clic del usuario local.
    Idle,
    /// El usuario local acepto: video y entrada habilitados.
    Active,
    /// Rechazada o revocada: la red cierra la sesion del operador.
    Closed,
}

struct GateState {
    session: Option<ApprovedActiveSession>,
    desktop: DesktopSessionMonitor,
    input: Box<dyn InputSink>,
}

/// Peticiones que no esperan el candado principal (lo puede retener la captura durante
/// `AcquireNextFrame`): las aplica quien tenga el candado, antes y despues de usarlo.
#[derive(Default)]
struct Deferred {
    revoke: Option<(String, Instant)>,
    rect: Option<ProtectedRect>,
    ping: Option<Instant>,
    /// Tic del dead-man switch pendiente (el instante mas reciente).
    tick: Option<Instant>,
    last_revocation: Option<SessionRevocation>,
}

struct Inner {
    active: AtomicBool,
    state: Mutex<GateState>,
    deferred: Mutex<Deferred>,
    status: watch::Sender<GateStatus>,
}

/// Compuerta clonable (UI, hilo del atajo, red y captura comparten la misma).
#[derive(Clone)]
pub struct SessionGate {
    inner: Arc<Inner>,
}

/// Resultado de procesar el escritorio de entrada. Cada campo vale `true` una sola vez por
/// transicion del `DesktopSessionMonitor` (sus avisos `NotifyOperator`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopChange {
    /// Se suspendio por escritorio seguro o bloqueo: el operador recibe `LocalApprovalRequired`.
    pub local_approval_required: bool,
    /// Se reanudo: el operador recibe `LocalApprovalCleared` y el siguiente fotograma es clave.
    pub resumed: bool,
}

impl SessionGate {
    pub fn new(input: Box<dyn InputSink>) -> Self {
        let (status, _) = watch::channel(GateStatus::Idle);
        Self {
            inner: Arc::new(Inner {
                active: AtomicBool::new(false),
                state: Mutex::new(GateState {
                    session: None,
                    desktop: DesktopSessionMonitor::new(InputDesktopKind::Default),
                    input,
                }),
                deferred: Mutex::new(Deferred::default()),
                status,
            }),
        }
    }

    fn deferred(&self) -> MutexGuard<'_, Deferred> {
        self.inner
            .deferred
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Aplica las peticiones diferidas con el candado principal tomado. `true` si el tic del
    /// heartbeat acaba de expirar (y libero lo retenido).
    fn apply_deferred(&self, state: &mut GateState) -> bool {
        let (revoke, rect, ping, tick) = {
            let mut d = self.deferred();
            (d.revoke.take(), d.rect.take(), d.ping.take(), d.tick.take())
        };
        let mut expired = false;
        if let Some(session) = state.session.as_mut() {
            if let Some(rect) = rect {
                session.update_protected_host_ui(Some(rect));
            }
            if let Some(now) = ping {
                state.input.record_ping(now);
            }
            if let Some(now) = tick {
                expired = state.input.tick_heartbeat(session, now);
            }
        }
        if let Some((reason, now)) = revoke
            && let Some(session) = state.session.take()
        {
            let revocation = session.revoke_immediately(now, reason);
            state.input.flush_revocation_releases(&revocation);
            self.deferred().last_revocation = Some(revocation);
            self.inner.status.send_replace(GateStatus::Closed);
        }
        expired
    }

    fn has_deferred(&self) -> bool {
        let d = self.deferred();
        d.revoke.is_some() || d.rect.is_some() || d.ping.is_some() || d.tick.is_some()
    }

    /// Ejecuta `f` con el candado principal; aplica lo diferido antes y despues. Si al soltarlo
    /// quedo algo pendiente (llego mientras se usaba), lo intenta aplicar sin esperar.
    fn locked<R>(&self, f: impl FnOnce(&mut GateState) -> R) -> R {
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.apply_deferred(&mut guard);
        let result = f(&mut guard);
        self.apply_deferred(&mut guard);
        drop(guard);
        self.try_apply();
        result
    }

    /// Aplica lo diferido si el candado esta libre; si no, lo aplicara quien lo tenga al soltarlo.
    /// Tras soltarlo vuelve a mirar: lo que llego mientras se aplicaba no queda colgado.
    /// `true` si algun tic aplicado aqui expiro el heartbeat.
    fn try_apply(&self) -> bool {
        let mut expired = false;
        while self.has_deferred() {
            let mut guard = match self.inner.state.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => break,
            };
            expired |= self.apply_deferred(&mut guard);
        }
        expired
    }

    /// Recibe la sesion que acaba de aprobar el usuario local y activa el heartbeat.
    pub fn activate(&self, session: ApprovedActiveSession, now: Instant) {
        self.locked(|state| {
            state.session = Some(session);
            state.desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);
            state.input.enable_heartbeat(now);
            *self.deferred() = Deferred::default();
            self.inner.active.store(true, Ordering::SeqCst);
        });
        self.inner.status.send_replace(GateStatus::Active);
    }

    /// El usuario local rechazo (o el modal termino sin aprobar).
    pub fn decline(&self) {
        if !self.is_active() {
            self.inner.status.send_replace(GateStatus::Closed);
        }
    }

    /// Prepara la compuerta para una solicitud nueva (la usa la red al emparejar).
    pub fn reset(&self) {
        if !self.is_active() {
            self.inner.status.send_replace(GateStatus::Idle);
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::SeqCst)
    }

    pub fn subscribe(&self) -> watch::Receiver<GateStatus> {
        self.inner.status.subscribe()
    }

    /// Revoca la sesion si la hay: detiene video y entrada al instante (marca atomica), consume la
    /// sesion y libera teclas y botones retenidos. No espera el candado: si la captura lo tiene, la
    /// revocacion se completa en cuanto lo suelte. Devuelve `false` si no habia sesion activa.
    pub fn revoke(&self, reason: &str, now: Instant) -> bool {
        // Primero la marca: ningun fotograma ni comando sale desde este punto.
        if !self.inner.active.swap(false, Ordering::SeqCst) {
            return false;
        }
        self.deferred()
            .revoke
            .get_or_insert_with(|| (reason.to_string(), now));
        self.try_apply();
        true
    }

    /// Ultima revocacion (con las liberaciones ya entregadas al despachador).
    pub fn take_revocation(&self) -> Option<SessionRevocation> {
        self.deferred().last_revocation.take()
    }

    pub fn update_protected_rect(&self, rect: ProtectedRect) {
        self.deferred().rect = Some(rect);
        self.try_apply();
    }

    /// Ejecuta `f` con la sesion aprobada y el estado del escritorio. `None` sin sesion activa.
    /// La captura lo usa para `capture_authorized_frame`, que exige el prestamo de la sesion
    /// durante toda la llamada.
    pub fn with_session<R>(
        &self,
        f: impl FnOnce(&ApprovedActiveSession, &DesktopSessionMonitor) -> R,
    ) -> Option<R> {
        if !self.is_active() {
            return None;
        }
        self.locked(|state| {
            let session = state.session.as_ref()?;
            Some(f(session, &state.desktop))
        })
    }

    /// Despacha un comando del operador. Antes revisa el heartbeat.
    pub fn dispatch(&self, cmd: &RemoteInputCommand, now: Instant) -> Result<(), String> {
        if !self.is_active() {
            return Err("sin sesion activa".to_string());
        }
        self.locked(|state| {
            let Some(session) = state.session.as_mut() else {
                return Err("sin sesion activa".to_string());
            };
            state.input.tick_heartbeat(session, now);
            state.input.dispatch(session, &state.desktop, cmd)
        })
    }

    pub fn record_ping(&self, now: Instant) {
        if self.is_active() {
            self.deferred().ping = Some(now);
            self.try_apply();
        }
    }

    /// Tic del dead-man switch (cada <= 250 ms). `true` si acaba de expirar aqui mismo. Si la
    /// captura tiene el candado, el tic queda diferido y lo aplica la captura al soltarlo (antes de
    /// su siguiente fotograma), de modo que la expiracion libera lo retenido igualmente.
    pub fn tick_heartbeat(&self, now: Instant) -> bool {
        {
            let mut d = self.deferred();
            d.tick = Some(d.tick.map_or(now, |prev| prev.max(now)));
        }
        self.try_apply()
    }

    /// Aplica un sondeo del escritorio de entrada (o un fallo de captura por escritorio seguro):
    /// suspende captura y entrada, libera lo retenido y, al volver a `Default`, reanuda.
    pub fn observe_input_desktop(&self, kind: InputDesktopKind) -> DesktopChange {
        let mut change = DesktopChange {
            local_approval_required: false,
            resumed: false,
        };
        self.locked(|state| {
            let Some(session) = state.session.as_mut() else {
                return;
            };
            for action in state.desktop.handle(DesktopEvent::InputDesktop(kind)) {
                match action {
                    MonitorAction::ReleaseHeldInput => state.input.release_held_input(session),
                    MonitorAction::NotifyOperator(
                        OperatorNotice::LocalApprovalRequired | OperatorNotice::SessionLocked,
                    ) => change.local_approval_required = true,
                    MonitorAction::NotifyOperator(OperatorNotice::Resumed) => change.resumed = true,
                    _ => {}
                }
            }
        });
        change
    }

    pub fn capture_allowed(&self) -> bool {
        self.is_active() && self.locked(|state| state.desktop.capture_allowed())
    }
}
