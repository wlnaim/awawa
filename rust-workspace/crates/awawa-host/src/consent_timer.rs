//! Temporizadores del modal de consentimiento local (logica pura, reloj inyectable).
//!
//! El modal se muestra en el instante `shown_at`, el mismo `Instant` con el que nace el
//! `PendingLocalConsent` (`prompt_displayed_at`). Desde ahi:
//! - durante `ANTI_CLICKJACK_GRACE_PERIOD` (1 500 ms) el boton Aceptar esta inhabilitado;
//! - al llegar a `LOCAL_CONSENT_TIMEOUT` (60 s) la solicitud se rechaza por defecto.
//!
//! La inhabilitacion de Aceptar se ancla al primer cuadro en que el modal se pinta
//! (`painted`); mientras no se haya pintado, Aceptar sigue inhabilitado. Los 60 s cuentan desde
//! `shown_at`.
//!
//! Los plazos se importan de `awawa-protocol`: la FSM sigue siendo la autoridad final
//! (`approve_locally` los vuelve a validar); aqui solo se decide que mostrar y cuando rechazar.

use std::time::{Duration, Instant};

use awawa_protocol::consent_fsm::{ANTI_CLICKJACK_GRACE_PERIOD, LOCAL_CONSENT_TIMEOUT};

/// Fase del modal en un instante dado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalPhase {
    /// Aceptar inhabilitado: falta `remaining` para que se habilite.
    Locked { remaining: Duration },
    /// Aceptar habilitado.
    Ready,
    /// Se agoto el tiempo: se rechaza por defecto.
    Expired,
}

/// Que puede hacer el usuario con el boton Aceptar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptAvailability {
    /// Inhabilitado por la ventana anti-clickjacking.
    LockedByGracePeriod,
    /// Inhabilitado porque el atajo global de revocacion no quedo armado.
    KillSwitchUnavailable,
    Enabled,
    /// El plazo vencio: la solicitud ya no se puede aceptar.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentModalTimer {
    shown_at: Instant,
    first_painted_at: Option<Instant>,
}

impl ConsentModalTimer {
    pub fn new(shown_at: Instant) -> Self {
        Self {
            shown_at,
            first_painted_at: None,
        }
    }

    /// Registra el primer cuadro en que el modal se pinto (las llamadas siguientes no lo cambian).
    pub fn painted(mut self, now: Instant) -> Self {
        self.first_painted_at.get_or_insert(now);
        self
    }

    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.shown_at)
    }

    pub fn phase(&self, now: Instant) -> ModalPhase {
        if self.elapsed(now) >= LOCAL_CONSENT_TIMEOUT {
            return ModalPhase::Expired;
        }
        let since_paint = match self.first_painted_at {
            Some(at) => now.saturating_duration_since(at),
            None => Duration::ZERO,
        };
        if since_paint < ANTI_CLICKJACK_GRACE_PERIOD {
            ModalPhase::Locked {
                remaining: ANTI_CLICKJACK_GRACE_PERIOD - since_paint,
            }
        } else {
            ModalPhase::Ready
        }
    }

    /// `true` cuando corresponde rechazar por defecto (60 s sin decision).
    pub fn is_expired(&self, now: Instant) -> bool {
        self.phase(now) == ModalPhase::Expired
    }

    /// Segundos enteros restantes de la cuenta regresiva (redondeo hacia arriba; 60 al inicio, 0 al vencer).
    pub fn seconds_left(&self, now: Instant) -> u64 {
        let left = LOCAL_CONSENT_TIMEOUT.saturating_sub(self.elapsed(now));
        left.as_millis().div_ceil(1000) as u64
    }

    /// Disponibilidad del boton Aceptar. Aceptar exige ademas que el atajo global de revocacion este armado.
    pub fn accept_availability(&self, now: Instant, kill_switch_armed: bool) -> AcceptAvailability {
        match self.phase(now) {
            ModalPhase::Expired => AcceptAvailability::Expired,
            ModalPhase::Locked { .. } => AcceptAvailability::LockedByGracePeriod,
            ModalPhase::Ready if !kill_switch_armed => AcceptAvailability::KillSwitchUnavailable,
            ModalPhase::Ready => AcceptAvailability::Enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn accept_is_locked_for_exactly_1500_ms() {
        let t0 = Instant::now();
        let timer = ConsentModalTimer::new(t0).painted(t0);
        assert_eq!(
            timer.phase(t0),
            ModalPhase::Locked {
                remaining: ms(1500)
            }
        );
        assert_eq!(
            timer.phase(t0 + ms(1499)),
            ModalPhase::Locked { remaining: ms(1) }
        );
        assert_eq!(timer.phase(t0 + ms(1500)), ModalPhase::Ready);
        assert_eq!(
            timer.accept_availability(t0 + ms(1499), true),
            AcceptAvailability::LockedByGracePeriod
        );
        assert_eq!(
            timer.accept_availability(t0 + ms(1500), true),
            AcceptAvailability::Enabled
        );
    }

    #[test]
    fn modal_expires_at_60_seconds_and_defaults_to_reject() {
        let t0 = Instant::now();
        let timer = ConsentModalTimer::new(t0).painted(t0);
        assert!(!timer.is_expired(t0 + ms(59_999)));
        assert!(timer.is_expired(t0 + ms(60_000)));
        assert_eq!(
            timer.accept_availability(t0 + ms(60_000), true),
            AcceptAvailability::Expired
        );
        assert_eq!(timer.phase(t0 + ms(59_999)), ModalPhase::Ready);
    }

    #[test]
    fn countdown_rounds_up_and_ends_at_zero() {
        let t0 = Instant::now();
        let timer = ConsentModalTimer::new(t0).painted(t0);
        assert_eq!(timer.seconds_left(t0), 60);
        assert_eq!(timer.seconds_left(t0 + ms(1)), 60);
        assert_eq!(timer.seconds_left(t0 + ms(1000)), 59);
        assert_eq!(timer.seconds_left(t0 + ms(59_001)), 1);
        assert_eq!(timer.seconds_left(t0 + ms(60_000)), 0);
        assert_eq!(timer.seconds_left(t0 + ms(90_000)), 0);
    }

    #[test]
    fn accept_requires_an_armed_kill_switch() {
        let t0 = Instant::now();
        let timer = ConsentModalTimer::new(t0).painted(t0);
        assert_eq!(
            timer.accept_availability(t0 + ms(2000), false),
            AcceptAvailability::KillSwitchUnavailable
        );
        // Sin atajo, el bloqueo de gracia y el vencimiento siguen mandando.
        assert_eq!(
            timer.accept_availability(t0 + ms(100), false),
            AcceptAvailability::LockedByGracePeriod
        );
        assert_eq!(
            timer.accept_availability(t0 + ms(61_000), false),
            AcceptAvailability::Expired
        );
    }

    #[test]
    fn clock_going_backwards_is_treated_as_just_shown() {
        let t0 = Instant::now();
        let timer = ConsentModalTimer::new(t0 + ms(500)).painted(t0 + ms(500));
        assert_eq!(
            timer.phase(t0),
            ModalPhase::Locked {
                remaining: ms(1500)
            }
        );
    }

    #[test]
    fn lock_is_anchored_to_the_first_painted_frame() {
        let t0 = Instant::now();
        let unpainted = ConsentModalTimer::new(t0);
        // Sin pintar, Aceptar sigue bloqueado aunque pase el tiempo.
        assert_eq!(
            unpainted.accept_availability(t0 + ms(10_000), true),
            AcceptAvailability::LockedByGracePeriod
        );
        let timer = unpainted.painted(t0 + ms(4000)).painted(t0 + ms(9000));
        assert_eq!(
            timer.accept_availability(t0 + ms(5499), true),
            AcceptAvailability::LockedByGracePeriod
        );
        assert_eq!(
            timer.accept_availability(t0 + ms(5500), true),
            AcceptAvailability::Enabled
        );
        // Los 60 s siguen contando desde que se mostro, pintado o no.
        assert!(unpainted.is_expired(t0 + ms(60_000)));
    }
}
