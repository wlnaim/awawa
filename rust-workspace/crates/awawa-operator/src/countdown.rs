//! Cuenta regresiva de la vista de espera. El reloj es inyectado (`Duration` monotonica), por lo
//! que la logica es determinista y no depende de egui ni del reloj del sistema.

use std::time::Duration;

/// Plazo que anuncia el host para aprobar localmente. Al llegar a cero el host rechaza por defecto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Countdown {
    started_at: Duration,
    total: Duration,
}

impl Countdown {
    pub fn start(now: Duration, timeout_secs: u16) -> Self {
        Self {
            started_at: now,
            total: Duration::from_secs(u64::from(timeout_secs)),
        }
    }

    pub fn remaining(&self, now: Duration) -> Duration {
        let elapsed = now.saturating_sub(self.started_at);
        self.total.saturating_sub(elapsed)
    }

    /// Segundos restantes redondeados hacia arriba (59.2 s se muestra como 60).
    pub fn remaining_secs(&self, now: Duration) -> u64 {
        let rem = self.remaining(now);
        rem.as_secs() + u64::from(rem.subsec_nanos() > 0)
    }

    pub fn is_expired(&self, now: Duration) -> bool {
        self.remaining(now).is_zero()
    }

    /// Fraccion restante `0.0..=1.0` para la barra de progreso.
    pub fn fraction_left(&self, now: Duration) -> f32 {
        if self.total.is_zero() {
            return 0.0;
        }
        (self.remaining(now).as_secs_f32() / self.total.as_secs_f32()).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn counts_down_from_the_start_instant() {
        let c = Countdown::start(ms(5_000), 60);
        assert_eq!(c.remaining_secs(ms(5_000)), 60);
        assert_eq!(c.remaining_secs(ms(5_001)), 60);
        assert_eq!(c.remaining_secs(ms(6_000)), 59);
        assert_eq!(c.remaining_secs(ms(64_999)), 1);
        assert!(!c.is_expired(ms(64_999)));
    }

    #[test]
    fn expires_exactly_at_the_deadline_and_stays_expired() {
        let c = Countdown::start(ms(0), 60);
        assert!(c.is_expired(ms(60_000)));
        assert!(c.is_expired(ms(1_000_000)));
        assert_eq!(c.remaining_secs(ms(1_000_000)), 0);
    }

    #[test]
    fn clock_before_start_does_not_underflow() {
        let c = Countdown::start(ms(10_000), 30);
        assert_eq!(c.remaining_secs(ms(0)), 30);
    }

    #[test]
    fn zero_timeout_is_expired_immediately() {
        let c = Countdown::start(ms(0), 0);
        assert!(c.is_expired(ms(0)));
        assert_eq!(c.fraction_left(ms(0)), 0.0);
    }

    #[test]
    fn fraction_goes_from_one_to_zero() {
        let c = Countdown::start(ms(0), 10);
        assert_eq!(c.fraction_left(ms(0)), 1.0);
        assert!((c.fraction_left(ms(5_000)) - 0.5).abs() < 1e-6);
        assert_eq!(c.fraction_left(ms(10_000)), 0.0);
    }
}
