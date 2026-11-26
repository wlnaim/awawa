//! Limite de tasa por IP de origen con `governor` y reloj inyectable.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::Instant;

use governor::clock::Clock;
#[cfg(any(test, feature = "test-support"))]
use governor::clock::FakeRelativeClock;
use governor::middleware::NoOpMiddleware;
use governor::nanos::Nanos;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

/// Reloj del limitador: el del sistema en produccion, o uno manual en pruebas (feature `test-support`).
#[derive(Clone, Debug)]
pub enum RelayClock {
    System {
        start: Instant,
    },
    #[cfg(any(test, feature = "test-support"))]
    Manual(FakeRelativeClock),
}

impl RelayClock {
    pub fn system() -> Self {
        Self::System {
            start: Instant::now(),
        }
    }

    /// Reloj manual (comienza en 0); avanza con `FakeRelativeClock::advance`. Los clones comparten hora.
    #[cfg(any(test, feature = "test-support"))]
    pub fn manual(clock: FakeRelativeClock) -> Self {
        Self::Manual(clock)
    }
}

impl Clock for RelayClock {
    type Instant = Nanos;

    fn now(&self) -> Nanos {
        match self {
            Self::System { start } => start.elapsed().into(),
            #[cfg(any(test, feature = "test-support"))]
            Self::Manual(clock) => clock.now(),
        }
    }
}

/// Clave de limitacion: IPv4 tal cual, IPv4 mapeada en IPv6 como IPv4 y el resto de IPv6 por /64
/// (un atacante controla normalmente un prefijo completo, no una sola direccion).
pub(crate) fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

pub(crate) struct IpLimiter {
    inner: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, RelayClock, NoOpMiddleware<Nanos>>,
}

impl IpLimiter {
    /// `per_minute` intentos por minuto y por origen (rafaga igual a `per_minute`).
    pub(crate) fn per_minute(per_minute: NonZeroU32, clock: RelayClock) -> Self {
        Self {
            inner: RateLimiter::dashmap_with_clock(Quota::per_minute(per_minute), clock),
        }
    }

    /// Cuenta un intento de `ip`; `false` si excede el limite.
    pub(crate) fn check(&self, ip: IpAddr) -> bool {
        self.inner.check_key(&limiter_key(ip)).is_ok()
    }

    /// Libera el estado de los origenes que ya recuperaron todo su cupo.
    pub(crate) fn prune(&self) {
        self.inner.retain_recent();
        self.inner.shrink_to_fit();
    }

    #[cfg(test)]
    pub(crate) fn tracked_keys(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn limiter(clock: &FakeRelativeClock) -> IpLimiter {
        IpLimiter::per_minute(
            NonZeroU32::new(5).unwrap(),
            RelayClock::manual(clock.clone()),
        )
    }

    #[test]
    fn sixth_attempt_within_a_minute_is_rejected() {
        let clock = FakeRelativeClock::default();
        let l = limiter(&clock);
        for n in 1..=5 {
            assert!(l.check(ip(1)), "intento {n} debe pasar");
        }
        assert!(!l.check(ip(1)), "el sexto debe rechazarse");
        assert!(!l.check(ip(1)));
    }

    #[test]
    fn other_origins_are_independent() {
        let clock = FakeRelativeClock::default();
        let l = limiter(&clock);
        for _ in 0..5 {
            assert!(l.check(ip(1)));
        }
        assert!(!l.check(ip(1)));
        assert!(l.check(ip(2)));
    }

    #[test]
    fn quota_refills_over_time() {
        let clock = FakeRelativeClock::default();
        let l = limiter(&clock);
        for _ in 0..5 {
            assert!(l.check(ip(1)));
        }
        assert!(!l.check(ip(1)));
        clock.advance(Duration::from_secs(11));
        assert!(!l.check(ip(1)), "una celda cada 12 s");
        clock.advance(Duration::from_secs(1));
        assert!(l.check(ip(1)));
        assert!(!l.check(ip(1)));
        clock.advance(Duration::from_secs(60));
        for _ in 0..5 {
            assert!(l.check(ip(1)));
        }
        assert!(!l.check(ip(1)));
    }

    #[test]
    fn ipv6_is_limited_per_prefix_64_and_mapped_v4_equals_v4() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limiter_key(a), limiter_key(b));
        assert_ne!(limiter_key(a), limiter_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(limiter_key(mapped), ip(1));
    }

    #[test]
    fn prune_drops_recovered_origins() {
        let clock = FakeRelativeClock::default();
        let l = limiter(&clock);
        assert!(l.check(ip(1)));
        assert_eq!(l.tracked_keys(), 1);
        clock.advance(Duration::from_secs(120));
        l.prune();
        assert_eq!(l.tracked_keys(), 0);
    }
}
