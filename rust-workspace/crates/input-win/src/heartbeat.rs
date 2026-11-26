//! Dead-man switch por heartbeat: si pasan 3 s sin `Ping` del operador se deben liberar teclas y botones.
//! El reloj se inyecta (`Instant` explícito) para pruebas deterministas.

use std::time::{Duration, Instant};

/// Tiempo máximo sin `Ping` antes de liberar todo.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct HeartbeatDeadMan {
    timeout: Duration,
    last_ping: Instant,
    expired: bool,
}

impl HeartbeatDeadMan {
    pub fn new(now: Instant) -> Self {
        Self::with_timeout(now, HEARTBEAT_TIMEOUT)
    }

    pub fn with_timeout(now: Instant, timeout: Duration) -> Self {
        Self {
            timeout,
            last_ping: now,
            expired: false,
        }
    }

    /// Registra un `Ping` recibido; reanuda el vigilante si había expirado.
    pub fn record_ping(&mut self, now: Instant) {
        self.last_ping = now;
        self.expired = false;
    }

    /// Devuelve `true` una sola vez, en el instante en que el silencio alcanza el límite.
    pub fn poll_expired(&mut self, now: Instant) -> bool {
        if !self.expired && now.saturating_duration_since(self.last_ping) >= self.timeout {
            self.expired = true;
            return true;
        }
        false
    }

    /// `true` mientras no llegue un nuevo `Ping` tras expirar.
    pub fn is_expired(&self) -> bool {
        self.expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_exactly_once_after_three_seconds_without_ping() {
        let t0 = Instant::now();
        let mut hb = HeartbeatDeadMan::new(t0);
        assert!(!hb.poll_expired(t0 + Duration::from_millis(2_999)));
        assert!(!hb.is_expired());
        assert!(hb.poll_expired(t0 + Duration::from_secs(3)));
        assert!(hb.is_expired());
        assert!(!hb.poll_expired(t0 + Duration::from_secs(10)));
        assert!(hb.is_expired());
    }

    #[test]
    fn ping_postpones_expiry_and_resumes_after_expiry() {
        let t0 = Instant::now();
        let mut hb = HeartbeatDeadMan::new(t0);
        hb.record_ping(t0 + Duration::from_secs(2));
        assert!(!hb.poll_expired(t0 + Duration::from_secs(4)));
        assert!(hb.poll_expired(t0 + Duration::from_secs(5)));
        hb.record_ping(t0 + Duration::from_secs(6));
        assert!(!hb.is_expired());
        assert!(hb.poll_expired(t0 + Duration::from_secs(9)));
    }
}
