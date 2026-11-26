//! Cronometro de la sesion activa mostrado en el banner (logica pura, reloj inyectable).

use std::time::{Duration, Instant};

/// Formatea una duracion como `MM:SS`, o `H:MM:SS` desde la primera hora.
pub fn format_elapsed(elapsed: Duration) -> String {
    let total = elapsed.as_secs();
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionClock {
    started_at: Instant,
}

impl SessionClock {
    pub fn start(started_at: Instant) -> Self {
        Self { started_at }
    }

    pub fn label(&self, now: Instant) -> String {
        format_elapsed(now.saturating_duration_since(self.started_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_minutes_seconds_and_hours() {
        assert_eq!(format_elapsed(Duration::ZERO), "00:00");
        assert_eq!(format_elapsed(Duration::from_millis(59_999)), "00:59");
        assert_eq!(format_elapsed(Duration::from_secs(61)), "01:01");
        assert_eq!(format_elapsed(Duration::from_secs(3599)), "59:59");
        assert_eq!(format_elapsed(Duration::from_secs(3600)), "1:00:00");
        assert_eq!(
            format_elapsed(Duration::from_secs(36_000 + 125)),
            "10:02:05"
        );
    }

    #[test]
    fn clock_counts_from_its_start_and_never_goes_negative() {
        let t0 = Instant::now();
        let clock = SessionClock::start(t0 + Duration::from_secs(10));
        assert_eq!(clock.label(t0), "00:00");
        assert_eq!(clock.label(t0 + Duration::from_secs(75)), "01:05");
    }
}
