//! Calculo de FPS y RTT para la barra del visor. Reloj inyectado, sin dependencias de egui.

use std::collections::VecDeque;
use std::time::Duration;

/// Ventana sobre la que se promedian los fotogramas por segundo.
pub const FPS_WINDOW: Duration = Duration::from_secs(1);

/// FPS = fotogramas recibidos dentro de la ultima ventana.
#[derive(Debug, Default)]
pub struct FpsMeter {
    stamps: VecDeque<Duration>,
}

impl FpsMeter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_frame(&mut self, now: Duration) {
        self.stamps.push_back(now);
        self.evict(now);
    }

    fn evict(&mut self, now: Duration) {
        while let Some(&front) = self.stamps.front() {
            if now.saturating_sub(front) >= FPS_WINDOW {
                self.stamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Fotogramas por segundo en la ventana que termina en `now`.
    pub fn fps(&mut self, now: Duration) -> u32 {
        self.evict(now);
        u32::try_from(self.stamps.len()).unwrap_or(u32::MAX)
    }

    pub fn reset(&mut self) {
        self.stamps.clear();
    }
}

/// Factor de suavizado exponencial del RTT mostrado (1/4 de la muestra nueva).
const RTT_SMOOTHING_DIV: u128 = 4;

/// RTT suavizado (media movil exponencial) a partir de las muestras que reporta el transporte.
#[derive(Debug, Default)]
pub struct RttTracker {
    smoothed_us: Option<u128>,
}

impl RttTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, sample: Duration) {
        let sample_us = sample.as_micros();
        self.smoothed_us = Some(match self.smoothed_us {
            None => sample_us,
            Some(prev) => {
                (prev * (RTT_SMOOTHING_DIV - 1) + sample_us + RTT_SMOOTHING_DIV / 2)
                    / RTT_SMOOTHING_DIV
            }
        });
    }

    /// RTT en milisegundos redondeados, o `None` si aun no hay muestras.
    pub fn millis(&self) -> Option<u32> {
        self.smoothed_us
            .map(|us| u32::try_from((us + 500) / 1_000).unwrap_or(u32::MAX))
    }

    pub fn reset(&mut self) {
        self.smoothed_us = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn fps_counts_frames_in_the_last_second() {
        let mut m = FpsMeter::new();
        for i in 0..30 {
            m.record_frame(ms(i * 33));
        }
        assert_eq!(m.fps(ms(990)), 30);
    }

    #[test]
    fn fps_drops_old_frames_and_reaches_zero() {
        let mut m = FpsMeter::new();
        m.record_frame(ms(0));
        m.record_frame(ms(500));
        assert_eq!(m.fps(ms(999)), 2);
        assert_eq!(m.fps(ms(1_000)), 1);
        assert_eq!(m.fps(ms(1_500)), 0);
    }

    #[test]
    fn fps_reset_clears_history() {
        let mut m = FpsMeter::new();
        m.record_frame(ms(0));
        m.reset();
        assert_eq!(m.fps(ms(1)), 0);
    }

    #[test]
    fn rtt_is_none_until_first_sample() {
        let t = RttTracker::new();
        assert_eq!(t.millis(), None);
    }

    #[test]
    fn rtt_first_sample_is_taken_as_is_then_smoothed() {
        let mut t = RttTracker::new();
        t.record(ms(40));
        assert_eq!(t.millis(), Some(40));
        t.record(ms(80));
        // (40 * 3 + 80) / 4 = 50
        assert_eq!(t.millis(), Some(50));
    }

    #[test]
    fn rtt_reset_forgets_samples() {
        let mut t = RttTracker::new();
        t.record(ms(10));
        t.reset();
        assert_eq!(t.millis(), None);
    }

    #[test]
    fn rtt_rounds_sub_millisecond_samples() {
        let mut t = RttTracker::new();
        t.record(Duration::from_micros(1_600));
        assert_eq!(t.millis(), Some(2));
    }
}
