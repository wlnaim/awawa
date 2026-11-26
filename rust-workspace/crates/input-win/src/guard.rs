//! `ProtectedWindowGuard`: impide clics sintéticos sobre la UI propia del host (banner, botón de revocar).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::UI::WindowsAndMessaging::{
    GA_ROOT, GetAncestor, GetCursorPos, WindowFromPoint,
};

/// Margen alrededor de la ventana protegida donde también se bloquea el clic.
pub const PROTECTED_MARGIN_PX: i32 = 8;

/// Desplazamientos de las sondas alrededor del punto: cubre el margen en las 8 direcciones y el interior.
const PROBE_OFFSETS: [i32; 5] = [
    -PROTECTED_MARGIN_PX,
    -PROTECTED_MARGIN_PX / 2,
    0,
    PROTECTED_MARGIN_PX / 2,
    PROTECTED_MARGIN_PX,
];

/// Origen de las consultas de ventana; permite probar la guardia sin ventanas reales.
pub trait WindowProbe {
    /// Identificador (`HWND` como entero) de la ventana de primer nivel bajo `(x, y)`, si existe.
    fn root_window_at(&self, x: i32, y: i32) -> Option<isize>;
    /// Posición actual del cursor físico, si se puede leer.
    fn cursor_position(&self) -> Option<(i32, i32)>;
}

/// Sonda real basada en `WindowFromPoint` + `GetAncestor(GA_ROOT)` y `GetCursorPos`.
/// Requiere que el proceso sea DPI-aware (el manifiesto del host usa `PerMonitorV2`) para trabajar en píxeles físicos.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemWindowProbe;

impl WindowProbe for SystemWindowProbe {
    fn root_window_at(&self, x: i32, y: i32) -> Option<isize> {
        // SAFETY: llamadas Win32 sin precondiciones de puntero; un HWND nulo indica "sin ventana".
        let hwnd = unsafe { WindowFromPoint(POINT { x, y }) };
        if hwnd.0.is_null() {
            return None;
        }
        // SAFETY: `hwnd` acaba de devolverlo el sistema; si ya no es válido, GetAncestor devuelve nulo.
        let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
        let chosen = if root.0.is_null() { hwnd } else { root };
        Some(chosen.0 as isize)
    }

    fn cursor_position(&self) -> Option<(i32, i32)> {
        let mut pt = POINT::default();
        // SAFETY: `pt` es un POINT válido y exclusivo durante la llamada.
        unsafe { GetCursorPos(&mut pt) }.ok()?;
        Some((pt.x, pt.y))
    }
}

/// Registro compartido (clonable) de las ventanas de primer nivel de la UI del host.
/// La UI registra sus `HWND`; el inyector consulta la misma lista desde otro hilo.
#[derive(Debug, Clone, Default)]
pub struct ProtectedWindowGuard {
    windows: Arc<Mutex<BTreeSet<isize>>>,
}

impl ProtectedWindowGuard {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeSet<isize>> {
        self.windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Registra una ventana de primer nivel de la UI del host.
    pub fn register(&self, hwnd: HWND) {
        self.register_raw(hwnd.0 as isize);
    }

    pub fn unregister(&self, hwnd: HWND) {
        self.lock().remove(&(hwnd.0 as isize));
    }

    pub fn register_raw(&self, hwnd: isize) {
        self.lock().insert(hwnd);
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    pub fn registered_count(&self) -> usize {
        self.lock().len()
    }

    /// `true` si alguna ventana registrada está bajo `(x, y)` o a menos de `PROTECTED_MARGIN_PX` de él.
    pub fn is_point_protected<P: WindowProbe>(&self, probe: &P, x: i32, y: i32) -> bool {
        let registered = self.lock();
        if registered.is_empty() {
            return false;
        }
        for dy in PROBE_OFFSETS {
            for dx in PROBE_OFFSETS {
                if let Some(hwnd) = probe.root_window_at(x.saturating_add(dx), y.saturating_add(dy))
                    && registered.contains(&hwnd)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Un clic se bloquea si el punto indicado por el operador o la posición real del cursor caen sobre la UI protegida.
    pub fn blocks_click<P: WindowProbe>(&self, probe: &P, target_x: i32, target_y: i32) -> bool {
        self.is_point_protected(probe, target_x, target_y)
            || probe
                .cursor_position()
                .is_some_and(|(x, y)| self.is_point_protected(probe, x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una ventana rectangular `(hwnd, left, top, right, bottom)` sobre un fondo de otra ventana (hwnd 1).
    struct FakeProbe {
        window: (isize, i32, i32, i32, i32),
        cursor: Option<(i32, i32)>,
    }

    impl WindowProbe for FakeProbe {
        fn root_window_at(&self, x: i32, y: i32) -> Option<isize> {
            let (h, l, t, r, b) = self.window;
            if x >= l && x < r && y >= t && y < b {
                Some(h)
            } else {
                Some(1)
            }
        }

        fn cursor_position(&self) -> Option<(i32, i32)> {
            self.cursor
        }
    }

    fn probe(cursor: Option<(i32, i32)>) -> FakeProbe {
        FakeProbe {
            window: (42, 100, 100, 300, 200),
            cursor,
        }
    }

    #[test]
    fn unregistered_windows_never_block() {
        let guard = ProtectedWindowGuard::new();
        assert!(!guard.blocks_click(&probe(None), 150, 150));
    }

    #[test]
    fn click_inside_registered_window_is_blocked() {
        let guard = ProtectedWindowGuard::new();
        guard.register_raw(42);
        assert!(guard.blocks_click(&probe(None), 150, 150));
    }

    #[test]
    fn click_within_margin_is_blocked_and_beyond_margin_is_not() {
        let guard = ProtectedWindowGuard::new();
        guard.register_raw(42);
        let p = probe(None);
        // A 8 px del borde izquierdo (x=100) y a 8 px del último píxel derecho (299): bloqueado; más allá: permitido.
        assert!(guard.is_point_protected(&p, 92, 150));
        assert!(guard.is_point_protected(&p, 307, 207));
        assert!(!guard.is_point_protected(&p, 308, 208));
        assert!(!guard.is_point_protected(&p, 80, 150));
        assert!(!guard.is_point_protected(&p, 500, 500));
    }

    #[test]
    fn real_cursor_position_is_checked_even_if_target_points_elsewhere() {
        let guard = ProtectedWindowGuard::new();
        guard.register_raw(42);
        assert!(guard.blocks_click(&probe(Some((150, 150))), 900, 900));
        assert!(!guard.blocks_click(&probe(Some((900, 900))), 900, 900));
    }

    #[test]
    fn clones_share_registrations_and_unregister_clears() {
        let guard = ProtectedWindowGuard::new();
        let shared = guard.clone();
        shared.register_raw(42);
        assert_eq!(guard.registered_count(), 1);
        assert!(guard.blocks_click(&probe(None), 150, 150));
        guard.clear();
        assert!(!shared.blocks_click(&probe(None), 150, 150));
    }
}
