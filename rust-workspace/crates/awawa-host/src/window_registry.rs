//! Sincroniza las ventanas de primer nivel de la UI del host con `ProtectedWindowGuard`.
//!
//! La UI registra TODAS las ventanas que existen en su hilo (principal, modal, banner y cualquier
//! popup o viewport que aparezca despues), no una lista fija: cada ciclo se compara la lista
//! actual con la ya registrada, se registran las nuevas y se retiran las que desaparecieron.

use std::collections::BTreeSet;
use std::ffi::c_void;

use input_win::ProtectedWindowGuard;
use windows::Win32::Foundation::HWND;

#[derive(Debug, Default)]
pub struct WindowRegistry {
    known: BTreeSet<isize>,
}

impl WindowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registra en `guard` las ventanas de `current` que aun no lo estaban y retira las que ya no
    /// existen. Devuelve `true` si el conjunto cambio.
    pub fn sync(&mut self, current: &[isize], guard: &ProtectedWindowGuard) -> bool {
        let now: BTreeSet<isize> = current.iter().copied().filter(|h| *h != 0).collect();
        let mut changed = false;
        for hwnd in now.difference(&self.known) {
            guard.register_raw(*hwnd);
            changed = true;
        }
        for hwnd in self.known.difference(&now) {
            guard.unregister(HWND(*hwnd as *mut c_void));
            changed = true;
        }
        self.known = now;
        changed
    }

    /// Retira todas las ventanas (cierre de la aplicacion).
    pub fn clear(&mut self, guard: &ProtectedWindowGuard) {
        self.sync(&[], guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use input_win::WindowProbe;

    /// Sonda falsa: la ventana `window` ocupa (100,100)-(300,200); el resto es la ventana 1.
    struct FakeProbe {
        window: isize,
    }

    impl WindowProbe for FakeProbe {
        fn root_window_at(&self, x: i32, y: i32) -> Option<isize> {
            if (100..300).contains(&x) && (100..200).contains(&y) {
                Some(self.window)
            } else {
                Some(1)
            }
        }

        fn cursor_position(&self) -> Option<(i32, i32)> {
            None
        }
    }

    #[test]
    fn new_windows_are_registered_including_popups_that_appear_later() {
        let guard = ProtectedWindowGuard::new();
        let mut registry = WindowRegistry::new();
        assert!(registry.sync(&[10, 20], &guard));
        assert_eq!(guard.registered_count(), 2);
        // Aparece un popup/viewport nuevo: tambien queda protegido.
        assert!(registry.sync(&[10, 20, 30], &guard));
        assert_eq!(guard.registered_count(), 3);
        assert!(guard.blocks_click(&FakeProbe { window: 30 }, 150, 150));
    }

    #[test]
    fn unchanged_sets_report_no_change() {
        let guard = ProtectedWindowGuard::new();
        let mut registry = WindowRegistry::new();
        registry.sync(&[10, 20], &guard);
        assert!(!registry.sync(&[20, 10], &guard));
        assert_eq!(guard.registered_count(), 2);
    }

    #[test]
    fn vanished_windows_are_unregistered_and_stop_blocking() {
        let guard = ProtectedWindowGuard::new();
        let mut registry = WindowRegistry::new();
        registry.sync(&[10, 30], &guard);
        assert!(registry.sync(&[10], &guard));
        assert_eq!(guard.registered_count(), 1);
        assert!(!guard.blocks_click(&FakeProbe { window: 30 }, 150, 150));
    }

    #[test]
    fn null_handles_are_ignored_and_clear_empties_the_guard() {
        let guard = ProtectedWindowGuard::new();
        let mut registry = WindowRegistry::new();
        registry.sync(&[0, 10], &guard);
        assert_eq!(guard.registered_count(), 1);
        registry.clear(&guard);
        assert_eq!(guard.registered_count(), 0);
    }
}
