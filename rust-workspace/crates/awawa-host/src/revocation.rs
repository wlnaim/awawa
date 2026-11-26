//! Decision de revocacion del kill-switch (logica pura).
//!
//! Con una sesion activa, cualquiera de estas senales revoca el control de inmediato:
//! boton **Revocar control ahora**, atajo global, intento de cerrar o minimizar el banner
//! (SC_CLOSE / SC_MINIMIZE, p. ej. Alt+F4), cierre de la ventana principal o desconexion
//! del operador. No existe ninguna senal que el banner ignore: ante la duda, se revoca.

/// Origen de una revocacion; define el motivo registrado en `SessionRevocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationTrigger {
    Button,
    Hotkey,
    BannerCloseRequested,
    BannerMinimized,
    MainWindowClosed,
    OperatorDisconnected,
}

impl RevocationTrigger {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Button => "Revocado por el usuario local (boton)",
            Self::Hotkey => "Revocado por el usuario local (atajo global)",
            Self::BannerCloseRequested => "Revocado: intento de cerrar el banner",
            Self::BannerMinimized => "Revocado: intento de minimizar el banner",
            Self::MainWindowClosed => "Revocado: cierre de la aplicacion",
            Self::OperatorDisconnected => "Operador desconectado",
        }
    }
}

/// Senales observadas en un ciclo de la UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RevocationSignals {
    pub button_clicked: bool,
    pub hotkey_pressed: bool,
    pub banner_close_requested: bool,
    pub banner_minimized: bool,
}

impl RevocationSignals {
    /// Motivo de revocacion si hay alguna senal activa. Prioridad: acciones explicitas del
    /// usuario local primero, despues intentos sobre el banner. Cerrar la aplicacion y la
    /// desconexion del operador los resuelve el controlador directamente (`shutdown`, `on_event`).
    pub fn decide(&self) -> Option<RevocationTrigger> {
        if self.button_clicked {
            Some(RevocationTrigger::Button)
        } else if self.hotkey_pressed {
            Some(RevocationTrigger::Hotkey)
        } else if self.banner_close_requested {
            Some(RevocationTrigger::BannerCloseRequested)
        } else if self.banner_minimized {
            Some(RevocationTrigger::BannerMinimized)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_signal_means_no_revocation() {
        assert_eq!(RevocationSignals::default().decide(), None);
    }

    #[test]
    fn every_single_signal_revokes() {
        let cases = [
            (
                RevocationSignals {
                    button_clicked: true,
                    ..Default::default()
                },
                RevocationTrigger::Button,
            ),
            (
                RevocationSignals {
                    hotkey_pressed: true,
                    ..Default::default()
                },
                RevocationTrigger::Hotkey,
            ),
            (
                RevocationSignals {
                    banner_close_requested: true,
                    ..Default::default()
                },
                RevocationTrigger::BannerCloseRequested,
            ),
            (
                RevocationSignals {
                    banner_minimized: true,
                    ..Default::default()
                },
                RevocationTrigger::BannerMinimized,
            ),
        ];
        for (signals, expected) in cases {
            assert_eq!(signals.decide(), Some(expected));
        }
    }

    #[test]
    fn local_user_actions_take_priority_over_environment_events() {
        let all = RevocationSignals {
            button_clicked: true,
            hotkey_pressed: true,
            banner_close_requested: true,
            banner_minimized: true,
        };
        assert_eq!(all.decide(), Some(RevocationTrigger::Button));
        let mut s = all;
        s.button_clicked = false;
        assert_eq!(s.decide(), Some(RevocationTrigger::Hotkey));
        s.hotkey_pressed = false;
        assert_eq!(s.decide(), Some(RevocationTrigger::BannerCloseRequested));
    }

    #[test]
    fn reasons_are_distinct_and_non_empty() {
        let triggers = [
            RevocationTrigger::Button,
            RevocationTrigger::Hotkey,
            RevocationTrigger::BannerCloseRequested,
            RevocationTrigger::BannerMinimized,
            RevocationTrigger::MainWindowClosed,
            RevocationTrigger::OperatorDisconnected,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for t in triggers {
            assert!(!t.reason().is_empty());
            assert!(seen.insert(t.reason()));
        }
    }
}
