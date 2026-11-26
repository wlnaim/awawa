use std::collections::BTreeSet;

use crate::messages::{ButtonState, KeyState, MouseButton, RemoteInputCommand};

/// Rastreador de estado de periféricos (*Dead-Man Switch*).
/// Garantiza que si la sesión cae abruptamente o el usuario local revoca el acceso,
/// se sinteticen eventos `Released`/`Up` para todas las teclas modificadoras y botones activos.
#[derive(Debug, Default)]
pub struct ActiveInputTracker {
    pressed_scancodes: BTreeSet<(u16, bool)>,
    pressed_buttons: BTreeSet<u8>,
}

impl ActiveInputTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_event(&mut self, cmd: &RemoteInputCommand) {
        match cmd {
            RemoteInputCommand::Keyboard {
                scancode,
                extended,
                unicode_char: None,
                state,
            } => match state {
                KeyState::Down => {
                    self.pressed_scancodes.insert((*scancode, *extended));
                }
                KeyState::Up => {
                    self.pressed_scancodes.remove(&(*scancode, *extended));
                }
            },
            RemoteInputCommand::MouseButton { button, state, .. } => {
                let code = Self::button_id(*button);
                match state {
                    ButtonState::Pressed => {
                        self.pressed_buttons.insert(code);
                    }
                    ButtonState::Released => {
                        self.pressed_buttons.remove(&code);
                    }
                }
            }
            _ => {}
        }
    }

    /// Drena todos los periféricos presionados generando la secuencia exacta de comandos de liberación.
    pub fn drain_release_commands(&mut self) -> Vec<RemoteInputCommand> {
        let mut releases = Vec::new();

        for code in core::mem::take(&mut self.pressed_buttons) {
            releases.push(RemoteInputCommand::MouseButton {
                button: Self::id_to_button(code),
                state: ButtonState::Released,
                target_x: 0,
                target_y: 0,
            });
        }

        for (scancode, extended) in core::mem::take(&mut self.pressed_scancodes) {
            releases.push(RemoteInputCommand::Keyboard {
                scancode,
                extended,
                unicode_char: None,
                state: KeyState::Up,
            });
        }

        releases
    }

    pub fn has_active_inputs(&self) -> bool {
        !self.pressed_scancodes.is_empty() || !self.pressed_buttons.is_empty()
    }

    fn button_id(b: MouseButton) -> u8 {
        match b {
            MouseButton::Left => 1,
            MouseButton::Right => 2,
            MouseButton::Middle => 3,
            MouseButton::X1 => 4,
            MouseButton::X2 => 5,
        }
    }

    fn id_to_button(id: u8) -> MouseButton {
        match id {
            1 => MouseButton::Left,
            2 => MouseButton::Right,
            3 => MouseButton::Middle,
            4 => MouseButton::X1,
            _ => MouseButton::X2,
        }
    }
}
