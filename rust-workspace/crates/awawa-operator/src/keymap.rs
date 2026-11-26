//! Mapeo de teclas de egui a comandos de teclado remotos.
//!
//! Regla: un comando de teclado usa scancode **o** Unicode, nunca ambos ni ninguno.
//! Si la tecla fisica tiene scancode conocido se envia por scancode; el texto que egui genera
//! para esa misma pulsacion se descarta. El texto sin tecla mapeada (teclas muertas, IME, AltGr)
//! se envia como Unicode con scancode 0.

use awawa_protocol::{KeyState, RemoteInputCommand};
use egui::{Key, Modifiers};

/// Scancode (set 1) y bandera de tecla extendida (`E0`) de una tecla de egui.
pub fn scancode_for(key: Key) -> Option<(u16, bool)> {
    let (code, extended) = match key {
        Key::Escape => (0x01, false),
        Key::Num1 => (0x02, false),
        Key::Num2 => (0x03, false),
        Key::Num3 => (0x04, false),
        Key::Num4 => (0x05, false),
        Key::Num5 => (0x06, false),
        Key::Num6 => (0x07, false),
        Key::Num7 => (0x08, false),
        Key::Num8 => (0x09, false),
        Key::Num9 => (0x0A, false),
        Key::Num0 => (0x0B, false),
        Key::Minus => (0x0C, false),
        Key::Equals => (0x0D, false),
        Key::Backspace => (0x0E, false),
        Key::Tab => (0x0F, false),
        Key::Q => (0x10, false),
        Key::W => (0x11, false),
        Key::E => (0x12, false),
        Key::R => (0x13, false),
        Key::T => (0x14, false),
        Key::Y => (0x15, false),
        Key::U => (0x16, false),
        Key::I => (0x17, false),
        Key::O => (0x18, false),
        Key::P => (0x19, false),
        Key::OpenBracket => (0x1A, false),
        Key::CloseBracket => (0x1B, false),
        Key::Enter => (0x1C, false),
        Key::ControlLeft => (0x1D, false),
        Key::A => (0x1E, false),
        Key::S => (0x1F, false),
        Key::D => (0x20, false),
        Key::F => (0x21, false),
        Key::G => (0x22, false),
        Key::H => (0x23, false),
        Key::J => (0x24, false),
        Key::K => (0x25, false),
        Key::L => (0x26, false),
        Key::Semicolon => (0x27, false),
        Key::Quote => (0x28, false),
        Key::Backtick => (0x29, false),
        Key::ShiftLeft => (0x2A, false),
        Key::Backslash => (0x2B, false),
        Key::Z => (0x2C, false),
        Key::X => (0x2D, false),
        Key::C => (0x2E, false),
        Key::V => (0x2F, false),
        Key::B => (0x30, false),
        Key::N => (0x31, false),
        Key::M => (0x32, false),
        Key::Comma => (0x33, false),
        Key::Period => (0x34, false),
        Key::Slash => (0x35, false),
        Key::ShiftRight => (0x36, false),
        Key::PrintScreen => (0x37, true),
        Key::AltLeft => (0x38, false),
        Key::Space => (0x39, false),
        Key::CapsLock => (0x3A, false),
        Key::F1 => (0x3B, false),
        Key::F2 => (0x3C, false),
        Key::F3 => (0x3D, false),
        Key::F4 => (0x3E, false),
        Key::F5 => (0x3F, false),
        Key::F6 => (0x40, false),
        Key::F7 => (0x41, false),
        Key::F8 => (0x42, false),
        Key::F9 => (0x43, false),
        Key::F10 => (0x44, false),
        Key::NumLock => (0x45, false),
        Key::ScrollLock => (0x46, false),
        Key::IntlBackslash => (0x56, false),
        Key::F11 => (0x57, false),
        Key::F12 => (0x58, false),
        Key::F13 => (0x64, false),
        Key::F14 => (0x65, false),
        Key::F15 => (0x66, false),
        Key::F16 => (0x67, false),
        Key::F17 => (0x68, false),
        Key::F18 => (0x69, false),
        Key::F19 => (0x6A, false),
        Key::F20 => (0x6B, false),
        Key::F21 => (0x6C, false),
        Key::F22 => (0x6D, false),
        Key::F23 => (0x6E, false),
        Key::F24 => (0x76, false),
        Key::ControlRight => (0x1D, true),
        Key::AltRight => (0x38, true),
        Key::Home => (0x47, true),
        Key::ArrowUp => (0x48, true),
        Key::PageUp => (0x49, true),
        Key::ArrowLeft => (0x4B, true),
        Key::ArrowRight => (0x4D, true),
        Key::End => (0x4F, true),
        Key::ArrowDown => (0x50, true),
        Key::PageDown => (0x51, true),
        Key::Insert => (0x52, true),
        Key::Delete => (0x53, true),
        Key::SuperLeft => (0x5B, true),
        Key::SuperRight => (0x5C, true),
        Key::Menu => (0x5D, true),
        _ => return None,
    };
    Some((code, extended))
}

/// Accion de portapapeles local (solo para los campos del formulario; nunca viaja al remoto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardAction {
    Cut,
    Copy,
    Paste,
}

/// Atajo de portapapeles de Windows que corresponde a la tecla y los modificadores:
/// Ctrl+X/C/V, Ctrl+Insert, Shift+Insert y Shift+Supr.
pub fn clipboard_action(key: Key, m: Modifiers) -> Option<ClipboardAction> {
    let ctrl_only = m.ctrl && !m.shift && !m.alt;
    match key {
        Key::X if ctrl_only => Some(ClipboardAction::Cut),
        Key::C if ctrl_only => Some(ClipboardAction::Copy),
        Key::V if ctrl_only => Some(ClipboardAction::Paste),
        Key::Insert if ctrl_only => Some(ClipboardAction::Copy),
        Key::Insert if m.shift && !m.ctrl && !m.alt => Some(ClipboardAction::Paste),
        Key::Delete if m.shift && !m.ctrl && !m.alt => Some(ClipboardAction::Cut),
        _ => None,
    }
}

/// Comando de teclado por scancode fisico (sin Unicode).
pub fn scancode_command(scancode: u16, extended: bool, state: KeyState) -> RemoteInputCommand {
    RemoteInputCommand::Keyboard {
        scancode,
        extended,
        unicode_char: None,
        state,
    }
}

/// Comando de teclado Unicode (scancode 0). Rechaza caracteres de control.
pub fn unicode_command(c: char, state: KeyState) -> Option<RemoteInputCommand> {
    if c.is_control() {
        return None;
    }
    Some(RemoteInputCommand::Keyboard {
        scancode: 0,
        extended: false,
        unicode_char: Some(c),
        state,
    })
}

/// Traduce un evento de tecla: prefiere la tecla fisica y, si no hay, la logica. Devuelve `None`
/// si ninguna tiene scancode.
pub fn translate_key(
    key: Key,
    physical_key: Option<Key>,
    pressed: bool,
) -> Option<RemoteInputCommand> {
    let (code, extended) = physical_key
        .and_then(scancode_for)
        .or_else(|| scancode_for(key))?;
    let state = if pressed {
        KeyState::Down
    } else {
        KeyState::Up
    };
    Some(scancode_command(code, extended, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_chords_map_to_local_actions() {
        let ctrl = Modifiers {
            ctrl: true,
            ..Modifiers::NONE
        };
        let shift = Modifiers {
            shift: true,
            ..Modifiers::NONE
        };
        let ctrl_shift = Modifiers {
            ctrl: true,
            shift: true,
            ..Modifiers::NONE
        };
        assert_eq!(clipboard_action(Key::V, ctrl), Some(ClipboardAction::Paste));
        assert_eq!(clipboard_action(Key::C, ctrl), Some(ClipboardAction::Copy));
        assert_eq!(clipboard_action(Key::X, ctrl), Some(ClipboardAction::Cut));
        assert_eq!(
            clipboard_action(Key::Insert, ctrl),
            Some(ClipboardAction::Copy)
        );
        assert_eq!(
            clipboard_action(Key::Insert, shift),
            Some(ClipboardAction::Paste)
        );
        assert_eq!(
            clipboard_action(Key::Delete, shift),
            Some(ClipboardAction::Cut)
        );
        assert_eq!(clipboard_action(Key::X, ctrl_shift), None);
        assert_eq!(clipboard_action(Key::Delete, ctrl_shift), None);
        assert_eq!(clipboard_action(Key::V, Modifiers::NONE), None);
    }

    #[test]
    fn letters_digits_and_arrows_have_expected_scancodes() {
        assert_eq!(scancode_for(Key::A), Some((0x1E, false)));
        assert_eq!(scancode_for(Key::Q), Some((0x10, false)));
        assert_eq!(scancode_for(Key::Num0), Some((0x0B, false)));
        assert_eq!(scancode_for(Key::Enter), Some((0x1C, false)));
        assert_eq!(scancode_for(Key::ArrowLeft), Some((0x4B, true)));
        assert_eq!(scancode_for(Key::Delete), Some((0x53, true)));
        assert_eq!(scancode_for(Key::ControlRight), Some((0x1D, true)));
        assert_eq!(scancode_for(Key::ControlLeft), Some((0x1D, false)));
    }

    #[test]
    fn keys_without_a_mapping_return_none() {
        assert_eq!(scancode_for(Key::Pause), None);
        assert_eq!(scancode_for(Key::MediaPlayPause), None);
        assert_eq!(scancode_for(Key::Copy), None);
    }

    #[test]
    fn no_mapped_key_yields_scancode_zero() {
        let all = [
            Key::Escape,
            Key::Tab,
            Key::Space,
            Key::Backspace,
            Key::F1,
            Key::F12,
            Key::F24,
            Key::Home,
            Key::End,
            Key::SuperLeft,
            Key::Menu,
            Key::IntlBackslash,
        ];
        for k in all {
            let (code, _) = scancode_for(k).expect("mapeada");
            assert_ne!(code, 0, "{k:?}");
        }
    }

    #[test]
    fn physical_key_wins_over_logical_key() {
        // Distribucion distinta: la tecla logica es Z pero la fisica es Y.
        let cmd = translate_key(Key::Z, Some(Key::Y), true).unwrap();
        assert_eq!(cmd, scancode_command(0x15, false, KeyState::Down));
    }

    #[test]
    fn logical_key_is_used_when_there_is_no_physical_key() {
        let cmd = translate_key(Key::Z, None, false).unwrap();
        assert_eq!(cmd, scancode_command(0x2C, false, KeyState::Up));
    }

    #[test]
    fn unmapped_physical_falls_back_to_mapped_logical_and_none_when_neither() {
        let cmd = translate_key(Key::A, Some(Key::Pause), true).unwrap();
        assert_eq!(cmd, scancode_command(0x1E, false, KeyState::Down));
        assert_eq!(translate_key(Key::Pause, None, true), None);
    }

    #[test]
    fn scancode_commands_never_carry_unicode() {
        let RemoteInputCommand::Keyboard {
            scancode,
            unicode_char,
            ..
        } = translate_key(Key::A, None, true).unwrap()
        else {
            panic!("se esperaba teclado");
        };
        assert_ne!(scancode, 0);
        assert_eq!(unicode_char, None);
    }

    #[test]
    fn unicode_commands_have_scancode_zero_and_reject_control_chars() {
        let cmd = unicode_command('\u{00F1}', KeyState::Down).unwrap();
        assert_eq!(
            cmd,
            RemoteInputCommand::Keyboard {
                scancode: 0,
                extended: false,
                unicode_char: Some('\u{00F1}'),
                state: KeyState::Down,
            }
        );
        assert_eq!(unicode_command('\n', KeyState::Down), None);
        assert_eq!(unicode_command('\u{7F}', KeyState::Up), None);
    }
}
