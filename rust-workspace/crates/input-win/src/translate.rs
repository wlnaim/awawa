//! Traducción pura `RemoteInputCommand` → `INPUT` de Win32. No invoca `SendInput`: es verificable sin inyectar.

use std::mem::size_of;

use awawa_protocol::{ButtonState, KeyState, MouseButton, RemoteInputCommand};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
    MOUSE_EVENT_FLAGS, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
};

/// `mouseData` de `MOUSEEVENTF_XDOWN/XUP` para el primer botón lateral.
const XBUTTON1: u32 = 0x0001;
/// `mouseData` de `MOUSEEVENTF_XDOWN/XUP` para el segundo botón lateral.
const XBUTTON2: u32 = 0x0002;

/// Tamaño de `INPUT` que exige `SendInput` como `cbSize`.
pub const INPUT_SIZE: i32 = size_of::<INPUT>() as i32;

/// Comando que no se puede expresar como `INPUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslateError {
    /// Teclado sin scancode (0) y sin carácter Unicode.
    KeyboardWithoutScancodeOrChar,
}

fn mouse_input(dx: i32, dy: i32, mouse_data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn keyboard_input(scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Movimiento absoluto sobre todo el escritorio virtual. `norm_*` ya está en `[0..=65535]`
/// relativo al escritorio virtual (ver `VirtualDesktopBounds::normalize_pixel`).
pub fn translate_move(norm_x: u16, norm_y: u16) -> INPUT {
    mouse_input(
        i32::from(norm_x),
        i32::from(norm_y),
        0,
        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
    )
}

/// Botón del ratón en la posición actual del cursor (los `target_*` solo los usa la guardia).
pub fn translate_button(button: MouseButton, state: ButtonState) -> INPUT {
    let down = state == ButtonState::Pressed;
    let (flags, data) = match button {
        MouseButton::Left => (
            if down {
                MOUSEEVENTF_LEFTDOWN
            } else {
                MOUSEEVENTF_LEFTUP
            },
            0,
        ),
        MouseButton::Right => (
            if down {
                MOUSEEVENTF_RIGHTDOWN
            } else {
                MOUSEEVENTF_RIGHTUP
            },
            0,
        ),
        MouseButton::Middle => (
            if down {
                MOUSEEVENTF_MIDDLEDOWN
            } else {
                MOUSEEVENTF_MIDDLEUP
            },
            0,
        ),
        MouseButton::X1 => (
            if down {
                MOUSEEVENTF_XDOWN
            } else {
                MOUSEEVENTF_XUP
            },
            XBUTTON1,
        ),
        MouseButton::X2 => (
            if down {
                MOUSEEVENTF_XDOWN
            } else {
                MOUSEEVENTF_XUP
            },
            XBUTTON2,
        ),
    };
    mouse_input(0, 0, data, flags)
}

/// Rueda vertical y/o horizontal; un `INPUT` por eje distinto de cero. `mouseData` lleva el delta con signo.
pub fn translate_wheel(delta_x: i16, delta_y: i16) -> Vec<INPUT> {
    let mut out = Vec::with_capacity(2);
    if delta_y != 0 {
        out.push(mouse_input(
            0,
            0,
            i32::from(delta_y) as u32,
            MOUSEEVENTF_WHEEL,
        ));
    }
    if delta_x != 0 {
        out.push(mouse_input(
            0,
            0,
            i32::from(delta_x) as u32,
            MOUSEEVENTF_HWHEEL,
        ));
    }
    out
}

/// Teclado. Si hay carácter Unicode se inyecta como `KEYEVENTF_UNICODE` (una unidad UTF-16 por `INPUT`);
/// si no, por scancode físico con `KEYEVENTF_EXTENDEDKEY` cuando corresponde.
pub fn translate_keyboard(
    scancode: u16,
    extended: bool,
    unicode_char: Option<char>,
    state: KeyState,
) -> Result<Vec<INPUT>, TranslateError> {
    let up = if state == KeyState::Up {
        KEYEVENTF_KEYUP
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    if let Some(c) = unicode_char {
        let mut units = [0u16; 2];
        return Ok(c
            .encode_utf16(&mut units)
            .iter()
            .map(|unit| keyboard_input(*unit, KEYEVENTF_UNICODE | up))
            .collect());
    }
    if scancode == 0 {
        return Err(TranslateError::KeyboardWithoutScancodeOrChar);
    }
    let ext = if extended {
        KEYEVENTF_EXTENDEDKEY
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    Ok(vec![keyboard_input(
        scancode,
        KEYEVENTF_SCANCODE | ext | up,
    )])
}

/// Traduce un comando remoto a cero o más `INPUT`.
pub fn translate_command(cmd: &RemoteInputCommand) -> Result<Vec<INPUT>, TranslateError> {
    match cmd {
        RemoteInputCommand::MoveCursor { norm_x, norm_y } => {
            Ok(vec![translate_move(*norm_x, *norm_y)])
        }
        RemoteInputCommand::MouseButton { button, state, .. } => {
            Ok(vec![translate_button(*button, *state)])
        }
        RemoteInputCommand::MouseWheel { delta_x, delta_y } => {
            Ok(translate_wheel(*delta_x, *delta_y))
        }
        RemoteInputCommand::Keyboard {
            scancode,
            extended,
            unicode_char,
            state,
        } => translate_keyboard(*scancode, *extended, *unicode_char, *state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mi(input: &INPUT) -> MOUSEINPUT {
        assert_eq!(input.r#type, INPUT_MOUSE);
        // SAFETY: `type` es INPUT_MOUSE, por lo que la variante activa de la unión es `mi`.
        unsafe { input.Anonymous.mi }
    }

    fn ki(input: &INPUT) -> KEYBDINPUT {
        assert_eq!(input.r#type, INPUT_KEYBOARD);
        // SAFETY: `type` es INPUT_KEYBOARD, por lo que la variante activa de la unión es `ki`.
        unsafe { input.Anonymous.ki }
    }

    #[test]
    fn move_uses_absolute_virtual_desktop_flags_and_normalized_coords() {
        let m = mi(&translate_move(65_535, 0));
        assert_eq!((m.dx, m.dy), (65_535, 0));
        assert_eq!(
            m.dwFlags,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        );
    }

    #[test]
    fn buttons_map_to_down_and_up_flags_without_move() {
        let cases = [
            (
                MouseButton::Left,
                MOUSEEVENTF_LEFTDOWN,
                MOUSEEVENTF_LEFTUP,
                0,
            ),
            (
                MouseButton::Right,
                MOUSEEVENTF_RIGHTDOWN,
                MOUSEEVENTF_RIGHTUP,
                0,
            ),
            (
                MouseButton::Middle,
                MOUSEEVENTF_MIDDLEDOWN,
                MOUSEEVENTF_MIDDLEUP,
                0,
            ),
            (MouseButton::X1, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, 1),
            (MouseButton::X2, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, 2),
        ];
        for (button, down, up, data) in cases {
            let d = mi(&translate_button(button, ButtonState::Pressed));
            let u = mi(&translate_button(button, ButtonState::Released));
            assert_eq!((d.dwFlags, d.mouseData), (down, data), "{button:?} down");
            assert_eq!((u.dwFlags, u.mouseData), (up, data), "{button:?} up");
            assert_eq!((d.dx, d.dy), (0, 0));
        }
    }

    #[test]
    fn wheel_emits_one_input_per_nonzero_axis_with_signed_delta() {
        assert!(translate_wheel(0, 0).is_empty());
        let both = translate_wheel(-120, 240);
        assert_eq!(both.len(), 2);
        let v = mi(&both[0]);
        assert_eq!(v.dwFlags, MOUSEEVENTF_WHEEL);
        assert_eq!(v.mouseData as i32, 240);
        let h = mi(&both[1]);
        assert_eq!(h.dwFlags, MOUSEEVENTF_HWHEEL);
        assert_eq!(h.mouseData as i32, -120);
    }

    #[test]
    fn scancode_key_uses_scancode_flag_and_extended_and_keyup() {
        let down = translate_keyboard(0x1D, false, None, KeyState::Down).unwrap();
        let k = ki(&down[0]);
        assert_eq!((k.wVk, k.wScan), (VIRTUAL_KEY(0), 0x1D));
        assert_eq!(k.dwFlags, KEYEVENTF_SCANCODE);

        let up = translate_keyboard(0x4B, true, None, KeyState::Up).unwrap();
        assert_eq!(
            ki(&up[0]).dwFlags,
            KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP
        );
    }

    #[test]
    fn char_without_scancode_uses_unicode_including_surrogate_pairs() {
        let n = translate_keyboard(0, false, Some('ñ'), KeyState::Down).unwrap();
        assert_eq!(n.len(), 1);
        let k = ki(&n[0]);
        assert_eq!((k.wScan, k.wVk), ('ñ' as u16, VIRTUAL_KEY(0)));
        assert_eq!(k.dwFlags, KEYEVENTF_UNICODE);

        let up = translate_keyboard(0, false, Some('á'), KeyState::Up).unwrap();
        assert_eq!(ki(&up[0]).dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);

        let emoji = translate_keyboard(0, false, Some('\u{1F600}'), KeyState::Down).unwrap();
        assert_eq!(emoji.len(), 2);
        assert_eq!(ki(&emoji[0]).wScan, 0xD83D);
        assert_eq!(ki(&emoji[1]).wScan, 0xDE00);
    }

    #[test]
    fn key_without_scancode_or_char_is_rejected() {
        assert!(matches!(
            translate_keyboard(0, false, None, KeyState::Down),
            Err(TranslateError::KeyboardWithoutScancodeOrChar)
        ));
    }

    #[test]
    fn translate_command_dispatches_by_variant() {
        let cmd = RemoteInputCommand::MoveCursor {
            norm_x: 10,
            norm_y: 20,
        };
        let inputs = translate_command(&cmd).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(mi(&inputs[0]).dx, 10);
        // Los target_* no se usan para inyectar: el clic ocurre donde está el cursor.
        let click = RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state: ButtonState::Pressed,
            target_x: 500,
            target_y: 600,
        };
        let m = mi(&translate_command(&click).unwrap()[0]);
        assert_eq!((m.dx, m.dy), (0, 0));
        assert_eq!(INPUT_SIZE as usize, size_of::<INPUT>());
    }
}
