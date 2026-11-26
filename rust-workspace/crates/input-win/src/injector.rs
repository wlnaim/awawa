//! `WindowsSendInputInjector`: backend real de `PeripheralBackend` sobre `USER32!SendInput`.
//!
//! No expone métodos de inyección propios: solo se alcanza mediante el trait, y debe vivir dentro de
//! `ConsentGatedInputDispatcher`, que exige sesión aprobada y escritorio `Streaming`. Con el escritorio
//! seguro activo `SendInput` falla y el error se propaga (las liberaciones se reintentan en el dispatcher).

use awawa_protocol::{ButtonState, RemoteInputCommand};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Input::KeyboardAndMouse::{INPUT, SendInput};

use crate::guard::{ProtectedWindowGuard, SystemWindowProbe, WindowProbe};
use crate::translate::{INPUT_SIZE, translate_command};
use crate::{ConsentGatedInputDispatcher, InjectionError, PeripheralBackend};

#[derive(Debug, Clone)]
pub struct WindowsSendInputInjector {
    guard: ProtectedWindowGuard,
}

/// Única vía pública para obtener el backend real: lo devuelve ya dentro del despachador con
/// consentimiento, escritorio `Streaming`, guardia de ventanas y dead-man (`enable_heartbeat`).
pub fn windows_input_dispatcher(
    guard: ProtectedWindowGuard,
) -> ConsentGatedInputDispatcher<WindowsSendInputInjector> {
    ConsentGatedInputDispatcher::new(WindowsSendInputInjector::new(guard))
}

impl WindowsSendInputInjector {
    pub(crate) fn new(guard: ProtectedWindowGuard) -> Self {
        Self { guard }
    }

    /// Registro de ventanas protegidas (compartido: la UI registra sus HWND en él).
    pub fn guard(&self) -> &ProtectedWindowGuard {
        &self.guard
    }
}

fn send(inputs: &[INPUT]) -> Result<(), InjectionError> {
    if inputs.is_empty() {
        return Ok(());
    }
    // SAFETY: `inputs` es un slice válido de `INPUT` y `INPUT_SIZE` es `size_of::<INPUT>()`.
    let sent = unsafe { SendInput(inputs, INPUT_SIZE) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        // SAFETY: lectura del último error del hilo, sin precondiciones.
        Err(InjectionError::OsSendInputBlockedOrFailed(
            unsafe { GetLastError() }.0,
        ))
    }
}

/// Solo se bloquea la pulsación: la liberación nunca se retiene para no dejar un botón pegado.
fn check_guard<P: WindowProbe>(
    guard: &ProtectedWindowGuard,
    probe: &P,
    cmd: &RemoteInputCommand,
) -> Result<(), InjectionError> {
    if let RemoteInputCommand::MouseButton {
        state: ButtonState::Pressed,
        target_x,
        target_y,
        ..
    } = cmd
        && guard.blocks_click(probe, *target_x, *target_y)
    {
        return Err(InjectionError::ProtectedWindowHit);
    }
    Ok(())
}

impl PeripheralBackend for WindowsSendInputInjector {
    fn inject_command(&mut self, cmd: &RemoteInputCommand) -> Result<(), InjectionError> {
        check_guard(&self.guard, &SystemWindowProbe, cmd)?;
        let inputs = translate_command(cmd).map_err(|_| InjectionError::InvalidCommand)?;
        send(&inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_constructor_keeps_the_shared_guard() {
        let guard = ProtectedWindowGuard::new();
        let dispatcher = windows_input_dispatcher(guard.clone());
        guard.register_raw(0x1234);
        assert_eq!(dispatcher.backend().guard().registered_count(), 1);
        assert_eq!(dispatcher.pending_release_count(), 0);
    }
    use awawa_protocol::{KeyState, MouseButton, VirtualDesktopBounds};
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    fn cursor() -> (i32, i32) {
        let mut pt = POINT::default();
        // SAFETY: `pt` es un POINT válido durante la llamada.
        unsafe { GetCursorPos(&mut pt) }.unwrap();
        (pt.x, pt.y)
    }

    /// Mueve el cursor real al centro del escritorio virtual y lo devuelve a su sitio.
    /// Ejecutar solo a petición: `cargo test -p input-win -- --ignored`.
    #[test]
    #[ignore = "mueve el cursor fisico; ejecutar solo a peticion"]
    fn live_moves_cursor_to_center_and_restores_it() {
        // SAFETY: GetSystemMetrics no tiene precondiciones.
        let bounds = unsafe {
            VirtualDesktopBounds {
                left: GetSystemMetrics(SM_XVIRTUALSCREEN),
                top: GetSystemMetrics(SM_YVIRTUALSCREEN),
                width: GetSystemMetrics(SM_CXVIRTUALSCREEN) as u32,
                height: GetSystemMetrics(SM_CYVIRTUALSCREEN) as u32,
            }
        };
        let original = cursor();
        let mut injector = WindowsSendInputInjector::new(ProtectedWindowGuard::new());

        let center = bounds.normalize_pixel(
            bounds.left + bounds.width as i32 / 2,
            bounds.top + bounds.height as i32 / 2,
        );
        let moved = injector.inject_command(&RemoteInputCommand::MoveCursor {
            norm_x: center.x,
            norm_y: center.y,
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let after_move = cursor();

        let back = bounds.normalize_pixel(original.0, original.1);
        let restored = injector.inject_command(&RemoteInputCommand::MoveCursor {
            norm_x: back.x,
            norm_y: back.y,
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let after_restore = cursor();

        moved.unwrap();
        restored.unwrap();
        let (ex, ey) = bounds.denormalize_point(center);
        assert!((after_move.0 - ex).abs() <= 2 && (after_move.1 - ey).abs() <= 2);
        assert!((after_restore.0 - original.0).abs() <= 2);
        assert!((after_restore.1 - original.1).abs() <= 2);
    }

    struct AlwaysOnProtected;

    impl WindowProbe for AlwaysOnProtected {
        fn root_window_at(&self, _x: i32, _y: i32) -> Option<isize> {
            Some(7)
        }

        fn cursor_position(&self) -> Option<(i32, i32)> {
            None
        }
    }

    fn click(state: ButtonState) -> RemoteInputCommand {
        RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state,
            target_x: 10,
            target_y: 10,
        }
    }

    #[test]
    fn press_over_protected_window_is_blocked_but_release_and_other_commands_pass() {
        let guard = ProtectedWindowGuard::new();
        guard.register_raw(7);
        assert_eq!(
            check_guard(&guard, &AlwaysOnProtected, &click(ButtonState::Pressed)),
            Err(InjectionError::ProtectedWindowHit)
        );
        assert_eq!(
            check_guard(&guard, &AlwaysOnProtected, &click(ButtonState::Released)),
            Ok(())
        );
        let mv = RemoteInputCommand::MoveCursor {
            norm_x: 1,
            norm_y: 1,
        };
        assert_eq!(check_guard(&guard, &AlwaysOnProtected, &mv), Ok(()));
    }

    #[test]
    fn invalid_keyboard_command_is_rejected_before_send_input() {
        let mut injector = WindowsSendInputInjector::new(ProtectedWindowGuard::new());
        let invalid = RemoteInputCommand::Keyboard {
            scancode: 0,
            extended: false,
            unicode_char: None,
            state: KeyState::Down,
        };
        assert_eq!(
            injector.inject_command(&invalid),
            Err(InjectionError::InvalidCommand)
        );
    }
}
