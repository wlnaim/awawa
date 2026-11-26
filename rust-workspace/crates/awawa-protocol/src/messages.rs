use serde::{Deserialize, Serialize};

/// Capacidades estrictamente acotadas al requerimiento del sistema:
/// ÚNICAMENTE visualización de escritorio y control de Cursor + Teclado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedCapabilities {
    pub view_desktop: bool,
    pub control_cursor: bool,
    pub control_keyboard: bool,
}

impl ScopedCapabilities {
    /// Perfil estándar completo permitido cuando el cliente cede el control total de escritorio y periféricos.
    pub const FULL_DESKTOP_AND_PERIPHERALS: Self = Self {
        view_desktop: true,
        control_cursor: true,
        control_keyboard: true,
    };

    /// Decodifica una máscara de bits recibida por red rechazando cualquier bandera fuera de alcance
    /// (por ejemplo transferencia de archivos, shell remota, bloqueo de entrada local o audio).
    pub fn from_wire_bits(bits: u32) -> Result<Self, &'static str> {
        const BIT_VIEW: u32 = 0b0001;
        const BIT_CURSOR: u32 = 0b0010;
        const BIT_KEYBOARD: u32 = 0b0100;
        const ALLOWED_MASK: u32 = BIT_VIEW | BIT_CURSOR | BIT_KEYBOARD;

        if (bits & !ALLOWED_MASK) != 0 {
            return Err("capacidad fuera de alcance rechazada por politica de seguridad");
        }
        if (bits & BIT_VIEW) == 0 {
            return Err("la sesion requiere al menos capacidad de visualizacion");
        }
        Ok(Self {
            view_desktop: (bits & BIT_VIEW) != 0,
            control_cursor: (bits & BIT_CURSOR) != 0,
            control_keyboard: (bits & BIT_KEYBOARD) != 0,
        })
    }

    pub fn to_wire_bits(self) -> u32 {
        let mut bits = 0u32;
        if self.view_desktop {
            bits |= 0b0001;
        }
        if self.control_cursor {
            bits |= 0b0010;
        }
        if self.control_keyboard {
            bits |= 0b0100;
        }
        bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ButtonState {
    Pressed,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Down,
    Up,
}

/// Comandos de entrada remota permitidos desde el Agente de Soporte hacia el Cliente Receptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteInputCommand {
    /// Movimiento de cursor en espacio normalizado `[0..=65535]` del escritorio virtual.
    MoveCursor { norm_x: u16, norm_y: u16 },
    /// Clic o liberación de botón de ratón en la posición actual o indicada.
    MouseButton {
        button: MouseButton,
        state: ButtonState,
        target_x: i32,
        target_y: i32,
    },
    /// Rueda vertical/horizontal del ratón.
    MouseWheel { delta_x: i16, delta_y: i16 },
    /// Evento de teclado por Scan Code físico o carácter Unicode imprimible.
    Keyboard {
        scancode: u16,
        extended: bool,
        unicode_char: Option<char>,
        state: KeyState,
    },
}
