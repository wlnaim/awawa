//! Sonda del escritorio de entrada: detecta si Windows cambio al escritorio seguro (UAC, Ctrl+Alt+Supr, bloqueo).
//!
//! Usa `OpenInputDesktop` + `GetUserObjectInformationW(UOI_NAME)` + `CloseDesktop`. Nunca llama a
//! `SetThreadDesktop`: el proceso jamas se adjunta al escritorio seguro, por lo que no puede capturar
//! pantalla ni inyectar entrada ahi. Un fallo de apertura (p. ej. acceso denegado en `Winlogon`) se
//! reporta como [`InputDesktopKind::Inaccessible`] y el monitor lo trata igual que el escritorio seguro.

use core::ffi::c_void;

use awawa_protocol::desktop_session::InputDesktopKind;

const DESKTOP_READOBJECTS: u32 = 0x0001;
const UOI_NAME: i32 = 2;

#[link(name = "user32")]
unsafe extern "system" {
    fn OpenInputDesktop(dw_flags: u32, f_inherit: i32, dw_desired_access: u32) -> *mut c_void;
    fn CloseDesktop(h_desktop: *mut c_void) -> i32;
    fn GetUserObjectInformationW(
        h_obj: *mut c_void,
        n_index: i32,
        pv_info: *mut c_void,
        n_length: u32,
        lpn_length_needed: *mut u32,
    ) -> i32;
}

/// Clasifica el nombre del escritorio de entrada: `Default` (sin distinguir mayusculas) es el del usuario.
pub fn classify_desktop_name(name: &str) -> InputDesktopKind {
    if name.eq_ignore_ascii_case("Default") {
        InputDesktopKind::Default
    } else {
        InputDesktopKind::SecureOrOther
    }
}

/// Sondea el escritorio que recibe la entrada ahora mismo.
pub fn probe_input_desktop() -> InputDesktopKind {
    // SAFETY: parametros documentados; devuelve un manejador propio que se cierra abajo, o nulo si falla.
    let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if desktop.is_null() {
        return InputDesktopKind::Inaccessible;
    }

    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    // SAFETY: `desktop` es un manejador valido con DESKTOP_READOBJECTS; `buf` es memoria mutable valida
    // de `size_of_val(&buf)` bytes y `needed` un destino valido.
    let ok = unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_NAME,
            buf.as_mut_ptr().cast(),
            size_of_val(&buf) as u32,
            &mut needed,
        )
    };
    // SAFETY: `desktop` fue abierto arriba y no se usa despues.
    unsafe { CloseDesktop(desktop) };

    if ok == 0 {
        return InputDesktopKind::Inaccessible;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    classify_desktop_name(&String::from_utf16_lossy(&buf[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clasifica_nombres() {
        assert_eq!(classify_desktop_name("Default"), InputDesktopKind::Default);
        assert_eq!(classify_desktop_name("default"), InputDesktopKind::Default);
        assert_eq!(
            classify_desktop_name("Winlogon"),
            InputDesktopKind::SecureOrOther
        );
        assert_eq!(
            classify_desktop_name("Screen-saver"),
            InputDesktopKind::SecureOrOther
        );
        assert_eq!(classify_desktop_name(""), InputDesktopKind::SecureOrOther);
    }

    /// Requiere sesion interactiva (escritorio del usuario activo y sin UAC/bloqueo en curso).
    #[test]
    fn sonda_en_vivo_devuelve_default_en_sesion_interactiva() {
        assert_eq!(probe_input_desktop(), InputDesktopKind::Default);
    }
}
