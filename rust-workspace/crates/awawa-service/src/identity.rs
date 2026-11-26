//! Identidad del proceso desde su token: SID y nombre de cuenta (no se confia en variables de entorno).

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use crate::winutil::last_error;

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER_CLASS: i32 = 1;
const SE_KERNEL_OBJECT: i32 = 6;
const OWNER_SECURITY_INFORMATION: u32 = 1;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: i32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn OpenThreadToken(
        thread: *mut c_void,
        access: u32,
        open_as_self: i32,
        token: *mut *mut c_void,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
    fn CreateWellKnownSid(
        kind: i32,
        domain_sid: *mut c_void,
        sid: *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn CheckTokenMembership(token: *mut c_void, sid: *mut c_void, is_member: *mut i32) -> i32;
    fn LookupAccountSidW(
        system: *const u16,
        sid: *mut c_void,
        name: *mut u16,
        cch_name: *mut u32,
        domain: *mut u16,
        cch_domain: *mut u32,
        use_: *mut i32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentThread() -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn LocalFree(h: *mut c_void) -> *mut c_void;
}

/// Convierte un SID a su forma textual (`S-1-5-18`).
///
/// # Safety
/// `sid` debe apuntar a un SID valido durante la llamada.
pub unsafe fn sid_to_string(sid: *mut c_void) -> Option<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: el llamador garantiza que `sid` es valido; `out` es un destino valido y se libera abajo.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 {
        return None;
    }
    // SAFETY: tras el exito, `out` es una cadena ancha terminada en NUL asignada con LocalAlloc.
    let text = unsafe {
        let mut len = 0usize;
        while *out.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(out, len))
    };
    // SAFETY: `out` fue asignado por la API y no se usa despues.
    unsafe { LocalFree(out.cast()) };
    Some(text)
}

/// Ejecuta `f` con el SID del usuario de `token` (buffer vivo durante `f`). No cierra `token`.
fn with_token_user_sid<T>(
    token: *mut c_void,
    f: impl FnOnce(*mut c_void) -> Option<T>,
) -> Result<T, u32> {
    let mut needed = 0u32;
    // SAFETY: consulta de tamano (buffer nulo, longitud 0); `token` es un manejador valido del llamador.
    unsafe { GetTokenInformation(token, TOKEN_USER_CLASS, null_mut(), 0, &mut needed) };
    // Vec<u64> garantiza la alineacion de TOKEN_USER.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` tiene al menos `needed` bytes escribibles.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: TOKEN_USER empieza por un puntero a SID que apunta dentro de `buf`.
    let sid = unsafe { *(buf.as_ptr().cast::<*mut c_void>()) };
    f(sid).ok_or(0)
}

/// Ejecuta `f` con el SID del usuario del token del proceso (buffer vivo durante `f`).
fn with_user_sid<T>(f: impl FnOnce(*mut c_void) -> Option<T>) -> Result<T, u32> {
    let mut token: *mut c_void = null_mut();
    // SAFETY: pseudo-manejador del proceso actual; `token` es un destino valido; se cierra abajo.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    let result = with_token_user_sid(token, f);
    // SAFETY: `token` fue abierto arriba y no se usa despues.
    unsafe { CloseHandle(token) };
    result
}

/// `true` si `token` (nulo = token efectivo del hilo) pertenece a BUILTIN\Administrators con el grupo
/// habilitado. Un administrador sin elevar lo tiene solo como "deny-only" y devuelve `false`.
fn token_is_administrator(token: *mut c_void) -> bool {
    let mut sid = [0u8; 68]; // SECURITY_MAX_SID_SIZE
    let mut size = 68u32;
    // SAFETY: `sid` es un buffer valido de `size` bytes; tipo 26 = WinBuiltinAdministratorsSid; SID de dominio nulo.
    if unsafe { CreateWellKnownSid(26, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return false;
    }
    let mut member = 0i32;
    // SAFETY: `token` es nulo o un token de suplantacion valido del llamador; `sid` es un SID valido.
    let ok = unsafe { CheckTokenMembership(token, sid.as_mut_ptr().cast(), &mut member) };
    ok != 0 && member != 0
}

/// `true` si el token efectivo (elevado) pertenece a BUILTIN\Administrators. Un administrador sin elevar
/// tiene el grupo solo como "deny-only" y devuelve `false`.
pub fn is_administrator() -> bool {
    token_is_administrator(null_mut())
}

/// Token de suplantacion del hilo, abierto con `OpenThreadToken(open_as_self = TRUE)`; se cierra al soltarse.
/// Permite consultar al cliente de una pipe DESPUES de `RevertToSelf`, con un manejador explicito.
pub struct ThreadToken(*mut c_void);

impl ThreadToken {
    /// Abre el token del hilo actual (el hilo debe estar suplantando).
    pub fn open() -> Result<Self, u32> {
        let mut token: *mut c_void = null_mut();
        // SAFETY: seudo-manejador del hilo actual; `open_as_self = 1` evalua el acceso con el token del
        // proceso (el del hilo es de suplantacion); `token` es un destino valido y se cierra en `Drop`.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(last_error());
        }
        Ok(Self(token))
    }

    /// Pertenencia elevada a BUILTIN\Administrators, con `CheckTokenMembership` sobre este manejador.
    pub fn is_administrator(&self) -> bool {
        token_is_administrator(self.0)
    }

    /// Nombre `DOMINIO\usuario` del `TokenUser` (si no se resuelve, el SID textual).
    pub fn account_name(&self) -> Result<String, u32> {
        with_token_user_sid(self.0, account_name_of)
    }
}

impl Drop for ThreadToken {
    fn drop(&mut self) {
        // SAFETY: manejador abierto en `open` y no usado despues.
        unsafe { CloseHandle(self.0) };
    }
}

/// SID textual del dueno del objeto del nucleo abierto en `file` (por ejemplo una pipe).
pub fn handle_owner_sid_string(file: &std::fs::File) -> Result<String, u32> {
    use std::os::windows::io::AsRawHandle;
    let handle: *mut c_void = file.as_raw_handle();
    let mut owner: *mut c_void = null_mut();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: `handle` es el manejador vivo de `file`; los destinos son validos; el descriptor se libera abajo.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(status);
    }
    // SAFETY: `owner` apunta dentro de `descriptor`, vivo hasta el `LocalFree` de abajo.
    let text = unsafe { sid_to_string(owner) };
    // SAFETY: `descriptor` fue asignado por la API y no se usa despues.
    unsafe { LocalFree(descriptor) };
    text.ok_or(0)
}

/// SID textual del usuario del token del proceso.
pub fn current_user_sid_string() -> Result<String, u32> {
    // SAFETY: `sid` es valido durante el cierre.
    with_user_sid(|sid| unsafe { sid_to_string(sid) })
}

/// Nombre `DOMINIO\usuario` de un SID (si no se resuelve, el SID textual).
fn account_name_of(sid: *mut c_void) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let (mut n, mut d, mut kind) = (256u32, 256u32, 0i32);
    // SAFETY: `sid` es valido; los buffers tienen las capacidades indicadas.
    let ok = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut n,
            domain.as_mut_ptr(),
            &mut d,
            &mut kind,
        )
    };
    if ok == 0 {
        // SAFETY: `sid` es valido.
        return unsafe { sid_to_string(sid) };
    }
    let name = String::from_utf16_lossy(&name[..n as usize]);
    let domain = String::from_utf16_lossy(&domain[..d as usize]);
    Some(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

/// Nombre `DOMINIO\usuario` del token del proceso (si no se resuelve, el SID textual).
pub fn current_account_name() -> Result<String, u32> {
    with_user_sid(account_name_of)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_y_nombre_del_token_se_resuelven() {
        assert!(current_user_sid_string().unwrap().starts_with("S-1-5-"));
        assert!(!current_account_name().unwrap().is_empty());
    }
}
