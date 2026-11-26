//! Lanzamiento del agente de sesion en la sesion del usuario autorizado, desde el servicio (SYSTEM).
//!
//! Flujo: `WTSQueryUserToken` -> `DuplicateTokenEx(TokenPrimary, SecurityImpersonation)` ->
//! `CreateEnvironmentBlock` -> `CreateProcessAsUserW` en `winsta0\default` -> cierre de manejadores.
//! El agente corre con el token del usuario (no SYSTEM): no hereda privilegios del servicio.
//! `WTSQueryUserToken` exige `SeTcbPrivilege`, que el servicio declara y solo SYSTEM posee, por lo
//! que esta funcion no puede ejecutarse desde una cuenta de usuario normal.
//!
//! El servicio pide al agente que libere las teclas y salga; [`ProcessHandle::wait_exit`] espera
//! su salida y solo despues de ese plazo se usa [`terminate`] (`TerminateProcess`).

use core::ffi::c_void;
use core::fmt;
use core::ptr::{null, null_mut};
use std::path::Path;
use std::time::Duration;

use crate::winutil::{last_error, wide, wide_path};

const TOKEN_PRIMARY: i32 = 1;
const SECURITY_IMPERSONATION: i32 = 2;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const TOKEN_USER_CLASS: i32 = 1;
const WAIT_OBJECT_0: u32 = 0;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    h_process: *mut c_void,
    h_thread: *mut c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[link(name = "wtsapi32")]
unsafe extern "system" {
    fn WTSQueryUserToken(session_id: u32, ph_token: *mut *mut c_void) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn DuplicateTokenEx(
        h_existing_token: *mut c_void,
        dw_desired_access: u32,
        lp_token_attributes: *const c_void,
        impersonation_level: i32,
        token_type: i32,
        ph_new_token: *mut *mut c_void,
    ) -> i32;
    fn CreateProcessAsUserW(
        h_token: *mut c_void,
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *const c_void,
        lp_thread_attributes: *const c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *const StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
}

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateEnvironmentBlock(
        lp_environment: *mut *mut c_void,
        h_token: *mut c_void,
        b_inherit: i32,
    ) -> i32;
    fn DestroyEnvironmentBlock(lp_environment: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(h_object: *mut c_void) -> i32;
    fn TerminateProcess(h_process: *mut c_void, u_exit_code: u32) -> i32;
    fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
    fn WTSGetActiveConsoleSessionId() -> u32;
}

/// Fallo al lanzar el agente; cada variante incluye el codigo Win32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    QueryUserToken(u32),
    DuplicateToken(u32),
    EnvironmentBlock(u32),
    CreateProcess(u32),
    /// `GetTokenInformation(TokenUser)` fallo o el SID no se pudo convertir.
    TokenUser(u32),
    /// Argumento de linea de comandos con comillas o caracteres de control.
    InvalidArgument,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (what, code) = match self {
            Self::QueryUserToken(c) => ("WTSQueryUserToken", c),
            Self::DuplicateToken(c) => ("DuplicateTokenEx", c),
            Self::EnvironmentBlock(c) => ("CreateEnvironmentBlock", c),
            Self::CreateProcess(c) => ("CreateProcessAsUserW", c),
            Self::TokenUser(c) => ("GetTokenInformation(TokenUser)", c),
            Self::InvalidArgument => {
                return f.write_str("no se pudo lanzar el agente de sesion: argumento invalido");
            }
        };
        write!(
            f,
            "no se pudo lanzar el agente de sesion: {what} fallo (Win32={code})"
        )
    }
}

impl std::error::Error for LaunchError {}

/// Manejador del proceso del agente; se cierra al soltarse.
#[derive(Debug)]
pub struct ProcessHandle {
    handle: *mut c_void,
    pid: u32,
}

// SAFETY: el manejador de proceso es un objeto del kernel utilizable desde cualquier hilo; el
// valor es su unico dueno y lo cierra una sola vez en `Drop`.
unsafe impl Send for ProcessHandle {}

impl ProcessHandle {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Espera hasta `timeout` a que el proceso termine. `true` si ya termino.
    pub fn wait_exit(&self, timeout: Duration) -> bool {
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: `handle` es un manejador de proceso valido con SYNCHRONIZE (CreateProcess lo concede).
        unsafe { WaitForSingleObject(self.handle, ms) == WAIT_OBJECT_0 }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: `handle` es un manejador de proceso propio, valido y no cerrado antes.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Cierra un manejador al salir del ambito.
struct OwnedHandle(*mut c_void);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: manejador propio valido, cerrado una sola vez aqui.
        unsafe { CloseHandle(self.0) };
    }
}

/// Bloque de entorno liberado con `DestroyEnvironmentBlock`.
struct EnvBlock(*mut c_void);
impl Drop for EnvBlock {
    fn drop(&mut self) {
        // SAFETY: bloque creado por `CreateEnvironmentBlock`, destruido una sola vez aqui.
        unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

/// Sesion de consola activa (`WTSGetActiveConsoleSessionId`); `0xFFFFFFFF` si no hay.
pub fn active_console_session() -> u32 {
    // SAFETY: sin parametros; solo lee el estado del sistema.
    unsafe { WTSGetActiveConsoleSessionId() }
}

fn query_user_token(session_id: u32) -> Result<OwnedHandle, LaunchError> {
    let mut user_token: *mut c_void = null_mut();
    // SAFETY: `user_token` es un destino valido; requiere SeTcbPrivilege (servicio como SYSTEM).
    if unsafe { WTSQueryUserToken(session_id, &mut user_token) } == 0 {
        return Err(LaunchError::QueryUserToken(last_error()));
    }
    Ok(OwnedHandle(user_token))
}

/// SID textual del usuario de la sesion `session_id` (desde su token; solo como SYSTEM).
pub fn session_user_sid(session_id: u32) -> Result<String, LaunchError> {
    let token = query_user_token(session_id)?;
    let mut needed = 0u32;
    // SAFETY: consulta de tamano (buffer nulo, longitud 0) sobre un token valido.
    unsafe { GetTokenInformation(token.0, TOKEN_USER_CLASS, null_mut(), 0, &mut needed) };
    // Vec<u64> garantiza la alineacion de TOKEN_USER.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` tiene al menos `needed` bytes escribibles; token valido.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER_CLASS,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(LaunchError::TokenUser(last_error()));
    }
    // SAFETY: TOKEN_USER empieza por un puntero a SID que apunta dentro de `buf`, vivo aqui.
    let sid = unsafe { *(buf.as_ptr().cast::<*mut c_void>()) };
    // SAFETY: `sid` apunta a un SID valido dentro de `buf`.
    unsafe { crate::identity::sid_to_string(sid) }.ok_or(LaunchError::TokenUser(0))
}

/// Lanza `agent_exe` (con `args`) en el escritorio interactivo de `session_id` con el token del
/// usuario. Cada argumento va entre comillas; se rechazan comillas y caracteres de control.
pub fn launch_session_agent(
    session_id: u32,
    agent_exe: &Path,
    args: &[&str],
) -> Result<ProcessHandle, LaunchError> {
    if args
        .iter()
        .any(|a| a.chars().any(|c| c == '"' || c.is_control()))
    {
        return Err(LaunchError::InvalidArgument);
    }
    let user_token = query_user_token(session_id)?;

    let mut primary: *mut c_void = null_mut();
    // SAFETY: `user_token.0` es un token valido; atributos nulos; `primary` es un destino valido.
    let ok = unsafe {
        DuplicateTokenEx(
            user_token.0,
            MAXIMUM_ALLOWED,
            null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut primary,
        )
    };
    if ok == 0 {
        return Err(LaunchError::DuplicateToken(last_error()));
    }
    let primary = OwnedHandle(primary);

    let mut env: *mut c_void = null_mut();
    // SAFETY: `primary.0` es un token primario valido; `env` es un destino valido.
    if unsafe { CreateEnvironmentBlock(&mut env, primary.0, 0) } == 0 {
        return Err(LaunchError::EnvironmentBlock(last_error()));
    }
    let env = EnvBlock(env);

    let exe = wide_path(agent_exe);
    let mut line = format!("\"{}\"", agent_exe.display());
    for arg in args {
        line.push_str(&format!(" \"{arg}\""));
    }
    let mut cmdline = wide(&line);
    let mut desktop = wide("winsta0\\default");
    let startup = StartupInfoW {
        cb: size_of::<StartupInfoW>() as u32,
        lp_reserved: null_mut(),
        lp_desktop: desktop.as_mut_ptr(),
        lp_title: null_mut(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: 0,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: null_mut(),
        h_std_input: null_mut(),
        h_std_output: null_mut(),
        h_std_error: null_mut(),
    };
    let mut info = ProcessInformation {
        h_process: null_mut(),
        h_thread: null_mut(),
        dw_process_id: 0,
        dw_thread_id: 0,
    };
    // SAFETY: token primario valido; `exe`, `cmdline` y `desktop` son cadenas anchas terminadas en NUL
    // y mutables donde la API lo exige, vivas durante la llamada; `env` es un bloque Unicode valido
    // (CREATE_UNICODE_ENVIRONMENT); `startup` e `info` tienen el diseno de Win32.
    let ok = unsafe {
        CreateProcessAsUserW(
            primary.0,
            exe.as_ptr(),
            cmdline.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env.0,
            null(),
            &startup,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(LaunchError::CreateProcess(last_error()));
    }
    // El manejador del hilo principal no se necesita.
    drop(OwnedHandle(info.h_thread));
    Ok(ProcessHandle {
        handle: info.h_process,
        pid: info.dw_process_id,
    })
}

/// Termina el proceso del agente (p. ej. ante `MonitorAction::TerminateAgent`) y cierra su manejador.
pub fn terminate(process: ProcessHandle) {
    // SAFETY: `handle` es un manejador de proceso valido con derecho de terminacion (CreateProcess lo concede);
    // el fallo se ignora porque el proceso pudo terminar ya. El manejador se cierra en `Drop`.
    unsafe { TerminateProcess(process.handle, 1) };
}
