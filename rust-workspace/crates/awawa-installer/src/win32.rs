//! FFI manual (como `awawa-service`) para las carpetas conocidas y los accesos directos.
//!
//! No usa el crate `windows`: activarle features nuevas cambiaria, por la unificacion de features del
//! workspace, los binarios de los demas crates (y sus SHA-256 en el paquete).

use core::ffi::c_void;
use core::ptr::null_mut;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

#[repr(C)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    const fn from_u128(v: u128) -> Self {
        Self {
            data1: (v >> 96) as u32,
            data2: (v >> 80 & 0xffff) as u16,
            data3: (v >> 64 & 0xffff) as u16,
            data4: (v as u64).to_be_bytes(),
        }
    }
}

pub const FOLDERID_PROGRAM_FILES_X64: Guid =
    Guid::from_u128(0x6d809377_6af0_444b_8957_a3773f02200e);
pub const FOLDERID_PROGRAM_DATA: Guid = Guid::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97);
pub const FOLDERID_COMMON_PROGRAMS: Guid = Guid::from_u128(0x0139d44e_6afe_49f2_8690_3dafcae6ffb8);
pub const FOLDERID_COMMON_STARTUP: Guid = Guid::from_u128(0x82a5ea35_d9cd_47c5_9629_e15d2f714e6e);
pub const FOLDERID_PUBLIC_DESKTOP: Guid = Guid::from_u128(0xc4aa340d_f20f_4863_afef_f87ef2e6ba25);
pub const FOLDERID_DESKTOP: Guid = Guid::from_u128(0xb4bfcc3a_db2c_424c_b029_7fe99a87c641);
pub const FOLDERID_SYSTEM: Guid = Guid::from_u128(0x1ac14e77_02e7_4e5d_b744_2eb1ae5198b7);

const CLSID_SHELL_LINK: Guid = Guid::from_u128(0x00021401_0000_0000_c000_000000000046);
const IID_ISHELL_LINK_W: Guid = Guid::from_u128(0x000214f9_0000_0000_c000_000000000046);
const IID_IPERSIST_FILE: Guid = Guid::from_u128(0x0000010b_0000_0000_c000_000000000046);
const CLSCTX_INPROC_SERVER: u32 = 0x1;
const COINIT_APARTMENTTHREADED: u32 = 0x2;

// Indices de la vtable (IUnknown ocupa 0..=2).
const QUERY_INTERFACE: usize = 0;
const RELEASE: usize = 2;
const SL_SET_DESCRIPTION: usize = 7;
const SL_SET_WORKING_DIRECTORY: usize = 9;
const SL_SET_ARGUMENTS: usize = 11;
const SL_SET_ICON_LOCATION: usize = 17;
const SL_SET_PATH: usize = 20;
const PF_SAVE: usize = 6;

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        id: *const Guid,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(pv: *mut c_void);
    fn CoInitializeEx(reserved: *mut c_void, coinit: u32) -> i32;
    fn CoCreateInstance(
        clsid: *const Guid,
        outer: *mut c_void,
        context: u32,
        iid: *const Guid,
        out: *mut *mut c_void,
    ) -> i32;
}

/// Ruta de una carpeta conocida del usuario actual.
pub fn known_folder(id: &Guid, what: &str) -> Result<PathBuf, String> {
    let mut raw: *mut u16 = null_mut();
    // SAFETY: GUID valido; flags 0; sin token (usuario actual); `raw` es un destino valido.
    let hr = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut raw) };
    let result = if hr < 0 || raw.is_null() {
        Err(format!(
            "carpeta {what}: SHGetKnownFolderPath fallo (HRESULT {hr:#010x})"
        ))
    } else {
        // SAFETY: la API devuelve una cadena ancha terminada en NUL.
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        // SAFETY: `len` unidades validas antes del NUL.
        let units = unsafe { std::slice::from_raw_parts(raw, len) };
        String::from_utf16(units)
            .map(PathBuf::from)
            .map_err(|_| format!("carpeta {what}: ruta no representable"))
    };
    // SAFETY: el buffer lo asigna la API (incluso si falla) y se libera una sola vez; nulo es valido.
    unsafe { CoTaskMemFree(raw.cast()) };
    result
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// Puntero COM propio: se libera al soltarse.
struct ComPtr(*mut c_void);

impl ComPtr {
    /// Funcion `index` de la vtable.
    ///
    /// # Safety
    /// `index` debe ser una entrada valida de la vtable de la interfaz que apunta `self`.
    unsafe fn slot(&self, index: usize) -> *const c_void {
        // SAFETY: un objeto COM empieza por el puntero a su vtable; el llamador garantiza el indice.
        unsafe { *(*(self.0 as *const *const *const c_void)).add(index) }
    }
}

impl Drop for ComPtr {
    fn drop(&mut self) {
        // SAFETY: IUnknown::Release en un puntero valido obtenido de COM; se llama una sola vez.
        unsafe {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                core::mem::transmute(self.slot(RELEASE));
            release(self.0);
        }
    }
}

fn check(hr: i32, what: &str) -> Result<(), String> {
    if hr < 0 {
        Err(format!("{what} fallo (HRESULT {hr:#010x})"))
    } else {
        Ok(())
    }
}

/// Inicializa COM en el hilo actual (STA). S_FALSE o RPC_E_CHANGED_MODE: ya estaba inicializado.
pub fn init_com() {
    // SAFETY: reservado nulo; modo documentado.
    let _ = unsafe { CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED) };
}

/// Crea un acceso directo `.lnk` con `IShellLinkW` + `IPersistFile::Save`. Requiere `init_com`.
pub fn create_shortcut(
    link: &OsStr,
    target: &OsStr,
    args: &OsStr,
    workdir: &OsStr,
    description: &OsStr,
) -> Result<(), String> {
    type SetStr = unsafe extern "system" fn(*mut c_void, *const u16) -> i32;
    type SetIcon = unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32;
    type QueryInterface =
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type Save = unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32;

    let mut raw: *mut c_void = null_mut();
    // SAFETY: CLSID/IID documentados; sin agregacion; `raw` es un destino valido.
    check(
        unsafe {
            CoCreateInstance(
                &CLSID_SHELL_LINK,
                null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ISHELL_LINK_W,
                &mut raw,
            )
        },
        "CoCreateInstance(ShellLink)",
    )?;
    let shell_link = ComPtr(raw);
    let (target, args, workdir, description, link) = (
        wide(target),
        wide(args),
        wide(workdir),
        wide(description),
        wide(link),
    );
    // SAFETY: `shell_link` es un IShellLinkW valido; los indices son los de su vtable (SDK) y las cadenas
    // anchas terminadas en NUL viven durante cada llamada.
    unsafe {
        let set = |index: usize, value: &[u16], what: &str| -> Result<(), String> {
            let f: SetStr = core::mem::transmute(shell_link.slot(index));
            check(f(shell_link.0, value.as_ptr()), what)
        };
        set(SL_SET_PATH, &target, "IShellLinkW::SetPath")?;
        set(SL_SET_ARGUMENTS, &args, "IShellLinkW::SetArguments")?;
        set(
            SL_SET_WORKING_DIRECTORY,
            &workdir,
            "IShellLinkW::SetWorkingDirectory",
        )?;
        set(
            SL_SET_DESCRIPTION,
            &description,
            "IShellLinkW::SetDescription",
        )?;
        let icon: SetIcon = core::mem::transmute(shell_link.slot(SL_SET_ICON_LOCATION));
        check(
            icon(shell_link.0, target.as_ptr(), 0),
            "IShellLinkW::SetIconLocation",
        )?;

        let qi: QueryInterface = core::mem::transmute(shell_link.slot(QUERY_INTERFACE));
        let mut raw_file: *mut c_void = null_mut();
        check(
            qi(shell_link.0, &IID_IPERSIST_FILE, &mut raw_file),
            "QueryInterface(IPersistFile)",
        )?;
        let file = ComPtr(raw_file);
        let save: Save = core::mem::transmute(file.slot(PF_SAVE));
        check(save(file.0, link.as_ptr(), 1), "IPersistFile::Save")
    }
}

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const SDDL_REVISION_1: u32 = 1;
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetDefaultDllDirectories(flags: u32) -> i32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        sd: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorOwner(
        sd: *mut c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        sd: *mut c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        name: *const u16,
        object_type: i32,
        info: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
}

/// Las cargas dinamicas de DLL del proceso, y las diferidas (`/DELAYLOAD` de `build.rs`) con sus
/// dependencias, solo buscan en System32 (no en la carpeta del Setup ni en el directorio actual).
/// Si falla (no deberia en Windows 8 o posterior) se sigue con el orden por defecto.
pub fn restrict_dll_search_to_system32() {
    // SAFETY: constante documentada; sin punteros.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
}

/// Fija explicitamente el dueno y la DACL protegida de `sddl` (que debe incluir `O:` y `D:`) sobre
/// un archivo o carpeta, sin depender del dueno por defecto del token que lo creo. Requiere que el
/// token pueda asignar ese dueno (administrador elevado para `O:BA`).
pub fn set_owner_and_dacl(path: &std::path::Path, sddl: &str) -> Result<(), String> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: SDDL ancho terminado en NUL; `sd` es un destino valido; se libera con LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    } == 0
    {
        return Err(format!("SDDL invalido: {sddl}"));
    }
    let result = (|| {
        let (mut owner, mut dacl) = (null_mut(), null_mut());
        let (mut defaulted, mut present) = (0i32, 0i32);
        // SAFETY: `sd` es un descriptor valido recien creado; destinos validos.
        let ok = unsafe {
            GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) != 0
                && GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) != 0
        };
        if !ok || owner.is_null() || present == 0 || dacl.is_null() {
            return Err(format!("el SDDL debe tener dueno y DACL: {sddl}"));
        }
        let name = wide(path.as_os_str());
        // SAFETY: ruta ancha terminada en NUL; dueno y DACL apuntan dentro de `sd`, vivo durante la llamada.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if rc != 0 {
            return Err(format!(
                "{}: SetNamedSecurityInfoW fallo (Win32={rc})",
                path.display()
            ));
        }
        Ok(())
    })();
    // SAFETY: `sd` lo asigno la API de conversion (LocalAlloc) y no se usa despues.
    unsafe { LocalFree(sd) };
    result
}

/// Solo pruebas: suplanta en el hilo actual un duplicado del token del proceso cuyo dueno por
/// defecto es el SID del usuario (no Administradores), como el de un instalador no elevado o el de
/// una cuenta cuyo token no tiene a BA como dueno por defecto. Se revierte al soltarse.
#[cfg(test)]
pub(crate) mod test_token {
    use super::*;

    const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
    const SECURITY_IMPERSONATION: i32 = 2;
    const TOKEN_IMPERSONATION: i32 = 2;
    const TOKEN_USER_CLASS: i32 = 1;
    const TOKEN_OWNER_CLASS: i32 = 4;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn DuplicateTokenEx(
            existing: *mut c_void,
            access: u32,
            attrs: *mut c_void,
            level: i32,
            kind: i32,
            new: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: i32,
            info: *mut c_void,
            len: u32,
            ret: *mut u32,
        ) -> i32;
        fn SetTokenInformation(token: *mut c_void, class: i32, info: *mut c_void, len: u32) -> i32;
        fn SetThreadToken(thread: *mut c_void, token: *mut c_void) -> i32;
        fn RevertToSelf() -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    pub struct UserOwnerImpersonation(*mut c_void);

    impl UserOwnerImpersonation {
        pub fn start() -> Self {
            // SAFETY: llamadas documentadas con destinos validos; los manejadores se cierran en Drop.
            unsafe {
                let mut process = null_mut();
                assert_ne!(
                    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut process),
                    0
                );
                let mut dup = null_mut();
                assert_ne!(
                    DuplicateTokenEx(
                        process,
                        TOKEN_ALL_ACCESS,
                        null_mut(),
                        SECURITY_IMPERSONATION,
                        TOKEN_IMPERSONATION,
                        &mut dup
                    ),
                    0
                );
                CloseHandle(process);
                let mut buf = [0u8; 256];
                let mut len = 0u32;
                assert_ne!(
                    GetTokenInformation(
                        dup,
                        TOKEN_USER_CLASS,
                        buf.as_mut_ptr().cast(),
                        256,
                        &mut len
                    ),
                    0
                );
                // TOKEN_USER empieza por el puntero al SID del usuario; TOKEN_OWNER es ese mismo puntero.
                let mut owner = buf.as_ptr().cast::<*mut c_void>().read_unaligned();
                assert_ne!(
                    SetTokenInformation(
                        dup,
                        TOKEN_OWNER_CLASS,
                        (&raw mut owner).cast(),
                        size_of::<*mut c_void>() as u32
                    ),
                    0
                );
                assert_ne!(SetThreadToken(null_mut(), dup), 0);
                Self(dup)
            }
        }
    }

    impl Drop for UserOwnerImpersonation {
        fn drop(&mut self) {
            // SAFETY: deja de suplantar en este hilo y cierra el duplicado.
            unsafe {
                RevertToSelf();
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_con_la_disposicion_de_windows() {
        let g = Guid::from_u128(0x000214f9_0000_0000_c000_000000000046);
        assert_eq!((g.data1, g.data2, g.data3), (0x000214f9, 0, 0));
        assert_eq!(g.data4, [0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
        assert_eq!(size_of::<Guid>(), 16);
    }

    #[test]
    fn lee_carpetas_conocidas() {
        let system = known_folder(&FOLDERID_SYSTEM, "System32").unwrap();
        assert!(system.join("schtasks.exe").exists());
    }
}
