//! Persistencia de la identidad del relay en disco: escritura atomica y, para la clave privada, DACL
//! restringida (Windows).
//!
//! Escritura: los bytes se escriben en un temporal `<archivo>.<pid>.tmp` de la misma carpeta, se
//! sincronizan y se renombran sobre el destino (`std::fs::rename`, que en Windows usa `MoveFileExW` con
//! `MOVEFILE_REPLACE_EXISTING`). Si el destino ya existe se reemplaza sin avisar: el binario solo
//! escribe cuando no existen ni certificado ni clave, asi que el reemplazo solo ocurriria si otro
//! proceso crea el archivo entre la comprobacion y el renombrado. Si algo falla, el temporal se borra.
//!
//! DACL de la clave (`KEY_DACL_SDDL`): protegida (no hereda de la carpeta) con control total solo para
//! el dueno del archivo (`OW`, el usuario que ejecuta el relay), SYSTEM (`SY`) y Administradores (`BA`).
//! Se aplica al crear el temporal (`CreateFileW` con `SECURITY_ATTRIBUTES`), antes de escribir un solo
//! byte, y se conserva al renombrar. Como el descriptor no fija dueno, no requiere elevacion.
//!
//! Lectura: `check_key_acl` falla cerrado si la DACL de una clave existente no es exactamente de ese
//! tipo (protegida y solo `OW`/`SY`/`BA`). Fuera de Windows no hay DACL y la comprobacion no aplica.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// DACL de `relay-key.der`: protegida; control total para el dueno (`OW`), SYSTEM y Administradores.
#[cfg(windows)]
pub const KEY_DACL_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

/// Argumentos de `icacls` que dejan la clave con la DACL aceptada por `check_key_acl` (icacls marca la
/// DACL como protegida y de herencia automatica: `D:PAI(...)`, que se acepta igual que `D:P(...)`).
#[cfg(windows)]
const ICACLS_FIX_ARGS: &str = "/inheritance:r /grant:r *S-1-3-4:F *S-1-5-18:F *S-1-5-32-544:F";

/// Escribe `bytes` de forma atomica en `path` con la DACL por defecto de la carpeta (material publico).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_via_temp(path, bytes, |tmp| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
    })
}

/// Escribe `bytes` de forma atomica en `path`; en Windows el archivo nace con `KEY_DACL_SDDL`.
pub fn write_key_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        write_via_temp(path, bytes, win::create_protected)
    }
    #[cfg(not(windows))]
    {
        write_atomic(path, bytes)
    }
}

/// Falla si la clave existente tiene una DACL distinta de `KEY_DACL_SDDL` (solo Windows).
pub fn check_key_acl(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let sddl = win::dacl_sddl(path)?;
        if win::dacl_is_restricted(&sddl) {
            return Ok(());
        }
        Err(format!(
            "{} tiene permisos inseguros (DACL {sddl}). Restrinjalos con el comando \
             `icacls \"{}\" {ICACLS_FIX_ARGS}` o borre relay-cert.der y relay-key.der \
             para generar una identidad nueva (habra que redistribuir el pin)",
            path.display(),
            path.display()
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

fn write_via_temp(
    path: &Path,
    bytes: &[u8],
    create: impl FnOnce(&Path) -> std::io::Result<File>,
) -> Result<(), String> {
    let mut name = path
        .file_name()
        .ok_or("ruta sin nombre de archivo")?
        .to_owned();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp: PathBuf = path.with_file_name(name);
    // Un temporal viejo de una ejecucion con el mismo PID que murio a medias no debe bloquear.
    let _ = std::fs::remove_file(&tmp);
    let result = (|| {
        let mut file = create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    use super::KEY_DACL_SDDL;

    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const INVALID_HANDLE_VALUE: isize = -1;
    const SE_FILE_OBJECT: i32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x4;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor: *mut c_void,
            requested_string_sd_revision: u32,
            security_information: u32,
            string_security_descriptor: *mut *mut u16,
            string_security_descriptor_len: *mut u32,
        ) -> i32;
        fn GetNamedSecurityInfoW(
            object_name: *const u16,
            object_type: i32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *const SecurityAttributes,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> isize;
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// Crea el archivo nuevo (exclusivo) con `KEY_DACL_SDDL` aplicada en la propia creacion.
    pub fn create_protected(path: &Path) -> std::io::Result<File> {
        let sddl: Vec<u16> = KEY_DACL_SDDL.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: `sddl` es una cadena ancha terminada en NUL; el descriptor devuelto (LocalAlloc) se
        // libera abajo con `LocalFree`; el tamano de salida es opcional.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let attrs = SecurityAttributes {
            n_length: size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: descriptor,
            b_inherit_handle: 0,
        };
        let w = wide(path);
        // SAFETY: ruta ancha terminada en NUL; `attrs` referencia un descriptor vivo durante la llamada.
        let handle = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_WRITE,
                0,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: `descriptor` lo asigno la conversion SDDL y no se usa despues de la llamada anterior.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: manejador de archivo valido recien creado, de propiedad exclusiva de `File`.
        Ok(unsafe { File::from_raw_handle(handle as *mut c_void) })
    }

    /// DACL de `path` en formato SDDL (`GetNamedSecurityInfoW` + conversion a texto).
    pub fn dacl_sddl(path: &Path) -> Result<String, String> {
        let w = wide(path);
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: ruta ancha terminada en NUL; solo se pide la DACL y el descriptor de salida se libera abajo.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if rc != 0 {
            return Err(format!(
                "{}: GetNamedSecurityInfoW fallo (Win32={rc})",
                path.display()
            ));
        }
        let mut text: *mut u16 = null_mut();
        // SAFETY: `descriptor` es valido hasta el `LocalFree`; `text` recibe una cadena LocalAlloc.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        let result = if ok == 0 {
            Err(format!(
                "{}: conversion a SDDL fallo: {error}",
                path.display()
            ))
        } else {
            // SAFETY: `text` es una cadena ancha terminada en NUL devuelta por la conversion.
            let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
            // SAFETY: `text` apunta a `len` unidades u16 validas hasta el `LocalFree` de abajo.
            let units = unsafe { std::slice::from_raw_parts(text, len) };
            Ok(String::from_utf16_lossy(units))
        };
        // SAFETY: ambos punteros los asigno el sistema con LocalAlloc y no se usan despues.
        unsafe {
            if !text.is_null() {
                LocalFree(text.cast());
            }
            LocalFree(descriptor);
        }
        result
    }

    /// `true` si la DACL (SDDL) es protegida (`P`, con o sin los flags `AI`/`AR` que ponen icacls, el
    /// Explorador y `Set-Acl`) y solo contiene ACE de permiso para `OW`, `SY` y `BA`.
    pub fn dacl_is_restricted(sddl: &str) -> bool {
        let Some(rest) = sddl.strip_prefix("D:") else {
            return false;
        };
        let (flags, aces) = rest.split_at(rest.find('(').unwrap_or(rest.len()));
        flags
            .strip_prefix('P')
            .is_some_and(|extra| matches!(extra, "" | "AI" | "AR" | "AIAR"))
            && aces.split(')').filter(|a| !a.is_empty()).all(|ace| {
                let fields: Vec<&str> = ace.trim_start_matches('(').split(';').collect();
                fields.len() == 6 && fields[0] == "A" && matches!(fields[5], "OW" | "SY" | "BA")
            })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::win::{dacl_is_restricted, dacl_sddl};
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("relay-keyfile-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn la_clave_nace_con_la_dacl_esperada_y_sin_temporal() {
        let dir = scratch("dacl");
        let key = dir.join("relay-key.der");
        write_key_atomic(&key, b"secreto").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), b"secreto");
        assert!(leftovers(&dir).is_empty(), "no debe quedar temporal");

        let sddl = dacl_sddl(&key).unwrap();
        let aces = |s: &str| {
            let mut v: Vec<String> = s
                .trim_start_matches("D:P")
                .split(')')
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
                .collect();
            v.sort();
            v
        };
        assert!(sddl.starts_with("D:P("), "DACL protegida: {sddl}");
        assert_eq!(aces(&sddl), aces(KEY_DACL_SDDL), "DACL leida: {sddl}");
        assert!(check_key_acl(&key).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reemplaza_un_destino_existente_de_forma_atomica() {
        let dir = scratch("replace");
        let key = dir.join("relay-key.der");
        write_key_atomic(&key, b"uno").unwrap();
        write_key_atomic(&key, b"dos").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), b"dos");
        assert!(leftovers(&dir).is_empty());
        assert!(
            check_key_acl(&key).is_ok(),
            "la DACL sobrevive al reemplazo"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_fallo_no_deja_temporal() {
        let dir = scratch("fallo");
        let key = dir.join("relay-key.der");
        // El destino es un directorio: el renombrado falla y el temporal debe retirarse.
        std::fs::create_dir(&key).unwrap();
        assert!(write_key_atomic(&key, b"x").is_err());
        assert!(leftovers(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_clave_con_permisos_heredados_falla_cerrado() {
        let dir = scratch("insegura");
        let key = dir.join("relay-key.der");
        std::fs::write(&key, b"secreto").unwrap(); // hereda la DACL de la carpeta
        let err = check_key_acl(&key).unwrap_err();
        assert!(err.contains("permisos inseguros"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn el_comando_icacls_del_mensaje_deja_una_clave_aceptada() {
        let dir = scratch("remedio");
        let key = dir.join("relay-key.der");
        std::fs::write(&key, b"secreto").unwrap(); // DACL heredada
        let err = check_key_acl(&key).unwrap_err();
        let command = format!("icacls \"{}\" {ICACLS_FIX_ARGS}", key.display());
        assert!(err.contains(&format!("`{command}`")), "{err}");

        let status = std::process::Command::new("icacls")
            .arg(&key)
            .args(ICACLS_FIX_ARGS.split_whitespace())
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
        let sddl = dacl_sddl(&key).unwrap();
        assert!(sddl.starts_with("D:PAI"), "icacls marca AI: {sddl}");
        assert!(check_key_acl(&key).is_ok(), "DACL tras icacls: {sddl}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clasifica_dacl_de_ejemplo() {
        assert!(dacl_is_restricted(KEY_DACL_SDDL));
        assert!(dacl_is_restricted("D:P(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert!(!dacl_is_restricted("D:(A;;FA;;;SY)(A;;FA;;;BA)"));
        assert!(dacl_is_restricted(
            "D:PAI(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(dacl_is_restricted("D:PAR(A;;FA;;;SY)"));
        assert!(!dacl_is_restricted("D:AI(A;;FA;;;SY)"));
        assert!(!dacl_is_restricted("D:PAI(A;;FA;;;SY)(A;;FA;;;BU)"));
        assert!(!dacl_is_restricted("D:PAI(D;;FA;;;BU)(A;;FA;;;SY)"));
        assert!(!dacl_is_restricted("D:PAI(A;;FA;;;SY)S:(AU;SA;FA;;;WD)"));
        assert!(!dacl_is_restricted("D:P(A;;FA;;;SY)(A;;FR;;;BU)"));
        assert!(!dacl_is_restricted("D:P(A;;FA;;;SY)(A;;FA;;;WD)"));
        assert!(!dacl_is_restricted("D:P(D;;FA;;;SY)"));
        assert!(!dacl_is_restricted("D:NO_ACCESS_CONTROL"));
    }
}
