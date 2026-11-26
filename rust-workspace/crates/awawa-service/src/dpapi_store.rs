//! Proteccion en reposo del verificador: DPAPI + archivo con DACL protegida + escritura atomica.
//!
//! - `protect`/`unprotect` usan `CryptProtectData`/`CryptUnprotectData` con `CRYPTPROTECT_UI_FORBIDDEN`
//!   y `CRYPTPROTECT_LOCAL_MACHINE` (ambito de maquina): cualquier identidad del equipo puede descifrar. El
//!   verificador lo deriva, lo protege y lo persiste solo el servicio (SYSTEM), que recibe la contrasena de
//!   `awawa-admin` por la pipe de administracion ([`crate::admin_pipe`]); `awawa-admin status` solo lo lee.
//!   La barrera de lectura es la DACL protegida SYSTEM/Administradores del archivo y del directorio; el
//!   verificador no es la contrasena, y DPAPI aporta cifrado en reposo e integridad (un blob alterado no descifra).
//! - Los archivos se crean con la DACL SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)` (solo SYSTEM y Administradores).
//! - Antes de leer o escribir se VALIDA la ubicacion ([`crate::trust`]): dueno SYSTEM/Administradores, DACL
//!   protegida sin escritura para otros y sin reparse points, tanto del directorio como del archivo. Un
//!   usuario estandar puede crear subdirectorios en `C:\ProgramData`; por eso un directorio preexistente
//!   inseguro es `InsecureLocation` (fail closed) y solo `install` lo endurece.
//! - `VerifierFileStore::save` escribe un archivo temporal en el mismo directorio y lo mueve sobre el
//!   destino con `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`, de modo que nunca queda un archivo parcial.

use core::ffi::c_void;
use core::fmt;
use core::ptr::{null, null_mut};
use std::fs::File;
use std::io::Write;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};

use awawa_protocol::unattended::{PasswordVerifierRecord, UnattendedError};

use crate::trust::{TrustPolicy, is_reparse_point, validate_location, validate_tree_owners};
use crate::winutil::{last_error, wide, wide_path};

/// DACL de archivos: dueno BUILTIN\Administrators y control total solo para SYSTEM y Administradores, sin herencia.
/// El dueno se fija al crear (no depende del TokenOwner del proceso); ver `open_raw` para el respaldo.
pub const FILE_DACL_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
/// DACL del directorio contenedor: igual, heredable por archivos y subdirectorios.
pub const DIR_DACL_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;
const SDDL_REVISION_1: u32 = 1;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const CREATE_NEW: u32 = 1;
const OPEN_ALWAYS: u32 = 4;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
const INVALID_HANDLE_VALUE: isize = -1;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_INVALID_OWNER: u32 = 1307;
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

/// `SECURITY_ATTRIBUTES` de Win32.
#[repr(C)]
pub struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        p_data_in: *const DataBlob,
        sz_data_descr: *const u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut c_void,
        p_prompt_struct: *mut c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        pv_reserved: *mut c_void,
        p_prompt_struct: *mut c_void,
        dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorOwner(
        sd: *mut c_void,
        owner: *mut *mut c_void,
        owner_defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        sd: *mut c_void,
        dacl_present: *mut i32,
        dacl: *mut *mut c_void,
        dacl_defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: i32,
        security_info: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
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
    ) -> *mut c_void;
    fn CreateDirectoryW(
        lp_path_name: *const u16,
        lp_security_attributes: *const SecurityAttributes,
    ) -> i32;
    fn MoveFileExW(
        lp_existing_file_name: *const u16,
        lp_new_file_name: *const u16,
        dw_flags: u32,
    ) -> i32;
}

/// Error del almacen del verificador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(String),
    /// Fallo al construir el descriptor de seguridad desde SDDL (codigo Win32).
    Sddl(u32),
    /// Fallo de DPAPI (codigo Win32); incluye blobs manipulados.
    Dpapi {
        op: &'static str,
        code: u32,
    },
    /// El contenido descifrado no es un registro valido.
    Record(UnattendedError),
    /// Ubicacion no confiable (dueno ajeno, DACL laxa/heredada, reparse point): fail closed.
    InsecureLocation(String),
    /// Otro proceso mantiene el bloqueo exclusivo del almacen.
    LockBusy,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "error de E/S del almacen del verificador: {m}"),
            Self::Sddl(c) => write!(f, "no se pudo crear la DACL protegida (Win32={c})"),
            Self::Dpapi { op, code } => write!(f, "fallo de DPAPI en {op} (Win32={code})"),
            Self::Record(e) => write!(f, "{e}"),
            Self::InsecureLocation(m) => write!(f, "ubicacion no confiable: {m}"),
            Self::LockBusy => write!(f, "el almacen esta bloqueado por otra operacion"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Descriptor de seguridad construido desde SDDL; se libera con `LocalFree` al soltarse.
pub struct ProtectedSecurity {
    descriptor: *mut c_void,
}

impl ProtectedSecurity {
    pub fn from_sddl(sddl: &str) -> Result<Self, StoreError> {
        let w = wide(sddl);
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: `w` es una cadena ancha terminada en NUL; `descriptor` es un destino valido y el
        // tamano de salida es opcional (nulo). El buffer devuelto se libera en `Drop` con `LocalFree`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(StoreError::Sddl(last_error()));
        }
        Ok(Self { descriptor })
    }

    /// Dueno del descriptor (nulo si el SDDL no lo define); valido mientras `self` viva.
    fn owner(&self) -> *mut c_void {
        let mut owner: *mut c_void = null_mut();
        let mut defaulted = 0i32;
        // SAFETY: descriptor valido; destinos validos; el SID apunta dentro del descriptor.
        if unsafe { GetSecurityDescriptorOwner(self.descriptor, &mut owner, &mut defaulted) } == 0 {
            return null_mut();
        }
        owner
    }

    /// DACL del descriptor (nula si no existe); valida mientras `self` viva.
    fn dacl(&self) -> *mut c_void {
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut acl: *mut c_void = null_mut();
        // SAFETY: descriptor valido; destinos validos; la ACL apunta dentro del descriptor.
        let ok = unsafe {
            GetSecurityDescriptorDacl(self.descriptor, &mut present, &mut acl, &mut defaulted)
        };
        if ok == 0 || present == 0 {
            null_mut()
        } else {
            acl
        }
    }

    /// Atributos que referencian este descriptor; validos mientras `self` viva.
    pub fn attributes(&self) -> SecurityAttributes {
        SecurityAttributes {
            n_length: size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: self.descriptor,
            b_inherit_handle: 0,
        }
    }
}

impl Drop for ProtectedSecurity {
    fn drop(&mut self) {
        // SAFETY: `descriptor` fue asignado por la API de conversion SDDL (memoria LocalAlloc) y no se libera antes.
        unsafe { LocalFree(self.descriptor) };
    }
}

/// Modo de apertura de archivos protegidos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// Crea un archivo nuevo para escritura exclusiva (`CREATE_NEW`).
    CreateNew,
    /// Abre/crea para anexar, compartiendo lectura/escritura (`OPEN_ALWAYS`).
    Append,
    /// Abre/crea sin compartir (`OPEN_ALWAYS`, share 0): sirve de bloqueo exclusivo entre procesos.
    Lock,
}

fn has_owner(sddl: &str) -> bool {
    sddl.starts_with("O:")
}

/// SDDL sin la parte de dueno (`O:xx`), para el respaldo cuando el SO no deja fijar el dueno al crear.
fn strip_owner(sddl: &str) -> &str {
    if has_owner(sddl) {
        sddl.find("D:").map_or(sddl, |i| &sddl[i..])
    } else {
        sddl
    }
}

/// SDDL transitorio del respaldo: sin dueno explicito y con control total para OWNER RIGHTS, de modo que el
/// creador (aun sin ser administrador) pueda fijar la seguridad definitiva o eliminar el objeto si falla.
/// La DACL definitiva (sin esa ACE) se aplica despues con `apply_owner_and_dacl`.
fn fallback_sddl(sddl: &str) -> String {
    format!("{}(A;;FA;;;OW)", strip_owner(sddl))
}

/// Fija dueno y DACL protegida de un objeto existente con `SetNamedSecurityInfoW`, tomando ambos del SDDL
/// (sin dueno en el SDDL solo se fija la DACL). Exige un token con derecho a asignar ese dueno
/// (administrador elevado para BUILTIN\Administrators).
fn apply_owner_and_dacl(path: &Path, sddl: &str) -> Result<(), StoreError> {
    let security = ProtectedSecurity::from_sddl(sddl)?;
    let owner = security.owner();
    let acl = security.dacl();
    if acl.is_null() {
        return Err(StoreError::Sddl(0));
    }
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if !owner.is_null() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    let mut w = wide_path(path);
    // SAFETY: ruta ancha mutable terminada en NUL; dueno y ACL apuntan al descriptor vivo en `security`;
    // PROTECTED_DACL impide heredar permisos del padre.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            w.as_mut_ptr(),
            SE_FILE_OBJECT,
            info,
            owner,
            null_mut(),
            acl,
            null_mut(),
        )
    };
    if rc != 0 {
        return Err(StoreError::Io(format!(
            "SetNamedSecurityInfoW fallo para {} (Win32={rc}); se requiere administrador elevado",
            path.display()
        )));
    }
    Ok(())
}

/// Abre/crea un archivo con la DACL (y dueno) del SDDL. Si el SO rechaza el dueno al crear
/// (`ERROR_INVALID_OWNER`), crea sin dueno explicito y lo fija despues con `SetNamedSecurityInfoW`; si eso
/// tampoco es posible (token sin elevar) el archivo recien creado se elimina y se devuelve error.
fn open_raw(path: &Path, sddl: &str, mode: FileMode) -> Result<Result<File, u32>, StoreError> {
    let existed = path.exists();
    match create_once(path, sddl, mode)? {
        Err(ERROR_INVALID_OWNER) if has_owner(sddl) => {}
        other => return Ok(other),
    }
    match create_once(path, &fallback_sddl(sddl), mode)? {
        Err(code) => return Ok(Err(code)),
        Ok(file) => drop(file), // el manejo con share 0 impediria fijar la seguridad
    }
    if let Err(e) = apply_owner_and_dacl(path, sddl) {
        if !existed {
            let _ = std::fs::remove_file(path);
        }
        return Err(e);
    }
    use std::os::windows::fs::OpenOptionsExt;
    let reopened = match mode {
        FileMode::Append => std::fs::OpenOptions::new()
            .append(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path),
        FileMode::CreateNew | FileMode::Lock => std::fs::OpenOptions::new()
            .write(true)
            .share_mode(0)
            .open(path),
    };
    match reopened {
        Ok(f) => Ok(Ok(f)),
        Err(e) => Ok(Err(e.raw_os_error().unwrap_or(0) as u32)),
    }
}

/// Un intento de CreateFileW con el SDDL tal cual; la DACL solo se aplica al crear.
/// El resultado interno es el codigo Win32 si falla la apertura.
fn create_once(path: &Path, sddl: &str, mode: FileMode) -> Result<Result<File, u32>, StoreError> {
    let security = ProtectedSecurity::from_sddl(sddl)?;
    let attrs = security.attributes();
    let w = wide_path(path);
    let (access, share, disposition) = match mode {
        FileMode::Append => (
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_ALWAYS,
        ),
        FileMode::CreateNew => (GENERIC_WRITE, 0, CREATE_NEW),
        FileMode::Lock => (GENERIC_WRITE, 0, OPEN_ALWAYS),
    };
    // SAFETY: `w` es una ruta ancha terminada en NUL; `attrs` referencia un descriptor valido durante
    // la llamada; el resto de parametros son valores documentados.
    let handle = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            share,
            &attrs,
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle as isize == INVALID_HANDLE_VALUE {
        return Ok(Err(last_error()));
    }
    // SAFETY: `handle` es un manejador de archivo valido recien creado y propiedad exclusiva de `File`.
    Ok(Ok(unsafe { File::from_raw_handle(handle) }))
}

/// Abre/crea un archivo con la DACL SDDL indicada (ver [`FileMode`]).
pub fn create_protected_file(path: &Path, sddl: &str, mode: FileMode) -> Result<File, StoreError> {
    open_raw(path, sddl, mode)?
        .map_err(|code| StoreError::Io(format!("CreateFileW fallo (Win32={code})")))
}

/// Crea un directorio con la DACL SDDL indicada (error si ya existe).
pub fn create_dir_with_sddl(path: &Path, sddl: &str) -> Result<(), StoreError> {
    let security = ProtectedSecurity::from_sddl(sddl)?;
    let attrs = security.attributes();
    let w = wide_path(path);
    // SAFETY: `w` es una ruta ancha terminada en NUL; `attrs` es valido durante la llamada.
    if unsafe { CreateDirectoryW(w.as_ptr(), &attrs) } != 0 {
        return Ok(());
    }
    let code = last_error();
    if code == ERROR_INVALID_OWNER && has_owner(sddl) {
        // Respaldo: crear sin dueno explicito y fijarlo despues; si no se puede, se elimina el directorio.
        create_dir_with_sddl(path, &fallback_sddl(sddl))?;
        if let Err(e) = apply_owner_and_dacl(path, sddl) {
            let _ = std::fs::remove_dir(path);
            return Err(e);
        }
        return Ok(());
    }
    Err(StoreError::Io(format!(
        "CreateDirectoryW fallo para {} (Win32={code})",
        path.display()
    )))
}

/// Garantiza un directorio de confianza con la politica de produccion (SYSTEM/Administradores).
pub fn ensure_protected_dir(path: &Path) -> Result<(), StoreError> {
    ensure_protected_dir_with(path, DIR_DACL_SDDL, &TrustPolicy::production())
}

/// Si el directorio no existe lo crea con `sddl`; en todos los casos lo VALIDA contra `policy`.
/// Un directorio preexistente inseguro (dueno ajeno, DACL laxa o heredada, reparse point) es
/// `InsecureLocation`: NO se corrige en silencio (fail closed). Solo `install` endurece (ver
/// [`harden_protected_dir`]).
pub fn ensure_protected_dir_with(
    path: &Path,
    sddl: &str,
    policy: &TrustPolicy,
) -> Result<(), StoreError> {
    if std::fs::symlink_metadata(path).is_err() {
        create_dir_with_sddl(path, sddl)?;
        // Recien creado por nosotros: si no cumple la politica (p. ej. dueno no fijable sin elevar) se elimina.
        if let Err(e) = validate_location(path, policy) {
            let _ = std::fs::remove_dir(path);
            return Err(e);
        }
        return Ok(());
    }
    validate_location(path, policy)
}

/// Solo para `install` (administrador elevado): crea el directorio si falta; si ya existe NO lo adopta
/// salvo que el directorio y todos sus descendientes tengan dueno SYSTEM/Administradores y ningun reparse
/// point (si no, error pidiendo limpieza manual). Luego fuerza dueno BUILTIN\Administrators y la DACL
/// protegida de [`DIR_DACL_SDDL`] con `SetNamedSecurityInfoW` (propaga a los hijos heredables) y valida.
/// No se puede probar sin elevacion.
pub fn harden_protected_dir(path: &Path) -> Result<(), StoreError> {
    let production = TrustPolicy::production();
    if std::fs::symlink_metadata(path).is_err() {
        create_dir_with_sddl(path, DIR_DACL_SDDL)?;
    } else {
        // Reparse point ANTES de tocar la seguridad: SetNamedSecurityInfoW seguiria el enlace.
        if is_reparse_point(path)? {
            return Err(StoreError::InsecureLocation(format!(
                "{}: es un punto de reanalisis; eliminelo manualmente antes de instalar",
                path.display()
            )));
        }
        validate_tree_owners(path, &production).map_err(|e| {
            StoreError::InsecureLocation(format!(
                "directorio preexistente no confiable ({e}); eliminelo o limpielo manualmente antes de instalar"
            ))
        })?;
    }
    apply_owner_and_dacl(path, DIR_DACL_SDDL)?;
    validate_location(path, &production)
}

fn zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` es una referencia mutable valida; la escritura volatil evita que se elimine el borrado.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Cifra `data` con DPAPI en ambito de maquina (`LOCAL_MACHINE`), sin UI.
pub fn protect(data: &[u8]) -> Result<Vec<u8>, StoreError> {
    let input = DataBlob {
        cb_data: u32::try_from(data.len())
            .map_err(|_| StoreError::Io("blob demasiado grande".into()))?,
        pb_data: data.as_ptr().cast_mut(),
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: null_mut(),
    };
    // SAFETY: `input` describe `data` (solo lectura, vida >= llamada); `output` es un destino valido;
    // los parametros opcionales son nulos. El buffer de salida se libera con `LocalFree` abajo.
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(StoreError::Dpapi {
            op: "CryptProtectData",
            code: last_error(),
        });
    }
    // SAFETY: tras el exito, `pb_data` apunta a `cb_data` bytes validos asignados por DPAPI.
    let blob =
        unsafe { core::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }.to_vec();
    // SAFETY: el buffer fue asignado por DPAPI con LocalAlloc y no se usa despues.
    unsafe { LocalFree(output.pb_data.cast()) };
    Ok(blob)
}

/// Descifra un blob DPAPI. Falla si el blob fue alterado.
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, StoreError> {
    let input = DataBlob {
        cb_data: u32::try_from(blob.len())
            .map_err(|_| StoreError::Io("blob demasiado grande".into()))?,
        pb_data: blob.as_ptr().cast_mut(),
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: null_mut(),
    };
    // SAFETY: `input` describe `blob` (solo lectura, vida >= llamada); `output` es un destino valido;
    // la descripcion y los parametros opcionales son nulos. El buffer de salida se borra y libera abajo.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(StoreError::Dpapi {
            op: "CryptUnprotectData",
            code: last_error(),
        });
    }
    // SAFETY: tras el exito, `pb_data` apunta a `cb_data` bytes validos y mutables asignados por DPAPI.
    let plain = unsafe { core::slice::from_raw_parts_mut(output.pb_data, output.cb_data as usize) };
    let result = plain.to_vec();
    zero(plain);
    // SAFETY: el buffer fue asignado por DPAPI con LocalAlloc y no se usa despues.
    unsafe { LocalFree(output.pb_data.cast()) };
    Ok(result)
}

/// Almacen en archivo del registro verificador (DPAPI + DACL protegida + reemplazo atomico).
/// Valida el directorio y el archivo (dueno, DACL, reparse points) antes de leer o escribir.
#[derive(Debug, Clone)]
pub struct VerifierFileStore {
    path: PathBuf,
    dacl: String,
    policy: TrustPolicy,
}

/// Bloqueo exclusivo entre procesos del almacen; se libera al soltarse.
#[derive(Debug)]
pub struct StoreLock {
    _file: File,
}

impl VerifierFileStore {
    /// Almacen de produccion: DACL [`FILE_DACL_SDDL`] y politica SYSTEM/Administradores.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_policy(path, FILE_DACL_SDDL, TrustPolicy::production())
    }

    /// Almacen con DACL y politica propias (pruebas en directorios temporales).
    pub fn with_policy(path: impl Into<PathBuf>, sddl: &str, policy: TrustPolicy) -> Self {
        Self {
            path: path.into(),
            dacl: sddl.to_owned(),
            policy,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn validate_dir(&self) -> Result<(), StoreError> {
        match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => validate_location(dir, &self.policy),
            _ => Ok(()),
        }
    }

    /// Intenta tomar el bloqueo exclusivo (`admin.lock` junto al verificador) sin esperar.
    pub fn try_lock(&self) -> Result<StoreLock, StoreError> {
        self.validate_dir()?;
        let lock_path = self.path.with_file_name("admin.lock");
        match open_raw(&lock_path, &self.dacl, FileMode::Lock)? {
            Ok(file) => {
                // El archivo de bloqueo tambien debe ser de confianza (dueno/DACL).
                validate_location(&lock_path, &self.policy)?;
                Ok(StoreLock { _file: file })
            }
            Err(ERROR_SHARING_VIOLATION) => Err(StoreError::LockBusy),
            Err(code) => Err(StoreError::Io(format!(
                "CreateFileW(admin.lock) fallo (Win32={code})"
            ))),
        }
    }

    /// Toma el bloqueo exclusivo esperando hasta ~10 s.
    pub fn lock(&self) -> Result<StoreLock, StoreError> {
        for _ in 0..100 {
            match self.try_lock() {
                Err(StoreError::LockBusy) => {
                    std::thread::sleep(std::time::Duration::from_millis(100))
                }
                other => return other,
            }
        }
        Err(StoreError::LockBusy)
    }

    /// Guarda el registro (tambien el revocado) de forma atomica.
    pub fn save(&self, record: &PasswordVerifierRecord) -> Result<(), StoreError> {
        self.validate_dir()?;
        let mut bytes = record.to_bytes();
        let protected = protect(&bytes);
        zero(&mut bytes);
        let blob = protected?;

        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "verifier".into());
        let temp = self
            .path
            .with_file_name(format!("{name}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&temp);

        let write_result = (|| -> Result<(), StoreError> {
            let mut file = create_protected_file(&temp, &self.dacl, FileMode::CreateNew)?;
            file.write_all(&blob)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }

        // El temporal debe cumplir la misma politica que `load` exigira: si no, nunca se publica.
        if let Err(e) = validate_location(&temp, &self.policy) {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }

        let from = wide_path(&temp);
        let to = wide_path(&self.path);
        // SAFETY: ambas rutas son cadenas anchas terminadas en NUL validas durante la llamada.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let code = last_error();
            let _ = std::fs::remove_file(&temp);
            return Err(StoreError::Io(format!("MoveFileExW fallo (Win32={code})")));
        }
        // Verificacion posterior con la lectura real: nunca se informa exito con un verificador que `load` rechazaria.
        match self.load()? {
            Some(loaded) if loaded.to_bytes() == record.to_bytes() => Ok(()),
            _ => Err(StoreError::Io(
                "el verificador guardado no coincide al releerlo".into(),
            )),
        }
    }

    /// Carga el registro. `Ok(None)` si el archivo no existe; error si la ubicacion no es de confianza
    /// (`InsecureLocation`), esta manipulado o es invalido (el llamador debe tratarlo como acceso
    /// desatendido deshabilitado, no como "sin configurar").
    pub fn load(&self) -> Result<Option<PasswordVerifierRecord>, StoreError> {
        // Sin archivo no hay nada en que confiar: no configurado (un directorio inexistente tampoco es error).
        if std::fs::symlink_metadata(&self.path).is_err() {
            return Ok(None);
        }
        self.validate_dir()?;
        validate_location(&self.path, &self.policy)?;
        let blob = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut plain = unprotect(&blob)?;
        let parsed = PasswordVerifierRecord::from_bytes(&plain);
        zero(&mut plain);
        parsed.map(Some).map_err(StoreError::Record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        TempDir, current_sid, safe_dir, test_dir_dacl, test_file_dacl, test_policy,
    };
    use awawa_protocol::unattended::{
        PasswordKdf, UnattendedCredentialState, UnattendedStatus, VerifierStatus,
    };

    /// KDF determinista solo para estas pruebas (no criptografico).
    struct FakeKdf;
    impl PasswordKdf for FakeKdf {
        fn derive(
            &self,
            password: &[u8],
            salt: &[u8; 16],
            _params: awawa_protocol::unattended::VerifierKdfParams,
            out: &mut [u8; 32],
        ) -> Result<(), awawa_protocol::unattended::KdfError> {
            for (i, o) in out.iter_mut().enumerate() {
                *o = password[i % password.len()] ^ salt[i % 16];
            }
            Ok(())
        }
    }

    fn test_store(dir: &Path) -> VerifierFileStore {
        VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        )
    }

    fn configured_state() -> UnattendedCredentialState {
        let mut state = UnattendedCredentialState::not_configured();
        state.configure("clave-de-prueba-1", &FakeKdf).unwrap();
        state
    }

    #[test]
    fn dpapi_roundtrip() {
        let data = b"registro de prueba 0123456789";
        let blob = protect(data).unwrap();
        assert_ne!(blob.as_slice(), data.as_slice());
        assert_eq!(unprotect(&blob).unwrap(), data);
    }

    /// El blob se produce con ambito de maquina y el formato del registro (v2: 72 bytes, magic "UAPV") no cambia.
    #[test]
    fn ambito_de_maquina_y_formato_del_registro_intacto() {
        let bytes = configured_state().record().unwrap().to_bytes();
        assert_eq!(bytes.len(), 72);
        assert_eq!(&bytes[..4], b"UAPV");
        let blob = protect(&bytes).unwrap();
        assert_eq!(unprotect(&blob).unwrap(), bytes);
        // Cabecera del blob DPAPI: version (4) + GUID proveedor (16) + version clave maestra (4) + GUID clave
        // maestra (16) + dwFlags (4, offset 40): el bit 0x4 indica ambito de maquina.
        let flags = u32::from_le_bytes(blob[40..44].try_into().unwrap());
        assert_eq!(
            flags & CRYPTPROTECT_LOCAL_MACHINE,
            CRYPTPROTECT_LOCAL_MACHINE
        );
    }

    #[test]
    fn dpapi_detecta_manipulacion() {
        let mut blob = protect(b"registro de prueba").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            unprotect(&blob),
            Err(StoreError::Dpapi {
                op: "CryptUnprotectData",
                ..
            })
        ));
    }

    #[test]
    fn store_guarda_y_carga_registro_y_reemplaza() {
        let tmp = TempDir::new("store");
        let dir = safe_dir(&tmp);
        let store = test_store(&dir);
        assert!(store.load().unwrap().is_none());

        let mut state = configured_state();
        store.save(state.record().unwrap()).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.to_bytes(), state.record().unwrap().to_bytes());

        // Revocar guarda el registro revocado (no borra el archivo) y reemplaza al anterior.
        state.revoke().unwrap();
        store.save(state.record().unwrap()).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.status(), VerifierStatus::Revoked);
        assert_eq!(
            UnattendedCredentialState::from_record(loaded).status(),
            UnattendedStatus::Revoked { generation: 2 }
        );

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, vec!["unattended.verifier".to_string()]);
    }

    /// El almacen acepta los dos tamanos de registro: un v1 (64 bytes) se guarda y se relee sin cambios.
    #[test]
    fn store_acepta_registro_v1_sin_reescribirlo() {
        let tmp = TempDir::new("storev1");
        let dir = safe_dir(&tmp);
        let store = test_store(&dir);
        let v1 = crate::kdf_argon2::v1_vector_bytes();
        let record = awawa_protocol::unattended::PasswordVerifierRecord::from_bytes(&v1).unwrap();
        store.save(&record).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.version(), 1);
        assert_eq!(loaded.to_bytes(), v1);
    }

    #[test]
    fn store_rechaza_archivo_manipulado() {
        let tmp = TempDir::new("tamper");
        let dir = safe_dir(&tmp);
        let store = test_store(&dir);
        store.save(configured_state().record().unwrap()).unwrap();

        // Se altera el contenido conservando la ubicacion segura: el fallo es de DPAPI.
        let path = store.path().to_path_buf();
        let mut raw = std::fs::read(&path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        std::fs::write(&path, raw).unwrap();
        assert!(matches!(store.load(), Err(StoreError::Dpapi { .. })));
    }

    #[test]
    fn directorio_seguro_se_acepta_y_es_idempotente() {
        let tmp = TempDir::new("dir");
        let sub = tmp.path().join("Awawa");
        ensure_protected_dir_with(&sub, &test_dir_dacl(), &test_policy()).unwrap();
        assert!(sub.is_dir());
        ensure_protected_dir_with(&sub, &test_dir_dacl(), &test_policy()).unwrap();
    }

    #[test]
    fn directorio_con_ace_everyone_w_se_rechaza() {
        let tmp = TempDir::new("lax");
        let sub = tmp.path().join("lax");
        let sid = current_sid();
        let lax = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;WD)");
        create_dir_with_sddl(&sub, &lax).unwrap();
        match ensure_protected_dir_with(&sub, &lax, &test_policy()) {
            Err(StoreError::InsecureLocation(m)) => assert!(m.contains("S-1-1-0"), "{m}"),
            other => panic!("se esperaba InsecureLocation: {other:?}"),
        }
        // Un almacen en ese directorio tambien falla cerrado al cargar y al guardar.
        let store = test_store(&sub);
        assert!(matches!(store.load(), Ok(None))); // sin archivo no hay nada en que confiar
        create_protected_file(store.path(), &test_file_dacl(), FileMode::CreateNew).unwrap();
        assert!(matches!(store.load(), Err(StoreError::InsecureLocation(_))));
        assert!(matches!(
            store.save(configured_state().record().unwrap()),
            Err(StoreError::InsecureLocation(_))
        ));
    }

    #[test]
    fn directorio_con_dacl_heredada_se_rechaza() {
        let tmp = TempDir::new("inherit");
        let sub = tmp.path().join("hereda");
        std::fs::create_dir(&sub).unwrap(); // DACL heredada del padre, no protegida
        assert!(matches!(
            ensure_protected_dir_with(&sub, &test_dir_dacl(), &test_policy()),
            Err(StoreError::InsecureLocation(_))
        ));
    }

    #[test]
    fn dueno_no_confiable_se_rechaza() {
        // Politica solo-SYSTEM: el directorio creado por la prueba (dueno: el usuario o Administradores) se rechaza.
        let tmp = TempDir::new("owner");
        let sub = tmp.path().join("d");
        create_dir_with_sddl(&sub, &test_dir_dacl()).unwrap();
        match validate_location(&sub, &TrustPolicy::only(&[crate::trust::SID_SYSTEM])) {
            Err(StoreError::InsecureLocation(m)) => {
                assert!(m.contains("dueno no confiable"), "{m}")
            }
            other => panic!("se esperaba InsecureLocation por dueno: {other:?}"),
        }
    }

    #[test]
    fn archivo_plantado_con_dacl_laxa_no_carga() {
        let tmp = TempDir::new("planted");
        let dir = safe_dir(&tmp);
        let store = test_store(&dir);
        // Archivo con Everyone:W en un directorio seguro.
        let sid = current_sid();
        let lax = format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;WD)");
        let mut f = create_protected_file(store.path(), &lax, FileMode::CreateNew).unwrap();
        let blob = protect(&configured_state().record().unwrap().to_bytes()).unwrap();
        f.write_all(&blob).unwrap();
        drop(f);
        assert!(matches!(store.load(), Err(StoreError::InsecureLocation(_))));
    }

    #[test]
    fn junction_se_rechaza() {
        let tmp = TempDir::new("junction");
        let target = safe_dir(&tmp);
        let link = tmp.path().join("enlace");
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("mklink");
        assert!(out.status.success(), "mklink /J fallo");
        let verdict = validate_location(&link, &test_policy());
        // La junction se quita antes de que el TempDir borre el arbol, para no seguirla.
        std::fs::remove_dir(&link).unwrap();
        match verdict {
            Err(StoreError::InsecureLocation(m)) => assert!(m.contains("reanalisis"), "{m}"),
            other => panic!("se esperaba InsecureLocation: {other:?}"),
        }
    }

    #[test]
    fn bloqueo_exclusivo_entre_tomas() {
        let tmp = TempDir::new("lock");
        let dir = safe_dir(&tmp);
        let store = test_store(&dir);
        let guard = store.try_lock().unwrap();
        assert!(matches!(store.try_lock(), Err(StoreError::LockBusy)));
        drop(guard);
        assert!(store.try_lock().is_ok());
    }
}
