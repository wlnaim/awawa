//! Validacion de ubicaciones de confianza (fail closed): un archivo o directorio solo es de confianza si no es
//! un punto de reanalisis, su dueno es un SID de confianza y su DACL esta protegida y no concede escritura,
//! borrado ni cambio de DACL/dueno a nadie fuera de los SID de confianza.
//!
//! Motivo: `C:\ProgramData` permite a usuarios estandar crear subdirectorios (quedan como CREATOR OWNER), de
//! modo que un directorio preexistente podria haber sido plantado para falsificar el verificador.

use core::ffi::c_void;
use core::ptr::null_mut;
use std::path::Path;

use crate::dpapi_store::StoreError;
use crate::identity::sid_to_string;
use crate::winutil::{last_error, wide_path};

pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
pub const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const SE_DACL_PROTECTED: u16 = 0x1000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const INHERIT_ONLY_ACE: u8 = 0x08;
/// Escritura de datos/archivos, anexar/subdirectorios, EA, borrar hijos, atributos, DELETE, WRITE_DAC,
/// WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL y MAXIMUM_ALLOWED.
const WRITE_LIKE_MASK: u32 = 0x2
    | 0x4
    | 0x10
    | 0x40
    | 0x100
    | 0x1_0000
    | 0x4_0000
    | 0x8_0000
    | 0x4000_0000
    | 0x1000_0000
    | 0x0200_0000;

#[repr(C)]
struct AclSizeInformation {
    ace_count: u32,
    acl_bytes_in_use: u32,
    acl_bytes_free: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
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
    fn GetSecurityDescriptorControl(sd: *mut c_void, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAclInformation(acl: *mut c_void, info: *mut c_void, len: u32, class: i32) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileAttributesW(path: *const u16) -> u32;
    fn LocalFree(h: *mut c_void) -> *mut c_void;
}

/// Politica de confianza: SID aceptados como dueno y como titulares de escritura/control.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    trustees: Vec<String>,
    require_protected_dacl: bool,
    /// Ignora las ACE de solo herencia (no aplican al propio objeto; p. ej. CREATOR OWNER en Program Files).
    ignore_inherit_only: bool,
}

impl TrustPolicy {
    /// Produccion: solo SYSTEM y BUILTIN\Administrators, DACL protegida.
    pub fn production() -> Self {
        Self {
            trustees: vec![SID_SYSTEM.into(), SID_ADMINISTRATORS.into()],
            require_protected_dacl: true,
            ignore_inherit_only: false,
        }
    }

    /// Solo los SID indicados, DACL protegida.
    pub fn only(sids: &[&str]) -> Self {
        Self {
            trustees: sids.iter().map(|s| (*s).to_owned()).collect(),
            require_protected_dacl: true,
            ignore_inherit_only: false,
        }
    }

    /// Ubicaciones de instalacion (Program Files): SYSTEM, Administradores y TrustedInstaller; la DACL
    /// hereda del padre por diseno y las ACE de solo herencia no cuentan.
    pub fn program_files() -> Self {
        Self {
            trustees: vec![
                SID_SYSTEM.into(),
                SID_ADMINISTRATORS.into(),
                SID_TRUSTED_INSTALLER.into(),
            ],
            require_protected_dacl: false,
            ignore_inherit_only: true,
        }
    }

    /// Agrega un SID de confianza (para pruebas: el usuario actual, que corre sin elevar).
    pub fn with_trustee(mut self, sid: &str) -> Self {
        self.trustees.push(sid.to_owned());
        self
    }

    pub fn is_trusted(&self, sid: &str) -> bool {
        self.trustees.iter().any(|t| t == sid)
    }
}

fn insecure(path: &Path, why: impl Into<String>) -> StoreError {
    StoreError::InsecureLocation(format!("{}: {}", path.display(), why.into()))
}

/// `true` si `path` es un punto de reanalisis (enlace simbolico, junction). No sigue el enlace.
pub fn is_reparse_point(path: &Path) -> Result<bool, StoreError> {
    let w = wide_path(path);
    // SAFETY: ruta ancha terminada en NUL; GetFileAttributesW no sigue el reparse point final.
    let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(StoreError::Io(format!(
            "GetFileAttributesW fallo para {} (Win32={})",
            path.display(),
            last_error()
        )));
    }
    Ok(attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// Valida que `path` (archivo o directorio existente) sea una ubicacion de confianza segun `policy`:
/// no reparse point, dueno de confianza, DACL (protegida si la politica lo exige) sin escritura ajena.
pub fn validate_location(path: &Path, policy: &TrustPolicy) -> Result<(), StoreError> {
    inspect(path, policy, true)
}

/// Valida solo que `path` no sea reparse point y que su dueno sea de confianza (no mira la DACL).
pub fn validate_owner(path: &Path, policy: &TrustPolicy) -> Result<(), StoreError> {
    inspect(path, policy, false)
}

/// Valida el dueno (y la ausencia de reparse points) de `root` y de TODOS sus descendientes.
pub fn validate_tree_owners(root: &Path, policy: &TrustPolicy) -> Result<(), StoreError> {
    validate_owner(root, policy)?;
    if root.is_dir() {
        for entry in std::fs::read_dir(root)? {
            let child = entry?.path();
            if is_reparse_point(&child)? {
                return Err(insecure(
                    &child,
                    "es un punto de reanalisis (enlace/junction)",
                ));
            }
            validate_tree_owners(&child, policy)?;
        }
    }
    Ok(())
}

fn inspect(path: &Path, policy: &TrustPolicy, full: bool) -> Result<(), StoreError> {
    if is_reparse_point(path)? {
        return Err(insecure(
            path,
            "es un punto de reanalisis (enlace/junction)",
        ));
    }
    let w = wide_path(path);

    let mut owner: *mut c_void = null_mut();
    let mut dacl: *mut c_void = null_mut();
    let mut sd: *mut c_void = null_mut();
    // SAFETY: ruta valida; destinos validos; el descriptor devuelto se libera abajo con LocalFree.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(StoreError::Io(format!(
            "GetNamedSecurityInfoW fallo para {} (Win32={rc})",
            path.display()
        )));
    }
    let result = check_descriptor(path, policy, owner, dacl, sd, full);
    // SAFETY: `sd` fue asignado por GetNamedSecurityInfoW (LocalAlloc) y no se usa despues.
    unsafe { LocalFree(sd) };
    result
}

fn check_descriptor(
    path: &Path,
    policy: &TrustPolicy,
    owner: *mut c_void,
    dacl: *mut c_void,
    sd: *mut c_void,
    full: bool,
) -> Result<(), StoreError> {
    // SAFETY: `owner` apunta a un SID dentro del descriptor `sd`, vivo durante esta funcion.
    let owner_sid =
        unsafe { sid_to_string(owner) }.ok_or_else(|| insecure(path, "dueno ilegible"))?;
    if !policy.is_trusted(&owner_sid) {
        return Err(insecure(path, format!("dueno no confiable {owner_sid}")));
    }
    if !full {
        return Ok(());
    }

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd` es un descriptor valido; destinos validos.
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
        return Err(insecure(path, "no se pudo leer el control del descriptor"));
    }
    if policy.require_protected_dacl && control & SE_DACL_PROTECTED == 0 {
        return Err(insecure(
            path,
            "la DACL no esta protegida (hereda permisos del padre)",
        ));
    }
    if dacl.is_null() {
        return Err(insecure(path, "DACL nula (acceso total para todos)"));
    }

    let mut info = AclSizeInformation {
        ace_count: 0,
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
    };
    // SAFETY: `dacl` es una ACL valida; `info` es del tamano indicado (clase 2 = AclSizeInformation).
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            size_of::<AclSizeInformation>() as u32,
            2,
        )
    };
    if ok == 0 {
        return Err(insecure(path, "no se pudo leer la DACL"));
    }
    for index in 0..info.ace_count {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: `index` < ace_count de una ACL valida.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(insecure(path, "ACE ilegible"));
        }
        // SAFETY: toda ACE empieza por una cabecera (tipo u8, flags u8, tamano u16).
        let (ace_type, ace_flags) = unsafe {
            let base = ace.cast::<u8>();
            (*base, *base.add(1))
        };
        // El tipo se comprueba ANTES de interpretar el resto: solo allowed/denied tienen mascara y SID
        // en las posiciones conocidas; cualquier otro tipo es no soportado (fail closed).
        match ace_type {
            ACCESS_DENIED_ACE_TYPE => continue,
            ACCESS_ALLOWED_ACE_TYPE => {}
            other => {
                return Err(insecure(
                    path,
                    format!("tipo de ACE no soportado ({other})"),
                ));
            }
        }
        if policy.ignore_inherit_only && ace_flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // SAFETY: ACCESS_ALLOWED_ACE: cabecera de 4 bytes, mascara u32 y SID desde el offset 8.
        let (mask, sid) = unsafe {
            let base = ace.cast::<u8>();
            (
                base.add(4).cast::<u32>().read_unaligned(),
                base.add(8).cast::<c_void>(),
            )
        };
        // SAFETY: el SID esta dentro de la ACE valida.
        let sid =
            unsafe { sid_to_string(sid) }.ok_or_else(|| insecure(path, "SID de ACE ilegible"))?;
        if mask & WRITE_LIKE_MASK != 0 && !policy.is_trusted(&sid) {
            return Err(insecure(
                path,
                format!("{sid} tiene acceso de escritura/control (mascara {mask:#x})"),
            ));
        }
    }
    Ok(())
}
