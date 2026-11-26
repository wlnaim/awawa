//! Identidad persistente del servicio: ID de 9 digitos y par Ed25519.
//!
//! `awawa-admin set` la genera UNA sola vez; despues solo se lee. Se guarda como el verificador:
//! DPAPI de ambito de maquina + archivo con DACL protegida SY/BA y validacion de ubicacion
//! ([`crate::trust`]) antes de leer o escribir. Si el archivo ya existe nunca se sobrescribe.
//!
//! Formato en claro (antes de DPAPI), 44 bytes: magic `USID` | version `1` | 3 bytes a cero |
//! ID `u32` little-endian | semilla Ed25519 (32 bytes). La semilla se borra de los buferes
//! intermedios.
//!
//! Exportacion para el operador (`awawa-admin status --export-key <archivo>`): el archivo
//! contiene exactamente los 32 bytes crudos de la `VerifyingKey` Ed25519. Huella mostrada:
//! los primeros 8 bytes de `SHA-256(clave publica de 32 bytes)` en hexadecimal minuscula
//! agrupado de dos en dos bytes con `-` (`abcd-ef01-2345-6789`), el mismo formato que muestra el
//! operador al cargar `--host-key`.

use core::ffi::c_void;
use core::ptr::null_mut;
use std::io::Write;
use std::path::{Path, PathBuf};

use awawa_protocol::unattended_channel::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::dpapi_store::{
    FILE_DACL_SDDL, FileMode, StoreError, create_protected_file, protect, unprotect,
};
use crate::trust::{TrustPolicy, validate_location};
use crate::winutil::{last_error, wide_path};

const MAGIC: &[u8; 4] = b"USID";
const VERSION: u8 = 1;
/// Longitud del registro en claro.
pub const IDENTITY_RECORD_LEN: usize = 44;
/// Primer y ultimo ID valido en el relay (9 digitos).
const ID_MIN: u32 = 100_000_000;
const ID_MAX: u32 = 999_999_999;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x2;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(h_algorithm: *mut c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
}

/// Llena `buf` con el generador del sistema (`BCryptGenRandom`).
pub fn os_random(buf: &mut [u8]) -> Result<(), StoreError> {
    let len =
        u32::try_from(buf.len()).map_err(|_| StoreError::Io("bufer demasiado grande".into()))?;
    // SAFETY: `buf` es memoria mutable valida de `len` bytes; sin manejador de algoritmo se usa el
    // RNG preferido del sistema (BCRYPT_USE_SYSTEM_PREFERRED_RNG).
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(StoreError::Io(format!(
            "BCryptGenRandom fallo (NTSTATUS={status:#x})"
        )));
    }
    Ok(())
}

/// Huella corta de una clave publica: primeros 8 bytes de SHA-256, `abcd-ef01-2345-6789`.
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest[..8]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join("-")
}

/// Identidad del servicio. `Debug` no muestra la clave privada.
pub struct ServiceIdentity {
    id: u32,
    signing: SigningKey,
}

impl core::fmt::Debug for ServiceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceIdentity")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl ServiceIdentity {
    /// Genera una identidad nueva con el RNG del sistema.
    pub fn generate() -> Result<Self, StoreError> {
        let id = loop {
            let mut raw = [0u8; 4];
            os_random(&mut raw)?;
            // Muestreo por rechazo sobre 30 bits: sin sesgo hacia ningun ID.
            let candidate = u32::from_le_bytes(raw) & 0x3FFF_FFFF;
            if candidate <= ID_MAX - ID_MIN {
                break ID_MIN + candidate;
            }
        };
        let mut seed = Zeroizing::new([0u8; 32]);
        os_random(seed.as_mut_slice())?;
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn fingerprint(&self) -> String {
        key_fingerprint(&self.verifying_key())
    }

    fn to_bytes(&self) -> Zeroizing<[u8; IDENTITY_RECORD_LEN]> {
        let mut out = Zeroizing::new([0u8; IDENTITY_RECORD_LEN]);
        out[..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[8..12].copy_from_slice(&self.id.to_le_bytes());
        let mut seed = self.signing.to_bytes();
        out[12..].copy_from_slice(&seed);
        seed.zeroize();
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let invalid = || StoreError::Io("registro de identidad invalido".into());
        if bytes.len() != IDENTITY_RECORD_LEN
            || &bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || bytes[5..8] != [0, 0, 0]
        {
            return Err(invalid());
        }
        let id = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid())?);
        if !(ID_MIN..=ID_MAX).contains(&id) {
            return Err(invalid());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[12..]);
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(&seed),
        })
    }
}

/// Archivo de la identidad (DPAPI + DACL protegida), con la misma validacion que el verificador.
#[derive(Debug, Clone)]
pub struct IdentityFileStore {
    path: PathBuf,
    dacl: String,
    policy: TrustPolicy,
}

impl IdentityFileStore {
    /// Almacen de produccion: DACL SY/BA y politica SYSTEM/Administradores.
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

    /// Carga la identidad. `Ok(None)` si no existe; error si la ubicacion no es de confianza o el
    /// contenido no descifra o no es valido (el servicio no se registra en el relay).
    pub fn load(&self) -> Result<Option<ServiceIdentity>, StoreError> {
        if std::fs::symlink_metadata(&self.path).is_err() {
            return Ok(None);
        }
        self.validate_dir()?;
        validate_location(&self.path, &self.policy)?;
        let blob = std::fs::read(&self.path)?;
        let plain = Zeroizing::new(unprotect(&blob)?);
        ServiceIdentity::from_bytes(&plain).map(Some)
    }

    /// Devuelve la identidad existente o, si no hay, genera y guarda una nueva. Nunca
    /// sobrescribe: si otro proceso la crea a la vez, gana la primera y se devuelve esa.
    /// El booleano indica si se creo en esta llamada.
    pub fn load_or_create(&self) -> Result<(ServiceIdentity, bool), StoreError> {
        if let Some(existing) = self.load()? {
            return Ok((existing, false));
        }
        self.validate_dir()?;
        let identity = ServiceIdentity::generate()?;
        let blob = protect(identity.to_bytes().as_slice())?;
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "identity".into());
        let temp = self
            .path
            .with_file_name(format!("{name}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&temp);
        let written = (|| -> Result<(), StoreError> {
            let mut file = create_protected_file(&temp, &self.dacl, FileMode::CreateNew)?;
            file.write_all(&blob)?;
            file.sync_all()?;
            drop(file);
            validate_location(&temp, &self.policy)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }
        let from = wide_path(&temp);
        let to = wide_path(&self.path);
        // SAFETY: rutas anchas terminadas en NUL validas durante la llamada. Sin
        // MOVEFILE_REPLACE_EXISTING: si el destino ya existe falla y no se sobrescribe.
        let moved = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
        if moved == 0 {
            let code = last_error();
            let _ = std::fs::remove_file(&temp);
            return match self.load()? {
                Some(existing) => Ok((existing, false)),
                None => Err(StoreError::Io(format!("MoveFileExW fallo (Win32={code})"))),
            };
        }
        match self.load()? {
            Some(loaded)
                if loaded.id == identity.id
                    && loaded.verifying_key() == identity.verifying_key() =>
            {
                Ok((loaded, true))
            }
            _ => Err(StoreError::Io(
                "la identidad guardada no coincide al releerla".into(),
            )),
        }
    }
}

/// Escribe la clave publica (32 bytes crudos) para que el operador la cargue con `--host-key`.
pub fn export_public_key(identity: &ServiceIdentity, path: &Path) -> std::io::Result<()> {
    std::fs::write(path, identity.verifying_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};

    fn store_in(dir: &Path) -> IdentityFileStore {
        IdentityFileStore::with_policy(
            dir.join("service.identity"),
            &test_file_dacl(),
            test_policy(),
        )
    }

    #[test]
    fn se_genera_una_sola_vez_y_se_relee_igual() {
        let tmp = TempDir::new("identity");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        assert!(store.load().unwrap().is_none());
        let (first, created) = store.load_or_create().unwrap();
        assert!(created);
        assert!((ID_MIN..=ID_MAX).contains(&first.id()));
        let (second, created) = store.load_or_create().unwrap();
        assert!(!created, "nunca se regenera");
        assert_eq!(first.id(), second.id());
        assert_eq!(first.verifying_key(), second.verifying_key());
        // En disco no esta la semilla en claro.
        let blob = std::fs::read(store.path()).unwrap();
        let seed = first.signing_key().to_bytes();
        assert!(!blob.windows(32).any(|w| w == seed));
    }

    #[test]
    fn exporta_32_bytes_y_huella_de_8_bytes() {
        let tmp = TempDir::new("identity-export");
        let identity = ServiceIdentity::generate().unwrap();
        let out = tmp.path().join("host.key");
        export_public_key(&identity, &out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.as_slice(), identity.verifying_key().as_bytes());
        let d = Sha256::digest(&bytes);
        let expected = format!(
            "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        );
        assert_eq!(identity.fingerprint(), expected);
    }

    #[test]
    fn registro_manipulado_o_ubicacion_insegura_falla_cerrado() {
        let tmp = TempDir::new("identity-bad");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        let mut file =
            create_protected_file(store.path(), &test_file_dacl(), FileMode::CreateNew).unwrap();
        file.write_all(b"no es dpapi").unwrap();
        drop(file);
        assert!(store.load().is_err());
        assert!(
            store.load_or_create().is_err(),
            "no se sobrescribe un archivo existente"
        );

        let lax_dir = tmp.path().join("lax");
        let sid = crate::testutil::current_sid();
        let lax = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;WD)");
        crate::dpapi_store::create_dir_with_sddl(&lax_dir, &lax).unwrap();
        assert!(matches!(
            store_in(&lax_dir).load_or_create(),
            Err(StoreError::InsecureLocation(_))
        ));
    }

    #[test]
    fn el_formato_rechaza_ids_fuera_de_rango() {
        let identity = ServiceIdentity::generate().unwrap();
        let mut bytes = *identity.to_bytes();
        assert!(ServiceIdentity::from_bytes(&bytes).is_ok());
        bytes[8..12].copy_from_slice(&5u32.to_le_bytes());
        assert!(ServiceIdentity::from_bytes(&bytes).is_err());
    }
}
