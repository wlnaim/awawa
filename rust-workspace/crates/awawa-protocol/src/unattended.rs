//! # Acceso desatendido (servicio de Windows)
//!
//! - Contraseña persistente administrada: el administrador la configura, la cambia (rotación) o la revoca.
//! - La contraseña en claro nunca se almacena: se guarda un verificador ([`PasswordVerifierRecord`]:
//!   salt CSPRNG de 16 bytes + clave derivada de 32 bytes). Los registros nuevos son v2 (Argon2id con sus
//!   parámetros codificados); los v1 (PBKDF2-HMAC-SHA256) se siguen leyendo y verificando sin tocarlos, y el
//!   siguiente `configure`/`rotate`/`revoke` los reescribe como v2.
//!   La protección en reposo del registro (DPAPI + DACL de solo SYSTEM/Administradores) corresponde al servicio.
//! - La derivación entra por el trait [`PasswordKdf`] con los parámetros del registro ([`VerifierKdfParams`]),
//!   de modo que este módulo es portable y comprobable con un KDF falso determinista.
//! - [`UnattendedAuthenticator`] combina el verificador con [`AuthThrottle`] (por origen y global) y solo
//!   ante una verificación correcta emite [`UnattendedAuthorization`], token no construible fuera del crate.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use crate::credentials::{CredentialsError, fill_os_random};

/// Longitud mínima de la contraseña desatendida (en caracteres).
pub const UNATTENDED_PASSWORD_MIN_LEN: usize = 12;
/// Longitud máxima de la contraseña desatendida (en caracteres).
pub const UNATTENDED_PASSWORD_MAX_LEN: usize = 128;
/// Iteraciones PBKDF2-HMAC-SHA256 mínimas de un verificador v1 (los v1 ya no se generan).
pub const PRODUCTION_PBKDF2_ITERATIONS: u32 = 600_000;
/// Tope de iteraciones aceptado al leer un verificador (evita un registro manipulado que bloquee el servicio).
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;
/// Memoria Argon2id de producción (KiB, 19 MiB). También es el mínimo aceptado al leer un v2.
pub const PRODUCTION_ARGON2ID_M_COST_KIB: u32 = 19_456;
/// Pasadas Argon2id de producción. También es el mínimo aceptado al leer un v2.
pub const PRODUCTION_ARGON2ID_T_COST: u32 = 2;
/// Carriles Argon2id de producción. También es el mínimo aceptado al leer un v2.
pub const PRODUCTION_ARGON2ID_P_COST: u32 = 1;
/// Tope de memoria Argon2id al leer un verificador (64 MiB): acota la reserva por intento.
pub const ARGON2ID_MAX_M_COST_KIB: u32 = 65_536;
/// Tope de pasadas Argon2id al leer un verificador. Con el tope de memoria, el peor registro cuesta
/// unas 16,8 veces una derivación de producción (el tope de iteraciones de v1 son 16,7 veces).
pub const ARGON2ID_MAX_T_COST: u32 = 10;
/// Tope de carriles Argon2id al leer un verificador.
pub const ARGON2ID_MAX_P_COST: u32 = 4;
/// Versión del algoritmo Argon2 (RFC 9106: 0x13), fija en el formato v2.
pub const ARGON2_VERSION_0X13: u8 = 0x13;
/// Longitud del salt CSPRNG del verificador.
pub const VERIFIER_SALT_LEN: usize = 16;
/// Longitud de la clave derivada almacenada.
pub const VERIFIER_DK_LEN: usize = 32;
/// Versión 1 del formato binario de [`PasswordVerifierRecord`] (PBKDF2-HMAC-SHA256; solo lectura).
pub const VERIFIER_RECORD_VERSION: u8 = 1;
/// Versión 2 del formato binario de [`PasswordVerifierRecord`] (Argon2id; la que se escribe).
pub const VERIFIER_RECORD_VERSION_V2: u8 = 2;
/// Identificador del algoritmo PBKDF2-HMAC-SHA256 en el formato binario.
pub const VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256: u8 = 1;
/// Identificador del algoritmo Argon2id en el formato binario.
pub const VERIFIER_ALGORITHM_ARGON2ID: u8 = 2;
/// Longitud exacta del registro v1 serializado.
pub const VERIFIER_RECORD_LEN: usize = 64;
/// Longitud exacta del registro v2 serializado.
pub const VERIFIER_RECORD_V2_LEN: usize = 72;

/// Fallos consecutivos por origen tolerados antes del primer bloqueo.
pub const THROTTLE_FAILURES_BEFORE_LOCKOUT: u32 = 3;
/// Primer bloqueo por origen; se duplica con cada fallo adicional.
pub const THROTTLE_BASE_LOCKOUT: Duration = Duration::from_secs(30);
/// Tope del bloqueo por origen.
pub const THROTTLE_MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Fallos globales (todos los orígenes) que disparan el bloqueo global dentro de la ventana.
pub const GLOBAL_FAILURE_THRESHOLD: usize = 10;
/// Ventana deslizante del contador global de fallos.
pub const GLOBAL_FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Duración del bloqueo global.
pub const GLOBAL_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Máximo de orígenes rastreados por el limitador (acota la memoria ante rotación de orígenes).
pub const THROTTLE_MAX_TRACKED_SOURCES: usize = 4096;

const RECORD_MAGIC: [u8; 4] = *b"UAPV";
const STATUS_ENABLED: u8 = 1;
const STATUS_REVOKED: u8 = 2;

/// Error del proveedor de derivación de clave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    InvalidParameters,
    BackendFailure(i32),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters => write!(f, "parametros de derivacion de clave invalidos"),
            Self::BackendFailure(code) => {
                write!(
                    f,
                    "fallo del proveedor de derivacion de clave (NTSTATUS={code:#x})"
                )
            }
        }
    }
}

impl std::error::Error for KdfError {}

/// Algoritmo y parámetros de derivación codificados en el verificador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierKdfParams {
    /// Formato v1: PBKDF2-HMAC-SHA256.
    Pbkdf2HmacSha256 { iterations: u32 },
    /// Formato v2: Argon2id versión 0x13, sin secreto ni datos asociados.
    Argon2id {
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

impl VerifierKdfParams {
    /// Parámetros de producción de los verificadores nuevos.
    pub const PRODUCTION: Self = Self::Argon2id {
        m_cost_kib: PRODUCTION_ARGON2ID_M_COST_KIB,
        t_cost: PRODUCTION_ARGON2ID_T_COST,
        p_cost: PRODUCTION_ARGON2ID_P_COST,
    };

    /// Parámetros del registro que reemplaza a uno con `self`: nunca por debajo de los de producción ni de
    /// los del registro anterior (un v2 más fuerte conserva su fuerza). Un v1 pasa a los de producción.
    fn successor(self) -> Self {
        match self {
            Self::Pbkdf2HmacSha256 { .. } => Self::PRODUCTION,
            Self::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } => Self::Argon2id {
                m_cost_kib: m_cost_kib.max(PRODUCTION_ARGON2ID_M_COST_KIB),
                t_cost: t_cost.max(PRODUCTION_ARGON2ID_T_COST),
                p_cost: p_cost.max(PRODUCTION_ARGON2ID_P_COST),
            },
        }
    }
}

/// Derivación de 32 bytes con el algoritmo y los parámetros del verificador.
/// Un proveedor que no soporte el algoritmo pedido devuelve [`KdfError::InvalidParameters`].
pub trait PasswordKdf {
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8; 16],
        params: VerifierKdfParams,
        out: &mut [u8; 32],
    ) -> Result<(), KdfError>;
}

/// Ámbito de un bloqueo por limitación de intentos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleScope {
    Source,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnattendedError {
    PasswordTooShort,
    PasswordTooLong,
    /// Ya existe una contraseña activa: usar `rotate` para cambiarla.
    AlreadyConfigured,
    /// No hay contraseña configurada (nunca se configuró).
    NotConfigured,
    /// El acceso desatendido está revocado o no configurado: no se acepta autenticación.
    UnattendedDisabled,
    InvalidPassword,
    Throttled {
        scope: ThrottleScope,
        retry_after: Duration,
    },
    Rng(CredentialsError),
    Kdf(KdfError),
    InvalidRecord(&'static str),
}

impl fmt::Display for UnattendedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooShort => write!(
                f,
                "la contrasena desatendida requiere al menos {UNATTENDED_PASSWORD_MIN_LEN} caracteres"
            ),
            Self::PasswordTooLong => write!(
                f,
                "la contrasena desatendida admite como maximo {UNATTENDED_PASSWORD_MAX_LEN} caracteres"
            ),
            Self::AlreadyConfigured => write!(f, "ya existe una contrasena desatendida activa"),
            Self::NotConfigured => write!(f, "no hay contrasena desatendida configurada"),
            Self::UnattendedDisabled => write!(f, "el acceso desatendido esta deshabilitado"),
            Self::InvalidPassword => write!(f, "autenticacion desatendida rechazada"),
            Self::Throttled { scope, retry_after } => write!(
                f,
                "demasiados intentos ({}); reintentar en {} s",
                match scope {
                    ThrottleScope::Source => "origen",
                    ThrottleScope::Global => "global",
                },
                retry_after.as_secs().max(1)
            ),
            Self::Rng(e) => write!(f, "{e}"),
            Self::Kdf(e) => write!(f, "{e}"),
            Self::InvalidRecord(why) => write!(f, "registro verificador invalido: {why}"),
        }
    }
}

impl std::error::Error for UnattendedError {}

/// Estado del verificador persistido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierStatus {
    Enabled,
    Revoked,
}

/// Verificador persistente de la contraseña desatendida. Nunca contiene la contraseña en claro.
///
/// Formato binario v1 (64 bytes, enteros little-endian; solo lectura):
/// `magic "UAPV" (4) | version = 1 (1) | algoritmo = 1 (1) | estado (1) | reservado = 0 (1) |
///  iteraciones u32 (4) | generacion u32 (4) | salt (16) | dk (32)`.
///
/// Formato binario v2 (72 bytes, enteros little-endian; el único que se escribe):
/// `magic "UAPV" (4) | version = 2 (1) | algoritmo = 2 (1) | estado (1) | version Argon2 = 0x13 (1) |
///  m_cost KiB u32 (4) | generacion u32 (4) | t_cost u32 (4) | p_cost u32 (4) | salt (16) | dk (32)`.
/// La generación ocupa el mismo desplazamiento (12) en ambas versiones.
///
/// Un registro revocado conserva la generación y tiene salt y dk en cero.
pub struct PasswordVerifierRecord {
    params: VerifierKdfParams,
    generation: u32,
    status: VerifierStatus,
    salt: [u8; VERIFIER_SALT_LEN],
    dk: [u8; VERIFIER_DK_LEN],
}

impl PasswordVerifierRecord {
    pub fn version(&self) -> u8 {
        match self.params {
            VerifierKdfParams::Pbkdf2HmacSha256 { .. } => VERIFIER_RECORD_VERSION,
            VerifierKdfParams::Argon2id { .. } => VERIFIER_RECORD_VERSION_V2,
        }
    }

    pub fn algorithm_id(&self) -> u8 {
        match self.params {
            VerifierKdfParams::Pbkdf2HmacSha256 { .. } => VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256,
            VerifierKdfParams::Argon2id { .. } => VERIFIER_ALGORITHM_ARGON2ID,
        }
    }

    pub fn kdf_params(&self) -> VerifierKdfParams {
        self.params
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn status(&self) -> VerifierStatus {
        self.status
    }

    /// Serializa en el formato de su versión: 64 bytes (v1) o 72 bytes (v2).
    pub fn to_bytes(&self) -> Vec<u8> {
        let status = match self.status {
            VerifierStatus::Enabled => STATUS_ENABLED,
            VerifierStatus::Revoked => STATUS_REVOKED,
        };
        let mut out = Vec::with_capacity(VERIFIER_RECORD_V2_LEN);
        out.extend_from_slice(&RECORD_MAGIC);
        match self.params {
            VerifierKdfParams::Pbkdf2HmacSha256 { iterations } => {
                out.extend_from_slice(&[
                    VERIFIER_RECORD_VERSION,
                    VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256,
                    status,
                    0,
                ]);
                out.extend_from_slice(&iterations.to_le_bytes());
                out.extend_from_slice(&self.generation.to_le_bytes());
            }
            VerifierKdfParams::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } => {
                out.extend_from_slice(&[
                    VERIFIER_RECORD_VERSION_V2,
                    VERIFIER_ALGORITHM_ARGON2ID,
                    status,
                    ARGON2_VERSION_0X13,
                ]);
                out.extend_from_slice(&m_cost_kib.to_le_bytes());
                out.extend_from_slice(&self.generation.to_le_bytes());
                out.extend_from_slice(&t_cost.to_le_bytes());
                out.extend_from_slice(&p_cost.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.dk);
        out
    }

    /// Decodifica v1 o v2 con validación estricta de longitud, versión, algoritmo, estado y parámetros:
    /// mínimos de la política y topes que impiden que un registro manipulado bloquee el servicio.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UnattendedError> {
        if bytes.len() != VERIFIER_RECORD_LEN && bytes.len() != VERIFIER_RECORD_V2_LEN {
            return Err(UnattendedError::InvalidRecord("longitud inesperada"));
        }
        if bytes[0..4] != RECORD_MAGIC {
            return Err(UnattendedError::InvalidRecord("firma desconocida"));
        }
        let (expected_len, expected_algorithm) = match bytes[4] {
            VERIFIER_RECORD_VERSION => (VERIFIER_RECORD_LEN, VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256),
            VERIFIER_RECORD_VERSION_V2 => (VERIFIER_RECORD_V2_LEN, VERIFIER_ALGORITHM_ARGON2ID),
            _ => return Err(UnattendedError::InvalidRecord("version no soportada")),
        };
        if bytes.len() != expected_len {
            return Err(UnattendedError::InvalidRecord("longitud inesperada"));
        }
        if bytes[5] != expected_algorithm {
            return Err(UnattendedError::InvalidRecord("algoritmo no soportado"));
        }
        let status = match bytes[6] {
            STATUS_ENABLED => VerifierStatus::Enabled,
            STATUS_REVOKED => VerifierStatus::Revoked,
            _ => return Err(UnattendedError::InvalidRecord("estado desconocido")),
        };
        let u32_at = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let (params, material_at) = if bytes[4] == VERIFIER_RECORD_VERSION {
            if bytes[7] != 0 {
                return Err(UnattendedError::InvalidRecord(
                    "byte reservado distinto de cero",
                ));
            }
            let iterations = u32_at(8);
            if iterations < PRODUCTION_PBKDF2_ITERATIONS {
                return Err(UnattendedError::InvalidRecord(
                    "iteraciones por debajo de la politica",
                ));
            }
            if iterations > PBKDF2_MAX_ITERATIONS {
                return Err(UnattendedError::InvalidRecord(
                    "iteraciones por encima del tope",
                ));
            }
            (VerifierKdfParams::Pbkdf2HmacSha256 { iterations }, 16)
        } else {
            if bytes[7] != ARGON2_VERSION_0X13 {
                return Err(UnattendedError::InvalidRecord(
                    "version de Argon2 no soportada",
                ));
            }
            let (m_cost_kib, t_cost, p_cost) = (u32_at(8), u32_at(16), u32_at(20));
            if m_cost_kib < PRODUCTION_ARGON2ID_M_COST_KIB
                || t_cost < PRODUCTION_ARGON2ID_T_COST
                || p_cost < PRODUCTION_ARGON2ID_P_COST
            {
                return Err(UnattendedError::InvalidRecord(
                    "parametros Argon2id por debajo de la politica",
                ));
            }
            if m_cost_kib > ARGON2ID_MAX_M_COST_KIB
                || t_cost > ARGON2ID_MAX_T_COST
                || p_cost > ARGON2ID_MAX_P_COST
            {
                return Err(UnattendedError::InvalidRecord(
                    "parametros Argon2id por encima del tope",
                ));
            }
            let params = VerifierKdfParams::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            };
            (params, 24)
        };
        let generation = u32_at(12);
        if generation == 0 {
            return Err(UnattendedError::InvalidRecord("generacion cero"));
        }
        let mut salt = [0u8; VERIFIER_SALT_LEN];
        salt.copy_from_slice(&bytes[material_at..material_at + VERIFIER_SALT_LEN]);
        let mut dk = [0u8; VERIFIER_DK_LEN];
        dk.copy_from_slice(&bytes[material_at + VERIFIER_SALT_LEN..]);
        let record = Self {
            params,
            generation,
            status,
            salt,
            dk,
        };
        if status == VerifierStatus::Revoked
            && (record.salt.iter().any(|b| *b != 0) || record.dk.iter().any(|b| *b != 0))
        {
            return Err(UnattendedError::InvalidRecord(
                "registro revocado con material residual",
            ));
        }
        Ok(record)
    }

    /// Registro nuevo con `params` (en la práctica, Argon2id de producción o más fuerte).
    fn derive_new(
        password: &str,
        generation: u32,
        params: VerifierKdfParams,
        kdf: &dyn PasswordKdf,
    ) -> Result<Self, UnattendedError> {
        validate_new_password(password)?;
        let mut salt = [0u8; VERIFIER_SALT_LEN];
        fill_os_random(&mut salt).map_err(UnattendedError::Rng)?;
        let mut record = Self {
            params,
            generation,
            status: VerifierStatus::Enabled,
            salt,
            dk: [0u8; VERIFIER_DK_LEN],
        };
        kdf.derive(
            password.as_bytes(),
            &record.salt,
            record.params,
            &mut record.dk,
        )
        .map_err(UnattendedError::Kdf)?;
        Ok(record)
    }

    fn revoked(generation: u32, params: VerifierKdfParams) -> Self {
        Self {
            params,
            generation,
            status: VerifierStatus::Revoked,
            salt: [0u8; VERIFIER_SALT_LEN],
            dk: [0u8; VERIFIER_DK_LEN],
        }
    }

    fn matches(&self, candidate: &str, kdf: &dyn PasswordKdf) -> Result<bool, KdfError> {
        let mut derived = [0u8; VERIFIER_DK_LEN];
        let result = kdf
            .derive(candidate.as_bytes(), &self.salt, self.params, &mut derived)
            .map(|()| constant_time_eq(&derived, &self.dk));
        wipe(&mut derived);
        result
    }
}

impl fmt::Debug for PasswordVerifierRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordVerifierRecord")
            .field("version", &self.version())
            .field("kdf", &self.params)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("salt", &"[REDACTED]")
            .field("dk", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PasswordVerifierRecord {
    fn drop(&mut self) {
        wipe(&mut self.salt);
        wipe(&mut self.dk);
    }
}

fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` es una referencia mutable válida y alineada a un byte propio del búfer.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Comparación en tiempo constante de dos claves derivadas de 32 bytes.
fn constant_time_eq(a: &[u8; VERIFIER_DK_LEN], b: &[u8; VERIFIER_DK_LEN]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

fn validate_new_password(password: &str) -> Result<(), UnattendedError> {
    let len = password.chars().count();
    if len < UNATTENDED_PASSWORD_MIN_LEN {
        return Err(UnattendedError::PasswordTooShort);
    }
    if len > UNATTENDED_PASSWORD_MAX_LEN {
        return Err(UnattendedError::PasswordTooLong);
    }
    Ok(())
}

/// Estado resumido de la credencial desatendida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnattendedStatus {
    NotConfigured,
    Enabled { generation: u32 },
    Revoked { generation: u32 },
}

/// Credencial desatendida persistente y sus operaciones de administrador.
/// La autorización del administrador (pertenencia a Administradores) la verifica el servicio.
#[derive(Debug, Default)]
pub struct UnattendedCredentialState {
    record: Option<PasswordVerifierRecord>,
}

impl UnattendedCredentialState {
    pub fn not_configured() -> Self {
        Self::default()
    }

    /// Restaura el estado desde un registro persistido y validado.
    pub fn from_record(record: PasswordVerifierRecord) -> Self {
        Self {
            record: Some(record),
        }
    }

    pub fn record(&self) -> Option<&PasswordVerifierRecord> {
        self.record.as_ref()
    }

    pub fn status(&self) -> UnattendedStatus {
        match &self.record {
            None => UnattendedStatus::NotConfigured,
            Some(r) => match r.status {
                VerifierStatus::Enabled => UnattendedStatus::Enabled {
                    generation: r.generation,
                },
                VerifierStatus::Revoked => UnattendedStatus::Revoked {
                    generation: r.generation,
                },
            },
        }
    }

    /// Configura la contraseña cuando no hay ninguna activa (primera vez o tras revocar).
    /// Devuelve la nueva generación.
    pub fn configure(
        &mut self,
        new_password: &str,
        kdf: &dyn PasswordKdf,
    ) -> Result<u32, UnattendedError> {
        let generation = match self.status() {
            UnattendedStatus::Enabled { .. } => return Err(UnattendedError::AlreadyConfigured),
            UnattendedStatus::NotConfigured => 1,
            UnattendedStatus::Revoked { generation } => generation.saturating_add(1),
        };
        self.record = Some(PasswordVerifierRecord::derive_new(
            new_password,
            generation,
            self.next_params(),
            kdf,
        )?);
        Ok(generation)
    }

    /// Cambia la contraseña activa: nuevo salt y nueva clave derivada; la anterior deja de verificar.
    /// Un verificador v1 se reemplaza por uno v2 (migración). Devuelve la nueva generación.
    pub fn rotate(
        &mut self,
        new_password: &str,
        kdf: &dyn PasswordKdf,
    ) -> Result<u32, UnattendedError> {
        let generation = match self.status() {
            UnattendedStatus::Enabled { generation } => generation.saturating_add(1),
            UnattendedStatus::NotConfigured => return Err(UnattendedError::NotConfigured),
            UnattendedStatus::Revoked { .. } => return Err(UnattendedError::UnattendedDisabled),
        };
        self.record = Some(PasswordVerifierRecord::derive_new(
            new_password,
            generation,
            self.next_params(),
            kdf,
        )?);
        Ok(generation)
    }

    /// Revoca la contraseña activa: destruye salt y clave derivada y deshabilita el acceso desatendido.
    /// El registro revocado se escribe como v2 (sin material, con los parámetros que heredará el siguiente
    /// `configure`). Devuelve la nueva generación.
    pub fn revoke(&mut self) -> Result<u32, UnattendedError> {
        let generation = match self.status() {
            UnattendedStatus::Enabled { generation } => generation.saturating_add(1),
            UnattendedStatus::NotConfigured => return Err(UnattendedError::NotConfigured),
            UnattendedStatus::Revoked { .. } => return Err(UnattendedError::UnattendedDisabled),
        };
        self.record = Some(PasswordVerifierRecord::revoked(
            generation,
            self.next_params(),
        ));
        Ok(generation)
    }

    /// Parámetros del próximo registro: Argon2id, nunca por debajo de producción ni del registro actual.
    fn next_params(&self) -> VerifierKdfParams {
        self.record
            .as_ref()
            .map_or(VerifierKdfParams::PRODUCTION, |r| r.params.successor())
    }

    fn enabled_record(&self) -> Option<&PasswordVerifierRecord> {
        self.record
            .as_ref()
            .filter(|r| r.status == VerifierStatus::Enabled)
    }
}

#[derive(Debug)]
struct SourceThrottle {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
    last_failure: Instant,
}

impl SourceThrottle {
    /// Purgable: sin bloqueo vigente y sin fallos dentro de la ventana global.
    fn is_stale(&self, now: Instant) -> bool {
        let locked = self.locked_until.is_some_and(|until| now < until);
        !locked && now.saturating_duration_since(self.last_failure) >= GLOBAL_FAILURE_WINDOW
    }
}

/// Limitador de intentos por origen y global, con reloj inyectado (`Instant` como parámetro).
#[derive(Debug, Default)]
pub struct AuthThrottle {
    per_source: HashMap<String, SourceThrottle>,
    global_failures: VecDeque<Instant>,
    global_locked_until: Option<Instant>,
}

impl AuthThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Comprueba si `source` puede intentar autenticarse en `now`.
    pub fn check(&mut self, source: &str, now: Instant) -> Result<(), UnattendedError> {
        if let Some(until) = self.global_locked_until {
            if now < until {
                return Err(UnattendedError::Throttled {
                    scope: ThrottleScope::Global,
                    retry_after: until - now,
                });
            }
            self.global_locked_until = None;
        }
        if let Some(state) = self.per_source.get(source)
            && let Some(until) = state.locked_until
            && now < until
        {
            return Err(UnattendedError::Throttled {
                scope: ThrottleScope::Source,
                retry_after: until - now,
            });
        }
        Ok(())
    }

    /// Registra un fallo. Si el mapa por origen está lleno ([`THROTTLE_MAX_TRACKED_SOURCES`]) se purgan
    /// los orígenes inactivos; si aun así no hay espacio, el origen nuevo solo cuenta en el contador global.
    /// Nunca se expulsa un origen con bloqueo vigente.
    pub fn record_failure(&mut self, source: &str, now: Instant) {
        if !self.per_source.contains_key(source)
            && self.per_source.len() >= THROTTLE_MAX_TRACKED_SOURCES
        {
            self.per_source.retain(|_, state| !state.is_stale(now));
        }
        let tracked = if self.per_source.contains_key(source)
            || self.per_source.len() < THROTTLE_MAX_TRACKED_SOURCES
        {
            Some(
                self.per_source
                    .entry(source.to_owned())
                    .or_insert(SourceThrottle {
                        consecutive_failures: 0,
                        locked_until: None,
                        last_failure: now,
                    }),
            )
        } else {
            None
        };
        if let Some(state) = tracked {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.last_failure = now;
            if state.consecutive_failures >= THROTTLE_FAILURES_BEFORE_LOCKOUT {
                state.locked_until = Some(now + source_lockout(state.consecutive_failures));
            }
        }

        while let Some(&oldest) = self.global_failures.front() {
            if now.saturating_duration_since(oldest) >= GLOBAL_FAILURE_WINDOW {
                self.global_failures.pop_front();
            } else {
                break;
            }
        }
        self.global_failures.push_back(now);
        if self.global_failures.len() >= GLOBAL_FAILURE_THRESHOLD {
            self.global_locked_until = Some(now + GLOBAL_LOCKOUT);
            self.global_failures.clear();
        }
    }

    /// Un éxito reinicia el contador del origen (no la ventana global).
    pub fn record_success(&mut self, source: &str) {
        self.per_source.remove(source);
    }
}

/// Bloqueo por origen: 30 s al tercer fallo consecutivo, doblando por fallo adicional, tope 15 min.
fn source_lockout(consecutive_failures: u32) -> Duration {
    let doublings = consecutive_failures
        .saturating_sub(THROTTLE_FAILURES_BEFORE_LOCKOUT)
        .min(10);
    (THROTTLE_BASE_LOCKOUT * (1u32 << doublings)).min(THROTTLE_MAX_LOCKOUT)
}

/// Autorización desatendida emitida solo tras verificar la contraseña. No es construible fuera del crate
/// y se consume al crear `ApprovedActiveSession::from_unattended_authorization`.
#[derive(Debug)]
pub struct UnattendedAuthorization {
    generation: u32,
    source: String,
    authorized_at: Instant,
}

impl UnattendedAuthorization {
    /// Generación del verificador con el que se autenticó.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn authorized_at(&self) -> Instant {
        self.authorized_at
    }
}

/// Autenticador desatendido: credencial persistente + limitación de intentos.
#[derive(Debug, Default)]
pub struct UnattendedAuthenticator {
    credentials: UnattendedCredentialState,
    throttle: AuthThrottle,
}

impl UnattendedAuthenticator {
    pub fn new(credentials: UnattendedCredentialState) -> Self {
        Self {
            credentials,
            throttle: AuthThrottle::new(),
        }
    }

    pub fn credentials(&self) -> &UnattendedCredentialState {
        &self.credentials
    }

    /// Acceso a las operaciones de administrador (configurar / cambiar / revocar).
    pub fn credentials_mut(&mut self) -> &mut UnattendedCredentialState {
        &mut self.credentials
    }

    /// Verifica la contraseña desatendida presentada desde `source`.
    /// No ejecuta el KDF si el acceso está deshabilitado o si el origen/global está bloqueado.
    pub fn authenticate(
        &mut self,
        source: &str,
        candidate_password: &str,
        kdf: &dyn PasswordKdf,
        now: Instant,
    ) -> Result<UnattendedAuthorization, UnattendedError> {
        let Some(record) = self.credentials.enabled_record() else {
            return Err(UnattendedError::UnattendedDisabled);
        };
        self.throttle.check(source, now)?;

        // Fuera de política nunca puede coincidir: se cuenta como fallo sin derivar (evita KDF sobre entradas enormes).
        if validate_new_password(candidate_password).is_err() {
            self.throttle.record_failure(source, now);
            return Err(UnattendedError::InvalidPassword);
        }

        let generation = record.generation;
        let matched = record
            .matches(candidate_password, kdf)
            .map_err(UnattendedError::Kdf)?;
        if !matched {
            self.throttle.record_failure(source, now);
            return Err(UnattendedError::InvalidPassword);
        }

        self.throttle.record_success(source);
        Ok(UnattendedAuthorization {
            generation,
            source: source.to_owned(),
            authorized_at: now,
        })
    }
}

/// KDF falso determinista (no criptográfico) para pruebas del dominio.
#[cfg(test)]
pub(crate) mod test_kdf {
    use super::{KdfError, PasswordKdf, VerifierKdfParams};
    use std::cell::Cell;

    #[derive(Default)]
    pub(crate) struct CountingFakeKdf {
        pub calls: Cell<u32>,
    }

    /// Parámetros como bytes (algoritmo + valores) para que el resultado dependa de ellos.
    pub(crate) fn params_tag(params: VerifierKdfParams) -> Vec<u8> {
        match params {
            VerifierKdfParams::Pbkdf2HmacSha256 { iterations } => {
                [&[1u8][..], &iterations.to_le_bytes()].concat()
            }
            VerifierKdfParams::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } => [
                &[2u8][..],
                &m_cost_kib.to_le_bytes(),
                &t_cost.to_le_bytes(),
                &p_cost.to_le_bytes(),
            ]
            .concat(),
        }
    }

    impl PasswordKdf for CountingFakeKdf {
        fn derive(
            &self,
            password: &[u8],
            salt: &[u8; 16],
            params: VerifierKdfParams,
            out: &mut [u8; 32],
        ) -> Result<(), KdfError> {
            self.calls.set(self.calls.get() + 1);
            let tag = params_tag(params);
            for (chunk_idx, chunk) in out.chunks_mut(8).enumerate() {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ chunk_idx as u64;
                for b in password.iter().chain(salt.iter()).chain(tag.iter()) {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
                chunk.copy_from_slice(&h.to_le_bytes());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_kdf::CountingFakeKdf;
    use super::*;
    use crate::audit::{AuditEvent, AuditRecord};

    const PW: &str = "Correct-Horse-Battery-9";
    const PW2: &str = "Otra-Clave-Segura-2026";

    fn hex(bytes: &[u8], upper: bool) -> String {
        bytes
            .iter()
            .map(|b| {
                if upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
            })
            .collect()
    }

    fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn configure_enforces_length_and_produces_versioned_record_without_plaintext() {
        let kdf = CountingFakeKdf::default();
        let mut state = UnattendedCredentialState::not_configured();
        assert_eq!(
            state.configure("corta-11ch!", &kdf),
            Err(UnattendedError::PasswordTooShort)
        );
        assert_eq!(
            state.configure(&"x".repeat(129), &kdf),
            Err(UnattendedError::PasswordTooLong)
        );
        assert_eq!(state.status(), UnattendedStatus::NotConfigured);
        assert_eq!(kdf.calls.get(), 0);

        assert_eq!(state.configure("doce-chars12", &kdf), Ok(1));
        assert_eq!(state.status(), UnattendedStatus::Enabled { generation: 1 });
        assert_eq!(
            state.configure(PW, &kdf),
            Err(UnattendedError::AlreadyConfigured)
        );

        let mut state = UnattendedCredentialState::not_configured();
        state.configure(PW, &kdf).unwrap();
        let rec = state.record().unwrap();
        assert_eq!(rec.version(), 2);
        assert_eq!(rec.algorithm_id(), VERIFIER_ALGORITHM_ARGON2ID);
        assert_eq!(rec.kdf_params(), VerifierKdfParams::PRODUCTION);
        assert!(
            rec.salt.iter().any(|b| *b != 0),
            "salt CSPRNG no puede ser todo ceros"
        );

        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), VERIFIER_RECORD_V2_LEN);
        assert!(!contains_subslice(&bytes, PW.as_bytes()));

        let dbg = format!("{rec:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&hex(&rec.dk, false)) && !dbg.contains(PW));

        // Roundtrip y verificación tras restaurar.
        let restored = PasswordVerifierRecord::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
        let mut auth =
            UnattendedAuthenticator::new(UnattendedCredentialState::from_record(restored));
        assert!(
            auth.authenticate("10.0.0.1", PW, &kdf, Instant::now())
                .is_ok()
        );
    }

    /// Salt fija de los vectores de prueba: 0x10..=0x1f.
    fn fixed_salt() -> [u8; 16] {
        core::array::from_fn(|i| 0x10 + i as u8)
    }

    /// Registro v1 armado byte a byte como lo escribía la versión anterior (PBKDF2, 600 000 iteraciones).
    /// La clave derivada sale del KDF falso: el vector con PBKDF2 real vive en `awawa-service`.
    fn v1_bytes(kdf: &CountingFakeKdf, password: &str, generation: u32) -> Vec<u8> {
        let salt = fixed_salt();
        let mut dk = [0u8; 32];
        kdf.derive(
            password.as_bytes(),
            &salt,
            VerifierKdfParams::Pbkdf2HmacSha256 {
                iterations: 600_000,
            },
            &mut dk,
        )
        .unwrap();
        let mut b = b"UAPV".to_vec();
        b.extend_from_slice(&[1, 1, STATUS_ENABLED, 0]);
        b.extend_from_slice(&600_000u32.to_le_bytes());
        b.extend_from_slice(&generation.to_le_bytes());
        b.extend_from_slice(&salt);
        b.extend_from_slice(&dk);
        b
    }

    /// Registro v2 armado byte a byte con parámetros Argon2id arbitrarios.
    fn v2_bytes(
        kdf: &CountingFakeKdf,
        password: &str,
        generation: u32,
        m: u32,
        t: u32,
        p: u32,
    ) -> Vec<u8> {
        let salt = fixed_salt();
        let mut dk = [0u8; 32];
        let params = VerifierKdfParams::Argon2id {
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
        };
        kdf.derive(password.as_bytes(), &salt, params, &mut dk)
            .unwrap();
        let mut b = b"UAPV".to_vec();
        b.extend_from_slice(&[2, 2, STATUS_ENABLED, 0x13]);
        b.extend_from_slice(&m.to_le_bytes());
        b.extend_from_slice(&generation.to_le_bytes());
        b.extend_from_slice(&t.to_le_bytes());
        b.extend_from_slice(&p.to_le_bytes());
        b.extend_from_slice(&salt);
        b.extend_from_slice(&dk);
        b
    }

    #[test]
    fn from_bytes_rejects_malformed_records() {
        let kdf = CountingFakeKdf::default();
        let good = v1_bytes(&kdf, PW, 1);
        assert!(PasswordVerifierRecord::from_bytes(&good).is_ok());

        assert!(PasswordVerifierRecord::from_bytes(&good[..63]).is_err());
        let mut longer = good.clone();
        longer.push(0);
        assert!(PasswordVerifierRecord::from_bytes(&longer).is_err());

        let mutate = |idx: usize, val: u8| {
            let mut b = good.clone();
            b[idx] = val;
            PasswordVerifierRecord::from_bytes(&b)
        };
        assert_eq!(
            mutate(0, b'X').unwrap_err(),
            UnattendedError::InvalidRecord("firma desconocida")
        );
        assert_eq!(
            mutate(4, 3).unwrap_err(),
            UnattendedError::InvalidRecord("version no soportada")
        );
        // Un v1 que se declara v2 no tiene la longitud de v2.
        assert_eq!(
            mutate(4, 2).unwrap_err(),
            UnattendedError::InvalidRecord("longitud inesperada")
        );
        assert_eq!(
            mutate(5, 9).unwrap_err(),
            UnattendedError::InvalidRecord("algoritmo no soportado")
        );
        assert_eq!(
            mutate(5, VERIFIER_ALGORITHM_ARGON2ID).unwrap_err(),
            UnattendedError::InvalidRecord("algoritmo no soportado")
        );
        assert_eq!(
            mutate(6, 7).unwrap_err(),
            UnattendedError::InvalidRecord("estado desconocido")
        );
        assert!(mutate(7, 1).is_err());

        let mut weak = good.clone();
        weak[8..12].copy_from_slice(&1000u32.to_le_bytes());
        assert!(PasswordVerifierRecord::from_bytes(&weak).is_err());

        let mut at_cap = good.clone();
        at_cap[8..12].copy_from_slice(&PBKDF2_MAX_ITERATIONS.to_le_bytes());
        assert!(PasswordVerifierRecord::from_bytes(&at_cap).is_ok());
        let mut huge = good.clone();
        huge[8..12].copy_from_slice(&(PBKDF2_MAX_ITERATIONS + 1).to_le_bytes());
        assert_eq!(
            PasswordVerifierRecord::from_bytes(&huge).unwrap_err(),
            UnattendedError::InvalidRecord("iteraciones por encima del tope")
        );

        // Revocado con material residual.
        assert!(mutate(6, STATUS_REVOKED).is_err());
    }

    #[test]
    fn rotate_changes_salt_and_hash_and_invalidates_old_password() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        assert_eq!(
            auth.credentials_mut().rotate(PW2, &kdf),
            Err(UnattendedError::NotConfigured)
        );
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        let before = auth.credentials().record().unwrap().to_bytes();

        assert_eq!(auth.credentials_mut().rotate(PW2, &kdf), Ok(2));
        let after_rec = auth.credentials().record().unwrap();
        assert_eq!(after_rec.generation(), 2);
        let after = after_rec.to_bytes();
        assert_ne!(before[24..40], after[24..40], "salt nuevo");
        assert_ne!(before[40..72], after[40..72], "hash nuevo");

        let t0 = Instant::now();
        assert_eq!(
            auth.authenticate("src", PW, &kdf, t0).unwrap_err(),
            UnattendedError::InvalidPassword
        );
        let ok = auth.authenticate("src", PW2, &kdf, t0).unwrap();
        assert_eq!(ok.generation(), 2);
        assert_eq!(ok.source(), "src");
    }

    #[test]
    fn revoked_rejects_without_running_kdf_and_can_be_reconfigured() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        let t0 = Instant::now();
        assert_eq!(
            auth.authenticate("src", PW, &kdf, t0).unwrap_err(),
            UnattendedError::UnattendedDisabled
        );
        assert_eq!(
            auth.credentials_mut().revoke(),
            Err(UnattendedError::NotConfigured)
        );

        auth.credentials_mut().configure(PW, &kdf).unwrap();
        assert_eq!(auth.credentials_mut().revoke(), Ok(2));
        assert_eq!(
            auth.credentials().status(),
            UnattendedStatus::Revoked { generation: 2 }
        );
        assert_eq!(
            auth.credentials_mut().revoke(),
            Err(UnattendedError::UnattendedDisabled)
        );
        assert_eq!(
            auth.credentials_mut().rotate(PW2, &kdf),
            Err(UnattendedError::UnattendedDisabled)
        );

        let rec = auth.credentials().record().unwrap();
        assert!(rec.salt.iter().all(|b| *b == 0) && rec.dk.iter().all(|b| *b == 0));
        let revoked_bytes = rec.to_bytes();
        assert_eq!(
            PasswordVerifierRecord::from_bytes(&revoked_bytes)
                .unwrap()
                .status(),
            VerifierStatus::Revoked
        );

        let calls = kdf.calls.get();
        for _ in 0..5 {
            assert_eq!(
                auth.authenticate("src", PW, &kdf, t0).unwrap_err(),
                UnattendedError::UnattendedDisabled
            );
        }
        assert_eq!(kdf.calls.get(), calls, "revocado no debe derivar");

        assert_eq!(auth.credentials_mut().configure(PW2, &kdf), Ok(3));
        assert!(auth.authenticate("src", PW2, &kdf, t0).is_ok());
    }

    #[test]
    fn constant_time_eq_detects_any_byte_difference() {
        let a = [7u8; 32];
        assert!(constant_time_eq(&a, &a));
        for i in 0..32 {
            let mut b = a;
            b[i] ^= 0x01;
            assert!(!constant_time_eq(&a, &b));
        }
    }

    #[test]
    fn per_source_throttle_backs_off_exponentially_without_running_kdf() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        let t0 = Instant::now();
        let base = kdf.calls.get();

        for _ in 0..3 {
            assert_eq!(
                auth.authenticate("a", "contrasena-mala", &kdf, t0)
                    .unwrap_err(),
                UnattendedError::InvalidPassword
            );
        }
        assert_eq!(kdf.calls.get(), base + 3);

        // Bloqueado 30 s: ni siquiera la contraseña correcta ejecuta el KDF.
        assert_eq!(
            auth.authenticate("a", PW, &kdf, t0 + Duration::from_secs(10))
                .unwrap_err(),
            UnattendedError::Throttled {
                scope: ThrottleScope::Source,
                retry_after: Duration::from_secs(20),
            }
        );
        assert_eq!(kdf.calls.get(), base + 3);

        // Otro origen no está afectado.
        assert!(auth.authenticate("b", PW, &kdf, t0).is_ok());

        // Tras 30 s, otro fallo -> 60 s.
        let t1 = t0 + Duration::from_secs(30);
        assert_eq!(
            auth.authenticate("a", "contrasena-mala", &kdf, t1)
                .unwrap_err(),
            UnattendedError::InvalidPassword
        );
        assert_eq!(
            auth.authenticate("a", PW, &kdf, t1 + Duration::from_secs(59))
                .unwrap_err(),
            UnattendedError::Throttled {
                scope: ThrottleScope::Source,
                retry_after: Duration::from_secs(1),
            }
        );

        // Éxito tras el bloqueo reinicia el contador del origen.
        let t2 = t1 + Duration::from_secs(60);
        assert!(auth.authenticate("a", PW, &kdf, t2).is_ok());
        assert_eq!(
            auth.authenticate("a", "contrasena-mala", &kdf, t2)
                .unwrap_err(),
            UnattendedError::InvalidPassword
        );
        assert!(auth.authenticate("a", PW, &kdf, t2).is_ok());
    }

    #[test]
    fn source_map_is_bounded_and_flooding_never_unlocks_a_locked_source() {
        let mut throttle = AuthThrottle::new();
        let t0 = Instant::now();
        let victim_locked = |th: &AuthThrottle, now: Instant| {
            th.per_source
                .get("victim")
                .and_then(|s| s.locked_until)
                .is_some_and(|until| now < until)
        };

        // Origen atacante bloqueado 15 min (8 fallos consecutivos).
        for _ in 0..8 {
            throttle.record_failure("victim", t0);
        }
        assert!(victim_locked(&throttle, t0 + Duration::from_secs(60)));

        // Inundación con orígenes distintos hasta llenar el mapa.
        for i in 0..THROTTLE_MAX_TRACKED_SOURCES - 1 {
            throttle.record_failure(&format!("flood-{i}"), t0);
        }
        assert_eq!(throttle.per_source.len(), THROTTLE_MAX_TRACKED_SOURCES);

        // Mapa lleno sin entradas purgables: el origen nuevo no se inserta (solo cuenta global).
        let t1 = t0 + Duration::from_secs(10);
        throttle.global_locked_until = None;
        throttle.global_failures.clear();
        for i in 0..GLOBAL_FAILURE_THRESHOLD - 1 {
            throttle.record_failure(&format!("extra-{i}"), t1);
        }
        assert_eq!(throttle.per_source.len(), THROTTLE_MAX_TRACKED_SOURCES);
        assert!(!throttle.per_source.contains_key("extra-0"));
        assert_eq!(throttle.global_failures.len(), GLOBAL_FAILURE_THRESHOLD - 1);
        throttle.record_failure("extra-final", t1);
        assert_eq!(
            throttle.check("otro-nuevo", t1),
            Err(UnattendedError::Throttled {
                scope: ThrottleScope::Global,
                retry_after: GLOBAL_LOCKOUT,
            })
        );
        assert!(victim_locked(&throttle, t1));

        // Tras la ventana global, los orígenes inactivos se purgan; el bloqueado se conserva.
        let t2 = t0 + GLOBAL_FAILURE_WINDOW;
        throttle.record_failure("tardio", t2);
        assert!(throttle.per_source.len() <= THROTTLE_MAX_TRACKED_SOURCES);
        assert_eq!(throttle.per_source.len(), 2);
        assert!(throttle.per_source.contains_key("tardio"));
        assert!(victim_locked(&throttle, t2));
        assert_eq!(throttle.per_source["victim"].consecutive_failures, 8);
    }

    #[test]
    fn lockout_schedule_caps_at_fifteen_minutes() {
        assert_eq!(source_lockout(3), Duration::from_secs(30));
        assert_eq!(source_lockout(4), Duration::from_secs(60));
        assert_eq!(source_lockout(5), Duration::from_secs(120));
        assert_eq!(source_lockout(7), Duration::from_secs(480));
        assert_eq!(source_lockout(8), THROTTLE_MAX_LOCKOUT);
        assert_eq!(source_lockout(u32::MAX), THROTTLE_MAX_LOCKOUT);
    }

    #[test]
    fn global_throttle_locks_all_sources_for_fifteen_minutes() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        let t0 = Instant::now();

        // 9 fallos de orígenes distintos dentro de la ventana: aún no hay bloqueo global.
        for i in 0..9 {
            let src = format!("10.0.0.{i}");
            auth.authenticate(&src, "contrasena-mala", &kdf, t0 + Duration::from_secs(i))
                .unwrap_err();
        }
        // Un fallo antiguo fuera de la ventana no cuenta: tras 10 min, la ventana se reinicia.
        let late = t0 + GLOBAL_FAILURE_WINDOW + Duration::from_secs(9);
        auth.authenticate("x", "contrasena-mala", &kdf, late)
            .unwrap_err();
        assert!(auth.authenticate("y", PW, &kdf, late).is_ok());

        // 10 fallos en ventana -> bloqueo global.
        let t1 = late + Duration::from_secs(1);
        for i in 0..9 {
            auth.authenticate(&format!("z{i}"), "contrasena-mala", &kdf, t1)
                .unwrap_err();
        }
        let calls = kdf.calls.get();
        assert_eq!(
            auth.authenticate("nuevo", PW, &kdf, t1).unwrap_err(),
            UnattendedError::Throttled {
                scope: ThrottleScope::Global,
                retry_after: GLOBAL_LOCKOUT,
            }
        );
        assert_eq!(kdf.calls.get(), calls, "sin KDF durante bloqueo global");

        assert!(
            auth.authenticate("nuevo", PW, &kdf, t1 + GLOBAL_LOCKOUT)
                .is_ok()
        );
    }

    #[test]
    fn out_of_policy_candidates_count_as_failures_without_kdf() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        let calls = kdf.calls.get();
        let t0 = Instant::now();
        let huge = "A".repeat(10_000);
        assert_eq!(
            auth.authenticate("s", &huge, &kdf, t0).unwrap_err(),
            UnattendedError::InvalidPassword
        );
        assert_eq!(
            auth.authenticate("s", "", &kdf, t0).unwrap_err(),
            UnattendedError::InvalidPassword
        );
        assert_eq!(kdf.calls.get(), calls);
    }

    #[test]
    fn unattended_authorization_yields_unattended_active_session() {
        use crate::consent_fsm::{AccessMode, ApprovedActiveSession};
        use crate::credentials::SessionId;
        use crate::messages::ScopedCapabilities;

        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        let t0 = Instant::now();
        let token = auth.authenticate("relay-peer-1", PW, &kdf, t0).unwrap();
        assert_eq!(token.authorized_at(), t0);

        let mut session = ApprovedActiveSession::from_unattended_authorization(
            token,
            SessionId::parse("482-910-337").unwrap(),
            "Operador #04".to_string(),
            [0x4A; 8],
            ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
            t0,
            None,
        );
        assert_eq!(session.access_mode(), AccessMode::Unattended);
        assert!(session.can_capture_desktop());
        assert_eq!(session.operator_display_name(), "Operador #04");

        let ctrl_down = crate::messages::RemoteInputCommand::Keyboard {
            scancode: 0x1D,
            extended: false,
            unicode_char: None,
            state: crate::messages::KeyState::Down,
        };
        session.authorize_remote_input(&ctrl_down).unwrap();
        assert_eq!(session.drain_held_input_releases().len(), 1);
        assert!(session.drain_held_input_releases().is_empty());
    }

    #[test]
    fn attended_flow_still_reports_attended_mode() {
        use crate::consent_fsm::{AccessMode, OperatorConnectionRequest, WaitingForRequest};
        use crate::handshake::run_in_memory_handshake;
        use crate::messages::ScopedCapabilities;

        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let t0 = Instant::now();
        let req = OperatorConnectionRequest {
            target_session_id: waiting.session_id(),
            operator_display_name: "Soporte".to_string(),
            operator_ed25519_fingerprint: [1; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };
        let password = waiting.display_password();
        let active = run_in_memory_handshake(waiting, &req, &password, t0)
            .unwrap()
            .0
            .pending
            .approve_locally(t0 + Duration::from_secs(2), None)
            .unwrap();
        assert_eq!(active.access_mode(), AccessMode::Attended);
        assert_eq!(active.unattended_generation(), None);
        assert!(active.is_unattended_grant_current(UnattendedStatus::NotConfigured));
        assert!(active.is_unattended_grant_current(UnattendedStatus::Revoked { generation: 9 }));
    }

    #[test]
    fn rotate_or_revoke_invalidates_active_unattended_grant() {
        use crate::consent_fsm::ApprovedActiveSession;
        use crate::credentials::SessionId;
        use crate::messages::ScopedCapabilities;

        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        assert_eq!(auth.credentials_mut().configure(PW, &kdf), Ok(1));
        let t0 = Instant::now();
        let new_session = |token| {
            ApprovedActiveSession::from_unattended_authorization(
                token,
                SessionId::parse("482-910-337").unwrap(),
                "Operador".to_string(),
                [0x4A; 8],
                ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
                t0,
                None,
            )
        };

        let session = new_session(auth.authenticate("s", PW, &kdf, t0).unwrap());
        assert_eq!(session.unattended_generation(), Some(1));
        assert!(session.is_unattended_grant_current(auth.credentials().status()));

        assert_eq!(auth.credentials_mut().rotate(PW2, &kdf), Ok(2));
        assert!(!session.is_unattended_grant_current(auth.credentials().status()));

        let session2 = new_session(auth.authenticate("s", PW2, &kdf, t0).unwrap());
        assert!(session2.is_unattended_grant_current(auth.credentials().status()));
        assert_eq!(auth.credentials_mut().revoke(), Ok(3));
        assert!(!session2.is_unattended_grant_current(auth.credentials().status()));
        assert!(!session2.is_unattended_grant_current(UnattendedStatus::NotConfigured));
    }

    #[test]
    fn audit_lines_never_contain_password_salt_or_hash() {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::default();
        let generation = auth.credentials_mut().configure(PW, &kdf).unwrap();
        let rec = auth.credentials().record().unwrap();
        let secrets = [
            PW.to_string(),
            hex(&rec.dk, false),
            hex(&rec.dk, true),
            hex(&rec.salt, false),
            hex(&rec.salt, true),
        ];

        let t0 = Instant::now();
        let mut lines = vec![
            AuditRecord::new(
                1,
                AuditEvent::PasswordConfigured { generation },
                "Administrador",
            )
            .to_json_line(),
        ];
        let fail = auth.authenticate("203.0.113.7", "contrasena-mala", &kdf, t0);
        assert!(fail.is_err());
        lines.push(
            AuditRecord::new(2, AuditEvent::AuthFailed, "Operador #04")
                .with_source("203.0.113.7")
                .to_json_line(),
        );
        let ok = auth.authenticate("203.0.113.7", PW, &kdf, t0).unwrap();
        lines.push(
            AuditRecord::new(3, AuditEvent::AuthSucceeded, "Operador #04")
                .with_source(ok.source())
                .with_operator_fingerprint([0x4A; 8])
                .with_windows_session_id(1)
                .to_json_line(),
        );

        for line in &lines {
            for secret in &secrets {
                assert!(
                    !line.contains(secret.as_str()),
                    "secreto filtrado en: {line}"
                );
            }
        }
    }

    #[test]
    fn v2_layout_is_fixed_byte_by_byte_and_round_trips() {
        let kdf = CountingFakeKdf::default();
        let mut state = UnattendedCredentialState::not_configured();
        state.configure(PW, &kdf).unwrap();
        let rec = state.record().unwrap();
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 72);
        assert_eq!(&bytes[0..4], b"UAPV");
        assert_eq!(bytes[4..8], [2, 2, STATUS_ENABLED, 0x13]);
        assert_eq!(bytes[8..12], 19_456u32.to_le_bytes());
        assert_eq!(bytes[12..16], 1u32.to_le_bytes());
        assert_eq!(bytes[16..20], 2u32.to_le_bytes());
        assert_eq!(bytes[20..24], 1u32.to_le_bytes());
        assert_eq!(bytes[24..40], rec.salt);
        assert_eq!(bytes[40..72], rec.dk);

        // Un registro armado a mano con el mismo diseño se decodifica a los mismos campos.
        let hand = v2_bytes(&kdf, PW, 5, 19_456, 2, 1);
        let parsed = PasswordVerifierRecord::from_bytes(&hand).unwrap();
        assert_eq!(parsed.to_bytes(), hand);
        assert_eq!(parsed.generation(), 5);
        assert_eq!(parsed.status(), VerifierStatus::Enabled);
        assert_eq!(parsed.kdf_params(), VerifierKdfParams::PRODUCTION);
        let mut auth = UnattendedAuthenticator::new(UnattendedCredentialState::from_record(parsed));
        assert_eq!(
            auth.authenticate("s", PW, &kdf, Instant::now())
                .unwrap()
                .generation(),
            5
        );
    }

    #[test]
    fn existing_v1_record_is_read_unchanged_and_still_authenticates() {
        let kdf = CountingFakeKdf::default();
        let v1 = v1_bytes(&kdf, PW, 7);
        let rec = PasswordVerifierRecord::from_bytes(&v1).unwrap();
        assert_eq!(rec.version(), 1);
        assert_eq!(rec.algorithm_id(), VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256);
        assert_eq!(
            rec.kdf_params(),
            VerifierKdfParams::Pbkdf2HmacSha256 {
                iterations: 600_000
            }
        );
        assert_eq!(rec.to_bytes(), v1, "leer un v1 no lo reescribe");

        let mut auth = UnattendedAuthenticator::new(UnattendedCredentialState::from_record(rec));
        let t0 = Instant::now();
        assert_eq!(
            auth.authenticate("s", PW2, &kdf, t0).unwrap_err(),
            UnattendedError::InvalidPassword
        );
        assert_eq!(
            auth.authenticate("s", PW, &kdf, t0).unwrap().generation(),
            7
        );
        // Autenticar no migra: el registro en memoria sigue siendo el v1 original.
        assert_eq!(auth.credentials().record().unwrap().to_bytes(), v1);
    }

    #[test]
    fn change_set_and_revoke_migrate_v1_to_v2_preserving_generation_and_status() {
        let kdf = CountingFakeKdf::default();

        // change (rotate): v1 habilitado -> v2 habilitado, generación + 1.
        let mut state = UnattendedCredentialState::from_record(
            PasswordVerifierRecord::from_bytes(&v1_bytes(&kdf, PW, 7)).unwrap(),
        );
        assert_eq!(state.rotate(PW2, &kdf), Ok(8));
        let rec = state.record().unwrap();
        assert_eq!(rec.version(), 2);
        assert_eq!(rec.kdf_params(), VerifierKdfParams::PRODUCTION);
        assert_eq!(state.status(), UnattendedStatus::Enabled { generation: 8 });
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), VERIFIER_RECORD_V2_LEN);
        let mut auth = UnattendedAuthenticator::new(UnattendedCredentialState::from_record(
            PasswordVerifierRecord::from_bytes(&bytes).unwrap(),
        ));
        let t0 = Instant::now();
        assert!(auth.authenticate("s", PW, &kdf, t0).is_err());
        assert_eq!(
            auth.authenticate("s", PW2, &kdf, t0).unwrap().generation(),
            8
        );

        // revoke: v1 habilitado -> v2 revocado sin material, generación + 1.
        let mut state = UnattendedCredentialState::from_record(
            PasswordVerifierRecord::from_bytes(&v1_bytes(&kdf, PW, 7)).unwrap(),
        );
        assert_eq!(state.revoke(), Ok(8));
        let revoked = state.record().unwrap().to_bytes();
        assert_eq!(revoked.len(), VERIFIER_RECORD_V2_LEN);
        assert_eq!(revoked[6], STATUS_REVOKED);
        assert!(revoked[24..].iter().all(|b| *b == 0));
        let reloaded = PasswordVerifierRecord::from_bytes(&revoked).unwrap();
        assert_eq!(reloaded.status(), VerifierStatus::Revoked);
        assert_eq!(reloaded.generation(), 8);

        // set (configure) tras un v1 revocado -> v2 habilitado, generación + 1.
        let mut v1_revoked = v1_bytes(&kdf, PW, 4);
        v1_revoked[6] = STATUS_REVOKED;
        v1_revoked[16..].fill(0);
        let mut state = UnattendedCredentialState::from_record(
            PasswordVerifierRecord::from_bytes(&v1_revoked).unwrap(),
        );
        assert_eq!(state.status(), UnattendedStatus::Revoked { generation: 4 });
        assert_eq!(
            state.rotate(PW2, &kdf),
            Err(UnattendedError::UnattendedDisabled)
        );
        assert_eq!(state.configure(PW2, &kdf), Ok(5));
        assert_eq!(state.record().unwrap().version(), 2);
        assert_eq!(state.status(), UnattendedStatus::Enabled { generation: 5 });
    }

    #[test]
    fn v2_rejects_parameters_below_policy_or_above_cap_and_bad_fields() {
        let kdf = CountingFakeKdf::default();
        let below = UnattendedError::InvalidRecord("parametros Argon2id por debajo de la politica");
        let above = UnattendedError::InvalidRecord("parametros Argon2id por encima del tope");
        let parse = |m, t, p| PasswordVerifierRecord::from_bytes(&v2_bytes(&kdf, PW, 1, m, t, p));

        assert_eq!(parse(19_455, 2, 1).unwrap_err(), below);
        assert_eq!(parse(19_456, 1, 1).unwrap_err(), below);
        assert_eq!(parse(19_456, 2, 0).unwrap_err(), below);
        assert_eq!(parse(ARGON2ID_MAX_M_COST_KIB + 1, 2, 1).unwrap_err(), above);
        assert_eq!(
            parse(19_456, ARGON2ID_MAX_T_COST + 1, 1).unwrap_err(),
            above
        );
        assert_eq!(
            parse(19_456, 2, ARGON2ID_MAX_P_COST + 1).unwrap_err(),
            above
        );
        assert_eq!(parse(u32::MAX, u32::MAX, u32::MAX).unwrap_err(), above);
        assert!(
            parse(
                ARGON2ID_MAX_M_COST_KIB,
                ARGON2ID_MAX_T_COST,
                ARGON2ID_MAX_P_COST
            )
            .is_ok()
        );

        let good = v2_bytes(&kdf, PW, 1, 19_456, 2, 1);
        let mutate = |idx: usize, val: u8| {
            let mut b = good.clone();
            b[idx] = val;
            PasswordVerifierRecord::from_bytes(&b)
        };
        assert_eq!(
            mutate(7, 0x10).unwrap_err(),
            UnattendedError::InvalidRecord("version de Argon2 no soportada")
        );
        assert_eq!(
            mutate(5, VERIFIER_ALGORITHM_PBKDF2_HMAC_SHA256).unwrap_err(),
            UnattendedError::InvalidRecord("algoritmo no soportado")
        );
        assert_eq!(
            mutate(4, 1).unwrap_err(),
            UnattendedError::InvalidRecord("longitud inesperada")
        );
        assert_eq!(
            mutate(6, 9).unwrap_err(),
            UnattendedError::InvalidRecord("estado desconocido")
        );
        assert_eq!(
            mutate(6, STATUS_REVOKED).unwrap_err(),
            UnattendedError::InvalidRecord("registro revocado con material residual")
        );
        let mut zero_gen = good.clone();
        zero_gen[12..16].fill(0);
        assert_eq!(
            PasswordVerifierRecord::from_bytes(&zero_gen).unwrap_err(),
            UnattendedError::InvalidRecord("generacion cero")
        );
        assert!(PasswordVerifierRecord::from_bytes(&good[..71]).is_err());
        let mut longer = good.clone();
        longer.push(0);
        assert!(PasswordVerifierRecord::from_bytes(&longer).is_err());
    }

    #[test]
    fn tampered_v2_record_never_authenticates() {
        let kdf = CountingFakeKdf::default();
        let good = v2_bytes(&kdf, PW, 3, 19_456, 2, 1);
        // Salt, clave derivada o parámetros alterados (dentro de los topes): decodifica pero no verifica.
        for (idx, val) in [
            (24, 0xAA),
            (39, 0x55),
            (40, 0x01),
            (71, 0xFF),
            (8, 0x01),
            (16, 0x01),
            (20, 0x03),
        ] {
            let mut b = good.clone();
            b[idx] ^= val;
            let rec = PasswordVerifierRecord::from_bytes(&b).unwrap();
            let mut auth =
                UnattendedAuthenticator::new(UnattendedCredentialState::from_record(rec));
            assert_eq!(
                auth.authenticate("s", PW, &kdf, Instant::now())
                    .unwrap_err(),
                UnattendedError::InvalidPassword,
                "byte {idx} alterado"
            );
        }
    }

    #[test]
    fn set_change_and_revoke_never_lower_parameters() {
        let kdf = CountingFakeKdf::default();
        let strong = VerifierKdfParams::Argon2id {
            m_cost_kib: 32_768,
            t_cost: 3,
            p_cost: 2,
        };
        let mut state = UnattendedCredentialState::from_record(
            PasswordVerifierRecord::from_bytes(&v2_bytes(&kdf, PW, 1, 32_768, 3, 2)).unwrap(),
        );
        assert_eq!(state.rotate(PW2, &kdf), Ok(2));
        assert_eq!(state.record().unwrap().kdf_params(), strong);
        assert_eq!(state.revoke(), Ok(3));
        let revoked = state.record().unwrap().to_bytes();
        assert_eq!(
            PasswordVerifierRecord::from_bytes(&revoked)
                .unwrap()
                .kdf_params(),
            strong
        );
        assert_eq!(state.configure(PW, &kdf), Ok(4));
        assert_eq!(state.record().unwrap().kdf_params(), strong);

        // Cualquier registro aceptable produce un sucesor Argon2id >= producción en cada eje.
        for params in [
            VerifierKdfParams::Pbkdf2HmacSha256 {
                iterations: PBKDF2_MAX_ITERATIONS,
            },
            VerifierKdfParams::PRODUCTION,
            VerifierKdfParams::Argon2id {
                m_cost_kib: ARGON2ID_MAX_M_COST_KIB,
                t_cost: 2,
                p_cost: ARGON2ID_MAX_P_COST,
            },
        ] {
            let VerifierKdfParams::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } = params.successor()
            else {
                panic!("el sucesor siempre es Argon2id");
            };
            assert!(m_cost_kib >= PRODUCTION_ARGON2ID_M_COST_KIB);
            assert!(t_cost >= PRODUCTION_ARGON2ID_T_COST);
            assert!(p_cost >= PRODUCTION_ARGON2ID_P_COST);
        }
    }

    #[test]
    fn debug_and_audit_of_migrated_records_carry_no_secrets() {
        let kdf = CountingFakeKdf::default();
        let v1 = PasswordVerifierRecord::from_bytes(&v1_bytes(&kdf, PW, 7)).unwrap();
        let v1_secrets = [hex(&v1.salt, false), hex(&v1.dk, false), hex(&v1.dk, true)];
        let dbg_v1 = format!("{v1:?}");
        let mut state = UnattendedCredentialState::from_record(v1);
        let generation = state.rotate(PW2, &kdf).unwrap();
        let v2 = state.record().unwrap();
        let dbg_v2 = format!("{v2:?}");
        let line = AuditRecord::new(
            1,
            AuditEvent::PasswordRotated { generation },
            "Administrador",
        )
        .to_json_line();
        let mut secrets = vec![
            PW.to_string(),
            PW2.to_string(),
            hex(&v2.salt, false),
            hex(&v2.dk, false),
        ];
        secrets.extend(v1_secrets);
        for text in [&dbg_v1, &dbg_v2, &line] {
            for secret in &secrets {
                assert!(
                    !text.contains(secret.as_str()),
                    "secreto filtrado en: {text}"
                );
            }
        }
        assert!(dbg_v1.contains("[REDACTED]") && dbg_v2.contains("[REDACTED]"));
    }
}
