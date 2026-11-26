use std::fmt;

use zeroize::Zeroizing;

/// Alfabeto sin caracteres ambiguos (excluye 0, O, 1, I, l) para lectura telefónica sin errores.
pub(crate) const PASSWORD_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialsError {
    OsRngFailed(i32),
    InvalidSessionIdFormat,
    EmptyPassword,
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OsRngFailed(code) => {
                write!(f, "fallo CSPRNG del sistema operativo (NTSTATUS={code:#x})")
            }
            Self::InvalidSessionIdFormat => {
                write!(f, "formato de ID de sesion invalido (esperado 9 digitos)")
            }
            Self::EmptyPassword => write!(f, "la contrasena no puede estar vacia"),
        }
    }
}

impl std::error::Error for CredentialsError {}

#[cfg(target_os = "windows")]
pub(crate) fn fill_os_random(buf: &mut [u8]) -> Result<(), CredentialsError> {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }
    let len = u32::try_from(buf.len()).map_err(|_| CredentialsError::OsRngFailed(-1))?;
    // SAFETY: `buf` apunta a memoria mutable válida de `len` bytes y `BCRYPT_USE_SYSTEM_PREFERRED_RNG`
    // permite `h_algorithm = null` según contrato oficial de Windows CNG.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(CredentialsError::OsRngFailed(status))
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn fill_os_random(buf: &mut [u8]) -> Result<(), CredentialsError> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom").map_err(|_| CredentialsError::OsRngFailed(-1))?;
    f.read_exact(buf)
        .map_err(|_| CredentialsError::OsRngFailed(-2))
}

/// Identificador numérico efímero de 9 dígitos (`XXX-XXX-XXX`), generado exclusivamente por el cliente receptor.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u32);

impl SessionId {
    pub fn parse(raw: &str) -> Result<Self, CredentialsError> {
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 9 {
            return Err(CredentialsError::InvalidSessionIdFormat);
        }
        let val: u32 = digits
            .parse()
            .map_err(|_| CredentialsError::InvalidSessionIdFormat)?;
        if !(100_000_000..=999_999_999).contains(&val) {
            return Err(CredentialsError::InvalidSessionIdFormat);
        }
        Ok(Self(val))
    }

    pub fn formatted(&self) -> String {
        let a = self.0 / 1_000_000;
        let b = (self.0 / 1_000) % 1_000;
        let c = self.0 % 1_000;
        format!("{a:03}-{b:03}-{c:03}")
    }

    pub fn raw_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self.formatted())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.formatted())
    }
}

/// Contraseña efímera de un solo uso (~50 bits de entropía: 10 símbolos de base 32 `XXXXX-XXXXX`).
/// Limpia sus bytes en memoria al destruirse (`Drop`).
pub struct SessionPassword {
    secret: Vec<u8>,
}

impl SessionPassword {
    pub fn expose_formatted(&self) -> String {
        let s = String::from_utf8_lossy(&self.secret);
        if s.len() == 10 {
            format!("{}-{}", &s[..5], &s[5..])
        } else {
            s.into_owned()
        }
    }

    /// Comparación en tiempo constante sobre la representación normalizada (sin guiones ni espacios, mayúsculas).
    pub fn verify_constant_time(&self, candidate: &str) -> bool {
        let normalized = normalize_password_input(candidate);

        let max_len = self.secret.len().max(normalized.len());
        let mut diff: u8 = (self.secret.len() ^ normalized.len()) as u8;
        for i in 0..max_len {
            let a = self.secret.get(i).copied().unwrap_or(0);
            let b = normalized.get(i).copied().unwrap_or(0xFF);
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Bytes normalizados de la contraseña: entrada del intercambio SPAKE2 del lado del host.
    pub(crate) fn normalized_bytes(&self) -> &[u8] {
        &self.secret
    }
}

/// Normaliza la contraseña tecleada por el operador (sin guiones ni espacios, mayúsculas).
/// El búfer se limpia de memoria al destruirse.
pub(crate) fn normalize_password_input(candidate: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        candidate
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'-')
            .map(|b| b.to_ascii_uppercase())
            .collect(),
    )
}

impl Drop for SessionPassword {
    fn drop(&mut self) {
        for b in &mut self.secret {
            // Limpieza volátil en memoria para evitar residuos de credenciales tras cerrar la sesión.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for SessionPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionPassword([REDACTED])")
    }
}

/// Par de credenciales generado exclusivamente en el equipo del Cliente que solicita soporte.
#[derive(Debug)]
pub struct HostCredentials {
    session_id: SessionId,
    password: SessionPassword,
}

impl HostCredentials {
    pub fn generate_for_client_host() -> Result<Self, CredentialsError> {
        let mut raw = [0u8; 16];
        fill_os_random(&mut raw)?;

        let rnd_u32 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let id_num = 100_000_000 + (rnd_u32 % 900_000_000);

        let mut secret = Vec::with_capacity(10);
        for &b in &raw[4..14] {
            let idx = (b & 0x1F) as usize;
            secret.push(PASSWORD_ALPHABET[idx]);
        }

        // Limpia buffer temporal
        raw.fill(0);

        Ok(Self {
            session_id: SessionId(id_num),
            password: SessionPassword { secret },
        })
    }

    pub fn rotate_password(&mut self) -> Result<(), CredentialsError> {
        let mut raw = [0u8; 10];
        fill_os_random(&mut raw)?;
        let mut secret = Vec::with_capacity(10);
        for &b in &raw {
            secret.push(PASSWORD_ALPHABET[(b & 0x1F) as usize]);
        }
        raw.fill(0);
        self.password = SessionPassword { secret };
        Ok(())
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn password(&self) -> &SessionPassword {
        &self.password
    }
}
