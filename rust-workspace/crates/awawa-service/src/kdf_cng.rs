//! PBKDF2-HMAC-SHA256 con CNG (`bcrypt.dll`): implementacion de [`PasswordKdf`] para el verificador v1.

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use awawa_protocol::unattended::{KdfError, PasswordKdf, VerifierKdfParams};

const BCRYPT_ALG_HANDLE_HMAC_FLAG: u32 = 0x0000_0008;
/// `BCRYPT_SHA256_ALGORITHM` = L"SHA256" terminado en NUL.
const BCRYPT_SHA256_ALGORITHM: [u16; 7] = [0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0];

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptOpenAlgorithmProvider(
        ph_algorithm: *mut *mut c_void,
        psz_alg_id: *const u16,
        psz_implementation: *const u16,
        dw_flags: u32,
    ) -> i32;
    fn BCryptCloseAlgorithmProvider(h_algorithm: *mut c_void, dw_flags: u32) -> i32;
    fn BCryptDeriveKeyPBKDF2(
        h_prf: *mut c_void,
        pb_password: *mut u8,
        cb_password: u32,
        pb_salt: *mut u8,
        cb_salt: u32,
        c_iterations: u64,
        pb_derived_key: *mut u8,
        cb_derived_key: u32,
        dw_flags: u32,
    ) -> i32;
}

/// PBKDF2-HMAC-SHA256 generico (salt y salida de longitud arbitraria).
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    if iterations == 0 || out.is_empty() {
        return Err(KdfError::InvalidParameters);
    }
    let (Ok(cb_password), Ok(cb_salt), Ok(cb_out)) = (
        u32::try_from(password.len()),
        u32::try_from(salt.len()),
        u32::try_from(out.len()),
    ) else {
        return Err(KdfError::InvalidParameters);
    };

    let mut handle: *mut c_void = null_mut();
    // SAFETY: `handle` es un destino valido para el manejador; el identificador de algoritmo es una
    // cadena ancha terminada en NUL de vida 'static; la implementacion nula elige el proveedor por defecto.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut handle,
            BCRYPT_SHA256_ALGORITHM.as_ptr(),
            null(),
            BCRYPT_ALG_HANDLE_HMAC_FLAG,
        )
    };
    if status != 0 {
        return Err(KdfError::BackendFailure(status));
    }

    // SAFETY: `handle` es un proveedor HMAC valido abierto arriba; los punteros de contrasena y salt
    // cubren `cb_password`/`cb_salt` bytes y la API solo los lee (el tipo `*mut` es de la firma de Win32);
    // `out` es memoria mutable valida de `cb_out` bytes.
    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            handle,
            password.as_ptr().cast_mut(),
            cb_password,
            salt.as_ptr().cast_mut(),
            cb_salt,
            u64::from(iterations),
            out.as_mut_ptr(),
            cb_out,
            0,
        )
    };
    // SAFETY: `handle` fue abierto arriba y no se usa despues de cerrarlo.
    unsafe { BCryptCloseAlgorithmProvider(handle, 0) };

    if status != 0 {
        return Err(KdfError::BackendFailure(status));
    }
    Ok(())
}

/// PBKDF2-HMAC-SHA256 vía CNG (solo verificadores v1). Para Argon2id devuelve
/// [`KdfError::InvalidParameters`]; el servicio usa [`crate::kdf_argon2::ServiceKdf`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CngPbkdf2Sha256;

impl PasswordKdf for CngPbkdf2Sha256 {
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8; 16],
        params: VerifierKdfParams,
        out: &mut [u8; 32],
    ) -> Result<(), KdfError> {
        match params {
            VerifierKdfParams::Pbkdf2HmacSha256 { iterations } => {
                pbkdf2_sha256(password, salt, iterations, out)
            }
            VerifierKdfParams::Argon2id { .. } => Err(KdfError::InvalidParameters),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf_argon2::ServiceKdf;
    use awawa_protocol::unattended::{
        UnattendedAuthenticator, UnattendedCredentialState, UnattendedError, UnattendedStatus,
    };
    use std::time::Instant;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn vector_pbkdf2_sha256_c1() {
        let mut dk = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut dk).unwrap();
        assert_eq!(
            hex(&dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn vector_pbkdf2_sha256_c4096() {
        let mut dk = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 4096, &mut dk).unwrap();
        assert_eq!(
            hex(&dk),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn iteraciones_cero_son_invalidas() {
        let mut dk = [0u8; 32];
        assert_eq!(
            pbkdf2_sha256(b"password", b"salt", 0, &mut dk),
            Err(KdfError::InvalidParameters)
        );
    }

    #[test]
    fn trait_deriva_igual_que_la_funcion() {
        let salt = [7u8; 16];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        CngPbkdf2Sha256
            .derive(
                b"password",
                &salt,
                VerifierKdfParams::Pbkdf2HmacSha256 { iterations: 2 },
                &mut a,
            )
            .unwrap();
        pbkdf2_sha256(b"password", &salt, 2, &mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            CngPbkdf2Sha256.derive(b"password", &salt, VerifierKdfParams::PRODUCTION, &mut a),
            Err(KdfError::InvalidParameters)
        );
    }

    /// Integracion con el KDF real del servicio (varias derivaciones Argon2id de produccion; tarda).
    #[test]
    fn configurar_rotar_y_autenticar_con_kdf_real() {
        let kdf = ServiceKdf;
        let mut state = UnattendedCredentialState::not_configured();
        assert_eq!(state.configure("primera-clave-larga", &kdf), Ok(1));
        assert_eq!(
            state.record().unwrap().kdf_params(),
            VerifierKdfParams::PRODUCTION
        );
        assert_eq!(state.rotate("segunda-clave-larga", &kdf), Ok(2));
        assert_eq!(state.status(), UnattendedStatus::Enabled { generation: 2 });

        let mut auth = UnattendedAuthenticator::new(state);
        let now = Instant::now();
        let ok = auth
            .authenticate("op-1", "segunda-clave-larga", &kdf, now)
            .expect("la clave correcta autentica");
        assert_eq!(ok.generation(), 2);
        assert!(matches!(
            auth.authenticate("op-1", "primera-clave-larga", &kdf, now),
            Err(UnattendedError::InvalidPassword)
        ));
    }
}
