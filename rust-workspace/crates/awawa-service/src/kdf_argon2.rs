//! Argon2id (crate `argon2`, RFC 9106) para el verificador v2 y [`ServiceKdf`], el KDF del servicio:
//! Argon2id para los registros v2 y PBKDF2-HMAC-SHA256 con CNG ([`crate::kdf_cng`]) para los v1.
//!
//! La memoria de trabajo (`m_cost` KiB) la reserva este modulo con `try_reserve_exact` (sin abortar el
//! proceso si no hay memoria) y se pone a cero antes de liberarla.

use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use awawa_protocol::unattended::{KdfError, PasswordKdf, VerifierKdfParams};
use zeroize::Zeroize;

use crate::kdf_cng::pbkdf2_sha256;

/// `STATUS_NO_MEMORY`: la reserva de la memoria de trabajo fallo.
const STATUS_NO_MEMORY: i32 = 0xC000_0017_u32 as i32;

/// Argon2id v0x13 con secreto y datos asociados opcionales (los usa solo el vector de la RFC 9106).
fn argon2id_with(
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    associated_data: &[u8],
    (m_cost_kib, t_cost, p_cost): (u32, u32, u32),
    out: &mut [u8],
) -> Result<(), KdfError> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(m_cost_kib)
        .t_cost(t_cost)
        .p_cost(p_cost)
        .output_len(out.len());
    if !associated_data.is_empty() {
        builder
            .data(AssociatedData::new(associated_data).map_err(|_| KdfError::InvalidParameters)?);
    }
    let params = builder.build().map_err(|_| KdfError::InvalidParameters)?;
    let blocks_len = params.block_count();
    let context = match secret {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
                .map_err(|_| KdfError::InvalidParameters)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
    };

    let mut blocks: Vec<Block> = Vec::new();
    blocks
        .try_reserve_exact(blocks_len)
        .map_err(|_| KdfError::BackendFailure(STATUS_NO_MEMORY))?;
    blocks.resize(blocks_len, Block::new());
    let result = context
        .hash_password_into_with_memory(password, salt, out, &mut blocks[..])
        .map_err(|_| KdfError::InvalidParameters);
    blocks.zeroize();
    result
}

/// Argon2id v0x13 sin secreto ni datos asociados (formato v2 del verificador).
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    argon2id_with(password, salt, None, &[], (m_cost_kib, t_cost, p_cost), out)
}

/// KDF de produccion del servicio: Argon2id para v2 y PBKDF2-HMAC-SHA256 (CNG) para v1.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceKdf;

impl PasswordKdf for ServiceKdf {
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
            VerifierKdfParams::Argon2id {
                m_cost_kib,
                t_cost,
                p_cost,
            } => argon2id(password, salt, m_cost_kib, t_cost, p_cost, out),
        }
    }
}

/// Verificador v1 escrito por la version anterior: "Clave-Version1-Heredada", salt 0x10..=0x1f,
/// 600 000 iteraciones, generacion 7. La clave derivada se calculo fuera de Rust con
/// `hashlib.pbkdf2_hmac('sha256', ...)` de Python.
#[cfg(test)]
pub(crate) const V1_VECTOR_HEX: &str = concat!(
    "55415056",
    "01010100",
    "c0270900",
    "07000000",
    "101112131415161718191a1b1c1d1e1f",
    "7ea3c45ea40fb0fd4c95effac345d9232cb8f53019774bc697640d8c9d87fc92",
);
#[cfg(test)]
pub(crate) const V1_VECTOR_PASSWORD: &str = "Clave-Version1-Heredada";

/// Bytes del verificador v1 de [`V1_VECTOR_HEX`].
#[cfg(test)]
pub(crate) fn v1_vector_bytes() -> Vec<u8> {
    (0..V1_VECTOR_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&V1_VECTOR_HEX[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::unattended::{
        PasswordVerifierRecord, UnattendedAuthenticator, UnattendedCredentialState,
        UnattendedError, UnattendedStatus,
    };
    use std::time::Instant;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 9106 §5.3 (Argon2id v0x13): m = 32 KiB, t = 3, p = 4, password 32 x 0x01, salt 16 x 0x02,
    /// secret 8 x 0x03, associated data 12 x 0x04, tag de 32 bytes.
    #[test]
    fn vector_rfc9106_argon2id() {
        let mut tag = [0u8; 32];
        argon2id_with(
            &[0x01; 32],
            &[0x02; 16],
            Some(&[0x03; 8]),
            &[0x04; 12],
            (32, 3, 4),
            &mut tag,
        )
        .unwrap();
        assert_eq!(
            hex(&tag),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// Vector propio con los parametros de produccion (m = 19 456 KiB, t = 2, p = 1), password
    /// "Clave-Desatendida-2026" y salt 0x00..=0x0f. Recalculado fuera de Rust con OpenSSL 3.5
    /// (`openssl kdf ... ARGON2ID`) y con `crypto.argon2Sync` de Node: ambos dan el mismo valor.
    #[test]
    fn vector_propio_argon2id_produccion() {
        let salt: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut out = [0u8; 32];
        ServiceKdf
            .derive(
                b"Clave-Desatendida-2026",
                &salt,
                VerifierKdfParams::PRODUCTION,
                &mut out,
            )
            .unwrap();
        assert_eq!(
            hex(&out),
            "d22533fff02ab851fc86477cc87de958d05fc7021f908ec3da36faab046ad937"
        );
    }

    #[test]
    fn parametros_invalidos_no_derivan() {
        let mut out = [0u8; 32];
        // m < 8 * p: Argon2 lo rechaza.
        assert_eq!(
            argon2id(b"password", &[0u8; 16], 8, 1, 2, &mut out),
            Err(KdfError::InvalidParameters)
        );
        assert_eq!(
            argon2id(b"password", &[0u8; 16], 64, 0, 1, &mut out),
            Err(KdfError::InvalidParameters)
        );
    }

    #[test]
    fn v1_existente_autentica_con_pbkdf2_cng_y_change_migra_a_v2() {
        let bytes = v1_vector_bytes();
        let rec = PasswordVerifierRecord::from_bytes(&bytes).unwrap();
        assert_eq!(rec.version(), 1);
        assert_eq!(rec.to_bytes(), bytes);

        let kdf = ServiceKdf;
        let mut auth = UnattendedAuthenticator::new(UnattendedCredentialState::from_record(rec));
        let now = Instant::now();
        assert!(matches!(
            auth.authenticate("op", "otra-clave-larga", &kdf, now),
            Err(UnattendedError::InvalidPassword)
        ));
        assert_eq!(
            auth.authenticate("op", V1_VECTOR_PASSWORD, &kdf, now)
                .unwrap()
                .generation(),
            7
        );
        assert_eq!(auth.credentials().record().unwrap().to_bytes(), bytes);

        assert_eq!(
            auth.credentials_mut().rotate("clave-migrada-v2!", &kdf),
            Ok(8)
        );
        let migrated = auth.credentials().record().unwrap();
        assert_eq!(migrated.version(), 2);
        assert_eq!(migrated.kdf_params(), VerifierKdfParams::PRODUCTION);
        assert_eq!(
            auth.credentials().status(),
            UnattendedStatus::Enabled { generation: 8 }
        );
        assert!(
            auth.authenticate("op", "clave-migrada-v2!", &kdf, now)
                .is_ok()
        );
        assert!(
            auth.authenticate("op", V1_VECTOR_PASSWORD, &kdf, now)
                .is_err()
        );
    }

    /// Medicion de una derivacion de produccion (tiempo y memoria reservada). Informativa: imprime y solo
    /// exige que la memoria de trabajo sea la esperada. `cargo test --release -p awawa-service medicion
    /// -- --nocapture` da la cifra de release.
    #[test]
    fn medicion_derivacion_produccion() {
        let VerifierKdfParams::Argon2id {
            m_cost_kib,
            t_cost,
            p_cost,
        } = VerifierKdfParams::PRODUCTION
        else {
            unreachable!()
        };
        let params = argon2::Params::new(m_cost_kib, t_cost, p_cost, Some(32)).unwrap();
        assert_eq!(params.block_count() * Block::SIZE, 19_456 * 1024);
        let mut out = [0u8; 32];
        let start = Instant::now();
        ServiceKdf
            .derive(
                b"medicion-de-tiempo",
                &[7u8; 16],
                VerifierKdfParams::PRODUCTION,
                &mut out,
            )
            .unwrap();
        println!(
            "argon2id m={m_cost_kib} KiB t={t_cost} p={p_cost}: {:?}, memoria de trabajo {} KiB",
            start.elapsed(),
            params.block_count() * Block::SIZE / 1024
        );
    }
}
