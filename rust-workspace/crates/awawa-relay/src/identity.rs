//! Identidad TLS del relay (certificado autofirmado con rcgen) y su clave fijada en los clientes.
//!
//! Los clientes no usan raices de internet ni el verificador de la plataforma: conocen de antemano
//! el certificado del relay (`RelayPin`) y rechazan cualquier otro por comparacion exacta. La firma
//! del handshake TLS 1.3 se verifica con el proveedor `ring` contra la clave publica de ese
//! certificado, de modo que solo quien posee la clave privada del relay completa el handshake.
//! Rotar la identidad implica distribuir un nuevo pin.

use std::fmt;
use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, ring as ring_provider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error as TlsError};
use zeroize::Zeroize;

use crate::protocol::SERVER_NAME;

#[derive(Debug)]
pub enum IdentityError {
    Generate(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate(e) => write!(f, "no se pudo generar la identidad del relay: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Certificado (DER) y clave privada (PKCS#8 DER) del relay. Al soltarse, los bytes de la clave
/// propia se ponen a cero (las copias que haga `rustls` al construir el servidor no dependen de esto).
#[derive(Clone)]
pub struct RelayIdentity {
    cert_der: Vec<u8>,
    key_pkcs8_der: Vec<u8>,
}

impl RelayIdentity {
    /// Genera un par de claves ECDSA P-256 y un certificado autofirmado nuevos.
    pub fn generate() -> Result<Self, IdentityError> {
        let key = rcgen::KeyPair::generate().map_err(|e| IdentityError::Generate(e.to_string()))?;
        let params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])
            .map_err(|e| IdentityError::Generate(e.to_string()))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| IdentityError::Generate(e.to_string()))?;
        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_pkcs8_der: key.serialize_der(),
        })
    }

    /// Reconstruye la identidad desde material guardado. La validez del par se comprueba al
    /// construir el servidor (`RelayServer::bind`).
    pub fn from_der(cert_der: Vec<u8>, key_pkcs8_der: Vec<u8>) -> Self {
        Self {
            cert_der,
            key_pkcs8_der,
        }
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn key_pkcs8_der(&self) -> &[u8] {
        &self.key_pkcs8_der
    }

    /// Clave fijada que se distribuye a los clientes (material publico).
    pub fn pin(&self) -> RelayPin {
        RelayPin::from_cert_der(self.cert_der.clone())
    }
}

impl Drop for RelayIdentity {
    fn drop(&mut self) {
        self.key_pkcs8_der.zeroize();
    }
}

impl fmt::Debug for RelayIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayIdentity")
            .field("cert_der_len", &self.cert_der.len())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Certificado del relay que los clientes aceptan (comparacion exacta de los bytes DER).
#[derive(Clone, PartialEq, Eq)]
pub struct RelayPin(Vec<u8>);

impl RelayPin {
    pub fn from_cert_der(cert_der: Vec<u8>) -> Self {
        Self(cert_der)
    }

    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RelayPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayPin({} bytes)", self.0.len())
    }
}

/// Verificador de certificados que acepta unicamente el certificado fijado.
#[derive(Debug)]
pub(crate) struct PinnedCertVerifier {
    pin: RelayPin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    pub(crate) fn new(pin: RelayPin) -> Arc<Self> {
        Arc::new(Self {
            pin,
            algorithms: ring_provider::default_provider().signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    /// Acepta solo si el certificado presentado es byte a byte el fijado. No se valida cadena,
    /// nombre ni vigencia: el pin sustituye a la PKI.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.pin.as_der() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_clave_se_pone_a_cero_al_soltar() {
        let mut identity = RelayIdentity::from_der(vec![1, 2, 3], vec![0xAB; 64]);
        let ptr = identity.key_pkcs8_der.as_ptr();
        let cap = identity.key_pkcs8_der.capacity();
        // Es la misma llamada que hace `Drop`; el buffer sigue asignado tras vaciarse, asi que se puede leer.
        identity.key_pkcs8_der.zeroize();
        assert!(identity.key_pkcs8_der.is_empty());
        // SAFETY: `Vec::zeroize` conserva la asignacion (capacidad intacta) y `identity` sigue viva.
        let wiped = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(wiped.iter().all(|b| *b == 0));
    }

    fn name() -> ServerName<'static> {
        ServerName::try_from(SERVER_NAME).unwrap()
    }

    fn verify(verifier: &PinnedCertVerifier, cert: &[u8]) -> Result<ServerCertVerified, TlsError> {
        verifier.verify_server_cert(
            &CertificateDer::from(cert.to_vec()),
            &[],
            &name(),
            &[],
            UnixTime::now(),
        )
    }

    #[test]
    fn accepts_only_the_exact_pinned_certificate() {
        let relay = RelayIdentity::generate().unwrap();
        let other = RelayIdentity::generate().unwrap();
        let verifier = PinnedCertVerifier::new(relay.pin());
        assert!(verify(&verifier, relay.cert_der()).is_ok());
        assert!(verify(&verifier, other.cert_der()).is_err());
        let mut altered = relay.cert_der().to_vec();
        *altered.last_mut().unwrap() ^= 1;
        assert!(verify(&verifier, &altered).is_err());
        assert!(verify(&verifier, &[]).is_err());
    }

    #[test]
    fn identities_are_distinct_and_debug_hides_the_key() {
        let a = RelayIdentity::generate().unwrap();
        let b = RelayIdentity::generate().unwrap();
        assert_ne!(a.pin(), b.pin());
        assert_ne!(a.key_pkcs8_der(), b.key_pkcs8_der());
        let shown = format!("{a:?}");
        assert!(shown.contains("REDACTED"));
        assert_eq!(a.pin(), RelayPin::from_cert_der(a.cert_der().to_vec()));
    }
}
