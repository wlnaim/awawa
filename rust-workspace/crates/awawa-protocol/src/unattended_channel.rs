//! Canal E2E del acceso desatendido: X25519 efímero firmado con la clave
//! Ed25519 persistente del servicio, que el operador tiene fijada de antemano (sin TOFU). La
//! contraseña persistente viaja **dentro** del canal.
//!
//! Secuencia por el stream de control (cada mensaje en un frame de `framing`), con el relay como
//! transporte opaco:
//! 1. Operador → Servicio, en claro: `UnattendedHello` (versión, ID destino, nombre, X25519 efímero).
//! 2. Servicio → Operador, en claro: `UnattendedHelloReply::Accepted` (X25519 efímero del servicio y
//!    firma Ed25519 del transcript) o `UnattendedHelloReply::UnsupportedProtocolVersion` (no cuenta
//!    como intento).
//! 3. El operador verifica la firma con la clave fijada; si falla aborta sin enviar nada más.
//! 4. Operador → Servicio: registro `SecureChannel` n.º 0 con la contraseña tal como se escribió.
//! 5. Servicio → Operador: registro `SecureChannel` n.º 0 con `UnattendedAuthReply` genérico
//!    (`Granted` o `Rejected` con el tiempo de espera, si aplica).
//! 6. Con `Granted`, el control sigue por el mismo `SecureChannel` y el video por `video_channel`.
//!
//! Transcript: `SHA-256(etiqueta ‖ lp(postcard(UnattendedHello)) ‖ efímero del servicio ‖ clave
//! pública Ed25519 del servicio)`. La firma cubre el transcript, de modo que versión, ID, nombre y
//! ambos efímeros quedan autenticados.
//! Derivación: `HKDF-SHA256(salt = transcript, ikm = X25519)` → claves direccionales de control,
//! clave de video, SAS de 6 caracteres y huella de sesión, con etiquetas propias (distintas de las
//! de SPAKE2).
//! Módulo puro: sin red ni E/S. Cada paso consume el estado anterior; cualquier error lo descarta y
//! con él el canal.

use std::convert::Infallible;
use std::fmt;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::rand_core::{TryCryptoRng, TryRng};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

pub use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::credentials::{CredentialsError, PASSWORD_ALPHABET, fill_os_random};
use crate::handshake::SasCode;
use crate::secure_channel::{ChannelError, Direction, SecureChannel};
use crate::unattended::{UnattendedAuthorization, UnattendedError};
use crate::video_channel::{VideoOpener, VideoSealer};

const TRANSCRIPT_LABEL: &[u8] = b"support-protocol/v1 unattended x25519 transcript";
const INFO_KEY_OPERATOR_TO_HOST: &[u8] = b"support-protocol/v1 unattended key op->host";
const INFO_KEY_HOST_TO_OPERATOR: &[u8] = b"support-protocol/v1 unattended key host->op";
const INFO_KEY_VIDEO_HOST_TO_OPERATOR: &[u8] = b"support-protocol/v1 unattended key video host->op";
const INFO_SAS: &[u8] = b"support-protocol/v1 unattended sas";
const INFO_FINGERPRINT: &[u8] = b"support-protocol/v1 unattended fingerprint";

/// Versión del protocolo desatendido que envía el operador en `UnattendedHello`.
pub const UNATTENDED_PROTOCOL_VERSION: u16 = 1;

/// Primer mensaje del operador. Viaja en claro, pero queda ligado al transcript firmado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattendedHello {
    pub protocol_version: u16,
    pub target_id: u32,
    pub operator_display_name: String,
    pub operator_ephemeral: [u8; 32],
}

/// Respuesta del servicio al hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnattendedHelloReply {
    /// Efímero del servicio y firma Ed25519 (64 bytes) del transcript.
    Accepted {
        service_ephemeral: [u8; 32],
        signature: Vec<u8>,
    },
    /// El servicio solo habla `supported`. No es un fallo de contraseña ni cuenta como intento.
    UnsupportedProtocolVersion { supported: u16 },
}

/// Contenido del primer registro cifrado del operador. Solo existe dentro del canal.
#[derive(Serialize, Deserialize)]
struct UnattendedAuthRequest<'a> {
    password: &'a str,
}

/// Veredicto que el servicio cifra para el operador. Es genérico: no distingue acceso revocado,
/// contraseña inválida ni bloqueo, salvo el tiempo de espera.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnattendedAuthReply {
    Granted,
    Rejected { retry_after_secs: Option<u32> },
}

/// Resultado que el autenticador del servicio entrega al canal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnattendedVerdict {
    Granted { generation: u32 },
    Rejected { retry_after: Option<Duration> },
}

impl UnattendedVerdict {
    /// Traduce el resultado de `UnattendedAuthenticator::authenticate`. Solo el bloqueo conserva su
    /// tiempo de espera; cualquier otro error es un rechazo sin detalle.
    pub fn from_result(result: &Result<UnattendedAuthorization, UnattendedError>) -> Self {
        match result {
            Ok(authorization) => Self::Granted {
                generation: authorization.generation(),
            },
            Err(UnattendedError::Throttled { retry_after, .. }) => Self::Rejected {
                retry_after: Some(*retry_after),
            },
            Err(_) => Self::Rejected { retry_after: None },
        }
    }

    fn to_reply(self) -> UnattendedAuthReply {
        match self {
            Self::Granted { .. } => UnattendedAuthReply::Granted,
            Self::Rejected { retry_after } => UnattendedAuthReply::Rejected {
                retry_after_secs: retry_after
                    .map(|d| u32::try_from(d.as_secs().max(1)).unwrap_or(u32::MAX)),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnattendedChannelError {
    /// Versión de protocolo distinta; el servicio solo habla `supported`.
    UnsupportedProtocolVersion {
        supported: u16,
    },
    /// El hello va dirigido a otro ID.
    TargetMismatch,
    /// Mensaje o registro que no se puede decodificar.
    Malformed,
    /// La firma no verifica con la clave fijada del servicio.
    InvalidSignature,
    /// El intercambio X25519 dio un secreto no contributivo (punto de orden bajo).
    NonContributoryKeyExchange,
    /// Autenticación rechazada por el servicio (respuesta genérica).
    Rejected {
        retry_after: Option<Duration>,
    },
    Channel(ChannelError),
    Rng(CredentialsError),
}

impl From<ChannelError> for UnattendedChannelError {
    fn from(e: ChannelError) -> Self {
        Self::Channel(e)
    }
}

/// Adapta 32 bytes ya obtenidos del CSPRNG del sistema (o fijos, en pruebas) a la interfaz que
/// pide `EphemeralSecret::random_from_rng`.
struct PreparedRandom<'a>(&'a [u8; 32]);

impl TryRng for PreparedRandom<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3],
        ]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[..8]);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for (d, s) in dst.iter_mut().zip(self.0.iter().cycle()) {
            *d = *s;
        }
        Ok(())
    }
}

impl TryCryptoRng for PreparedRandom<'_> {}

fn ephemeral_from(seed: &Zeroizing<[u8; 32]>) -> EphemeralSecret {
    EphemeralSecret::random_from_rng(&mut PreparedRandom(seed))
}

fn os_ephemeral_seed() -> Result<Zeroizing<[u8; 32]>, UnattendedChannelError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_os_random(seed.as_mut()).map_err(UnattendedChannelError::Rng)?;
    Ok(seed)
}

fn transcript_hash(
    hello: &UnattendedHello,
    service_ephemeral: &[u8; 32],
    service_key: &VerifyingKey,
) -> [u8; 32] {
    let hello_bytes =
        postcard::to_allocvec(hello).expect("la serializacion postcard en memoria no falla");
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_LABEL);
    h.update((hello_bytes.len() as u64).to_be_bytes());
    h.update(&hello_bytes);
    h.update(service_ephemeral);
    h.update(service_key.as_bytes());
    h.finalize().into()
}

/// Secretos de la sesión desatendida. Se limpian de memoria al destruirse.
struct ChannelSecrets {
    key_operator_to_host: Zeroizing<[u8; 32]>,
    key_host_to_operator: Zeroizing<[u8; 32]>,
    key_video_host_to_operator: Zeroizing<[u8; 32]>,
    sas: SasCode,
    fingerprint: [u8; 8],
}

impl ChannelSecrets {
    fn derive(shared: &[u8; 32], transcript: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
        let expand32 = |info: &[u8]| {
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(info, out.as_mut())
                .expect("32 bytes es una longitud valida para HKDF-SHA256");
            out
        };
        let mut sas_raw = Zeroizing::new([0u8; 6]);
        hk.expand(INFO_SAS, sas_raw.as_mut())
            .expect("6 bytes es una longitud valida para HKDF-SHA256");
        let mut sas = [0u8; 6];
        for (dst, src) in sas.iter_mut().zip(sas_raw.iter()) {
            *dst = PASSWORD_ALPHABET[(src & 0x1F) as usize];
        }
        let mut fingerprint = [0u8; 8];
        hk.expand(INFO_FINGERPRINT, &mut fingerprint)
            .expect("8 bytes es una longitud valida para HKDF-SHA256");
        Self {
            key_operator_to_host: expand32(INFO_KEY_OPERATOR_TO_HOST),
            key_host_to_operator: expand32(INFO_KEY_HOST_TO_OPERATOR),
            key_video_host_to_operator: expand32(INFO_KEY_VIDEO_HOST_TO_OPERATOR),
            sas: SasCode(sas),
            fingerprint,
        }
    }
}

fn agree(
    secret: EphemeralSecret,
    peer: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, UnattendedChannelError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(UnattendedChannelError::NonContributoryKeyExchange);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

// ---------------------------------------------------------------------------------------------
// Operador
// ---------------------------------------------------------------------------------------------

/// Operador: hello enviado, esperando la respuesta firmada del servicio.
pub struct OperatorUnattendedHandshake {
    secret: EphemeralSecret,
    hello: UnattendedHello,
    pinned_service_key: VerifyingKey,
}

/// Operador: servicio verificado contra la clave fijada; todavía no envió la contraseña.
pub struct OperatorUnattendedPending {
    secrets: ChannelSecrets,
    channel: SecureChannel,
}

/// Operador: contraseña enviada, esperando el veredicto cifrado.
pub struct OperatorAwaitingAuth {
    secrets: ChannelSecrets,
    channel: SecureChannel,
}

/// Operador autenticado: SAS y huella de la sesión, canal de control y abridor de video.
#[derive(Debug)]
pub struct OperatorUnattendedSession {
    pub sas: SasCode,
    pub fingerprint: [u8; 8],
    pub channel: SecureChannel,
    pub video: VideoOpener,
}

impl OperatorUnattendedHandshake {
    /// Inicia el handshake contra el servicio `target_id`, cuya clave pública Ed25519 el operador
    /// tiene fijada (archivo exportado por `awawa-admin`).
    pub fn start(
        target_id: u32,
        operator_display_name: &str,
        pinned_service_key: &VerifyingKey,
    ) -> Result<(Self, UnattendedHello), UnattendedChannelError> {
        let seed = os_ephemeral_seed()?;
        Ok(Self::start_with_seed(
            target_id,
            operator_display_name,
            pinned_service_key,
            &seed,
        ))
    }

    fn start_with_seed(
        target_id: u32,
        operator_display_name: &str,
        pinned_service_key: &VerifyingKey,
        seed: &Zeroizing<[u8; 32]>,
    ) -> (Self, UnattendedHello) {
        let secret = ephemeral_from(seed);
        let hello = UnattendedHello {
            protocol_version: UNATTENDED_PROTOCOL_VERSION,
            target_id,
            operator_display_name: operator_display_name.to_owned(),
            operator_ephemeral: PublicKey::from(&secret).to_bytes(),
        };
        (
            Self {
                secret,
                hello: hello.clone(),
                pinned_service_key: *pinned_service_key,
            },
            hello,
        )
    }

    /// Verifica la respuesta del servicio. Si la versión no es compatible o la firma no verifica
    /// con la clave fijada, aborta: el operador no envía nada más.
    pub fn handle_reply(
        self,
        reply: &UnattendedHelloReply,
    ) -> Result<OperatorUnattendedPending, UnattendedChannelError> {
        let (service_ephemeral, signature) = match reply {
            UnattendedHelloReply::UnsupportedProtocolVersion { supported } => {
                return Err(UnattendedChannelError::UnsupportedProtocolVersion {
                    supported: *supported,
                });
            }
            UnattendedHelloReply::Accepted {
                service_ephemeral,
                signature,
            } => (service_ephemeral, signature),
        };
        let signature = Signature::from_slice(signature)
            .map_err(|_| UnattendedChannelError::InvalidSignature)?;
        let transcript = transcript_hash(&self.hello, service_ephemeral, &self.pinned_service_key);
        self.pinned_service_key
            .verify_strict(&transcript, &signature)
            .map_err(|_| UnattendedChannelError::InvalidSignature)?;
        let shared = agree(self.secret, service_ephemeral)?;
        let secrets = ChannelSecrets::derive(&shared, &transcript);
        let channel = SecureChannel::new(
            &secrets.key_operator_to_host,
            Direction::OperatorToHost,
            &secrets.key_host_to_operator,
            Direction::HostToOperator,
        );
        Ok(OperatorUnattendedPending { secrets, channel })
    }
}

impl OperatorUnattendedPending {
    pub fn sas(&self) -> SasCode {
        self.secrets.sas
    }

    pub fn fingerprint(&self) -> [u8; 8] {
        self.secrets.fingerprint
    }

    /// Cifra la contraseña, tal como la escribió el técnico, como primer registro del canal. La
    /// copia del operador se borra al terminar.
    pub fn send_password(
        mut self,
        password: Zeroizing<String>,
    ) -> Result<(OperatorAwaitingAuth, Vec<u8>), UnattendedChannelError> {
        let mut buf = Zeroizing::new(vec![0u8; password.len() + 10]);
        let used = postcard::to_slice(
            &UnattendedAuthRequest {
                password: password.as_str(),
            },
            buf.as_mut_slice(),
        )
        .map_err(|_| UnattendedChannelError::Malformed)?
        .len();
        drop(password);
        let record = self.channel.seal(&buf[..used])?;
        Ok((
            OperatorAwaitingAuth {
                secrets: self.secrets,
                channel: self.channel,
            },
            record,
        ))
    }
}

impl OperatorAwaitingAuth {
    /// Abre el veredicto del servicio. Con `Granted` entrega la sesión; con `Rejected` el canal se
    /// descarta.
    pub fn finish(
        mut self,
        record: &[u8],
    ) -> Result<OperatorUnattendedSession, UnattendedChannelError> {
        let plaintext = self.channel.open(record)?;
        match crate::wire::decode_message::<UnattendedAuthReply>(&plaintext)
            .map_err(|_| UnattendedChannelError::Malformed)?
        {
            UnattendedAuthReply::Rejected { retry_after_secs } => {
                Err(UnattendedChannelError::Rejected {
                    retry_after: retry_after_secs.map(|s| Duration::from_secs(u64::from(s))),
                })
            }
            UnattendedAuthReply::Granted => Ok(OperatorUnattendedSession {
                sas: self.secrets.sas,
                fingerprint: self.secrets.fingerprint,
                video: VideoOpener::new(&self.secrets.key_video_host_to_operator),
                channel: self.channel,
            }),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Servicio
// ---------------------------------------------------------------------------------------------

/// Servicio: hello aceptado y respuesta firmada enviada; espera el registro con la contraseña.
pub struct ServiceAwaitingPassword {
    secrets: ChannelSecrets,
    channel: SecureChannel,
    operator_display_name: String,
}

/// Servicio autenticado: SAS y huella, generación con la que se autorizó, canal de control y
/// sellador de video.
#[derive(Debug)]
pub struct ServiceUnattendedSession {
    pub sas: SasCode,
    pub fingerprint: [u8; 8],
    pub generation: u32,
    pub channel: SecureChannel,
    pub video: VideoSealer,
}

/// Resultado de procesar la contraseña. En ambos casos hay que enviar `reply_record` al operador;
/// con `Rejected` el canal ya se descartó y la conexión debe cerrarse después del envío.
#[derive(Debug)]
pub enum ServiceAuthOutcome {
    Granted {
        session: ServiceUnattendedSession,
        reply_record: Vec<u8>,
    },
    Rejected {
        retry_after: Option<Duration>,
        reply_record: Vec<u8>,
    },
}

/// Rechazo del hello por el servicio: el error y, si corresponde, la respuesta que se envía.
pub type ServiceHelloRejection = (UnattendedChannelError, Option<UnattendedHelloReply>);

impl ServiceAwaitingPassword {
    /// Responde al hello con un X25519 efímero firmado con la clave persistente del servicio.
    /// Una versión incompatible devuelve su propia respuesta y no llega al autenticador.
    pub fn respond(
        hello: &UnattendedHello,
        expected_target_id: u32,
        identity: &SigningKey,
    ) -> Result<(Self, UnattendedHelloReply), ServiceHelloRejection> {
        Self::check_hello(hello, expected_target_id)?;
        let seed = os_ephemeral_seed().map_err(|e| (e, None))?;
        Self::respond_with_seed(hello, identity, &seed).map_err(|e| (e, None))
    }

    fn check_hello(
        hello: &UnattendedHello,
        expected_target_id: u32,
    ) -> Result<(), ServiceHelloRejection> {
        if hello.protocol_version != UNATTENDED_PROTOCOL_VERSION {
            return Err((
                UnattendedChannelError::UnsupportedProtocolVersion {
                    supported: UNATTENDED_PROTOCOL_VERSION,
                },
                Some(UnattendedHelloReply::UnsupportedProtocolVersion {
                    supported: UNATTENDED_PROTOCOL_VERSION,
                }),
            ));
        }
        if hello.target_id != expected_target_id {
            return Err((UnattendedChannelError::TargetMismatch, None));
        }
        Ok(())
    }

    fn respond_with_seed(
        hello: &UnattendedHello,
        identity: &SigningKey,
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<(Self, UnattendedHelloReply), UnattendedChannelError> {
        let secret = ephemeral_from(seed);
        let service_ephemeral = PublicKey::from(&secret).to_bytes();
        let shared = agree(secret, &hello.operator_ephemeral)?;
        let transcript = transcript_hash(hello, &service_ephemeral, &identity.verifying_key());
        let signature = identity.sign(&transcript).to_bytes().to_vec();
        let secrets = ChannelSecrets::derive(&shared, &transcript);
        let channel = SecureChannel::new(
            &secrets.key_host_to_operator,
            Direction::HostToOperator,
            &secrets.key_operator_to_host,
            Direction::OperatorToHost,
        );
        Ok((
            Self {
                secrets,
                channel,
                operator_display_name: hello.operator_display_name.clone(),
            },
            UnattendedHelloReply::Accepted {
                service_ephemeral,
                signature,
            },
        ))
    }

    pub fn sas(&self) -> SasCode {
        self.secrets.sas
    }

    pub fn fingerprint(&self) -> [u8; 8] {
        self.secrets.fingerprint
    }

    /// Nombre que declaró el operador (autenticado por el transcript; sin sanear).
    pub fn operator_display_name(&self) -> &str {
        &self.operator_display_name
    }

    /// Descifra la contraseña y se la entrega a `authenticate` (normalmente un cierre sobre
    /// `UnattendedAuthenticator::authenticate` y `UnattendedVerdict::from_result`). La contraseña
    /// solo vive en búferes que se limpian al salir. Un registro inválido cierra el canal sin
    /// respuesta ni llamada al autenticador.
    pub fn handle_password_record<F>(
        mut self,
        record: &[u8],
        authenticate: F,
    ) -> Result<ServiceAuthOutcome, UnattendedChannelError>
    where
        F: FnOnce(&str) -> UnattendedVerdict,
    {
        let plaintext = Zeroizing::new(self.channel.open(record)?);
        let verdict = {
            let (request, rest) =
                postcard::take_from_bytes::<UnattendedAuthRequest<'_>>(&plaintext)
                    .map_err(|_| UnattendedChannelError::Malformed)?;
            if !rest.is_empty() {
                return Err(UnattendedChannelError::Malformed);
            }
            authenticate(request.password)
        };
        drop(plaintext);
        let reply = crate::wire::encode_message(&verdict.to_reply())
            .map_err(|_| UnattendedChannelError::Malformed)?;
        let reply_record = self.channel.seal(&reply)?;
        Ok(match verdict {
            UnattendedVerdict::Granted { generation } => ServiceAuthOutcome::Granted {
                session: ServiceUnattendedSession {
                    sas: self.secrets.sas,
                    fingerprint: self.secrets.fingerprint,
                    generation,
                    video: VideoSealer::new(&self.secrets.key_video_host_to_operator),
                    channel: self.channel,
                },
                reply_record,
            },
            UnattendedVerdict::Rejected { retry_after } => ServiceAuthOutcome::Rejected {
                retry_after,
                reply_record,
            },
        })
    }
}

/// Ejecuta en memoria el canal desatendido completo, pasando cada mensaje por postcard como en la
/// red. Exige la firma válida y el veredicto del autenticador. Solo existe en las pruebas o con la
/// feature `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub fn run_in_memory_unattended<F>(
    service_identity: &SigningKey,
    pinned_service_key: &VerifyingKey,
    target_id: u32,
    operator_display_name: &str,
    password: Zeroizing<String>,
    authenticate: F,
) -> Result<(ServiceUnattendedSession, OperatorUnattendedSession), UnattendedChannelError>
where
    F: FnOnce(&str) -> UnattendedVerdict,
{
    fn wire<T: Serialize + serde::de::DeserializeOwned>(msg: &T) -> T {
        let bytes = crate::wire::encode_message(msg).expect("serializacion en memoria");
        crate::wire::decode_message(&bytes).expect("decodificacion en memoria")
    }
    let (operator, hello) =
        OperatorUnattendedHandshake::start(target_id, operator_display_name, pinned_service_key)?;
    let (service, reply) =
        ServiceAwaitingPassword::respond(&wire(&hello), target_id, service_identity)
            .map_err(|(e, _)| e)?;
    let pending = operator.handle_reply(&wire(&reply))?;
    let (awaiting, record) = pending.send_password(password)?;
    match service.handle_password_record(&record, authenticate)? {
        ServiceAuthOutcome::Granted {
            session,
            reply_record,
        } => Ok((session, awaiting.finish(&reply_record)?)),
        ServiceAuthOutcome::Rejected { reply_record, .. } => Err(awaiting
            .finish(&reply_record)
            .err()
            .unwrap_or(UnattendedChannelError::Rejected { retry_after: None })),
    }
}

impl fmt::Debug for OperatorUnattendedHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorUnattendedHandshake")
            .field("target_id", &self.hello.target_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for OperatorUnattendedPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorUnattendedPending([REDACTED])")
    }
}

impl fmt::Debug for OperatorAwaitingAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorAwaitingAuth([REDACTED])")
    }
}

impl fmt::Debug for ServiceAwaitingPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceAwaitingPassword([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::unattended::test_kdf::CountingFakeKdf;
    use crate::unattended::{UnattendedAuthenticator, UnattendedCredentialState};
    use crate::wire::{VideoCodec, VideoPacketHeader, decode_message, encode_message};

    const TARGET: u32 = 123_456_789;
    const PW: &str = "Correct-Horse-Battery-9";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn identity() -> SigningKey {
        SigningKey::from_bytes(&[0x07; 32])
    }

    fn seed(b: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([b; 32])
    }

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    fn authenticator() -> (UnattendedAuthenticator, CountingFakeKdf) {
        let kdf = CountingFakeKdf::default();
        let mut auth = UnattendedAuthenticator::new(UnattendedCredentialState::not_configured());
        auth.credentials_mut().configure(PW, &kdf).unwrap();
        (auth, kdf)
    }

    /// Handshake determinista (efímeros fijos) hasta que el operador verificó al servicio.
    fn deterministic(
        hello_tamper: impl FnOnce(&mut UnattendedHello),
    ) -> (
        Result<OperatorUnattendedPending, UnattendedChannelError>,
        Option<ServiceAwaitingPassword>,
    ) {
        let id = identity();
        let (op, mut hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &id.verifying_key(),
            &seed(0x11),
        );
        hello_tamper(&mut hello);
        match ServiceAwaitingPassword::respond_with_seed(&hello, &id, &seed(0x22)) {
            Ok((svc, reply)) => (op.handle_reply(&reply), Some(svc)),
            Err(e) => (Err(e), None),
        }
    }

    #[test]
    fn full_roundtrip_grants_and_yields_working_channels() {
        let id = identity();
        let (mut auth, kdf) = authenticator();
        let mut seen = None;
        let (mut svc, mut op) = run_in_memory_unattended(
            &id,
            &id.verifying_key(),
            TARGET,
            "Soporte Nivel 2",
            pw(PW),
            |candidate| {
                seen = Some(candidate == PW);
                UnattendedVerdict::from_result(&auth.authenticate(
                    "op",
                    candidate,
                    &kdf,
                    Instant::now(),
                ))
            },
        )
        .expect("autenticacion valida");
        assert_eq!(seen, Some(true), "la contrasena llega sin normalizar");
        assert_eq!(svc.generation, 1);
        assert_eq!(svc.sas, op.sas);
        assert!(
            svc.sas
                .as_bytes()
                .iter()
                .all(|b| PASSWORD_ALPHABET.contains(b))
        );
        assert_eq!(svc.fingerprint, op.fingerprint);

        let rec = op.channel.seal(b"clic").unwrap();
        assert_eq!(svc.channel.open(&rec).unwrap(), b"clic");
        let rec = svc.channel.seal(b"pong").unwrap();
        assert_eq!(op.channel.open(&rec).unwrap(), b"pong");

        let header = VideoPacketHeader {
            frame_seq: 0,
            capture_ts_us: 1,
            monitor_index: 0,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: 4,
        };
        let mut stream = svc.video.open_stream().unwrap();
        let vrec = stream.seal(&header, b"bgra").unwrap();
        let mut opened = op.video.accept_stream(stream.preamble()).unwrap();
        assert_eq!(opened.open(&vrec).unwrap(), (header, b"bgra".to_vec()));
    }

    #[test]
    fn invalid_signature_aborts_before_password() {
        let id = identity();
        let (op, hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &id.verifying_key(),
            &seed(0x11),
        );
        let (_, reply) =
            ServiceAwaitingPassword::respond_with_seed(&hello, &id, &seed(0x22)).unwrap();
        let UnattendedHelloReply::Accepted {
            service_ephemeral,
            mut signature,
        } = reply
        else {
            panic!("se esperaba Accepted");
        };
        signature[10] ^= 0x01;
        // `handle_reply` consume el estado: sin `OperatorUnattendedPending` no hay forma de enviar
        // la contraseña.
        assert_eq!(
            op.handle_reply(&UnattendedHelloReply::Accepted {
                service_ephemeral,
                signature: signature.clone(),
            })
            .unwrap_err(),
            UnattendedChannelError::InvalidSignature
        );
        let (op, _) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &id.verifying_key(),
            &seed(0x11),
        );
        signature.truncate(63);
        assert_eq!(
            op.handle_reply(&UnattendedHelloReply::Accepted {
                service_ephemeral,
                signature,
            })
            .unwrap_err(),
            UnattendedChannelError::InvalidSignature
        );
    }

    #[test]
    fn different_pinned_key_aborts_before_password() {
        let real = identity();
        let impostor = SigningKey::from_bytes(&[0x08; 32]);
        // El operador fijó la clave real; responde un servicio (o relay) con otra clave.
        let (op, hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &real.verifying_key(),
            &seed(0x11),
        );
        let (_, reply) =
            ServiceAwaitingPassword::respond_with_seed(&hello, &impostor, &seed(0x22)).unwrap();
        assert_eq!(
            op.handle_reply(&reply).unwrap_err(),
            UnattendedChannelError::InvalidSignature
        );
    }

    #[test]
    fn altered_transcript_is_rejected() {
        // El relay cambia el nombre, el ID o el efímero del operador: la firma ya no cubre el hello
        // del operador.
        let tampers: [fn(&mut UnattendedHello); 3] = [
            |h| h.operator_display_name = "Administrador".to_string(),
            |h| h.operator_ephemeral = PublicKey::from(&ephemeral_from(&seed(0x33))).to_bytes(),
            |h| h.target_id += 1,
        ];
        for tamper in tampers {
            let (result, _) = deterministic(tamper);
            assert_eq!(
                result.unwrap_err(),
                UnattendedChannelError::InvalidSignature
            );
        }
        // Efímero del servicio alterado en tránsito.
        let id = identity();
        let (op, hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &id.verifying_key(),
            &seed(0x11),
        );
        let (_, reply) =
            ServiceAwaitingPassword::respond_with_seed(&hello, &id, &seed(0x22)).unwrap();
        let UnattendedHelloReply::Accepted { signature, .. } = reply else {
            panic!("se esperaba Accepted");
        };
        let forged = UnattendedHelloReply::Accepted {
            service_ephemeral: PublicKey::from(&ephemeral_from(&seed(0x44))).to_bytes(),
            signature,
        };
        assert_eq!(
            op.handle_reply(&forged).unwrap_err(),
            UnattendedChannelError::InvalidSignature
        );
    }

    #[test]
    fn wrong_target_and_low_order_ephemeral_are_rejected_without_reply() {
        let id = identity();
        let (_, mut hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte",
            &id.verifying_key(),
            &seed(0x11),
        );
        let (err, reply) = ServiceAwaitingPassword::respond(&hello, TARGET + 1, &id).unwrap_err();
        assert_eq!((err, reply), (UnattendedChannelError::TargetMismatch, None));
        hello.operator_ephemeral = [0u8; 32];
        let (err, reply) = ServiceAwaitingPassword::respond(&hello, TARGET, &id).unwrap_err();
        assert_eq!(
            (err, reply),
            (UnattendedChannelError::NonContributoryKeyExchange, None)
        );
    }

    #[test]
    fn unsupported_version_has_own_reply_and_does_not_count_attempt() {
        let id = identity();
        let (mut auth, kdf) = authenticator();
        for version in [0, UNATTENDED_PROTOCOL_VERSION + 1, u16::MAX] {
            for _ in 0..5 {
                let (op, mut hello) =
                    OperatorUnattendedHandshake::start(TARGET, "Soporte", &id.verifying_key())
                        .unwrap();
                hello.protocol_version = version;
                let (err, reply) =
                    ServiceAwaitingPassword::respond(&hello, TARGET, &id).unwrap_err();
                let reply = reply.expect("respuesta propia de version");
                assert_eq!(
                    err,
                    UnattendedChannelError::UnsupportedProtocolVersion {
                        supported: UNATTENDED_PROTOCOL_VERSION
                    }
                );
                let received: UnattendedHelloReply =
                    decode_message(&encode_message(&reply).unwrap()).unwrap();
                assert_eq!(
                    op.handle_reply(&received).unwrap_err(),
                    UnattendedChannelError::UnsupportedProtocolVersion {
                        supported: UNATTENDED_PROTOCOL_VERSION
                    }
                );
            }
        }
        // Ningún rechazo de versión llegó al autenticador: no hay bloqueo ni KDF ejecutado.
        assert_eq!(kdf.calls.get(), 1, "solo la configuracion derivo");
        assert!(auth.authenticate("op", PW, &kdf, Instant::now()).is_ok());
    }

    /// Ejecuta la autenticación con efímeros fijos y devuelve el registro de respuesta del servicio.
    fn reply_record_for(verdict: impl FnOnce(&str) -> UnattendedVerdict) -> Vec<u8> {
        let (pending, svc) = deterministic(|_| {});
        let (_, record) = pending
            .unwrap()
            .send_password(pw("cualquier-clave-larga"))
            .unwrap();
        match svc
            .unwrap()
            .handle_password_record(&record, verdict)
            .unwrap()
        {
            ServiceAuthOutcome::Granted { reply_record, .. }
            | ServiceAuthOutcome::Rejected { reply_record, .. } => reply_record,
        }
    }

    #[test]
    fn generic_reply_is_byte_identical_for_revoked_invalid_and_throttled() {
        let (mut auth, kdf) = authenticator();
        let t0 = Instant::now();
        let invalid = reply_record_for(|p| {
            UnattendedVerdict::from_result(&auth.authenticate("a", p, &kdf, t0))
        });
        // Dos fallos más: el origen queda bloqueado.
        for _ in 0..2 {
            assert!(auth.authenticate("a", "contrasena-mala", &kdf, t0).is_err());
        }
        let mut throttled_verdict = None;
        let throttled = reply_record_for(|p| {
            let v = UnattendedVerdict::from_result(&auth.authenticate("a", p, &kdf, t0));
            throttled_verdict = Some(v);
            v
        });
        auth.credentials_mut().revoke().unwrap();
        let revoked = reply_record_for(|p| {
            UnattendedVerdict::from_result(&auth.authenticate("b", p, &kdf, t0))
        });
        let generic = reply_record_for(|_| UnattendedVerdict::Rejected { retry_after: None });

        assert_eq!(invalid, revoked);
        assert_eq!(invalid, generic);
        let Some(UnattendedVerdict::Rejected {
            retry_after: Some(wait),
        }) = throttled_verdict
        else {
            panic!("se esperaba bloqueo con espera");
        };
        // El bloqueo solo difiere por el tiempo de espera.
        assert_eq!(
            throttled,
            reply_record_for(|_| UnattendedVerdict::Rejected {
                retry_after: Some(wait)
            })
        );
        assert_ne!(throttled, invalid);

        // El operador recibe el mismo error para revocado e inválido, y la espera si hay bloqueo.
        let finish = |rec: &[u8]| {
            let (pending, _) = deterministic(|_| {});
            let (awaiting, _) = pending
                .unwrap()
                .send_password(pw("cualquier-clave-larga"))
                .unwrap();
            awaiting.finish(rec).unwrap_err()
        };
        assert_eq!(
            finish(&revoked),
            UnattendedChannelError::Rejected { retry_after: None }
        );
        assert_eq!(
            finish(&throttled),
            UnattendedChannelError::Rejected {
                retry_after: Some(Duration::from_secs(wait.as_secs().max(1)))
            }
        );
    }

    #[test]
    fn password_never_appears_in_clear() {
        let id = identity();
        let secret = "Contrasena-Muy-Secreta-2026";
        let (op, hello) =
            OperatorUnattendedHandshake::start(TARGET, "Soporte", &id.verifying_key()).unwrap();
        let (svc, reply) = ServiceAwaitingPassword::respond(&hello, TARGET, &id).unwrap();
        let (awaiting, record) = op
            .handle_reply(&reply)
            .unwrap()
            .send_password(pw(secret))
            .unwrap();
        let outcome = svc
            .handle_password_record(&record, |p| {
                assert_eq!(p, secret);
                UnattendedVerdict::Granted { generation: 4 }
            })
            .unwrap();
        let ServiceAuthOutcome::Granted {
            session,
            reply_record,
        } = outcome
        else {
            panic!("se esperaba Granted");
        };
        assert_eq!(session.generation, 4);
        let wire: Vec<Vec<u8>> = vec![
            encode_message(&hello).unwrap(),
            encode_message(&reply).unwrap(),
            record.clone(),
            reply_record.clone(),
        ];
        let needles = [
            secret.as_bytes().to_vec(),
            secret.to_uppercase().into_bytes(),
            b"Secreta".to_vec(),
        ];
        for msg in &wire {
            for needle in &needles {
                assert!(
                    !msg.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "la contrasena aparece en claro"
                );
            }
        }
        assert!(awaiting.finish(&reply_record).is_ok());
    }

    #[test]
    fn tampered_password_record_closes_without_calling_authenticator() {
        let (pending, svc) = deterministic(|_| {});
        let (_, mut record) = pending.unwrap().send_password(pw(PW)).unwrap();
        let last = record.len() - 1;
        record[last] ^= 0x01;
        let mut called = false;
        let err = svc
            .unwrap()
            .handle_password_record(&record, |_| {
                called = true;
                UnattendedVerdict::Granted { generation: 1 }
            })
            .unwrap_err();
        assert_eq!(
            err,
            UnattendedChannelError::Channel(ChannelError::AuthenticationFailed)
        );
        assert!(!called);
    }

    #[test]
    fn verdict_from_result_maps_only_throttle_wait() {
        let (mut auth, kdf) = authenticator();
        let t0 = Instant::now();
        assert_eq!(
            UnattendedVerdict::from_result(&auth.authenticate("s", PW, &kdf, t0)),
            UnattendedVerdict::Granted { generation: 1 }
        );
        for err in [
            UnattendedError::InvalidPassword,
            UnattendedError::UnattendedDisabled,
            UnattendedError::NotConfigured,
            UnattendedError::InvalidRecord("x"),
        ] {
            assert_eq!(
                UnattendedVerdict::from_result(&Err(err)),
                UnattendedVerdict::Rejected { retry_after: None }
            );
        }
        assert_eq!(
            UnattendedVerdict::from_result(&Err(UnattendedError::Throttled {
                scope: crate::unattended::ThrottleScope::Global,
                retry_after: Duration::from_secs(900),
            })),
            UnattendedVerdict::Rejected {
                retry_after: Some(Duration::from_secs(900))
            }
        );
    }

    #[test]
    fn unattended_messages_postcard_literals() {
        let hello = UnattendedHello {
            protocol_version: 1,
            target_id: TARGET,
            operator_display_name: "Op".to_string(),
            operator_ephemeral: [0xAA; 32],
        };
        assert_eq!(
            hex(&encode_message(&hello).unwrap()),
            format!("01959aef3a024f70{}", "aa".repeat(32))
        );
        let accepted = UnattendedHelloReply::Accepted {
            service_ephemeral: [0xBB; 32],
            signature: vec![0xCC; 64],
        };
        assert_eq!(
            hex(&encode_message(&accepted).unwrap()),
            format!("00{}40{}", "bb".repeat(32), "cc".repeat(64))
        );
        let unsupported = UnattendedHelloReply::UnsupportedProtocolVersion { supported: 1 };
        assert_eq!(hex(&encode_message(&unsupported).unwrap()), "0101");
        let request = UnattendedAuthRequest { password: "abc" };
        assert_eq!(hex(&encode_message(&request).unwrap()), "03616263");
        assert_eq!(
            hex(&encode_message(&UnattendedAuthReply::Granted).unwrap()),
            "00"
        );
        assert_eq!(
            hex(&encode_message(&UnattendedAuthReply::Rejected {
                retry_after_secs: None
            })
            .unwrap()),
            "0100"
        );
        assert_eq!(
            hex(&encode_message(&UnattendedAuthReply::Rejected {
                retry_after_secs: Some(300)
            })
            .unwrap()),
            "0101ac02"
        );
    }

    /// Vectores de regresión del canal desatendido v1 con claves deterministas (identidad Ed25519
    /// `[0x07; 32]`, efímeros X25519 `[0x11; 32]` del operador y `[0x22; 32]` del servicio).
    /// Recalculados de forma independiente en Python (`cryptography`): X25519, Ed25519, HKDF-SHA256
    /// y ChaCha20-Poly1305.
    #[test]
    fn unattended_v1_regression_vectors() {
        let id = identity();
        let (op, hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte Nivel 2",
            &id.verifying_key(),
            &seed(0x11),
        );
        let (svc, reply) =
            ServiceAwaitingPassword::respond_with_seed(&hello, &id, &seed(0x22)).unwrap();
        let UnattendedHelloReply::Accepted {
            service_ephemeral,
            signature,
        } = &reply
        else {
            panic!("se esperaba Accepted");
        };
        let transcript = transcript_hash(&hello, service_ephemeral, &id.verifying_key());
        let shared = agree(ephemeral_from(&seed(0x11)), service_ephemeral).unwrap();
        let s = ChannelSecrets::derive(&shared, &transcript);

        assert_eq!(
            hex(id.verifying_key().as_bytes()),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
        assert_eq!(
            hex(&hello.operator_ephemeral),
            "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex(service_ephemeral),
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
        );
        assert_eq!(
            hex(&encode_message(&hello).unwrap()),
            "01959aef3a0f536f706f727465204e6976656c20327b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex(&transcript),
            "078b09a621e67cefcc694a6daebe80d4b7b4369eeb1f2317f00b1d52dc60bd17"
        );
        assert_eq!(
            hex(signature),
            "c8acb039b4e1c90365c115dd931ce9669d000990b4b7ceb8becfe67a106fca5f603b33194b2c9a4384d735c562193dde4393006afdf3bada909280163989cc07"
        );
        assert_eq!(
            hex(shared.as_ref()),
            "9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056"
        );
        assert_eq!(
            hex(s.key_operator_to_host.as_ref()),
            "c9a35fae301bbee192e45d37f5534019d9768af638588fc7c63a53db2fc14b7b"
        );
        assert_eq!(
            hex(s.key_host_to_operator.as_ref()),
            "dd267387d853892366bf934893dc2fde6d8a984fd4cf1cc2675f358076082eb2"
        );
        assert_eq!(
            hex(s.key_video_host_to_operator.as_ref()),
            "df1fd7456d6c071c7de2f8a718434df5a4557d1e5114a0f4bedd9955f4378846"
        );
        assert_eq!(s.sas.as_str(), "UZAU44");
        assert_eq!(hex(&s.fingerprint), "45f181daa9f565ee");

        let pending = op.handle_reply(&reply).unwrap();
        assert_eq!(pending.sas(), s.sas);
        let (awaiting, op0) = pending.send_password(pw(PW)).unwrap();
        assert_eq!(
            hex(&op0),
            "000000000000000056d9f3ea3cc5b45eb1fc85b11ff0deed56d66b7d58b0b3df8c0cd1e9a457828b448c482a4d14a969"
        );
        let outcome = svc
            .handle_password_record(&op0, |p| {
                assert_eq!(p, PW);
                UnattendedVerdict::Granted { generation: 1 }
            })
            .unwrap();
        let ServiceAuthOutcome::Granted {
            mut session,
            reply_record,
        } = outcome
        else {
            panic!("se esperaba Granted");
        };
        assert_eq!(
            hex(&reply_record),
            "0000000000000000ab12ead1e3d530cbb92f52d71fe82ea621"
        );
        let mut op_session = awaiting.finish(&reply_record).unwrap();
        let op1 = op_session.channel.seal(b"op->host #1").unwrap();
        let host1 = session.channel.seal(b"host->op #1").unwrap();
        assert_eq!(
            hex(&op1),
            "00000000000000016e79bdead5568f873890dab1bc42cd9e66cf062a717c60fb9f0e89"
        );
        assert_eq!(
            hex(&host1),
            "0000000000000001d7993e75e49788a6375ce18ea5d77a781b5bfe591b8fccb94a4fff"
        );
        assert_eq!(session.channel.open(&op1).unwrap(), b"op->host #1");
        assert_eq!(op_session.channel.open(&host1).unwrap(), b"host->op #1");

        // Misma sesión determinista, pero el servicio rechaza con 30 s de espera.
        let (op, hello) = OperatorUnattendedHandshake::start_with_seed(
            TARGET,
            "Soporte Nivel 2",
            &id.verifying_key(),
            &seed(0x11),
        );
        let (svc, reply) =
            ServiceAwaitingPassword::respond_with_seed(&hello, &id, &seed(0x22)).unwrap();
        let (_, op0_again) = op
            .handle_reply(&reply)
            .unwrap()
            .send_password(pw(PW))
            .unwrap();
        assert_eq!(op0_again, op0);
        let ServiceAuthOutcome::Rejected {
            reply_record: rejected,
            ..
        } = svc
            .handle_password_record(&op0_again, |_| UnattendedVerdict::Rejected {
                retry_after: Some(Duration::from_secs(30)),
            })
            .unwrap()
        else {
            panic!("se esperaba Rejected");
        };
        assert_eq!(
            hex(&rejected),
            "0000000000000000aa7e02291a4f10856a8b745efd5386a519e225"
        );
    }
}
