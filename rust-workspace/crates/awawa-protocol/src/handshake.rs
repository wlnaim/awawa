//! Handshake E2E SPAKE2 (`Ed25519Group`) entre operador y host a través del relay ciego.
//!
//! Secuencia:
//! 1. Operador → Host: `PakeHello` (versión de protocolo, ID de sesión, nombre, huella,
//!    capacidades, mensaje SPAKE2 `A`).
//! 2. Host → Operador: `PakeHelloReply::Challenge` (`PakeChallenge`, mensaje SPAKE2 `B`) o
//!    `PakeHelloReply::UnsupportedProtocolVersion` si la versión no coincide (no cuenta intento).
//! 3. Operador → Host: `PakeConfirm` (MAC de confirmación del operador).
//! 4. Host → Operador: `HostAuthReply::Accepted` (MAC de confirmación del host) o `Rejected`.
//!
//! Entrada SPAKE2: contraseña normalizada; identidades `operator/<ID>` y `host/<ID>`.
//! Transcript: `SHA-256(etiqueta ‖ lp(postcard(PakeHello)) ‖ lp(mensaje B))`, de modo que versión
//! de protocolo, nombre, huella y capacidades del hello quedan autenticados: si el relay los altera,
//! la confirmación falla.
//! Derivación: `HKDF-SHA256(salt = transcript, ikm = clave SPAKE2)` → claves de confirmación,
//! claves direccionales `Host→Op` / `Op→Host` para `ChaCha20-Poly1305`, clave de video `Host→Op`
//! (`video_channel`) y SAS de 6 caracteres.
//! El relay solo ve mensajes SPAKE2 y MAC: no obtiene la contraseña ni las claves.

use std::fmt;
#[cfg(any(test, feature = "test-support"))]
use std::time::Instant;

use hkdf::Hkdf;
use hkdf::hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::consent_fsm::OperatorConnectionRequest;
#[cfg(any(test, feature = "test-support"))]
use crate::consent_fsm::{ConsentError, HostAuthenticated, WaitingForRequest};
use crate::credentials::{
    CredentialsError, PASSWORD_ALPHABET, SessionId, normalize_password_input,
};
use crate::secure_channel::{Direction, SecureChannel};
use crate::video_channel::{VideoOpener, VideoSealer};
use crate::wire::CapabilityMask;

const TRANSCRIPT_LABEL: &[u8] = b"support-protocol/v1 spake2 transcript";
const INFO_CONFIRM_OPERATOR: &[u8] = b"support-protocol/v1 confirm op->host";
const INFO_CONFIRM_HOST: &[u8] = b"support-protocol/v1 confirm host->op";
const INFO_KEY_OPERATOR_TO_HOST: &[u8] = b"support-protocol/v1 key op->host";
const INFO_KEY_HOST_TO_OPERATOR: &[u8] = b"support-protocol/v1 key host->op";
const INFO_KEY_VIDEO_HOST_TO_OPERATOR: &[u8] = b"support-protocol/v1 key video host->op";
const INFO_SAS: &[u8] = b"support-protocol/v1 sas";

type HmacSha256 = Hmac<Sha256>;

/// Versión del protocolo de handshake que envía el operador en `PakeHello`. El host rechaza
/// cualquier otra antes de SPAKE2; al ir dentro del hello serializado queda autenticada por el
/// transcript.
pub const PROTOCOL_VERSION: u16 = 1;

/// Primer mensaje del operador. Viaja en claro por el relay, pero queda ligado al transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakeHello {
    pub protocol_version: u16,
    pub target_session_id: u32,
    pub operator_display_name: String,
    pub operator_fingerprint: [u8; 8],
    pub requested_capabilities: CapabilityMask,
    pub spake_msg: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakeChallenge {
    pub spake_msg: Vec<u8>,
}

/// Respuesta del host al `PakeHello`: el challenge SPAKE2 o el rechazo por versión de protocolo.
/// El rechazo por versión tiene su propia señal para que el operador no lo confunda con una
/// contraseña incorrecta; no cuenta como intento ni rota la contraseña.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PakeHelloReply {
    Challenge(PakeChallenge),
    /// El host solo habla `supported` (su `PROTOCOL_VERSION`).
    UnsupportedProtocolVersion {
        supported: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PakeConfirm {
    pub operator_confirmation: [u8; 32],
}

/// Veredicto del host tras verificar la confirmación del operador.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostAuthReply {
    /// Contraseña válida: el host prueba que también conoce la clave. La sesión sigue bloqueada
    /// hasta la aprobación local.
    Accepted { host_confirmation: [u8; 32] },
    /// Confirmación inválida. No se muestra ningún diálogo al usuario local.
    Rejected { remaining_attempts: u8 },
}

/// Código corto de verificación (6 caracteres del alfabeto sin ambigüedades), igual en ambos lados.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SasCode(pub(crate) [u8; 6]);

impl SasCode {
    pub fn as_bytes(&self) -> [u8; 6] {
        self.0
    }

    pub fn as_str(&self) -> &str {
        // Solo contiene bytes ASCII de `PASSWORD_ALPHABET`.
        std::str::from_utf8(&self.0).unwrap_or("??????")
    }
}

impl fmt::Display for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SasCode({})", self.as_str())
    }
}

/// Errores del lado del operador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    Credentials(CredentialsError),
    MalformedChallenge,
    /// El host no habla la versión de protocolo del operador (no es un fallo de contraseña).
    UnsupportedProtocolVersion {
        supported: u16,
    },
    /// El host rechazó la confirmación (contraseña incorrecta o hello alterado).
    Rejected {
        remaining_attempts: u8,
    },
    /// El host no demostró conocer la clave: se aborta sin abrir canal.
    HostConfirmationFailed,
}

/// Secretos derivados del intercambio. Se limpian de memoria al destruirse.
struct SessionSecrets {
    transcript: [u8; 32],
    confirm_operator: Zeroizing<[u8; 32]>,
    confirm_host: Zeroizing<[u8; 32]>,
    key_operator_to_host: Zeroizing<[u8; 32]>,
    key_host_to_operator: Zeroizing<[u8; 32]>,
    key_video_host_to_operator: Zeroizing<[u8; 32]>,
    sas: SasCode,
}

impl SessionSecrets {
    fn derive(spake_key: &[u8], hello: &PakeHello, challenge_msg: &[u8]) -> Self {
        let transcript = transcript_hash(hello, challenge_msg);
        let hk = Hkdf::<Sha256>::new(Some(&transcript), spake_key);
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
        Self {
            transcript,
            confirm_operator: expand32(INFO_CONFIRM_OPERATOR),
            confirm_host: expand32(INFO_CONFIRM_HOST),
            key_operator_to_host: expand32(INFO_KEY_OPERATOR_TO_HOST),
            key_host_to_operator: expand32(INFO_KEY_HOST_TO_OPERATOR),
            key_video_host_to_operator: expand32(INFO_KEY_VIDEO_HOST_TO_OPERATOR),
            sas: SasCode(sas),
        }
    }

    fn mac(key: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
            .expect("HMAC acepta claves de cualquier longitud");
        mac.update(transcript);
        mac.finalize().into_bytes().into()
    }

    fn verify(key: &[u8; 32], transcript: &[u8; 32], tag: &[u8; 32]) -> bool {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
            .expect("HMAC acepta claves de cualquier longitud");
        mac.update(transcript);
        mac.verify_slice(tag).is_ok()
    }

    fn operator_confirmation(&self) -> [u8; 32] {
        Self::mac(&self.confirm_operator, &self.transcript)
    }

    fn host_confirmation(&self) -> [u8; 32] {
        Self::mac(&self.confirm_host, &self.transcript)
    }
}

fn transcript_hash(hello: &PakeHello, challenge_msg: &[u8]) -> [u8; 32] {
    let hello_bytes =
        postcard::to_allocvec(hello).expect("la serializacion postcard en memoria no falla");
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_LABEL);
    h.update((hello_bytes.len() as u64).to_be_bytes());
    h.update(&hello_bytes);
    h.update((challenge_msg.len() as u64).to_be_bytes());
    h.update(challenge_msg);
    h.finalize().into()
}

/// Identidades SPAKE2: el operador es el rol A y el host el rol B.
fn identities(session_id: u32) -> (Identity, Identity) {
    (
        Identity::new(format!("operator/{session_id:09}").as_bytes()),
        Identity::new(format!("host/{session_id:09}").as_bytes()),
    )
}

/// Operador: hello enviado, esperando el `PakeChallenge` del host.
pub struct OperatorHandshake {
    spake: Spake2<Ed25519Group>,
    hello: PakeHello,
}

/// Operador: confirmación enviada, esperando el veredicto del host.
pub struct OperatorAwaitingVerdict {
    secrets: SessionSecrets,
}

/// Operador autenticado: SAS para comparar con el host, canal cifrado de control y abridor de los
/// streams de video.
#[derive(Debug)]
pub struct OperatorSession {
    pub sas: SasCode,
    pub channel: SecureChannel,
    pub video: VideoOpener,
}

impl OperatorHandshake {
    /// Inicia el handshake con los datos de la petición y la contraseña tecleada por el técnico.
    /// La contraseña solo entra a SPAKE2; nunca se envía.
    pub fn start(
        request: &OperatorConnectionRequest,
        password: &str,
    ) -> Result<(Self, PakeHello), HandshakeError> {
        let normalized = normalize_password_input(password);
        if normalized.is_empty() {
            return Err(HandshakeError::Credentials(CredentialsError::EmptyPassword));
        }
        let session_id = request.target_session_id.raw_u32();
        let (id_operator, id_host) = identities(session_id);
        let (spake, spake_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(normalized.as_slice()),
            &id_operator,
            &id_host,
        );
        let hello = PakeHello {
            protocol_version: PROTOCOL_VERSION,
            target_session_id: session_id,
            operator_display_name: request.operator_display_name.clone(),
            operator_fingerprint: request.operator_ed25519_fingerprint,
            requested_capabilities: CapabilityMask::from_capabilities(
                request.requested_capabilities,
            ),
            spake_msg,
        };
        Ok((
            Self {
                spake,
                hello: hello.clone(),
            },
            hello,
        ))
    }

    pub fn handle_challenge(
        self,
        challenge: &PakeChallenge,
    ) -> Result<(OperatorAwaitingVerdict, PakeConfirm), HandshakeError> {
        let key = Zeroizing::new(
            self.spake
                .finish(&challenge.spake_msg)
                .map_err(|_| HandshakeError::MalformedChallenge)?,
        );
        let secrets = SessionSecrets::derive(&key, &self.hello, &challenge.spake_msg);
        let confirm = PakeConfirm {
            operator_confirmation: secrets.operator_confirmation(),
        };
        Ok((OperatorAwaitingVerdict { secrets }, confirm))
    }

    /// Procesa la respuesta del host al hello: continúa con el challenge o devuelve
    /// `HandshakeError::UnsupportedProtocolVersion` si el host no habla esta versión.
    pub fn handle_hello_reply(
        self,
        reply: &PakeHelloReply,
    ) -> Result<(OperatorAwaitingVerdict, PakeConfirm), HandshakeError> {
        match reply {
            PakeHelloReply::Challenge(challenge) => self.handle_challenge(challenge),
            PakeHelloReply::UnsupportedProtocolVersion { supported } => {
                Err(HandshakeError::UnsupportedProtocolVersion {
                    supported: *supported,
                })
            }
        }
    }
}

impl OperatorAwaitingVerdict {
    pub fn finish(self, reply: &HostAuthReply) -> Result<OperatorSession, HandshakeError> {
        match reply {
            HostAuthReply::Rejected { remaining_attempts } => Err(HandshakeError::Rejected {
                remaining_attempts: *remaining_attempts,
            }),
            HostAuthReply::Accepted { host_confirmation } => {
                let s = &self.secrets;
                if !SessionSecrets::verify(&s.confirm_host, &s.transcript, host_confirmation) {
                    return Err(HandshakeError::HostConfirmationFailed);
                }
                Ok(OperatorSession {
                    sas: s.sas,
                    channel: SecureChannel::new(
                        &s.key_operator_to_host,
                        Direction::OperatorToHost,
                        &s.key_host_to_operator,
                        Direction::HostToOperator,
                    ),
                    video: VideoOpener::new(&s.key_video_host_to_operator),
                })
            }
        }
    }
}

/// Lado criptográfico del host; la compuerta de consentimiento (`consent_fsm`) lo envuelve.
pub(crate) struct HostKeyExchange {
    secrets: SessionSecrets,
}

impl HostKeyExchange {
    pub(crate) fn respond(
        session_id: SessionId,
        normalized_password: &[u8],
        hello: &PakeHello,
    ) -> Result<(Self, PakeChallenge), &'static str> {
        let (id_operator, id_host) = identities(session_id.raw_u32());
        let (spake, spake_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(normalized_password),
            &id_operator,
            &id_host,
        );
        let key = Zeroizing::new(
            spake
                .finish(&hello.spake_msg)
                .map_err(|_| "mensaje SPAKE2 del operador invalido")?,
        );
        let secrets = SessionSecrets::derive(&key, hello, &spake_msg);
        Ok((Self { secrets }, PakeChallenge { spake_msg }))
    }

    pub(crate) fn verify_operator(&self, confirm: &PakeConfirm) -> bool {
        SessionSecrets::verify(
            &self.secrets.confirm_operator,
            &self.secrets.transcript,
            &confirm.operator_confirmation,
        )
    }

    pub(crate) fn sas(&self) -> SasCode {
        self.secrets.sas
    }

    pub(crate) fn into_accepted(self) -> (HostAuthReply, SecureChannel, VideoSealer) {
        let s = &self.secrets;
        let reply = HostAuthReply::Accepted {
            host_confirmation: s.host_confirmation(),
        };
        let channel = SecureChannel::new(
            &s.key_host_to_operator,
            Direction::HostToOperator,
            &s.key_operator_to_host,
            Direction::OperatorToHost,
        );
        let video = VideoSealer::new(&s.key_video_host_to_operator);
        (reply, channel, video)
    }
}

/// Ejecuta en memoria el handshake completo entre un operador y el host, sin red (pruebas y demos).
/// Recorre los mismos pasos que por red y exige la contraseña correcta: no permite saltarse la
/// autenticación ni la aprobación local posterior. No es API de producción: solo existe en las
/// pruebas o con la feature `test-support`.
#[cfg(any(test, feature = "test-support"))]
pub fn run_in_memory_handshake(
    waiting: WaitingForRequest,
    request: &OperatorConnectionRequest,
    password: &str,
    now: Instant,
) -> Result<(HostAuthenticated, OperatorSession), (WaitingForRequest, ConsentError)> {
    let (operator, hello) = match OperatorHandshake::start(request, password) {
        Ok(pair) => pair,
        Err(HandshakeError::Credentials(e)) => {
            return Err((waiting, ConsentError::CredentialsError(e)));
        }
        Err(_) => unreachable!("OperatorHandshake::start solo falla por credenciales"),
    };
    let (authenticating, challenge) = waiting.accept_operator_hello(&hello)?;
    let (verdict, confirm) = operator
        .handle_challenge(&challenge)
        .expect("el challenge del host en memoria es valido");
    let host = authenticating
        .verify_operator_confirmation(&confirm, now)
        .map_err(|(waiting, err, _)| (waiting, err))?;
    let operator = verdict
        .finish(&host.reply)
        .expect("el host autenticado en memoria confirma la misma clave");
    Ok((host, operator))
}

impl fmt::Debug for HostKeyExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostKeyExchange([REDACTED])")
    }
}

impl fmt::Debug for OperatorHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorHandshake")
            .field("target_session_id", &self.hello.target_session_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for OperatorAwaitingVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorAwaitingVerdict([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::consent_fsm::{MAX_FAILED_PASSWORD_ATTEMPTS, PendingLocalConsent};
    use crate::messages::ScopedCapabilities;
    use crate::secure_channel::ChannelError;
    use crate::wire::{VideoCodec, VideoPacketHeader};

    fn request_for(waiting: &WaitingForRequest) -> OperatorConnectionRequest {
        OperatorConnectionRequest {
            target_session_id: waiting.session_id(),
            operator_display_name: "Soporte Nivel 2".to_string(),
            operator_ed25519_fingerprint: [9; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        }
    }

    type HostOutcome = Result<
        (PendingLocalConsent, SecureChannel, HostAuthReply),
        (WaitingForRequest, ConsentError, HostAuthReply),
    >;

    /// Ejecuta el handshake completo en memoria y devuelve el resultado del host y el operador.
    fn run(waiting: WaitingForRequest, password: &str) -> (HostOutcome, OperatorAwaitingVerdict) {
        let req = request_for(&waiting);
        let (op, hello) = OperatorHandshake::start(&req, password).unwrap();
        let (auth, challenge) = waiting.accept_operator_hello(&hello).unwrap();
        let (op_wait, confirm) = op.handle_challenge(&challenge).unwrap();
        let outcome = auth
            .verify_operator_confirmation(&confirm, Instant::now())
            .map(|ok| (ok.pending, ok.channel, ok.reply));
        (outcome, op_wait)
    }

    #[test]
    fn correct_password_yields_same_sas_and_working_channel() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let (outcome, op_wait) = run(waiting, &pw.to_lowercase().replace('-', " "));
        let (pending, mut host_channel, reply) = outcome.expect("handshake valido");
        let mut op = op_wait.finish(&reply).expect("host confirmado");

        assert_eq!(pending.sas(), op.sas);
        assert_eq!(pending.sas().as_str().len(), 6);
        assert!(
            pending
                .sas()
                .as_bytes()
                .iter()
                .all(|b| PASSWORD_ALPHABET.contains(b))
        );
        assert_eq!(pending.operator_display_name(), "Soporte Nivel 2");

        let rec = op.channel.seal(b"mover cursor").unwrap();
        assert_eq!(host_channel.open(&rec).unwrap(), b"mover cursor");
        let rec = host_channel.seal(b"frame").unwrap();
        assert_eq!(op.channel.open(&rec).unwrap(), b"frame");
    }

    #[test]
    fn wrong_password_fails_without_pending_consent() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let (outcome, op_wait) = run(waiting, "ZZZZZ-ZZZZZ");
        let (_waiting, err, reply) = outcome.expect_err("no debe crear PendingLocalConsent");
        assert_eq!(
            err,
            ConsentError::InvalidPassword {
                failed_attempts: 1,
                password_rotated: false
            }
        );
        assert_eq!(
            reply,
            HostAuthReply::Rejected {
                remaining_attempts: 2
            }
        );
        assert_eq!(
            op_wait.finish(&reply).unwrap_err(),
            HandshakeError::Rejected {
                remaining_attempts: 2
            }
        );
    }

    #[test]
    fn three_failures_rotate_password() {
        let mut waiting = WaitingForRequest::start_client_reception().unwrap();
        let initial = waiting.display_password();
        for attempt in 1..=MAX_FAILED_PASSWORD_ATTEMPTS {
            let (outcome, _) = run(waiting, "ZZZZZ-ZZZZZ");
            let (next, err, _) = outcome.expect_err("debe fallar");
            waiting = next;
            assert_eq!(
                err,
                ConsentError::InvalidPassword {
                    failed_attempts: attempt,
                    password_rotated: attempt == MAX_FAILED_PASSWORD_ATTEMPTS,
                }
            );
        }
        assert_ne!(waiting.display_password(), initial);

        // La contraseña anterior ya no autentica; la nueva sí.
        let (outcome, _) = run(waiting, &initial);
        let (waiting, _, _) = outcome.expect_err("contrasena rotada");
        let new_pw = waiting.display_password();
        assert!(run(waiting, &new_pw).0.is_ok());
    }

    #[test]
    fn host_confirmation_mismatch_is_rejected_by_operator() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let (outcome, op_wait) = run(waiting, &pw);
        let (_, _, reply) = outcome.unwrap();
        let HostAuthReply::Accepted {
            mut host_confirmation,
        } = reply
        else {
            panic!("se esperaba Accepted");
        };
        host_confirmation[0] ^= 0x01;
        assert_eq!(
            op_wait
                .finish(&HostAuthReply::Accepted { host_confirmation })
                .unwrap_err(),
            HandshakeError::HostConfirmationFailed
        );
    }

    #[test]
    fn forged_operator_confirmation_is_rejected_by_host() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        let (op, hello) = OperatorHandshake::start(&req, &pw).unwrap();
        let (auth, challenge) = waiting.accept_operator_hello(&hello).unwrap();
        let (_, mut confirm) = op.handle_challenge(&challenge).unwrap();
        confirm.operator_confirmation[31] ^= 0x80;
        let (_, err, _) = auth
            .verify_operator_confirmation(&confirm, Instant::now())
            .unwrap_err();
        assert!(matches!(err, ConsentError::InvalidPassword { .. }));
    }

    #[test]
    fn relay_tampering_with_hello_breaks_confirmation() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = OperatorConnectionRequest {
            requested_capabilities: ScopedCapabilities {
                view_desktop: true,
                control_cursor: false,
                control_keyboard: false,
            },
            ..request_for(&waiting)
        };
        let (op, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
        // El relay intenta ampliar capacidades y cambiar el nombre mostrado en el modal.
        hello.requested_capabilities = CapabilityMask(0b0111);
        hello.operator_display_name = "Administrador".to_string();
        let (auth, challenge) = waiting.accept_operator_hello(&hello).unwrap();
        let (op_wait, confirm) = op.handle_challenge(&challenge).unwrap();
        let (_, err, reply) = auth
            .verify_operator_confirmation(&confirm, Instant::now())
            .unwrap_err();
        assert!(matches!(err, ConsentError::InvalidPassword { .. }));
        assert!(op_wait.finish(&reply).is_err());
    }

    #[test]
    fn out_of_mask_capabilities_and_wrong_session_are_rejected_before_spake() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        let (_, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
        hello.requested_capabilities = CapabilityMask(0b1111);
        let (waiting, err) = waiting.accept_operator_hello(&hello).unwrap_err();
        assert!(matches!(err, ConsentError::CapabilityDenied(_)));

        let (_, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
        hello.target_session_id = if hello.target_session_id == 999_999_999 {
            100_000_000
        } else {
            hello.target_session_id + 1
        };
        let (waiting, err) = waiting.accept_operator_hello(&hello).unwrap_err();
        assert_eq!(err, ConsentError::SessionIdMismatch);

        let (_, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
        hello.spake_msg.truncate(5);
        let (waiting, err) = waiting.accept_operator_hello(&hello).unwrap_err();
        assert!(matches!(err, ConsentError::MalformedHandshake(_)));

        // Ninguno de estos rechazos cuenta como intento de contraseña ni rota la contraseña.
        assert_eq!(waiting.display_password(), pw);
        assert!(run(waiting, &pw).0.is_ok());
    }

    #[test]
    fn empty_password_is_rejected_by_operator() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let req = request_for(&waiting);
        assert_eq!(
            OperatorHandshake::start(&req, " - ").unwrap_err(),
            HandshakeError::Credentials(CredentialsError::EmptyPassword)
        );
    }

    #[test]
    fn click_before_grace_period_still_fails_after_handshake() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        let t0 = Instant::now();
        let (host, _) = run_in_memory_handshake(waiting, &req, &pw, t0).unwrap();
        let (_, err) = host
            .pending
            .approve_locally(t0 + Duration::from_millis(300), None)
            .unwrap_err();
        assert_eq!(err, ConsentError::AntiClickjackGracePeriodActive);
    }

    #[test]
    fn unsupported_protocol_version_is_rejected_before_spake() {
        let mut waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        for version in [0, PROTOCOL_VERSION + 1, u16::MAX] {
            for _ in 0..MAX_FAILED_PASSWORD_ATTEMPTS {
                let (_, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
                hello.protocol_version = version;
                let (next, err) = waiting.accept_operator_hello(&hello).unwrap_err();
                waiting = next;
                // Error propio, distinto de contraseña incorrecta: no se llega a SPAKE2 ni al modal.
                assert_eq!(err, ConsentError::UnsupportedProtocolVersion(version));
            }
        }
        // Ningún rechazo de versión contó como intento ni rotó la contraseña.
        assert_eq!(waiting.display_password(), pw);
        let (outcome, op_wait) = run(waiting, &pw);
        let (pending, _, reply) = outcome.expect("la contrasena correcta sigue funcionando");
        assert_eq!(pending.sas(), op_wait.finish(&reply).unwrap().sas);
    }

    #[test]
    fn protocol_version_is_bound_to_transcript() {
        let hello = kat_hello();
        let mut other = hello.clone();
        other.protocol_version = PROTOCOL_VERSION + 1;
        assert_ne!(
            transcript_hash(&hello, &kat_challenge_msg()),
            transcript_hash(&other, &kat_challenge_msg())
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn kat_hello() -> PakeHello {
        PakeHello {
            protocol_version: PROTOCOL_VERSION,
            target_session_id: 123_456_789,
            operator_display_name: "Soporte Nivel 2".to_string(),
            operator_fingerprint: [1, 2, 3, 4, 5, 6, 7, 8],
            requested_capabilities: CapabilityMask(0b0111),
            spake_msg: (0x00..0x21).collect(),
        }
    }

    fn kat_challenge_msg() -> Vec<u8> {
        (0x80..0xA1).collect()
    }

    const KAT_SPAKE_KEY: [u8; 32] = [0x42; 32];

    /// Vectores de regresión del formato v1 (calculados una vez con este código; no son vectores
    /// externos). Fijan la serialización del hello, el transcript, la derivación HKDF, las MAC de
    /// confirmación, el SAS y los registros del canal a partir de la salida de SPAKE2.
    #[test]
    fn v1_format_regression_vectors() {
        let hello = kat_hello();
        let challenge = kat_challenge_msg();

        assert_eq!(
            hex(&postcard::to_allocvec(&hello).unwrap()),
            "01959aef3a0f536f706f727465204e6976656c203201020304050607080721000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        assert_eq!(
            hex(&transcript_hash(&hello, &challenge)),
            "04e30c37d618933cf2cec311c3c554bba71df6bc97f661eb6546eaa310dea5bd"
        );

        let s = SessionSecrets::derive(&KAT_SPAKE_KEY, &hello, &challenge);
        assert_eq!(
            hex(s.confirm_operator.as_ref()),
            "103f38a9c4313d04c2110fc01611a2f024233088f074e7af51cdccf0c1de05e4"
        );
        assert_eq!(
            hex(s.confirm_host.as_ref()),
            "9ca36a9ee25479706695e7620c2fc1f1c912566b4eb596cedd0fe6157186a2fe"
        );
        assert_eq!(
            hex(s.key_operator_to_host.as_ref()),
            "de6b636dc58dec1ef0b89d2120763edc93804f060c4935ffcda4e66978ef7144"
        );
        assert_eq!(
            hex(s.key_host_to_operator.as_ref()),
            "5037961c8afc0b9b3723e4f0c87ebee1fab0dc8041f86d8c1566880e00b89dc3"
        );
        assert_eq!(
            hex(&s.operator_confirmation()),
            "91e6f13adddaebae85eab98a0e51d26640018232e5e813d8d982ff627eeaef86"
        );
        assert_eq!(
            hex(&s.host_confirmation()),
            "4ad11cf96bf62f8f2a4bdf850119221549464999cd8b780a70312a7d105ba57f"
        );
        assert_eq!(s.sas.as_str(), "E6LTAT");

        let host = HostKeyExchange { secrets: s };
        assert!(host.verify_operator(&PakeConfirm {
            operator_confirmation:
                SessionSecrets::derive(&KAT_SPAKE_KEY, &hello, &challenge).operator_confirmation(),
        }));
        let (reply, mut host_channel, _video) = host.into_accepted();
        let operator = OperatorAwaitingVerdict {
            secrets: SessionSecrets::derive(&KAT_SPAKE_KEY, &hello, &challenge),
        };
        let mut op = operator
            .finish(&reply)
            .expect("confirmacion del host valida");

        let op0 = op.channel.seal(b"op->host #0").unwrap();
        let op1 = op.channel.seal(b"op->host #1").unwrap();
        let host0 = host_channel.seal(b"host->op #0").unwrap();
        let host1 = host_channel.seal(b"host->op #1").unwrap();
        assert_eq!(
            hex(&op0),
            "0000000000000000b29c87ddb226e7c2791de31461cdb11d0967828c55da0a4dbc374c"
        );
        assert_eq!(
            hex(&op1),
            "0000000000000001cf0a676043161773f2f9fed88e0b9ca30275795bcd84cb6450ab75"
        );
        assert_eq!(
            hex(&host0),
            "0000000000000000326564bf2f629d194052b2ff7efc34cb3a53cca64d470990999811"
        );
        assert_eq!(
            hex(&host1),
            "0000000000000001642f61cf7e9bb98cb2fe8d455ae9c63414d9ae7bf0f06bb63c4bdd"
        );

        assert_eq!(host_channel.open(&op0).unwrap(), b"op->host #0");
        assert_eq!(host_channel.open(&op1).unwrap(), b"op->host #1");
        assert_eq!(op.channel.open(&host0).unwrap(), b"host->op #0");
        assert_eq!(op.channel.open(&host1).unwrap(), b"host->op #1");
    }

    /// Vectores de regresión del video v1 (calculados una vez con este código): clave de video
    /// derivada por HKDF y registros sellados en dos streams. Agregarlos no altera las salidas v1
    /// anteriores, que fija `v1_format_regression_vectors`.
    #[test]
    fn video_v1_regression_vectors() {
        let s = SessionSecrets::derive(&KAT_SPAKE_KEY, &kat_hello(), &kat_challenge_msg());
        assert_eq!(
            hex(s.key_video_host_to_operator.as_ref()),
            "648d9496becafc5bb07aadb7883b255415f4084206c85e962246494046fa54d4"
        );
        let header = |frame_seq: u64, payload_len: u32| VideoPacketHeader {
            frame_seq,
            capture_ts_us: 1_000_000 + frame_seq,
            monitor_index: 1,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: frame_seq == 0,
            payload_len,
        };
        let mut sealer = VideoSealer::new(&s.key_video_host_to_operator);
        let mut s0 = sealer.open_stream().unwrap();
        let mut s1 = sealer.open_stream().unwrap();
        let r00 = s0.seal(&header(0, 5), b"frame").unwrap();
        let r01 = s0.seal(&header(1, 5), b"tiles").unwrap();
        let r10 = s1.seal(&header(2, 5), b"frame").unwrap();
        assert_eq!(hex(&s1.preamble()), "00000001");
        assert_eq!(
            hex(&r00),
            "00000000000000000000000040420f0000000000050000000101010005f6d5732fce30c57de6234b3160af86884eabd1a1"
        );
        assert_eq!(
            hex(&r01),
            "00000001010000000000000041420f00000000000500000001010000be2e52aabf8ce79f8969752215ac5577390357423e"
        );
        assert_eq!(
            hex(&r10),
            "00000000020000000000000042420f000000000005000000010100002ec52011dbbaa30e9798712791330cf8a06fea269f"
        );

        let mut opener = VideoOpener::new(&s.key_video_host_to_operator);
        let mut o0 = opener.accept_stream(s0.preamble()).unwrap();
        let mut o1 = opener.accept_stream(s1.preamble()).unwrap();
        assert_eq!(o1.open(&r10).unwrap(), (header(2, 5), b"frame".to_vec()));
        assert_eq!(o0.open(&r00).unwrap(), (header(0, 5), b"frame".to_vec()));
        assert_eq!(o0.open(&r01).unwrap(), (header(1, 5), b"tiles".to_vec()));
    }

    #[test]
    fn video_key_is_distinct_and_handshake_yields_working_video_pair() {
        let s = SessionSecrets::derive(&KAT_SPAKE_KEY, &kat_hello(), &kat_challenge_msg());
        assert_ne!(*s.key_video_host_to_operator, *s.key_host_to_operator);
        assert_ne!(*s.key_video_host_to_operator, *s.key_operator_to_host);

        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        let (mut host, mut op) =
            run_in_memory_handshake(waiting, &req, &pw, Instant::now()).unwrap();
        let header = VideoPacketHeader {
            frame_seq: 0,
            capture_ts_us: 7,
            monitor_index: 0,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: 4,
        };
        let mut stream = host.video.open_stream().unwrap();
        let rec = stream.seal(&header, b"bgra").unwrap();
        let mut opened = op.video.accept_stream(stream.preamble()).unwrap();
        assert_eq!(opened.open(&rec).unwrap(), (header, b"bgra".to_vec()));
        // El video no se abre con el canal de control ni el control con la clave de video.
        assert!(op.channel.open(&rec).is_err());
        let ctrl = host.channel.seal(b"pong").unwrap();
        let mut other = op.video.accept_stream(1u32.to_be_bytes()).unwrap();
        assert!(other.open(&ctrl).is_err());
    }

    /// Fija las identidades SPAKE2, los roles (operador = A, host = B) y la normalización de
    /// la contraseña con literales, sin RNG determinista: un SPAKE2 construido a mano con esos
    /// literales debe llegar a la misma clave que el código de producción.
    #[test]
    fn spake2_identities_roles_and_password_normalization_are_fixed() {
        let (id_a, id_b) = identities(123_456_789);
        assert_eq!(id_a.as_slice(), b"operator/123456789");
        assert_eq!(id_b.as_slice(), b"host/123456789");
        let (id_a, id_b) = identities(7);
        assert_eq!(id_a.as_slice(), b"operator/000000007");
        assert_eq!(id_b.as_slice(), b"host/000000007");

        let session_id = SessionId::parse("123 456 789").unwrap();
        let typed = " abcde-fghjk ";
        let normalized: &[u8] = b"ABCDEFGHJK";
        assert_eq!(normalize_password_input(typed).as_slice(), normalized);
        let request = OperatorConnectionRequest {
            target_session_id: session_id,
            operator_display_name: "Soporte".to_string(),
            operator_ed25519_fingerprint: [0; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };
        let literal_a = Identity::new(b"operator/123456789");
        let literal_b = Identity::new(b"host/123456789");

        // Operador de producción (rol A) frente a un host literal en rol B.
        let (op, hello) = OperatorHandshake::start(&request, typed).unwrap();
        let (host_b, msg_b) =
            Spake2::<Ed25519Group>::start_b(&Password::new(normalized), &literal_a, &literal_b);
        assert_eq!(
            op.spake.finish(&msg_b).unwrap(),
            host_b.finish(&hello.spake_msg).unwrap()
        );

        // Host de producción (rol B) frente a un operador literal en rol A.
        let (op_a, msg_a) =
            Spake2::<Ed25519Group>::start_a(&Password::new(normalized), &literal_a, &literal_b);
        let literal_hello = PakeHello {
            spake_msg: msg_a,
            ..hello
        };
        let (exchange, challenge) =
            HostKeyExchange::respond(session_id, normalized, &literal_hello).unwrap();
        let op_key = op_a.finish(&challenge.spake_msg).unwrap();
        let expected = SessionSecrets::derive(&op_key, &literal_hello, &challenge.spake_msg);
        assert!(exchange.verify_operator(&PakeConfirm {
            operator_confirmation: expected.operator_confirmation(),
        }));

        // Un mensaje del mismo rol se rechaza en ambos lados: el operador solo acepta B y el host
        // solo acepta A. Con las identidades intercambiadas la clave no coincide.
        let (op, hello) = OperatorHandshake::start(&request, typed).unwrap();
        let (_, msg_a) =
            Spake2::<Ed25519Group>::start_a(&Password::new(normalized), &literal_a, &literal_b);
        assert!(op.spake.finish(&msg_a).is_err());
        let (_, msg_b) =
            Spake2::<Ed25519Group>::start_b(&Password::new(normalized), &literal_a, &literal_b);
        let b_as_hello = PakeHello {
            spake_msg: msg_b,
            ..hello
        };
        assert!(HostKeyExchange::respond(session_id, normalized, &b_as_hello).is_err());
        let (op, hello) = OperatorHandshake::start(&request, typed).unwrap();
        let (swapped, msg) =
            Spake2::<Ed25519Group>::start_b(&Password::new(normalized), &literal_b, &literal_a);
        assert_ne!(
            op.spake.finish(&msg).unwrap(),
            swapped.finish(&hello.spake_msg).unwrap()
        );
    }

    /// Literales postcard de los mensajes del handshake posteriores al hello.
    #[test]
    fn handshake_messages_postcard_literals() {
        let challenge = PakeChallenge {
            spake_msg: kat_challenge_msg(),
        };
        let challenge_hex = "21808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0";
        assert_eq!(
            hex(&postcard::to_allocvec(&challenge).unwrap()),
            challenge_hex
        );
        assert_eq!(
            hex(&postcard::to_allocvec(&PakeHelloReply::Challenge(challenge)).unwrap()),
            format!("00{challenge_hex}")
        );
        let unsupported = PakeHelloReply::UnsupportedProtocolVersion {
            supported: PROTOCOL_VERSION,
        };
        assert_eq!(hex(&postcard::to_allocvec(&unsupported).unwrap()), "0101");
        let confirm = PakeConfirm {
            operator_confirmation: [0x11; 32],
        };
        assert_eq!(
            hex(&postcard::to_allocvec(&confirm).unwrap()),
            "11".repeat(32)
        );
        let accepted = HostAuthReply::Accepted {
            host_confirmation: [0x22; 32],
        };
        assert_eq!(
            hex(&postcard::to_allocvec(&accepted).unwrap()),
            format!("00{}", "22".repeat(32))
        );
        let rejected = HostAuthReply::Rejected {
            remaining_attempts: 2,
        };
        assert_eq!(hex(&postcard::to_allocvec(&rejected).unwrap()), "0102");
    }

    /// El rechazo por versión llega al operador con su propia señal, distinta de `Rejected`,
    /// y no cuenta intento ni rota la contraseña.
    #[test]
    fn unsupported_version_has_own_network_signal() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let req = request_for(&waiting);
        let (op, mut hello) = OperatorHandshake::start(&req, &pw).unwrap();
        hello.protocol_version = PROTOCOL_VERSION + 1;
        let (waiting, err) = waiting.accept_operator_hello(&hello).unwrap_err();
        assert_eq!(
            err,
            ConsentError::UnsupportedProtocolVersion(PROTOCOL_VERSION + 1)
        );
        let reply = PakeHelloReply::UnsupportedProtocolVersion {
            supported: PROTOCOL_VERSION,
        };
        let wire = postcard::to_allocvec(&reply).unwrap();
        let received: PakeHelloReply = postcard::from_bytes(&wire).unwrap();
        assert_eq!(
            op.handle_hello_reply(&received).unwrap_err(),
            HandshakeError::UnsupportedProtocolVersion {
                supported: PROTOCOL_VERSION
            }
        );
        assert_eq!(waiting.display_password(), pw);

        // Con la versión correcta el mismo camino de red completa el handshake.
        let (op, hello) = OperatorHandshake::start(&req, &pw).unwrap();
        let (auth, challenge) = waiting.accept_operator_hello(&hello).unwrap();
        let (verdict, confirm) = op
            .handle_hello_reply(&PakeHelloReply::Challenge(challenge))
            .unwrap();
        let host = auth
            .verify_operator_confirmation(&confirm, Instant::now())
            .unwrap();
        assert_eq!(verdict.finish(&host.reply).unwrap().sas, host.pending.sas());
    }

    #[test]
    fn records_from_handshake_reject_replay() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let pw = waiting.display_password();
        let (outcome, op_wait) = run(waiting, &pw);
        let (_, mut host_channel, reply) = outcome.unwrap();
        let mut op = op_wait.finish(&reply).unwrap();
        let rec = op.channel.seal(b"tecla").unwrap();
        host_channel.open(&rec).unwrap();
        assert!(matches!(
            host_channel.open(&rec),
            Err(ChannelError::Replay { .. })
        ));
    }
}
