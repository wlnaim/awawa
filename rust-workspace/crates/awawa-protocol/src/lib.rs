//! # `awawa-protocol`
//!
//! Núcleo de dominio y seguridad para el sistema de soporte remoto bajo demanda:
//! - Generación exclusiva de `SessionId` y `SessionPassword` efímeros con CSPRNG del SO (`BCryptGenRandom` en Windows).
//! - Máquina de estados **Type-State** (`WaitingForRequest` -> `PendingLocalConsent` -> `ApprovedActiveSession`)
//!   que garantiza por construcción que ningún cuadro de pantalla ni evento de cursor/teclado pueda fluir
//!   sin **Aprobación Local Mandatoria** en el equipo receptor.
//! - Normalización multimonitor `[0..=65535]` compatible con `Win32 SendInput` (`MOUSEEVENTF_VIRTUALDESK`).
//! - `ActiveInputTracker` (*Dead-Man Switch*) para liberar teclas y botones pegados al cerrar sesión.
//! - Exclusión geométrica (`ProtectedRect`) para impedir que el operador remoto interactúe con la UI de desconexión local.
//! - Protocolo de red (`wire`, `framing`) y handshake E2E SPAKE2 (`handshake`) con canal AEAD
//!   `ChaCha20-Poly1305` anti-replay (`secure_channel`). La sesión pendiente de aprobación local solo
//!   nace de un handshake exitoso.
//! - Acceso desatendido: verificador persistente PBKDF2 (`unattended`), auditoría sin secretos (`audit`) y
//!   suspensión de captura/entrada ante escritorio seguro, bloqueo o fin de sesión (`desktop_session`).
//! - Canal E2E desatendido: X25519 efímero firmado con la clave Ed25519 fijada del servicio y contraseña
//!   dentro del canal (`unattended_channel`).

pub mod audit;
pub mod consent_fsm;
pub mod credentials;
pub mod desktop_session;
pub mod framing;
pub mod geometry;
pub mod handshake;
pub mod input_safety;
pub mod messages;
pub mod secure_channel;
pub mod unattended;
pub mod unattended_channel;
pub mod video_channel;
pub mod wire;

pub use audit::{
    AUDIT_MAX_FIELD_CHARS, AuditEvent, AuditOutcome, AuditRecord, AuditSink, AuditSinkError,
    MemoryAuditSink, sanitize_audit_text,
};
pub use consent_fsm::{
    AccessMode, ApprovedActiveSession, AuthenticatingPake, ConsentError, HostAuthenticated,
    OperatorConnectionRequest, PendingLocalConsent, SessionRevocation, WaitingForRequest,
};
pub use credentials::{CredentialsError, HostCredentials, SessionId, SessionPassword};
pub use desktop_session::{
    DesktopEvent, DesktopSessionMonitor, EndReason, InputDesktopKind, MonitorAction, MonitorState,
    OperatorNotice, RESUME_CONSECUTIVE_DEFAULT_POLLS, SuspendReason,
};
pub use framing::{FRAME_LEN_PREFIX, FramingError, MAX_CTRL_FRAME, decode_frame, encode_frame};
pub use geometry::{MonitorDescriptor, NormalizedPoint, ProtectedRect, VirtualDesktopBounds};
#[cfg(any(test, feature = "test-support"))]
pub use handshake::run_in_memory_handshake;
pub use handshake::{
    HandshakeError, HostAuthReply, OperatorAwaitingVerdict, OperatorHandshake, OperatorSession,
    PROTOCOL_VERSION, PakeChallenge, PakeConfirm, PakeHello, PakeHelloReply, SasCode,
};
pub use input_safety::ActiveInputTracker;
pub use messages::{ButtonState, KeyState, MouseButton, RemoteInputCommand, ScopedCapabilities};
pub use secure_channel::{ChannelError, Direction, SecureChannel};
pub use unattended::{
    AuthThrottle, KdfError, PRODUCTION_PBKDF2_ITERATIONS, PasswordKdf, PasswordVerifierRecord,
    ThrottleScope, UNATTENDED_PASSWORD_MAX_LEN, UNATTENDED_PASSWORD_MIN_LEN,
    UnattendedAuthenticator, UnattendedAuthorization, UnattendedCredentialState, UnattendedError,
    UnattendedStatus, VERIFIER_DK_LEN, VERIFIER_RECORD_LEN, VERIFIER_SALT_LEN, VerifierStatus,
};
#[cfg(any(test, feature = "test-support"))]
pub use unattended_channel::run_in_memory_unattended;
pub use unattended_channel::{
    OperatorAwaitingAuth, OperatorUnattendedHandshake, OperatorUnattendedPending,
    OperatorUnattendedSession, ServiceAuthOutcome, ServiceAwaitingPassword, ServiceHelloRejection,
    ServiceUnattendedSession, UNATTENDED_PROTOCOL_VERSION, UnattendedAuthReply,
    UnattendedChannelError, UnattendedHello, UnattendedHelloReply, UnattendedVerdict,
};
pub use video_channel::{
    MAX_VIDEO_PAYLOAD_LEN, VIDEO_RECORD_COUNTER_LEN, VIDEO_RECORD_PREFIX_LEN,
    VIDEO_STREAM_PREAMBLE_LEN, VideoChannelError, VideoOpener, VideoSealer, VideoStreamOpener,
    VideoStreamSealer,
};
pub use wire::{
    CapabilityMask, ClientToHostMessage, DisconnectReason, HostToClientMessage,
    VIDEO_PACKET_HEADER_LEN, VideoCodec, VideoPacketHeader, WireError, decode_message,
    encode_message,
};
