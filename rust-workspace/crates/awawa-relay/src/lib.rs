//! # `awawa-relay`
//!
//! Relay ciego del sistema de soporte remoto: QUIC sobre UDP 4433 con certificado
//! autofirmado, registro de hosts por ID con TTL de 600 s, emparejamiento con un operador y puente
//! de bytes opaco. Invariante: el relay nunca ve la contrasena ni puede descifrar video o entrada;
//! tras el emparejamiento solo copia bytes y no parsea nada.
//!
//! - `protocol`: senalizacion propia (`Register`, `Lookup`, respuestas y errores).
//! - `server`: `RelayServer` (tabla `DashMap` con TTL, limpieza, limite por IP con `governor`).
//! - `client`: conector reutilizable por host, operador y servicio, con la clave del relay fijada.
//! - `identity`: certificado del relay y `RelayPin` que los clientes fijan.
//!
//! Limite de tasa: 5 intentos de `Lookup` por minuto y por IP (los intentos sobre IDs inexistentes
//! tambien cuentan) y, mas holgado, 30 registros por minuto y por IP. IPv6 se agrupa por /64.

pub mod client;
pub mod identity;
mod limiter;
pub mod protocol;
pub mod server;
mod slots;

pub use client::{
    ClientError, HostRegistration, RelayClient, RelayedReceiver, RelayedSender, RelayedStream,
    VideoReceiver, VideoSender, VideoStreams,
};
pub use identity::{IdentityError, RelayIdentity, RelayPin};
pub use limiter::RelayClock;
pub use protocol::{
    ALPN, ClientRequest, MAX_VIDEO_STREAMS, RELAY_PORT, RelayError, RelayResponse, SLOT_TTL,
    StreamError, is_valid_session_id,
};
#[cfg(any(test, feature = "test-support"))]
pub use server::{BridgeDirection, ByteTap};
pub use server::{RelayConfig, RelayHandle, RelayServer, RelayStartError};
