//! Senalizacion propia del relay: unico intercambio visible para el relay antes del emparejamiento.
//!
//! Cada conexion QUIC abre un unico stream bidireccional. El cliente envia una trama
//! (`awawa_protocol::framing`, cuerpo postcard) con un `ClientRequest` y el relay responde con
//! tramas `RelayResponse`:
//!
//! - Host: `Register` -> `Registered { ttl_secs }` y, cuando un operador lo busca, `Paired`
//!   (o `Error(Expired)` si el slot caduca sin emparejar).
//! - Operador: `Lookup` -> `Paired` o `Error(..)`.
//!
//! Tras `Paired` el relay solo copia bytes entre ambos streams: no parsea nada mas. Tambien puentea,
//! como copia opaca, los streams unidireccionales (video) que abra cualquiera de los dos extremos:
//! por cada uno abre otro hacia el extremo contrario (hasta `MAX_VIDEO_STREAMS` simultaneos).

use std::time::Duration;

use awawa_protocol::framing::{FRAME_LEN_PREFIX, FramingError, MAX_CTRL_FRAME, encode_frame};
use awawa_protocol::wire::{WireError, decode_message, encode_message};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

/// Puerto UDP por defecto del relay.
pub const RELAY_PORT: u16 = 4433;

/// Vida de un slot de host sin emparejar.
pub const SLOT_TTL: Duration = Duration::from_secs(600);

/// Streams unidireccionales simultaneos que cada extremo puede tener abiertos hacia el relay (y el
/// relay hacia cada extremo). Al llegar al tope, abrir otro espera a que se liberen lugares: quinn
/// devuelve el credito por lotes, cuando se cerraron (leidos hasta el final o reiniciados) mas de
/// 1/8 del tope, es decir, de 2 en 2 con 8.
pub const MAX_VIDEO_STREAMS: u32 = 8;

/// ALPN que identifica la version de la senalizacion del relay.
pub const ALPN: &[u8] = b"support-relay/1";

/// Nombre de servidor que usan los clientes al conectar. Con la clave fijada no se valida contra
/// DNS; solo debe ser un nombre sintacticamente valido para SNI.
pub(crate) const SERVER_NAME: &str = "support-relay";

/// Primera trama de un cliente en su stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientRequest {
    /// El host registra el ID que el propio host genero (el relay no genera IDs).
    Register { session_id: u32 },
    /// El operador busca el slot de un host.
    Lookup { session_id: u32 },
}

/// Respuesta del relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Slot creado; caduca a los `ttl_secs` si nadie se empareja.
    Registered {
        ttl_secs: u32,
    },
    /// Emparejado: a partir de aqui el stream es un canal opaco extremo a extremo.
    Paired,
    Error(RelayError),
}

/// Errores de senalizacion. `NotFound` cubre ID inexistente, caducado o ya emparejado (el relay
/// no distingue para no revelar el estado de los slots).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayError {
    InvalidSessionId,
    SessionIdTaken,
    NotFound,
    RateLimited,
    ServerBusy,
    /// El slot del host caduco sin que nadie se emparejara.
    Expired,
    MalformedRequest,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::InvalidSessionId => "ID de sesion invalido",
            Self::SessionIdTaken => "ID de sesion ya registrado",
            Self::NotFound => "sesion no encontrada",
            Self::RateLimited => "demasiados intentos desde este origen",
            Self::ServerBusy => "relay saturado",
            Self::Expired => "el registro de la sesion caduco",
            Self::MalformedRequest => "peticion mal formada",
        };
        f.write_str(text)
    }
}

/// Un ID valido tiene 9 digitos (mismo rango que `SessionId`).
pub fn is_valid_session_id(raw: u32) -> bool {
    (100_000_000..=999_999_999).contains(&raw)
}

/// Fallo al leer o escribir una trama en un stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// El extremo cerro el stream antes de completar la trama.
    Closed,
    Framing(FramingError),
    Wire(WireError),
    Io(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("stream cerrado"),
            Self::Framing(e) => write!(f, "trama invalida: {e:?}"),
            Self::Wire(e) => write!(f, "mensaje invalido: {e:?}"),
            Self::Io(e) => write!(f, "error de E/S: {e}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// Escribe `payload` como una trama `[len u32 BE][payload]`.
pub(crate) async fn write_frame(send: &mut SendStream, payload: &[u8]) -> Result<(), StreamError> {
    let frame = encode_frame(payload).map_err(StreamError::Framing)?;
    send.write_all(&frame)
        .await
        .map_err(|e| StreamError::Io(e.to_string()))
}

/// Lee una trama completa. La longitud declarada se valida antes de reservar memoria.
pub(crate) async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, StreamError> {
    let mut prefix = [0u8; FRAME_LEN_PREFIX];
    read_exact(recv, &mut prefix).await?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(StreamError::Framing(FramingError::EmptyFrame));
    }
    if declared > MAX_CTRL_FRAME {
        return Err(StreamError::Framing(FramingError::FrameTooLarge(declared)));
    }
    let mut body = vec![0u8; declared];
    read_exact(recv, &mut body).await?;
    Ok(body)
}

pub(crate) async fn read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> Result<(), StreamError> {
    recv.read_exact(buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => StreamError::Closed,
        quinn::ReadExactError::ReadError(e) => StreamError::Io(e.to_string()),
    })
}

pub(crate) async fn write_message<T: Serialize>(
    send: &mut SendStream,
    msg: &T,
) -> Result<(), StreamError> {
    let bytes = encode_message(msg).map_err(StreamError::Wire)?;
    write_frame(send, &bytes).await
}

pub(crate) async fn read_message<T: serde::de::DeserializeOwned>(
    recv: &mut RecvStream,
) -> Result<T, StreamError> {
    let bytes = read_frame(recv).await?;
    decode_message(&bytes).map_err(StreamError::Wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_v1_literals() {
        let req = ClientRequest::Register {
            session_id: 123_456_789,
        };
        assert_eq!(
            encode_message(&req).unwrap(),
            [0x00, 0x95, 0x9A, 0xEF, 0x3A]
        );
        let req = ClientRequest::Lookup {
            session_id: 123_456_789,
        };
        assert_eq!(
            encode_message(&req).unwrap(),
            [0x01, 0x95, 0x9A, 0xEF, 0x3A]
        );
        assert_eq!(
            encode_message(&RelayResponse::Registered { ttl_secs: 600 }).unwrap(),
            [0x00, 0xD8, 0x04]
        );
        assert_eq!(encode_message(&RelayResponse::Paired).unwrap(), [0x01]);
        assert_eq!(
            encode_message(&RelayResponse::Error(RelayError::NotFound)).unwrap(),
            [0x02, 0x02]
        );
        assert_eq!(
            encode_message(&RelayResponse::Error(RelayError::RateLimited)).unwrap(),
            [0x02, 0x03]
        );
    }

    #[test]
    fn requests_round_trip_and_reject_trailing_or_truncated_bytes() {
        let req = ClientRequest::Lookup {
            session_id: 999_999_999,
        };
        let bytes = encode_message(&req).unwrap();
        assert_eq!(decode_message::<ClientRequest>(&bytes).unwrap(), req);
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_message::<ClientRequest>(&extra).is_err());
        assert!(decode_message::<ClientRequest>(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_message::<ClientRequest>(&[0x07]).is_err());
    }

    #[test]
    fn session_id_range_matches_credentials() {
        assert!(!is_valid_session_id(99_999_999));
        assert!(is_valid_session_id(100_000_000));
        assert!(is_valid_session_id(999_999_999));
        assert!(!is_valid_session_id(1_000_000_000));
        assert!(!is_valid_session_id(0));
    }
}
