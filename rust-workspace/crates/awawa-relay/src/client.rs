//! Conector de cliente reutilizable por host, operador y servicio.
//!
//! - Host: `RelayClient::register_host(id)` -> `HostRegistration::wait_for_operator()`.
//! - Operador: `RelayClient::connect_operator(id)`.
//!
//! Ambos terminan en un `RelayedStream`: un canal de tramas (`awawa_protocol::framing`) opaco para
//! el relay, sobre el que corre el handshake de `awawa_protocol::handshake` y despues los
//! registros de `SecureChannel`. El cliente solo acepta el certificado fijado (`RelayPin`).
//!
//! Video: sobre la misma conexion emparejada, `RelayedStream::video_streams` da un `VideoStreams`
//! (clonable, usable desde cualquier tarea) para abrir streams unidireccionales (`open`, el host) y
//! aceptarlos (`accept`, el operador); el relay los puentea en ambos sentidos. Son bytes crudos: el
//! relay no impone tramas ni tope de tamano y entrega exactamente los bytes escritos, en orden, por
//! stream. El formato de registros y su cifrado los define la capa de protocolo. Hasta
//! `MAX_VIDEO_STREAMS` abiertos a la vez por sentido; con el tope alcanzado `open` espera.
//!
//! Lectura y escritura a la vez: `RelayedStream::into_split` da una mitad de envio y otra de
//! recepcion, cada una para su propia tarea.
//!
//! `RelayClient::new` debe llamarse dentro de un runtime de tokio.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use awawa_protocol::SessionId;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::time::timeout;

use crate::identity::{PinnedCertVerifier, RelayPin};
use crate::protocol::{
    ALPN, ClientRequest, MAX_VIDEO_STREAMS, RelayError, RelayResponse, SERVER_NAME, StreamError,
    read_exact, read_frame, read_message, write_frame, write_message,
};

/// Espera maxima por la respuesta del relay a `Register` / `Lookup`. No aplica a la espera de un
/// operador (`wait_for_operator`), que el llamador acota con su propio plazo.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

const KEEP_ALIVE: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ClientError {
    /// No se pudo preparar el cliente (socket o TLS).
    Setup(String),
    /// Fallo al establecer la conexion QUIC (incluye certificado distinto del fijado).
    Connect(String),
    /// El relay respondio con un error de senalizacion.
    Relay(RelayError),
    /// Fallo de transporte o de tramas.
    Stream(StreamError),
    /// El relay no respondio a tiempo.
    Timeout,
    /// Respuesta fuera de secuencia.
    UnexpectedResponse,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(e) => write!(f, "no se pudo preparar el cliente del relay: {e}"),
            Self::Connect(e) => write!(f, "no se pudo conectar con el relay: {e}"),
            Self::Relay(e) => write!(f, "el relay rechazo la peticion: {e}"),
            Self::Stream(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("el relay no respondio a tiempo"),
            Self::UnexpectedResponse => f.write_str("respuesta inesperada del relay"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<StreamError> for ClientError {
    fn from(e: StreamError) -> Self {
        Self::Stream(e)
    }
}

/// Cliente de un relay concreto, con su certificado fijado.
pub struct RelayClient {
    endpoint: Endpoint,
    relay_addr: SocketAddr,
}

impl RelayClient {
    /// Prepara un cliente para el relay en `relay_addr`; solo aceptara el certificado de `pin`.
    pub fn new(relay_addr: SocketAddr, pin: RelayPin) -> Result<Self, ClientError> {
        let setup = |e: &dyn fmt::Display| ClientError::Setup(e.to_string());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| setup(&e))?
            .dangerous()
            .with_custom_certificate_verifier(PinnedCertVerifier::new(pin))
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let quic = QuicClientConfig::try_from(tls).map_err(|e| setup(&e))?;
        let mut config = ClientConfig::new(Arc::new(quic));
        let mut transport = TransportConfig::default();
        transport
            .keep_alive_interval(Some(KEEP_ALIVE))
            .max_concurrent_bidi_streams(VarInt::from_u32(0))
            .max_concurrent_uni_streams(VarInt::from_u32(MAX_VIDEO_STREAMS));
        config.transport_config(Arc::new(transport));

        let bind: SocketAddr = if relay_addr.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let mut endpoint = Endpoint::client(bind).map_err(|e| setup(&e))?;
        endpoint.set_default_client_config(config);
        Ok(Self {
            endpoint,
            relay_addr,
        })
    }

    /// Registra en el relay el `session_id` que el host genero. Devuelve el registro en espera.
    pub async fn register_host(
        &self,
        session_id: SessionId,
    ) -> Result<HostRegistration, ClientError> {
        let (conn, mut send, mut recv) = self
            .request(ClientRequest::Register {
                session_id: session_id.raw_u32(),
            })
            .await?;
        match timeout(RESPONSE_TIMEOUT, read_message::<RelayResponse>(&mut recv)).await {
            Ok(Ok(RelayResponse::Registered { ttl_secs })) => Ok(HostRegistration {
                ttl: Duration::from_secs(u64::from(ttl_secs)),
                stream: RelayedStream { conn, send, recv },
            }),
            Ok(Ok(RelayResponse::Error(e))) => {
                let _ = send.finish();
                Err(ClientError::Relay(e))
            }
            Ok(Ok(RelayResponse::Paired)) => Err(ClientError::UnexpectedResponse),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// Busca el slot de `session_id` y, si existe, devuelve el canal emparejado con el host.
    pub async fn connect_operator(
        &self,
        session_id: SessionId,
    ) -> Result<RelayedStream, ClientError> {
        let (conn, send, mut recv) = self
            .request(ClientRequest::Lookup {
                session_id: session_id.raw_u32(),
            })
            .await?;
        match timeout(RESPONSE_TIMEOUT, read_message::<RelayResponse>(&mut recv)).await {
            Ok(Ok(RelayResponse::Paired)) => Ok(RelayedStream { conn, send, recv }),
            Ok(Ok(RelayResponse::Error(e))) => Err(ClientError::Relay(e)),
            Ok(Ok(RelayResponse::Registered { .. })) => Err(ClientError::UnexpectedResponse),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// Cierra el endpoint y todas sus conexiones.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"");
    }

    async fn request(
        &self,
        request: ClientRequest,
    ) -> Result<(Connection, SendStream, RecvStream), ClientError> {
        let connecting = self
            .endpoint
            .connect(self.relay_addr, SERVER_NAME)
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let conn = timeout(RESPONSE_TIMEOUT, connecting)
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        write_message(&mut send, &request).await?;
        Ok((conn, send, recv))
    }
}

impl fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayClient")
            .field("relay_addr", &self.relay_addr)
            .finish_non_exhaustive()
    }
}

/// Host registrado, esperando a que un operador lo busque.
pub struct HostRegistration {
    /// Tiempo que el relay mantiene el slot sin emparejar.
    pub ttl: Duration,
    stream: RelayedStream,
}

impl HostRegistration {
    /// Espera el emparejamiento. Termina con `Relay(Expired)` si el slot caduca; el llamador puede
    /// acotarla con `tokio::time::timeout`. Soltar este valor libera el slot en el relay.
    pub async fn wait_for_operator(mut self) -> Result<RelayedStream, ClientError> {
        match read_message::<RelayResponse>(&mut self.stream.recv).await? {
            RelayResponse::Paired => Ok(self.stream),
            RelayResponse::Error(e) => Err(ClientError::Relay(e)),
            RelayResponse::Registered { .. } => Err(ClientError::UnexpectedResponse),
        }
    }
}

impl fmt::Debug for HostRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostRegistration")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// Canal emparejado, opaco para el relay: tramas `[len u32 BE][bytes]` con tope `MAX_CTRL_FRAME`.
pub struct RelayedStream {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl RelayedStream {
    /// Envia una trama (por ejemplo un mensaje de handshake o un registro de `SecureChannel`).
    pub async fn send_frame(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        write_frame(&mut self.send, payload).await
    }

    /// Recibe la siguiente trama completa.
    ///
    /// No es seguro de cancelar: si el futuro se suelta a mitad de una trama (por ejemplo, porque
    /// otra rama de un `select!` gano), los bytes ya leidos se pierden y el canal queda
    /// desincronizado. Para leer mientras se escribe, usar `into_split` y dejar la mitad de
    /// recepcion en su propia tarea, esperando solo a `recv_frame`.
    pub async fn recv_frame(&mut self) -> Result<Vec<u8>, StreamError> {
        read_frame(&mut self.recv).await
    }

    /// Cierra el sentido de envio con gracia; el otro extremo vera el final del stream. Debe
    /// llamarse antes de soltar el canal si el ultimo mensaje enviado tiene que llegar: soltarlo
    /// cierra la conexion y puede descartar lo que aun no se entrego.
    pub async fn finish(&mut self) {
        let _ = self.send.finish();
        let _ = timeout(Duration::from_secs(2), self.send.stopped()).await;
    }

    /// Cierra la conexion de inmediato.
    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"");
    }

    /// Acceso a los streams de video de esta conexion (abrir y aceptar), desde cualquier tarea.
    pub fn video_streams(&self) -> VideoStreams {
        VideoStreams {
            conn: self.conn.clone(),
        }
    }

    /// Separa el canal en una mitad de envio y otra de recepcion, usables desde tareas distintas.
    pub fn into_split(self) -> (RelayedSender, RelayedReceiver) {
        (
            RelayedSender {
                conn: self.conn.clone(),
                send: self.send,
            },
            RelayedReceiver {
                conn: self.conn,
                recv: self.recv,
            },
        )
    }
}

impl fmt::Debug for RelayedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayedStream").finish_non_exhaustive()
    }
}

/// Mitad de envio de un `RelayedStream`.
pub struct RelayedSender {
    conn: Connection,
    send: SendStream,
}

impl RelayedSender {
    /// Igual que `RelayedStream::send_frame`.
    pub async fn send_frame(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        write_frame(&mut self.send, payload).await
    }

    /// Igual que `RelayedStream::finish`.
    pub async fn finish(&mut self) {
        let _ = self.send.finish();
        let _ = timeout(Duration::from_secs(2), self.send.stopped()).await;
    }

    /// Cierra la conexion de inmediato (tambien la mitad de recepcion y los streams de video).
    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"");
    }
}

impl fmt::Debug for RelayedSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayedSender").finish_non_exhaustive()
    }
}

/// Mitad de recepcion de un `RelayedStream`.
pub struct RelayedReceiver {
    conn: Connection,
    recv: RecvStream,
}

impl RelayedReceiver {
    /// Igual que `RelayedStream::recv_frame`, con la misma advertencia: no es seguro de cancelar;
    /// esta mitad debe vivir en su propia tarea.
    pub async fn recv_frame(&mut self) -> Result<Vec<u8>, StreamError> {
        read_frame(&mut self.recv).await
    }

    /// Cierra la conexion de inmediato (tambien la mitad de envio y los streams de video).
    pub fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"");
    }
}

impl fmt::Debug for RelayedReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayedReceiver").finish_non_exhaustive()
    }
}

/// Streams unidireccionales de video de una conexion emparejada. Clonable.
#[derive(Clone)]
pub struct VideoStreams {
    conn: Connection,
}

impl VideoStreams {
    /// Abre un stream hacia el otro extremo. Espera si ya hay `MAX_VIDEO_STREAMS` abiertos. El otro
    /// extremo no lo ve hasta que se escribe el primer byte.
    pub async fn open(&self) -> Result<VideoSender, StreamError> {
        let send = self
            .conn
            .open_uni()
            .await
            .map_err(|e| StreamError::Io(e.to_string()))?;
        Ok(VideoSender { send })
    }

    /// Espera el siguiente stream que abra el otro extremo. Falla cuando la conexion se cierra.
    pub async fn accept(&self) -> Result<VideoReceiver, StreamError> {
        let recv = self
            .conn
            .accept_uni()
            .await
            .map_err(|e| StreamError::Io(e.to_string()))?;
        Ok(VideoReceiver { recv })
    }
}

impl fmt::Debug for VideoStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoStreams").finish_non_exhaustive()
    }
}

/// Lado de escritura de un stream de video: bytes crudos, sin tramas.
pub struct VideoSender {
    send: SendStream,
}

impl VideoSender {
    /// Escribe todos los bytes. Espera (contrapresion) mientras el otro extremo no lea.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.send
            .write_all(bytes)
            .await
            .map_err(|e| StreamError::Io(e.to_string()))
    }

    /// Cierra el stream con gracia: el otro extremo vera el final despues del ultimo byte. Soltar
    /// el `VideoSender` sin llamarlo tambien lo cierra con gracia, sin esperar la entrega.
    pub async fn finish(&mut self) {
        let _ = self.send.finish();
        let _ = timeout(Duration::from_secs(2), self.send.stopped()).await;
    }
}

impl fmt::Debug for VideoSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoSender").finish_non_exhaustive()
    }
}

/// Lado de lectura de un stream de video: bytes crudos, sin tramas.
pub struct VideoReceiver {
    recv: RecvStream,
}

impl VideoReceiver {
    /// Lee hasta `buf.len()` bytes; `Ok(None)` al final limpio del stream. Seguro de cancelar.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        self.recv
            .read(buf)
            .await
            .map_err(|e| StreamError::Io(e.to_string()))
    }

    /// Llena `buf` por completo; `Closed` si el stream termina antes. No es seguro de cancelar.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), StreamError> {
        read_exact(&mut self.recv, buf).await
    }
}

impl fmt::Debug for VideoReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoReceiver").finish_non_exhaustive()
    }
}
