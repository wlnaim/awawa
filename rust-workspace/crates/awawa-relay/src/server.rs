//! Servidor del relay: QUIC sobre UDP, registro de hosts con TTL, emparejamiento y puente ciego.
//!
//! Concurrencia:
//! - Una tarea por conexion entrante (`run` acepta; cada conexion se atiende en su propia tarea).
//! - Cada conexion abre un unico stream bidireccional de control y lleva una de dos vidas:
//!   * Host (`Register`): inserta un slot en el `DashMap` con un `oneshot` y espera en `select!`
//!     entre el emparejamiento, la caida de su conexion (libera su slot) y el descarte del slot por
//!     caducidad (se le avisa con `Error(Expired)`). Al emparejarse, la tarea del host pasa a ser el
//!     puente: dos tareas copian bytes del stream de control en cada sentido y cualquier fallo cierra
//!     ambas conexiones. Otras dos tareas (una por sentido) aceptan los streams unidireccionales que
//!     abre cada extremo y, por cada uno, abren otro hacia el extremo contrario y copian sus bytes
//!     en una tarea propia. Al terminar el puente se cierran ambas conexiones y se abortan todas,
//!     lo que corta tambien los streams unidireccionales en curso.
//!   * Operador (`Lookup`): cuenta el intento contra el limite por IP, retira el slot (de un solo
//!     uso) y entrega sus streams a la tarea del host por el `oneshot`; luego termina.
//! - Una tarea de limpieza retira cada `sweep_interval` los slots vencidos y el estado de los
//!   limitadores ya recuperados. La caducidad exacta no depende de ella: `take` rechaza un slot
//!   vencido aunque la limpieza aun no haya pasado.
//!
//! Ciego: despues de `Paired` el relay no parsea nada; solo copia bytes. Con la feature `test-support`
//! (o en pruebas unitarias) `RelayConfig::tap` permite observar (solo lectura) lo que se retransmite;
//! en produccion ese gancho no se compila.
//!
//! Streams unidireccionales: QUIC limita a `MAX_VIDEO_STREAMS` (8) los que cada extremo tiene
//! abiertos hacia el relay; el cliente concede el mismo tope al relay. Contrapresion: cada copia usa
//! un bufer fijo de `PIPE_BUFFER` y no lee mas del origen hasta que el destino admite lo leido, asi
//! que si un extremo no lee, el control de flujo de QUIC frena al otro. La memoria por puente queda
//! acotada por las ventanas de quinn (1,25 MB por stream recibido y 10 MB de envio por conexion).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval, timeout};

use crate::identity::RelayIdentity;
use crate::limiter::{IpLimiter, RelayClock};
use crate::protocol::{
    ALPN, ClientRequest, MAX_VIDEO_STREAMS, RelayError, RelayResponse, SLOT_TTL, StreamError,
    is_valid_session_id, read_message, write_message,
};
use crate::slots::{InsertError, SlotTable};

/// Tiempo maximo para cerrar con gracia un stream (esperar a que el extremo reciba lo enviado).
const FINISH_GRACE: Duration = Duration::from_secs(2);

/// Inactividad tras la cual QUIC cierra una conexion (los clientes envian keep-alive).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

const PIPE_BUFFER: usize = 16 * 1024;

/// Sentido de los bytes retransmitidos (solo pruebas).
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeDirection {
    HostToOperator,
    OperatorToHost,
}

/// Observador de solo lectura de los bytes que el relay retransmite (para pruebas de "relay ciego").
#[cfg(any(test, feature = "test-support"))]
pub type ByteTap = Arc<dyn Fn(BridgeDirection, &[u8]) + Send + Sync>;

/// Parametros del relay. `Default` es la configuracion de produccion.
#[derive(Clone)]
pub struct RelayConfig {
    /// Vida de un slot sin emparejar (600 s).
    pub slot_ttl: Duration,
    /// Cada cuanto se limpian slots vencidos y estado de limitadores.
    pub sweep_interval: Duration,
    /// Intentos de `Lookup` por minuto y por IP de origen (5).
    pub lookup_attempts_per_minute: NonZeroU32,
    /// Registros por minuto y por IP de origen. Mas holgado que el de `Lookup` porque un host
    /// legitimo se vuelve a registrar tras cada intento fallido (30).
    pub register_attempts_per_minute: NonZeroU32,
    /// Tope de slots simultaneos en la tabla.
    pub max_slots: usize,
    /// Tiempo maximo para recibir la peticion inicial y para escribir las respuestas de senalizacion.
    pub request_timeout: Duration,
    /// Reloj de los limitadores (manual en pruebas).
    pub clock: RelayClock,
    /// Observador de bytes retransmitidos (solo pruebas).
    #[cfg(any(test, feature = "test-support"))]
    pub tap: Option<ByteTap>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            slot_ttl: SLOT_TTL,
            sweep_interval: Duration::from_secs(5),
            lookup_attempts_per_minute: NonZeroU32::new(5).expect("5 no es cero"),
            register_attempts_per_minute: NonZeroU32::new(30).expect("30 no es cero"),
            max_slots: 10_000,
            request_timeout: Duration::from_secs(10),
            clock: RelayClock::system(),
            #[cfg(any(test, feature = "test-support"))]
            tap: None,
        }
    }
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("RelayConfig");
        s.field("slot_ttl", &self.slot_ttl)
            .field("sweep_interval", &self.sweep_interval)
            .field(
                "lookup_attempts_per_minute",
                &self.lookup_attempts_per_minute,
            )
            .field(
                "register_attempts_per_minute",
                &self.register_attempts_per_minute,
            )
            .field("max_slots", &self.max_slots)
            .field("request_timeout", &self.request_timeout);
        #[cfg(any(test, feature = "test-support"))]
        s.field("tap", &self.tap.is_some());
        s.finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum RelayStartError {
    /// Identidad o configuracion TLS invalida.
    Tls(String),
    /// No se pudo abrir el socket UDP.
    Bind(io::Error),
}

impl fmt::Display for RelayStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "configuracion TLS del relay invalida: {e}"),
            Self::Bind(e) => write!(f, "no se pudo abrir el socket del relay: {e}"),
        }
    }
}

impl std::error::Error for RelayStartError {}

/// Un host esperando: la tarea de su conexion recibe por aqui los streams del operador.
struct PendingHost {
    to_host: oneshot::Sender<OperatorHalf>,
}

/// Extremo del operador entregado a la tarea del host. Mantiene viva su conexion.
struct OperatorHalf {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

struct Shared {
    slots: SlotTable<PendingHost>,
    lookup_limiter: IpLimiter,
    register_limiter: IpLimiter,
    request_timeout: Duration,
    #[cfg(any(test, feature = "test-support"))]
    tap: Option<ByteTap>,
}

pub struct RelayServer {
    endpoint: Endpoint,
    shared: Arc<Shared>,
    sweep_interval: Duration,
}

/// Control del servidor en marcha (cierre y consulta de estado).
#[derive(Clone)]
pub struct RelayHandle {
    endpoint: Endpoint,
    shared: Arc<Shared>,
}

impl RelayHandle {
    /// Cierra el endpoint: se dejan de aceptar conexiones y `run` termina.
    pub fn shutdown(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
    }

    /// Slots de hosts en espera (incluye los vencidos que la limpieza aun no retiro).
    pub fn waiting_slots(&self) -> usize {
        self.shared.slots.len()
    }
}

impl RelayServer {
    /// Abre el socket UDP en `addr` (usar puerto 0 para uno efimero). Debe llamarse dentro de un
    /// runtime de tokio.
    pub fn bind(
        addr: SocketAddr,
        identity: &RelayIdentity,
        config: RelayConfig,
    ) -> Result<Self, RelayStartError> {
        let server_config = build_server_config(identity)?;
        let endpoint = Endpoint::server(server_config, addr).map_err(RelayStartError::Bind)?;
        let shared = Arc::new(Shared {
            slots: SlotTable::new(config.slot_ttl, config.max_slots),
            lookup_limiter: IpLimiter::per_minute(
                config.lookup_attempts_per_minute,
                config.clock.clone(),
            ),
            register_limiter: IpLimiter::per_minute(
                config.register_attempts_per_minute,
                config.clock.clone(),
            ),
            request_timeout: config.request_timeout,
            #[cfg(any(test, feature = "test-support"))]
            tap: config.tap,
        });
        Ok(Self {
            endpoint,
            shared,
            sweep_interval: config.sweep_interval,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn handle(&self) -> RelayHandle {
        RelayHandle {
            endpoint: self.endpoint.clone(),
            shared: self.shared.clone(),
        }
    }

    /// Atiende conexiones hasta que `RelayHandle::shutdown` cierre el endpoint.
    pub async fn run(self) {
        let sweeper = tokio::spawn(sweep_loop(self.shared.clone(), self.sweep_interval));
        while let Some(incoming) = self.endpoint.accept().await {
            let shared = self.shared.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => handle_connection(shared, conn).await,
                    Err(e) => tracing::debug!(error = %e, "handshake QUIC fallido"),
                }
            });
        }
        sweeper.abort();
    }
}

fn build_server_config(identity: &RelayIdentity) -> Result<quinn::ServerConfig, RelayStartError> {
    let tls_err = |e: &dyn fmt::Display| RelayStartError::Tls(e.to_string());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = CertificateDer::from(identity.cert_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_pkcs8_der().to_vec()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| tls_err(&e))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| tls_err(&e))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(tls).map_err(|e| tls_err(&e))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));

    // Un unico stream bidireccional (control) por conexion y hasta `MAX_VIDEO_STREAMS`
    // unidireccionales simultaneos (video), que el relay solo atiende tras el emparejamiento.
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_VIDEO_STREAMS))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(IDLE_TIMEOUT).expect("30 s cabe en un IdleTimeout"),
        ));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn sweep_loop(shared: Arc<Shared>, period: Duration) {
    let mut ticker = interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let removed = shared.slots.sweep(Instant::now());
        if removed > 0 {
            tracing::debug!(removed, "slots vencidos retirados");
        }
        shared.lookup_limiter.prune();
        shared.register_limiter.prune();
    }
}

fn close(conn: &Connection, code: u32) {
    conn.close(VarInt::from_u32(code), b"");
}

/// Responde con un error de senalizacion, cierra el stream con gracia y la conexion.
async fn reject(conn: Connection, mut send: SendStream, error: RelayError, to: Duration) {
    let _ = timeout(to, write_message(&mut send, &RelayResponse::Error(error))).await;
    finish_gracefully(&mut send).await;
    close(&conn, 0);
}

async fn finish_gracefully(send: &mut SendStream) {
    let _ = send.finish();
    let _ = timeout(FINISH_GRACE, send.stopped()).await;
}

async fn handle_connection(shared: Arc<Shared>, conn: Connection) {
    let ip = conn.remote_address().ip();
    let to = shared.request_timeout;
    let Ok(Ok((send, mut recv))) = timeout(to, conn.accept_bi()).await else {
        close(&conn, 1);
        return;
    };
    let request = match timeout(to, read_message::<ClientRequest>(&mut recv)).await {
        Ok(Ok(request)) => request,
        Ok(Err(StreamError::Framing(_) | StreamError::Wire(_))) => {
            reject(conn, send, RelayError::MalformedRequest, to).await;
            return;
        }
        Ok(Err(_)) | Err(_) => {
            close(&conn, 1);
            return;
        }
    };
    match request {
        ClientRequest::Register { session_id } => {
            handle_register(&shared, conn, send, recv, ip, session_id).await;
        }
        ClientRequest::Lookup { session_id } => {
            handle_lookup(&shared, conn, send, recv, ip, session_id).await;
        }
    }
}

async fn handle_register(
    shared: &Shared,
    conn: Connection,
    mut send: SendStream,
    recv: RecvStream,
    ip: std::net::IpAddr,
    session_id: u32,
) {
    let to = shared.request_timeout;
    if !shared.register_limiter.check(ip) {
        tracing::warn!(%ip, "registro rechazado por limite de tasa");
        return reject(conn, send, RelayError::RateLimited, to).await;
    }
    if !is_valid_session_id(session_id) {
        return reject(conn, send, RelayError::InvalidSessionId, to).await;
    }
    let (to_host, rx) = oneshot::channel();
    let nonce = match shared
        .slots
        .insert(session_id, PendingHost { to_host }, Instant::now())
    {
        Ok(nonce) => nonce,
        Err(InsertError::Taken) => {
            return reject(conn, send, RelayError::SessionIdTaken, to).await;
        }
        Err(InsertError::Full) => {
            tracing::warn!("tabla de slots llena");
            return reject(conn, send, RelayError::ServerBusy, to).await;
        }
    };
    let registered = RelayResponse::Registered {
        ttl_secs: u32::try_from(shared.slots.ttl().as_secs()).unwrap_or(u32::MAX),
    };
    if !matches!(
        timeout(to, write_message(&mut send, &registered)).await,
        Ok(Ok(()))
    ) {
        shared.slots.remove_matching(session_id, nonce);
        close(&conn, 1);
        return;
    }
    tracing::debug!(%ip, "host registrado");

    let operator = tokio::select! {
        paired = rx => paired.ok(),
        _ = conn.closed() => {
            shared.slots.remove_matching(session_id, nonce);
            tracing::debug!(%ip, "host desconectado antes de emparejar");
            return;
        }
    };
    match operator {
        // El slot se descarto por caducidad sin emparejar.
        None => reject(conn, send, RelayError::Expired, to).await,
        Some(operator) => bridge(shared, conn, send, recv, operator).await,
    }
}

async fn handle_lookup(
    shared: &Shared,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    ip: std::net::IpAddr,
    session_id: u32,
) {
    let to = shared.request_timeout;
    // Todo intento cuenta, exista o no el ID: limita tambien la enumeracion de IDs.
    if !shared.lookup_limiter.check(ip) {
        tracing::warn!(%ip, "lookup rechazado por limite de tasa");
        return reject(conn, send, RelayError::RateLimited, to).await;
    }
    if !is_valid_session_id(session_id) {
        return reject(conn, send, RelayError::InvalidSessionId, to).await;
    }
    let Some(pending) = shared.slots.take(session_id, Instant::now()) else {
        return reject(conn, send, RelayError::NotFound, to).await;
    };
    let half = OperatorHalf { conn, send, recv };
    if let Err(half) = pending.to_host.send(half) {
        // El host se cayo entre el `take` y la entrega.
        reject(half.conn, half.send, RelayError::NotFound, to).await;
    }
    // Si se entrego, la tarea del host es duena de ambos extremos y avisa `Paired`.
}

/// Anuncia `Paired` a ambos extremos y copia bytes en los dos sentidos sin interpretarlos: el stream
/// de control y cada stream unidireccional que abra cualquiera de los dos extremos.
async fn bridge(
    shared: &Shared,
    host_conn: Connection,
    mut host_send: SendStream,
    host_recv: RecvStream,
    operator: OperatorHalf,
) {
    let OperatorHalf {
        conn: operator_conn,
        send: mut operator_send,
        recv: operator_recv,
    } = operator;
    let announce = async {
        write_message(&mut host_send, &RelayResponse::Paired).await?;
        write_message(&mut operator_send, &RelayResponse::Paired).await
    };
    if !matches!(timeout(shared.request_timeout, announce).await, Ok(Ok(()))) {
        close(&host_conn, 1);
        close(&operator_conn, 1);
        return;
    }
    tracing::debug!("sesion emparejada");

    #[cfg(any(test, feature = "test-support"))]
    let tap = shared.tap.clone();
    let uni_to_operator = tokio::spawn(bridge_uni(
        host_conn.clone(),
        operator_conn.clone(),
        #[cfg(any(test, feature = "test-support"))]
        BridgeDirection::HostToOperator,
        #[cfg(any(test, feature = "test-support"))]
        tap.clone(),
    ));
    let uni_to_host = tokio::spawn(bridge_uni(
        operator_conn.clone(),
        host_conn.clone(),
        #[cfg(any(test, feature = "test-support"))]
        BridgeDirection::OperatorToHost,
        #[cfg(any(test, feature = "test-support"))]
        tap.clone(),
    ));
    let mut to_operator = tokio::spawn(pipe(
        host_recv,
        operator_send,
        #[cfg(any(test, feature = "test-support"))]
        BridgeDirection::HostToOperator,
        #[cfg(any(test, feature = "test-support"))]
        tap.clone(),
    ));
    let mut to_host = tokio::spawn(pipe(
        operator_recv,
        host_send,
        #[cfg(any(test, feature = "test-support"))]
        BridgeDirection::OperatorToHost,
        #[cfg(any(test, feature = "test-support"))]
        tap,
    ));
    // Un sentido puede terminar limpio (EOF) mientras el otro sigue; un fallo en cualquiera cierra todo.
    let failed = tokio::select! {
        r = &mut to_operator => !pipe_ok(r) || !pipe_ok((&mut to_host).await),
        r = &mut to_host => !pipe_ok(r) || !pipe_ok((&mut to_operator).await),
    };
    // Primero se cierran las conexiones: soltar un `SendStream` de una conexion abierta lo
    // finalizaria con gracia y el otro extremo veria un final limpio en un stream cortado.
    let code = u32::from(failed);
    close(&host_conn, code);
    close(&operator_conn, code);
    to_operator.abort();
    to_host.abort();
    uni_to_operator.abort();
    uni_to_host.abort();
}

/// Acepta los streams unidireccionales que abre `from` y, por cada uno, abre otro hacia `to` y copia
/// sus bytes en una tarea propia. Cuando cualquiera de las dos conexiones se cierra deja de aceptar
/// y espera a que las copias en curso fallen (cada una reinicia su destino); si `bridge` la aborta,
/// se abortan tambien las copias. Abrir hacia `to` espera si el otro extremo ya tiene
/// `MAX_VIDEO_STREAMS` abiertos; mientras tanto no se aceptan mas de `from`.
async fn bridge_uni(
    from: Connection,
    to: Connection,
    #[cfg(any(test, feature = "test-support"))] direction: BridgeDirection,
    #[cfg(any(test, feature = "test-support"))] tap: Option<ByteTap>,
) {
    let mut copies = JoinSet::new();
    loop {
        let Ok(recv) = from.accept_uni().await else {
            break;
        };
        let Ok(send) = to.open_uni().await else {
            break;
        };
        copies.spawn(pipe(
            recv,
            send,
            #[cfg(any(test, feature = "test-support"))]
            direction,
            #[cfg(any(test, feature = "test-support"))]
            tap.clone(),
        ));
        while copies.try_join_next().is_some() {}
    }
    while copies.join_next().await.is_some() {}
}

fn pipe_ok(result: Result<Result<(), StreamError>, tokio::task::JoinError>) -> bool {
    matches!(result, Ok(Ok(())))
}

/// Copia bytes de `recv` a `send` hasta EOF y propaga el cierre ordenado. Si el origen se corta,
/// el destino se reinicia (no se presenta como un final limpio).
async fn pipe(
    mut recv: RecvStream,
    mut send: SendStream,
    #[cfg(any(test, feature = "test-support"))] direction: BridgeDirection,
    #[cfg(any(test, feature = "test-support"))] tap: Option<ByteTap>,
) -> Result<(), StreamError> {
    let mut buf = vec![0u8; PIPE_BUFFER];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                #[cfg(any(test, feature = "test-support"))]
                if let Some(tap) = &tap {
                    tap(direction, &buf[..n]);
                }
                send.write_all(&buf[..n])
                    .await
                    .map_err(|e| StreamError::Io(e.to_string()))?;
            }
            Ok(None) => break,
            Err(e) => {
                let _ = send.reset(VarInt::from_u32(0));
                return Err(StreamError::Io(e.to_string()));
            }
        }
    }
    finish_gracefully(&mut send).await;
    Ok(())
}
