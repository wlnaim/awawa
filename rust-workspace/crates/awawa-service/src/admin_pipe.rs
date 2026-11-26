//! Pipe de administracion del servicio: `awawa-admin` entrega la contrasena desatendida al servicio y
//! SOLO el servicio deriva el verificador, lo persiste y audita.
//!
//! # Pipe y protocolo
//! - Nombre fijo [`ADMIN_PIPE_NAME`] (`\\.\pipe\Awawa.admin`), DACL protegida
//!   [`ADMIN_PIPE_SDDL`] (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), `FILE_FLAG_FIRST_PIPE_INSTANCE`,
//!   `max_instances = 1` y `PIPE_REJECT_REMOTE_CLIENTS`. Una unica instancia que se reutiliza
//!   (`disconnect` + `connect`): nunca hay un instante sin instancia en el que alguien pueda plantar el nombre.
//! - Trama: `[len u32 LE][cuerpo postcard]`, con `1 <= len <= `[`MAX_ADMIN_FRAME`]; el tope se aplica ANTES
//!   de reservar el cuerpo. Una operacion por conexion: peticion ([`AdminRequest`]) y respuesta
//!   ([`AdminResponse`]).
//! - La contrasena viaja en un [`SecretString`] (`Zeroizing<String>`) y los buffers de trama se borran al
//!   soltarse; nunca se registra ni se audita (solo la generacion). Limitacion: las copias transitorias del
//!   serializador (`Vec` que crece) no se pueden borrar desde aqui.
//!
//! # Verificacion del cliente (ademas de la DACL)
//! Tras leer la longitud (`ImpersonateNamedPipeClient` exige haber leido) y antes de leer el cuerpo, el
//! servidor suplanta al cliente, abre su token con `OpenThreadToken(open_as_self = TRUE)` y revierte de
//! inmediato (`RevertToSelf`). Ya sin suplantar y con ese manejador explicito comprueba con
//! `CheckTokenMembership(token, BUILTIN\Administrators)` que el grupo esta habilitado (token ELEVADO: un
//! administrador sin elevar lo tiene "deny-only") y toma la cuenta del token (`TokenUser` +
//! `LookupAccountSidW`), nunca del mensaje. Con un cliente de nivel de identificacion y un servicio sin
//! `SeImpersonatePrivilege`, `LookupAccountSidW` bajo suplantacion falla (5) y deja el hilo en un estado en
//! que `CheckTokenMembership(NULL)` falla (1346): por eso ambas consultas se hacen tras revertir. Un cliente
//! que no es administrador se rechaza y se audita (`auth_failed`, origen `admin_pipe`).
//!
//! # Cliente
//! [`request_at`] abre la pipe con `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (el servicio puede
//! consultar el token pero no actuar como el administrador) y, antes de escribir nada, comprueba que el DUENO
//! del objeto pipe (`GetSecurityInfo`, `OWNER_SECURITY_INFORMATION`) es SYSTEM o BUILTIN\Administrators
//! ([`TRUSTED_PIPE_OWNERS`]): si el servicio no corre, un usuario sin privilegios podria crear la pipe y
//! recibir la contrasena, y su pipe tiene como dueno su propio SID. No se usa el PID del servidor
//! (`GetNamedPipeServerProcessId`): es el del creador de la instancia, no el de quien la sostiene, y puede
//! reutilizarse. No hay respaldo de escritura directa.
//!
//! # Arranque
//! Si al arrancar el nombre ya existe (alguien lo planto o una instancia anterior sigue viva), el servidor no
//! se rinde: reintenta cada [`ADMIN_PIPE_RETRY`] hasta crear la primera instancia y atiende la parada durante
//! los reintentos. El hecho queda en stderr (no hay variante de auditoria para ello).

use core::ffi::c_void;
use std::io;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{PoisonError, mpsc};
use std::time::{Duration, Instant};

use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, AuditSinkError};
use awawa_protocol::unattended::PasswordKdf;
use awawa_protocol::{
    UNATTENDED_PASSWORD_MAX_LEN, UNATTENDED_PASSWORD_MIN_LEN, decode_message, encode_message,
};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use zeroize::Zeroizing;

use crate::admin_ops::AdminOps;
use crate::dpapi_store::{ProtectedSecurity, VerifierFileStore};
use crate::identity::{ThreadToken, handle_owner_sid_string};
use crate::unattended_net::SharedAudit;
use crate::winutil::unix_ms_now;

/// Nombre fijo de la pipe de administracion.
pub const ADMIN_PIPE_NAME: &str = r"\\.\pipe\Awawa.admin";
/// DACL de la pipe: solo SYSTEM y Administradores (control total).
pub const ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
/// Duenos aceptados del objeto pipe en el cliente: LocalSystem y BUILTIN\Administrators.
pub const TRUSTED_PIPE_OWNERS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];
/// Espera entre intentos de crear la pipe cuando el nombre ya existe.
pub const ADMIN_PIPE_RETRY: Duration = Duration::from_secs(5);
/// Tope del cuerpo de una trama (la contrasena admite hasta 128 caracteres, 4 bytes cada uno).
pub const MAX_ADMIN_FRAME: usize = 1024;
/// Plazo de cada lectura del servidor y de la espera de cierre del cliente.
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// Espera maxima del cliente a que la pipe ocupada quede libre.
const CONNECT_WAIT: Duration = Duration::from_secs(5);

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_PIPE_BUSY: i32 = 231;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// Contrasena en transito: se borra al soltarse y no aparece en `Debug`.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(password: Zeroizing<String>) -> Self {
        Self(password)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;
        impl Visitor<'_> for SecretVisitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("una cadena")
            }

            // postcard entrega la cadena prestada del buffer: una sola copia, ya en `Zeroizing`.
            fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretString, E> {
                Ok(SecretString(Zeroizing::new(v.to_owned())))
            }
        }
        deserializer.deserialize_str(SecretVisitor)
    }
}

/// Peticion de administracion (una por conexion).
#[derive(Debug, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Primera configuracion (o tras revocar).
    Set { password: SecretString },
    /// Cambio de la contrasena activa.
    Change { password: SecretString },
    /// Revocar el acceso desatendido.
    Revoke,
}

/// Respuesta del servicio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminResponse {
    /// Operacion aplicada y persistida; generacion resultante.
    Done { generation: u32 },
    /// Operacion rechazada o fallida (texto para el administrador, sin secretos).
    Error { message: String },
}

/// Resultado de verificar al cliente conectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCheck {
    /// Administrador con token elevado; `account` sale de su token.
    Administrator { account: String },
    /// No es administrador (o no se pudo comprobar): se rechaza y se audita con `account`.
    Denied { account: String },
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "plazo de lectura agotado")
}

/// Valida la longitud declarada de una trama antes de reservar su cuerpo.
fn check_len(len: usize) -> io::Result<usize> {
    if len == 0 || len > MAX_ADMIN_FRAME {
        return Err(invalid("longitud de trama fuera de tope"));
    }
    Ok(len)
}

/// Trama completa `[len][cuerpo]`; el buffer se borra al soltarse (la peticion lleva la contrasena).
fn frame_bytes(body: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    check_len(body.len())?;
    let mut buf = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(body);
    Ok(buf)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let frame = frame_bytes(body)?;
    w.write_all(&frame).await?;
    w.flush().await
}

async fn read_len<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<usize> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    check_len(u32::from_le_bytes(len) as usize)
}

async fn read_body<R: AsyncRead + Unpin>(r: &mut R, len: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body[..]).await?;
    Ok(body)
}

/// Espera (acotada) a que el cliente cierre: asegura que leyo la respuesta antes de desconectar.
async fn wait_for_close<R: AsyncRead + Unpin>(r: &mut R) {
    let mut sink = Zeroizing::new([0u8; 256]);
    let _ = tokio::time::timeout(IO_TIMEOUT, async {
        while matches!(r.read(&mut sink[..]).await, Ok(n) if n > 0) {}
    })
    .await;
}

/// Adaptador que toma el bloqueo de la auditoria compartida solo durante cada escritura.
struct SharedSink(SharedAudit);

impl AuditSink for SharedSink {
    fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_record(record)
    }
}

/// Logica del servidor, independiente del transporte: verifica al cliente, decodifica y aplica la
/// operacion con [`AdminOps`] (KDF + almacen DPAPI con validacion de ubicacion + auditoria + `admin.lock`).
pub struct AdminService {
    store: VerifierFileStore,
    kdf: Box<dyn PasswordKdf + Send>,
    audit: SharedAudit,
}

impl AdminService {
    pub fn new(
        store: VerifierFileStore,
        kdf: Box<dyn PasswordKdf + Send>,
        audit: SharedAudit,
    ) -> Self {
        Self { store, kdf, audit }
    }

    /// Atiende UNA conexion. `verify` se invoca tras leer la longitud y antes del cuerpo; un mensaje mal
    /// formado recibe una respuesta de error y no afecta a las demas conexiones. `Err` solo para fallos del
    /// transporte o tramas fuera de tope (se cierra sin responder).
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        verify: impl FnOnce() -> ClientCheck,
    ) -> io::Result<()> {
        let len = tokio::time::timeout(IO_TIMEOUT, read_len(stream))
            .await
            .map_err(|_| timed_out())??;
        let account = match verify() {
            ClientCheck::Administrator { account } => account,
            ClientCheck::Denied { account } => {
                let record = AuditRecord::new(unix_ms_now(), AuditEvent::AuthFailed, &account)
                    .with_source("admin_pipe");
                let _ = SharedSink(self.audit.clone()).write_record(&record);
                let denied = AdminResponse::Error {
                    message: "acceso denegado: se requiere un administrador con token elevado"
                        .into(),
                };
                self.respond(stream, &denied).await?;
                return Ok(());
            }
        };
        let body = tokio::time::timeout(IO_TIMEOUT, read_body(stream, len))
            .await
            .map_err(|_| timed_out())??;
        let response = match decode_message::<AdminRequest>(&body) {
            Ok(request) => self.execute(request, &account),
            Err(_) => AdminResponse::Error {
                message: "solicitud mal formada".into(),
            },
        };
        self.respond(stream, &response).await
    }

    async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        response: &AdminResponse,
    ) -> io::Result<()> {
        let bytes = encode_message(response).map_err(|_| invalid("respuesta no serializable"))?;
        write_frame(stream, &bytes).await?;
        wait_for_close(stream).await;
        Ok(())
    }

    fn execute(&self, request: AdminRequest, account: &str) -> AdminResponse {
        let operator = format!("admin:{account}");
        let mut sink = SharedSink(self.audit.clone());
        let mut ops = AdminOps {
            store: &self.store,
            kdf: self.kdf.as_ref(),
            sink: &mut sink,
            operator: &operator,
        };
        let result = match &request {
            AdminRequest::Set { password } => ops.set_password(password.expose()),
            AdminRequest::Change { password } => ops.change_password(password.expose()),
            AdminRequest::Revoke => ops.revoke_password(),
        };
        match result {
            Ok(generation) => AdminResponse::Done { generation },
            Err(e) => AdminResponse::Error {
                message: e.to_string(),
            },
        }
    }
}

// ---------------------------------------------------------------- pipe real

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ImpersonateNamedPipeClient(pipe: *mut c_void) -> i32;
    fn RevertToSelf() -> i32;
}

/// Revierte la suplantacion del hilo al soltarse (tambien ante `panic`).
struct Impersonation;

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: sin argumentos; revierte la suplantacion del hilo actual.
        unsafe { RevertToSelf() };
    }
}

/// Suplanta al cliente de `pipe` (ya leyo al menos una vez), abre su token y revierte de inmediato; despues,
/// sin suplantar y con el manejador explicito, comprueba su pertenencia elevada a BUILTIN\Administrators y
/// toma su cuenta del token. Revierte siempre. Sin `await` mientras suplanta.
fn verify_pipe_client(pipe: RawHandle) -> ClientCheck {
    let unknown = |code: u32| ClientCheck::Denied {
        account: format!("desconocido(Win32={code})"),
    };
    // SAFETY: `pipe` es el manejador de una instancia conectada y vigente del llamador.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return unknown(io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
    }
    let revert = Impersonation;
    let token = ThreadToken::open();
    drop(revert);
    let token = match token {
        Ok(token) => token,
        Err(code) => return unknown(code),
    };
    let account = token
        .account_name()
        .unwrap_or_else(|code| format!("desconocido(Win32={code})"));
    if token.is_administrator() {
        ClientCheck::Administrator { account }
    } else {
        ClientCheck::Denied { account }
    }
}

/// Crea la unica instancia de la pipe con `sddl` y el nombre `name` (la primera: nadie la planto antes).
/// Debe llamarse dentro de un runtime de tokio.
pub fn create_admin_pipe(name: &str, sddl: &str) -> io::Result<NamedPipeServer> {
    let security =
        ProtectedSecurity::from_sddl(sddl).map_err(|e| io::Error::other(e.to_string()))?;
    let mut attrs = security.attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .pipe_mode(PipeMode::Byte)
        .in_buffer_size(4096)
        .out_buffer_size(4096);
    // SAFETY: `attrs` es un SECURITY_ATTRIBUTES valido que apunta al descriptor de `security`,
    // vivo durante toda la llamada (la pipe copia el descriptor al crearse).
    let server = unsafe {
        options.create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>())
    }?;
    drop(security);
    Ok(server)
}

async fn serve_loop(
    mut server: NamedPipeServer,
    service: AdminService,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            connected = server.connect() => {
                if connected.is_err() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = server.disconnect();
                    continue;
                }
            }
        }
        let raw = server.as_raw_handle();
        let _ = service.serve(&mut server, || verify_pipe_client(raw)).await;
        let _ = server.disconnect();
    }
}

/// Servidor de administracion en marcha (hilo propio con runtime propio: independiente de la red).
pub struct AdminPipeHandle {
    shutdown: tokio::sync::oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl AdminPipeHandle {
    /// Detiene el servidor: una operacion en curso termina (con plazos acotados) y se une el hilo.
    pub fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.thread.join();
    }
}

/// Arranca el servidor en `name` con `sddl`. Si la pipe no se puede crear (por ejemplo, el nombre ya existe:
/// no se acepta una pipe plantada), el hilo reintenta cada `retry` hasta lograrlo o hasta que se detenga.
/// `Err` solo si no se pudo lanzar el hilo o su runtime.
pub fn spawn_admin_pipe_at(
    name: &str,
    sddl: &str,
    service: AdminService,
    retry: Duration,
) -> io::Result<AdminPipeHandle> {
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel();
    let (name, sddl) = (name.to_owned(), sddl.to_owned());
    let thread = std::thread::Builder::new()
        .name("service-admin-pipe".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let mut announced = false;
                let server = loop {
                    match create_admin_pipe(&name, &sddl) {
                        Ok(server) => {
                            if announced {
                                eprintln!("awawa-service: pipe de administracion creada");
                            }
                            break server;
                        }
                        Err(e) => {
                            if !announced {
                                eprintln!(
                                    "awawa-service: pipe de administracion no disponible ({e}); se reintenta cada {} s",
                                    retry.as_secs_f32()
                                );
                                announced = true;
                                let _ = ready_tx.send(());
                            }
                            tokio::select! {
                                _ = &mut shutdown_rx => return,
                                _ = tokio::time::sleep(retry) => {}
                            }
                        }
                    }
                };
                if !announced {
                    let _ = ready_tx.send(());
                }
                serve_loop(server, service, shutdown_rx).await;
            });
        })?;
    match ready_rx.recv() {
        Ok(()) => Ok(AdminPipeHandle { shutdown, thread }),
        Err(_) => {
            let _ = thread.join();
            Err(io::Error::other("el servidor de administracion no arranco"))
        }
    }
}

/// Arranca el servidor de produccion ([`ADMIN_PIPE_NAME`] con [`ADMIN_PIPE_SDDL`], reintento [`ADMIN_PIPE_RETRY`]).
pub fn spawn_admin_pipe(service: AdminService) -> io::Result<AdminPipeHandle> {
    spawn_admin_pipe_at(ADMIN_PIPE_NAME, ADMIN_PIPE_SDDL, service, ADMIN_PIPE_RETRY)
}

// ---------------------------------------------------------------- cliente

/// Fallos del cliente de la pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// La pipe no existe: el servicio no esta en ejecucion.
    NotRunning,
    /// La pipe sigue ocupada tras la espera.
    Busy,
    /// El proceso que sirve la pipe no es el esperado: no se envia la contrasena.
    ServerNotTrusted(String),
    Io(String),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotRunning => write!(
                f,
                "el servicio Awawa no esta en ejecucion (no existe {ADMIN_PIPE_NAME}); inicielo e intente de nuevo"
            ),
            Self::Busy => write!(f, "el servicio esta ocupado atendiendo otra operacion"),
            Self::ServerNotTrusted(why) => {
                write!(f, "la pipe no la sirve el servicio esperado ({why})")
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Pre-validacion de la politica (12-128 caracteres) en el cliente; el servicio la aplica de todos modos.
pub fn password_len_ok(password: &str) -> bool {
    (UNATTENDED_PASSWORD_MIN_LEN..=UNATTENDED_PASSWORD_MAX_LEN).contains(&password.chars().count())
}

fn open_pipe(name: &str) -> Result<std::fs::File, ClientError> {
    let started = Instant::now();
    loop {
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name);
        match opened {
            Ok(file) => return Ok(file),
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(ClientError::NotRunning);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if started.elapsed() >= CONNECT_WAIT {
                    return Err(ClientError::Busy);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(ClientError::Io(
                    "acceso denegado a la pipe de administracion: ejecute desde una consola elevada"
                        .into(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Envia `request` por la pipe `name` y devuelve la respuesta. Antes de escribir nada comprueba que el dueno
/// del objeto pipe es uno de `trusted_owners` (produccion: [`TRUSTED_PIPE_OWNERS`]).
pub fn request_at(
    name: &str,
    trusted_owners: &[&str],
    request: &AdminRequest,
) -> Result<AdminResponse, ClientError> {
    let mut pipe = open_pipe(name)?;
    match handle_owner_sid_string(&pipe) {
        Ok(sid) if trusted_owners.contains(&sid.as_str()) => {}
        Ok(sid) => {
            return Err(ClientError::ServerNotTrusted(format!(
                "dueno de la pipe {sid}"
            )));
        }
        Err(code) => {
            return Err(ClientError::ServerNotTrusted(format!(
                "no se pudo leer el dueno de la pipe (Win32={code})"
            )));
        }
    }

    let body = Zeroizing::new(
        encode_message(request).map_err(|_| ClientError::Io("peticion no serializable".into()))?,
    );
    let frame = frame_bytes(&body)?;
    pipe.write_all(&frame)?;
    pipe.flush()?;

    let mut len = [0u8; 4];
    pipe.read_exact(&mut len)?;
    let len = check_len(u32::from_le_bytes(len) as usize)?;
    let mut response = vec![0u8; len];
    pipe.read_exact(&mut response)?;
    decode_message(&response).map_err(|_| ClientError::Io("respuesta mal formada".into()))
}

/// Envia `request` al servicio de produccion.
pub fn request(request: &AdminRequest) -> Result<AdminResponse, ClientError> {
    request_at(ADMIN_PIPE_NAME, &TRUSTED_PIPE_OWNERS, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{current_account_name, is_administrator};
    use crate::kdf_argon2::ServiceKdf;
    use crate::testutil::{TempDir, current_sid, safe_dir, test_file_dacl, test_policy};
    use awawa_protocol::audit::MemoryAuditSink;
    use std::sync::{Arc, Mutex};

    const FIRST: &str = "clave-inicial-segura";
    const SECOND: &str = "clave-nueva-segura!!";

    fn secret(text: &str) -> SecretString {
        SecretString::new(Zeroizing::new(text.to_owned()))
    }

    struct Fixture {
        _tmp: TempDir,
        service: AdminService,
        store: VerifierFileStore,
        audit: Arc<Mutex<MemoryAuditSink>>,
    }

    fn fixture(tag: &str) -> Fixture {
        let tmp = TempDir::new(tag);
        let dir = safe_dir(&tmp);
        let store = VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        );
        let audit = Arc::new(Mutex::new(MemoryAuditSink::new()));
        let shared: SharedAudit = audit.clone();
        let service = AdminService::new(store.clone(), Box::new(ServiceKdf), shared);
        Fixture {
            _tmp: tmp,
            service,
            store,
            audit,
        }
    }

    impl Fixture {
        fn lines(&self) -> Vec<String> {
            self.audit.lock().unwrap().lines.clone()
        }
    }

    fn admin(account: &str) -> ClientCheck {
        ClientCheck::Administrator {
            account: account.into(),
        }
    }

    /// Transporte simulado: el cliente envia `request` en bruto y lee la respuesta.
    async fn exchange_raw(
        service: &AdminService,
        check: ClientCheck,
        raw: &[u8],
    ) -> (io::Result<()>, Option<AdminResponse>) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let raw = raw.to_vec();
        let client_side = async move {
            client.write_all(&raw).await.unwrap();
            let response = match tokio::time::timeout(Duration::from_secs(5), async {
                let len = read_len(&mut client).await?;
                let body = read_body(&mut client, len).await?;
                decode_message::<AdminResponse>(&body).map_err(|_| invalid("respuesta"))
            })
            .await
            {
                Ok(Ok(r)) => Some(r),
                _ => None,
            };
            drop(client);
            response
        };
        let (served, response) = tokio::join!(service.serve(&mut server, || check), client_side);
        (served, response)
    }

    async fn exchange(
        service: &AdminService,
        check: ClientCheck,
        request: &AdminRequest,
    ) -> AdminResponse {
        let body = encode_message(request).unwrap();
        let frame = frame_bytes(&body).unwrap();
        let (served, response) = exchange_raw(service, check, &frame).await;
        served.unwrap();
        response.expect("respuesta")
    }

    #[tokio::test]
    async fn no_administrador_se_rechaza_y_se_audita_sin_tocar_el_almacen() {
        let fx = fixture("admin-pipe-denied");
        let request = AdminRequest::Set {
            password: secret(FIRST),
        };
        let response = exchange(
            &fx.service,
            ClientCheck::Denied {
                account: "PC-intruso".into(),
            },
            &request,
        )
        .await;
        assert!(matches!(response, AdminResponse::Error { .. }));
        assert!(!fx.store.path().exists());
        let lines = fx.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("auth_failed") && lines[0].contains("PC-intruso"));
        assert!(lines[0].contains("admin_pipe"));
        assert!(!lines[0].contains(FIRST));
    }

    #[tokio::test]
    async fn set_change_revoke_cambian_la_generacion_sin_secretos_en_auditoria() {
        let fx = fixture("admin-pipe-flow");
        let who = admin("PC-ana");
        let set = AdminRequest::Set {
            password: secret(FIRST),
        };
        let change = AdminRequest::Change {
            password: secret(SECOND),
        };
        assert_eq!(
            exchange(&fx.service, who.clone(), &set).await,
            AdminResponse::Done { generation: 1 }
        );
        // Un segundo `Set` con contrasena activa se rechaza sin cambiar la generacion.
        let again = exchange(&fx.service, who.clone(), &set).await;
        assert!(
            matches!(&again, AdminResponse::Error { message } if message.contains("ya existe"))
        );
        assert_eq!(
            exchange(&fx.service, who.clone(), &change).await,
            AdminResponse::Done { generation: 2 }
        );
        assert_eq!(
            exchange(&fx.service, who.clone(), &AdminRequest::Revoke).await,
            AdminResponse::Done { generation: 3 }
        );
        assert_eq!(
            exchange(&fx.service, who, &set).await,
            AdminResponse::Done { generation: 4 }
        );
        let lines = fx.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        let all = lines.join("\n");
        assert!(!all.contains(FIRST) && !all.contains(SECOND));
        assert!(all.contains("password_configured") && all.contains("password_rotated"));
        assert!(all.contains("password_revoked"));
        // La identidad auditada es la del token que entrego el verificador.
        assert!(all.contains("admin:PC-ana"));
        // El verificador persistido quedo configurado por el servicio (generacion vigente).
        assert_eq!(fx.store.load().unwrap().map(|r| r.generation()), Some(4),);
    }

    #[tokio::test]
    async fn la_politica_de_contrasena_la_aplica_el_servicio() {
        let fx = fixture("admin-pipe-policy");
        for bad in ["corta", &"x".repeat(129)] {
            let response = exchange(
                &fx.service,
                admin("PC-ana"),
                &AdminRequest::Set {
                    password: secret(bad),
                },
            )
            .await;
            match response {
                AdminResponse::Error { message } => {
                    assert!(message.contains("contrasena"), "{message}");
                    assert!(!message.contains(bad));
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(!fx.store.path().exists());
        assert!(fx.lines().is_empty());
        assert!(password_len_ok(&"x".repeat(12)) && password_len_ok(&"x".repeat(128)));
        assert!(!password_len_ok("x") && !password_len_ok(&"x".repeat(129)));
    }

    #[tokio::test]
    async fn trama_mayor_al_tope_o_vacia_se_rechaza_antes_de_reservar() {
        let fx = fixture("admin-pipe-cap");
        // Solo la cabecera: el servidor decide sin esperar un cuerpo que nunca llega.
        for declared in [(MAX_ADMIN_FRAME as u32) + 1, u32::MAX, 0] {
            let verified = std::cell::Cell::new(false);
            let (mut client, mut server) = tokio::io::duplex(64);
            client.write_all(&declared.to_le_bytes()).await.unwrap();
            let served = tokio::time::timeout(
                Duration::from_secs(2),
                fx.service.serve(&mut server, || {
                    verified.set(true);
                    admin("PC-ana")
                }),
            )
            .await
            .expect("no espera el cuerpo");
            assert!(served.is_err(), "{declared}");
            assert!(
                !verified.get(),
                "no se verifica ni se lee una trama invalida"
            );
        }
        assert!(fx.lines().is_empty());
        assert_eq!(
            check_len(MAX_ADMIN_FRAME).unwrap(),
            MAX_ADMIN_FRAME,
            "el tope es inclusivo"
        );
    }

    #[tokio::test]
    async fn mensaje_mal_formado_recibe_error_y_el_servicio_sigue() {
        let fx = fixture("admin-pipe-malformed");
        let garbage = [0xFFu8, 0xFF, 0xFF, 0x7F, 0x01];
        let framed = frame_bytes(&garbage).unwrap();
        let (served, response) = exchange_raw(&fx.service, admin("PC-ana"), &framed).await;
        served.unwrap();
        assert!(matches!(
            response,
            Some(AdminResponse::Error { message }) if message.contains("mal formada")
        ));
        // Bytes sobrantes tras una peticion valida tambien se rechazan.
        let mut body = encode_message(&AdminRequest::Revoke).unwrap();
        body.push(0);
        let (served, response) =
            exchange_raw(&fx.service, admin("PC-ana"), &frame_bytes(&body).unwrap()).await;
        served.unwrap();
        assert!(matches!(response, Some(AdminResponse::Error { .. })));
        // Cuerpo truncado y cliente que se va: error de transporte, sin panico ni cambios.
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&10u32.to_le_bytes()).await.unwrap();
        client.write_all(&[1, 2, 3]).await.unwrap();
        drop(client);
        assert!(
            fx.service
                .serve(&mut server, || admin("PC-ana"))
                .await
                .is_err()
        );
        assert!(!fx.store.path().exists());
        // El servicio sigue atendiendo.
        assert_eq!(
            exchange(
                &fx.service,
                admin("PC-ana"),
                &AdminRequest::Set {
                    password: secret(FIRST)
                }
            )
            .await,
            AdminResponse::Done { generation: 1 }
        );
    }

    #[test]
    fn la_contrasena_no_aparece_en_debug_y_viaja_por_postcard() {
        let request = AdminRequest::Change {
            password: secret(SECOND),
        };
        assert!(!format!("{request:?}").contains(SECOND));
        let bytes = encode_message(&request).unwrap();
        match decode_message::<AdminRequest>(&bytes).unwrap() {
            AdminRequest::Change { password } => assert_eq!(password.expose(), SECOND),
            other => panic!("{other:?}"),
        }
    }

    fn test_pipe_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!(
            r"\\.\pipe\Awawa.admin.test.{tag}.{}.{nanos}",
            std::process::id()
        )
    }

    /// DACL de prueba: el usuario del proceso en lugar de BA. Las pruebas corren sin elevar y la DACL de
    /// produccion (SY + BA) les negaria el acceso a la pipe; el resto de la configuracion es la de produccion.
    fn test_sddl() -> String {
        format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", current_sid())
    }

    #[test]
    fn pipe_real_verifica_al_cliente_por_su_token_y_opera_o_rechaza() {
        let fx = fixture("admin-pipe-real");
        let name = test_pipe_name("flow");
        let handle =
            spawn_admin_pipe_at(&name, &test_sddl(), fx.service, Duration::from_millis(100))
                .unwrap();
        let me = current_sid();
        // El cliente abre con nivel de identificacion (`request_at`): sin `SeImpersonatePrivilege` en el
        // servicio, la verificacion debe funcionar igual (token abierto y revertido antes de consultar).
        // Elevado: se acepta y opera. Con `runas /trustlevel:0x20000` (BA deny-only): se rechaza.
        let owners = [me.as_str(), TRUSTED_PIPE_OWNERS[1]];
        let request = |req: AdminRequest| request_at(&name, &owners, &req).unwrap();

        if is_administrator() {
            assert_eq!(
                request(AdminRequest::Set {
                    password: secret(FIRST)
                }),
                AdminResponse::Done { generation: 1 }
            );
            assert_eq!(
                request(AdminRequest::Change {
                    password: secret(SECOND)
                }),
                AdminResponse::Done { generation: 2 }
            );
            assert_eq!(
                request(AdminRequest::Revoke),
                AdminResponse::Done { generation: 3 }
            );
            let lines = fx.audit.lock().unwrap().lines.join("\n");
            assert!(lines.contains("password_configured") && !lines.contains(FIRST));
            let account = current_account_name().unwrap();
            assert!(lines.contains(account.rsplit('\\').next().unwrap()));
        } else {
            // Token sin elevar: la pipe lo deja pasar (DACL de prueba) y el servidor lo rechaza por su token.
            let response = request(AdminRequest::Set {
                password: secret(FIRST),
            });
            assert!(
                matches!(&response, AdminResponse::Error { message } if message.contains("denegado")),
                "{response:?}"
            );
            assert!(!fx.store.path().exists());
            let lines = fx.audit.lock().unwrap().lines.clone();
            assert_eq!(lines.len(), 1, "{lines:?}");
            let account = current_account_name().unwrap();
            assert!(lines[0].contains("auth_failed"));
            assert!(lines[0].contains(account.rsplit('\\').next().unwrap()));
            assert!(!lines[0].contains(FIRST));
        }
        handle.stop();
    }

    /// Pipe cuyo DUENO es un SID no privilegiado (el del usuario): el cliente de produccion la rechaza antes de
    /// escribir nada. Una pipe creada con un token elevado tiene dueno BA; con BA deny-only, el SID del usuario.
    #[test]
    fn cliente_no_envia_la_contrasena_a_una_pipe_de_dueno_no_privilegiado() {
        let fx = fixture("admin-pipe-owner");
        let name = test_pipe_name("owner");
        let me = current_sid();
        let sddl = format!("O:{me}D:P(A;;GA;;;SY)(A;;GA;;;{me})");
        let handle =
            spawn_admin_pipe_at(&name, &sddl, fx.service, Duration::from_millis(100)).unwrap();
        let set = AdminRequest::Set {
            password: secret(FIRST),
        };
        let err = request_at(&name, &TRUSTED_PIPE_OWNERS, &set).unwrap_err();
        assert!(
            matches!(&err, ClientError::ServerNotTrusted(why) if why.contains(&me)),
            "{err}"
        );
        // Nada llego al servidor: sin verificador y sin auditoria.
        assert!(!fx.store.path().exists());
        assert!(fx.audit.lock().unwrap().lines.is_empty());
        // Con ese dueno declarado como confiable, la comprobacion pasa y el servidor responde.
        assert!(request_at(&name, &[me.as_str()], &AdminRequest::Revoke).is_ok());
        handle.stop();
    }

    /// Si el nombre ya existe al arrancar, el servidor no se rinde: reintenta y toma la pipe al liberarse.
    #[test]
    fn el_servidor_reintenta_hasta_crear_la_pipe_ocupada() {
        let fx = fixture("admin-pipe-retry");
        let name = test_pipe_name("retry");
        let me = current_sid();
        let holder_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let holder = holder_rt.block_on(async { create_admin_pipe(&name, &test_sddl()) });
        let holder = holder.unwrap();
        let handle =
            spawn_admin_pipe_at(&name, &test_sddl(), fx.service, Duration::from_millis(100))
                .unwrap();
        drop(holder);
        drop(holder_rt);
        let owners = [me.as_str(), TRUSTED_PIPE_OWNERS[1]];
        let started = Instant::now();
        loop {
            match request_at(&name, &owners, &AdminRequest::Revoke) {
                Ok(_) => break,
                Err(e) => assert!(started.elapsed() < Duration::from_secs(10), "{e}"),
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        handle.stop();
    }

    /// La parada se atiende mientras el servidor reintenta (el nombre sigue ocupado).
    #[test]
    fn la_parada_se_atiende_durante_los_reintentos() {
        let fx = fixture("admin-pipe-stop");
        let name = test_pipe_name("stop");
        let holder_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _holder = holder_rt
            .block_on(async { create_admin_pipe(&name, &test_sddl()) })
            .unwrap();
        let handle =
            spawn_admin_pipe_at(&name, &test_sddl(), fx.service, Duration::from_secs(60)).unwrap();
        let started = Instant::now();
        handle.stop();
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn cliente_sin_servicio_informa_que_no_esta_en_ejecucion() {
        let err = request_at(
            &test_pipe_name("absent"),
            &TRUSTED_PIPE_OWNERS,
            &AdminRequest::Revoke,
        )
        .unwrap_err();
        assert_eq!(err, ClientError::NotRunning);
        assert!(
            err.to_string()
                .contains("el servicio Awawa no esta en ejecucion")
        );
    }

    /// Primera instancia y unica: nadie puede plantar el nombre antes ni crear otra instancia despues.
    /// Con la DACL de produccion, un token sin elevar no abre la pipe (solo SY y BA).
    #[tokio::test]
    async fn pipe_real_primera_instancia_y_dacl_de_produccion() {
        let name = test_pipe_name("dacl");
        let server = create_admin_pipe(&name, ADMIN_PIPE_SDDL).unwrap();
        assert!(create_admin_pipe(&name, ADMIN_PIPE_SDDL).is_err());
        assert!(ServerOptions::new().create(&name).is_err());
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name);
        if is_administrator() {
            assert!(opened.is_ok(), "{opened:?}");
        } else {
            assert_eq!(
                opened.unwrap_err().raw_os_error(),
                Some(ERROR_ACCESS_DENIED)
            );
        }
        drop(server);
    }
}
