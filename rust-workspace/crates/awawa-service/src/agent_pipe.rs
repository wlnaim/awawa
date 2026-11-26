//! Canal servicio <-> agente de sesion por named pipe local.
//!
//! El servicio (SYSTEM) es dueno de la red, de la identidad Ed25519, del canal E2E y del sellado
//! del video: por la pipe nunca viajan claves. Solo pasan, en claro y dentro de la maquina:
//! - agente -> servicio: monitores, fotogramas ya codificados con su cabecera, cursor y
//!   topologia, sondeos del escritorio de entrada, kill-switch, fallo y fin ordenado;
//! - servicio -> agente: inicio, orden de video, entrada del operador, ping (dead-man switch),
//!   suspension/reanudacion y parada ordenada.
//!
//! Trama: `[len u32 LE][tipo u8][cuerpo]`, con `len = 1 + cuerpo`. Tipo `0`: mensaje postcard
//! ([`ServiceToAgent`] o [`AgentToService`]). Tipo `1` (solo agente -> servicio): video,
//! `cabecera VideoPacketHeader (24 bytes) ‖ payload`, con `payload_len` igual al resto. Los topes
//! se comprueban antes de reservar memoria: [`MAX_SERVICE_FRAME`] hacia el agente,
//! [`MAX_AGENT_CONTROL_FRAME`] para mensajes del agente y [`MAX_AGENT_VIDEO_FRAME`] para video.
//!
//! Pipe de produccion ([`create_agent_pipe`]): una instancia por sesion
//! (`FILE_FLAG_FIRST_PIPE_INSTANCE`, `max_instances = 1`), nombre impredecible
//! `\\.\pipe\Awawa.agent.<32 hex>`, `PIPE_REJECT_REMOTE_CLIENTS` y DACL protegida
//! `D:P(A;;GA;;;SY)(A;;0x12008b;;;<SID del usuario>)`: SYSTEM y el usuario de la sesion
//! autorizada, este solo con lectura y `FILE_WRITE_DATA` (sin `FILE_CREATE_PIPE_INSTANCE`, que
//! en una pipe es el bit de `FILE_APPEND_DATA`). El agente abre con
//! `GENERIC_READ | FILE_WRITE_DATA`. Tras conectar, el servicio compara
//! `GetNamedPipeClientProcessId` con el PID que lanzo.

use core::ffi::c_void;
use std::io;

use awawa_protocol::{
    ClientToHostMessage, HostToClientMessage, InputDesktopKind, MAX_CTRL_FRAME,
    MAX_VIDEO_PAYLOAD_LEN, MonitorDescriptor, VIDEO_PACKET_HEADER_LEN, VideoPacketHeader,
    decode_message, encode_message,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Tope de una trama del servicio hacia el agente.
pub const MAX_SERVICE_FRAME: usize = 64 * 1024;
/// Tope de un mensaje (no video) del agente.
pub const MAX_AGENT_CONTROL_FRAME: usize = MAX_CTRL_FRAME;
/// Tope de una trama de video del agente.
pub const MAX_AGENT_VIDEO_FRAME: usize =
    1 + VIDEO_PACKET_HEADER_LEN + MAX_VIDEO_PAYLOAD_LEN as usize;
/// Prefijo del nombre de la pipe.
pub const PIPE_PREFIX: &str = r"\\.\pipe\Awawa.agent.";

const KIND_MESSAGE: u8 = 0;
const KIND_VIDEO: u8 = 1;

/// Sondeo del escritorio de entrada tal como viaja por la pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeKind {
    Default,
    SecureOrOther,
    Inaccessible,
}

impl From<InputDesktopKind> for ProbeKind {
    fn from(kind: InputDesktopKind) -> Self {
        match kind {
            InputDesktopKind::Default => Self::Default,
            InputDesktopKind::SecureOrOther => Self::SecureOrOther,
            InputDesktopKind::Inaccessible => Self::Inaccessible,
        }
    }
}

impl From<ProbeKind> for InputDesktopKind {
    fn from(kind: ProbeKind) -> Self {
        match kind {
            ProbeKind::Default => Self::Default,
            ProbeKind::SecureOrOther => Self::SecureOrOther,
            ProbeKind::Inaccessible => Self::Inaccessible,
        }
    }
}

/// Ordenes del servicio al agente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceToAgent {
    /// Primer mensaje: sesion autorizada por el administrador (sin secretos). El agente muestra
    /// el banner con el nombre del operador (ya saneado) y anuncia sus monitores.
    Start {
        /// ID persistente del servicio (9 digitos): identificador de la sesion en el agente.
        service_id: u32,
        operator_display_name: String,
        session_fingerprint: [u8; 8],
        generation: u32,
    },
    /// El operador ya recibio los monitores (`DisplayTopologyChanged`): el agente puede enviar video.
    StartVideo,
    /// Entrada del operador (solo `PointerMove`, `PointerButton`, `PointerWheel` y
    /// `KeyboardEvent`; el agente descarta cualquier otra variante).
    Input(ClientToHostMessage),
    /// `Ping` del operador: alimenta el dead-man switch de la entrada.
    OperatorPing,
    /// Bloqueo de sesion u otra suspension decidida por el servicio: detener captura y liberar
    /// teclas y botones retenidos.
    Suspend,
    /// Reanudar (el siguiente fotograma de cada monitor es clave si se pide).
    Resume { force_keyframe: bool },
    /// Cierre ordenado: liberar teclas y botones, enviar `Stopped` y salir.
    Stop { reason: String },
    /// El servicio descarto un fotograma (el operador no consume video): el siguiente de cada
    /// monitor debe ser clave.
    KeyframeRequest,
}

/// Avisos del agente al servicio (el video va como trama de tipo 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentToService {
    /// Monitores de la sesion (respuesta a `Start`).
    Started { monitors: Vec<MonitorDescriptor> },
    /// `CursorShapeUpdate` o `DisplayTopologyChanged`; el servicio descarta otras variantes.
    Control(HostToClientMessage),
    /// Resultado de un sondeo del escritorio de entrada (cada cambio).
    InputDesktop(ProbeKind),
    /// El usuario local pulso "Revocar control ahora" o el atajo global.
    KillSwitch,
    /// La captura o la entrada dejaron de estar disponibles.
    Failed { reason: String },
    /// Teclas liberadas; el agente sale.
    Stopped,
}

/// Fotograma codificado del agente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVideo {
    pub header: VideoPacketHeader,
    pub payload: Vec<u8>,
}

/// Trama del agente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentFrame {
    Message(AgentToService),
    Video(AgentVideo),
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    parts: &[&[u8]],
) -> io::Result<()> {
    let body: usize = parts.iter().map(|p| p.len()).sum();
    let len = u32::try_from(1 + body).map_err(|_| invalid("trama demasiado grande"))?;
    let mut buf = Vec::with_capacity(5 + body);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(kind);
    for part in parts {
        buf.extend_from_slice(part);
    }
    w.write_all(&buf).await?;
    w.flush().await
}

/// Lee una trama. `max_len(tipo)` es el tope de `len` para ese tipo (0 si el tipo no se admite):
/// se comprueba antes de reservar el cuerpo. Devuelve `(tipo, cuerpo)`.
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: impl Fn(u8) -> usize,
) -> io::Result<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    // Antes de leer el tipo: ninguna trama puede superar el mayor tope admitido.
    let any_kind = max_len(KIND_MESSAGE).max(max_len(KIND_VIDEO));
    if len == 0 || len > any_kind {
        return Err(invalid("longitud de trama fuera de tope"));
    }
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind).await?;
    let limit = max_len(kind[0]);
    if limit == 0 {
        return Err(invalid("tipo de trama desconocido"));
    }
    if len > limit {
        return Err(invalid("longitud de trama fuera de tope"));
    }
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body).await?;
    Ok((kind[0], body))
}

/// Servicio: envia una orden al agente.
pub async fn send_to_agent<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &ServiceToAgent,
) -> io::Result<()> {
    let bytes = encode_message(msg).map_err(|_| invalid("mensaje no serializable"))?;
    if bytes.len() + 1 > MAX_SERVICE_FRAME {
        return Err(invalid("orden demasiado grande"));
    }
    write_frame(w, KIND_MESSAGE, &[&bytes]).await
}

/// Agente: lee una orden del servicio.
pub async fn recv_from_service<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<ServiceToAgent> {
    let (_, body) = read_frame(r, |kind| {
        if kind == KIND_MESSAGE {
            MAX_SERVICE_FRAME
        } else {
            0
        }
    })
    .await?;
    decode_message(&body).map_err(|_| invalid("orden mal formada"))
}

/// Agente: envia un aviso.
pub async fn send_to_service<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &AgentToService,
) -> io::Result<()> {
    let bytes = encode_message(msg).map_err(|_| invalid("mensaje no serializable"))?;
    if bytes.len() + 1 > MAX_AGENT_CONTROL_FRAME {
        return Err(invalid("aviso demasiado grande"));
    }
    write_frame(w, KIND_MESSAGE, &[&bytes]).await
}

/// Agente: envia un fotograma codificado.
pub async fn send_video<W: AsyncWrite + Unpin>(w: &mut W, video: &AgentVideo) -> io::Result<()> {
    if video.payload.len() != video.header.payload_len as usize
        || video.header.payload_len > MAX_VIDEO_PAYLOAD_LEN
    {
        return Err(invalid("fotograma inconsistente"));
    }
    write_frame(w, KIND_VIDEO, &[&video.header.to_bytes(), &video.payload]).await
}

/// Servicio: lee una trama del agente, validando tipo, tope y coherencia de la cabecera.
pub async fn recv_from_agent<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<AgentFrame> {
    let (kind, body) = read_frame(r, |kind| match kind {
        KIND_MESSAGE => MAX_AGENT_CONTROL_FRAME,
        KIND_VIDEO => MAX_AGENT_VIDEO_FRAME,
        _ => 0,
    })
    .await?;
    match kind {
        KIND_MESSAGE => decode_message(&body)
            .map(AgentFrame::Message)
            .map_err(|_| invalid("aviso mal formado")),
        KIND_VIDEO => {
            if body.len() < VIDEO_PACKET_HEADER_LEN {
                return Err(invalid("fotograma sin cabecera"));
            }
            let header = VideoPacketHeader::from_bytes(&body[..VIDEO_PACKET_HEADER_LEN])
                .map_err(|_| invalid("cabecera de video invalida"))?;
            let payload = body[VIDEO_PACKET_HEADER_LEN..].to_vec();
            if payload.len() != header.payload_len as usize {
                return Err(invalid("longitud de video incoherente"));
            }
            Ok(AgentFrame::Video(AgentVideo { header, payload }))
        }
        _ => Err(invalid("tipo de trama desconocido")),
    }
}

/// SDDL de la pipe de una sesion: SYSTEM con control total y el usuario de la sesion con
/// lectura y `FILE_WRITE_DATA`. Rechaza SIDs con caracteres fuera de `S-<digitos y guiones>`.
pub fn pipe_sddl(user_sid: &str) -> io::Result<String> {
    let well_formed = user_sid.len() > 4
        && user_sid.starts_with("S-")
        && user_sid[2..]
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(invalid("SID de usuario invalido"));
    }
    Ok(format!("D:P(A;;GA;;;SY)(A;;0x12008b;;;{user_sid})"))
}

/// Nombre impredecible para una pipe nueva (128 bits del RNG del sistema).
pub fn random_pipe_name() -> io::Result<String> {
    let mut raw = [0u8; 16];
    crate::service_identity::os_random(&mut raw).map_err(|e| io::Error::other(e.to_string()))?;
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{PIPE_PREFIX}{hex}"))
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetNamedPipeClientProcessId(pipe: *mut c_void, client_pid: *mut u32) -> i32;
}

/// Pipe de produccion de una sesion, aun sin cliente.
pub struct AgentPipeServer {
    name: String,
    server: tokio::net::windows::named_pipe::NamedPipeServer,
}

/// Crea la unica instancia de la pipe de una sesion con la DACL de [`pipe_sddl`].
pub fn create_agent_pipe(user_sid: &str) -> io::Result<AgentPipeServer> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
    let sddl = pipe_sddl(user_sid)?;
    let security = crate::dpapi_store::ProtectedSecurity::from_sddl(&sddl)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut attrs = security.attributes();
    let name = random_pipe_name()?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .pipe_mode(PipeMode::Byte)
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);
    // SAFETY: `attrs` es un SECURITY_ATTRIBUTES valido que apunta al descriptor de `security`,
    // vivo durante toda la llamada (la pipe copia el descriptor al crearse).
    let server = unsafe {
        options.create_with_security_attributes_raw(&name, (&raw mut attrs).cast::<c_void>())
    }?;
    drop(security);
    Ok(AgentPipeServer { name, server })
}

impl AgentPipeServer {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Espera al cliente y devuelve la pipe conectada con el PID del proceso cliente.
    pub async fn accept(
        self,
    ) -> io::Result<(tokio::net::windows::named_pipe::NamedPipeServer, u32)> {
        use std::os::windows::io::AsRawHandle;
        self.server.connect().await?;
        let mut pid = 0u32;
        // SAFETY: manejador de pipe valido y conectado; `pid` es un destino valido.
        let ok = unsafe { GetNamedPipeClientProcessId(self.server.as_raw_handle(), &mut pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((self.server, pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::{KeyState, VideoCodec};

    fn header(len: u32) -> VideoPacketHeader {
        VideoPacketHeader {
            frame_seq: 7,
            capture_ts_us: 9,
            monitor_index: 0,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: len,
        }
    }

    #[tokio::test]
    async fn ida_y_vuelta_de_ordenes_avisos_y_video() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let cmd = ServiceToAgent::Input(ClientToHostMessage::KeyboardEvent {
            scancode: 0x1E,
            extended: false,
            unicode_fallback: None,
            state: KeyState::Down,
        });
        send_to_agent(&mut a, &cmd).await.unwrap();
        assert_eq!(recv_from_service(&mut b).await.unwrap(), cmd);

        send_to_service(
            &mut b,
            &AgentToService::InputDesktop(ProbeKind::SecureOrOther),
        )
        .await
        .unwrap();
        let video = AgentVideo {
            header: header(3),
            payload: vec![1, 2, 3],
        };
        send_video(&mut b, &video).await.unwrap();
        assert_eq!(
            recv_from_agent(&mut a).await.unwrap(),
            AgentFrame::Message(AgentToService::InputDesktop(ProbeKind::SecureOrOther))
        );
        assert_eq!(
            recv_from_agent(&mut a).await.unwrap(),
            AgentFrame::Video(video)
        );
    }

    #[tokio::test]
    async fn rechaza_tramas_fuera_de_tope_o_incoherentes() {
        // Longitud mayor que el tope: error antes de reservar.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&((MAX_SERVICE_FRAME as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        assert!(recv_from_service(&mut b).await.is_err());

        // Video con payload_len distinto del cuerpo.
        let (mut a, mut b) = tokio::io::duplex(1024);
        let mut body = header(10).to_bytes().to_vec();
        body.extend_from_slice(&[0; 3]);
        write_frame(&mut a, KIND_VIDEO, &[&body]).await.unwrap();
        assert!(recv_from_agent(&mut b).await.is_err());

        // Tipo desconocido y video hacia el agente.
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, 7, &[b"x"]).await.unwrap();
        assert!(recv_from_agent(&mut b).await.is_err());
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, KIND_VIDEO, &[b"x"]).await.unwrap();
        assert!(recv_from_service(&mut b).await.is_err());

        // Aviso de control mayor que su tope (aunque menor que el de video): se rechaza tras leer
        // solo la cabecera, sin esperar ni reservar el cuerpo.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&((MAX_AGENT_CONTROL_FRAME as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        a.write_all(&[KIND_MESSAGE]).await.unwrap();
        let rejected =
            tokio::time::timeout(std::time::Duration::from_secs(2), recv_from_agent(&mut b))
                .await
                .expect("no espera el cuerpo");
        assert!(rejected.is_err());

        // Longitud cero.
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&0u32.to_le_bytes()).await.unwrap();
        assert!(recv_from_agent(&mut b).await.is_err());
    }

    #[test]
    fn dacl_y_nombre_de_la_pipe() {
        assert_eq!(
            pipe_sddl("S-1-5-21-1-2-3-1001").unwrap(),
            "D:P(A;;GA;;;SY)(A;;0x12008b;;;S-1-5-21-1-2-3-1001)"
        );
        for bad in ["", "S-", "WD", "S-1-5)(A;;GA;;;WD", "S-1-5-21 1"] {
            assert!(pipe_sddl(bad).is_err(), "{bad}");
        }
        let a = random_pipe_name().unwrap();
        let b = random_pipe_name().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), PIPE_PREFIX.len() + 32);
    }

    /// La pipe real se crea con la DACL y solo admite una instancia; el PID del cliente se lee.
    #[tokio::test]
    async fn pipe_real_una_instancia_y_pid_del_cliente() {
        let sid = crate::testutil::current_sid();
        let server = create_agent_pipe(&sid).unwrap();
        let name = server.name().to_string();
        // Una segunda instancia con el mismo nombre falla (FIRST_PIPE_INSTANCE / max 1).
        assert!(
            tokio::net::windows::named_pipe::ServerOptions::new()
                .create(&name)
                .is_err()
        );
        let accept = tokio::spawn(server.accept());
        let open = |access: u32| {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().access_mode(access).open(&name)
        };
        // GENERIC_WRITE incluye FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE): denegado.
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_WRITE_DATA: u32 = 0x2;
        let denied = open(GENERIC_READ | GENERIC_WRITE).unwrap_err();
        assert_eq!(denied.raw_os_error(), Some(5), "{denied}");
        let client = open(GENERIC_READ | FILE_WRITE_DATA).unwrap();
        let (_pipe, pid) = accept.await.unwrap().unwrap();
        assert_eq!(pid, std::process::id());
        drop(client);
    }
}
