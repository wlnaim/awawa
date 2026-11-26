//! Transporte real del operador: `net::OperatorNet` + decodificacion acotada y composicion.
//!
//! Cada paquete de video es de un monitor (`monitor_index` de la cabecera). Se decodifica con
//! `TileDecoder::decode_into_bounded` usando `payload_len` de la cabecera y las dimensiones de ese
//! monitor negociado, y se compone en el lienzo del escritorio virtual que dibuja el visor.
//! El lienzo esta acotado a `MAX_FRAME_DIMENSION` (8192 px) por lado: una topologia mayor
//! termina la sesion con un aviso.
//!
//! Orden entre topologia y video: `DisplayTopologyChanged` viaja por el stream de control y los
//! fotogramas por streams unidireccionales, sin orden entre si. El host nunca emite un fotograma
//! que no coincida con la topologia que ya anuncio y, tras anunciar una nueva, el primer
//! fotograma de cada monitor es clave. Aqui:
//! - un fotograma que no cuadra con la topologia vigente (monitor desconocido o dimensiones
//!   distintas) no cierra la sesion: si es clave, se guarda junto con los que le siguen (cola
//!   acotada a `MAX_PENDING_VIDEO_BYTES`) y se reaplica cuando llega la topologia que le
//!   corresponde; si no, se descarta;
//! - tras una topologia nueva cada monitor nuevo o con otras dimensiones espera su fotograma
//!   clave (los parciales se descartan); un monitor que conserva indice y dimensiones conserva su
//!   imagen, que se recompone en su origen nuevo, y sigue aceptando parciales.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use awawa_protocol::unattended_channel::VerifyingKey;
use awawa_protocol::{
    MonitorDescriptor, OperatorConnectionRequest, RemoteInputCommand, VideoCodec,
    VideoPacketHeader, VirtualDesktopBounds,
};
use awawa_relay::RelayPin;
use capture_win::{DecodeLimits, DecodedFrame, DirtyRect, MAX_FRAME_DIMENSION, TileDecoder};
use zeroize::Zeroizing;

use crate::form::{ConnectMode, ConnectionParams, format_fingerprint};
use crate::net::{NetEvent, OperatorNet, OperatorNetConfig, VideoSink};
use crate::transport::{FrameUpdate, OperatorTransport, TransportEvent};

type FrameSlot = Arc<Mutex<Option<FrameUpdate>>>;

/// Tope del coste de video retenido a la espera de su topologia (todas las colas). Cada paquete
/// cuesta su payload mas `PENDING_PACKET_OVERHEAD`, de modo que muchos registros vacios tambien
/// agotan el tope.
const MAX_PENDING_VIDEO_BYTES: usize = 64 * 1024 * 1024;
/// Coste fijo por paquete retenido (cabecera, `Vec` y entrada de la cola).
const PENDING_PACKET_OVERHEAD: usize = 4096;
/// Tope de paquetes retenidos (todas las colas).
const MAX_PENDING_PACKETS: usize = 1024;

fn packet_cost(payload: &[u8]) -> usize {
    payload.len() + PENDING_PACKET_OVERHEAD
}

type Packet = (VideoPacketHeader, Vec<u8>);

/// Ancho y alto que declara un payload de tiles v1 (bytes 4..12), sin decodificarlo.
fn payload_dims(payload: &[u8]) -> Option<(u32, u32)> {
    let w = payload.get(4..8)?;
    let h = payload.get(8..12)?;
    Some((
        u32::from_le_bytes([w[0], w[1], w[2], w[3]]),
        u32::from_le_bytes([h[0], h[1], h[2], h[3]]),
    ))
}

/// Decodifica por monitor y compone en el lienzo del escritorio virtual.
pub struct Composer {
    decoder: TileDecoder,
    monitors: Vec<MonitorDescriptor>,
    bounds: Option<VirtualDesktopBounds>,
    frames: BTreeMap<u8, DecodedFrame>,
    canvas: DecodedFrame,
    /// Monitores que esperan su fotograma clave tras una topologia nueva o un desajuste.
    resync: BTreeSet<u8>,
    /// Fotogramas que llegaron antes que su topologia: clave + los siguientes, por monitor.
    pending: BTreeMap<u8, Vec<Packet>>,
    /// Coste y numero de paquetes de `pending`, llevados al dia en cada cambio.
    pending_cost: usize,
    pending_packets: usize,
    slot: FrameSlot,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Composer {
    fn new(slot: FrameSlot, wake: Arc<dyn Fn() + Send + Sync>) -> Result<Self, String> {
        Ok(Self {
            decoder: TileDecoder::new().map_err(|e| format!("{e:?}"))?,
            monitors: Vec::new(),
            bounds: None,
            frames: BTreeMap::new(),
            canvas: DecodedFrame::new(0, 0),
            resync: BTreeSet::new(),
            pending: BTreeMap::new(),
            pending_cost: 0,
            pending_packets: 0,
            slot,
            wake,
        })
    }
}

/// Copia `rect` (coordenadas de `src`) a `dst` desplazado `(ox, oy)`. Devuelve el rectangulo
/// copiado en coordenadas de `dst`, o `None` si queda vacio.
fn blit(
    src: &DecodedFrame,
    rect: &DirtyRect,
    dst: &mut DecodedFrame,
    ox: u32,
    oy: u32,
) -> Option<DirtyRect> {
    let x0 = rect.x.min(src.width);
    let y0 = rect.y.min(src.height);
    let x1 = rect.x.saturating_add(rect.width).min(src.width);
    let y1 = rect.y.saturating_add(rect.height).min(src.height);
    let dx1 = (ox.saturating_add(x1)).min(dst.width);
    let dy1 = (oy.saturating_add(y1)).min(dst.height);
    let (w, h) = (dx1.checked_sub(ox + x0)?, dy1.checked_sub(oy + y0)?);
    if w == 0 || h == 0 {
        return None;
    }
    for row in 0..h {
        let s = (((y0 + row) * src.width + x0) * 4) as usize;
        let d = (((oy + y0 + row) * dst.width + ox + x0) * 4) as usize;
        let n = (w * 4) as usize;
        dst.bgra[d..d + n].copy_from_slice(&src.bgra[s..s + n]);
    }
    Some(DirtyRect {
        x: ox + x0,
        y: oy + y0,
        width: w,
        height: h,
    })
}

impl VideoSink for Composer {
    fn set_monitors(&mut self, monitors: &[MonitorDescriptor]) -> Result<(), String> {
        let bounds = VirtualDesktopBounds::from_monitors(monitors)
            .ok_or_else(|| "El cliente informo una topologia de monitores invalida.".to_string())?;
        if bounds.width > MAX_FRAME_DIMENSION || bounds.height > MAX_FRAME_DIMENSION {
            return Err(format!(
                "El escritorio remoto mide {}x{} px; el visor admite hasta {MAX_FRAME_DIMENSION} px por lado.",
                bounds.width, bounds.height
            ));
        }
        // Un monitor que conserva indice y dimensiones conserva su imagen (y no espera otra clave:
        // la que el host forzo pudo llegar antes que este aviso).
        let kept: BTreeSet<u8> = monitors
            .iter()
            .filter(|m| {
                self.monitors.iter().any(|old| {
                    old.index == m.index
                        && (old.width_px, old.height_px) == (m.width_px, m.height_px)
                }) && self.frames.contains_key(&m.index)
                    && !self.resync.contains(&m.index)
            })
            .map(|m| m.index)
            .collect();
        self.frames.retain(|index, _| kept.contains(index));
        self.canvas = DecodedFrame::new(bounds.width, bounds.height);
        self.bounds = Some(bounds);
        self.monitors = monitors.to_vec();
        self.resync = monitors
            .iter()
            .map(|m| m.index)
            .filter(|index| !kept.contains(index))
            .collect();
        let mut dirty = Vec::new();
        for m in monitors.iter().filter(|m| kept.contains(&m.index)) {
            if let Some(frame) = self.frames.get(&m.index) {
                let (ox, oy) = monitor_offset(m, &bounds);
                let full = DirtyRect {
                    x: 0,
                    y: 0,
                    width: frame.width,
                    height: frame.height,
                };
                dirty.extend(blit(frame, &full, &mut self.canvas, ox, oy));
            }
        }
        self.publish(dirty);
        // Lo que llego antes que esta topologia se reaplica en orden.
        self.pending_cost = 0;
        self.pending_packets = 0;
        for (_, queue) in std::mem::take(&mut self.pending) {
            for (header, payload) in queue {
                self.packet(&header, &payload)?;
            }
        }
        Ok(())
    }

    fn packet(&mut self, header: &VideoPacketHeader, payload: &[u8]) -> Result<(), String> {
        if header.codec != VideoCodec::ZstdDirtyTiles {
            return Err("Codec de video no soportado.".to_string());
        }
        let bounds = self
            .bounds
            .ok_or_else(|| "Video antes de la topologia de monitores.".to_string())?;
        let index = header.monitor_index;
        let fits = self
            .monitors
            .iter()
            .any(|m| m.index == index && payload_dims(payload) == Some((m.width_px, m.height_px)));
        if !fits {
            self.hold(header, payload);
            return Ok(());
        }
        if self.resync.contains(&index) && !header.is_keyframe {
            return Ok(());
        }
        let Some(monitor) = self.monitors.iter().find(|m| m.index == index) else {
            return Ok(());
        };
        let frame = self
            .frames
            .entry(monitor.index)
            .or_insert_with(|| DecodedFrame::new(0, 0));
        let limits = DecodeLimits {
            payload_len: header.payload_len,
            max_width: monitor.width_px,
            max_height: monitor.height_px,
        };
        let rects = self
            .decoder
            .decode_into_bounded(payload, frame, limits)
            .map_err(|e| format!("Video invalido: {e:?}"))?;
        self.resync.remove(&index);
        let (ox, oy) = monitor_offset(monitor, &bounds);
        let mut dirty = Vec::new();
        for rect in &rects {
            if let Some(done) = blit(frame, rect, &mut self.canvas, ox, oy) {
                dirty.push(done);
            }
        }
        if header.is_keyframe {
            self.drop_pending(index);
        }
        self.publish(dirty);
        Ok(())
    }
}

/// Desplazamiento del monitor dentro del lienzo del escritorio virtual.
fn monitor_offset(monitor: &MonitorDescriptor, bounds: &VirtualDesktopBounds) -> (u32, u32) {
    (
        u32::try_from(monitor.origin_x - bounds.left).unwrap_or(0),
        u32::try_from(monitor.origin_y - bounds.top).unwrap_or(0),
    )
}

impl Composer {
    /// Retiene un fotograma que no cuadra con la topologia vigente (ver el comentario del modulo).
    fn hold(&mut self, header: &VideoPacketHeader, payload: &[u8]) {
        let index = header.monitor_index;
        self.resync.insert(index);
        if header.is_keyframe {
            self.drop_pending(index);
            self.pending.insert(index, Vec::new());
        }
        let Some(queue) = self.pending.get_mut(&index) else {
            return;
        };
        queue.push((*header, payload.to_vec()));
        self.pending_cost += packet_cost(payload);
        self.pending_packets += 1;
        if self.pending_cost > MAX_PENDING_VIDEO_BYTES || self.pending_packets > MAX_PENDING_PACKETS
        {
            self.drop_pending(index);
        }
    }

    /// Descarta la cola retenida de un monitor y descuenta su coste.
    fn drop_pending(&mut self, index: u8) {
        if let Some(queue) = self.pending.remove(&index) {
            for (_, payload) in &queue {
                self.pending_cost -= packet_cost(payload);
            }
            self.pending_packets -= queue.len();
        }
    }

    /// Entrega al visor las regiones cambiadas del lienzo (fusionando con lo no consumido).
    fn publish(&mut self, dirty: Vec<DirtyRect>) {
        if dirty.is_empty() {
            return;
        }
        let mut pending = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        let update = FrameUpdate {
            frame: self.canvas.clone(),
            dirty,
        };
        *pending = Some(match pending.take() {
            Some(older) => older.merge(update),
            None => update,
        });
        drop(pending);
        (self.wake)();
    }
}

/// `OperatorTransport` sobre el relay real.
pub struct RelayTransport {
    net: OperatorNet,
    frames: FrameSlot,
}

impl RelayTransport {
    /// `host_key` es la clave fijada del servicio (`--host-key`); el modo desatendido la exige.
    pub fn spawn(
        relay_addr: SocketAddr,
        pin: RelayPin,
        host_key: Option<VerifyingKey>,
        params: ConnectionParams,
        ctx: egui::Context,
    ) -> Self {
        let host_key = match (params.mode, host_key) {
            (ConnectMode::Unattended, None) => {
                return Self {
                    net: OperatorNet::failed(
                        "Falta la clave del host (--host-key) para el modo desatendido."
                            .to_string(),
                    ),
                    frames: FrameSlot::default(),
                };
            }
            (ConnectMode::Unattended, key) => key,
            (ConnectMode::OnDemand, _) => None,
        };
        let frames = FrameSlot::default();
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(move || ctx.request_repaint());
        let request = OperatorConnectionRequest {
            target_session_id: params.session_id,
            operator_display_name: params.agent_name.clone(),
            // Sin identidad persistente del operador todavia.
            operator_ed25519_fingerprint: [0; 8],
            requested_capabilities: params.requested_capabilities,
        };
        let password = Box::new(Zeroizing::new(params.password.clone()));
        drop(params);
        let net = match Composer::new(frames.clone(), wake.clone()) {
            Ok(composer) => OperatorNet::start(OperatorNetConfig {
                relay_addr,
                pin,
                request,
                host_key,
                password,
                sink: Box::new(composer),
                wake,
            }),
            Err(e) => OperatorNet::failed(format!("No se pudo iniciar el video: {e}")),
        };
        Self { net, frames }
    }
}

impl OperatorTransport for RelayTransport {
    fn send_input(&mut self, command: RemoteInputCommand) {
        self.net.send_input(command);
    }

    fn disconnect(&mut self) {
        self.net.disconnect();
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        // Primero los eventos de control: `Approved` llega antes que cualquier fotograma.
        if let Some(event) = self.net.poll_event() {
            return Some(match event {
                NetEvent::AwaitingApproval { timeout_secs, sas } => {
                    TransportEvent::AwaitingApproval { timeout_secs, sas }
                }
                NetEvent::Approved { monitors } => TransportEvent::Approved { monitors },
                NetEvent::UnattendedGranted { fingerprint } => TransportEvent::UnattendedGranted {
                    fingerprint: format_fingerprint(&fingerprint),
                },
                NetEvent::Rejected { reason } => TransportEvent::Rejected { reason },
                NetEvent::TopologyChanged { monitors } => {
                    TransportEvent::TopologyChanged { monitors }
                }
                NetEvent::Rtt(rtt) => TransportEvent::Rtt(rtt),
                NetEvent::LocalApprovalRequired => TransportEvent::LocalApprovalRequired,
                NetEvent::LocalApprovalCleared => TransportEvent::LocalApprovalCleared,
                NetEvent::Disconnected { reason } => TransportEvent::Disconnected { reason },
            });
        }
        let pending = self.frames.lock().ok()?.take();
        pending.map(TransportEvent::Frame)
    }
}

#[cfg(test)]
mod tests {
    use capture_win::TileEncoder;

    use super::*;

    fn monitors() -> Vec<MonitorDescriptor> {
        vec![
            MonitorDescriptor {
                index: 0,
                is_primary: true,
                origin_x: 0,
                origin_y: 0,
                width_px: 128,
                height_px: 64,
                dpi_scale_percent: 100,
            },
            MonitorDescriptor {
                index: 1,
                is_primary: false,
                origin_x: 128,
                origin_y: 0,
                width_px: 64,
                height_px: 64,
                dpi_scale_percent: 100,
            },
        ]
    }

    fn composer() -> (Composer, FrameSlot) {
        let slot = FrameSlot::default();
        let mut c = Composer::new(slot.clone(), Arc::new(|| {})).unwrap();
        c.set_monitors(&monitors()).unwrap();
        (c, slot)
    }

    fn packet(monitor: u8, w: u32, h: u32, px: u8) -> (VideoPacketHeader, Vec<u8>) {
        let bgra = vec![px; (w * h * 4) as usize];
        let payload = TileEncoder::new()
            .unwrap()
            .encode_keyframe(w, h, &bgra)
            .unwrap();
        let header = VideoPacketHeader {
            frame_seq: 1,
            capture_ts_us: 0,
            monitor_index: monitor,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: payload.len() as u32,
        };
        (header, payload)
    }

    #[test]
    fn each_monitor_is_composed_at_its_origin() {
        let (mut c, slot) = composer();
        let (h, p) = packet(1, 64, 64, 9);
        c.packet(&h, &p).unwrap();
        let update = slot.lock().unwrap().take().unwrap();
        assert_eq!((update.frame.width, update.frame.height), (192, 64));
        assert_eq!(
            update.dirty,
            vec![DirtyRect {
                x: 128,
                y: 0,
                width: 64,
                height: 64
            }]
        );
        let at = |x: u32, y: u32| update.frame.bgra[((y * 192 + x) * 4) as usize];
        assert_eq!(at(127, 10), 0, "el monitor 0 sigue en negro");
        assert_eq!(at(128, 10), 9);
    }

    #[test]
    fn a_frame_that_does_not_fit_the_topology_is_held_without_closing() {
        let (mut c, slot) = composer();
        let (h, p) = packet(1, 128, 64, 1);
        assert!(c.packet(&h, &p).is_ok(), "no cierra la sesion");
        assert!(slot.lock().unwrap().is_none(), "no se compone");
    }

    fn delta(monitor: u8, w: u32, h: u32, px: u8) -> (VideoPacketHeader, Vec<u8>) {
        let (mut header, payload) = packet(monitor, w, h, px);
        header.is_keyframe = false;
        (header, payload)
    }

    #[test]
    fn a_keyframe_that_arrives_before_its_topology_is_applied_when_it_arrives() {
        let (mut c, slot) = composer();
        // El monitor 1 crece a 128x64: el fotograma clave llega antes que el aviso.
        let (k, kp) = packet(1, 128, 64, 5);
        let (d, dp) = delta(1, 128, 64, 6);
        c.packet(&k, &kp).unwrap();
        c.packet(&d, &dp).unwrap();
        assert!(slot.lock().unwrap().is_none());
        let mut grown = monitors();
        grown[1].width_px = 128;
        c.set_monitors(&grown).unwrap();
        let update = slot.lock().unwrap().take().unwrap();
        assert_eq!((update.frame.width, update.frame.height), (256, 64));
        let at = |x: u32| update.frame.bgra[((10 * 256 + x) * 4) as usize];
        assert_eq!(at(130), 6, "clave y parcial reaplicados en orden");
        assert_eq!(at(10), 0);
    }

    #[test]
    fn after_a_new_topology_partial_frames_wait_for_a_keyframe() {
        let (mut c, slot) = composer();
        let mut shrunk = monitors();
        shrunk[0].width_px = 64;
        shrunk[1].origin_x = 64;
        c.set_monitors(&shrunk).unwrap();
        let (d, dp) = delta(0, 64, 64, 3);
        c.packet(&d, &dp).unwrap();
        assert!(
            slot.lock().unwrap().is_none(),
            "parcial sin clave: descartado"
        );
        let (k, kp) = packet(0, 64, 64, 4);
        c.packet(&k, &kp).unwrap();
        let update = slot.lock().unwrap().take().unwrap();
        assert_eq!((update.frame.width, update.frame.height), (128, 64));
        assert_eq!(update.frame.bgra[0], 4);
        c.packet(&d, &dp).unwrap();
        assert!(
            slot.lock().unwrap().is_some(),
            "tras la clave los parciales pasan"
        );
    }

    #[test]
    fn an_unchanged_monitor_keyframe_before_the_notice_keeps_accepting_partials() {
        let (mut c, slot) = composer();
        let (k0, kp0) = packet(0, 128, 64, 2);
        c.packet(&k0, &kp0).unwrap();
        // Llega la clave forzada del monitor 0 (sin cambios) antes del aviso que agrega otro.
        let (k, kp) = packet(0, 128, 64, 3);
        c.packet(&k, &kp).unwrap();
        slot.lock().unwrap().take();
        let mut moved = monitors();
        moved[0].origin_x = 64;
        moved[1].origin_x = 0;
        c.set_monitors(&moved).unwrap();
        let update = slot
            .lock()
            .unwrap()
            .take()
            .expect("se recompone la imagen conservada");
        let at = |f: &DecodedFrame, x: u32| f.bgra[((10 * f.width + x) * 4) as usize];
        assert_eq!(at(&update.frame, 64), 3, "monitor 0 en su origen nuevo");
        assert_eq!(at(&update.frame, 10), 0, "monitor 1 espera su clave");
        // El parcial siguiente del monitor sin cambios se compone sin otra clave.
        let (d, dp) = delta(0, 128, 64, 9);
        c.packet(&d, &dp).unwrap();
        let update = slot.lock().unwrap().take().expect("el parcial se compone");
        assert_eq!(at(&update.frame, 64), 9);
    }

    #[test]
    fn many_empty_held_records_are_bounded() {
        let (mut c, _) = composer();
        let header = VideoPacketHeader {
            frame_seq: 1,
            capture_ts_us: 0,
            monitor_index: 9,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: 0,
        };
        c.packet(&header, &[]).unwrap();
        let delta_header = VideoPacketHeader {
            is_keyframe: false,
            ..header
        };
        for _ in 0..(MAX_PENDING_PACKETS * 4) {
            c.packet(&delta_header, &[]).unwrap();
            assert!(c.pending_packets <= MAX_PENDING_PACKETS);
            assert!(c.pending_cost <= MAX_PENDING_VIDEO_BYTES);
        }
        let held: usize = c.pending.values().map(Vec::len).sum();
        assert_eq!(held, c.pending_packets);
    }

    #[test]
    fn a_new_monitor_count_is_composed_after_its_topology() {
        let (mut c, slot) = composer();
        let (k, kp) = packet(2, 32, 32, 8);
        c.packet(&k, &kp).unwrap();
        let mut three = monitors();
        three.push(MonitorDescriptor {
            index: 2,
            is_primary: false,
            origin_x: 192,
            origin_y: 0,
            width_px: 32,
            height_px: 32,
            dpi_scale_percent: 100,
        });
        c.set_monitors(&three).unwrap();
        let update = slot.lock().unwrap().take().unwrap();
        assert_eq!(update.frame.width, 224);
        assert_eq!(update.frame.bgra[(200 * 4) as usize], 8);
    }

    #[test]
    fn header_payload_len_must_match_the_payload() {
        let (mut c, _) = composer();
        let (mut h, p) = packet(0, 128, 64, 1);
        h.payload_len += 1;
        assert!(c.packet(&h, &p).is_err());
    }

    #[test]
    fn unknown_monitor_waits_and_oversized_desktops_are_rejected() {
        let (mut c, slot) = composer();
        let (h, p) = packet(7, 64, 64, 1);
        assert!(c.packet(&h, &p).is_ok());
        assert!(slot.lock().unwrap().is_none());
        let mut wide = monitors();
        wide[1].width_px = MAX_FRAME_DIMENSION;
        assert!(c.set_monitors(&wide).is_err());
    }
}
