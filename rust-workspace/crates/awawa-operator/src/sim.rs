//! Transporte simulado para ejercitar la UI sin red (solo pruebas; la red real es `relay_transport`).
//!
//! Un hilo hace de "host": anuncia la espera de aprobacion con un SAS, aprueba / rechaza / no
//! responde segun el escenario y, tras aprobar, emite fotogramas sinteticos que pasan por
//! `TileEncoder` -> `TileDecoder`, un RTT de ejemplo y un marcador que sigue al cursor recibido
//! (permite comprobar a simple vista el mapeo de coordenadas). Antes de aprobar descarta la
//! entrada y no emite fotogramas.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use awawa_protocol::{MonitorDescriptor, RemoteInputCommand, VirtualDesktopBounds};
use capture_win::{DecodedFrame, DirtyRect, TileDecoder, TileEncoder};

use crate::form::ConnectionParams;
use crate::transport::{FrameUpdate, OperatorTransport, TransportEvent};

const MONITOR_W: u32 = 640;
const MONITOR_H: u32 = 360;
const FRAME_INTERVAL: Duration = Duration::from_millis(66);
const AWAITING_DELAY: Duration = Duration::from_millis(600);
const DECISION_DELAY: Duration = Duration::from_millis(4_000);
const RTT_INTERVAL: Duration = Duration::from_millis(1_000);
const REVOKE_AFTER: Duration = Duration::from_millis(15_000);
const SIM_APPROVAL_TIMEOUT_SECS: u16 = 60;
const SIM_SAS: &str = "A7K29F";
const BOX: u32 = 48;
const CURSOR: u32 = 9;

/// Resultado que simula el usuario del equipo remoto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimScenario {
    Approve,
    Reject,
    /// El usuario no responde: vence la cuenta regresiva del operador.
    NoResponse,
    /// Aprueba y, tras unos segundos, revoca el control.
    Revoke,
}

impl SimScenario {
    pub fn parse(arg: &str) -> Option<Self> {
        match arg {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            "timeout" => Some(Self::NoResponse),
            "revoke" => Some(Self::Revoke),
            _ => None,
        }
    }
}

type FrameSlot = Arc<Mutex<Option<FrameUpdate>>>;

enum Command {
    Input(RemoteInputCommand),
    Disconnect,
}

pub struct SimulatedTransport {
    commands: Sender<Command>,
    events: Receiver<TransportEvent>,
    /// Ultimo fotograma pendiente: si la UI no consume, los nuevos se fusionan en vez de encolarse.
    frames: FrameSlot,
    worker: Option<JoinHandle<()>>,
}

impl SimulatedTransport {
    pub fn spawn(_params: ConnectionParams, ctx: egui::Context, scenario: SimScenario) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let frames = FrameSlot::default();
        let worker_frames = Arc::clone(&frames);
        let worker = thread::spawn(move || run_host(scenario, cmd_rx, evt_tx, worker_frames, ctx));
        Self {
            commands: cmd_tx,
            events: evt_rx,
            frames,
            worker: Some(worker),
        }
    }
}

impl OperatorTransport for SimulatedTransport {
    fn send_input(&mut self, command: RemoteInputCommand) {
        let _ = self.commands.send(Command::Input(command));
    }

    fn disconnect(&mut self) {
        let _ = self.commands.send(Command::Disconnect);
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        // Primero los eventos de control (Approved llega antes que cualquier fotograma).
        if let Ok(event) = self.events.try_recv() {
            return Some(event);
        }
        let pending = self.frames.lock().ok()?.take();
        pending.map(TransportEvent::Frame)
    }
}

impl Drop for SimulatedTransport {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Disconnect);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn sim_monitors() -> Vec<MonitorDescriptor> {
    (0..2u8)
        .map(|i| MonitorDescriptor {
            index: i,
            is_primary: i == 0,
            origin_x: i32::from(i) * MONITOR_W as i32,
            origin_y: 0,
            width_px: MONITOR_W,
            height_px: MONITOR_H,
            dpi_scale_percent: 100,
        })
        .collect()
}

/// Color BGRA del fondo: degradado azul en el monitor 0 y verde en el 1, con cuadricula.
fn background_pixel(x: u32, y: u32) -> [u8; 4] {
    let monitor = x / MONITOR_W;
    let lx = x % MONITOR_W;
    if lx == 0 || y == 0 || lx == MONITOR_W - 1 || y == MONITOR_H - 1 {
        return [255, 255, 255, 255];
    }
    if lx.is_multiple_of(80) || y.is_multiple_of(80) {
        return [90, 90, 90, 255];
    }
    let shade = (40 + (y * 120 / MONITOR_H)) as u8;
    if monitor == 0 {
        [shade + 60, shade / 2, shade / 4, 255]
    } else {
        [shade / 4, shade + 60, shade / 2, 255]
    }
}

struct Canvas {
    width: u32,
    height: u32,
    bgra: Vec<u8>,
}

impl Canvas {
    fn new(width: u32, height: u32) -> Self {
        let mut c = Self {
            width,
            height,
            bgra: vec![0; width as usize * height as usize * 4],
        };
        c.paint_background(full_rect(width, height));
        c
    }

    fn put(&mut self, x: u32, y: u32, px: [u8; 4]) {
        let i = (y as usize * self.width as usize + x as usize) * 4;
        self.bgra[i..i + 4].copy_from_slice(&px);
    }

    fn paint_background(&mut self, r: DirtyRect) {
        for y in r.y..(r.y + r.height).min(self.height) {
            for x in r.x..(r.x + r.width).min(self.width) {
                self.put(x, y, background_pixel(x, y));
            }
        }
    }

    fn fill(&mut self, r: DirtyRect, px: [u8; 4]) {
        for y in r.y..(r.y + r.height).min(self.height) {
            for x in r.x..(r.x + r.width).min(self.width) {
                self.put(x, y, px);
            }
        }
    }
}

fn full_rect(width: u32, height: u32) -> DirtyRect {
    DirtyRect {
        x: 0,
        y: 0,
        width,
        height,
    }
}

fn square(cx: u32, cy: u32, size: u32, w: u32, h: u32) -> DirtyRect {
    let x = cx.saturating_sub(size / 2).min(w.saturating_sub(size));
    let y = cy.saturating_sub(size / 2).min(h.saturating_sub(size));
    DirtyRect {
        x,
        y,
        width: size,
        height: size,
    }
}

/// Simula el host: estado del escritorio sintetico y el cursor recibido.
struct SimDesktop {
    canvas: Canvas,
    bounds: VirtualDesktopBounds,
    encoder: TileEncoder,
    decoder: TileDecoder,
    decoded: DecodedFrame,
    box_x: u32,
    cursor: (u32, u32),
    cursor_rect: DirtyRect,
    box_rect: DirtyRect,
}

impl SimDesktop {
    fn new(monitors: &[MonitorDescriptor]) -> Option<Self> {
        let bounds = VirtualDesktopBounds::from_monitors(monitors)?;
        let (w, h) = (bounds.width, bounds.height);
        let cursor = (w / 2, h / 2);
        let cursor_rect = square(cursor.0, cursor.1, CURSOR, w, h);
        Some(Self {
            canvas: Canvas::new(w, h),
            bounds,
            encoder: TileEncoder::new().ok()?,
            decoder: TileDecoder::new().ok()?,
            decoded: DecodedFrame::new(w, h),
            box_x: 0,
            cursor,
            cursor_rect,
            box_rect: square(BOX, h / 4, BOX, w, h),
        })
    }

    fn apply_input(&mut self, cmd: &RemoteInputCommand) {
        if let RemoteInputCommand::MoveCursor { norm_x, norm_y } = cmd {
            let (w, h) = (self.bounds.width, self.bounds.height);
            let x = (u64::from(*norm_x) * u64::from(w - 1) / 65_535) as u32;
            let y = (u64::from(*norm_y) * u64::from(h - 1) / 65_535) as u32;
            self.cursor = (x, y);
        }
    }

    fn keyframe(&mut self) -> Option<FrameUpdate> {
        let payload = self
            .encoder
            .encode_keyframe(self.canvas.width, self.canvas.height, &self.canvas.bgra)
            .ok()?;
        self.decode(&payload)
    }

    /// Avanza la animacion y devuelve solo las regiones cambiadas.
    fn next_frame(&mut self) -> Option<FrameUpdate> {
        let (w, h) = (self.canvas.width, self.canvas.height);
        self.box_x = (self.box_x + 8) % (w - BOX);
        let old_box = self.box_rect;
        let old_cursor = self.cursor_rect;
        self.box_rect = DirtyRect {
            x: self.box_x,
            y: old_box.y,
            width: BOX,
            height: BOX,
        };
        self.cursor_rect = square(self.cursor.0, self.cursor.1, CURSOR, w, h);

        let dirty = [old_box, self.box_rect, old_cursor, self.cursor_rect];
        for r in dirty {
            self.canvas.paint_background(r);
        }
        self.canvas.fill(self.box_rect, [40, 200, 255, 255]);
        self.canvas.fill(self.cursor_rect, [0, 0, 255, 255]);

        let payload = self
            .encoder
            .encode_rects(w, h, &self.canvas.bgra, &dirty)
            .ok()?;
        self.decode(&payload)
    }

    fn decode(&mut self, payload: &[u8]) -> Option<FrameUpdate> {
        let dirty = self.decoder.decode_into(payload, &mut self.decoded).ok()?;
        Some(FrameUpdate {
            frame: self.decoded.clone(),
            dirty,
        })
    }
}

/// Devuelve `false` si el receptor de eventos ya no existe.
/// Deja un fotograma pendiente fusionandolo con el anterior si la UI aun no lo consumio.
fn push_frame(slot: &FrameSlot, ctx: &egui::Context, update: FrameUpdate) {
    if let Ok(mut pending) = slot.lock() {
        *pending = Some(match pending.take() {
            Some(older) => older.merge(update),
            None => update,
        });
    }
    ctx.request_repaint();
}

fn emit(events: &Sender<TransportEvent>, ctx: &egui::Context, event: TransportEvent) -> bool {
    let alive = events.send(event).is_ok();
    ctx.request_repaint();
    alive
}

fn run_host(
    scenario: SimScenario,
    commands: Receiver<Command>,
    events: Sender<TransportEvent>,
    frames: FrameSlot,
    ctx: egui::Context,
) {
    let start = Instant::now();
    let mut announced = false;
    let mut desktop: Option<SimDesktop> = None;
    let mut decided = false;
    let mut next_frame = Duration::ZERO;
    let mut next_rtt = Duration::ZERO;
    let mut rtt_n: u64 = 0;

    loop {
        match commands.recv_timeout(Duration::from_millis(20)) {
            Ok(Command::Disconnect) | Err(RecvTimeoutError::Disconnected) => return,
            Ok(Command::Input(cmd)) => {
                // Antes de la aprobacion no existe escritorio: la entrada se descarta.
                if let Some(d) = desktop.as_mut() {
                    d.apply_input(&cmd);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        let t = start.elapsed();
        if !announced && t >= AWAITING_DELAY {
            announced = true;
            let event = TransportEvent::AwaitingApproval {
                timeout_secs: SIM_APPROVAL_TIMEOUT_SECS,
                sas: SIM_SAS.to_string(),
            };
            if !emit(&events, &ctx, event) {
                return;
            }
        }

        if !decided && t >= DECISION_DELAY {
            match scenario {
                SimScenario::Approve | SimScenario::Revoke => {
                    decided = true;
                    let monitors = sim_monitors();
                    desktop = SimDesktop::new(&monitors);
                    if !emit(&events, &ctx, TransportEvent::Approved { monitors }) {
                        return;
                    }
                    if let Some(first) = desktop.as_mut().and_then(SimDesktop::keyframe) {
                        push_frame(&frames, &ctx, first);
                    }
                    next_frame = t + FRAME_INTERVAL;
                    next_rtt = t;
                }
                SimScenario::Reject => {
                    decided = true;
                    let event = TransportEvent::Rejected {
                        reason: "El usuario rechazó la solicitud.".to_string(),
                    };
                    if !emit(&events, &ctx, event) {
                        return;
                    }
                }
                SimScenario::NoResponse => decided = true,
            }
        }

        if scenario == SimScenario::Revoke
            && desktop.is_some()
            && t >= DECISION_DELAY + REVOKE_AFTER
        {
            let event = TransportEvent::Disconnected {
                reason: "El usuario revocó el control.".to_string(),
            };
            emit(&events, &ctx, event);
            return;
        }

        if let Some(d) = desktop.as_mut() {
            if t >= next_frame {
                next_frame = t + FRAME_INTERVAL;
                if let Some(update) = d.next_frame() {
                    push_frame(&frames, &ctx, update);
                }
            }
            if t >= next_rtt {
                next_rtt = t + RTT_INTERVAL;
                rtt_n += 1;
                let rtt = Duration::from_millis(18 + rtt_n % 7);
                if !emit(&events, &ctx, TransportEvent::Rtt(rtt)) {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_parsing() {
        assert_eq!(SimScenario::parse("approve"), Some(SimScenario::Approve));
        assert_eq!(SimScenario::parse("reject"), Some(SimScenario::Reject));
        assert_eq!(SimScenario::parse("timeout"), Some(SimScenario::NoResponse));
        assert_eq!(SimScenario::parse("revoke"), Some(SimScenario::Revoke));
        assert_eq!(SimScenario::parse("otro"), None);
    }

    #[test]
    fn sim_monitors_form_a_valid_two_monitor_desktop() {
        let ms = sim_monitors();
        let d = VirtualDesktopBounds::from_monitors(&ms).unwrap();
        assert_eq!((d.width, d.height), (MONITOR_W * 2, MONITOR_H));
    }

    #[test]
    fn synthetic_frames_survive_the_tile_codec_round_trip() {
        let mut d = SimDesktop::new(&sim_monitors()).unwrap();
        let first = d.keyframe().unwrap();
        assert_eq!(first.frame.bgra, d.canvas.bgra);
        for _ in 0..5 {
            let update = d.next_frame().unwrap();
            assert!(!update.dirty.is_empty());
            assert_eq!(update.frame.bgra, d.canvas.bgra);
        }
    }

    #[test]
    fn simulated_host_cursor_follows_move_commands() {
        let mut d = SimDesktop::new(&sim_monitors()).unwrap();
        d.apply_input(&RemoteInputCommand::MoveCursor {
            norm_x: 0,
            norm_y: 65_535,
        });
        assert_eq!(d.cursor, (0, MONITOR_H - 1));
        d.apply_input(&RemoteInputCommand::MoveCursor {
            norm_x: 65_535,
            norm_y: 0,
        });
        assert_eq!(d.cursor, (MONITOR_W * 2 - 1, 0));
    }
}
