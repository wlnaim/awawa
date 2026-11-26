//! Backends reales del host para la red: captura DXGI/GDI + codec de tiles, despachador
//! `SendInput` con consentimiento, sonda del escritorio de entrada y foco de ventanas protegidas.

use std::ffi::c_void;
use std::time::Instant;

use awawa_protocol::{
    ApprovedActiveSession, DesktopSessionMonitor, HostToClientMessage, InputDesktopKind,
    MonitorDescriptor, RemoteInputCommand, SessionRevocation,
};
use capture_win::{
    CaptureError, ConsentGatedCapturer, CursorShapeChange, DesktopCaptureBackend, TileEncoder,
    cursor_shape_to_bgra,
};
use input_win::{
    ConsentGatedInputDispatcher, PeripheralBackend, ProtectedWindowGuard, WindowProbe,
};
use windows::Win32::UI::WindowsAndMessaging::{GA_ROOT, GetAncestor, GetForegroundWindow};

use crate::gate::InputSink;
use crate::net::{SourceError, SourcePacket, VideoSource};

impl<B: PeripheralBackend + Send> InputSink for ConsentGatedInputDispatcher<B> {
    fn enable_heartbeat(&mut self, now: Instant) {
        ConsentGatedInputDispatcher::enable_heartbeat(self, now);
    }

    fn record_ping(&mut self, now: Instant) {
        ConsentGatedInputDispatcher::record_ping(self, now);
    }

    fn tick_heartbeat(&mut self, session: &mut ApprovedActiveSession, now: Instant) -> bool {
        ConsentGatedInputDispatcher::tick_heartbeat(self, session, now)
    }

    fn dispatch(
        &mut self,
        session: &mut ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        cmd: &RemoteInputCommand,
    ) -> Result<(), String> {
        self.dispatch_authorized(session, desktop, cmd)
            .map_err(|e| format!("{e:?}"))
    }

    fn release_held_input(&mut self, session: &mut ApprovedActiveSession) {
        ConsentGatedInputDispatcher::release_held_input(self, session);
    }

    fn flush_revocation_releases(&mut self, revocation: &SessionRevocation) {
        ConsentGatedInputDispatcher::flush_revocation_releases(self, revocation);
    }
}

/// Fuente de video sobre cualquier backend de captura, siempre detras de `ConsentGatedCapturer`.
pub struct CaptureSource<B: DesktopCaptureBackend> {
    capturer: ConsentGatedCapturer<B>,
    encoder: TileEncoder,
    probe: fn() -> InputDesktopKind,
}

impl<B: DesktopCaptureBackend> CaptureSource<B> {
    pub fn new(
        capturer: ConsentGatedCapturer<B>,
        probe: fn() -> InputDesktopKind,
    ) -> Result<Self, String> {
        Ok(Self {
            capturer,
            encoder: TileEncoder::new().map_err(|e| format!("{e:?}"))?,
            probe,
        })
    }
}

/// `CursorShapeUpdate` con la forma ya en BGRA de alfa recto.
fn cursor_update(change: CursorShapeChange) -> Option<HostToClientMessage> {
    let (width, height, hotspot_x, hotspot_y, bgra_zstd) = match change.shape {
        Some(shape) => {
            let bgra = cursor_shape_to_bgra(&shape).ok()?;
            let packed = zstd::bulk::compress(&bgra.bgra, 1).ok()?;
            (
                bgra.width,
                bgra.height,
                bgra.hotspot_x,
                bgra.hotspot_y,
                Some(packed),
            )
        }
        None => (0, 0, 0, 0, None),
    };
    Some(HostToClientMessage::CursorShapeUpdate {
        cursor_hash: change.hash,
        hotspot_x: u16::try_from(hotspot_x).ok()?,
        hotspot_y: u16::try_from(hotspot_y).ok()?,
        width: u16::try_from(width).ok()?,
        height: u16::try_from(height).ok()?,
        bgra_zstd,
    })
}

impl<B: DesktopCaptureBackend> VideoSource for CaptureSource<B> {
    fn monitors(&mut self) -> Vec<MonitorDescriptor> {
        self.capturer.monitors().unwrap_or_default()
    }

    fn probe_input_desktop(&mut self) -> InputDesktopKind {
        (self.probe)()
    }

    fn next_packet(
        &mut self,
        session: &ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        monitor_index: u8,
        keyframe: bool,
    ) -> Result<Option<SourcePacket>, SourceError> {
        let frame = match self
            .capturer
            .capture_authorized_frame(session, desktop, monitor_index)
        {
            Ok(frame) => frame,
            Err(CaptureError::SecureDesktopOrUacActive) => return Err(SourceError::SecureDesktop),
            Err(e) => return Err(SourceError::Failed(format!("{e:?}"))),
        };
        let cursor = frame
            .pointer
            .and_then(|p| p.shape_change)
            .and_then(cursor_update);
        let payload = if keyframe {
            self.encoder
                .encode_keyframe(frame.width, frame.height, &frame.bgra_payload)
        } else if frame.dirty_rects.is_empty() {
            // Sin cambios de imagen: solo la forma del puntero, si cambio.
            return Ok(cursor.map(|c| SourcePacket {
                payload: Vec::new(),
                width: frame.width,
                height: frame.height,
                cursor: Some(c),
            }));
        } else {
            self.encoder.encode_rects(
                frame.width,
                frame.height,
                &frame.bgra_payload,
                &frame.dirty_rects,
            )
        }
        .map_err(|e| SourceError::Failed(format!("{e:?}")))?;
        Ok(Some(SourcePacket {
            payload,
            width: frame.width,
            height: frame.height,
            cursor,
        }))
    }
}

const DESKTOP_READOBJECTS: u32 = 0x0001;
const UOI_NAME: i32 = 2;

#[link(name = "user32")]
unsafe extern "system" {
    fn OpenInputDesktop(dw_flags: u32, f_inherit: i32, dw_desired_access: u32) -> *mut c_void;
    fn CloseDesktop(h_desktop: *mut c_void) -> i32;
    fn GetUserObjectInformationW(
        h_obj: *mut c_void,
        n_index: i32,
        pv_info: *mut c_void,
        n_length: u32,
        lpn_length_needed: *mut u32,
    ) -> i32;
}

/// Escritorio que recibe la entrada (`Default` es el del usuario). Nunca se adjunta al escritorio
/// seguro: solo lee su nombre. Un fallo de apertura cuenta como inaccesible (suspende).
pub fn probe_input_desktop() -> InputDesktopKind {
    // SAFETY: parametros documentados; devuelve un manejador propio que se cierra abajo, o nulo.
    let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if desktop.is_null() {
        return InputDesktopKind::Inaccessible;
    }
    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    // SAFETY: `desktop` es valido con DESKTOP_READOBJECTS; `buf` y `needed` son destinos validos.
    let ok = unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_NAME,
            buf.as_mut_ptr().cast(),
            size_of_val(&buf) as u32,
            &mut needed,
        )
    };
    // SAFETY: `desktop` se abrio arriba y no se usa despues.
    unsafe { CloseDesktop(desktop) };
    if ok == 0 {
        return InputDesktopKind::Inaccessible;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if String::from_utf16_lossy(&buf[..len]).eq_ignore_ascii_case("Default") {
        InputDesktopKind::Default
    } else {
        InputDesktopKind::SecureOrOther
    }
}

/// Sonda que responde con la ventana de primer plano para cualquier punto: permite preguntar a la
/// guardia si el foco esta en una ventana protegida.
struct ForegroundProbe;

impl WindowProbe for ForegroundProbe {
    fn root_window_at(&self, _x: i32, _y: i32) -> Option<isize> {
        // SAFETY: llamadas Win32 sin punteros; un HWND nulo indica que no hay ventana.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0.is_null() {
            return None;
        }
        // SAFETY: `hwnd` lo acaba de devolver el sistema; si ya no es valido devuelve nulo.
        let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
        Some(if root.0.is_null() { hwnd } else { root }.0 as isize)
    }

    fn cursor_position(&self) -> Option<(i32, i32)> {
        None
    }
}

/// `true` si una ventana registrada en la guardia tiene el foco del teclado.
pub fn protected_window_focused(guard: &ProtectedWindowGuard) -> bool {
    guard.is_point_protected(&ForegroundProbe, 0, 0)
}
