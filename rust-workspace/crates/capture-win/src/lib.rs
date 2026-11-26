//! # `capture-win`
//!
//! Abstracción segura para captura de escritorio en Windows (cascada DXGI Desktop Duplication / WGC / GDI).
//! Exige una referencia a `&ApprovedActiveSession` para producir fotogramas, impidiendo capturas sin
//! consentimiento local activo, y una referencia a `&DesktopSessionMonitor` para no capturar nunca
//! mientras el escritorio seguro (UAC), el bloqueo o el fin de sesión mantienen la sesión fuera de `Streaming`.

use awawa_protocol::{ApprovedActiveSession, DesktopSessionMonitor, MonitorDescriptor};

mod cursor;
mod tiles;

#[cfg(windows)]
mod cascade;
#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
mod gdi;

pub use cursor::{
    CURSOR_CACHE_CAPACITY, CursorBgra, CursorConvertError, CursorShape, CursorShapeCache,
    CursorShapeChange, CursorShapeKind, MAX_CURSOR_DIMENSION, PointerState, cursor_shape_to_bgra,
};
pub use tiles::{
    DecodeLimits, DecodedFrame, MAX_FRAME_DIMENSION, TILE_FORMAT_VERSION, TILE_PAYLOAD_HEADER_LEN,
    TILE_SIZE, TileCodecError, TileDecoder, TileEncoder, ZSTD_LEVEL,
};

#[cfg(windows)]
pub use cascade::WindowsDesktopCapture;
#[cfg(windows)]
pub use dxgi::{ACCESS_LOST_BACKOFF, DxgiDesktopDuplication};
#[cfg(windows)]
pub use gdi::GdiBitBltCapture;

/// Aviso para el operador cuando DXGI pierde el acceso.
pub const ACCESS_LOST_OPERATOR_NOTICE: &str =
    "Escritorio temporalmente protegido por Windows UAC / Cambio de modo de video";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Región copiada por el compositor desde `(source_x, source_y)` hasta `destination`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRect {
    pub source_x: u32,
    pub source_y: u32,
    pub destination: DirtyRect,
}

/// Fotograma BGRA completo del monitor (stride = `width * 4`).
///
/// `dirty_rects` cubre todo lo que cambió respecto del fotograma anterior, incluidos los
/// destinos de `move_rects`; vacío significa sin cambios de imagen.
#[derive(Debug, Clone)]
pub struct CapturedDesktopFrame {
    pub frame_seq: u64,
    pub monitor_index: u8,
    pub width: u32,
    pub height: u32,
    pub dirty_rects: Vec<DirtyRect>,
    pub move_rects: Vec<MoveRect>,
    /// Posición y forma del puntero, solo si cambiaron en este fotograma.
    pub pointer: Option<PointerState>,
    pub bgra_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    VisualizationNotGranted,
    AccessLostNeedReinit,
    SecureDesktopOrUacActive,
    /// El monitor de escritorio/sesión no está en `Streaming` (escritorio seguro, bloqueo o sesión finalizada).
    SuspendedByDesktopState,
    BackendFailure(String),
}

impl CaptureError {
    /// Texto a mostrar al operador cuando la captura se interrumpe por Windows.
    pub fn operator_notice(&self) -> Option<&'static str> {
        match self {
            CaptureError::AccessLostNeedReinit | CaptureError::SecureDesktopOrUacActive => {
                Some(ACCESS_LOST_OPERATOR_NOTICE)
            }
            _ => None,
        }
    }
}

pub trait DesktopCaptureBackend {
    fn enumerate_monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError>;
    fn grab_next_frame(&mut self, monitor_index: u8) -> Result<CapturedDesktopFrame, CaptureError>;
}

/// Envoltorio que exige `ApprovedActiveSession` en cada cuadro capturado.
pub struct ConsentGatedCapturer<B: DesktopCaptureBackend> {
    backend: B,
}

impl<B: DesktopCaptureBackend> ConsentGatedCapturer<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn capture_authorized_frame(
        &mut self,
        session: &ApprovedActiveSession,
        desktop: &DesktopSessionMonitor,
        monitor_index: u8,
    ) -> Result<CapturedDesktopFrame, CaptureError> {
        if !desktop.capture_allowed() {
            return Err(CaptureError::SuspendedByDesktopState);
        }
        if !session.can_capture_desktop() {
            return Err(CaptureError::VisualizationNotGranted);
        }
        self.backend.grab_next_frame(monitor_index)
    }

    pub fn monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError> {
        self.backend.enumerate_monitors()
    }
}

#[cfg(windows)]
impl ConsentGatedCapturer<WindowsDesktopCapture> {
    /// Captura real de Windows (DXGI con respaldo GDI), siempre detrás de la guardia.
    pub fn open_windows() -> Result<Self, CaptureError> {
        Ok(Self::new(WindowsDesktopCapture::open()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::{
        DesktopEvent, InputDesktopKind, OperatorConnectionRequest, ScopedCapabilities,
        WaitingForRequest, run_in_memory_handshake,
    };
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct CountingBackend {
        grabs: u32,
    }

    impl DesktopCaptureBackend for CountingBackend {
        fn enumerate_monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError> {
            Ok(Vec::new())
        }

        fn grab_next_frame(
            &mut self,
            monitor_index: u8,
        ) -> Result<CapturedDesktopFrame, CaptureError> {
            self.grabs += 1;
            Ok(CapturedDesktopFrame {
                frame_seq: u64::from(self.grabs),
                monitor_index,
                width: 1,
                height: 1,
                dirty_rects: Vec::new(),
                move_rects: Vec::new(),
                pointer: None,
                bgra_payload: vec![0; 4],
            })
        }
    }

    fn approved_session() -> ApprovedActiveSession {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let t0 = Instant::now();
        let req = OperatorConnectionRequest {
            target_session_id: waiting.session_id(),
            operator_display_name: "Soporte".to_string(),
            operator_ed25519_fingerprint: [1; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };
        let password = waiting.display_password();
        run_in_memory_handshake(waiting, &req, &password, t0)
            .unwrap()
            .0
            .pending
            .approve_locally(t0 + Duration::from_secs(2), None)
            .unwrap()
    }

    #[test]
    fn capture_is_rejected_while_desktop_monitor_is_not_streaming() {
        let session = approved_session();
        let mut capturer = ConsentGatedCapturer::new(CountingBackend::default());
        let mut desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);

        assert!(
            capturer
                .capture_authorized_frame(&session, &desktop, 0)
                .is_ok()
        );

        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::SecureOrOther));
        assert_eq!(
            capturer
                .capture_authorized_frame(&session, &desktop, 0)
                .unwrap_err(),
            CaptureError::SuspendedByDesktopState
        );

        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        assert_eq!(
            capturer
                .capture_authorized_frame(&session, &desktop, 0)
                .unwrap_err(),
            CaptureError::SuspendedByDesktopState
        );
        desktop.handle(DesktopEvent::InputDesktop(InputDesktopKind::Default));
        assert!(
            capturer
                .capture_authorized_frame(&session, &desktop, 0)
                .is_ok()
        );

        desktop.handle(DesktopEvent::SessionLogoff);
        assert_eq!(
            capturer
                .capture_authorized_frame(&session, &desktop, 0)
                .unwrap_err(),
            CaptureError::SuspendedByDesktopState
        );

        // El backend solo se invocó en los dos intentos permitidos.
        assert_eq!(capturer.backend.grabs, 2);
    }

    #[test]
    fn windows_interruptions_carry_an_operator_notice() {
        assert_eq!(
            CaptureError::AccessLostNeedReinit.operator_notice(),
            Some(ACCESS_LOST_OPERATOR_NOTICE)
        );
        assert_eq!(
            CaptureError::SecureDesktopOrUacActive.operator_notice(),
            Some(ACCESS_LOST_OPERATOR_NOTICE)
        );
        assert_eq!(
            CaptureError::VisualizationNotGranted.operator_notice(),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "en vivo: captura un fotograma real del monitor principal"]
    fn live_capture_of_primary_monitor_goes_through_the_guard() {
        let session = approved_session();
        let desktop = DesktopSessionMonitor::new(InputDesktopKind::Default);
        let mut capturer = ConsentGatedCapturer::open_windows().expect("abrir la captura");
        let monitors = capturer.monitors().expect("enumerar monitores");
        let primary = monitors
            .iter()
            .find(|m| m.is_primary)
            .expect("monitor principal")
            .index;

        let mut frame = None;
        for _ in 0..5 {
            match capturer.capture_authorized_frame(&session, &desktop, primary) {
                Ok(captured) => {
                    frame = Some(captured);
                    break;
                }
                Err(CaptureError::AccessLostNeedReinit) => continue,
                Err(other) => panic!("captura fallida: {other:?}"),
            }
        }
        let frame = frame.expect("un fotograma del monitor principal");
        assert!(frame.width > 0 && frame.height > 0);
        assert_eq!(
            frame.bgra_payload.len(),
            frame.width as usize * frame.height as usize * 4
        );
        assert!(!frame.dirty_rects.is_empty());

        let payload = TileEncoder::new()
            .unwrap()
            .encode_keyframe(frame.width, frame.height, &frame.bgra_payload)
            .unwrap();
        let mut decoded = DecodedFrame::new(frame.width, frame.height);
        TileDecoder::new()
            .unwrap()
            .decode_into(&payload, &mut decoded)
            .unwrap();
        assert_eq!(decoded.bgra, frame.bgra_payload);
    }
}
