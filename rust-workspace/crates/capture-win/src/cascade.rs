//! Cascada de backends de Windows: DXGI Desktop Duplication y, si no está soportado, GDI `BitBlt`.

use awawa_protocol::MonitorDescriptor;

use crate::dxgi::{DxgiDesktopDuplication, DxgiFailure};
use crate::gdi::GdiBitBltCapture;
use crate::{CaptureError, CapturedDesktopFrame, DesktopCaptureBackend};

enum Active {
    Dxgi(DxgiDesktopDuplication),
    Gdi(GdiBitBltCapture),
}

/// Backend real de Windows. Se obtiene con `ConsentGatedCapturer::open_windows`.
pub struct WindowsDesktopCapture {
    active: Active,
}

impl WindowsDesktopCapture {
    pub(crate) fn open() -> Result<Self, CaptureError> {
        let active = match DxgiDesktopDuplication::open() {
            Ok(dxgi) => Active::Dxgi(dxgi),
            Err(_) => Active::Gdi(GdiBitBltCapture::open()?),
        };
        Ok(Self { active })
    }
}

impl DesktopCaptureBackend for WindowsDesktopCapture {
    fn enumerate_monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError> {
        match &self.active {
            Active::Dxgi(dxgi) => dxgi.enumerate_monitors(),
            Active::Gdi(gdi) => gdi.enumerate_monitors(),
        }
    }

    fn grab_next_frame(&mut self, monitor_index: u8) -> Result<CapturedDesktopFrame, CaptureError> {
        let dxgi = match &mut self.active {
            Active::Dxgi(dxgi) => dxgi,
            Active::Gdi(gdi) => return gdi.grab_next_frame(monitor_index),
        };
        match dxgi.grab(monitor_index) {
            Ok(frame) => Ok(frame),
            // Solo "no soportado" cambia a GDI; escritorio seguro y ACCESS_LOST se devuelven tal cual.
            Err(DxgiFailure::Unsupported) => {
                self.active = Active::Gdi(GdiBitBltCapture::open()?);
                self.grab_next_frame(monitor_index)
            }
            Err(DxgiFailure::Capture(error)) => Err(error),
        }
    }
}
