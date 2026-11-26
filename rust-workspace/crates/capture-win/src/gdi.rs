//! Respaldo GDI (`BitBlt`) cuando DXGI Desktop Duplication no está disponible, y utilidades de
//! monitor compartidas con el backend DXGI.

use std::ffi::c_void;

use awawa_protocol::MonitorDescriptor;
use windows::Win32::Foundation::{LPARAM, RECT};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, EnumDisplayMonitors, GetDC, GetMonitorInfoW, HDC,
    HGDIOBJ, HMONITOR, MONITORINFO, ReleaseDC, SRCCOPY, SelectObject,
};
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows::core::BOOL;

use crate::{CaptureError, CapturedDesktopFrame, DesktopCaptureBackend, DirtyRect};

const MONITORINFOF_PRIMARY: u32 = 1;

/// `(rcMonitor, es_principal)` del monitor.
pub(crate) fn monitor_info(monitor: HMONITOR) -> Option<(RECT, bool)> {
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` es un MONITORINFO válido con `cbSize` inicializado.
    let ok = unsafe { GetMonitorInfoW(monitor, &mut info) };
    ok.as_bool()
        .then_some((info.rcMonitor, info.dwFlags & MONITORINFOF_PRIMARY != 0))
}

pub(crate) fn monitor_descriptor(
    index: u8,
    monitor: HMONITOR,
    rect: RECT,
    is_primary: bool,
) -> MonitorDescriptor {
    let (mut dpi_x, mut dpi_y) = (0u32, 0u32);
    // SAFETY: punteros a variables locales válidas.
    let dpi_scale_percent =
        match unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) } {
            Ok(()) if dpi_x > 0 => u16::try_from(dpi_x * 100 / 96).unwrap_or(u16::MAX),
            _ => 100,
        };
    MonitorDescriptor {
        index,
        is_primary,
        origin_x: rect.left,
        origin_y: rect.top,
        width_px: u32::try_from(rect.right - rect.left).unwrap_or(0),
        height_px: u32::try_from(rect.bottom - rect.top).unwrap_or(0),
        dpi_scale_percent,
    }
}

unsafe extern "system" fn collect_monitor(
    monitor: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    data: LPARAM,
) -> BOOL {
    // SAFETY: `data` apunta al Vec local de `enumerate_gdi_monitors`, vivo durante la enumeración.
    let handles = unsafe { &mut *(data.0 as *mut Vec<HMONITOR>) };
    handles.push(monitor);
    BOOL::from(true)
}

fn enumerate_gdi_monitors() -> Result<Vec<MonitorDescriptor>, CaptureError> {
    let mut handles: Vec<HMONITOR> = Vec::new();
    // SAFETY: el callback solo escribe en `handles`, que sobrevive a la llamada.
    let ok = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(collect_monitor),
            LPARAM(&mut handles as *mut Vec<HMONITOR> as isize),
        )
    };
    if !ok.as_bool() {
        return Err(CaptureError::BackendFailure(
            "EnumDisplayMonitors fallo".to_string(),
        ));
    }
    let mut monitors = Vec::new();
    for handle in handles {
        let Ok(index) = u8::try_from(monitors.len()) else {
            break;
        };
        if let Some((rect, is_primary)) = monitor_info(handle) {
            monitors.push(monitor_descriptor(index, handle, rect, is_primary));
        }
    }
    Ok(monitors)
}

/// Captura por `BitBlt` del escritorio actual del proceso. Cada fotograma es completo.
pub struct GdiBitBltCapture {
    monitors: Vec<MonitorDescriptor>,
    frame_seq: u64,
}

impl GdiBitBltCapture {
    pub(crate) fn open() -> Result<Self, CaptureError> {
        let monitors = enumerate_gdi_monitors()?;
        if monitors.is_empty() {
            return Err(CaptureError::BackendFailure(
                "GDI: sin monitores".to_string(),
            ));
        }
        Ok(Self {
            monitors,
            frame_seq: 0,
        })
    }
}

impl DesktopCaptureBackend for GdiBitBltCapture {
    fn enumerate_monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError> {
        Ok(self.monitors.clone())
    }

    fn grab_next_frame(&mut self, monitor_index: u8) -> Result<CapturedDesktopFrame, CaptureError> {
        let monitor = self
            .monitors
            .get(usize::from(monitor_index))
            .ok_or_else(|| {
                CaptureError::BackendFailure(format!("GDI: monitor {monitor_index} inexistente"))
            })?;
        let (width, height) = (monitor.width_px, monitor.height_px);
        if width == 0 || height == 0 {
            return Err(CaptureError::BackendFailure(
                "GDI: monitor sin area".to_string(),
            ));
        }
        let bgra = bitblt_region(monitor.origin_x, monitor.origin_y, width, height)?;
        self.frame_seq += 1;
        Ok(CapturedDesktopFrame {
            frame_seq: self.frame_seq,
            monitor_index,
            width,
            height,
            dirty_rects: vec![DirtyRect {
                x: 0,
                y: 0,
                width,
                height,
            }],
            move_rects: Vec::new(),
            pointer: None,
            bgra_payload: bgra,
        })
    }
}

fn bitblt_region(x: i32, y: i32, width: u32, height: u32) -> Result<Vec<u8>, CaptureError> {
    let fail = |what: &str| CaptureError::BackendFailure(format!("GDI: {what} fallo"));
    let (w, h) = (
        i32::try_from(width).map_err(|_| fail("ancho"))?,
        i32::try_from(height).map_err(|_| fail("alto"))?,
    );
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: cada handle GDI se libera en orden inverso a su creación en esta misma función;
    // `bits` lo asigna CreateDIBSection para un DIB top-down de 32 bpp (stride = ancho * 4).
    unsafe {
        let screen = GetDC(None);
        if screen.is_invalid() {
            return Err(fail("GetDC"));
        }
        let memory = CreateCompatibleDC(Some(screen));
        let mut bits: *mut c_void = std::ptr::null_mut();
        let result = match CreateDIBSection(Some(memory), &info, DIB_RGB_COLORS, &mut bits, None, 0)
        {
            Ok(bitmap) => {
                let previous = SelectObject(memory, HGDIOBJ(bitmap.0));
                let blit = BitBlt(memory, 0, 0, w, h, Some(screen), x, y, SRCCOPY | CAPTUREBLT);
                let pixels = match blit {
                    Ok(()) if !bits.is_null() => Ok(std::slice::from_raw_parts(
                        bits as *const u8,
                        width as usize * height as usize * 4,
                    )
                    .to_vec()),
                    _ => Err(fail("BitBlt")),
                };
                SelectObject(memory, previous);
                let _ = DeleteObject(HGDIOBJ(bitmap.0));
                pixels
            }
            Err(_) => Err(fail("CreateDIBSection")),
        };
        let _ = DeleteDC(memory);
        ReleaseDC(None, screen);
        result
    }
}
