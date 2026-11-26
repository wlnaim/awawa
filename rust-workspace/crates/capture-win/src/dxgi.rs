//! Backend primario: DXGI Desktop Duplication (`IDXGIOutput1::DuplicateOutput`).
//!
//! - Monitores: salidas DXGI unidas al escritorio, en orden adaptador/salida.
//! - Cada fotograma copia la textura del escritorio a una textura de staging y entrega el
//!   fotograma BGRA completo junto con los dirty rects y move rects de DXGI.
//! - `DXGI_ERROR_ACCESS_LOST`: se liberan todas las duplicaciones, se esperan 150 ms, se
//!   re-enumeran las salidas y se devuelve `CaptureError::AccessLostNeedReinit` como aviso
//!   para el operador; la siguiente llamada vuelve a duplicar la salida.
//! - `DuplicateOutput` con `E_ACCESSDENIED` (escritorio seguro) se informa como
//!   `CaptureError::SecureDesktopOrUacActive`; nunca se intenta otra vía de captura.

use std::thread;
use std::time::Duration;

use awawa_protocol::MonitorDescriptor;
use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_UNSUPPORTED,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT,
    DXGI_OUTDUPL_POINTER_SHAPE_INFO, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
    IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use crate::cursor::{CursorShape, CursorShapeCache, CursorShapeKind, PointerState};
use crate::gdi::{monitor_descriptor, monitor_info};
use crate::{CaptureError, CapturedDesktopFrame, DesktopCaptureBackend, DirtyRect, MoveRect};

/// Espera tras `DXGI_ERROR_ACCESS_LOST` antes de re-enumerar.
pub const ACCESS_LOST_BACKOFF: Duration = Duration::from_millis(150);
/// Espera máxima de `AcquireNextFrame` con imagen previa disponible.
const ACQUIRE_TIMEOUT_MS: u32 = 100;
/// Espera máxima del primer fotograma tras (re)crear la duplicación.
const FIRST_ACQUIRE_TIMEOUT_MS: u32 = 1000;

pub(crate) enum DxgiFailure {
    /// DXGI Desktop Duplication no está soportado en esta sesión: procede el respaldo GDI.
    Unsupported,
    Capture(CaptureError),
}

impl From<DxgiFailure> for CaptureError {
    fn from(failure: DxgiFailure) -> Self {
        match failure {
            DxgiFailure::Unsupported => {
                CaptureError::BackendFailure("DXGI Desktop Duplication no soportado".to_string())
            }
            DxgiFailure::Capture(error) => error,
        }
    }
}

fn failure(call: &str, error: &windows::core::Error) -> DxgiFailure {
    DxgiFailure::Capture(CaptureError::BackendFailure(format!(
        "{call}: {:#010x}",
        error.code().0
    )))
}

fn failure_msg(message: &str) -> DxgiFailure {
    DxgiFailure::Capture(CaptureError::BackendFailure(message.to_string()))
}

struct OutputSlot {
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    descriptor: MonitorDescriptor,
}

struct ActiveDuplication {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    width: u32,
    height: u32,
    frame: Vec<u8>,
    needs_full_frame: bool,
    move_buf: Vec<DXGI_OUTDUPL_MOVE_RECT>,
    dirty_buf: Vec<RECT>,
    pointer_buf: Vec<u8>,
}

/// Captura DXGI Desktop Duplication. Solo se construye dentro del crate y se usa a través de
/// `ConsentGatedCapturer`, que aplica la guardia de sesión aprobada y de escritorio.
pub struct DxgiDesktopDuplication {
    outputs: Vec<OutputSlot>,
    active: Vec<Option<ActiveDuplication>>,
    frame_seq: u64,
    cursor: CursorShapeCache,
}

impl DxgiDesktopDuplication {
    pub(crate) fn open() -> Result<Self, DxgiFailure> {
        let outputs = enumerate_outputs()?;
        if outputs.is_empty() {
            return Err(DxgiFailure::Unsupported);
        }
        let mut active = Vec::new();
        active.resize_with(outputs.len(), || None);
        Ok(Self {
            outputs,
            active,
            frame_seq: 0,
            cursor: CursorShapeCache::new(),
        })
    }

    fn recover_access_lost(&mut self) {
        self.active.clear();
        thread::sleep(ACCESS_LOST_BACKOFF);
        self.outputs = enumerate_outputs().unwrap_or_default();
        self.active.resize_with(self.outputs.len(), || None);
    }

    pub(crate) fn grab(&mut self, monitor_index: u8) -> Result<CapturedDesktopFrame, DxgiFailure> {
        if self.outputs.is_empty() {
            self.outputs = enumerate_outputs()?;
            self.active.clear();
            self.active.resize_with(self.outputs.len(), || None);
        }
        let index = usize::from(monitor_index);
        let Some(slot) = self.outputs.get(index) else {
            return Err(failure_msg("DXGI: monitor inexistente"));
        };
        if self.active[index].is_none() {
            self.active[index] = Some(start_duplication(slot)?);
        }
        let Some(state) = self.active[index].as_mut() else {
            return Err(failure_msg("DXGI: duplicacion no disponible"));
        };

        let duplication = state.duplication.clone();
        let timeout = if state.width == 0 {
            FIRST_ACQUIRE_TIMEOUT_MS
        } else {
            ACQUIRE_TIMEOUT_MS
        };
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // SAFETY: punteros a variables locales válidas; el fotograma se libera con `FrameGuard`.
        let acquired = unsafe { duplication.AcquireNextFrame(timeout, &mut info, &mut resource) };
        if let Err(error) = acquired {
            if error.code() == DXGI_ERROR_WAIT_TIMEOUT && state.width > 0 {
                self.frame_seq += 1;
                return Ok(CapturedDesktopFrame {
                    frame_seq: self.frame_seq,
                    monitor_index,
                    width: state.width,
                    height: state.height,
                    dirty_rects: Vec::new(),
                    move_rects: Vec::new(),
                    pointer: None,
                    bgra_payload: state.frame.clone(),
                });
            }
            if error.code() == DXGI_ERROR_ACCESS_LOST {
                drop(duplication);
                self.recover_access_lost();
                return Err(DxgiFailure::Capture(CaptureError::AccessLostNeedReinit));
            }
            return Err(failure("AcquireNextFrame", &error));
        }
        let _guard = FrameGuard(&duplication);

        let mut dirty_rects = Vec::new();
        let mut move_rects = Vec::new();
        if info.LastPresentTime != 0 {
            let texture: ID3D11Texture2D = resource
                .ok_or_else(|| failure_msg("DXGI: fotograma sin textura"))?
                .cast()
                .map_err(|e| failure("IDXGIResource::cast", &e))?;
            copy_texture(state, &texture)?;
            read_metadata(
                state,
                &duplication,
                &info,
                &mut dirty_rects,
                &mut move_rects,
            )?;
        }
        if state.width == 0 {
            return Err(failure_msg("DXGI: sin fotograma inicial"));
        }
        if state.needs_full_frame {
            state.needs_full_frame = false;
            move_rects.clear();
            dirty_rects = vec![DirtyRect {
                x: 0,
                y: 0,
                width: state.width,
                height: state.height,
            }];
        }
        let pointer = read_pointer(state, &duplication, &info, &mut self.cursor)?;

        self.frame_seq += 1;
        Ok(CapturedDesktopFrame {
            frame_seq: self.frame_seq,
            monitor_index,
            width: state.width,
            height: state.height,
            dirty_rects,
            move_rects,
            pointer,
            bgra_payload: state.frame.clone(),
        })
    }
}

impl DesktopCaptureBackend for DxgiDesktopDuplication {
    fn enumerate_monitors(&self) -> Result<Vec<MonitorDescriptor>, CaptureError> {
        Ok(self
            .outputs
            .iter()
            .map(|slot| slot.descriptor.clone())
            .collect())
    }

    fn grab_next_frame(&mut self, monitor_index: u8) -> Result<CapturedDesktopFrame, CaptureError> {
        self.grab(monitor_index).map_err(CaptureError::from)
    }
}

/// Libera el fotograma adquirido al salir de alcance.
struct FrameGuard<'a>(&'a IDXGIOutputDuplication);

impl Drop for FrameGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: solo se construye tras un `AcquireNextFrame` exitoso.
        let _ = unsafe { self.0.ReleaseFrame() };
    }
}

fn enumerate_outputs() -> Result<Vec<OutputSlot>, DxgiFailure> {
    // SAFETY: llamadas COM sin punteros crudos; los errores se propagan.
    unsafe {
        let factory: IDXGIFactory1 =
            CreateDXGIFactory1().map_err(|e| failure("CreateDXGIFactory1", &e))?;
        let mut slots = Vec::new();
        let mut adapter_index = 0;
        loop {
            let adapter = match factory.EnumAdapters1(adapter_index) {
                Ok(adapter) => adapter,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(failure("EnumAdapters1", &e)),
            };
            adapter_index += 1;
            let mut output_index = 0;
            loop {
                let output = match adapter.EnumOutputs(output_index) {
                    Ok(output) => output,
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                    Err(e) => return Err(failure("EnumOutputs", &e)),
                };
                output_index += 1;
                let desc = output.GetDesc().map_err(|e| failure("GetDesc", &e))?;
                if !desc.AttachedToDesktop.as_bool() {
                    continue;
                }
                let Ok(index) = u8::try_from(slots.len()) else {
                    return Ok(slots);
                };
                let output: IDXGIOutput1 = output.cast().map_err(|_| DxgiFailure::Unsupported)?;
                let is_primary = monitor_info(desc.Monitor).is_some_and(|(_, primary)| primary);
                let descriptor =
                    monitor_descriptor(index, desc.Monitor, desc.DesktopCoordinates, is_primary);
                slots.push(OutputSlot {
                    adapter: adapter.clone(),
                    output,
                    descriptor,
                });
            }
        }
        Ok(slots)
    }
}

fn start_duplication(slot: &OutputSlot) -> Result<ActiveDuplication, DxgiFailure> {
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;
    // SAFETY: punteros de salida a variables locales válidas.
    unsafe {
        D3D11CreateDevice(
            &slot.adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .map_err(|e| failure("D3D11CreateDevice", &e))?;
    let (Some(device), Some(context)) = (device, context) else {
        return Err(failure_msg("D3D11CreateDevice sin dispositivo"));
    };
    // SAFETY: `device` es un dispositivo D3D11 válido creado sobre el adaptador de la salida.
    let duplication = match unsafe { slot.output.DuplicateOutput(&device) } {
        Ok(duplication) => duplication,
        Err(e) if e.code() == E_ACCESSDENIED => {
            return Err(DxgiFailure::Capture(CaptureError::SecureDesktopOrUacActive));
        }
        Err(e) if e.code() == DXGI_ERROR_UNSUPPORTED => return Err(DxgiFailure::Unsupported),
        Err(e) => return Err(failure("DuplicateOutput", &e)),
    };
    Ok(ActiveDuplication {
        device,
        context,
        duplication,
        staging: None,
        width: 0,
        height: 0,
        frame: Vec::new(),
        needs_full_frame: true,
        move_buf: Vec::new(),
        dirty_buf: Vec::new(),
        pointer_buf: Vec::new(),
    })
}

fn copy_texture(
    state: &mut ActiveDuplication,
    texture: &ID3D11Texture2D,
) -> Result<(), DxgiFailure> {
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    // SAFETY: `desc` es un destino válido.
    unsafe { texture.GetDesc(&mut desc) };
    if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
        return Err(failure_msg("DXGI: formato de escritorio no BGRA8"));
    }
    let (width, height) = (desc.Width, desc.Height);
    let staging = match &state.staging {
        Some((texture, w, h)) if (*w, *h) == (width, height) => texture.clone(),
        _ => {
            let staging_desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: desc.Format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut created: Option<ID3D11Texture2D> = None;
            // SAFETY: descriptor y destino válidos.
            unsafe {
                state
                    .device
                    .CreateTexture2D(&staging_desc, None, Some(&mut created))
            }
            .map_err(|e| failure("CreateTexture2D", &e))?;
            let created = created.ok_or_else(|| failure_msg("CreateTexture2D sin textura"))?;
            state.staging = Some((created.clone(), width, height));
            created
        }
    };
    if (width, height) != (state.width, state.height) {
        state.width = width;
        state.height = height;
        state.frame = vec![0; width as usize * height as usize * 4];
        state.needs_full_frame = true;
    }

    let row_len = width as usize * 4;
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    // SAFETY: `staging` es una textura de staging legible del mismo tamaño y formato; la
    // región mapeada mide `RowPitch * height` y se desmapea antes de salir.
    unsafe {
        state.context.CopyResource(&staging, texture);
        state
            .context
            .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
            .map_err(|e| failure("Map", &e))?;
        let pitch = mapped.RowPitch as usize;
        let base = mapped.pData as *const u8;
        for y in 0..height as usize {
            let src = std::slice::from_raw_parts(base.add(y * pitch), row_len);
            state.frame[y * row_len..(y + 1) * row_len].copy_from_slice(src);
        }
        state.context.Unmap(&staging, 0);
    }
    Ok(())
}

fn clip_rect(rect: &RECT, width: u32, height: u32) -> Option<DirtyRect> {
    let clamp = |value: i32, max: u32| u32::try_from(value.max(0)).unwrap_or(0).min(max);
    let (left, top) = (clamp(rect.left, width), clamp(rect.top, height));
    let (right, bottom) = (clamp(rect.right, width), clamp(rect.bottom, height));
    (right > left && bottom > top).then_some(DirtyRect {
        x: left,
        y: top,
        width: right - left,
        height: bottom - top,
    })
}

/// Lee move rects y dirty rects. `dirty_rects` incluye también los destinos de los move rects.
fn read_metadata(
    state: &mut ActiveDuplication,
    duplication: &IDXGIOutputDuplication,
    info: &DXGI_OUTDUPL_FRAME_INFO,
    dirty_rects: &mut Vec<DirtyRect>,
    move_rects: &mut Vec<MoveRect>,
) -> Result<(), DxgiFailure> {
    let total = info.TotalMetadataBufferSize as usize;
    if total == 0 {
        return Ok(());
    }
    let (width, height) = (state.width, state.height);

    let move_size = size_of::<DXGI_OUTDUPL_MOVE_RECT>();
    state
        .move_buf
        .resize(total.div_ceil(move_size), DXGI_OUTDUPL_MOVE_RECT::default());
    let mut required = 0u32;
    // SAFETY: el búfer tiene `move_buf.len() * move_size` bytes alineados para el tipo.
    unsafe {
        duplication.GetFrameMoveRects(
            (state.move_buf.len() * move_size) as u32,
            state.move_buf.as_mut_ptr(),
            &mut required,
        )
    }
    .map_err(|e| failure("GetFrameMoveRects", &e))?;
    let moves = (required as usize / move_size).min(state.move_buf.len());
    for moved in &state.move_buf[..moves] {
        if let Some(destination) = clip_rect(&moved.DestinationRect, width, height) {
            move_rects.push(MoveRect {
                source_x: u32::try_from(moved.SourcePoint.x).unwrap_or(0),
                source_y: u32::try_from(moved.SourcePoint.y).unwrap_or(0),
                destination,
            });
            dirty_rects.push(destination);
        }
    }

    let rect_size = size_of::<RECT>();
    state
        .dirty_buf
        .resize(total.div_ceil(rect_size), RECT::default());
    let mut required = 0u32;
    // SAFETY: el búfer tiene `dirty_buf.len() * rect_size` bytes alineados para RECT.
    unsafe {
        duplication.GetFrameDirtyRects(
            (state.dirty_buf.len() * rect_size) as u32,
            state.dirty_buf.as_mut_ptr(),
            &mut required,
        )
    }
    .map_err(|e| failure("GetFrameDirtyRects", &e))?;
    let dirty = (required as usize / rect_size).min(state.dirty_buf.len());
    dirty_rects.extend(
        state.dirty_buf[..dirty]
            .iter()
            .filter_map(|rect| clip_rect(rect, width, height)),
    );
    Ok(())
}

fn read_pointer(
    state: &mut ActiveDuplication,
    duplication: &IDXGIOutputDuplication,
    info: &DXGI_OUTDUPL_FRAME_INFO,
    cursor: &mut CursorShapeCache,
) -> Result<Option<PointerState>, DxgiFailure> {
    if info.LastMouseUpdateTime == 0 {
        return Ok(None);
    }
    let mut shape_change = None;
    let len = info.PointerShapeBufferSize as usize;
    if len > 0 {
        state.pointer_buf.resize(len, 0);
        let mut required = 0u32;
        let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
        // SAFETY: búfer de `len` bytes y destinos locales válidos.
        unsafe {
            duplication.GetFramePointerShape(
                len as u32,
                state.pointer_buf.as_mut_ptr().cast(),
                &mut required,
                &mut shape_info,
            )
        }
        .map_err(|e| failure("GetFramePointerShape", &e))?;
        let kind = match shape_info.Type {
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 as u32 => {
                Some(CursorShapeKind::Monochrome)
            }
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0 as u32 => {
                Some(CursorShapeKind::Color)
            }
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR.0 as u32 => {
                Some(CursorShapeKind::MaskedColor)
            }
            _ => None,
        };
        if let Some(kind) = kind {
            shape_change = cursor.observe(CursorShape {
                kind,
                width: shape_info.Width,
                height: shape_info.Height,
                pitch: shape_info.Pitch,
                hotspot_x: u32::try_from(shape_info.HotSpot.x).unwrap_or(0),
                hotspot_y: u32::try_from(shape_info.HotSpot.y).unwrap_or(0),
                data: state.pointer_buf[..(required as usize).min(len)].to_vec(),
            });
        }
    }
    Ok(Some(PointerState {
        visible: info.PointerPosition.Visible.as_bool(),
        x: info.PointerPosition.Position.x,
        y: info.PointerPosition.Position.y,
        shape_change,
    }))
}
