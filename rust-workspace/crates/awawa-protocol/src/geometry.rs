use serde::{Deserialize, Serialize};

/// Descriptor de un monitor físico reportado por el Cliente Receptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorDescriptor {
    pub index: u8,
    pub is_primary: bool,
    pub origin_x: i32,
    pub origin_y: i32,
    pub width_px: u32,
    pub height_px: u32,
    pub dpi_scale_percent: u16,
}

/// Límites del escritorio virtual combinado (`SM_XVIRTUALSCREEN..SM_CYVIRTUALSCREEN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualDesktopBounds {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}

/// Punto normalizado `[0..=65535]` requerido por `SendInput` con `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizedPoint {
    pub x: u16,
    pub y: u16,
}

impl VirtualDesktopBounds {
    pub fn from_monitors(monitors: &[MonitorDescriptor]) -> Option<Self> {
        if monitors.is_empty() {
            return None;
        }
        let mut min_x = i32::MAX;
        let mut min_y = i32::MAX;
        let mut max_x = i32::MIN;
        let mut max_y = i32::MIN;

        for m in monitors {
            min_x = min_x.min(m.origin_x);
            min_y = min_y.min(m.origin_y);
            max_x = max_x.max(m.origin_x.saturating_add(m.width_px as i32));
            max_y = max_y.max(m.origin_y.saturating_add(m.height_px as i32));
        }

        let width = u32::try_from(max_x.saturating_sub(min_x)).ok()?;
        let height = u32::try_from(max_y.saturating_sub(min_y)).ok()?;
        if width == 0 || height == 0 {
            return None;
        }
        Some(Self {
            left: min_x,
            top: min_y,
            width,
            height,
        })
    }

    /// Convierte una coordenada física `(px_x, px_y)` del escritorio virtual al rango `[0..=65535]`.
    pub fn normalize_pixel(&self, px_x: i32, px_y: i32) -> NormalizedPoint {
        let clamped_x = px_x.clamp(self.left, self.left + (self.width as i32) - 1);
        let clamped_y = px_y.clamp(self.top, self.top + (self.height as i32) - 1);

        let rel_x = (clamped_x - self.left) as u64;
        let rel_y = (clamped_y - self.top) as u64;

        let max_w = (self.width.saturating_sub(1)).max(1) as u64;
        let max_h = (self.height.saturating_sub(1)).max(1) as u64;

        let norm_x = ((rel_x * 65_535 + max_w / 2) / max_w).min(65_535) as u16;
        let norm_y = ((rel_y * 65_535 + max_h / 2) / max_h).min(65_535) as u16;

        NormalizedPoint {
            x: norm_x,
            y: norm_y,
        }
    }

    /// Reconstruye la coordenada en píxeles aproximada a partir de un `NormalizedPoint`.
    pub fn denormalize_point(&self, pt: NormalizedPoint) -> (i32, i32) {
        let max_w = (self.width.saturating_sub(1)) as u64;
        let max_h = (self.height.saturating_sub(1)) as u64;
        let px_x = self.left + ((pt.x as u64 * max_w + 32_767) / 65_535) as i32;
        let px_y = self.top + ((pt.y as u64 * max_h + 32_767) / 65_535) as i32;
        (px_x, px_y)
    }
}

/// Rectángulo protegido de la interfaz local del Cliente Receptor (ej. barra "Revocar Control Ahora")
/// donde se bloquean clics sintéticos remotos para evitar que el operador cierre la barra de seguridad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub safety_margin_px: i32,
}

impl ProtectedRect {
    pub fn contains_with_margin(&self, x: i32, y: i32) -> bool {
        let m = self.safety_margin_px.max(0);
        x >= (self.left - m)
            && x <= (self.right + m)
            && y >= (self.top - m)
            && y <= (self.bottom + m)
    }
}
