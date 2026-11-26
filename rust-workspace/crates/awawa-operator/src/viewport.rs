//! Geometria del visor: seleccion de monitor, escalado (ajustar / 1:1) y mapeo de coordenadas
//! del lienzo al espacio normalizado `0..=65535` del escritorio virtual remoto.
//!
//! Logica pura (solo tipos de datos de egui, sin contexto ni ventana). El fotograma decodificado
//! cubre el escritorio virtual anunciado por el host; la seleccion de monitor recorta una region
//! de ese fotograma y el mapeo vuelve a coordenadas del escritorio virtual completo, que son las
//! que normaliza `VirtualDesktopBounds::normalize_pixel`.

use awawa_protocol::{MonitorDescriptor, NormalizedPoint, VirtualDesktopBounds};
use egui::{Pos2, Rect, Vec2, pos2, vec2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScaleMode {
    /// Ajustar a la ventana conservando la relacion de aspecto.
    Fit,
    /// Un pixel remoto por pixel fisico local.
    OneToOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorSelection {
    /// Todo el escritorio virtual.
    All,
    /// Un monitor remoto por su `MonitorDescriptor::index`.
    Monitor(u8),
}

/// Region visible del escritorio virtual remoto, en pixeles del escritorio virtual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopRegion {
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
}

/// Punto del escritorio remoto al que apunta el puntero local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedPoint {
    pub norm: NormalizedPoint,
    /// Pixel en coordenadas del escritorio virtual (para el filtro de ventanas protegidas del host).
    pub desktop_px: (i32, i32),
}

/// Region que corresponde a la seleccion. Un monitor desconocido cae al escritorio completo.
pub fn region_for(
    selection: MonitorSelection,
    monitors: &[MonitorDescriptor],
    desktop: &VirtualDesktopBounds,
) -> DesktopRegion {
    if let MonitorSelection::Monitor(index) = selection
        && let Some(m) = monitors.iter().find(|m| m.index == index)
        && m.width_px > 0
        && m.height_px > 0
    {
        return DesktopRegion {
            left: m.origin_x,
            top: m.origin_y,
            width: m.width_px,
            height: m.height_px,
        };
    }
    DesktopRegion {
        left: desktop.left,
        top: desktop.top,
        width: desktop.width,
        height: desktop.height,
    }
}

/// Rectangulo UV `0..1` de la region dentro del fotograma (que cubre el escritorio virtual).
pub fn uv_rect(region: &DesktopRegion, desktop: &VirtualDesktopBounds) -> Rect {
    let dw = desktop.width.max(1) as f32;
    let dh = desktop.height.max(1) as f32;
    let x0 = (region.left - desktop.left) as f32 / dw;
    let y0 = (region.top - desktop.top) as f32 / dh;
    let x1 = x0 + region.width as f32 / dw;
    let y1 = y0 + region.height as f32 / dh;
    Rect::from_min_max(
        pos2(x0.clamp(0.0, 1.0), y0.clamp(0.0, 1.0)),
        pos2(x1.clamp(0.0, 1.0), y1.clamp(0.0, 1.0)),
    )
}

/// Tamano en pixeles del fotograma que ocupa la region (el fotograma puede estar reducido
/// respecto del escritorio real).
pub fn region_size_in_frame(
    region: &DesktopRegion,
    desktop: &VirtualDesktopBounds,
    frame_w: u32,
    frame_h: u32,
) -> Vec2 {
    let sx = frame_w as f32 / desktop.width.max(1) as f32;
    let sy = frame_h as f32 / desktop.height.max(1) as f32;
    vec2(region.width as f32 * sx, region.height as f32 * sy)
}

/// Tamano en puntos con el que se dibuja el contenido.
///
/// `content_px` es el tamano de la region en pixeles remotos y `pixels_per_point` el factor de
/// escala local: en 1:1 un pixel remoto ocupa un pixel fisico local.
pub fn display_size(
    content_px: Vec2,
    canvas: Vec2,
    mode: ScaleMode,
    pixels_per_point: f32,
) -> Vec2 {
    if content_px.x <= 0.0 || content_px.y <= 0.0 {
        return Vec2::ZERO;
    }
    match mode {
        ScaleMode::OneToOne => content_px / pixels_per_point.max(0.01),
        ScaleMode::Fit => {
            if canvas.x <= 0.0 || canvas.y <= 0.0 {
                return Vec2::ZERO;
            }
            let scale = (canvas.x / content_px.x).min(canvas.y / content_px.y);
            content_px * scale
        }
    }
}

/// Coloca `size` centrado en `canvas`; si no cabe en un eje, se alinea al origen del lienzo
/// (el exceso se recorre con las barras de desplazamiento).
pub fn place_in_canvas(canvas: Rect, size: Vec2) -> Rect {
    let x = if size.x < canvas.width() {
        canvas.min.x + (canvas.width() - size.x) / 2.0
    } else {
        canvas.min.x
    };
    let y = if size.y < canvas.height() {
        canvas.min.y + (canvas.height() - size.y) / 2.0
    } else {
        canvas.min.y
    };
    Rect::from_min_size(pos2(x, y), size)
}

/// Convierte una posicion del puntero local a un punto normalizado del escritorio remoto.
///
/// `image_rect` es donde se dibuja la region y `visible` la parte del lienzo realmente visible
/// (relevante en 1:1 cuando la imagen es mayor que la ventana). Devuelve `None` si el puntero
/// esta fuera de la imagen visible.
pub fn map_pointer(
    pos: Pos2,
    image_rect: Rect,
    visible: Rect,
    region: &DesktopRegion,
    desktop: &VirtualDesktopBounds,
) -> Option<MappedPoint> {
    if image_rect.width() <= 0.0 || image_rect.height() <= 0.0 || region.width == 0 {
        return None;
    }
    if !image_rect.contains(pos) || !visible.contains(pos) {
        return None;
    }
    // Multiplicar antes de dividir evita errores de redondeo en los casos exactos (1:1).
    let dx = (pos.x - image_rect.min.x).max(0.0) * region.width as f32 / image_rect.width();
    let dy = (pos.y - image_rect.min.y).max(0.0) * region.height as f32 / image_rect.height();
    let px = region.left + (dx as i32).min(region.width as i32 - 1);
    let py = region.top + (dy as i32).min(region.height as i32 - 1);
    Some(MappedPoint {
        norm: desktop.normalize_pixel(px, py),
        desktop_px: (px, py),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(index: u8, x: i32, y: i32, w: u32, h: u32) -> MonitorDescriptor {
        MonitorDescriptor {
            index,
            is_primary: index == 0,
            origin_x: x,
            origin_y: y,
            width_px: w,
            height_px: h,
            dpi_scale_percent: 100,
        }
    }

    /// Dos monitores 1920x1080 lado a lado, el segundo a la derecha.
    fn two_monitors() -> (Vec<MonitorDescriptor>, VirtualDesktopBounds) {
        let ms = vec![
            monitor(0, 0, 0, 1920, 1080),
            monitor(1, 1920, 0, 1920, 1080),
        ];
        let d = VirtualDesktopBounds::from_monitors(&ms).unwrap();
        (ms, d)
    }

    fn rect(x: f32, y: f32, w: f32, h: f32) -> Rect {
        Rect::from_min_size(pos2(x, y), vec2(w, h))
    }

    #[test]
    fn region_all_is_the_virtual_desktop() {
        let (ms, d) = two_monitors();
        let r = region_for(MonitorSelection::All, &ms, &d);
        assert_eq!((r.left, r.top, r.width, r.height), (0, 0, 3840, 1080));
    }

    #[test]
    fn region_for_monitor_and_unknown_monitor_fallback() {
        let (ms, d) = two_monitors();
        let r = region_for(MonitorSelection::Monitor(1), &ms, &d);
        assert_eq!((r.left, r.top, r.width, r.height), (1920, 0, 1920, 1080));
        let fallback = region_for(MonitorSelection::Monitor(9), &ms, &d);
        assert_eq!(fallback.width, 3840);
    }

    #[test]
    fn uv_rect_selects_the_right_half_for_the_second_monitor() {
        let (ms, d) = two_monitors();
        let uv = uv_rect(&region_for(MonitorSelection::Monitor(1), &ms, &d), &d);
        assert_eq!(uv, Rect::from_min_max(pos2(0.5, 0.0), pos2(1.0, 1.0)));
        let all = uv_rect(&region_for(MonitorSelection::All, &ms, &d), &d);
        assert_eq!(all, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)));
    }

    #[test]
    fn uv_rect_handles_negative_origins() {
        let ms = vec![monitor(0, 0, 0, 1000, 500), monitor(1, -1000, 0, 1000, 500)];
        let d = VirtualDesktopBounds::from_monitors(&ms).unwrap();
        let uv = uv_rect(&region_for(MonitorSelection::Monitor(1), &ms, &d), &d);
        assert_eq!(uv, Rect::from_min_max(pos2(0.0, 0.0), pos2(0.5, 1.0)));
    }

    #[test]
    fn fit_scales_to_the_limiting_axis_keeping_aspect() {
        let size = display_size(
            vec2(1920.0, 1080.0),
            vec2(960.0, 960.0),
            ScaleMode::Fit,
            1.0,
        );
        assert!((size.x - 960.0).abs() < 1e-3 && (size.y - 540.0).abs() < 1e-3);
        let up = display_size(vec2(100.0, 100.0), vec2(400.0, 200.0), ScaleMode::Fit, 1.0);
        assert!((up.x - 200.0).abs() < 1e-3 && (up.y - 200.0).abs() < 1e-3);
    }

    #[test]
    fn one_to_one_uses_physical_pixels() {
        let s = display_size(
            vec2(1920.0, 1080.0),
            vec2(500.0, 500.0),
            ScaleMode::OneToOne,
            1.5,
        );
        assert!((s.x - 1280.0).abs() < 1e-3 && (s.y - 720.0).abs() < 1e-3);
    }

    #[test]
    fn degenerate_sizes_give_zero() {
        assert_eq!(
            display_size(vec2(0.0, 10.0), vec2(10.0, 10.0), ScaleMode::Fit, 1.0),
            Vec2::ZERO
        );
        assert_eq!(
            display_size(vec2(10.0, 10.0), vec2(0.0, 10.0), ScaleMode::Fit, 1.0),
            Vec2::ZERO
        );
    }

    #[test]
    fn placement_centers_when_smaller_and_aligns_when_larger() {
        let canvas = rect(10.0, 20.0, 400.0, 300.0);
        let small = place_in_canvas(canvas, vec2(200.0, 100.0));
        assert_eq!(small.min, pos2(110.0, 120.0));
        let big = place_in_canvas(canvas, vec2(800.0, 100.0));
        assert_eq!(big.min, pos2(10.0, 120.0));
    }

    #[test]
    fn fit_mapping_corners_and_center_cover_the_whole_range() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::All, &ms, &d);
        // Lienzo 1920x540 mostrando 3840x1080 -> escala 0.5, sin bandas.
        let img = rect(0.0, 0.0, 1920.0, 540.0);
        let at = |x, y| map_pointer(pos2(x, y), img, img, &region, &d).unwrap();
        let tl = at(0.0, 0.0);
        assert_eq!((tl.norm.x, tl.norm.y), (0, 0));
        assert_eq!(tl.desktop_px, (0, 0));
        let br = at(1919.99, 539.99);
        assert_eq!((br.norm.x, br.norm.y), (65_535, 65_535));
        assert_eq!(br.desktop_px, (3839, 1079));
        let c = at(960.0, 270.0);
        assert_eq!(c.desktop_px, (1920, 540));
        assert!((i32::from(c.norm.x) - 32_768).abs() <= 20);
    }

    #[test]
    fn mapping_ignores_letterbox_bars() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::All, &ms, &d);
        // Imagen 800x225 centrada en un lienzo 800x600: hay bandas arriba y abajo.
        let canvas = rect(0.0, 0.0, 800.0, 600.0);
        let img = place_in_canvas(canvas, vec2(800.0, 225.0));
        assert!(map_pointer(pos2(400.0, 10.0), img, canvas, &region, &d).is_none());
        assert!(map_pointer(pos2(400.0, 590.0), img, canvas, &region, &d).is_none());
        let top_edge = map_pointer(pos2(0.0, img.min.y), img, canvas, &region, &d).unwrap();
        assert_eq!(top_edge.desktop_px, (0, 0));
    }

    #[test]
    fn monitor_selection_maps_into_that_monitors_pixels() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::Monitor(1), &ms, &d);
        let img = rect(0.0, 0.0, 960.0, 540.0);
        let origin = map_pointer(pos2(0.0, 0.0), img, img, &region, &d).unwrap();
        assert_eq!(origin.desktop_px, (1920, 0));
        // Mitad del escritorio virtual (x = 1920 de 3840).
        assert!((i32::from(origin.norm.x) - 32_768).abs() <= 20);
        let far = map_pointer(pos2(959.9, 539.9), img, img, &region, &d).unwrap();
        assert_eq!(far.desktop_px, (3839, 1079));
        assert_eq!((far.norm.x, far.norm.y), (65_535, 65_535));
    }

    #[test]
    fn one_to_one_mapping_with_partial_visibility() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::Monitor(0), &ms, &d);
        // Imagen 1:1 de 1920x1080 en un lienzo visible de 800x600, desplazada 100 px a la izquierda.
        let img = rect(-100.0, 0.0, 1920.0, 1080.0);
        let visible = rect(0.0, 0.0, 800.0, 600.0);
        let p = map_pointer(pos2(0.0, 0.0), img, visible, &region, &d).unwrap();
        assert_eq!(p.desktop_px, (100, 0));
        assert!(map_pointer(pos2(900.0, 100.0), img, visible, &region, &d).is_none());
    }

    #[test]
    fn mapping_scales_with_a_reduced_frame_independent_of_frame_size() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::All, &ms, &d);
        let size = region_size_in_frame(&region, &d, 1920, 540);
        assert_eq!(size, vec2(1920.0, 540.0));
        let img = rect(0.0, 0.0, 192.0, 54.0);
        let p = map_pointer(pos2(96.0, 27.0), img, img, &region, &d).unwrap();
        assert_eq!(p.desktop_px, (1920, 540));
    }

    #[test]
    fn mapping_with_empty_image_is_none() {
        let (ms, d) = two_monitors();
        let region = region_for(MonitorSelection::All, &ms, &d);
        let img = rect(0.0, 0.0, 0.0, 0.0);
        assert!(map_pointer(pos2(0.0, 0.0), img, img, &region, &d).is_none());
    }
}
