//! Geometria del banner de revocacion (logica pura).
//!
//! El banner se coloca centrado en el borde superior del monitor principal. Aqui se calcula su
//! posicion en puntos logicos para la ventana y, a partir de los mismos numeros, el rectangulo
//! en pixeles fisicos que `ApprovedActiveSession` usa para rechazar clics remotos sobre el boton.
//! Tras mostrarse, la UI lo sustituye por el rectangulo real de la ventana (`GetWindowRect`).

use awawa_protocol::ProtectedRect;

/// Tamano del banner en puntos logicos.
pub const BANNER_SIZE_POINTS: (f32, f32) = (560.0, 64.0);
/// Margen de seguridad alrededor del banner, en pixeles fisicos.
pub const BANNER_SAFETY_MARGIN_PX: i32 = 8;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BannerLayout {
    /// Esquina superior izquierda en puntos logicos.
    pub position_points: (f32, f32),
    pub size_points: (f32, f32),
    /// Rectangulo en pixeles fisicos.
    pub protected_rect: ProtectedRect,
}

/// Calcula la ubicacion del banner para un monitor principal de `screen_width_px` pixeles de ancho
/// y un factor de escala `pixels_per_point` (>= 1.0 en la practica).
pub fn banner_layout(screen_width_px: i32, pixels_per_point: f32) -> BannerLayout {
    let ppp = if pixels_per_point.is_finite() && pixels_per_point > 0.0 {
        pixels_per_point
    } else {
        1.0
    };
    let width_px = (BANNER_SIZE_POINTS.0 * ppp).round() as i32;
    let height_px = (BANNER_SIZE_POINTS.1 * ppp).round() as i32;
    let left = ((screen_width_px - width_px) / 2).max(0);
    BannerLayout {
        position_points: (left as f32 / ppp, 0.0),
        size_points: BANNER_SIZE_POINTS,
        protected_rect: ProtectedRect {
            left,
            top: 0,
            right: left + width_px,
            bottom: height_px,
            safety_margin_px: BANNER_SAFETY_MARGIN_PX,
        },
    }
}

/// Esquina superior izquierda (pixeles fisicos) que centra una ventana de `window_width_px` en el
/// borde superior del monitor principal, cuyo origen es siempre (0, 0).
pub fn banner_origin_px(screen_width_px: i32, window_width_px: i32) -> (i32, i32) {
    (((screen_width_px - window_width_px) / 2).max(0), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_centered_at_the_top_edge_at_100_percent() {
        let l = banner_layout(1920, 1.0);
        assert_eq!(l.protected_rect.left, 680);
        assert_eq!(l.protected_rect.right, 1240);
        assert_eq!(l.protected_rect.top, 0);
        assert_eq!(l.protected_rect.bottom, 64);
        assert_eq!(l.position_points, (680.0, 0.0));
    }

    #[test]
    fn rect_scales_with_dpi_and_position_stays_in_logical_points() {
        let l = banner_layout(3840, 2.0);
        assert_eq!(l.protected_rect.right - l.protected_rect.left, 1120);
        assert_eq!(l.protected_rect.bottom, 128);
        assert_eq!(l.protected_rect.left, 1360);
        assert_eq!(l.position_points.0, 680.0);
    }

    #[test]
    fn narrow_screens_and_bad_scale_do_not_produce_negative_or_nan_values() {
        let l = banner_layout(300, 1.0);
        assert_eq!(l.protected_rect.left, 0);
        let l = banner_layout(1920, f32::NAN);
        assert_eq!(l.protected_rect.right - l.protected_rect.left, 560);
        assert!(l.position_points.0.is_finite());
    }

    #[test]
    fn the_revoke_button_area_is_inside_the_protected_rect_with_margin() {
        let l = banner_layout(1920, 1.0);
        let r = l.protected_rect;
        assert!(r.contains_with_margin(r.left + 10, r.top + 10));
        assert!(r.contains_with_margin(r.left - BANNER_SAFETY_MARGIN_PX, 0));
        assert!(!r.contains_with_margin(r.left - BANNER_SAFETY_MARGIN_PX - 1, 0));
    }

    #[test]
    fn origin_recenters_for_any_window_width_and_screen() {
        assert_eq!(banner_origin_px(1920, 560), (680, 0));
        assert_eq!(banner_origin_px(2560, 840), (860, 0));
        assert_eq!(banner_origin_px(400, 560), (0, 0));
    }
}
