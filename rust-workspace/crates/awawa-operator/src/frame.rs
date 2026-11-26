//! Conversion de fotogramas decodificados (BGRA) a los bytes RGBA que sube la textura del visor.

use capture_win::{DecodedFrame, DirtyRect};

const BYTES_PER_PIXEL: usize = 4;

/// Region recortada al fotograma, lista para `TextureHandle::set_partial`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbaRegion {
    pub pos: [usize; 2],
    pub size: [usize; 2],
    pub rgba: Vec<u8>,
}

/// Convierte la region (recortada al fotograma) de BGRA a RGBA opaco. `None` si queda vacia o
/// el fotograma no es coherente con sus dimensiones.
pub fn region_to_rgba(frame: &DecodedFrame, rect: &DirtyRect) -> Option<RgbaRegion> {
    let (fw, fh) = (frame.width as usize, frame.height as usize);
    if frame.bgra.len() != fw * fh * BYTES_PER_PIXEL {
        return None;
    }
    let x0 = (rect.x as usize).min(fw);
    let y0 = (rect.y as usize).min(fh);
    let x1 = (rect.x as usize)
        .saturating_add(rect.width as usize)
        .min(fw);
    let y1 = (rect.y as usize)
        .saturating_add(rect.height as usize)
        .min(fh);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    let (w, h) = (x1 - x0, y1 - y0);
    let mut rgba = Vec::with_capacity(w * h * BYTES_PER_PIXEL);
    for y in y0..y1 {
        let row = &frame.bgra[(y * fw + x0) * BYTES_PER_PIXEL..(y * fw + x1) * BYTES_PER_PIXEL];
        for px in row.as_chunks::<BYTES_PER_PIXEL>().0 {
            rgba.extend_from_slice(&[px[2], px[1], px[0], 255]);
        }
    }
    Some(RgbaRegion {
        pos: [x0, y0],
        size: [w, h],
        rgba,
    })
}

/// Region que cubre todo el fotograma.
pub fn full_rgba(frame: &DecodedFrame) -> Option<RgbaRegion> {
    region_to_rgba(
        frame,
        &DirtyRect {
            x: 0,
            y: 0,
            width: frame.width,
            height: frame.height,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_2x2() -> DecodedFrame {
        // BGRA: (b,g,r,a) por pixel; alfa de origen distinto de 255 a proposito.
        DecodedFrame {
            width: 2,
            height: 2,
            bgra: vec![
                1, 2, 3, 0, //
                4, 5, 6, 0, //
                7, 8, 9, 0, //
                10, 11, 12, 0,
            ],
        }
    }

    #[test]
    fn full_frame_swaps_channels_and_forces_opaque_alpha() {
        let r = full_rgba(&frame_2x2()).unwrap();
        assert_eq!(r.pos, [0, 0]);
        assert_eq!(r.size, [2, 2]);
        assert_eq!(
            r.rgba,
            vec![3, 2, 1, 255, 6, 5, 4, 255, 9, 8, 7, 255, 12, 11, 10, 255]
        );
    }

    #[test]
    fn sub_region_is_extracted_with_its_position() {
        let r = region_to_rgba(
            &frame_2x2(),
            &DirtyRect {
                x: 1,
                y: 1,
                width: 1,
                height: 1,
            },
        )
        .unwrap();
        assert_eq!(r.pos, [1, 1]);
        assert_eq!(r.size, [1, 1]);
        assert_eq!(r.rgba, vec![12, 11, 10, 255]);
    }

    #[test]
    fn region_is_clipped_to_the_frame() {
        let r = region_to_rgba(
            &frame_2x2(),
            &DirtyRect {
                x: 1,
                y: 0,
                width: 50,
                height: 50,
            },
        )
        .unwrap();
        assert_eq!(r.size, [1, 2]);
    }

    #[test]
    fn empty_or_outside_region_is_none() {
        let f = frame_2x2();
        let at = |x, y, w, h| {
            region_to_rgba(
                &f,
                &DirtyRect {
                    x,
                    y,
                    width: w,
                    height: h,
                },
            )
        };
        assert!(at(0, 0, 0, 1).is_none());
        assert!(at(5, 0, 1, 1).is_none());
        assert!(at(u32::MAX, 0, u32::MAX, 1).is_none());
    }

    #[test]
    fn inconsistent_buffer_is_none() {
        let mut f = frame_2x2();
        f.bgra.pop();
        assert!(full_rgba(&f).is_none());
    }
}
