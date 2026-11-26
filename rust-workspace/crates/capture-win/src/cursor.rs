//! Forma del cursor de hardware y caché por hash: la forma completa solo viaja la primera vez;
//! si vuelve una forma ya enviada, basta su hash (`CursorShapeUpdate { bgra_zstd: None, .. }`).

use std::collections::VecDeque;

/// Formas distintas que recuerda la caché (el operador debe conservar al menos las mismas).
pub const CURSOR_CACHE_CAPACITY: usize = 32;

/// Tipo de forma según `DXGI_OUTDUPL_POINTER_SHAPE_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorShapeKind {
    /// 1 bpp: máscara AND seguida de máscara XOR (`height` cuenta ambas).
    Monochrome,
    /// BGRA de 32 bpp con alfa.
    Color,
    /// BGRA de 32 bpp donde el alfa actúa como máscara XOR.
    MaskedColor,
}

/// Forma del cursor tal como la entrega el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub kind: CursorShapeKind,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub data: Vec<u8>,
}

impl CursorShape {
    /// FNV-1a de 64 bits sobre tipo, geometría, hotspot y bytes: estable entre ejecuciones.
    pub fn content_hash(&self) -> u64 {
        let kind = match self.kind {
            CursorShapeKind::Monochrome => 1u8,
            CursorShapeKind::Color => 2,
            CursorShapeKind::MaskedColor => 4,
        };
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        feed(&[kind]);
        for value in [
            self.width,
            self.height,
            self.pitch,
            self.hotspot_x,
            self.hotspot_y,
        ] {
            feed(&value.to_le_bytes());
        }
        feed(&self.data);
        hash
    }
}

/// Lado máximo (ancho o alto, ya sin contar la máscara doble) que acepta la conversión.
pub const MAX_CURSOR_DIMENSION: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorConvertError {
    /// Ancho o alto en cero, mayor que [`MAX_CURSOR_DIMENSION`] o, en monocromo, alto impar.
    InvalidDimensions,
    /// `pitch` menor que una fila de píxeles.
    InvalidPitch,
    /// `data` más corto que `pitch * filas`.
    DataTooShort,
}

/// Cursor convertido a BGRA de 32 bpp con alfa **recto** (sin premultiplicar), stride = `width * 4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorBgra {
    pub width: u32,
    pub height: u32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub bgra: Vec<u8>,
}

/// Convierte la forma DXGI a BGRA con alfa recto (el operador debe componer con "over" recto).
///
/// - `Color`: ya es BGRA con alfa; se copia fila a fila sin el relleno de `pitch`.
/// - `Monochrome`: máscara AND y luego XOR (1 bpp, MSB primero; `height` cuenta ambas). AND=1/XOR=0
///   es transparente, AND=0/XOR=0 negro opaco y AND=0/XOR=1 blanco opaco. AND=1/XOR=1 invierte el
///   fondo, que no es representable sin el fondo: se aproxima con blanco opaco.
/// - `MaskedColor`: el alfa es una máscara. Alfa 0 sustituye el píxel (opaco con ese color); alfa
///   distinto de 0 hace XOR con el fondo: con color 0 no cambia nada (transparente) y con otro
///   color se aproxima por ese color opaco.
pub fn cursor_shape_to_bgra(shape: &CursorShape) -> Result<CursorBgra, CursorConvertError> {
    let (width, hotspot_x, hotspot_y) = (shape.width, shape.hotspot_x, shape.hotspot_y);
    let out_height = match shape.kind {
        CursorShapeKind::Monochrome if !shape.height.is_multiple_of(2) => {
            return Err(CursorConvertError::InvalidDimensions);
        }
        CursorShapeKind::Monochrome => shape.height / 2,
        _ => shape.height,
    };
    if width == 0
        || out_height == 0
        || width > MAX_CURSOR_DIMENSION
        || out_height > MAX_CURSOR_DIMENSION
    {
        return Err(CursorConvertError::InvalidDimensions);
    }
    let (w, h, pitch) = (width as usize, out_height as usize, shape.pitch as usize);
    let row_bytes = match shape.kind {
        CursorShapeKind::Monochrome => w.div_ceil(8),
        _ => w * 4,
    };
    if pitch < row_bytes {
        return Err(CursorConvertError::InvalidPitch);
    }
    let rows = match shape.kind {
        CursorShapeKind::Monochrome => h * 2,
        _ => h,
    };
    if shape.data.len() < pitch * rows {
        return Err(CursorConvertError::DataTooShort);
    }

    let mut bgra = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        match shape.kind {
            CursorShapeKind::Color => {
                bgra.extend_from_slice(&shape.data[y * pitch..y * pitch + w * 4]);
            }
            CursorShapeKind::MaskedColor => {
                for px in shape.data[y * pitch..y * pitch + w * 4].as_chunks::<4>().0 {
                    let opaque = px[3] == 0 || px[..3] != [0, 0, 0];
                    let alpha = if opaque { 0xFF } else { 0 };
                    bgra.extend_from_slice(&[px[0], px[1], px[2], alpha]);
                }
            }
            CursorShapeKind::Monochrome => {
                let and_row = &shape.data[y * pitch..];
                let xor_row = &shape.data[(h + y) * pitch..];
                for x in 0..w {
                    let bit = 0x80u8 >> (x % 8);
                    let and = and_row[x / 8] & bit != 0;
                    let xor = xor_row[x / 8] & bit != 0;
                    let px = match (and, xor) {
                        (true, false) => [0, 0, 0, 0],
                        (false, false) => [0, 0, 0, 0xFF],
                        _ => [0xFF, 0xFF, 0xFF, 0xFF],
                    };
                    bgra.extend_from_slice(&px);
                }
            }
        }
    }
    Ok(CursorBgra {
        width,
        height: out_height,
        hotspot_x,
        hotspot_y,
        bgra,
    })
}

/// Cambio de forma a comunicar al operador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShapeChange {
    pub hash: u64,
    /// `None` si la forma ya se envió antes y sigue en la caché.
    pub shape: Option<CursorShape>,
}

/// Posición del puntero en coordenadas del monitor capturado y, si cambió, su forma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub shape_change: Option<CursorShapeChange>,
}

#[derive(Debug, Default)]
pub struct CursorShapeCache {
    current: Option<u64>,
    known: VecDeque<u64>,
}

impl CursorShapeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `None` si la forma es la actual; si no, el cambio con o sin bytes según la caché (LRU).
    pub fn observe(&mut self, shape: CursorShape) -> Option<CursorShapeChange> {
        let hash = shape.content_hash();
        if self.current == Some(hash) {
            return None;
        }
        self.current = Some(hash);
        if let Some(pos) = self.known.iter().position(|known| *known == hash) {
            self.known.remove(pos);
            self.known.push_back(hash);
            return Some(CursorShapeChange { hash, shape: None });
        }
        if self.known.len() == CURSOR_CACHE_CAPACITY {
            self.known.pop_front();
        }
        self.known.push_back(hash);
        Some(CursorShapeChange {
            hash,
            shape: Some(shape),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(seed: u8) -> CursorShape {
        CursorShape {
            kind: CursorShapeKind::Color,
            width: 2,
            height: 2,
            pitch: 8,
            hotspot_x: 0,
            hotspot_y: 0,
            data: vec![seed; 16],
        }
    }

    #[test]
    fn unchanged_shape_is_not_reported_again() {
        let mut cache = CursorShapeCache::new();
        let first = cache.observe(shape(1)).unwrap();
        assert_eq!(first.shape, Some(shape(1)));
        assert_eq!(cache.observe(shape(1)), None);
    }

    #[test]
    fn known_shape_is_reported_by_hash_only() {
        let mut cache = CursorShapeCache::new();
        let arrow = cache.observe(shape(1)).unwrap();
        assert!(cache.observe(shape(2)).unwrap().shape.is_some());
        let back = cache.observe(shape(1)).unwrap();
        assert_eq!(back.hash, arrow.hash);
        assert_eq!(back.shape, None);
    }

    #[test]
    fn evicted_shape_is_sent_in_full_again() {
        let mut cache = CursorShapeCache::new();
        for seed in 0..=CURSOR_CACHE_CAPACITY as u8 {
            assert!(cache.observe(shape(seed)).unwrap().shape.is_some());
        }
        // La forma 0 salió de la caché al entrar la número CURSOR_CACHE_CAPACITY + 1.
        assert!(cache.observe(shape(0)).unwrap().shape.is_some());
    }

    #[test]
    fn hash_covers_geometry_and_hotspot() {
        let base = shape(1);
        let mut moved_hotspot = base.clone();
        moved_hotspot.hotspot_x = 1;
        let mut other_kind = base.clone();
        other_kind.kind = CursorShapeKind::MaskedColor;
        assert_eq!(base.content_hash(), shape(1).content_hash());
        assert_ne!(base.content_hash(), moved_hotspot.content_hash());
        assert_ne!(base.content_hash(), other_kind.content_hash());
    }

    fn raw(
        kind: CursorShapeKind,
        width: u32,
        height: u32,
        pitch: u32,
        data: Vec<u8>,
    ) -> CursorShape {
        CursorShape {
            kind,
            width,
            height,
            pitch,
            hotspot_x: 1,
            hotspot_y: 2,
            data,
        }
    }

    #[test]
    fn color_shape_drops_pitch_padding_and_keeps_alpha() {
        // 2x2 con pitch 12 (4 bytes de relleno por fila).
        let data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 9, 9, //
            10, 11, 12, 13, 14, 15, 16, 17, 9, 9, 9, 9,
        ];
        let out = cursor_shape_to_bgra(&raw(CursorShapeKind::Color, 2, 2, 12, data)).unwrap();
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!((out.hotspot_x, out.hotspot_y), (1, 2));
        assert_eq!(
            out.bgra,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17]
        );
    }

    #[test]
    fn monochrome_shape_maps_and_xor_masks() {
        // 4x1 lógico (height 2 = AND + XOR), pitch 1. Píxeles (AND,XOR): (1,0) (0,0) (0,1) (1,1).
        let data = vec![0b1001_0000, 0b0011_0000];
        let out = cursor_shape_to_bgra(&raw(CursorShapeKind::Monochrome, 4, 2, 1, data)).unwrap();
        assert_eq!((out.width, out.height), (4, 1));
        assert_eq!(
            out.bgra,
            vec![
                0, 0, 0, 0, //
                0, 0, 0, 0xFF, //
                0xFF, 0xFF, 0xFF, 0xFF, //
                0xFF, 0xFF, 0xFF, 0xFF,
            ]
        );
    }

    #[test]
    fn monochrome_reads_the_xor_plane_from_the_second_half() {
        // 8x2 lógico, pitch 2 (relleno): fila 0 con AND=0xFF, fila 1 con AND=0x00; XOR todo 0.
        let data = vec![
            0xFF, 0, //
            0x00, 0, //
            0x00, 0, //
            0x00, 0,
        ];
        let out = cursor_shape_to_bgra(&raw(CursorShapeKind::Monochrome, 8, 4, 2, data)).unwrap();
        assert_eq!((out.width, out.height), (8, 2));
        assert!(
            out.bgra[..32]
                .as_chunks::<4>()
                .0
                .iter()
                .all(|p| *p == [0, 0, 0, 0])
        );
        assert!(
            out.bgra[32..]
                .as_chunks::<4>()
                .0
                .iter()
                .all(|p| *p == [0, 0, 0, 0xFF])
        );
    }

    #[test]
    fn masked_color_uses_alpha_as_xor_mask() {
        let data = vec![
            10, 20, 30, 0, // alfa 0: sustituye, opaco
            0, 0, 0, 0xFF, // XOR con negro: sin efecto
            40, 50, 60, 0xFF, // XOR con color: aproximado opaco
            0, 0, 0, 0, // sustituye por negro, opaco
        ];
        let out = cursor_shape_to_bgra(&raw(CursorShapeKind::MaskedColor, 2, 2, 8, data)).unwrap();
        assert_eq!(
            out.bgra,
            vec![
                10, 20, 30, 0xFF, 0, 0, 0, 0, //
                40, 50, 60, 0xFF, 0, 0, 0, 0xFF
            ]
        );
    }

    #[test]
    fn conversion_rejects_invalid_geometry_without_panicking() {
        use CursorConvertError::*;
        let color = |w, h, pitch, len| raw(CursorShapeKind::Color, w, h, pitch, vec![0; len]);
        let mono = |w, h, pitch, len| raw(CursorShapeKind::Monochrome, w, h, pitch, vec![0; len]);
        assert_eq!(
            cursor_shape_to_bgra(&color(0, 2, 8, 16)),
            Err(InvalidDimensions)
        );
        assert_eq!(
            cursor_shape_to_bgra(&color(2, 0, 8, 16)),
            Err(InvalidDimensions)
        );
        assert_eq!(
            cursor_shape_to_bgra(&color(MAX_CURSOR_DIMENSION + 1, 1, u32::MAX, 16)),
            Err(InvalidDimensions)
        );
        assert_eq!(
            cursor_shape_to_bgra(&mono(8, 3, 1, 3)),
            Err(InvalidDimensions)
        );
        assert_eq!(cursor_shape_to_bgra(&color(2, 2, 7, 16)), Err(InvalidPitch));
        assert_eq!(cursor_shape_to_bgra(&mono(9, 2, 1, 2)), Err(InvalidPitch));
        assert_eq!(cursor_shape_to_bgra(&color(2, 2, 8, 15)), Err(DataTooShort));
        assert_eq!(cursor_shape_to_bgra(&mono(8, 2, 1, 1)), Err(DataTooShort));
        assert_eq!(
            cursor_shape_to_bgra(&color(2, 2, u32::MAX, 16)),
            Err(DataTooShort)
        );
    }
}
