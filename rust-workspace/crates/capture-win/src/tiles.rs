//! Codificador de tiles BGRA sin pérdida + zstd nivel 1 (`VideoCodec::ZstdDirtyTiles`) y su
//! decodificador simétrico.
//!
//! El resultado de [`TileEncoder`] es el payload completo que sigue a un `VideoPacketHeader`
//! (`payload_len` = longitud de este payload). Formato v1, little-endian:
//!
//! ```text
//! [0]      versión (1)
//! [1]      reservado (0)
//! [2..4]   tamaño de tile en píxeles (64)
//! [4..8]   ancho del fotograma
//! [8..12]  alto del fotograma
//! [12..16] cantidad de tiles
//! [16..20] longitud del cuerpo descomprimido
//! [20..]   un frame zstd con el cuerpo
//! ```
//!
//! Cuerpo: por cada tile, en orden fila-columna estrictamente creciente, `columna: u16`,
//! `fila: u16` y los píxeles BGRA del tile fila por fila. Los tiles del borde derecho e inferior
//! se recortan al fotograma (no se rellenan).

use crate::DirtyRect;

/// Versión del formato de payload.
pub const TILE_FORMAT_VERSION: u8 = 1;
/// Lado del tile en píxeles.
pub const TILE_SIZE: u32 = 64;
/// Ancho o alto máximo aceptado por el codificador y el decodificador.
pub const MAX_FRAME_DIMENSION: u32 = 8192;
/// Nivel de compresión zstd.
pub const ZSTD_LEVEL: i32 = 1;
/// Longitud de la cabecera del payload, antes del frame zstd.
pub const TILE_PAYLOAD_HEADER_LEN: usize = 20;

const TILE_RECORD_HEADER_LEN: usize = 4;
const BYTES_PER_PIXEL: usize = 4;
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TileCodecError {
    /// Ancho o alto en cero o mayor que [`MAX_FRAME_DIMENSION`].
    InvalidDimensions,
    /// El búfer BGRA no mide `ancho * alto * 4`.
    BufferSizeMismatch,
    UnsupportedVersion(u8),
    /// Payload truncado, incoherente o con datos sobrantes.
    Malformed,
    /// Lo que declara el payload excede el tope que recibió el llamador (tamaño del payload,
    /// `payload_len` de la cabecera o dimensiones del monitor negociado).
    LimitExceeded,
    Compression(String),
}

/// Tope que fija el llamador antes de que el decodificador reserve memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// `VideoPacketHeader.payload_len`: debe coincidir con la longitud real del payload.
    pub payload_len: u32,
    /// Ancho del monitor negociado: el payload no puede declarar más.
    pub max_width: u32,
    /// Alto del monitor negociado: el payload no puede declarar más.
    pub max_height: u32,
}

/// Fotograma BGRA reconstruido por el decodificador (stride = `width * 4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}

impl DecodedFrame {
    /// Fotograma negro (todos los bytes en cero).
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            bgra: vec![0; width as usize * height as usize * BYTES_PER_PIXEL],
        }
    }
}

pub struct TileEncoder {
    compressor: zstd::bulk::Compressor<'static>,
    selected: Vec<bool>,
    body: Vec<u8>,
}

impl TileEncoder {
    pub fn new() -> Result<Self, TileCodecError> {
        let compressor = zstd::bulk::Compressor::new(ZSTD_LEVEL)
            .map_err(|e| TileCodecError::Compression(e.to_string()))?;
        Ok(Self {
            compressor,
            selected: Vec::new(),
            body: Vec::new(),
        })
    }

    /// Codifica el fotograma completo (todos los tiles).
    pub fn encode_keyframe(
        &mut self,
        width: u32,
        height: u32,
        bgra: &[u8],
    ) -> Result<Vec<u8>, TileCodecError> {
        let full = DirtyRect {
            x: 0,
            y: 0,
            width,
            height,
        };
        self.encode_rects(width, height, bgra, &[full])
    }

    /// Codifica solo los tiles que tocan algún rectángulo (recortado al fotograma). Sin
    /// rectángulos produce un payload válido sin tiles.
    pub fn encode_rects(
        &mut self,
        width: u32,
        height: u32,
        bgra: &[u8],
        rects: &[DirtyRect],
    ) -> Result<Vec<u8>, TileCodecError> {
        validate_dimensions(width, height)?;
        if bgra.len() != frame_len(width, height) {
            return Err(TileCodecError::BufferSizeMismatch);
        }
        let (cols, rows) = grid(width, height);
        self.selected.clear();
        self.selected.resize(cols * rows, false);
        for rect in rects {
            let Some((x0, y0, x1, y1)) = clip(rect, width, height) else {
                continue;
            };
            for row in (y0 / TILE_SIZE)..=((y1 - 1) / TILE_SIZE) {
                for col in (x0 / TILE_SIZE)..=((x1 - 1) / TILE_SIZE) {
                    self.selected[row as usize * cols + col as usize] = true;
                }
            }
        }

        let stride = width as usize * BYTES_PER_PIXEL;
        self.body.clear();
        let mut tile_count: u32 = 0;
        for (slot, _) in self.selected.iter().enumerate().filter(|(_, s)| **s) {
            let (col, row) = ((slot % cols) as u32, (slot / cols) as u32);
            let (x0, y0) = (col * TILE_SIZE, row * TILE_SIZE);
            let tile_w = TILE_SIZE.min(width - x0) as usize;
            let tile_h = TILE_SIZE.min(height - y0) as usize;
            self.body.extend_from_slice(&(col as u16).to_le_bytes());
            self.body.extend_from_slice(&(row as u16).to_le_bytes());
            for y in y0 as usize..y0 as usize + tile_h {
                let start = y * stride + x0 as usize * BYTES_PER_PIXEL;
                self.body
                    .extend_from_slice(&bgra[start..start + tile_w * BYTES_PER_PIXEL]);
            }
            tile_count += 1;
        }

        let compressed = self
            .compressor
            .compress(&self.body)
            .map_err(|e| TileCodecError::Compression(e.to_string()))?;
        let raw_len = u32::try_from(self.body.len()).map_err(|_| TileCodecError::Malformed)?;
        let mut out = Vec::with_capacity(TILE_PAYLOAD_HEADER_LEN + compressed.len());
        out.push(TILE_FORMAT_VERSION);
        out.push(0);
        out.extend_from_slice(&(TILE_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&tile_count.to_le_bytes());
        out.extend_from_slice(&raw_len.to_le_bytes());
        out.extend_from_slice(&compressed);
        Ok(out)
    }
}

pub struct TileDecoder {
    decompressor: zstd::bulk::Decompressor<'static>,
    body: Vec<u8>,
}

impl TileDecoder {
    pub fn new() -> Result<Self, TileCodecError> {
        let decompressor = zstd::bulk::Decompressor::new()
            .map_err(|e| TileCodecError::Compression(e.to_string()))?;
        Ok(Self {
            decompressor,
            body: Vec::new(),
        })
    }

    /// Aplica un payload sobre `frame` y devuelve los rectángulos actualizados.
    ///
    /// Todo el payload se valida antes de escribir: si hay error, `frame` queda intacto. Si las
    /// dimensiones del payload difieren de las de `frame` (cambio de modo de video), `frame` se
    /// reinicia en negro con las nuevas dimensiones antes de aplicar los tiles.
    ///
    /// Sin tope del llamador: solo admite hasta [`MAX_FRAME_DIMENSION`] y el propio payload.
    /// Para payloads recibidos de la red usar [`TileDecoder::decode_into_bounded`].
    pub fn decode_into(
        &mut self,
        payload: &[u8],
        frame: &mut DecodedFrame,
    ) -> Result<Vec<DirtyRect>, TileCodecError> {
        let limits = DecodeLimits {
            payload_len: u32::try_from(payload.len()).map_err(|_| TileCodecError::LimitExceeded)?,
            max_width: MAX_FRAME_DIMENSION,
            max_height: MAX_FRAME_DIMENSION,
        };
        self.decode_into_bounded(payload, frame, limits)
    }

    /// Igual que [`TileDecoder::decode_into`], pero antes de reservar memoria exige que el
    /// payload mida exactamente `limits.payload_len` y que sus dimensiones y su cuerpo
    /// descomprimido quepan en el monitor negociado (`LimitExceeded` si no).
    pub fn decode_into_bounded(
        &mut self,
        payload: &[u8],
        frame: &mut DecodedFrame,
        limits: DecodeLimits,
    ) -> Result<Vec<DirtyRect>, TileCodecError> {
        if payload.len() != limits.payload_len as usize {
            return Err(TileCodecError::LimitExceeded);
        }
        if payload.len() < TILE_PAYLOAD_HEADER_LEN {
            return Err(TileCodecError::Malformed);
        }
        if payload[0] != TILE_FORMAT_VERSION {
            return Err(TileCodecError::UnsupportedVersion(payload[0]));
        }
        let tile_size = u32::from(u16::from_le_bytes([payload[2], payload[3]]));
        let width = read_u32(payload, 4);
        let height = read_u32(payload, 8);
        let tile_count = read_u32(payload, 12) as usize;
        let raw_len = read_u32(payload, 16) as usize;
        if payload[1] != 0 || tile_size != TILE_SIZE {
            return Err(TileCodecError::Malformed);
        }
        validate_dimensions(width, height)?;
        if width > limits.max_width || height > limits.max_height {
            return Err(TileCodecError::LimitExceeded);
        }
        let (cols, rows) = grid(width, height);
        let max_tile_record = TILE_RECORD_HEADER_LEN + (TILE_SIZE * TILE_SIZE) as usize * 4;
        if tile_count > cols * rows || raw_len > tile_count * max_tile_record {
            return Err(TileCodecError::Malformed);
        }
        // Un cuerpo legítimo son los píxeles del fotograma más una cabecera por tile.
        if raw_len > frame_len(width, height) + tile_count * TILE_RECORD_HEADER_LEN {
            return Err(TileCodecError::Malformed);
        }
        let compressed = &payload[TILE_PAYLOAD_HEADER_LEN..];
        // Solo frames zstd estándar: sin frames heredados ni "skippable".
        if !compressed.starts_with(&ZSTD_FRAME_MAGIC) {
            return Err(TileCodecError::Malformed);
        }

        self.body.clear();
        self.body.reserve(raw_len);
        let written = self
            .decompressor
            .decompress_to_buffer(compressed, &mut self.body)
            .map_err(|_| TileCodecError::Malformed)?;
        if written != raw_len || self.body.len() != raw_len {
            return Err(TileCodecError::Malformed);
        }

        // Primera pasada: validar la estructura completa sin tocar `frame`.
        let mut tiles = Vec::with_capacity(tile_count);
        let mut offset = 0usize;
        let mut previous_slot: Option<usize> = None;
        for _ in 0..tile_count {
            let header = self
                .body
                .get(offset..offset + TILE_RECORD_HEADER_LEN)
                .ok_or(TileCodecError::Malformed)?;
            let col = u32::from(u16::from_le_bytes([header[0], header[1]]));
            let row = u32::from(u16::from_le_bytes([header[2], header[3]]));
            if col as usize >= cols || row as usize >= rows {
                return Err(TileCodecError::Malformed);
            }
            let slot = row as usize * cols + col as usize;
            if previous_slot.is_some_and(|p| slot <= p) {
                return Err(TileCodecError::Malformed);
            }
            previous_slot = Some(slot);
            let rect = DirtyRect {
                x: col * TILE_SIZE,
                y: row * TILE_SIZE,
                width: TILE_SIZE.min(width - col * TILE_SIZE),
                height: TILE_SIZE.min(height - row * TILE_SIZE),
            };
            let pixels_len = rect.width as usize * rect.height as usize * BYTES_PER_PIXEL;
            let pixels_start = offset + TILE_RECORD_HEADER_LEN;
            if self.body.len() < pixels_start + pixels_len {
                return Err(TileCodecError::Malformed);
            }
            tiles.push((rect, pixels_start));
            offset = pixels_start + pixels_len;
        }
        if offset != self.body.len() {
            return Err(TileCodecError::Malformed);
        }

        // Segunda pasada: aplicar.
        if frame.width != width || frame.height != height {
            *frame = DecodedFrame::new(width, height);
        }
        let stride = width as usize * BYTES_PER_PIXEL;
        for (rect, pixels_start) in &tiles {
            let row_len = rect.width as usize * BYTES_PER_PIXEL;
            for dy in 0..rect.height as usize {
                let src = pixels_start + dy * row_len;
                let dst = (rect.y as usize + dy) * stride + rect.x as usize * BYTES_PER_PIXEL;
                frame.bgra[dst..dst + row_len].copy_from_slice(&self.body[src..src + row_len]);
            }
        }
        Ok(tiles.into_iter().map(|(rect, _)| rect).collect())
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), TileCodecError> {
    if width == 0 || height == 0 || width > MAX_FRAME_DIMENSION || height > MAX_FRAME_DIMENSION {
        return Err(TileCodecError::InvalidDimensions);
    }
    Ok(())
}

fn frame_len(width: u32, height: u32) -> usize {
    width as usize * height as usize * BYTES_PER_PIXEL
}

fn grid(width: u32, height: u32) -> (usize, usize) {
    (
        width.div_ceil(TILE_SIZE) as usize,
        height.div_ceil(TILE_SIZE) as usize,
    )
}

/// Recorta el rectángulo al fotograma; devuelve `(x0, y0, x1, y1)` exclusivo o `None` si queda vacío.
fn clip(rect: &DirtyRect, width: u32, height: u32) -> Option<(u32, u32, u32, u32)> {
    let x0 = rect.x.min(width);
    let y0 = rect.y.min(height);
    let x1 = rect.x.saturating_add(rect.width).min(width);
    let y1 = rect.y.saturating_add(rect.height).min(height);
    (x1 > x0 && y1 > y0).then_some((x0, y0, x1, y1))
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Patrón determinista no trivial (LCG) para que cada píxel sea distinto.
    fn pattern_frame(width: u32, height: u32, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..frame_len(width, height))
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn rect(x: u32, y: u32, width: u32, height: u32) -> DirtyRect {
        DirtyRect {
            x,
            y,
            width,
            height,
        }
    }

    fn tile_count(payload: &[u8]) -> u32 {
        read_u32(payload, 12)
    }

    #[test]
    fn keyframe_round_trip_is_lossless_with_partial_edge_tiles() {
        // 130x70 no es múltiplo de 64: la última columna mide 2 px y la última fila 6 px.
        let (w, h) = (130, 70);
        let source = pattern_frame(w, h, 7);
        let mut encoder = TileEncoder::new().unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let payload = encoder.encode_keyframe(w, h, &source).unwrap();
        assert_eq!(tile_count(&payload), 3 * 2);

        let mut frame = DecodedFrame::new(1, 1);
        let rects = decoder.decode_into(&payload, &mut frame).unwrap();
        assert_eq!((frame.width, frame.height), (w, h));
        assert_eq!(frame.bgra, source);
        assert_eq!(rects.len(), 6);
        assert_eq!(rects.last(), Some(&rect(128, 64, 2, 6)));
    }

    #[test]
    fn empty_rect_list_and_empty_rects_produce_a_payload_without_tiles() {
        let (w, h) = (64, 64);
        let source = pattern_frame(w, h, 1);
        let mut encoder = TileEncoder::new().unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(w, h);
        let before = frame.clone();

        for rects in [&[][..], &[rect(10, 10, 0, 5), rect(64, 0, 10, 10)][..]] {
            let payload = encoder.encode_rects(w, h, &source, rects).unwrap();
            assert_eq!(tile_count(&payload), 0);
            assert!(
                decoder
                    .decode_into(&payload, &mut frame)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(frame, before);
        }
    }

    #[test]
    fn blank_tiles_round_trip_and_compress() {
        let (w, h) = (256, 128);
        let source = vec![0u8; frame_len(w, h)];
        let mut encoder = TileEncoder::new().unwrap();
        let payload = encoder.encode_keyframe(w, h, &source).unwrap();
        assert!(payload.len() < source.len() / 100);

        let mut frame = DecodedFrame::new(w, h);
        frame.bgra.fill(0xAA);
        TileDecoder::new()
            .unwrap()
            .decode_into(&payload, &mut frame)
            .unwrap();
        assert_eq!(frame.bgra, source);
    }

    #[test]
    fn corner_pixel_and_overflowing_rect_touch_only_their_tiles() {
        let (w, h) = (130, 70);
        let first = pattern_frame(w, h, 3);
        let mut encoder = TileEncoder::new().unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(w, h);
        decoder
            .decode_into(&encoder.encode_keyframe(w, h, &first).unwrap(), &mut frame)
            .unwrap();

        let second = pattern_frame(w, h, 4);
        // Píxel de la esquina inferior derecha y un rectángulo que se sale del fotograma.
        let rects = [rect(129, 69, 1, 1), rect(120, 0, u32::MAX, 10)];
        let payload = encoder.encode_rects(w, h, &second, &rects).unwrap();
        let updated = decoder.decode_into(&payload, &mut frame).unwrap();
        assert_eq!(
            updated,
            vec![
                rect(64, 0, 64, 64),
                rect(128, 0, 2, 64),
                rect(128, 64, 2, 6)
            ]
        );

        let stride = w as usize * 4;
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride + x * 4;
                let in_updated = updated.iter().any(|r| {
                    (r.x as usize..(r.x + r.width) as usize).contains(&x)
                        && (r.y as usize..(r.y + r.height) as usize).contains(&y)
                });
                let expected = if in_updated { &second } else { &first };
                assert_eq!(
                    &frame.bgra[i..i + 4],
                    &expected[i..i + 4],
                    "pixel ({x},{y})"
                );
            }
        }
    }

    #[test]
    fn dimension_change_resets_the_decoded_frame() {
        let mut encoder = TileEncoder::new().unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(100, 100);
        let source = pattern_frame(80, 40, 9);
        decoder
            .decode_into(
                &encoder.encode_keyframe(80, 40, &source).unwrap(),
                &mut frame,
            )
            .unwrap();
        assert_eq!(
            frame,
            DecodedFrame {
                width: 80,
                height: 40,
                bgra: source
            }
        );
    }

    #[test]
    fn encoder_rejects_invalid_input() {
        let mut encoder = TileEncoder::new().unwrap();
        assert_eq!(
            encoder.encode_keyframe(0, 10, &[]),
            Err(TileCodecError::InvalidDimensions)
        );
        assert_eq!(
            encoder.encode_keyframe(MAX_FRAME_DIMENSION + 1, 1, &[]),
            Err(TileCodecError::InvalidDimensions)
        );
        assert_eq!(
            encoder.encode_keyframe(2, 2, &[0; 15]),
            Err(TileCodecError::BufferSizeMismatch)
        );
    }

    fn handmade_payload(width: u32, height: u32, tile_count: u32, body: &[u8]) -> Vec<u8> {
        let mut out = vec![TILE_FORMAT_VERSION, 0];
        out.extend_from_slice(&(TILE_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&tile_count.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&zstd::bulk::compress(body, ZSTD_LEVEL).unwrap());
        out
    }

    fn tile_record(col: u16, row: u16, pixels: usize) -> Vec<u8> {
        let mut out = col.to_le_bytes().to_vec();
        out.extend_from_slice(&row.to_le_bytes());
        out.resize(4 + pixels * 4, 0x11);
        out
    }

    #[test]
    fn decoder_rejects_malformed_payloads_without_touching_the_frame() {
        let (w, h) = (130, 70);
        let valid = TileEncoder::new()
            .unwrap()
            .encode_keyframe(w, h, &pattern_frame(w, h, 5))
            .unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(w, h);
        let before = frame.clone();

        let mut bad_version = valid.clone();
        bad_version[0] = 2;
        let mut bad_reserved = valid.clone();
        bad_reserved[1] = 1;
        let mut bad_tile_size = valid.clone();
        bad_tile_size[2] = 32;
        let mut bad_count = valid.clone();
        bad_count[12] = 7;
        let mut bad_raw_len = valid.clone();
        bad_raw_len[16] ^= 1;
        let mut not_zstd = valid.clone();
        not_zstd[TILE_PAYLOAD_HEADER_LEN] ^= 0xFF;
        let mut huge = valid.clone();
        huge[4..8].copy_from_slice(&(MAX_FRAME_DIMENSION + 1).to_le_bytes());

        let tile = 64 * 64;
        let out_of_grid = handmade_payload(w, h, 1, &tile_record(3, 0, tile));
        let mut unordered_body = tile_record(1, 0, tile);
        unordered_body.extend(tile_record(0, 0, tile));
        let unordered = handmade_payload(w, h, 2, &unordered_body);
        let mut trailing_body = tile_record(0, 0, tile);
        trailing_body.push(0);
        let trailing = handmade_payload(w, h, 1, &trailing_body);
        let short_edge = handmade_payload(w, h, 1, &tile_record(2, 1, 2 * 6 - 1));

        let cases: Vec<(&str, Vec<u8>, TileCodecError)> = vec![
            ("truncado", valid[..10].to_vec(), TileCodecError::Malformed),
            (
                "version",
                bad_version,
                TileCodecError::UnsupportedVersion(2),
            ),
            ("reservado", bad_reserved, TileCodecError::Malformed),
            ("tile", bad_tile_size, TileCodecError::Malformed),
            ("conteo", bad_count, TileCodecError::Malformed),
            ("raw_len", bad_raw_len, TileCodecError::Malformed),
            ("magic", not_zstd, TileCodecError::Malformed),
            ("dimension", huge, TileCodecError::InvalidDimensions),
            ("fuera de rejilla", out_of_grid, TileCodecError::Malformed),
            ("desordenado", unordered, TileCodecError::Malformed),
            ("sobrante", trailing, TileCodecError::Malformed),
            ("borde corto", short_edge, TileCodecError::Malformed),
        ];
        for (name, payload, expected) in cases {
            assert_eq!(
                decoder.decode_into(&payload, &mut frame),
                Err(expected),
                "{name}"
            );
            assert_eq!(frame, before, "{name}");
        }

        // El decodificador sigue operativo tras los rechazos.
        decoder.decode_into(&valid, &mut frame).unwrap();
        assert_ne!(frame, before);
    }

    fn limits_for(payload: &[u8], max_width: u32, max_height: u32) -> DecodeLimits {
        DecodeLimits {
            payload_len: payload.len() as u32,
            max_width,
            max_height,
        }
    }

    #[test]
    fn bounded_decoder_accepts_a_payload_within_limits() {
        let (w, h) = (130, 70);
        let bgra = vec![0x22; w as usize * h as usize * 4];
        let payload = TileEncoder::new()
            .unwrap()
            .encode_keyframe(w, h, &bgra)
            .unwrap();
        let mut frame = DecodedFrame::new(w, h);
        TileDecoder::new()
            .unwrap()
            .decode_into_bounded(&payload, &mut frame, limits_for(&payload, w, h))
            .unwrap();
        assert_eq!(frame.bgra, bgra);
    }

    #[test]
    fn bounded_decoder_rejects_payload_len_mismatch_and_oversized_dimensions() {
        let (w, h) = (130, 70);
        let bgra = vec![0x22; w as usize * h as usize * 4];
        let payload = TileEncoder::new()
            .unwrap()
            .encode_keyframe(w, h, &bgra)
            .unwrap();
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(w, h);
        let before = frame.clone();

        let mut short = limits_for(&payload, w, h);
        short.payload_len -= 1;
        let mut long = limits_for(&payload, w, h);
        long.payload_len += 1;
        for (name, limits) in [
            ("payload_len menor", short),
            ("payload_len mayor", long),
            ("ancho mayor que el monitor", limits_for(&payload, w - 1, h)),
            ("alto mayor que el monitor", limits_for(&payload, w, h - 1)),
        ] {
            assert_eq!(
                decoder.decode_into_bounded(&payload, &mut frame, limits),
                Err(TileCodecError::LimitExceeded),
                "{name}"
            );
        }
        assert_eq!(frame, before);
    }

    #[test]
    fn hostile_raw_len_is_rejected_before_reserving_memory() {
        // Una sola tile declarando un cuerpo de ~256 MiB en un monitor de 64x64.
        let mut payload = handmade_payload(64, 64, 1, &tile_record(0, 0, 64 * 64));
        payload[16..20].copy_from_slice(&(256u32 * 1024 * 1024).to_le_bytes());
        let mut decoder = TileDecoder::new().unwrap();
        let mut frame = DecodedFrame::new(64, 64);
        assert_eq!(
            decoder.decode_into_bounded(&payload, &mut frame, limits_for(&payload, 64, 64)),
            Err(TileCodecError::Malformed)
        );
        // Muchas tiles en un monitor grande tampoco sobrepasan el tamaño del fotograma negociado.
        let mut many = handmade_payload(64, 64, 1, &tile_record(0, 0, 64 * 64));
        many[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        many[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decoder.decode_into_bounded(&many, &mut frame, limits_for(&many, 64, 64)),
            Err(TileCodecError::Malformed | TileCodecError::LimitExceeded)
        ));
        assert!(decoder.body.capacity() < 1024 * 1024);
    }
}
