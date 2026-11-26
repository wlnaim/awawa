//! Medición de codificación de tiles sobre un fotograma sintético de oficina a 1080p.
//!
//! `cargo run --release -p capture-win --example tile_bench`
//!
//! No toca la pantalla ni periféricos: el fotograma se genera en memoria.

use std::time::{Duration, Instant};

use capture_win::{DecodedFrame, DirtyRect, TileDecoder, TileEncoder};

const WIDTH: u32 = 1920;
const HEIGHT: u32 = 1080;
const ITERATIONS: usize = 200;

struct Canvas {
    bgra: Vec<u8>,
    rng: u32,
}

impl Canvas {
    fn new() -> Self {
        Self {
            bgra: vec![0xFF; WIDTH as usize * HEIGHT as usize * 4],
            rng: 0x1234_5678,
        }
    }

    fn next(&mut self) -> u32 {
        self.rng = self.rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.rng >> 8
    }

    fn put(&mut self, x: u32, y: u32, [b, g, r]: [u8; 3]) {
        if x < WIDTH && y < HEIGHT {
            let i = (y as usize * WIDTH as usize + x as usize) * 4;
            self.bgra[i..i + 4].copy_from_slice(&[b, g, r, 0xFF]);
        }
    }

    fn fill(&mut self, x: u32, y: u32, w: u32, h: u32, color: [u8; 3]) {
        for yy in y..y + h {
            for xx in x..x + w {
                self.put(xx, yy, color);
            }
        }
    }

    /// Líneas de "texto": glifos de 7x11 con bordes antialias y franjas de color tipo ClearType.
    fn text_block(&mut self, x: u32, y: u32, w: u32, h: u32, line_height: u32) {
        let mut line_y = y;
        while line_y + 11 <= y + h {
            let mut cursor_x = x;
            let line_end = x + w - (self.next() % (w / 3));
            while cursor_x + 8 < line_end {
                let word = 2 + self.next() % 9;
                for _ in 0..word {
                    for gy in 0..11 {
                        for gx in 0..7 {
                            let v = self.next() % 100;
                            let color = match v {
                                0..=54 => continue,
                                55..=69 => [0x20, 0x20, 0x20],
                                70..=79 => [0x90, 0x70, 0x60],
                                80..=89 => [0x60, 0x70, 0x90],
                                _ => [0xC0, 0xC0, 0xC0],
                            };
                            self.put(cursor_x + gx, line_y + gy, color);
                        }
                    }
                    cursor_x += 8;
                }
                cursor_x += 5;
            }
            line_y += line_height;
        }
    }
}

/// Escritorio de oficina: fondo, barra de tareas con iconos, una ventana con barra de título,
/// menú, barra lateral y documento de texto.
fn office_frame() -> Vec<u8> {
    let mut c = Canvas::new();
    c.fill(0, 0, WIDTH, HEIGHT, [0x80, 0x50, 0x20]);
    c.fill(0, HEIGHT - 48, WIDTH, 48, [0x20, 0x20, 0x20]);
    for i in 0..12 {
        let color = [(i * 40) as u8, (255 - i * 20) as u8, (i * 17) as u8];
        c.fill(16 + i * 48, HEIGHT - 40, 32, 32, color);
    }
    c.text_block(WIDTH - 140, HEIGHT - 40, 120, 30, 15);
    let (wx, wy, ww, wh) = (80, 40, 1760, 960);
    c.fill(wx, wy, ww, wh, [0xFF, 0xFF, 0xFF]);
    c.fill(wx, wy, ww, 32, [0xD7, 0x78, 0x00]);
    c.text_block(wx + 12, wy + 10, 400, 14, 14);
    c.fill(wx, wy + 32, ww, 28, [0xF3, 0xF3, 0xF3]);
    c.text_block(wx + 12, wy + 40, 700, 14, 14);
    c.fill(wx, wy + 60, 260, wh - 60, [0xF8, 0xF4, 0xF0]);
    c.text_block(wx + 16, wy + 76, 220, wh - 100, 22);
    c.text_block(wx + 300, wy + 90, ww - 360, wh - 120, 20);
    c.bgra
}

fn stats(label: &str, samples: &mut [Duration], payload_len: usize) {
    samples.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let mean = samples.iter().map(|d| ms(*d)).sum::<f64>() / samples.len() as f64;
    println!(
        "{label}: min {:.3} ms | mediana {:.3} ms | p95 {:.3} ms | media {:.3} ms | max {:.3} ms | payload {} B",
        ms(samples[0]),
        ms(samples[samples.len() / 2]),
        ms(samples[samples.len() * 95 / 100]),
        mean,
        ms(samples[samples.len() - 1]),
        payload_len
    );
}

fn main() {
    let frame = office_frame();
    let mut encoder = TileEncoder::new().expect("codificador");
    let mut decoder = TileDecoder::new().expect("decodificador");

    // Verificación sin pérdida antes de medir.
    let keyframe = encoder
        .encode_keyframe(WIDTH, HEIGHT, &frame)
        .expect("keyframe");
    let mut decoded = DecodedFrame::new(WIDTH, HEIGHT);
    decoder
        .decode_into(&keyframe, &mut decoded)
        .expect("decodificar");
    assert_eq!(decoded.bgra, frame, "ida y vuelta con pérdida");

    println!(
        "Fotograma sintetico de oficina {WIDTH}x{HEIGHT} BGRA ({} B), {ITERATIONS} iteraciones",
        frame.len()
    );

    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut len = 0;
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        len = encoder
            .encode_keyframe(WIDTH, HEIGHT, &frame)
            .unwrap()
            .len();
        samples.push(t.elapsed());
    }
    stats("Codificar fotograma completo (keyframe)", &mut samples, len);

    // Actualización típica: un párrafo editado (900x120) y el reloj de la barra de tareas.
    let rects = [
        DirtyRect {
            x: 380,
            y: 400,
            width: 900,
            height: 120,
        },
        DirtyRect {
            x: WIDTH - 140,
            y: HEIGHT - 40,
            width: 120,
            height: 30,
        },
    ];
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        len = encoder
            .encode_rects(WIDTH, HEIGHT, &frame, &rects)
            .unwrap()
            .len();
        samples.push(t.elapsed());
    }
    stats("Codificar dirty rects tipicos", &mut samples, len);

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        decoder.decode_into(&keyframe, &mut decoded).unwrap();
        samples.push(t.elapsed());
    }
    stats(
        "Decodificar fotograma completo",
        &mut samples,
        keyframe.len(),
    );
}
