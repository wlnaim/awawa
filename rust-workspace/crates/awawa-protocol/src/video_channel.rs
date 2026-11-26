//! Cifrado del video Host→Operador por stream QUIC unidireccional.
//!
//! El video no usa `SecureChannel`: cada fotograma viaja por un stream unidireccional propio y el
//! relay los copia opacos, así que un contador compartido no sirve y reutilizar la clave de control
//! en un stream nuevo repetiría nonces. Se usa una clave propia derivada en el handshake
//! (`support-protocol/v1 key video host->op`).
//!
//! Cada stream empieza con un preámbulo de 4 bytes: el identificador de stream `u32` BE. El host lo
//! asigna de forma monótona (0, 1, 2, ...) y nunca lo repite en la sesión; el operador rechaza un
//! identificador repetido o menor que el último aceptado.
//!
//! Registro: `[contador u32 BE][VideoPacketHeader 24 B][texto cifrado de payload_len B + etiqueta 16 B]`.
//! Nonce de 96 bits: `[dominio u32 BE = 3][stream u32 BE][contador u32 BE]`; el dominio 3 lo separa
//! de los nonces del canal de control (prefijos 1 y 2). AAD = contador ‖ cabecera de video, de modo
//! que `payload_len`, códec, monitor y marca de keyframe quedan autenticados.
//! El receptor exige exactamente el siguiente contador dentro del stream y acota `payload_len` a
//! [`MAX_VIDEO_PAYLOAD_LEN`] antes de reservar memoria. Cualquier error deja inutilizable el stream
//! (y, si es de identificador, el abridor completo); quien integra debe cerrar la sesión.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::secure_channel::RECORD_TAG_LEN;
use crate::wire::{VIDEO_PACKET_HEADER_LEN, VideoPacketHeader, WireError};

/// Bytes del preámbulo de cada stream de video (identificador de stream `u32` BE).
pub const VIDEO_STREAM_PREAMBLE_LEN: usize = 4;
/// Bytes del contador al inicio de cada registro de video.
pub const VIDEO_RECORD_COUNTER_LEN: usize = 4;
/// Bytes que preceden al texto cifrado: contador + cabecera de video. Basta leerlos para conocer la
/// longitud total del registro con [`VideoStreamOpener::record_len`].
pub const VIDEO_RECORD_PREFIX_LEN: usize = VIDEO_RECORD_COUNTER_LEN + VIDEO_PACKET_HEADER_LEN;
/// Tope de `payload_len` (64 MiB). Cubre el peor caso de un fotograma 4K BGRA sin compresión
/// posible (3840 × 2160 × 4 ≈ 31,6 MiB más coordenadas de tiles y sobrecarga zstd) con margen.
/// Un payload mayor se rechaza en ambos extremos antes de cifrar o de reservar memoria.
pub const MAX_VIDEO_PAYLOAD_LEN: u32 = 64 * 1024 * 1024;

/// Dominio de nonce del video; el canal de control usa 1 (Host→Op) y 2 (Op→Host).
const VIDEO_NONCE_DOMAIN: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoChannelError {
    /// Identificador de stream repetido o menor que el último aceptado.
    StreamIdNotIncreasing { last: u32, received: u32 },
    /// El host agotó los identificadores de stream de la sesión.
    StreamIdsExhausted,
    /// Contador ya consumido dentro del stream.
    Replay { expected: u32, received: u32 },
    /// Contador adelantado dentro del stream (reordenamiento o pérdida).
    OutOfOrder { expected: u32, received: u32 },
    /// Etiqueta inválida: registro alterado, stream equivocado o clave distinta.
    AuthenticationFailed,
    /// Cabecera de video inválida.
    InvalidHeader(WireError),
    /// `payload_len` mayor que [`MAX_VIDEO_PAYLOAD_LEN`].
    PayloadTooLarge { payload_len: u32 },
    /// La longitud del registro o del payload no coincide con `payload_len`.
    LengthMismatch,
    /// Se agotó el contador del stream; hay que abrir otro.
    CounterExhausted,
    /// El stream o el abridor ya rechazó algo y quedó cerrado.
    Closed,
}

fn cipher_from(key: &Zeroizing<[u8; 32]>) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(<&Key>::from(&**key))
}

fn copy_key(key: &Zeroizing<[u8; 32]>) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&key[..]);
    out
}

fn video_nonce(stream_id: u32, counter: u32) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&VIDEO_NONCE_DOMAIN.to_be_bytes());
    nonce[4..8].copy_from_slice(&stream_id.to_be_bytes());
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(nonce)
}

fn check_payload_len(payload_len: u32) -> Result<(), VideoChannelError> {
    if payload_len > MAX_VIDEO_PAYLOAD_LEN {
        return Err(VideoChannelError::PayloadTooLarge { payload_len });
    }
    Ok(())
}

/// Lado del host: asigna identificadores de stream y crea un sellador por stream.
pub struct VideoSealer {
    key: Zeroizing<[u8; 32]>,
    next_stream_id: u64,
}

impl VideoSealer {
    pub(crate) fn new(key: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: copy_key(key),
            next_stream_id: 0,
        }
    }

    /// Reserva el siguiente identificador de stream. El host escribe
    /// [`VideoStreamSealer::preamble`] al inicio del stream unidireccional nuevo.
    pub fn open_stream(&mut self) -> Result<VideoStreamSealer, VideoChannelError> {
        let stream_id = u32::try_from(self.next_stream_id)
            .map_err(|_| VideoChannelError::StreamIdsExhausted)?;
        self.next_stream_id += 1;
        Ok(VideoStreamSealer {
            cipher: cipher_from(&self.key),
            stream_id,
            counter: 0,
        })
    }
}

/// Sellador de un stream de video.
pub struct VideoStreamSealer {
    cipher: ChaCha20Poly1305,
    stream_id: u32,
    counter: u32,
}

impl VideoStreamSealer {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Bytes que abren el stream: el identificador `u32` BE.
    pub fn preamble(&self) -> [u8; VIDEO_STREAM_PREAMBLE_LEN] {
        self.stream_id.to_be_bytes()
    }

    /// Cifra un paquete de video. `header.payload_len` debe ser igual a `payload.len()` y no
    /// superar [`MAX_VIDEO_PAYLOAD_LEN`].
    pub fn seal(
        &mut self,
        header: &VideoPacketHeader,
        payload: &[u8],
    ) -> Result<Vec<u8>, VideoChannelError> {
        check_payload_len(header.payload_len)?;
        if payload.len() != header.payload_len as usize {
            return Err(VideoChannelError::LengthMismatch);
        }
        let counter = self.counter;
        if counter == u32::MAX {
            return Err(VideoChannelError::CounterExhausted);
        }
        let mut record =
            Vec::with_capacity(VIDEO_RECORD_PREFIX_LEN + payload.len() + RECORD_TAG_LEN);
        record.extend_from_slice(&counter.to_be_bytes());
        record.extend_from_slice(&header.to_bytes());
        let ciphertext = self
            .cipher
            .encrypt(
                &video_nonce(self.stream_id, counter),
                Payload {
                    msg: payload,
                    aad: &record,
                },
            )
            .map_err(|_| VideoChannelError::AuthenticationFailed)?;
        self.counter = counter + 1;
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
}

/// Lado del operador: valida los identificadores de stream y crea un abridor por stream.
pub struct VideoOpener {
    key: Zeroizing<[u8; 32]>,
    last_stream_id: Option<u32>,
    closed: bool,
}

impl VideoOpener {
    pub(crate) fn new(key: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: copy_key(key),
            last_stream_id: None,
            closed: false,
        }
    }

    /// Acepta un stream nuevo a partir de su preámbulo. Rechaza un identificador repetido o menor
    /// que el último aceptado; tras un rechazo el abridor queda cerrado.
    pub fn accept_stream(
        &mut self,
        preamble: [u8; VIDEO_STREAM_PREAMBLE_LEN],
    ) -> Result<VideoStreamOpener, VideoChannelError> {
        if self.closed {
            return Err(VideoChannelError::Closed);
        }
        let received = u32::from_be_bytes(preamble);
        if let Some(last) = self.last_stream_id
            && received <= last
        {
            self.closed = true;
            return Err(VideoChannelError::StreamIdNotIncreasing { last, received });
        }
        self.last_stream_id = Some(received);
        Ok(VideoStreamOpener {
            cipher: cipher_from(&self.key),
            stream_id: received,
            counter: 0,
            closed: false,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Abridor de un stream de video: contador estricto, tope de tamaño y cierre ante cualquier error.
pub struct VideoStreamOpener {
    cipher: ChaCha20Poly1305,
    stream_id: u32,
    counter: u32,
    closed: bool,
}

impl VideoStreamOpener {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    /// Longitud total del registro a partir de sus primeros [`VIDEO_RECORD_PREFIX_LEN`] bytes.
    /// Valida la cabecera y el tope de `payload_len` antes de que el llamador reserve el búfer.
    pub fn record_len(&mut self, prefix: &[u8]) -> Result<usize, VideoChannelError> {
        if self.closed {
            return Err(VideoChannelError::Closed);
        }
        let result = Self::parse_prefix(prefix)
            .map(|header| VIDEO_RECORD_PREFIX_LEN + header.payload_len as usize + RECORD_TAG_LEN);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    /// Verifica y descifra el siguiente registro del stream.
    pub fn open(
        &mut self,
        record: &[u8],
    ) -> Result<(VideoPacketHeader, Vec<u8>), VideoChannelError> {
        if self.closed {
            return Err(VideoChannelError::Closed);
        }
        let result = self.open_inner(record);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn parse_prefix(prefix: &[u8]) -> Result<VideoPacketHeader, VideoChannelError> {
        if prefix.len() < VIDEO_RECORD_PREFIX_LEN {
            return Err(VideoChannelError::LengthMismatch);
        }
        let header = VideoPacketHeader::from_bytes(
            &prefix[VIDEO_RECORD_COUNTER_LEN..VIDEO_RECORD_PREFIX_LEN],
        )
        .map_err(VideoChannelError::InvalidHeader)?;
        check_payload_len(header.payload_len)?;
        Ok(header)
    }

    fn open_inner(
        &mut self,
        record: &[u8],
    ) -> Result<(VideoPacketHeader, Vec<u8>), VideoChannelError> {
        let header = Self::parse_prefix(record)?;
        if record.len() != VIDEO_RECORD_PREFIX_LEN + header.payload_len as usize + RECORD_TAG_LEN {
            return Err(VideoChannelError::LengthMismatch);
        }
        let mut counter_bytes = [0u8; VIDEO_RECORD_COUNTER_LEN];
        counter_bytes.copy_from_slice(&record[..VIDEO_RECORD_COUNTER_LEN]);
        let received = u32::from_be_bytes(counter_bytes);
        let expected = self.counter;
        if received < expected {
            return Err(VideoChannelError::Replay { expected, received });
        }
        if received > expected {
            return Err(VideoChannelError::OutOfOrder { expected, received });
        }
        if expected == u32::MAX {
            return Err(VideoChannelError::CounterExhausted);
        }
        let (aad, ciphertext) = record.split_at(VIDEO_RECORD_PREFIX_LEN);
        let payload = self
            .cipher
            .decrypt(
                &video_nonce(self.stream_id, received),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| VideoChannelError::AuthenticationFailed)?;
        self.counter = expected + 1;
        Ok((header, payload))
    }
}

impl fmt::Debug for VideoSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoSealer")
            .field("next_stream_id", &self.next_stream_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VideoStreamSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoStreamSealer")
            .field("stream_id", &self.stream_id)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VideoOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoOpener")
            .field("last_stream_id", &self.last_stream_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VideoStreamOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoStreamOpener")
            .field("stream_id", &self.stream_id)
            .field("counter", &self.counter)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::VideoCodec;

    fn pair() -> (VideoSealer, VideoOpener) {
        let key = Zeroizing::new([0x33u8; 32]);
        (VideoSealer::new(&key), VideoOpener::new(&key))
    }

    fn header(frame_seq: u64, payload_len: u32) -> VideoPacketHeader {
        VideoPacketHeader {
            frame_seq,
            capture_ts_us: 1_000 + frame_seq,
            monitor_index: 0,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: frame_seq == 0,
            payload_len,
        }
    }

    #[test]
    fn records_roundtrip_across_independent_streams() {
        let (mut sealer, mut opener) = pair();
        let mut s0 = sealer.open_stream().unwrap();
        let mut s1 = sealer.open_stream().unwrap();
        assert_eq!((s0.stream_id(), s1.stream_id()), (0, 1));
        let mut o0 = opener.accept_stream(s0.preamble()).unwrap();
        let mut o1 = opener.accept_stream(s1.preamble()).unwrap();
        // Los streams avanzan por separado: el contador de uno no afecta al otro.
        for i in 0..3u8 {
            let rec = s1.seal(&header(u64::from(i), 4), &[i; 4]).unwrap();
            let (h, p) = o1.open(&rec).unwrap();
            assert_eq!((h, p), (header(u64::from(i), 4), vec![i; 4]));
        }
        let rec = s0.seal(&header(0, 3), b"abc").unwrap();
        assert_eq!(
            o0.record_len(&rec[..VIDEO_RECORD_PREFIX_LEN]),
            Ok(rec.len())
        );
        assert_eq!(o0.open(&rec).unwrap().1, b"abc");
        // Payload vacío también es válido.
        let rec = s0.seal(&header(1, 0), b"").unwrap();
        assert_eq!(o0.open(&rec).unwrap().1, b"");
    }

    #[test]
    fn same_counter_on_different_streams_yields_different_ciphertext() {
        let (mut sealer, _) = pair();
        let mut s0 = sealer.open_stream().unwrap();
        let mut s1 = sealer.open_stream().unwrap();
        let a = s0.seal(&header(0, 8), &[7; 8]).unwrap();
        let b = s1.seal(&header(0, 8), &[7; 8]).unwrap();
        assert_eq!(a[..VIDEO_RECORD_PREFIX_LEN], b[..VIDEO_RECORD_PREFIX_LEN]);
        assert_ne!(a[VIDEO_RECORD_PREFIX_LEN..], b[VIDEO_RECORD_PREFIX_LEN..]);
    }

    #[test]
    fn repeated_or_decreasing_stream_id_is_rejected_and_closes_opener() {
        let (_, mut opener) = pair();
        opener.accept_stream(5u32.to_be_bytes()).unwrap();
        assert_eq!(
            opener.accept_stream(5u32.to_be_bytes()).unwrap_err(),
            VideoChannelError::StreamIdNotIncreasing {
                last: 5,
                received: 5
            }
        );
        assert!(opener.is_closed());
        assert_eq!(
            opener.accept_stream(6u32.to_be_bytes()).unwrap_err(),
            VideoChannelError::Closed
        );

        let (_, mut opener) = pair();
        opener.accept_stream(2u32.to_be_bytes()).unwrap();
        assert_eq!(
            opener.accept_stream(1u32.to_be_bytes()).unwrap_err(),
            VideoChannelError::StreamIdNotIncreasing {
                last: 2,
                received: 1
            }
        );
    }

    #[test]
    fn record_from_another_stream_fails_authentication() {
        let (mut sealer, mut opener) = pair();
        let mut s0 = sealer.open_stream().unwrap();
        let s1 = sealer.open_stream().unwrap();
        let _o0 = opener.accept_stream(s0.preamble()).unwrap();
        let mut o1 = opener.accept_stream(s1.preamble()).unwrap();
        let rec = s0.seal(&header(0, 4), b"tile").unwrap();
        assert_eq!(o1.open(&rec), Err(VideoChannelError::AuthenticationFailed));
        assert!(o1.is_closed());
    }

    #[test]
    fn replay_and_reorder_within_stream_are_rejected() {
        let (mut sealer, mut opener) = pair();
        let mut s = sealer.open_stream().unwrap();
        let first = s.seal(&header(0, 1), b"a").unwrap();
        let second = s.seal(&header(1, 1), b"b").unwrap();

        let mut o = opener.accept_stream(s.preamble()).unwrap();
        o.open(&first).unwrap();
        assert_eq!(
            o.open(&first),
            Err(VideoChannelError::Replay {
                expected: 1,
                received: 0
            })
        );
        assert_eq!(o.open(&second), Err(VideoChannelError::Closed));

        let (mut sealer, mut opener) = pair();
        let mut s = sealer.open_stream().unwrap();
        let _first = s.seal(&header(0, 1), b"a").unwrap();
        let second = s.seal(&header(1, 1), b"b").unwrap();
        let mut o = opener.accept_stream(s.preamble()).unwrap();
        assert_eq!(
            o.open(&second),
            Err(VideoChannelError::OutOfOrder {
                expected: 0,
                received: 1
            })
        );
        assert!(o.is_closed());
    }

    #[test]
    fn tampered_header_or_payload_fails_authentication() {
        let (mut sealer, mut opener) = pair();
        let mut s = sealer.open_stream().unwrap();
        let rec = s.seal(&header(0, 6), b"pixels").unwrap();
        let preamble = s.preamble();
        // Byte de frame_seq, de monitor, de keyframe y del texto cifrado.
        for byte in [
            VIDEO_RECORD_COUNTER_LEN,
            VIDEO_RECORD_COUNTER_LEN + 20,
            VIDEO_RECORD_COUNTER_LEN + 22,
            rec.len() - 1,
        ] {
            let mut tampered = rec.clone();
            tampered[byte] ^= 0x01;
            let (_, mut fresh) = pair();
            let mut o = fresh.accept_stream(preamble).unwrap();
            assert_eq!(
                o.open(&tampered),
                Err(VideoChannelError::AuthenticationFailed)
            );
        }
        // Preámbulo alterado: el identificador forma parte del nonce.
        let mut o = opener.accept_stream(7u32.to_be_bytes()).unwrap();
        assert_eq!(o.open(&rec), Err(VideoChannelError::AuthenticationFailed));
    }

    #[test]
    fn payload_len_is_bounded_and_must_match_record() {
        let (mut sealer, mut opener) = pair();
        let mut s = sealer.open_stream().unwrap();
        assert_eq!(
            s.seal(&header(0, 3), b"abcd").unwrap_err(),
            VideoChannelError::LengthMismatch
        );
        assert_eq!(
            s.seal(&header(0, MAX_VIDEO_PAYLOAD_LEN + 1), b"")
                .unwrap_err(),
            VideoChannelError::PayloadTooLarge {
                payload_len: MAX_VIDEO_PAYLOAD_LEN + 1
            }
        );

        // Prefijo que declara un payload enorme: se rechaza sin reservar memoria.
        let mut prefix = [0u8; VIDEO_RECORD_PREFIX_LEN];
        prefix[VIDEO_RECORD_COUNTER_LEN..].copy_from_slice(&header(0, u32::MAX).to_bytes());
        let mut o = opener.accept_stream(s.preamble()).unwrap();
        assert_eq!(
            o.record_len(&prefix),
            Err(VideoChannelError::PayloadTooLarge {
                payload_len: u32::MAX
            })
        );
        assert!(o.is_closed());

        // Registro truncado, con bytes sobrantes, cabecera inválida o prefijo corto.
        let rec = s.seal(&header(0, 3), b"abc").unwrap();
        let mut long = rec.clone();
        long.push(0);
        let mut bad_codec = rec.clone();
        bad_codec[VIDEO_RECORD_COUNTER_LEN + 21] = 9;
        for (bad, expected) in [
            (
                rec[..rec.len() - 1].to_vec(),
                VideoChannelError::LengthMismatch,
            ),
            (long, VideoChannelError::LengthMismatch),
            (
                bad_codec,
                VideoChannelError::InvalidHeader(WireError::UnknownVideoCodec(9)),
            ),
            (rec[..10].to_vec(), VideoChannelError::LengthMismatch),
        ] {
            let (_, mut fresh) = pair();
            let mut o = fresh.accept_stream(s.preamble()).unwrap();
            assert_eq!(o.open(&bad), Err(expected));
            assert!(o.is_closed());
        }
    }

    #[test]
    fn exhausted_stream_ids_and_counters_fail_closed() {
        let (mut sealer, mut opener) = pair();
        sealer.next_stream_id = u64::from(u32::MAX);
        let mut s = sealer.open_stream().unwrap();
        assert_eq!(s.stream_id(), u32::MAX);
        assert_eq!(
            sealer.open_stream().unwrap_err(),
            VideoChannelError::StreamIdsExhausted
        );
        s.counter = u32::MAX;
        assert_eq!(
            s.seal(&header(0, 1), b"x").unwrap_err(),
            VideoChannelError::CounterExhausted
        );
        let mut o = opener.accept_stream(s.preamble()).unwrap();
        o.counter = u32::MAX;
        let mut rec = vec![0xFF; VIDEO_RECORD_COUNTER_LEN];
        rec.extend_from_slice(&header(0, 0).to_bytes());
        rec.extend_from_slice(&[0u8; RECORD_TAG_LEN]);
        assert_eq!(o.open(&rec), Err(VideoChannelError::CounterExhausted));
    }

    #[test]
    fn nonce_domain_is_separate_from_control_channel() {
        let nonce = video_nonce(0x0102_0304, 0x0A0B_0C0D);
        assert_eq!(
            nonce.as_slice(),
            &[0, 0, 0, 3, 1, 2, 3, 4, 0x0A, 0x0B, 0x0C, 0x0D]
        );
    }
}
