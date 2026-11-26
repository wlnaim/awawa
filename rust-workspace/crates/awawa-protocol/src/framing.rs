//! Delimitación de tramas del canal de control: prefijo de longitud `u32` big-endian seguido del
//! contenido. Ninguna trama puede superar `MAX_CTRL_FRAME` (64 KiB); la longitud declarada se
//! valida antes de reservar memoria.

/// Tamaño máximo del contenido de una trama de control.
pub const MAX_CTRL_FRAME: usize = 64 * 1024;

/// Longitud del prefijo de cada trama.
pub const FRAME_LEN_PREFIX: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramingError {
    /// La trama (declarada o a enviar) excede `MAX_CTRL_FRAME`.
    FrameTooLarge(usize),
    /// Trama de longitud cero.
    EmptyFrame,
    /// Faltan bytes para completar el prefijo o el contenido.
    Incomplete,
}

/// Construye una trama `[len u32 BE][payload]`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if payload.is_empty() {
        return Err(FramingError::EmptyFrame);
    }
    if payload.len() > MAX_CTRL_FRAME {
        return Err(FramingError::FrameTooLarge(payload.len()));
    }
    let len =
        u32::try_from(payload.len()).map_err(|_| FramingError::FrameTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(FRAME_LEN_PREFIX + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Extrae la primera trama de `buf`. Devuelve el contenido y el total de bytes consumidos.
pub fn decode_frame(buf: &[u8]) -> Result<(&[u8], usize), FramingError> {
    let Some(prefix) = buf.get(..FRAME_LEN_PREFIX) else {
        return Err(FramingError::Incomplete);
    };
    let declared = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    if declared == 0 {
        return Err(FramingError::EmptyFrame);
    }
    if declared > MAX_CTRL_FRAME {
        return Err(FramingError::FrameTooLarge(declared));
    }
    let end = FRAME_LEN_PREFIX + declared;
    let Some(payload) = buf.get(FRAME_LEN_PREFIX..end) else {
        return Err(FramingError::Incomplete);
    };
    Ok((payload, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_concatenated_frames() {
        let mut stream = encode_frame(b"uno").unwrap();
        stream.extend_from_slice(&encode_frame(b"dos!").unwrap());

        let (first, used) = decode_frame(&stream).unwrap();
        assert_eq!(first, b"uno");
        let (second, used2) = decode_frame(&stream[used..]).unwrap();
        assert_eq!(second, b"dos!");
        assert_eq!(used + used2, stream.len());
    }

    #[test]
    fn frames_larger_than_64_kib_are_rejected() {
        let max = vec![0xAB; MAX_CTRL_FRAME];
        let framed = encode_frame(&max).unwrap();
        assert_eq!(decode_frame(&framed).unwrap().0.len(), MAX_CTRL_FRAME);

        let too_big = vec![0xAB; MAX_CTRL_FRAME + 1];
        assert_eq!(
            encode_frame(&too_big),
            Err(FramingError::FrameTooLarge(MAX_CTRL_FRAME + 1))
        );

        // Prefijo hostil que declara más de 64 KiB: se rechaza sin esperar el contenido.
        let declared = (MAX_CTRL_FRAME as u32 + 1).to_be_bytes();
        assert_eq!(
            decode_frame(&declared),
            Err(FramingError::FrameTooLarge(MAX_CTRL_FRAME + 1))
        );
        assert_eq!(
            decode_frame(&u32::MAX.to_be_bytes()),
            Err(FramingError::FrameTooLarge(u32::MAX as usize))
        );
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert_eq!(decode_frame(&[]), Err(FramingError::Incomplete));
        assert_eq!(decode_frame(&[0, 0, 1]), Err(FramingError::Incomplete));
        assert_eq!(decode_frame(&[0, 0, 0, 0]), Err(FramingError::EmptyFrame));
        assert_eq!(encode_frame(&[]), Err(FramingError::EmptyFrame));

        let framed = encode_frame(b"contenido").unwrap();
        assert_eq!(
            decode_frame(&framed[..framed.len() - 1]),
            Err(FramingError::Incomplete)
        );
    }
}
