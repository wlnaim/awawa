//! Canal AEAD `ChaCha20-Poly1305` con claves direccionales derivadas del handshake SPAKE2.
//!
//! Formato de registro: `[contador u64 BE][texto cifrado + etiqueta de 16 bytes]`.
//! Nonce de 96 bits: `[dirección u32 BE][contador u64 BE]`. El contador se autentica como AAD.
//! El receptor exige exactamente el siguiente contador: rechaza *replay* (contador ya visto) y
//! reordenamiento (contador adelantado). Cualquier error deja el canal inutilizable.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

/// Bytes de cabecera de cada registro (contador).
pub const RECORD_HEADER_LEN: usize = 8;
/// Bytes de la etiqueta Poly1305.
pub const RECORD_TAG_LEN: usize = 16;

/// Sentido del tráfico; cada sentido usa su propia clave y su propio prefijo de nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    HostToOperator,
    OperatorToHost,
}

impl Direction {
    fn nonce_prefix(self) -> [u8; 4] {
        match self {
            Self::HostToOperator => 1u32.to_be_bytes(),
            Self::OperatorToHost => 2u32.to_be_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Contador ya consumido (repetición de un registro anterior).
    Replay { expected: u64, received: u64 },
    /// Contador adelantado: falta un registro previo (reordenamiento o pérdida).
    OutOfOrder { expected: u64, received: u64 },
    /// Etiqueta inválida: registro alterado o clave distinta.
    AuthenticationFailed,
    /// Registro más corto que cabecera + etiqueta.
    Truncated,
    /// Se agotó el espacio de contadores; hay que renegociar.
    CounterExhausted,
    /// El canal ya rechazó un registro y quedó cerrado.
    Closed,
}

struct DirectionalKey {
    cipher: ChaCha20Poly1305,
    direction: Direction,
    counter: u64,
}

impl DirectionalKey {
    fn new(key: &Zeroizing<[u8; 32]>, direction: Direction) -> Self {
        Self {
            // Se construye desde una referencia: no queda copia temporal de la clave sin limpiar.
            cipher: ChaCha20Poly1305::new(<&Key>::from(&**key)),
            direction,
            counter: 0,
        }
    }

    fn nonce(&self, counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.direction.nonce_prefix());
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        Nonce::from(nonce)
    }
}

/// Canal cifrado de un extremo. Solo se obtiene de un handshake SPAKE2 exitoso.
pub struct SecureChannel {
    send: DirectionalKey,
    recv: DirectionalKey,
    closed: bool,
}

impl SecureChannel {
    pub(crate) fn new(
        send_key: &Zeroizing<[u8; 32]>,
        send_direction: Direction,
        recv_key: &Zeroizing<[u8; 32]>,
        recv_direction: Direction,
    ) -> Self {
        Self {
            send: DirectionalKey::new(send_key, send_direction),
            recv: DirectionalKey::new(recv_key, recv_direction),
            closed: false,
        }
    }

    /// Cifra `plaintext` como el siguiente registro del sentido de envío.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        let counter = self.send.counter;
        if counter == u64::MAX {
            return Err(ChannelError::CounterExhausted);
        }
        let header = counter.to_be_bytes();
        let ciphertext = self
            .send
            .cipher
            .encrypt(
                &self.send.nonce(counter),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| ChannelError::AuthenticationFailed)?;
        self.send.counter = counter + 1;
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// Verifica y descifra el siguiente registro del sentido de recepción.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if self.closed {
            return Err(ChannelError::Closed);
        }
        let result = self.open_inner(record);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn open_inner(&mut self, record: &[u8]) -> Result<Vec<u8>, ChannelError> {
        if record.len() < RECORD_HEADER_LEN + RECORD_TAG_LEN {
            return Err(ChannelError::Truncated);
        }
        let (header, ciphertext) = record.split_at(RECORD_HEADER_LEN);
        let mut counter_bytes = [0u8; RECORD_HEADER_LEN];
        counter_bytes.copy_from_slice(header);
        let received = u64::from_be_bytes(counter_bytes);
        let expected = self.recv.counter;
        if received < expected {
            return Err(ChannelError::Replay { expected, received });
        }
        if received > expected {
            return Err(ChannelError::OutOfOrder { expected, received });
        }
        if expected == u64::MAX {
            return Err(ChannelError::CounterExhausted);
        }
        let plaintext = self
            .recv
            .cipher
            .decrypt(
                &self.recv.nonce(received),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| ChannelError::AuthenticationFailed)?;
        self.recv.counter = expected + 1;
        Ok(plaintext)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureChannel")
            .field("send_direction", &self.send.direction)
            .field("send_counter", &self.send.counter)
            .field("recv_direction", &self.recv.direction)
            .field("recv_counter", &self.recv.counter)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SecureChannel, SecureChannel) {
        let h2o = Zeroizing::new([0x11u8; 32]);
        let o2h = Zeroizing::new([0x22u8; 32]);
        let host = SecureChannel::new(
            &h2o,
            Direction::HostToOperator,
            &o2h,
            Direction::OperatorToHost,
        );
        let operator = SecureChannel::new(
            &o2h,
            Direction::OperatorToHost,
            &h2o,
            Direction::HostToOperator,
        );
        (host, operator)
    }

    #[test]
    fn records_roundtrip_in_both_directions() {
        let (mut host, mut operator) = pair();
        for i in 0..3u8 {
            let rec = operator.seal(&[i; 5]).unwrap();
            assert_eq!(host.open(&rec).unwrap(), vec![i; 5]);
            let rec = host.seal(&[i; 7]).unwrap();
            assert_eq!(operator.open(&rec).unwrap(), vec![i; 7]);
        }
    }

    #[test]
    fn replay_is_rejected() {
        let (mut host, mut operator) = pair();
        let rec = operator.seal(b"clic").unwrap();
        host.open(&rec).unwrap();
        assert_eq!(
            host.open(&rec),
            Err(ChannelError::Replay {
                expected: 1,
                received: 0
            })
        );
        assert!(host.is_closed());
    }

    #[test]
    fn reordering_is_rejected() {
        let (mut host, mut operator) = pair();
        let first = operator.seal(b"uno").unwrap();
        let second = operator.seal(b"dos").unwrap();
        assert_eq!(
            host.open(&second),
            Err(ChannelError::OutOfOrder {
                expected: 0,
                received: 1
            })
        );
        assert_eq!(host.open(&first), Err(ChannelError::Closed));
    }

    #[test]
    fn flipped_bit_is_rejected() {
        let (mut host, mut operator) = pair();
        let rec = operator.seal(b"tecla").unwrap();
        for byte in [RECORD_HEADER_LEN, rec.len() - 1] {
            let (mut h, _) = pair();
            let mut tampered = rec.clone();
            tampered[byte] ^= 0x01;
            assert_eq!(h.open(&tampered), Err(ChannelError::AuthenticationFailed));
        }
        // Bit volteado en el contador: se detecta antes de descifrar.
        let mut tampered = rec.clone();
        tampered[RECORD_HEADER_LEN - 1] ^= 0x01;
        assert!(host.open(&tampered).is_err());
        assert!(
            host.open(&rec).is_err(),
            "el canal queda cerrado tras un rechazo"
        );
    }

    #[test]
    fn wrong_direction_key_cannot_open() {
        let (mut host, _operator) = pair();
        let (mut other_host, _) = pair();
        // Un registro emitido por el propio host no se acepta como si viniera del operador.
        let own = host.seal(b"eco").unwrap();
        assert_eq!(
            other_host.open(&own),
            Err(ChannelError::AuthenticationFailed)
        );
        assert_eq!(host.open(&[0u8; 10]), Err(ChannelError::Truncated));
    }
}
