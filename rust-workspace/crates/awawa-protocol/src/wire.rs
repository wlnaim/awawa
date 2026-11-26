//! Mensajes de red del canal de control y cabecera fija de video.
//!
//! Los mensajes de control se serializan con `postcard` y viajan dentro de registros AEAD
//! (`secure_channel`). La cabecera de video usa una codificación fija de 24 bytes.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::geometry::MonitorDescriptor;
use crate::messages::{ButtonState, KeyState, MouseButton, ScopedCapabilities};

/// Máscara de capacidades tal como viaja por red. Solo se convierte en `ScopedCapabilities`
/// mediante `ScopedCapabilities::from_wire_bits`, que rechaza bits fuera de alcance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMask(pub u32);

impl CapabilityMask {
    pub fn from_capabilities(caps: ScopedCapabilities) -> Self {
        Self(caps.to_wire_bits())
    }

    pub fn validate(self) -> Result<ScopedCapabilities, &'static str> {
        ScopedCapabilities::from_wire_bits(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectReason {
    UserRequested,
    ProtocolError,
}

/// Mensajes del Agente de Soporte (operador) hacia el Cliente Receptor (host).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientToHostMessage {
    ControlRequest {
        operator_display_name: String,
        client_version: String,
        requested_capabilities: CapabilityMask,
    },
    /// Rango normalizado `0..=65535` del escritorio virtual.
    PointerMove {
        norm_x: u16,
        norm_y: u16,
        monitor_id: Option<u8>,
    },
    PointerButton {
        button: MouseButton,
        state: ButtonState,
    },
    PointerWheel {
        delta_x: i16,
        delta_y: i16,
    },
    KeyboardEvent {
        scancode: u16,
        extended: bool,
        unicode_fallback: Option<char>,
        state: KeyState,
    },
    Ping {
        seq: u64,
        client_mono_us: u64,
    },
    Disconnect {
        reason: DisconnectReason,
    },
}

/// Mensajes del Cliente Receptor (host) hacia el Agente de Soporte (operador).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostToClientMessage {
    PendingApproval {
        timeout_secs: u16,
        session_fingerprint_short: [u8; 6],
    },
    ApprovalResult {
        granted: bool,
        reason: Option<String>,
        monitors: Vec<MonitorDescriptor>,
    },
    CursorShapeUpdate {
        cursor_hash: u64,
        hotspot_x: u16,
        hotspot_y: u16,
        width: u16,
        height: u16,
        bgra_zstd: Option<Vec<u8>>,
    },
    DisplayTopologyChanged {
        monitors: Vec<MonitorDescriptor>,
    },
    Pong {
        seq: u64,
        client_mono_us: u64,
    },
    SessionRevoked {
        reason: String,
    },
    /// El host suspendió video y entrada: Windows muestra el escritorio seguro (UAC, Winlogon o
    /// bloqueo) y solo el usuario local puede continuar. Va al final para no mover los índices.
    LocalApprovalRequired,
    /// El escritorio del usuario volvió: video y entrada se reanudan.
    LocalApprovalCleared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Bytes que no corresponden a un mensaje válido (incluye bytes sobrantes al final).
    Malformed,
    Encode,
    UnknownVideoCodec(u8),
    InvalidVideoHeader,
}

/// Serializa un mensaje con `postcard`.
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    postcard::to_allocvec(msg).map_err(|_| WireError::Encode)
}

/// Deserializa un mensaje completo; rechaza entrada truncada, inválida o con bytes sobrantes.
pub fn decode_message<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    let (msg, rest) = postcard::take_from_bytes::<T>(bytes).map_err(|_| WireError::Malformed)?;
    if !rest.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok(msg)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    /// Texto nítido en LAN.
    ZstdDirtyTiles = 1,
    /// WAN fluida.
    Vp9Realtime = 2,
}

impl TryFrom<u8> for VideoCodec {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ZstdDirtyTiles),
            2 => Ok(Self::Vp9Realtime),
            other => Err(WireError::UnknownVideoCodec(other)),
        }
    }
}

/// Tamaño fijo de la cabecera de video en el cable.
pub const VIDEO_PACKET_HEADER_LEN: usize = 24;

/// Cabecera de cada frame/tile de video (24 bytes, little-endian):
/// `[0..8] frame_seq`, `[8..16] capture_ts_us`, `[16..20] payload_len`, `[20] monitor_index`,
/// `[21] codec`, `[22] is_keyframe (0|1)`, `[23] reservado (0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoPacketHeader {
    pub frame_seq: u64,
    pub capture_ts_us: u64,
    pub monitor_index: u8,
    pub codec: VideoCodec,
    pub is_keyframe: bool,
    pub payload_len: u32,
}

impl VideoPacketHeader {
    pub fn to_bytes(&self) -> [u8; VIDEO_PACKET_HEADER_LEN] {
        let mut out = [0u8; VIDEO_PACKET_HEADER_LEN];
        out[0..8].copy_from_slice(&self.frame_seq.to_le_bytes());
        out[8..16].copy_from_slice(&self.capture_ts_us.to_le_bytes());
        out[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        out[20] = self.monitor_index;
        out[21] = self.codec as u8;
        out[22] = u8::from(self.is_keyframe);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let raw: &[u8; VIDEO_PACKET_HEADER_LEN] = bytes
            .try_into()
            .map_err(|_| WireError::InvalidVideoHeader)?;
        let codec = VideoCodec::try_from(raw[21])?;
        let is_keyframe = match raw[22] {
            0 => false,
            1 => true,
            _ => return Err(WireError::InvalidVideoHeader),
        };
        if raw[23] != 0 {
            return Err(WireError::InvalidVideoHeader);
        }
        let mut u64_buf = [0u8; 8];
        u64_buf.copy_from_slice(&raw[0..8]);
        let frame_seq = u64::from_le_bytes(u64_buf);
        u64_buf.copy_from_slice(&raw[8..16]);
        let capture_ts_us = u64::from_le_bytes(u64_buf);
        let mut u32_buf = [0u8; 4];
        u32_buf.copy_from_slice(&raw[16..20]);
        Ok(Self {
            frame_seq,
            capture_ts_us,
            monitor_index: raw[20],
            codec,
            is_keyframe,
            payload_len: u32::from_le_bytes(u32_buf),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> VideoPacketHeader {
        VideoPacketHeader {
            frame_seq: 0x0102_0304_0506_0708,
            capture_ts_us: 1_234_567_890,
            monitor_index: 2,
            codec: VideoCodec::ZstdDirtyTiles,
            is_keyframe: true,
            payload_len: 65_000,
        }
    }

    #[test]
    fn video_header_is_24_bytes_and_roundtrips() {
        let header = sample_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(VIDEO_PACKET_HEADER_LEN, 24);
        assert_eq!(VideoPacketHeader::from_bytes(&bytes).unwrap(), header);

        let vp9 = VideoPacketHeader {
            codec: VideoCodec::Vp9Realtime,
            is_keyframe: false,
            ..header
        };
        assert_eq!(VideoPacketHeader::from_bytes(&vp9.to_bytes()).unwrap(), vp9);
    }

    #[test]
    fn video_header_rejects_unknown_codec_and_bad_fields() {
        let mut bytes = sample_header().to_bytes();
        bytes[21] = 0;
        assert_eq!(
            VideoPacketHeader::from_bytes(&bytes),
            Err(WireError::UnknownVideoCodec(0))
        );
        bytes[21] = 3;
        assert_eq!(
            VideoPacketHeader::from_bytes(&bytes),
            Err(WireError::UnknownVideoCodec(3))
        );

        let mut bad_flag = sample_header().to_bytes();
        bad_flag[22] = 2;
        assert_eq!(
            VideoPacketHeader::from_bytes(&bad_flag),
            Err(WireError::InvalidVideoHeader)
        );

        let mut bad_reserved = sample_header().to_bytes();
        bad_reserved[23] = 1;
        assert_eq!(
            VideoPacketHeader::from_bytes(&bad_reserved),
            Err(WireError::InvalidVideoHeader)
        );

        let bytes = sample_header().to_bytes();
        assert_eq!(
            VideoPacketHeader::from_bytes(&bytes[..23]),
            Err(WireError::InvalidVideoHeader)
        );
    }

    #[test]
    fn control_messages_roundtrip_and_reject_malformed() {
        let msgs = vec![
            ClientToHostMessage::ControlRequest {
                operator_display_name: "Soporte".to_string(),
                client_version: "0.1.0".to_string(),
                requested_capabilities: CapabilityMask(0b0111),
            },
            ClientToHostMessage::KeyboardEvent {
                scancode: 0x1D,
                extended: false,
                unicode_fallback: Some('ñ'),
                state: KeyState::Down,
            },
            ClientToHostMessage::PointerMove {
                norm_x: 65_535,
                norm_y: 0,
                monitor_id: Some(1),
            },
        ];
        for msg in msgs {
            let bytes = encode_message(&msg).unwrap();
            assert_eq!(decode_message::<ClientToHostMessage>(&bytes).unwrap(), msg);

            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(
                decode_message::<ClientToHostMessage>(&trailing),
                Err(WireError::Malformed)
            );
            assert_eq!(
                decode_message::<ClientToHostMessage>(&bytes[..bytes.len() - 1]),
                Err(WireError::Malformed)
            );
        }

        let reply = HostToClientMessage::PendingApproval {
            timeout_secs: 60,
            session_fingerprint_short: *b"ABC234",
        };
        let bytes = encode_message(&reply).unwrap();
        assert_eq!(
            decode_message::<HostToClientMessage>(&bytes).unwrap(),
            reply
        );

        // Discriminante de variante inexistente.
        assert_eq!(
            decode_message::<HostToClientMessage>(&[0x7F]),
            Err(WireError::Malformed)
        );
    }

    #[test]
    fn local_approval_notices_are_appended_without_moving_existing_variants() {
        // Literal postcard v1: índice de variante como varint.
        assert_eq!(
            encode_message(&HostToClientMessage::LocalApprovalRequired).unwrap(),
            vec![0x06]
        );
        assert_eq!(
            encode_message(&HostToClientMessage::LocalApprovalCleared).unwrap(),
            vec![0x07]
        );
        let existing = [
            HostToClientMessage::PendingApproval {
                timeout_secs: 0,
                session_fingerprint_short: [0; 6],
            },
            HostToClientMessage::ApprovalResult {
                granted: false,
                reason: None,
                monitors: Vec::new(),
            },
            HostToClientMessage::CursorShapeUpdate {
                cursor_hash: 0,
                hotspot_x: 0,
                hotspot_y: 0,
                width: 0,
                height: 0,
                bgra_zstd: None,
            },
            HostToClientMessage::DisplayTopologyChanged {
                monitors: Vec::new(),
            },
            HostToClientMessage::Pong {
                seq: 0,
                client_mono_us: 0,
            },
            HostToClientMessage::SessionRevoked {
                reason: String::new(),
            },
        ];
        for (index, msg) in existing.iter().enumerate() {
            let bytes = encode_message(msg).unwrap();
            assert_eq!(bytes[0] as usize, index, "{msg:?}");
            assert_eq!(decode_message::<HostToClientMessage>(&bytes).unwrap(), *msg);
        }
        for bytes in [[0x06], [0x07]] {
            let msg = decode_message::<HostToClientMessage>(&bytes).unwrap();
            assert_eq!(encode_message(&msg).unwrap(), bytes);
        }
    }

    #[test]
    fn out_of_scope_capability_mask_is_rejected() {
        assert!(CapabilityMask(0b1000 | 0b0111).validate().is_err());
        assert!(CapabilityMask(0x8000_0001).validate().is_err());
        assert_eq!(
            CapabilityMask::from_capabilities(ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS)
                .validate()
                .unwrap(),
            ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS
        );
    }
}
