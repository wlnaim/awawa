//! Auditoría de accesos desatendidos en formato JSON-lines.
//!
//! Ningún tipo de este módulo acepta contraseñas, salts ni hashes: los eventos solo transportan
//! datos no secretos (generación del verificador, motivos, segundos de espera). Los textos libres
//! (operador, origen) se sanean eliminando caracteres de control y se truncan a
//! [`AUDIT_MAX_FIELD_CHARS`] caracteres.

use std::fmt;
use std::fmt::Write as _;

use crate::desktop_session::{EndReason, SuspendReason};

/// Longitud máxima (en caracteres) de los campos de texto libre auditados.
pub const AUDIT_MAX_FIELD_CHARS: usize = 64;

/// Eventos auditables del acceso desatendido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    AuthSucceeded,
    AuthFailed,
    AuthThrottled {
        retry_after_secs: u64,
    },
    PasswordConfigured {
        generation: u32,
    },
    PasswordRotated {
        generation: u32,
    },
    PasswordRevoked {
        generation: u32,
    },
    SessionStarted,
    SessionSuspended {
        reason: SuspendReason,
    },
    SessionResumed,
    SessionEnded {
        reason: EndReason,
    },
    /// El verificador persistido es ilegible, fue manipulado o su dueño/DACL no es seguro.
    VerifierRejected,
    ServiceStarted,
    ServiceStopped,
}

/// Resultado agregado de un evento auditado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Info,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Info => "info",
        }
    }
}

impl AuditEvent {
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthSucceeded => "auth_succeeded",
            Self::AuthFailed => "auth_failed",
            Self::AuthThrottled { .. } => "auth_throttled",
            Self::PasswordConfigured { .. } => "password_configured",
            Self::PasswordRotated { .. } => "password_rotated",
            Self::PasswordRevoked { .. } => "password_revoked",
            Self::SessionStarted => "session_started",
            Self::SessionSuspended { .. } => "session_suspended",
            Self::SessionResumed => "session_resumed",
            Self::SessionEnded { .. } => "session_ended",
            Self::VerifierRejected => "verifier_rejected",
            Self::ServiceStarted => "service_started",
            Self::ServiceStopped => "service_stopped",
        }
    }

    pub fn outcome(self) -> AuditOutcome {
        match self {
            Self::AuthSucceeded
            | Self::PasswordConfigured { .. }
            | Self::PasswordRotated { .. }
            | Self::PasswordRevoked { .. } => AuditOutcome::Success,
            Self::AuthFailed | Self::VerifierRejected => AuditOutcome::Failure,
            Self::AuthThrottled { .. } => AuditOutcome::Denied,
            Self::SessionStarted
            | Self::SessionSuspended { .. }
            | Self::SessionResumed
            | Self::SessionEnded { .. }
            | Self::ServiceStarted
            | Self::ServiceStopped => AuditOutcome::Info,
        }
    }
}

/// Elimina caracteres de control y trunca a [`AUDIT_MAX_FIELD_CHARS`] caracteres.
pub fn sanitize_audit_text(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(AUDIT_MAX_FIELD_CHARS)
        .collect()
}

/// Registro de auditoría. Los campos de texto se sanean en construcción.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    unix_ms: u64,
    event: AuditEvent,
    operator: String,
    operator_fingerprint: Option<[u8; 8]>,
    source: Option<String>,
    windows_session_id: Option<u32>,
}

impl AuditRecord {
    pub fn new(unix_ms: u64, event: AuditEvent, operator: &str) -> Self {
        Self {
            unix_ms,
            event,
            operator: sanitize_audit_text(operator),
            operator_fingerprint: None,
            source: None,
            windows_session_id: None,
        }
    }

    pub fn with_operator_fingerprint(mut self, fingerprint: [u8; 8]) -> Self {
        self.operator_fingerprint = Some(fingerprint);
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source = Some(sanitize_audit_text(source));
        self
    }

    pub fn with_windows_session_id(mut self, session_id: u32) -> Self {
        self.windows_session_id = Some(session_id);
        self
    }

    pub fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    pub fn event(&self) -> AuditEvent {
        self.event
    }

    pub fn outcome(&self) -> AuditOutcome {
        self.event.outcome()
    }

    pub fn operator(&self) -> &str {
        &self.operator
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    pub fn windows_session_id(&self) -> Option<u32> {
        self.windows_session_id
    }

    /// Huella del operador en hexadecimal `AA:BB:...` (formato de la UI de consentimiento).
    pub fn operator_fingerprint_hex(&self) -> Option<String> {
        self.operator_fingerprint.map(|fp| {
            fp.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }

    /// Renderiza el registro como una línea JSON (sin salto de línea final).
    pub fn to_json_line(&self) -> String {
        let mut out = String::with_capacity(192);
        let _ = write!(out, "{{\"ts_ms\":{}", self.unix_ms);
        push_str_field(&mut out, "event", self.event.name());
        push_str_field(&mut out, "outcome", self.event.outcome().as_str());
        push_str_field(&mut out, "operator", &self.operator);
        if let Some(fp) = self.operator_fingerprint_hex() {
            push_str_field(&mut out, "operator_fingerprint", &fp);
        }
        if let Some(src) = &self.source {
            push_str_field(&mut out, "source", src);
        }
        if let Some(sid) = self.windows_session_id {
            let _ = write!(out, ",\"windows_session_id\":{sid}");
        }
        match self.event {
            AuditEvent::AuthThrottled { retry_after_secs } => {
                let _ = write!(out, ",\"retry_after_secs\":{retry_after_secs}");
            }
            AuditEvent::PasswordConfigured { generation }
            | AuditEvent::PasswordRotated { generation }
            | AuditEvent::PasswordRevoked { generation } => {
                let _ = write!(out, ",\"generation\":{generation}");
            }
            AuditEvent::SessionSuspended { reason } => {
                push_str_field(&mut out, "reason", reason.as_str());
            }
            AuditEvent::SessionEnded { reason } => {
                push_str_field(&mut out, "reason", reason.as_str());
            }
            AuditEvent::AuthSucceeded
            | AuditEvent::AuthFailed
            | AuditEvent::SessionStarted
            | AuditEvent::SessionResumed
            | AuditEvent::VerifierRejected
            | AuditEvent::ServiceStarted
            | AuditEvent::ServiceStopped => {}
        }
        out.push('}');
        out
    }
}

fn push_str_field(out: &mut String, key: &str, value: &str) {
    out.push_str(",\"");
    out.push_str(key);
    out.push_str("\":\"");
    escape_json_into(out, value);
    out.push('"');
}

/// Escapa una cadena según RFC 8259 (comillas, barra invertida y caracteres de control).
fn escape_json_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditSinkError {
    Io(String),
}

impl fmt::Display for AuditSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "fallo al escribir el registro de auditoria: {msg}"),
        }
    }
}

impl std::error::Error for AuditSinkError {}

/// Destino de registros de auditoría (archivo protegido, Event Log, memoria en pruebas).
pub trait AuditSink {
    fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError>;
}

/// Destino en memoria para pruebas: guarda cada línea JSON renderizada.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    pub lines: Vec<String>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for MemoryAuditSink {
    fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
        self.lines.push(record.to_json_line());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_operator_and_escapes_json() {
        let raw = "Op\u{1b}[31m \"Mesa\" \\TI\r\n\u{7}";
        let rec = AuditRecord::new(1_700_000_000_123, AuditEvent::AuthFailed, raw)
            .with_source("10.0.0.5\nINJECT")
            .with_operator_fingerprint([0x4A, 0x91, 0, 0, 0, 0, 0, 0xFF])
            .with_windows_session_id(3);
        assert_eq!(rec.operator(), "Op[31m \"Mesa\" \\TI");
        assert_eq!(rec.source(), Some("10.0.0.5INJECT"));

        let line = rec.to_json_line();
        assert_eq!(
            line,
            "{\"ts_ms\":1700000000123,\"event\":\"auth_failed\",\"outcome\":\"failure\",\
             \"operator\":\"Op[31m \\\"Mesa\\\" \\\\TI\",\
             \"operator_fingerprint\":\"4A:91:00:00:00:00:00:FF\",\
             \"source\":\"10.0.0.5INJECT\",\"windows_session_id\":3}"
        );
        assert!(!line.contains('\n') && !line.contains('\r'));
    }

    #[test]
    fn truncates_free_text_to_64_chars() {
        let long = "ñ".repeat(200);
        let rec = AuditRecord::new(0, AuditEvent::SessionStarted, &long);
        assert_eq!(rec.operator().chars().count(), AUDIT_MAX_FIELD_CHARS);
    }

    #[test]
    fn renders_event_specific_fields() {
        let susp = AuditRecord::new(
            1,
            AuditEvent::SessionSuspended {
                reason: SuspendReason::SecureDesktop,
            },
            "op",
        )
        .to_json_line();
        assert!(susp.contains("\"event\":\"session_suspended\""));
        assert!(susp.contains("\"reason\":\"secure_desktop\""));

        let ended = AuditRecord::new(
            2,
            AuditEvent::SessionEnded {
                reason: EndReason::SessionSwitched,
            },
            "op",
        )
        .to_json_line();
        assert!(ended.contains("\"reason\":\"session_switched\""));

        let revoked = AuditRecord::new(
            2,
            AuditEvent::SessionEnded {
                reason: EndReason::CredentialRevoked,
            },
            "admin",
        )
        .to_json_line();
        assert!(revoked.contains("\"reason\":\"credential_revoked\""));

        let thr = AuditRecord::new(
            3,
            AuditEvent::AuthThrottled {
                retry_after_secs: 30,
            },
            "op",
        )
        .to_json_line();
        assert!(thr.contains("\"outcome\":\"denied\"") && thr.contains("\"retry_after_secs\":30"));

        let rot = AuditRecord::new(4, AuditEvent::PasswordRotated { generation: 2 }, "admin")
            .to_json_line();
        assert!(rot.contains("\"generation\":2"));
    }

    #[test]
    fn renders_service_and_verifier_events() {
        let cases = [
            (AuditEvent::VerifierRejected, "verifier_rejected", "failure"),
            (AuditEvent::ServiceStarted, "service_started", "info"),
            (AuditEvent::ServiceStopped, "service_stopped", "info"),
        ];
        for (event, name, outcome) in cases {
            let line = AuditRecord::new(7, event, "LocalSystem").to_json_line();
            assert_eq!(
                line,
                format!(
                    "{{\"ts_ms\":7,\"event\":\"{name}\",\"outcome\":\"{outcome}\",\"operator\":\"LocalSystem\"}}"
                )
            );
        }
    }

    #[test]
    fn memory_sink_collects_lines() {
        let mut sink = MemoryAuditSink::new();
        sink.write_record(&AuditRecord::new(5, AuditEvent::SessionResumed, "op"))
            .unwrap();
        assert_eq!(sink.lines.len(), 1);
        assert!(sink.lines[0].starts_with("{\"ts_ms\":5,"));
    }
}
