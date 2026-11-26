//! Destinos de auditoria: archivo JSON Lines con DACL protegida y Event Log de Windows.
//! Ambos escriben `AuditRecord::to_json_line()`, que por construccion no contiene secretos.

use core::ffi::c_void;
use core::ptr::null;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use awawa_protocol::audit::{AuditOutcome, AuditRecord, AuditSink, AuditSinkError};

use crate::dpapi_store::{FILE_DACL_SDDL, FileMode, create_protected_file};
use crate::trust::{TrustPolicy, validate_location};
use crate::winutil::{last_error, wide};

/// Nombre de la fuente del Event Log.
pub const EVENT_SOURCE_NAME: &str = "Awawa";
const EVENT_ID_AUDIT: u32 = 1000;
const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegisterEventSourceW(
        lp_unc_server_name: *const u16,
        lp_source_name: *const u16,
    ) -> *mut c_void;
    fn ReportEventW(
        h_event_log: *mut c_void,
        w_type: u16,
        w_category: u16,
        dw_event_id: u32,
        lp_user_sid: *mut c_void,
        w_num_strings: u16,
        dw_data_size: u32,
        lp_strings: *const *const u16,
        lp_raw_data: *mut c_void,
    ) -> i32;
    fn DeregisterEventSource(h_event_log: *mut c_void) -> i32;
}

/// Archivo JSON Lines en modo anexar, creado con la DACL SYSTEM/Administradores.
/// La DACL se aplica solo al crear el archivo; uno preexistente conserva la suya.
pub struct JsonLinesFileSink {
    file: File,
}

impl JsonLinesFileSink {
    /// Abre/crea el archivo con la DACL y la politica de produccion (SYSTEM/Administradores).
    pub fn open(path: &Path) -> Result<Self, AuditSinkError> {
        Self::open_with(path, FILE_DACL_SDDL, &TrustPolicy::production())
    }

    /// Abre/crea el archivo con DACL y politica propias (pruebas en directorios temporales).
    /// Valida el directorio contenedor y el archivo (dueno, DACL, reparse points): si no son de
    /// confianza devuelve error y no escribe nada (un archivo plantado por otro usuario no se usa).
    pub fn open_with(
        path: &Path,
        sddl: &str,
        policy: &TrustPolicy,
    ) -> Result<Self, AuditSinkError> {
        let io = |e: crate::dpapi_store::StoreError| AuditSinkError::Io(e.to_string());
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            validate_location(dir, policy).map_err(io)?;
        }
        let file = create_protected_file(path, sddl, FileMode::Append).map_err(io)?;
        validate_location(path, policy).map_err(io)?;
        Ok(Self { file })
    }
}

impl AuditSink for JsonLinesFileSink {
    fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
        let mut line = record.to_json_line();
        line.push('\n');
        // Una sola escritura por registro: con FILE_APPEND_DATA el SO la posiciona al final de forma atomica.
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| AuditSinkError::Io(e.to_string()))
    }
}

/// Registro en el Event Log de Windows (fuente `Awawa`).
/// Sin registrar la fuente con un archivo de mensajes, el Visor de eventos muestra el texto precedido de
/// un aviso de descripcion no encontrada; el contenido sigue siendo legible.
pub struct EventLogSink {
    handle: *mut c_void,
}

impl EventLogSink {
    pub fn open() -> Result<Self, AuditSinkError> {
        let source = wide(EVENT_SOURCE_NAME);
        // SAFETY: nombre de fuente ancho terminado en NUL; servidor nulo = equipo local.
        let handle = unsafe { RegisterEventSourceW(null(), source.as_ptr()) };
        if handle.is_null() {
            return Err(AuditSinkError::Io(format!(
                "RegisterEventSourceW fallo (Win32={})",
                last_error()
            )));
        }
        Ok(Self { handle })
    }
}

impl AuditSink for EventLogSink {
    fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
        let kind = match record.outcome() {
            AuditOutcome::Failure | AuditOutcome::Denied => EVENTLOG_WARNING_TYPE,
            AuditOutcome::Success | AuditOutcome::Info => EVENTLOG_INFORMATION_TYPE,
        };
        let text = wide(&record.to_json_line());
        let strings = [text.as_ptr()];
        // SAFETY: `handle` es una fuente valida registrada en `open`; `strings` contiene 1 puntero a una
        // cadena ancha terminada en NUL que vive durante la llamada; el SID y los datos crudos son nulos.
        let ok = unsafe {
            ReportEventW(
                self.handle,
                kind,
                0,
                EVENT_ID_AUDIT,
                core::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(AuditSinkError::Io(format!(
                "ReportEventW fallo (Win32={})",
                last_error()
            )));
        }
        Ok(())
    }
}

impl Drop for EventLogSink {
    fn drop(&mut self) {
        // SAFETY: `handle` fue obtenido de `RegisterEventSourceW` y no se usa despues.
        unsafe { DeregisterEventSource(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};
    use awawa_protocol::audit::AuditEvent;

    #[test]
    fn file_sink_anexa_una_linea_json_por_registro_sin_secretos() {
        let tmp = TempDir::new("audit");
        let dir = safe_dir(&tmp);
        let path = dir.join("audit.jsonl");
        let open =
            || JsonLinesFileSink::open_with(&path, &test_file_dacl(), &test_policy()).unwrap();
        {
            let mut sink = open();
            let r1 = AuditRecord::new(1_000, AuditEvent::AuthFailed, "tester")
                .with_source("203.0.113.9");
            let r2 = AuditRecord::new(
                2_000,
                AuditEvent::PasswordRotated { generation: 3 },
                "tester",
            );
            sink.write_record(&r1).unwrap();
            sink.write_record(&r2).unwrap();
        }
        // Reabrir anexa sin truncar.
        {
            let mut sink = open();
            sink.write_record(&AuditRecord::new(3_000, AuditEvent::SessionResumed, "svc"))
                .unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("auth_failed"));
        assert!(lines[1].contains("password_rotated"));
        assert!(lines[2].contains("session_resumed"));
        assert!(content.ends_with('\n'));
    }
}
