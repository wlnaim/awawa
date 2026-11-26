//! Implementacion real de [`System`]: archivos con escritura atomica, validacion de ubicaciones con
//! `awawa_service::trust`, carpeta del relay con DACL explicita, procesos del sistema con argumentos
//! fijos y sin ventana, accesos directos con `IShellLinkW` (COM, `crate::win32`), SCM por FFI y la pipe de
//! administracion con el cliente existente (`admin_pipe::request`, que comprueba el dueno SYSTEM/BA).
//!
//! Solo la usa la ejecucion de la interfaz grafica. `--dry-run` y las pruebas nunca la construyen.

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use std::ffi::OsStr;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use awawa_protocol::audit::MemoryAuditSink;
use awawa_protocol::unattended::UnattendedStatus;
use awawa_service::admin_ops::AdminOps;
use awawa_service::admin_pipe::{self, AdminRequest, AdminResponse, ClientError};
use awawa_service::dpapi_store::{VerifierFileStore, create_dir_with_sddl};
use awawa_service::kdf_cng::CngPbkdf2Sha256;
use awawa_service::service_identity::IdentityFileStore;
use awawa_service::trust::{
    TrustPolicy, is_reparse_point, validate_location, validate_owner, validate_tree_owners,
};

use crate::cmdline::CommandSpec;
use crate::connection::HostIdentity;
use crate::paths::Layout;
use crate::plan::{
    INSTALL_DIR_SDDL, INSTALL_FILE_SDDL, RELAY_DIR_SDDL, SERVICE_NAME, SID_ADMINISTRATORS,
    SID_LOCAL_SERVICE, SID_SYSTEM, Shortcut,
};
use crate::system::{ServiceState, System};
use crate::win32::set_owner_and_dacl;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct RealSystem {
    service_data_dir: PathBuf,
    com_ready: bool,
}

impl RealSystem {
    pub fn new(layout: &Layout) -> Self {
        Self {
            service_data_dir: layout.service_data_dir.clone(),
            com_ready: false,
        }
    }
}

fn io(path: &Path, e: impl std::fmt::Display) -> String {
    format!("{}: {e}", path.display())
}

impl System for RealSystem {
    fn create_install_dir(&mut self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        set_owner_and_dacl(dir, INSTALL_DIR_SDDL)
    }

    fn validate_program_files(&mut self, path: &Path) -> Result<(), String> {
        validate_location(path, &TrustPolicy::program_files()).map_err(|e| e.to_string())
    }

    fn create_relay_data_dir(&mut self, dir: &Path) -> Result<(), String> {
        // Hijos (relay-key.der) con dueno LOCAL SERVICE; la carpeta, siempre SYSTEM o Administradores.
        let policy = TrustPolicy::only(&[SID_SYSTEM, SID_ADMINISTRATORS, SID_LOCAL_SERVICE]);
        if std::fs::symlink_metadata(dir).is_err() {
            create_dir_with_sddl(dir, RELAY_DIR_SDDL).map_err(|e| e.to_string())?;
        } else {
            let reparse = is_reparse_point(dir).map_err(|e| e.to_string())?;
            if reparse {
                return Err(format!(
                    "{} es un enlace o junction: borrelo manualmente",
                    dir.display()
                ));
            }
            validate_tree_owners(dir, &policy).map_err(|e| {
                format!("carpeta del relay preexistente no confiable ({e}); borrela manualmente")
            })?;
        }
        validate_owner(dir, &TrustPolicy::production())
            .and_then(|()| validate_location(dir, &policy))
            .map_err(|e| format!("carpeta del relay no confiable ({e}); borrela manualmente"))
    }

    fn create_dir(&mut self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        set_owner_and_dacl(dir, INSTALL_DIR_SDDL)
    }

    fn secure_install_file(&mut self, path: &Path) -> Result<(), String> {
        set_owner_and_dacl(path, INSTALL_FILE_SDDL)
    }

    fn payload(&mut self, name: &str) -> Result<Vec<u8>, String> {
        crate::payload::extract(name)
    }

    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut name = path.file_name().ok_or("ruta sin nombre")?.to_owned();
        name.push(format!(".{}.tmp", std::process::id()));
        let tmp = path.with_file_name(name);
        let result = std::fs::write(&tmp, bytes)
            .and_then(|()| std::fs::rename(&tmp, path))
            .map_err(|e| io(path, e));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    fn read_file(&mut self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| io(path, e))
    }

    fn exists(&mut self, path: &Path) -> bool {
        path.exists()
    }

    fn remove_file(&mut self, path: &Path) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(path, e)),
            _ => Ok(()),
        }
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<(), String> {
        // std no sigue enlaces ni junctions al borrar (solo quita el enlace).
        match std::fs::remove_dir_all(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(path, e)),
            _ => Ok(()),
        }
    }

    fn remove_dir_if_empty(&mut self, path: &Path) {
        let _ = std::fs::remove_dir(path);
    }

    fn run(&mut self, cmd: &CommandSpec) -> Result<(i32, String), String> {
        let mut command = std::process::Command::new(&cmd.program);
        if cmd.raw {
            for arg in &cmd.args {
                command.raw_arg(arg);
            }
        } else {
            command.args(&cmd.args);
        }
        let output = command
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| io(&cmd.program, e))?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        Ok((output.status.code().unwrap_or(-1), text))
    }

    fn create_shortcut(&mut self, s: &Shortcut) -> Result<(), String> {
        if let Some(parent) = s.link.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        if !self.com_ready {
            crate::win32::init_com();
            self.com_ready = true;
        }
        crate::win32::create_shortcut(
            s.link.as_os_str(),
            s.target.as_os_str(),
            OsStr::new(&s.args),
            s.workdir.as_os_str(),
            OsStr::new(&s.description),
        )
        .map_err(|e| format!("acceso directo {}: {e}", s.link.display()))
    }

    fn service_state(&mut self) -> Result<ServiceState, String> {
        scm::state()
    }

    fn start_service(&mut self) -> Result<(), String> {
        scm::start()
    }

    fn stop_service(&mut self) -> Result<(), String> {
        scm::stop()
    }

    fn delete_service(&mut self) -> Result<(), String> {
        scm::delete()
    }

    fn verifier_status(&mut self) -> Result<UnattendedStatus, String> {
        // Solo lectura, como `awawa-admin status`: no deriva ni persiste.
        let store = VerifierFileStore::new(self.service_data_dir.join("unattended.verifier"));
        let mut sink = MemoryAuditSink::new();
        let ops = AdminOps {
            store: &store,
            kdf: &CngPbkdf2Sha256,
            sink: &mut sink,
            operator: "installer",
        };
        ops.status().map_err(|e| e.to_string())
    }

    fn admin_request(&mut self, request: &AdminRequest) -> Result<AdminResponse, ClientError> {
        admin_pipe::request(request)
    }

    fn identity_load_or_create(&mut self) -> Result<(HostIdentity, bool), String> {
        let store = IdentityFileStore::new(self.service_data_dir.join("service.identity"));
        let (identity, created) = store.load_or_create().map_err(|e| e.to_string())?;
        Ok((
            HostIdentity {
                id: Some(identity.id()),
                key: identity.verifying_key().to_bytes(),
            },
            created,
        ))
    }

    fn identity_load(&mut self) -> Result<Option<HostIdentity>, String> {
        let store = IdentityFileStore::new(self.service_data_dir.join("service.identity"));
        Ok(store
            .load()
            .map_err(|e| e.to_string())?
            .map(|identity| HostIdentity {
                id: Some(identity.id()),
                key: identity.verifying_key().to_bytes(),
            }))
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Control del servicio `Awawa` por el SCM (FFI manual, como `awawa-service`).
mod scm {
    use super::*;

    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SERVICE_START: u32 = 0x0010;
    const SERVICE_STOP: u32 = 0x0020;
    const DELETE: u32 = 0x0001_0000;
    const SERVICE_CONTROL_STOP: u32 = 1;
    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_RUNNING: u32 = 4;
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
    const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;

    #[repr(C)]
    #[derive(Default)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        check_point: u32,
        wait_hint: u32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> *mut c_void;
        fn OpenServiceW(scm: *mut c_void, name: *const u16, access: u32) -> *mut c_void;
        fn QueryServiceStatus(service: *mut c_void, status: *mut ServiceStatus) -> i32;
        fn StartServiceW(service: *mut c_void, argc: u32, argv: *const *const u16) -> i32;
        fn ControlService(service: *mut c_void, control: u32, status: *mut ServiceStatus) -> i32;
        fn DeleteService(service: *mut c_void) -> i32;
        fn CloseServiceHandle(handle: *mut c_void) -> i32;
    }

    struct Handle(*mut c_void);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: manejador valido devuelto por OpenSCManagerW/OpenServiceW; se cierra una vez.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    fn last_error() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `None` si el servicio no existe.
    fn open(access: u32) -> Result<Option<Handle>, String> {
        // SAFETY: maquina y base de datos nulas = locales; solo derecho de conexion.
        let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
        if scm.is_null() {
            return Err(format!("OpenSCManagerW fallo (Win32={})", last_error()));
        }
        let scm = Handle(scm);
        let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain([0]).collect();
        // SAFETY: SCM valido y nombre ancho terminado en NUL.
        let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), access) };
        if svc.is_null() {
            return match last_error() {
                ERROR_SERVICE_DOES_NOT_EXIST => Ok(None),
                code => Err(format!("OpenServiceW fallo (Win32={code})")),
            };
        }
        Ok(Some(Handle(svc)))
    }

    pub fn state() -> Result<ServiceState, String> {
        let Some(svc) = open(SERVICE_QUERY_STATUS)? else {
            return Ok(ServiceState::Absent);
        };
        let mut status = ServiceStatus::default();
        // SAFETY: servicio valido con SERVICE_QUERY_STATUS; `status` es un destino valido.
        if unsafe { QueryServiceStatus(svc.0, &mut status) } == 0 {
            return Err(format!("QueryServiceStatus fallo (Win32={})", last_error()));
        }
        Ok(match status.current_state {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_RUNNING => ServiceState::Running,
            _ => ServiceState::Pending,
        })
    }

    pub fn start() -> Result<(), String> {
        let svc = open(SERVICE_START)?.ok_or("el servicio no esta instalado")?;
        // SAFETY: servicio valido con SERVICE_START; sin argumentos.
        if unsafe { StartServiceW(svc.0, 0, null_mut()) } == 0 {
            let code = last_error();
            if code != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(format!("StartServiceW fallo (Win32={code})"));
            }
        }
        Ok(())
    }

    pub fn stop() -> Result<(), String> {
        let Some(svc) = open(SERVICE_STOP)? else {
            return Ok(());
        };
        let mut status = ServiceStatus::default();
        // SAFETY: servicio valido con SERVICE_STOP; `status` es un destino valido.
        if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            let code = last_error();
            if code != ERROR_SERVICE_NOT_ACTIVE {
                return Err(format!("ControlService(STOP) fallo (Win32={code})"));
            }
        }
        Ok(())
    }

    pub fn delete() -> Result<(), String> {
        let Some(svc) = open(DELETE)? else {
            return Ok(());
        };
        // SAFETY: servicio valido con derecho DELETE.
        if unsafe { DeleteService(svc.0) } == 0 {
            let code = last_error();
            if code != ERROR_SERVICE_MARKED_FOR_DELETE {
                return Err(format!("DeleteService fallo (Win32={code})"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32::test_token::UserOwnerImpersonation;

    /// Con un token cuyo dueno por defecto es el usuario, lo creado tendria dueno no confiable;
    /// la carpeta y el binario quedan con dueno BA y DACL explicitos y pasan la politica Program Files.
    #[test]
    fn carpeta_y_binario_quedan_con_dueno_ba_aunque_el_token_no_lo_sea() {
        if !awawa_service::identity::is_administrator() {
            eprintln!("omitida: requiere un token de administrador elevado para fijar O:BA");
            return;
        }
        let root = std::env::temp_dir().join(format!("installer-owner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("Awawa");
        let exe = dir.join("awawa-host.exe");
        let policy = TrustPolicy::program_files();
        let mut sys = RealSystem::new(&Layout::for_tests());
        let control = root.join("control");
        {
            let _imp = UserOwnerImpersonation::start();
            // Control: sin fijar el dueno, lo creado con este token tiene dueno = usuario.
            std::fs::create_dir(&control).unwrap();
            sys.create_install_dir(&dir).unwrap();
            sys.write_file(&exe, b"MZ prueba").unwrap();
            sys.secure_install_file(&exe).unwrap();
        }
        let err = validate_location(&control, &policy)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dueno no confiable"), "{err}");
        validate_location(&dir, &policy).unwrap();
        validate_location(&exe, &policy).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }
}
