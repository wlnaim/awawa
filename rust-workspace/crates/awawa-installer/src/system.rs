//! Ejecucion del plan sobre un [`System`]: la implementacion real (`real::RealSystem`) usa Win32/COM y
//! procesos del sistema; la simulada (`fake::FakeSystem`, solo pruebas) registra cada llamada.
//!
//! La contrasena desatendida llega aparte, en [`Secrets`], y solo la usa `ConfigurePassword` para
//! construir la peticion de la pipe. Nunca se registra: ni el plan, ni el registro, ni las llamadas al
//! sistema la contienen (`SecretString` se muestra como `***`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use awawa_protocol::unattended::UnattendedStatus;
use awawa_service::admin_pipe::{
    AdminRequest, AdminResponse, ClientError, SecretString, password_len_ok,
};
use zeroize::Zeroizing;

use crate::cmdline::CommandSpec;
use crate::connection::{self, ConnectionInfo, HostIdentity};
use crate::plan::{Action, SERVICE_NAME, Shortcut};

/// Estado del servicio `Awawa` en el SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Absent,
    Stopped,
    Running,
    /// START_PENDING, STOP_PENDING y demas transitorios.
    Pending,
}

/// Operaciones primitivas del sistema.
pub trait System {
    fn create_install_dir(&mut self, dir: &Path) -> Result<(), String>;
    fn validate_program_files(&mut self, path: &Path) -> Result<(), String>;
    fn create_relay_data_dir(&mut self, dir: &Path) -> Result<(), String>;
    fn create_dir(&mut self, dir: &Path) -> Result<(), String>;
    /// Binario de la carga embebida, con su SHA-256 ya verificado.
    fn payload(&mut self, name: &str) -> Result<Vec<u8>, String>;
    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String>;
    /// Fija dueno BA y la DACL de `INSTALL_FILE_SDDL` en un binario instalado.
    fn secure_install_file(&mut self, path: &Path) -> Result<(), String>;
    fn read_file(&mut self, path: &Path) -> Result<Vec<u8>, String>;
    fn exists(&mut self, path: &Path) -> bool;
    /// Sin error si no existe.
    fn remove_file(&mut self, path: &Path) -> Result<(), String>;
    /// Sin error si no existe.
    fn remove_dir_all(&mut self, path: &Path) -> Result<(), String>;
    fn remove_dir_if_empty(&mut self, path: &Path);
    /// Codigo de salida y salida combinada del proceso.
    fn run(&mut self, cmd: &CommandSpec) -> Result<(i32, String), String>;
    fn create_shortcut(&mut self, shortcut: &Shortcut) -> Result<(), String>;
    fn service_state(&mut self) -> Result<ServiceState, String>;
    fn start_service(&mut self) -> Result<(), String>;
    /// Sin error si ya estaba detenido.
    fn stop_service(&mut self) -> Result<(), String>;
    fn delete_service(&mut self) -> Result<(), String>;
    fn verifier_status(&mut self) -> Result<UnattendedStatus, String>;
    fn admin_request(&mut self, request: &AdminRequest) -> Result<AdminResponse, ClientError>;
    /// Crea la identidad del servicio si falta (como `awawa-admin set`); `true` si la creo.
    fn identity_load_or_create(&mut self) -> Result<(HostIdentity, bool), String>;
    fn identity_load(&mut self) -> Result<Option<HostIdentity>, String>;
    fn sleep(&mut self, duration: Duration);
}

/// Secretos que no forman parte del plan.
#[derive(Default)]
pub struct Secrets {
    pub password: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secrets(***)")
    }
}

/// Resultado visible de una ejecucion.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub host: Option<HostIdentity>,
    pub connection_file: Option<PathBuf>,
    pub connection: Option<ConnectionInfo>,
}

const POLL: Duration = Duration::from_millis(500);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
const PIPE_ATTEMPTS: u32 = 20;
const REMOVE_ATTEMPTS: u32 = 10;
/// Tope de lineas de salida de un proceso que se copian al registro.
const MAX_OUTPUT_LINES: usize = 20;

struct Runner<'a> {
    sys: &'a mut dyn System,
    log: &'a mut dyn FnMut(&str),
    outcome: Outcome,
}

/// Ejecuta `plan` en orden y se detiene en el primer error (sin deshacer lo ya hecho; el registro dice
/// hasta donde llego y "Desinstalar" limpia).
pub fn run_plan(
    plan: &[Action],
    sys: &mut dyn System,
    secrets: &Secrets,
    log: &mut dyn FnMut(&str),
) -> Result<Outcome, String> {
    let mut runner = Runner {
        sys,
        log,
        outcome: Outcome::default(),
    };
    let total = plan.len();
    for (i, action) in plan.iter().enumerate() {
        (runner.log)(&format!("[{}/{total}] {action}", i + 1));
        if let Err(e) = runner.step(action, secrets) {
            (runner.log)(&format!("    ERROR: {e}"));
            return Err(e);
        }
    }
    (runner.log)("Terminado sin errores.");
    Ok(runner.outcome)
}

impl Runner<'_> {
    fn note(&mut self, text: &str) {
        (self.log)(&format!("    {text}"));
    }

    fn note_output(&mut self, output: &str) {
        for line in output
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(MAX_OUTPUT_LINES)
        {
            self.note(&format!("| {}", line.trim_end()));
        }
    }

    fn step(&mut self, action: &Action, secrets: &Secrets) -> Result<(), String> {
        match action {
            Action::Run {
                cmd, allow_fail, ..
            } => {
                let (code, output) = self.sys.run(cmd)?;
                self.note_output(&output);
                if code != 0 {
                    if *allow_fail {
                        self.note(&format!("codigo {code}: se continua"));
                    } else {
                        return Err(format!("el comando termino con codigo {code}"));
                    }
                }
                Ok(())
            }
            Action::CreateInstallDir(dir) => self.sys.create_install_dir(dir),
            Action::Extract { name, dest } => {
                let bytes = self.sys.payload(name)?;
                self.note(&format!(
                    "{} bytes, SHA-256 {}",
                    bytes.len(),
                    crate::payload::sha256_hex(&bytes)
                ));
                self.sys.write_file(dest, &bytes)?;
                self.sys.secure_install_file(dest)
            }
            Action::ValidateProgramFiles(paths) => {
                for path in paths {
                    self.sys.validate_program_files(path)?;
                }
                Ok(())
            }
            Action::CreateRelayDataDir(dir) => self.sys.create_relay_data_dir(dir),
            Action::CreateDir(dir) => self.sys.create_dir(dir),
            Action::WriteFile { path, bytes, .. } => self.sys.write_file(path, bytes),
            Action::RemoveFile(path) => self.sys.remove_file(path),
            Action::RemoveDir(path) => self.remove_dir(path),
            Action::RemoveDirIfEmpty(path) => {
                self.sys.remove_dir_if_empty(path);
                Ok(())
            }
            Action::WaitForFile { path, timeout_secs } => self.wait_for_file(path, *timeout_secs),
            Action::CreateShortcut(shortcut) => self.sys.create_shortcut(shortcut),
            Action::RemoveService(exe) => self.remove_service(exe),
            Action::StartService => self.start_service(),
            Action::RestartService => {
                self.stop_service()?;
                self.start_service()
            }
            Action::ConfigurePassword => self.configure_password(secrets),
            Action::ReadServiceIdentity => {
                let host = self
                    .sys
                    .identity_load()?
                    .ok_or("el servicio no tiene identidad (service.identity)")?;
                self.note(&format!(
                    "ID del equipo {} | huella de la clave {}",
                    host.id.map(|id| id.to_string()).unwrap_or_default(),
                    connection::host_key_fingerprint(&host.key)
                ));
                self.outcome.host = Some(host);
                Ok(())
            }
            Action::WriteConnectionFile { path, relay, pin } => {
                let relay_pin = self.sys.read_file(pin)?;
                connection::validate_pin(&relay_pin)?;
                let info = ConnectionInfo {
                    relay_addr: relay.clone(),
                    relay_pin,
                    host: self.outcome.host.clone(),
                };
                info.validate()?;
                self.sys.write_file(path, info.to_text().as_bytes())?;
                self.note(&format!(
                    "huella del pin del relay: {}",
                    connection::pin_fingerprint(&info.relay_pin)
                ));
                self.outcome.connection_file = Some(path.clone());
                self.outcome.connection = Some(info);
                Ok(())
            }
        }
    }

    fn remove_dir(&mut self, path: &Path) -> Result<(), String> {
        let mut last = String::new();
        for _ in 0..REMOVE_ATTEMPTS {
            match self.sys.remove_dir_all(path) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            self.sys.sleep(Duration::from_secs(1));
        }
        Err(format!(
            "{last} (cierre awawa-host o awawa-operator si siguen abiertos)"
        ))
    }

    fn wait_for_file(&mut self, path: &Path, timeout_secs: u64) -> Result<(), String> {
        let polls = timeout_secs * 1000 / POLL.as_millis() as u64;
        for _ in 0..=polls {
            if self.sys.exists(path) && self.sys.read_file(path).is_ok_and(|b| !b.is_empty()) {
                return Ok(());
            }
            self.sys.sleep(POLL);
        }
        Err(format!(
            "{} no aparecio en {timeout_secs} s: el relay no arranco (revise la tarea {} en el Programador de tareas)",
            path.display(),
            crate::plan::RELAY_TASK
        ))
    }

    fn wait_service(&mut self, wanted: ServiceState) -> Result<(), String> {
        let polls = SERVICE_TIMEOUT.as_millis() / POLL.as_millis();
        for _ in 0..=polls {
            if self.sys.service_state()? == wanted {
                return Ok(());
            }
            self.sys.sleep(POLL);
        }
        Err(format!(
            "el servicio {SERVICE_NAME} no llego a {wanted:?} en {} s",
            SERVICE_TIMEOUT.as_secs()
        ))
    }

    fn stop_service(&mut self) -> Result<(), String> {
        match self.sys.service_state()? {
            ServiceState::Absent => Err(format!("el servicio {SERVICE_NAME} no esta instalado")),
            ServiceState::Stopped => Ok(()),
            _ => {
                self.sys.stop_service()?;
                self.wait_service(ServiceState::Stopped)
            }
        }
    }

    fn start_service(&mut self) -> Result<(), String> {
        match self.sys.service_state()? {
            ServiceState::Absent => Err(format!("el servicio {SERVICE_NAME} no esta instalado")),
            ServiceState::Running => Ok(()),
            _ => {
                self.sys.start_service()?;
                self.wait_service(ServiceState::Running)
            }
        }
    }

    fn remove_service(&mut self, exe: &Path) -> Result<(), String> {
        if self.sys.service_state()? == ServiceState::Absent {
            self.note("no esta instalado");
            return Ok(());
        }
        self.stop_service()?;
        // `RemoveService` va antes de extraer o borrar binarios: el ejecutable instalado sigue ahi.
        if self.sys.exists(exe) {
            let cmd = CommandSpec::new(exe.to_path_buf(), &["uninstall"]);
            self.note(&format!("{cmd}"));
            let (code, output) = self.sys.run(&cmd)?;
            self.note_output(&output);
            if code != 0 {
                return Err(format!("awawa-service uninstall termino con codigo {code}"));
            }
        } else {
            self.note("sin awawa-service.exe: se borra directamente en el SCM");
            self.sys.delete_service()?;
        }
        self.wait_service(ServiceState::Absent)
            .map_err(|e| format!("{e}; cierre la consola de Servicios si esta abierta"))
    }

    fn configure_password(&mut self, secrets: &Secrets) -> Result<(), String> {
        let password = secrets
            .password
            .as_ref()
            .ok_or("falta la contrasena del acceso desatendido")?;
        if !password_len_ok(password) {
            return Err("la contrasena debe tener entre 12 y 128 caracteres".into());
        }
        let change = matches!(
            self.sys.verifier_status()?,
            UnattendedStatus::Enabled { .. }
        );
        let make = || {
            let secret = SecretString::new(Zeroizing::new(password.as_str().to_owned()));
            if change {
                AdminRequest::Change { password: secret }
            } else {
                AdminRequest::Set { password: secret }
            }
        };
        let mut attempt = 0;
        let generation = loop {
            attempt += 1;
            match self.sys.admin_request(&make()) {
                Ok(AdminResponse::Done { generation }) => break generation,
                Ok(AdminResponse::Error { message }) => return Err(message),
                Err(ClientError::NotRunning | ClientError::Busy) if attempt < PIPE_ATTEMPTS => {
                    self.sys.sleep(POLL);
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        self.note(&format!(
            "contrasena {} (generacion {generation})",
            if change { "cambiada" } else { "configurada" }
        ));
        let (host, created) = self.sys.identity_load_or_create()?;
        self.note(&format!(
            "identidad del servicio {}: ID {} huella {}",
            if created { "generada" } else { "existente" },
            host.id.map(|id| id.to_string()).unwrap_or_default(),
            connection::host_key_fingerprint(&host.key)
        ));
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::BTreeMap;

    use super::*;

    /// Sistema simulado: archivos en memoria, servicio con estados y registro de llamadas.
    pub struct FakeSystem {
        pub calls: Vec<String>,
        pub files: BTreeMap<PathBuf, Vec<u8>>,
        pub service: ServiceState,
        pub verifier: UnattendedStatus,
        pub identity: Option<HostIdentity>,
        /// Contrasenas que llegaron a la pipe (para comprobar la entrega).
        pub delivered: Vec<String>,
        /// Respuestas `NotRunning` antes de aceptar en la pipe.
        pub pipe_not_ready: u32,
        /// Certificado que "crea" el relay al arrancar la tarea.
        pub relay_cert: Option<(PathBuf, Vec<u8>)>,
        pub fail_validation: bool,
    }

    impl FakeSystem {
        pub fn new() -> Self {
            Self {
                calls: Vec::new(),
                files: BTreeMap::new(),
                service: ServiceState::Absent,
                verifier: UnattendedStatus::NotConfigured,
                identity: None,
                delivered: Vec::new(),
                pipe_not_ready: 0,
                relay_cert: None,
                fail_validation: false,
            }
        }

        fn call(&mut self, text: String) {
            self.calls.push(text);
        }
    }

    impl System for FakeSystem {
        fn create_install_dir(&mut self, dir: &Path) -> Result<(), String> {
            self.call(format!("create_install_dir {}", dir.display()));
            Ok(())
        }
        fn validate_program_files(&mut self, path: &Path) -> Result<(), String> {
            self.call(format!("validate {}", path.display()));
            if self.fail_validation {
                Err(format!("{}: dueno no confiable", path.display()))
            } else {
                Ok(())
            }
        }
        fn create_relay_data_dir(&mut self, dir: &Path) -> Result<(), String> {
            self.call(format!("create_relay_data_dir {}", dir.display()));
            Ok(())
        }
        fn create_dir(&mut self, dir: &Path) -> Result<(), String> {
            self.call(format!("create_dir {}", dir.display()));
            Ok(())
        }
        fn payload(&mut self, name: &str) -> Result<Vec<u8>, String> {
            self.call(format!("payload {name}"));
            Ok(format!("MZ {name}").into_bytes())
        }
        fn write_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), String> {
            self.call(format!("write {} {}", path.display(), bytes.len()));
            self.files.insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
        fn secure_install_file(&mut self, path: &Path) -> Result<(), String> {
            self.call(format!("secure {}", path.display()));
            Ok(())
        }
        fn read_file(&mut self, path: &Path) -> Result<Vec<u8>, String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| format!("{} no existe", path.display()))
        }
        fn exists(&mut self, path: &Path) -> bool {
            self.files.contains_key(path)
        }
        fn remove_file(&mut self, path: &Path) -> Result<(), String> {
            self.call(format!("remove_file {}", path.display()));
            self.files.remove(path);
            Ok(())
        }
        fn remove_dir_all(&mut self, path: &Path) -> Result<(), String> {
            self.call(format!("remove_dir_all {}", path.display()));
            self.files.retain(|p, _| !p.starts_with(path));
            Ok(())
        }
        fn remove_dir_if_empty(&mut self, path: &Path) {
            self.call(format!("remove_dir_if_empty {}", path.display()));
        }
        fn run(&mut self, cmd: &CommandSpec) -> Result<(i32, String), String> {
            self.call(format!("run {cmd}"));
            let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
            let program = cmd
                .program
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            match (program, args.first().copied()) {
                ("schtasks.exe", Some("/Run")) => {
                    if let Some((path, bytes)) = self.relay_cert.clone() {
                        self.files.insert(path, bytes);
                    }
                    Ok((0, "CORRECTO: se intento ejecutar la tarea".into()))
                }
                ("schtasks.exe", Some("/End" | "/Delete")) => Ok((1, "ERROR: no existe".into())),
                ("awawa-service.exe", Some("install")) => {
                    self.service = ServiceState::Stopped;
                    Ok((0, "servicio instalado: Awawa".into()))
                }
                ("awawa-service.exe", Some("uninstall")) => {
                    self.service = ServiceState::Absent;
                    Ok((0, "servicio desinstalado: Awawa".into()))
                }
                _ => Ok((0, String::new())),
            }
        }
        fn create_shortcut(&mut self, s: &Shortcut) -> Result<(), String> {
            self.call(format!(
                "shortcut {} -> {} {}",
                s.link.display(),
                s.target.display(),
                s.args
            ));
            Ok(())
        }
        fn service_state(&mut self) -> Result<ServiceState, String> {
            Ok(self.service)
        }
        fn start_service(&mut self) -> Result<(), String> {
            self.call("start_service".into());
            self.service = ServiceState::Running;
            Ok(())
        }
        fn stop_service(&mut self) -> Result<(), String> {
            self.call("stop_service".into());
            self.service = ServiceState::Stopped;
            Ok(())
        }
        fn delete_service(&mut self) -> Result<(), String> {
            self.call("delete_service".into());
            self.service = ServiceState::Absent;
            Ok(())
        }
        fn verifier_status(&mut self) -> Result<UnattendedStatus, String> {
            self.call("verifier_status".into());
            Ok(self.verifier)
        }
        fn admin_request(&mut self, request: &AdminRequest) -> Result<AdminResponse, ClientError> {
            self.call(format!("admin_request {request:?}"));
            if self.service != ServiceState::Running {
                return Err(ClientError::NotRunning);
            }
            if self.pipe_not_ready > 0 {
                self.pipe_not_ready -= 1;
                return Err(ClientError::NotRunning);
            }
            let (password, generation) = match (request, self.verifier) {
                (AdminRequest::Set { password }, UnattendedStatus::NotConfigured) => (password, 1),
                (AdminRequest::Set { password }, UnattendedStatus::Revoked { generation }) => {
                    (password, generation + 1)
                }
                (AdminRequest::Change { password }, UnattendedStatus::Enabled { generation }) => {
                    (password, generation + 1)
                }
                _ => {
                    return Ok(AdminResponse::Error {
                        message: "operacion no valida en este estado".into(),
                    });
                }
            };
            self.delivered.push(password.expose().to_owned());
            self.verifier = UnattendedStatus::Enabled { generation };
            Ok(AdminResponse::Done { generation })
        }
        fn identity_load_or_create(&mut self) -> Result<(HostIdentity, bool), String> {
            self.call("identity_load_or_create".into());
            match &self.identity {
                Some(identity) => Ok((identity.clone(), false)),
                None => {
                    let identity = HostIdentity {
                        id: Some(987_654_321),
                        key: crate::connection::tests::sample_key(),
                    };
                    self.identity = Some(identity.clone());
                    Ok((identity, true))
                }
            }
        }
        fn identity_load(&mut self) -> Result<Option<HostIdentity>, String> {
            self.call("identity_load".into());
            Ok(self.identity.clone())
        }
        fn sleep(&mut self, _duration: Duration) {}
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeSystem;
    use super::*;
    use crate::connection::tests::{sample_key, sample_pin};
    use crate::paths::Layout;
    use crate::plan::{
        HostOptions, OperatorOptions, UninstallOptions, host_plan, operator_plan, render,
        uninstall_plan,
    };

    const PASSWORD: &str = "Contrasena-Secreta-2026";

    fn host_opts(unattended: bool) -> HostOptions {
        HostOptions {
            unattended,
            autostart: false,
            public_relay: "192.168.1.20:4433".into(),
            connection_file: r"C:\Users\Prueba\Desktop\Awawa-conexion.rrs".into(),
        }
    }

    fn fake_with_relay(layout: &Layout) -> FakeSystem {
        let mut sys = FakeSystem::new();
        sys.relay_cert = Some((layout.relay_cert(), sample_pin()));
        // Binario instalado de una version previa, por si el plan quita el servicio.
        sys.files
            .insert(layout.exe("awawa-service.exe"), b"MZ".to_vec());
        sys
    }

    fn secrets() -> Secrets {
        Secrets {
            password: Some(Zeroizing::new(PASSWORD.to_owned())),
        }
    }

    fn run(
        plan: &[Action],
        sys: &mut FakeSystem,
        secrets: &Secrets,
    ) -> (Result<Outcome, String>, Vec<String>) {
        let mut lines = Vec::new();
        let result = run_plan(plan, sys, secrets, &mut |l| lines.push(l.to_owned()));
        (result, lines)
    }

    fn assert_no_password(sys: &FakeSystem, lines: &[String], plan: &[Action]) {
        for text in sys
            .calls
            .iter()
            .chain(lines)
            .chain(std::iter::once(&render(plan)))
        {
            assert!(!text.contains(PASSWORD), "contrasena filtrada en: {text}");
        }
        for bytes in sys.files.values() {
            assert!(
                !String::from_utf8_lossy(bytes).contains(PASSWORD),
                "contrasena en un archivo"
            );
        }
    }

    #[test]
    fn host_desatendido_completo_sin_filtrar_la_contrasena() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(true)).unwrap();
        let mut sys = fake_with_relay(&layout);
        sys.pipe_not_ready = 2;
        let (result, lines) = run(&plan, &mut sys, &secrets());
        let outcome = result.unwrap();

        assert_eq!(
            sys.delivered,
            vec![PASSWORD.to_owned()],
            "la contrasena llega a la pipe"
        );
        assert!(
            sys.calls
                .iter()
                .any(|c| c.contains("admin_request Set { password: SecretString(***) }"))
        );
        assert_eq!(sys.service, ServiceState::Running);
        // Reinicio tras configurar: el servicio carga la identidad.
        let cfg = sys
            .calls
            .iter()
            .position(|c| c == "identity_load_or_create")
            .unwrap();
        let restart_stop = sys.calls.iter().rposition(|c| c == "stop_service").unwrap();
        assert!(cfg < restart_stop);

        let host = outcome.host.clone().unwrap();
        assert_eq!(host.id, Some(987_654_321));
        let file = sys.files.get(&host_opts(true).connection_file).unwrap();
        let parsed = ConnectionInfo::parse(file).unwrap();
        assert_eq!(parsed.relay_addr, "192.168.1.20:4433");
        assert_eq!(parsed.relay_pin, sample_pin());
        assert_eq!(parsed.host, Some(host));
        assert_eq!(outcome.connection, Some(parsed));
        assert!(lines.iter().any(|l| l.contains("huella del pin del relay")));
        assert_no_password(&sys, &lines, &plan);
    }

    #[test]
    fn reconfigurar_cambia_la_contrasena_existente() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(true)).unwrap();
        let mut sys = fake_with_relay(&layout);
        sys.service = ServiceState::Running;
        sys.verifier = UnattendedStatus::Enabled { generation: 3 };
        sys.identity = Some(HostIdentity {
            id: Some(111_222_333),
            key: sample_key(),
        });
        let (result, lines) = run(&plan, &mut sys, &secrets());
        result.unwrap();
        // El servicio previo se quito con su propio binario antes de reinstalarlo.
        assert!(
            sys.calls
                .iter()
                .any(|c| c.contains("awawa-service.exe\" uninstall"))
        );
        assert!(sys.calls.iter().any(|c| c.contains("admin_request Change")));
        assert_eq!(sys.verifier, UnattendedStatus::Enabled { generation: 4 });
        assert!(
            lines
                .iter()
                .any(|l| l.contains("identidad del servicio existente: ID 111222333"))
        );
        assert_no_password(&sys, &lines, &plan);
    }

    #[test]
    fn host_sin_desatendido_no_toca_la_pipe() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(false)).unwrap();
        let mut sys = fake_with_relay(&layout);
        let (result, lines) = run(&plan, &mut sys, &Secrets::default());
        let outcome = result.unwrap();
        assert!(outcome.host.is_none());
        assert!(!sys.calls.iter().any(|c| c.starts_with("admin_request")));
        let parsed =
            ConnectionInfo::parse(sys.files.get(&host_opts(false).connection_file).unwrap())
                .unwrap();
        assert!(parsed.host.is_none());
        assert!(lines.last().unwrap().contains("Terminado"));
        // La regla de firewall se crea con la ruta exacta del relay.
        assert!(
            sys.calls
                .iter()
                .any(|c| { c.contains(r#"program="C:\Program Files\Awawa\awawa-relay.exe""#) })
        );
    }

    #[test]
    fn sin_certificado_del_relay_falla_con_aviso() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(false)).unwrap();
        let mut sys = FakeSystem::new();
        let (result, lines) = run(&plan, &mut sys, &Secrets::default());
        let err = result.unwrap_err();
        assert!(err.contains("no aparecio"), "{err}");
        assert!(lines.last().unwrap().contains("ERROR"));
        assert!(!sys.files.contains_key(&host_opts(false).connection_file));
    }

    #[test]
    fn falla_cerrado_si_program_files_no_es_de_confianza() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(true)).unwrap();
        let mut sys = fake_with_relay(&layout);
        sys.fail_validation = true;
        let (result, _) = run(&plan, &mut sys, &secrets());
        assert!(result.unwrap_err().contains("dueno no confiable"));
        assert!(!sys.calls.iter().any(|c| c.contains("install --relay")));
        assert!(sys.delivered.is_empty());
    }

    #[test]
    fn contrasena_ausente_o_corta_se_rechaza_sin_enviarla() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(true)).unwrap();
        let mut sys = fake_with_relay(&layout);
        assert!(
            run(&plan, &mut sys, &Secrets::default())
                .0
                .unwrap_err()
                .contains("falta la contrasena")
        );
        let mut sys = fake_with_relay(&layout);
        let short = Secrets {
            password: Some(Zeroizing::new("corta".into())),
        };
        let (result, lines) = run(&plan, &mut sys, &short);
        assert!(result.unwrap_err().contains("entre 12 y 128"));
        assert!(sys.delivered.is_empty());
        assert!(!lines.iter().any(|l| l.contains("corta\"")));
    }

    #[test]
    fn operador_importa_pin_y_clave() {
        let layout = Layout::for_tests();
        let connection = ConnectionInfo {
            relay_addr: "192.168.1.20:4433".into(),
            relay_pin: sample_pin(),
            host: Some(HostIdentity {
                id: Some(123_456_789),
                key: sample_key(),
            }),
        };
        let plan = operator_plan(&layout, &OperatorOptions { connection }).unwrap();
        let mut sys = FakeSystem::new();
        let (result, _) = run(&plan, &mut sys, &Secrets::default());
        result.unwrap();
        let dir = layout.operator_conn_dir();
        assert_eq!(
            sys.files.get(&dir.join("relay-cert.der")),
            Some(&sample_pin())
        );
        assert_eq!(
            sys.files.get(&dir.join("host-key.bin")),
            Some(&sample_key().to_vec())
        );
        assert_eq!(
            sys.calls
                .iter()
                .filter(|c| c.starts_with("shortcut"))
                .count(),
            2
        );
        assert!(
            sys.calls
                .iter()
                .any(|c| c.contains("awawa-operator.exe --relay 192.168.1.20:4433"))
        );
    }

    #[test]
    fn desinstalar_quita_servicio_tarea_firewall_y_carpetas() {
        let layout = Layout::for_tests();
        for keep_data in [true, false] {
            let mut sys = FakeSystem::new();
            sys.service = ServiceState::Running;
            sys.files
                .insert(layout.exe("awawa-service.exe"), b"MZ".to_vec());
            sys.files.insert(layout.relay_cert(), sample_pin());
            sys.files
                .insert(layout.service_data_dir.join("service.identity"), vec![1]);
            let plan = uninstall_plan(&layout, UninstallOptions { keep_data });
            let (result, _) = run(&plan, &mut sys, &Secrets::default());
            result.unwrap();
            assert_eq!(sys.service, ServiceState::Absent);
            let uninstall = sys
                .calls
                .iter()
                .position(|c| c.contains("awawa-service.exe\" uninstall"))
                .unwrap();
            let rmdir = sys
                .calls
                .iter()
                .position(|c| *c == format!("remove_dir_all {}", layout.install_dir.display()))
                .unwrap();
            assert!(
                uninstall < rmdir,
                "el servicio se quita antes de borrar sus binarios"
            );
            assert!(
                sys.calls
                    .iter()
                    .any(|c| c.contains("/Delete /TN Awawa\\Relay /F"))
            );
            assert!(
                sys.calls
                    .iter()
                    .any(|c| c.contains("delete rule name=Awawa-Relay-UDP-4433"))
            );
            assert!(!sys.files.contains_key(&layout.exe("awawa-service.exe")));
            assert_eq!(sys.files.contains_key(&layout.relay_cert()), keep_data);
            assert_eq!(
                sys.files
                    .contains_key(&layout.service_data_dir.join("service.identity")),
                keep_data
            );
        }
    }

    #[test]
    fn desinstalar_sin_binario_del_servicio_lo_borra_en_el_scm() {
        let layout = Layout::for_tests();
        let mut sys = FakeSystem::new();
        sys.service = ServiceState::Stopped;
        let plan = uninstall_plan(&layout, UninstallOptions { keep_data: true });
        run(&plan, &mut sys, &Secrets::default()).0.unwrap();
        assert!(sys.calls.iter().any(|c| c == "delete_service"));
        assert_eq!(sys.service, ServiceState::Absent);
    }
}
