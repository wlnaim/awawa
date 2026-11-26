//! Servicio de Windows `Awawa` (acceso desatendido).
//!
//! Uso:
//! - `awawa-service install [--relay <host:puerto> --relay-pin <relay-cert.der>]`: SCM, LocalSystem,
//!   inicio automatico, privilegios minimos declarados, SID de servicio y DACL del servicio. Con
//!   `--relay`/`--relay-pin` copia el certificado DER fijado del relay a
//!   `%ProgramData%\Awawa\relay.pin` y escribe la direccion en `relay.addr` (DACL SY/BA).
//! - `awawa-service uninstall`.
//! - Sin argumentos arranca como servicio (dispatcher del SCM).
//!
//! Acepta `STOP` y `SESSIONCHANGE`. Si hay verificador, identidad (`service.identity`, la genera
//! `awawa-admin set`) y configuracion del relay validas, arranca la red
//! (`awawa_service::unattended_net`): registro con el ID persistente, autenticacion dentro del canal
//! E2E y lanzamiento de `awawa-session-agent.exe` (junto a este binario) en la sesion de consola,
//! con la red como duena de la sesion y de su monitor. Sin identidad o sin relay no se registra en
//! ningun relay y los eventos de Windows no producen transiciones.
//! Al iniciar carga el verificador desde `%ProgramData%\Awawa\unattended.verifier`; si esta
//! manipulado o no se puede descifrar, el acceso desatendido queda deshabilitado (falla cerrada).
//! Atiende ademas la pipe de administracion (`awawa_service::admin_pipe`, DACL SY/BA): `awawa-admin
//! set|change|revoke` le entrega la contrasena y solo este proceso deriva, persiste y audita. Corre en su
//! propio hilo, independiente de la red, de modo que funciona igual con una sesion desatendida activa
//! (la revalidacion de generacion cada 2 s la termina si la contrasena cambia).

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("awawa-service solo esta disponible en Windows");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(imp::run());
}

#[cfg(target_os = "windows")]
mod imp {
    use core::ffi::c_void;
    use core::ptr::{null, null_mut};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, AuditSinkError};
    use awawa_protocol::unattended::{
        UnattendedAuthenticator, UnattendedCredentialState, UnattendedStatus,
    };
    use awawa_service::admin_pipe::{AdminPipeHandle, AdminService, spawn_admin_pipe};
    use awawa_service::audit_sink::{EventLogSink, JsonLinesFileSink};
    use awawa_service::dpapi_store::{
        VerifierFileStore, ensure_protected_dir, harden_protected_dir,
    };
    use awawa_service::kdf_argon2::ServiceKdf;
    use awawa_service::relay_config::{RelayConfigStore, RelaySettings};
    use awawa_service::service_identity::IdentityFileStore;
    use awawa_service::session_tracker::{SessionTracker, TrackerStep};
    use awawa_service::trust::{TrustPolicy, validate_location};
    use awawa_service::unattended_auth::{current_status, reload_credentials};
    use awawa_service::unattended_net::{
        ServiceEvent, SharedAudit, StoreAuth, Timings, UnattendedService, WindowsPlatform,
    };
    use awawa_service::winutil::{last_error, unix_ms_now, wide};

    const SERVICE_NAME: &str = "Awawa";
    const DISPLAY_NAME: &str = "Awawa (acceso desatendido)";
    const DESCRIPTION: &str = "Acceso desatendido con contrasena persistente administrada y suspension en escritorio seguro (UAC).";
    /// Control del servicio: solo SYSTEM y Administradores controlan/configuran; usuarios autenticados solo leen el estado.
    const SERVICE_SDDL: &str =
        "D:P(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;AU)";

    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
    const SERVICE_AUTO_START: u32 = 2;
    const SERVICE_ERROR_NORMAL: u32 = 1;
    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
    const DELETE: u32 = 0x0001_0000;
    const SERVICE_STOP: u32 = 0x0020;
    const SERVICE_CONFIG_DESCRIPTION: u32 = 1;
    const SERVICE_CONFIG_SERVICE_SID_INFO: u32 = 5;
    const SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO: u32 = 6;
    const SERVICE_SID_TYPE_UNRESTRICTED: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const SDDL_REVISION_1: u32 = 1;

    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_START_PENDING: u32 = 2;
    const SERVICE_STOP_PENDING: u32 = 3;
    const SERVICE_RUNNING: u32 = 4;
    const SERVICE_ACCEPT_STOP: u32 = 0x1;
    const SERVICE_ACCEPT_SESSIONCHANGE: u32 = 0x80;
    const SERVICE_CONTROL_STOP: u32 = 1;
    const SERVICE_CONTROL_INTERROGATE: u32 = 4;
    const SERVICE_CONTROL_SESSIONCHANGE: u32 = 0x0E;
    const NO_ERROR: u32 = 0;
    const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

    #[repr(C)]
    struct ServiceStatus {
        dw_service_type: u32,
        dw_current_state: u32,
        dw_controls_accepted: u32,
        dw_win32_exit_code: u32,
        dw_service_specific_exit_code: u32,
        dw_check_point: u32,
        dw_wait_hint: u32,
    }

    type ServiceMainFn = unsafe extern "system" fn(u32, *mut *mut u16);
    type HandlerExFn = unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32;

    #[repr(C)]
    struct ServiceTableEntryW {
        lp_service_name: *const u16,
        lp_service_proc: Option<ServiceMainFn>,
    }

    #[repr(C)]
    struct WtsSessionNotification {
        cb_size: u32,
        dw_session_id: u32,
    }

    #[repr(C)]
    struct ServiceDescriptionW {
        lp_description: *mut u16,
    }

    #[repr(C)]
    struct ServiceRequiredPrivilegesInfoW {
        pmsz_required_privileges: *mut u16,
    }

    #[repr(C)]
    struct ServiceSidInfo {
        dw_service_sid_type: u32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> *mut c_void;
        fn CreateServiceW(
            h_sc_manager: *mut c_void,
            service_name: *const u16,
            display_name: *const u16,
            desired_access: u32,
            service_type: u32,
            start_type: u32,
            error_control: u32,
            binary_path_name: *const u16,
            load_order_group: *const u16,
            tag_id: *mut u32,
            dependencies: *const u16,
            service_start_name: *const u16,
            password: *const u16,
        ) -> *mut c_void;
        fn OpenServiceW(
            h_sc_manager: *mut c_void,
            service_name: *const u16,
            desired_access: u32,
        ) -> *mut c_void;
        fn DeleteService(h_service: *mut c_void) -> i32;
        fn ControlService(
            h_service: *mut c_void,
            dw_control: u32,
            lp_service_status: *mut ServiceStatus,
        ) -> i32;
        fn CloseServiceHandle(h_sc_object: *mut c_void) -> i32;
        fn ChangeServiceConfig2W(h_service: *mut c_void, info_level: u32, info: *mut c_void)
        -> i32;
        fn SetServiceObjectSecurity(
            h_service: *mut c_void,
            security_information: u32,
            security_descriptor: *mut c_void,
        ) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            sd: *mut *mut c_void,
            sd_size: *mut u32,
        ) -> i32;
        fn StartServiceCtrlDispatcherW(service_table: *const ServiceTableEntryW) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            service_name: *const u16,
            handler: HandlerExFn,
            context: *mut c_void,
        ) -> *mut c_void;
        fn SetServiceStatus(h_status: *mut c_void, status: *const ServiceStatus) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    // ---------------------------------------------------------------- install / uninstall

    /// Manejador del SCM o de un servicio, cerrado al soltarse.
    struct ScHandle(*mut c_void);
    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: manejador de SCM/servicio propio y valido, cerrado una sola vez.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    fn open_scm() -> Result<ScHandle, String> {
        // SAFETY: maquina y base de datos nulas = SCM local activo.
        let h = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
        if h.is_null() {
            return Err(format!(
                "OpenSCManagerW fallo (Win32={}); se requiere administrador",
                last_error()
            ));
        }
        Ok(ScHandle(h))
    }

    fn check(ok: i32, what: &str) -> Result<(), String> {
        if ok == 0 {
            Err(format!("{what} fallo (Win32={})", last_error()))
        } else {
            Ok(())
        }
    }

    /// El binario del servicio corre como SYSTEM: solo se instala desde %ProgramFiles% (o `(x86)`), donde los
    /// usuarios estandar no pueden reemplazarlo, y solo si el directorio y el archivo cumplen la politica
    /// SYSTEM/Administradores/TrustedInstaller (sin escritura para otros). Si no, `install` se niega: evita
    /// registrar como LocalSystem un ejecutable que un usuario podria sustituir.
    fn check_install_location(exe: &std::path::Path) -> Result<(), String> {
        let norm = |p: &std::path::Path| {
            p.to_string_lossy()
                .trim_start_matches("\\\\?\\")
                .to_lowercase()
        };
        let exe = std::fs::canonicalize(exe).map_err(|e| e.to_string())?;
        let exe_text = norm(&exe);
        let under_program_files = ["ProgramFiles", "ProgramFiles(x86)"].iter().any(|var| {
            std::env::var_os(var).is_some_and(|root| {
                let root = norm(&std::fs::canonicalize(&root).unwrap_or_else(|_| root.into()));
                exe_text.starts_with(&format!("{}\\", root.trim_end_matches('\\')))
            })
        });
        if !under_program_files {
            return Err(format!(
                "instalacion rechazada: {} no esta bajo %ProgramFiles%; copie el binario alli (carpeta protegida) y reintente",
                exe.display()
            ));
        }
        let policy = TrustPolicy::program_files();
        if let Some(dir) = exe.parent() {
            validate_location(dir, &policy).map_err(|e| format!("instalacion rechazada: {e}"))?;
        }
        validate_location(&exe, &policy).map_err(|e| format!("instalacion rechazada: {e}"))
    }

    fn install(relay: Option<RelaySettings>) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        check_install_location(&exe)?;
        let bin_path = wide(&format!("\"{}\"", exe.display()));
        let name = wide(SERVICE_NAME);
        let display = wide(DISPLAY_NAME);
        let scm = open_scm()?;
        // Crea/endurece %ProgramData%\Awawa (dueno Administradores + DACL protegida SY/BA) antes
        // de registrar el servicio; un directorio plantado por un usuario estandar se corrige aqui.
        harden_protected_dir(&data_dir()).map_err(|e| e.to_string())?;
        if let Some(settings) = &relay {
            RelayConfigStore::new(data_dir())
                .save(settings)
                .map_err(|e| format!("configuracion del relay: {e}"))?;
        }

        // SAFETY: SCM valido; cadenas anchas terminadas en NUL; cuenta de inicio nula = LocalSystem;
        // sin grupo de orden, etiqueta, dependencias ni contrasena.
        let svc = unsafe {
            CreateServiceW(
                scm.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin_path.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        if svc.is_null() {
            return Err(format!("CreateServiceW fallo (Win32={})", last_error()));
        }
        let svc = ScHandle(svc);
        // Si falla un paso posterior a CreateServiceW se revierte el servicio (no queda a medio configurar).
        let configured = (|| -> Result<(), String> {
            let mut description = wide(DESCRIPTION);
            let mut desc_info = ServiceDescriptionW {
                lp_description: description.as_mut_ptr(),
            };
            // SAFETY: `svc` valido con SERVICE_CHANGE_CONFIG; la estructura coincide con el nivel indicado y
            // apunta a un buffer ancho vivo durante la llamada.
            check(
                unsafe {
                    ChangeServiceConfig2W(
                        svc.0,
                        SERVICE_CONFIG_DESCRIPTION,
                        (&raw mut desc_info).cast(),
                    )
                },
                "ChangeServiceConfig2W(DESCRIPTION)",
            )?;

            // Multi-cadena terminada en doble NUL: privilegios minimos que el servicio conserva.
            let mut privileges: Vec<u16> =
                "SeTcbPrivilege\0SeAssignPrimaryTokenPrivilege\0SeIncreaseQuotaPrivilege\0\0"
                    .encode_utf16()
                    .collect();
            let mut priv_info = ServiceRequiredPrivilegesInfoW {
                pmsz_required_privileges: privileges.as_mut_ptr(),
            };
            // SAFETY: igual que arriba; el buffer termina en doble NUL como exige el nivel REQUIRED_PRIVILEGES_INFO.
            check(
                unsafe {
                    ChangeServiceConfig2W(
                        svc.0,
                        SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                        (&raw mut priv_info).cast(),
                    )
                },
                "ChangeServiceConfig2W(REQUIRED_PRIVILEGES_INFO)",
            )?;

            let mut sid_info = ServiceSidInfo {
                dw_service_sid_type: SERVICE_SID_TYPE_UNRESTRICTED,
            };
            // SAFETY: igual que arriba; estructura de un solo campo vivo durante la llamada.
            check(
                unsafe {
                    ChangeServiceConfig2W(
                        svc.0,
                        SERVICE_CONFIG_SERVICE_SID_INFO,
                        (&raw mut sid_info).cast(),
                    )
                },
                "ChangeServiceConfig2W(SERVICE_SID_INFO)",
            )?;

            let sddl = wide(SERVICE_SDDL);
            let mut sd: *mut c_void = null_mut();
            // SAFETY: SDDL ancho terminado en NUL; `sd` es un destino valido; se libera con LocalFree abajo.
            check(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut sd,
                        null_mut(),
                    )
                },
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            )?;
            // SAFETY: `svc` valido (con WRITE_DAC por SERVICE_ALL_ACCESS) y `sd` un descriptor valido recien creado.
            let applied = unsafe { SetServiceObjectSecurity(svc.0, DACL_SECURITY_INFORMATION, sd) };
            let err = last_error();
            // SAFETY: `sd` fue asignado por la API de conversion (LocalAlloc) y no se usa despues.
            unsafe { LocalFree(sd) };
            if applied == 0 {
                return Err(format!("SetServiceObjectSecurity fallo (Win32={err})"));
            }
            Ok(())
        })();
        if let Err(e) = configured {
            // SAFETY: `svc` valido con derecho DELETE (SERVICE_ALL_ACCESS).
            unsafe { DeleteService(svc.0) };
            return Err(e);
        }
        Ok(())
    }

    fn uninstall() -> Result<(), String> {
        let name = wide(SERVICE_NAME);
        let scm = open_scm()?;
        // SAFETY: SCM valido y nombre ancho terminado en NUL.
        let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), DELETE | SERVICE_STOP) };
        if svc.is_null() {
            return Err(format!("OpenServiceW fallo (Win32={})", last_error()));
        }
        let svc = ScHandle(svc);
        let mut status = ServiceStatus {
            dw_service_type: 0,
            dw_current_state: 0,
            dw_controls_accepted: 0,
            dw_win32_exit_code: 0,
            dw_service_specific_exit_code: 0,
            dw_check_point: 0,
            dw_wait_hint: 0,
        };
        // SAFETY: `svc` valido con SERVICE_STOP; `status` es un destino valido. El resultado se ignora a proposito:
        // si el servicio ya estaba detenido, la parada falla y se continua con el borrado.
        unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) };
        // SAFETY: `svc` valido con derecho DELETE.
        check(unsafe { DeleteService(svc.0) }, "DeleteService")
    }

    // ---------------------------------------------------------------- servicio

    enum ServiceMsg {
        Stop,
        Session { event_type: u32, session_id: u32 },
    }

    static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static EVENTS: Mutex<Option<Sender<ServiceMsg>>> = Mutex::new(None);

    fn send(msg: ServiceMsg) {
        let guard = EVENTS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(msg);
        }
    }

    fn set_status(state: u32, accepted: u32, checkpoint: u32, wait_hint: u32) {
        let status = ServiceStatus {
            dw_service_type: SERVICE_WIN32_OWN_PROCESS,
            dw_current_state: state,
            dw_controls_accepted: accepted,
            dw_win32_exit_code: NO_ERROR,
            dw_service_specific_exit_code: 0,
            dw_check_point: checkpoint,
            dw_wait_hint: wait_hint,
        };
        let handle = STATUS_HANDLE.load(Ordering::SeqCst);
        if !handle.is_null() {
            // SAFETY: `handle` lo devolvio RegisterServiceCtrlHandlerExW; `status` es valido durante la llamada.
            unsafe { SetServiceStatus(handle, &status) };
        }
    }

    /// Manejador de controles. Se ejecuta en un hilo del SCM: solo encola mensajes y actualiza el estado.
    unsafe extern "system" fn control_handler(
        control: u32,
        event_type: u32,
        event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP => {
                // Margen para el cierre ordenado del agente (Timings::agent_exit) y el aviso al operador.
                set_status(SERVICE_STOP_PENDING, 0, 1, 15000);
                send(ServiceMsg::Stop);
                NO_ERROR
            }
            SERVICE_CONTROL_SESSIONCHANGE => {
                if !event_data.is_null() {
                    // SAFETY: para SERVICE_CONTROL_SESSIONCHANGE el SCM pasa un WTSSESSION_NOTIFICATION valido
                    // durante esta llamada; se copia el identificador antes de volver.
                    let session_id =
                        unsafe { (*event_data.cast::<WtsSessionNotification>()).dw_session_id };
                    send(ServiceMsg::Session {
                        event_type,
                        session_id,
                    });
                }
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    fn data_dir() -> PathBuf {
        PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()))
            .join("Awawa")
    }

    fn audit(sinks: &mut [Box<dyn AuditSink + Send>], event: AuditEvent, session_id: Option<u32>) {
        let mut record = AuditRecord::new(unix_ms_now(), event, "service");
        if let Some(id) = session_id {
            record = record.with_windows_session_id(id);
        }
        for sink in sinks.iter_mut() {
            let _ = sink.write_record(&record);
        }
    }

    /// Event Log compartible con el hilo de red.
    struct SendEventLog(EventLogSink);
    // SAFETY: el manejador de `RegisterEventSourceW` se puede usar desde cualquier hilo; aqui solo se
    // usa bajo el `Mutex` de `Fanout`.
    unsafe impl Send for SendEventLog {}
    impl AuditSink for SendEventLog {
        fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
            self.0.write_record(record)
        }
    }

    /// Todos los destinos de auditoria: basta con que uno escriba (si ninguno puede, el intento de
    /// autenticacion falla cerrado en `authenticate_unattended`).
    struct Fanout(Vec<Box<dyn AuditSink + Send>>);
    impl AuditSink for Fanout {
        fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditSinkError> {
            let mut result = Err(AuditSinkError::Io("sin destinos de auditoria".into()));
            for sink in self.0.iter_mut() {
                let written = sink.write_record(record);
                if result.is_err() {
                    result = written;
                }
            }
            result
        }
    }

    /// Arranca la pipe de administracion; si el nombre esta ocupado reintenta en segundo plano (mientras tanto
    /// no se puede cambiar la contrasena: falla cerrada).
    fn start_admin_pipe(store: &VerifierFileStore, audit: &SharedAudit) -> Option<AdminPipeHandle> {
        let service = AdminService::new(store.clone(), Box::new(ServiceKdf), audit.clone());
        match spawn_admin_pipe(service) {
            Ok(handle) => Some(handle),
            Err(e) => {
                eprintln!("awawa-service: pipe de administracion no disponible: {e}");
                None
            }
        }
    }

    type NetHandle = (
        tokio::sync::mpsc::UnboundedSender<ServiceEvent>,
        std::thread::JoinHandle<()>,
    );

    /// Arranca la red en un hilo con runtime propio. `None` si falta identidad o relay o no son validos.
    fn start_network(
        dir: &std::path::Path,
        store: &VerifierFileStore,
        audit: SharedAudit,
    ) -> Option<NetHandle> {
        let identity = IdentityFileStore::new(dir.join("service.identity"))
            .load()
            .ok()??;
        let settings = RelayConfigStore::new(dir).load().ok()??;
        let relay_addr = std::net::ToSocketAddrs::to_socket_addrs(&settings.addr)
            .ok()?
            .next()?;
        let pin = awawa_relay::RelayPin::from_cert_der(settings.pin_der);
        let agent_exe = std::env::current_exe()
            .ok()?
            .with_file_name("awawa-session-agent.exe");
        let auth = StoreAuth {
            store: store.clone(),
            authenticator: UnattendedAuthenticator::default(),
            kdf: Box::new(ServiceKdf),
            audit: audit.clone(),
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let service = UnattendedService::new(
            identity.id(),
            identity.signing_key().clone(),
            Arc::new(Mutex::new(auth)),
            WindowsPlatform { agent_exe },
            audit,
            rx,
            Timings::default(),
        );
        let handle = std::thread::Builder::new()
            .name("service-net".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok(client) = awawa_relay::RelayClient::new(relay_addr, pin) else {
                        return;
                    };
                    service.run(&client).await;
                    client.close();
                });
            })
            .ok()?;
        Some((tx, handle))
    }

    /// Punto de entrada del servicio invocado por el SCM.
    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = wide(SERVICE_NAME);
        // SAFETY: nombre ancho terminado en NUL; el manejador es una funcion `extern "system"` 'static.
        let handle =
            unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), control_handler, null_mut()) };
        if handle.is_null() {
            return;
        }
        STATUS_HANDLE.store(handle, Ordering::SeqCst);
        set_status(SERVICE_START_PENDING, 0, 1, 5000);

        let (tx, rx) = channel();
        *EVENTS.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);

        let dir = data_dir();
        let mut sinks: Vec<Box<dyn AuditSink + Send>> = Vec::new();
        if ensure_protected_dir(&dir).is_ok()
            && let Ok(s) = JsonLinesFileSink::open(&dir.join("audit.jsonl"))
        {
            sinks.push(Box::new(s));
        }
        if let Ok(s) = EventLogSink::open() {
            sinks.push(Box::new(SendEventLog(s)));
        }
        // Sin ningun destino de auditoria no se habilita el acceso desatendido (fail closed) ni la pipe
        // de administracion (toda operacion se audita).
        let have_audit = !sinks.is_empty();
        let mut unattended_enabled = have_audit;
        if !unattended_enabled {
            eprintln!("awawa-service: sin destino de auditoria; acceso desatendido deshabilitado");
        }
        audit(&mut sinks, AuditEvent::ServiceStarted, None);

        // El verificador se recarga del disco con validacion de ubicacion de confianza; si se rechaza,
        // el acceso desatendido queda deshabilitado (no "sin configurar") y se audita.
        let store = VerifierFileStore::new(dir.join("unattended.verifier"));
        let mut authenticator = UnattendedAuthenticator::default();
        if reload_credentials(&store, &mut authenticator).is_err() {
            unattended_enabled = false;
            audit(&mut sinks, AuditEvent::VerifierRejected, None);
        }
        if !unattended_enabled {
            *authenticator.credentials_mut() = UnattendedCredentialState::not_configured();
        }

        // Un unico destino compartido: rastreador, red y pipe de administracion auditan por el mismo.
        let shared = Arc::new(Mutex::new(Fanout(sinks)));
        let admin_audit: SharedAudit = shared.clone();
        let admin_pipe = if have_audit {
            start_admin_pipe(&store, &admin_audit)
        } else {
            None
        };

        set_status(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE,
            0,
            0,
        );
        if unattended_enabled {
            let net_audit: SharedAudit = shared.clone();
            if let Some((net_tx, net)) = start_network(&dir, &store, net_audit) {
                // La red es duena de la sesion y de su monitor: se le reenvian los eventos del SCM.
                while let Ok(ServiceMsg::Session {
                    event_type,
                    session_id,
                }) = rx.recv()
                {
                    let _ = net_tx.send(ServiceEvent::Wts {
                        event_type,
                        session_id,
                    });
                }
                let _ = net_tx.send(ServiceEvent::Stop);
                let _ = net.join();
                if let Some(pipe) = admin_pipe {
                    pipe.stop();
                }
                let mut fanout = shared.lock().unwrap_or_else(PoisonError::into_inner);
                audit(&mut fanout.0, AuditEvent::ServiceStopped, None);
                set_status(SERVICE_STOPPED, 0, 0, 0);
                return;
            }
        }
        // Sin red (falta identidad o relay): ninguna sesion se autentica; el rastreador queda sin
        // sesion activa y los eventos de Windows no producen transiciones.
        let mut tracker = SessionTracker::new();
        run_loop(&rx, &mut tracker, &shared, &store, unattended_enabled);

        let step = tracker.stop();
        emit(&shared, &step, tracker.windows_session_id());
        if let Some(pipe) = admin_pipe {
            pipe.stop();
        }
        let mut fanout = shared.lock().unwrap_or_else(PoisonError::into_inner);
        audit(&mut fanout.0, AuditEvent::ServiceStopped, None);
        set_status(SERVICE_STOPPED, 0, 0, 0);
    }

    fn emit(sinks: &Mutex<Fanout>, step: &TrackerStep, session_id: Option<u32>) {
        if let Some(event) = step.audit {
            let mut fanout = sinks.lock().unwrap_or_else(PoisonError::into_inner);
            audit(&mut fanout.0, event, session_id);
        }
    }

    fn run_loop(
        rx: &Receiver<ServiceMsg>,
        tracker: &mut SessionTracker,
        sinks: &Mutex<Fanout>,
        store: &VerifierFileStore,
        unattended_enabled: bool,
    ) {
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(ServiceMsg::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(ServiceMsg::Session {
                    event_type,
                    session_id,
                }) => {
                    let step = tracker.on_wts_event(event_type, session_id);
                    emit(sinks, &step, Some(session_id));
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Cambiar o revocar la contrasena corta la sesion ya autorizada con la anterior.
                    if tracker.is_active() {
                        let status = if unattended_enabled {
                            current_status(store).unwrap_or(UnattendedStatus::NotConfigured)
                        } else {
                            UnattendedStatus::NotConfigured
                        };
                        let id = tracker.windows_session_id();
                        let step = tracker.revalidate(status);
                        emit(sinks, &step, id);
                    }
                }
            }
        }
    }

    fn dispatch() -> Result<(), String> {
        let name = wide(SERVICE_NAME);
        let table = [
            ServiceTableEntryW {
                lp_service_name: name.as_ptr(),
                lp_service_proc: Some(service_main),
            },
            ServiceTableEntryW {
                lp_service_name: null(),
                lp_service_proc: None,
            },
        ];
        // SAFETY: tabla terminada con una entrada nula; los nombres anchos viven hasta que el dispatcher retorna.
        check(
            unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) },
            "StartServiceCtrlDispatcherW",
        )
        .map_err(|e| format!("{e}; este binario debe iniciarlo el SCM (use `install`)"))
    }

    const USAGE: &str = "uso: awawa-service [install [--relay <host:puerto> --relay-pin <relay-cert.der>] | uninstall]";

    /// `--relay` y `--relay-pin` van juntos o ninguno.
    fn parse_relay_args(
        mut args: impl Iterator<Item = String>,
    ) -> Result<Option<RelaySettings>, String> {
        let (mut addr, mut pin_file) = (None, None);
        while let Some(arg) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("falta el valor de {arg}"))?;
            match arg.as_str() {
                "--relay" => addr = Some(value),
                "--relay-pin" => pin_file = Some(PathBuf::from(value)),
                _ => return Err(format!("opcion desconocida: {arg}")),
            }
        }
        match (addr, pin_file) {
            (None, None) => Ok(None),
            (Some(addr), Some(pin_file)) => {
                awawa_service::relay_config::validate_addr(&addr)?;
                let pin_der = std::fs::read(&pin_file)
                    .map_err(|e| format!("no se pudo leer {}: {e}", pin_file.display()))?;
                Ok(Some(RelaySettings { addr, pin_der }))
            }
            _ => Err("--relay y --relay-pin van juntos".to_string()),
        }
    }

    pub fn run() -> i32 {
        let result = match std::env::args().nth(1).as_deref() {
            Some("install") => match parse_relay_args(std::env::args().skip(2)) {
                Ok(relay) => {
                    install(relay).map(|()| println!("servicio instalado: {SERVICE_NAME}"))
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    eprintln!("{USAGE}");
                    return 2;
                }
            },
            Some("uninstall") => {
                uninstall().map(|()| println!("servicio desinstalado: {SERVICE_NAME}"))
            }
            None => dispatch(),
            Some(_) => {
                eprintln!("{USAGE}");
                return 2;
            }
        };
        match result {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        }
    }
}
