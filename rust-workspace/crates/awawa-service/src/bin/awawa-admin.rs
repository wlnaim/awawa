//! Herramienta de administrador de la contrasena desatendida: `set`, `change`, `revoke`, `status`.
//!
//! La contrasena se lee SOLO de la entrada estandar (sin eco en consola; `set`/`change` piden confirmacion),
//! nunca por argumentos de linea de comandos, y los buffers se sobrescriben tras usarlos.
//! Requiere un token de administrador elevado. Opcion `--store <ruta>` (solo `status`) para leer otro archivo.
//!
//! Identidad del servicio: `set` genera UNA vez el ID persistente (9 digitos) y el par
//! Ed25519 en `service.identity`, junto al verificador (DPAPI de maquina + DACL SY/BA). `status`
//! muestra el ID y la huella de la clave publica (primeros 8 bytes de SHA-256 en hex,
//! `xxxx-xxxx-xxxx-xxxx`) y, con `--export-key <archivo>`, escribe los 32 bytes crudos de la clave
//! publica que el operador carga con `--host-key`.
//!
//! `set`, `change` y `revoke` NO derivan ni escriben nada: leen la contrasena, la envian al servicio por la
//! pipe de administracion (`awawa_service::admin_pipe`, DACL "D:P(A;;GA;;;SY)(A;;GA;;;BA)") y muestran el
//! resultado. Solo el servicio deriva el verificador, lo persiste (DPAPI de maquina + DACL SY/BA) y audita.
//! No hay respaldo de escritura directa: si el servicio no esta en ejecucion, el comando falla.
//!
//! `status` sigue leyendo el almacen directamente (solo lectura, no deriva ni persiste); `--store` solo
//! aplica a `status`. La identidad del servicio sigue generandose aqui en el primer `set`:
//! es el par Ed25519 del servicio, no la contrasena, y asi `status --export-key` no cambia. El servicio la
//! carga al arrancar: tras el primer `set` hay que reiniciarlo para que se registre en el relay.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("awawa-admin solo esta disponible en Windows");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(imp::run());
}

#[cfg(target_os = "windows")]
mod imp {
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use std::io::{BufRead, Write};
    use std::path::PathBuf;

    use awawa_protocol::audit::MemoryAuditSink;
    use awawa_protocol::unattended::UnattendedStatus;
    use awawa_protocol::{UNATTENDED_PASSWORD_MAX_LEN, UNATTENDED_PASSWORD_MIN_LEN};
    use awawa_service::admin_ops::AdminOps;
    use awawa_service::admin_pipe::{
        self, AdminRequest, AdminResponse, SecretString, password_len_ok,
    };
    use awawa_service::dpapi_store::VerifierFileStore;
    use awawa_service::identity::current_account_name;
    use awawa_service::kdf_cng::CngPbkdf2Sha256;
    use awawa_service::service_identity::{IdentityFileStore, export_public_key};
    use zeroize::Zeroizing;

    const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
    const SECURITY_MAX_SID_SIZE: usize = 68;
    const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CreateWellKnownSid(
            well_known_sid_type: i32,
            domain_sid: *mut c_void,
            p_sid: *mut c_void,
            cb_sid: *mut u32,
        ) -> i32;
        fn CheckTokenMembership(
            token_handle: *mut c_void,
            sid_to_check: *mut c_void,
            is_member: *mut i32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n_std_handle: u32) -> *mut c_void;
        fn GetConsoleMode(h_console: *mut c_void, lp_mode: *mut u32) -> i32;
        fn SetConsoleMode(h_console: *mut c_void, dw_mode: u32) -> i32;
    }

    /// `true` si el token actual (elevado) pertenece a BUILTIN\Administrators.
    /// Un administrador sin elevar tiene el grupo solo "deny-only" y devuelve `false`.
    fn is_administrator() -> bool {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE];
        let mut size = SECURITY_MAX_SID_SIZE as u32;
        // SAFETY: `sid` es un buffer valido de `size` bytes (tamano maximo de un SID); SID de dominio nulo.
        let ok = unsafe {
            CreateWellKnownSid(
                WIN_BUILTIN_ADMINISTRATORS_SID,
                null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 {
            return false;
        }
        let mut member = 0i32;
        // SAFETY: token nulo = token efectivo del hilo; `sid` es un SID valido recien construido.
        let ok = unsafe { CheckTokenMembership(null_mut(), sid.as_mut_ptr().cast(), &mut member) };
        ok != 0 && member != 0
    }

    /// Restablece el modo de consola al soltarse (incluso ante errores de lectura).
    struct EchoGuard {
        handle: *mut c_void,
        original: u32,
    }

    impl EchoGuard {
        /// Desactiva el eco si la entrada es una consola; si es una tuberia no hay eco que quitar.
        fn disable() -> Option<Self> {
            // SAFETY: STD_INPUT_HANDLE es una constante documentada.
            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let mut mode = 0u32;
            // SAFETY: `mode` es un destino valido; falla (0) si el manejador no es una consola.
            if handle.is_null() || unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
                return None;
            }
            // SAFETY: `handle` es una consola valida; solo se quita el bit de eco.
            unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
            Some(Self {
                handle,
                original: mode,
            })
        }
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            // SAFETY: restaura el modo original sobre la misma consola valida.
            unsafe { SetConsoleMode(self.handle, self.original) };
        }
    }

    /// Lee una linea de stdin sin eco. Limitacion: copias intermedias del runtime de E/S no se pueden borrar.
    fn read_secret(prompt: &str) -> std::io::Result<Zeroizing<String>> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let guard = EchoGuard::disable();
        let mut line = Zeroizing::new(String::with_capacity(256));
        let result = std::io::stdin().lock().read_line(&mut line);
        drop(guard);
        eprintln!();
        result?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    fn read_confirmed() -> Result<Zeroizing<String>, String> {
        let first = read_secret("Contrasena: ").map_err(|e| e.to_string())?;
        let second = read_secret("Confirmar contrasena: ").map_err(|e| e.to_string())?;
        if *first == *second {
            Ok(first)
        } else {
            Err("las contrasenas no coinciden".into())
        }
    }

    fn default_store_path() -> Result<PathBuf, String> {
        let base = std::env::var_os("ProgramData").ok_or("variable ProgramData no definida")?;
        Ok(PathBuf::from(base)
            .join("Awawa")
            .join("unattended.verifier"))
    }

    /// Entrega la peticion al servicio por la pipe y devuelve la generacion resultante.
    fn send(request: AdminRequest) -> Result<u32, String> {
        match admin_pipe::request(&request) {
            Ok(AdminResponse::Done { generation }) => Ok(generation),
            Ok(AdminResponse::Error { message }) => Err(message),
            Err(e) => Err(e.to_string()),
        }
    }

    fn usage() -> i32 {
        eprintln!(
            "uso: awawa-admin <set|change|revoke|status> [--store <ruta>] [--export-key <archivo>]"
        );
        eprintln!(
            "--export-key solo con status: escribe la clave publica (32 bytes) para --host-key"
        );
        eprintln!("la contrasena se lee de la entrada estandar (sin eco); nunca por argumentos");
        2
    }

    pub fn run() -> i32 {
        let mut args = std::env::args().skip(1);
        let Some(command) = args.next() else {
            return usage();
        };
        let mut store_path: Option<PathBuf> = None;
        let mut export_key: Option<PathBuf> = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--store" => match args.next() {
                    Some(p) => store_path = Some(PathBuf::from(p)),
                    None => return usage(),
                },
                "--export-key" if command == "status" => match args.next() {
                    Some(p) => export_key = Some(PathBuf::from(p)),
                    None => return usage(),
                },
                _ => return usage(),
            }
        }
        if !matches!(command.as_str(), "set" | "change" | "revoke" | "status") {
            return usage();
        }
        if command != "status" && store_path.is_some() {
            eprintln!("--store solo aplica a status: el servicio decide donde persiste");
            return usage();
        }

        if !is_administrator() {
            eprintln!("awawa-admin requiere administrador: ejecute desde una consola elevada");
            return 3;
        }

        let path = match store_path.map(Ok).unwrap_or_else(default_store_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        let store = VerifierFileStore::new(&path);
        let identity_store = IdentityFileStore::new(path.with_file_name("service.identity"));

        let outcome: Result<String, String> = match command.as_str() {
            "status" => {
                // `status` es de solo lectura: no deriva, no persiste, no crea el directorio ni abre la
                // auditoria (el destino en memoria solo satisface el contexto de `AdminOps`).
                let mut sink = MemoryAuditSink::new();
                // Identidad desde el token del proceso (no desde variables de entorno falsificables).
                let operator = format!(
                    "admin:{}",
                    current_account_name()
                        .unwrap_or_else(|code| format!("desconocido(Win32={code})"))
                );
                let kdf = CngPbkdf2Sha256;
                let ops = AdminOps {
                    store: &store,
                    kdf: &kdf,
                    sink: &mut sink,
                    operator: &operator,
                };
                ops.status()
                    .map(|s| match s {
                        UnattendedStatus::NotConfigured => "no configurada".to_string(),
                        UnattendedStatus::Enabled { generation } => {
                            format!("habilitada (generacion {generation})")
                        }
                        UnattendedStatus::Revoked { generation } => {
                            format!("revocada (generacion {generation})")
                        }
                    })
                    .and_then(|mut text| {
                        match identity_store.load()? {
                            None => text.push_str(
                                "
identidad del servicio: sin generar (ejecute set)",
                            ),
                            Some(identity) => {
                                text.push_str(&format!(
                                    "
ID del equipo: {}
huella de la clave del servicio: {}",
                                    identity.id(),
                                    identity.fingerprint()
                                ));
                                if let Some(out) = &export_key {
                                    export_public_key(&identity, out).map_err(|e| {
                                        awawa_service::dpapi_store::StoreError::Io(e.to_string())
                                    })?;
                                    text.push_str(&format!(
                                        "
clave publica exportada en {}",
                                        out.display()
                                    ));
                                }
                            }
                        }
                        Ok(text)
                    })
                    .map_err(|e| e.to_string())
            }
            "revoke" => {
                send(AdminRequest::Revoke).map(|g| format!("contrasena revocada (generacion {g})"))
            }
            "set" | "change" => {
                let password = match read_confirmed() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: {e}");
                        return 1;
                    }
                };
                // Pre-validacion; el servicio aplica la politica de todos modos.
                if !password_len_ok(&password) {
                    eprintln!(
                        "error: la contrasena debe tener entre {UNATTENDED_PASSWORD_MIN_LEN} y {UNATTENDED_PASSWORD_MAX_LEN} caracteres"
                    );
                    return 1;
                }
                let password = SecretString::new(password);
                if command == "set" {
                    send(AdminRequest::Set { password })
                        .map(|g| format!("contrasena configurada (generacion {g})"))
                        .and_then(|mut text| {
                            // La identidad se genera una sola vez; un `set` posterior la conserva.
                            let (identity, created) =
                                identity_store.load_or_create().map_err(|e| e.to_string())?;
                            text.push_str(&format!(
                                "
identidad del servicio {}: ID {} huella {}",
                                if created { "generada" } else { "existente" },
                                identity.id(),
                                identity.fingerprint()
                            ));
                            if created {
                                text.push_str(
                                    "
reinicie el servicio para que cargue la identidad y se registre en el relay",
                                );
                            }
                            Ok(text)
                        })
                } else {
                    send(AdminRequest::Change { password })
                        .map(|g| format!("contrasena cambiada (generacion {g})"))
                }
            }
            _ => unreachable!("subcomando validado arriba"),
        };

        match outcome {
            Ok(msg) => {
                println!("{msg}");
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        }
    }
}
