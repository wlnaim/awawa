//! Plan de acciones de cada rol. Es puro: no toca el sistema; lo ejecuta `system::run_plan` y
//! `--dry-run` solo lo imprime. Ninguna accion contiene la contrasena desatendida: la recibe el
//! ejecutor aparte (`system::Secrets`) solo en `ConfigurePassword`.

use std::fmt;
use std::path::PathBuf;

use crate::cmdline::{CommandSpec, check_relay_addr, host_args, operator_args, path_arg, quote};
use crate::connection::ConnectionInfo;
use crate::paths::Layout;

pub const SERVICE_NAME: &str = "Awawa";
pub const RELAY_TASK: &str = r"Awawa\Relay";
pub const FIREWALL_RULE: &str = "Awawa-Relay-UDP-4433";
pub const RELAY_PORT: u16 = 4433;
pub const LOCAL_RELAY: &str = "127.0.0.1:4433";
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
pub const SID_LOCAL_SERVICE: &str = "S-1-5-19";
/// Carpeta del relay: dueno Administradores, DACL protegida; SYSTEM y Administradores control
/// total, LOCAL SERVICE (cuenta del relay) modificar para crear `relay-key.der`/`relay-cert.der`, y
/// Usuarios solo lectura (leen `relay-cert.der`, el pin publico). La clave nace con su propia DACL
/// protegida OW/SY/BA y como la crea el relay su dueno es LOCAL SERVICE.
pub const RELAY_DIR_SDDL: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;LS)(A;OICI;0x1200a9;;;BU)";
/// Carpeta de instalacion (y `conexion\`): dueno Administradores fijado explicitamente (no el dueno
/// por defecto del token), DACL protegida; SYSTEM y Administradores control total, Usuarios
/// lectura y ejecucion (LOCAL SERVICE ejecuta el relay como miembro de Usuarios).
pub const INSTALL_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// Binarios extraidos: mismo criterio que la carpeta.
pub const INSTALL_FILE_SDDL: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";
/// Espera maxima de `relay-cert.der` tras arrancar el relay.
pub const RELAY_CERT_TIMEOUT_SECS: u64 = 30;

pub const HOST_EXES: [&str; 2] = ["awawa-host.exe", "awawa-relay.exe"];
pub const SERVICE_EXES: [&str; 3] = [
    "awawa-service.exe",
    "awawa-session-agent.exe",
    "awawa-admin.exe",
];
pub const OPERATOR_EXE: &str = "awawa-operator.exe";
pub const HOST_SHORTCUT: &str = "Awawa - Este equipo";
pub const OPERATOR_SHORTCUT: &str = "Agente de soporte";

/// Opciones del rol "Equipo que recibe soporte (Host)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOptions {
    /// Copiar e instalar el servicio desatendido (pide la contrasena en la interfaz).
    pub unattended: bool,
    /// Acceso directo en la carpeta Inicio comun (al iniciar sesion).
    pub autostart: bool,
    /// Direccion del relay que vera el otro equipo (`ip:4433`), para el archivo de conexion.
    pub public_relay: String,
    /// Destino del archivo de conexion.
    pub connection_file: PathBuf,
}

/// Opciones del rol "Agente de soporte (operador)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorOptions {
    pub connection: ConnectionInfo,
}

/// Opciones de "Desinstalar".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallOptions {
    /// Conservar `%ProgramData%\Awawa` y `%ProgramData%\Awawa-Relay`.
    pub keep_data: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortcut {
    pub link: PathBuf,
    pub target: PathBuf,
    pub args: String,
    pub workdir: PathBuf,
    pub description: String,
}

/// Paso del plan. Todo lo que muestra es publico (rutas, comandos, tamanos y huellas).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Proceso del sistema. `allow_fail`: un codigo distinto de 0 solo se registra.
    Run {
        label: &'static str,
        cmd: CommandSpec,
        allow_fail: bool,
    },
    /// Crea la carpeta bajo Program Files y le fija `INSTALL_DIR_SDDL` (dueno BA explicito).
    CreateInstallDir(PathBuf),
    /// Extrae un binario de la carga (SHA-256 verificado), lo escribe de forma atomica y le fija
    /// `INSTALL_FILE_SDDL`.
    Extract {
        name: &'static str,
        dest: PathBuf,
    },
    /// Valida dueno y DACL (politica Program Files de `awawa_service::trust`).
    ValidateProgramFiles(Vec<PathBuf>),
    /// Crea (o valida si existe) la carpeta del relay con `RELAY_DIR_SDDL`.
    CreateRelayDataDir(PathBuf),
    /// Subcarpeta de la instalacion (`conexion\`) con `INSTALL_DIR_SDDL`.
    CreateDir(PathBuf),
    /// Material publico (XML de la tarea, pin, clave del host).
    WriteFile {
        path: PathBuf,
        bytes: Vec<u8>,
        label: &'static str,
    },
    RemoveFile(PathBuf),
    RemoveDir(PathBuf),
    RemoveDirIfEmpty(PathBuf),
    WaitForFile {
        path: PathBuf,
        timeout_secs: u64,
    },
    CreateShortcut(Shortcut),
    /// Detiene y quita el servicio si existe (`<exe> uninstall`, o el SCM si falta el binario) y espera a
    /// que desaparezca.
    RemoveService(PathBuf),
    StartService,
    RestartService,
    /// Configura (o cambia) la contrasena desatendida por la pipe de administracion y crea la
    /// identidad del servicio si falta.
    ConfigurePassword,
    /// Lee el ID y la clave publica del servicio.
    ReadServiceIdentity,
    /// Escribe el archivo de conexion con el pin leido de `pin` y, si existe, la identidad del host.
    WriteConnectionFile {
        path: PathBuf,
        relay: String,
        pin: PathBuf,
    },
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run {
                label,
                cmd,
                allow_fail,
            } => {
                write!(f, "{label}: {cmd}")?;
                if *allow_fail {
                    write!(f, "  (si falla se continua)")?;
                }
                Ok(())
            }
            Self::CreateInstallDir(p) => {
                write!(
                    f,
                    "Crear carpeta {} con dueno y DACL {INSTALL_DIR_SDDL}",
                    p.display()
                )
            }
            Self::Extract { name, dest } => {
                write!(
                    f,
                    "Extraer {name} -> {} (verifica SHA-256; dueno y DACL {INSTALL_FILE_SDDL})",
                    dest.display()
                )
            }
            Self::ValidateProgramFiles(paths) => {
                write!(
                    f,
                    "Validar dueno Administradores/SYSTEM y sin escritura para usuarios:"
                )?;
                for p in paths {
                    write!(f, " {}", quote(&p.display().to_string()))?;
                }
                Ok(())
            }
            Self::CreateRelayDataDir(p) => {
                write!(
                    f,
                    "Crear o validar carpeta del relay {} con DACL {RELAY_DIR_SDDL}",
                    p.display()
                )
            }
            Self::CreateDir(p) => write!(
                f,
                "Crear carpeta {} con dueno y DACL {INSTALL_DIR_SDDL}",
                p.display()
            ),
            Self::WriteFile { path, bytes, label } => write!(
                f,
                "Escribir {label} {} ({} bytes, SHA-256 {})",
                path.display(),
                bytes.len(),
                crate::payload::sha256_hex(bytes)
            ),
            Self::RemoveFile(p) => write!(f, "Borrar {} (si existe)", p.display()),
            Self::RemoveDir(p) => write!(
                f,
                "Borrar carpeta {} y su contenido (si existe)",
                p.display()
            ),
            Self::RemoveDirIfEmpty(p) => write!(f, "Borrar carpeta {} si queda vacia", p.display()),
            Self::WaitForFile { path, timeout_secs } => {
                write!(f, "Esperar {} (hasta {timeout_secs} s)", path.display())
            }
            Self::CreateShortcut(s) => write!(
                f,
                "Acceso directo {} -> {} {}",
                s.link.display(),
                quote(&s.target.display().to_string()),
                s.args
            ),
            Self::RemoveService(exe) => write!(
                f,
                "Servicio {SERVICE_NAME}: si existe, detenerlo, \"{}\" uninstall y esperar a que desaparezca",
                exe.display()
            ),
            Self::StartService => write!(f, "Iniciar el servicio {SERVICE_NAME} y esperar RUNNING"),
            Self::RestartService => write!(
                f,
                "Reiniciar el servicio {SERVICE_NAME} (carga la identidad y se registra en el relay)"
            ),
            Self::ConfigurePassword => write!(
                f,
                "Contrasena desatendida: enviar por \\\\.\\pipe\\Awawa.admin (set, o change si ya existe; dueno SYSTEM/BA verificado) y crear service.identity si falta  [contrasena: no se muestra]"
            ),
            Self::ReadServiceIdentity => {
                write!(f, "Leer ID y clave publica del servicio (service.identity)")
            }
            Self::WriteConnectionFile { path, relay, pin } => write!(
                f,
                "Escribir archivo de conexion {} (relay={relay}, pin de {}, identidad del host si hay desatendido)",
                path.display(),
                pin.display()
            ),
        }
    }
}

fn tool(
    layout: &Layout,
    exe: &str,
    label: &'static str,
    args: &[&str],
    allow_fail: bool,
) -> Action {
    Action::Run {
        label,
        cmd: CommandSpec::new(layout.tool(exe), args),
        allow_fail,
    }
}

/// XML de la tarea programada del relay: al iniciar el sistema, como LOCAL SERVICE (S-1-5-19), sin
/// limite de tiempo de ejecucion y con reinicio ante fallo.
pub fn relay_task_xml(layout: &Layout) -> Result<String, String> {
    let exe = path_arg(&layout.exe("awawa-relay.exe"))?;
    let dir = path_arg(&layout.relay_data_dir)?;
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Relay QUIC de Awawa (UDP {RELAY_PORT}).</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Relay">
      <UserId>{SID_LOCAL_SERVICE}</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Relay">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--dir "{dir}"</Arguments>
      <WorkingDirectory>{dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        exe = esc(&exe),
        dir = esc(&dir),
    ))
}

/// UTF-16 LE con BOM, la codificacion que declara el XML y que `schtasks /XML` acepta.
pub fn utf16_with_bom(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn stop_relay(layout: &Layout) -> Action {
    tool(
        layout,
        "schtasks.exe",
        "Detener el relay",
        &["/End", "/TN", RELAY_TASK],
        true,
    )
}

fn delete_firewall_rule(layout: &Layout, allow_fail: bool) -> Action {
    tool(
        layout,
        "netsh.exe",
        "Quitar regla de firewall",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE}"),
        ],
        allow_fail,
    )
}

/// Rol Host: awawa-host + relay local (tarea al inicio como LOCAL SERVICE) + firewall + accesos
/// directos y, con `unattended`, el servicio con su contrasena. Termina con el archivo de conexion.
pub fn host_plan(layout: &Layout, opts: &HostOptions) -> Result<Vec<Action>, String> {
    check_relay_addr(&opts.public_relay)?;
    path_arg(&opts.connection_file)?;
    let relay_exe = layout.exe("awawa-relay.exe");
    let cert = layout.relay_cert();
    let host_exe = layout.exe("awawa-host.exe");
    // Dentro de la carpeta de instalacion ya validada (solo Administradores escriben), no en %TEMP%.
    let task_xml = layout.install_dir.join("relay-task.xml");

    let mut plan = vec![
        // Reinstalar/reconfigurar: liberar los binarios en uso antes de reemplazarlos.
        stop_relay(layout),
        Action::RemoveService(layout.exe("awawa-service.exe")),
        Action::CreateInstallDir(layout.install_dir.clone()),
    ];
    let mut exes: Vec<&'static str> = HOST_EXES.to_vec();
    if opts.unattended {
        exes.extend(SERVICE_EXES);
    }
    for name in &exes {
        plan.push(Action::Extract {
            name,
            dest: layout.exe(name),
        });
    }
    if !opts.unattended {
        for name in SERVICE_EXES {
            plan.push(Action::RemoveFile(layout.exe(name)));
        }
    }
    let mut validate = vec![layout.install_dir.clone()];
    validate.extend(exes.iter().map(|n| layout.exe(n)));
    plan.push(Action::ValidateProgramFiles(validate));

    // Relay local.
    plan.push(Action::CreateRelayDataDir(layout.relay_data_dir.clone()));
    plan.push(Action::WriteFile {
        path: task_xml.clone(),
        bytes: utf16_with_bom(&relay_task_xml(layout)?),
        label: "XML de la tarea del relay",
    });
    plan.push(Action::Run {
        label: "Registrar tarea del relay (inicio del sistema, LOCAL SERVICE)",
        cmd: CommandSpec::new(
            layout.tool("schtasks.exe"),
            &[
                "/Create",
                "/TN",
                RELAY_TASK,
                "/XML",
                &path_arg(&task_xml)?,
                "/F",
            ],
        ),
        allow_fail: false,
    });
    plan.push(Action::RemoveFile(task_xml));
    plan.push(delete_firewall_rule(layout, true));
    plan.push(Action::Run {
        label: "Abrir UDP 4433 solo para awawa-relay.exe",
        cmd: CommandSpec {
            program: layout.tool("netsh.exe"),
            args: vec![
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={FIREWALL_RULE}"),
                "dir=in".into(),
                "action=allow".into(),
                "protocol=UDP".into(),
                format!("localport={RELAY_PORT}"),
                format!("program=\"{}\"", path_arg(&relay_exe)?),
                "enable=yes".into(),
                "profile=any".into(),
            ],
            raw: true,
        },
        allow_fail: false,
    });
    plan.push(tool(
        layout,
        "schtasks.exe",
        "Arrancar el relay",
        &["/Run", "/TN", RELAY_TASK],
        false,
    ));
    plan.push(Action::WaitForFile {
        path: cert.clone(),
        timeout_secs: RELAY_CERT_TIMEOUT_SECS,
    });

    // Accesos directos de awawa-host contra el relay local.
    let shortcut = |dir: &PathBuf| -> Result<Shortcut, String> {
        Ok(Shortcut {
            link: layout.shortcut(dir, HOST_SHORTCUT),
            target: host_exe.clone(),
            args: host_args(LOCAL_RELAY, &cert)?,
            workdir: layout.install_dir.clone(),
            description: "Recibir soporte remoto en este equipo".into(),
        })
    };
    plan.push(Action::CreateShortcut(shortcut(&layout.start_menu_dir)?));
    plan.push(Action::CreateShortcut(shortcut(&layout.public_desktop)?));
    if opts.autostart {
        plan.push(Action::CreateShortcut(shortcut(&layout.common_startup)?));
    } else {
        plan.push(Action::RemoveFile(
            layout.shortcut(&layout.common_startup, HOST_SHORTCUT),
        ));
    }

    if opts.unattended {
        plan.push(Action::Run {
            label: "Instalar el servicio desatendido",
            cmd: CommandSpec::new(
                layout.exe("awawa-service.exe"),
                &[
                    "install",
                    "--relay",
                    LOCAL_RELAY,
                    "--relay-pin",
                    &path_arg(&cert)?,
                ],
            ),
            allow_fail: false,
        });
        plan.push(Action::StartService);
        plan.push(Action::ConfigurePassword);
        plan.push(Action::RestartService);
        plan.push(Action::ReadServiceIdentity);
    }

    plan.push(Action::WriteConnectionFile {
        path: opts.connection_file.clone(),
        relay: opts.public_relay.clone(),
        pin: cert,
    });
    Ok(plan)
}

/// Rol Agente de soporte: awawa-operator + pin y clave del host importados + accesos directos.
pub fn operator_plan(layout: &Layout, opts: &OperatorOptions) -> Result<Vec<Action>, String> {
    let conn = &opts.connection;
    conn.validate()?;
    let exe = layout.exe(OPERATOR_EXE);
    let dir = layout.operator_conn_dir();
    let pin = dir.join("relay-cert.der");
    let key = dir.join("host-key.bin");
    let mut plan = vec![
        Action::CreateInstallDir(layout.install_dir.clone()),
        Action::Extract {
            name: OPERATOR_EXE,
            dest: exe.clone(),
        },
        Action::CreateDir(dir.clone()),
        Action::WriteFile {
            path: pin.clone(),
            bytes: conn.relay_pin.clone(),
            label: "pin del relay",
        },
    ];
    match &conn.host {
        Some(host) => plan.push(Action::WriteFile {
            path: key.clone(),
            bytes: host.key.to_vec(),
            label: "clave publica del host",
        }),
        None => plan.push(Action::RemoveFile(key.clone())),
    }
    plan.push(Action::ValidateProgramFiles(vec![
        layout.install_dir.clone(),
        exe.clone(),
        dir.clone(),
    ]));
    let args = operator_args(
        &conn.relay_addr,
        &pin,
        conn.host.as_ref().map(|_| key.as_path()),
    )?;
    for link_dir in [&layout.start_menu_dir, &layout.public_desktop] {
        plan.push(Action::CreateShortcut(Shortcut {
            link: layout.shortcut(link_dir, OPERATOR_SHORTCUT),
            target: exe.clone(),
            args: args.clone(),
            workdir: layout.install_dir.clone(),
            description: "Dar soporte remoto a otro equipo".into(),
        }));
    }
    Ok(plan)
}

/// Desinstalar: accesos directos, tarea del relay, servicio, regla de firewall, Program Files y, si no
/// se conservan, los datos de `%ProgramData%`.
pub fn uninstall_plan(layout: &Layout, opts: UninstallOptions) -> Vec<Action> {
    let mut plan = Vec::new();
    for (dir, name) in [
        (&layout.start_menu_dir, HOST_SHORTCUT),
        (&layout.public_desktop, HOST_SHORTCUT),
        (&layout.common_startup, HOST_SHORTCUT),
        (&layout.start_menu_dir, OPERATOR_SHORTCUT),
        (&layout.public_desktop, OPERATOR_SHORTCUT),
    ] {
        plan.push(Action::RemoveFile(layout.shortcut(dir, name)));
    }
    plan.push(Action::RemoveDirIfEmpty(layout.start_menu_dir.clone()));
    plan.push(stop_relay(layout));
    plan.push(tool(
        layout,
        "schtasks.exe",
        "Quitar la tarea del relay",
        &["/Delete", "/TN", RELAY_TASK, "/F"],
        true,
    ));
    plan.push(Action::RemoveService(layout.exe("awawa-service.exe")));
    plan.push(delete_firewall_rule(layout, true));
    plan.push(Action::RemoveDir(layout.install_dir.clone()));
    if !opts.keep_data {
        plan.push(Action::RemoveDir(layout.service_data_dir.clone()));
        plan.push(Action::RemoveDir(layout.relay_data_dir.clone()));
    }
    plan
}

/// Texto del plan numerado (para `--dry-run` y el registro).
pub fn render(plan: &[Action]) -> String {
    plan.iter()
        .enumerate()
        .map(|(i, a)| format!("{:>2}. {a}\n", i + 1))
        .collect()
}

/// Direccion del relay para el otro equipo a partir de una IPv4 o un nombre.
pub fn public_relay_addr(host: &str) -> Result<String, String> {
    let host = host.trim();
    let addr = if host.contains(':') && !host.starts_with('[') {
        host.to_owned()
    } else {
        format!("{host}:{RELAY_PORT}")
    };
    check_relay_addr(&addr)?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::HostIdentity;
    use crate::connection::tests::{sample_key, sample_pin};

    fn host_opts(unattended: bool, autostart: bool) -> HostOptions {
        HostOptions {
            unattended,
            autostart,
            public_relay: "192.168.1.20:4433".into(),
            connection_file: r"C:\Users\Prueba\Desktop\Awawa-conexion.rrs".into(),
        }
    }

    fn rendered(plan: &[Action]) -> String {
        render(plan)
    }

    #[test]
    fn host_sin_desatendido() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(false, false)).unwrap();
        let text = rendered(&plan);
        assert!(text.contains("Extraer awawa-host.exe"));
        assert!(text.contains("Extraer awawa-relay.exe"));
        assert!(!text.contains("Extraer awawa-service.exe"));
        assert!(text.contains(r"Borrar C:\Program Files\Awawa\awawa-service.exe"));
        assert!(!plan.contains(&Action::ConfigurePassword));
        assert!(!plan.contains(&Action::StartService));
        assert!(text.contains(
            r#"netsh.exe" advfirewall firewall add rule name=Awawa-Relay-UDP-4433 dir=in action=allow protocol=UDP localport=4433 program="C:\Program Files\Awawa\awawa-relay.exe" enable=yes profile=any"#
        ));
        assert!(text.contains(r#"schtasks.exe" /Create /TN Awawa\Relay /XML "C:\Program Files\Awawa\relay-task.xml" /F"#));
        // El XML se escribe despues de validar la carpeta de instalacion y se borra al final.
        let xml = layout.install_dir.join("relay-task.xml");
        let validate = plan
            .iter()
            .position(|a| matches!(a, Action::ValidateProgramFiles(_)))
            .unwrap();
        let write = plan
            .iter()
            .position(|a| matches!(a, Action::WriteFile { path, .. } if *path == xml))
            .unwrap();
        assert!(validate < write);
        assert!(plan.contains(&Action::RemoveFile(xml)));
        assert!(!text.contains(r"AppData\Local\Temp"));
        assert!(text.contains(r"Borrar C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Awawa - Este equipo.lnk"));
        // El relay arranca antes de esperar su certificado, y el archivo de conexion es lo ultimo.
        let run = plan
            .iter()
            .position(|a| {
                matches!(
                    a,
                    Action::Run {
                        label: "Arrancar el relay",
                        ..
                    }
                )
            })
            .unwrap();
        let wait = plan
            .iter()
            .position(|a| matches!(a, Action::WaitForFile { .. }))
            .unwrap();
        assert!(run < wait);
        assert!(
            matches!(plan.last(), Some(Action::WriteConnectionFile { relay, .. }) if relay == "192.168.1.20:4433")
        );
    }

    #[test]
    fn host_con_desatendido_y_autoarranque() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(true, true)).unwrap();
        let text = rendered(&plan);
        for exe in SERVICE_EXES {
            assert!(text.contains(&format!("Extraer {exe}")), "{exe}");
        }
        assert!(text.contains(r#"awawa-service.exe" install --relay 127.0.0.1:4433 --relay-pin C:\ProgramData\Awawa-Relay\relay-cert.der"#));
        let pos = |a: &Action| plan.iter().position(|x| x == a).unwrap();
        assert!(pos(&Action::StartService) < pos(&Action::ConfigurePassword));
        assert!(pos(&Action::ConfigurePassword) < pos(&Action::RestartService));
        assert!(pos(&Action::RestartService) < pos(&Action::ReadServiceIdentity));
        let startup = plan.iter().any(|a| matches!(a, Action::CreateShortcut(s) if s.link.starts_with(&layout.common_startup)));
        assert!(startup);
        // Los binarios del servicio se validan en Program Files antes de instalarlo.
        let validate = plan
            .iter()
            .find_map(|a| match a {
                Action::ValidateProgramFiles(p) => Some(p.clone()),
                _ => None,
            })
            .unwrap();
        assert!(validate.contains(&layout.exe("awawa-service.exe")));
    }

    #[test]
    fn accesos_directos_del_host_usan_el_relay_local_y_el_pin() {
        let layout = Layout::for_tests();
        let plan = host_plan(&layout, &host_opts(false, false)).unwrap();
        let shortcuts: Vec<&Shortcut> = plan
            .iter()
            .filter_map(|a| match a {
                Action::CreateShortcut(s) => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(shortcuts.len(), 2);
        for s in shortcuts {
            assert_eq!(s.target, layout.exe("awawa-host.exe"));
            assert_eq!(
                s.args,
                r"--relay 127.0.0.1:4433 --relay-pin C:\ProgramData\Awawa-Relay\relay-cert.der"
            );
        }
    }

    #[test]
    fn host_rechaza_direccion_o_destino_invalidos() {
        let layout = Layout::for_tests();
        let mut opts = host_opts(false, false);
        opts.public_relay = "1.2.3.4:4433 & calc".into();
        assert!(host_plan(&layout, &opts).is_err());
        let mut opts = host_opts(false, false);
        opts.connection_file = "relativo.rrs".into();
        assert!(host_plan(&layout, &opts).is_err());
    }

    #[test]
    fn xml_de_la_tarea() {
        let layout = Layout::for_tests();
        let xml = relay_task_xml(&layout).unwrap();
        assert!(xml.contains("<UserId>S-1-5-19</UserId>"));
        assert!(xml.contains("<BootTrigger>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains(r"<Command>C:\Program Files\Awawa\awawa-relay.exe</Command>"));
        assert!(xml.contains(r#"<Arguments>--dir "C:\ProgramData\Awawa-Relay"</Arguments>"#));
        let bytes = utf16_with_bom(&xml);
        assert_eq!(&bytes[..4], &[0xFF, 0xFE, b'<', 0]);
    }

    #[test]
    fn operador_con_y_sin_clave_del_host() {
        let layout = Layout::for_tests();
        let mut connection = ConnectionInfo {
            relay_addr: "192.168.1.20:4433".into(),
            relay_pin: sample_pin(),
            host: Some(HostIdentity {
                id: Some(123_456_789),
                key: sample_key(),
            }),
        };
        let plan = operator_plan(
            &layout,
            &OperatorOptions {
                connection: connection.clone(),
            },
        )
        .unwrap();
        let text = rendered(&plan);
        assert!(text.contains("Extraer awawa-operator.exe"));
        assert!(text.contains(r"Escribir clave publica del host C:\Program Files\Awawa\conexion\host-key.bin (32 bytes"));
        assert!(text.contains(
            r"Escribir pin del relay C:\Program Files\Awawa\conexion\relay-cert.der (203 bytes"
        ));
        let args: Vec<&str> = plan
            .iter()
            .filter_map(|a| match a {
                Action::CreateShortcut(s) => Some(s.args.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(args.len(), 2);
        assert!(args.iter().all(|a| *a == "--relay 192.168.1.20:4433 --relay-pin \"C:\\Program Files\\Awawa\\conexion\\relay-cert.der\" --host-key \"C:\\Program Files\\Awawa\\conexion\\host-key.bin\""));

        connection.host = None;
        let plan = operator_plan(
            &layout,
            &OperatorOptions {
                connection: connection.clone(),
            },
        )
        .unwrap();
        let text = rendered(&plan);
        assert!(!text.contains("--host-key"));
        assert!(text.contains(r"Borrar C:\Program Files\Awawa\conexion\host-key.bin"));

        connection.relay_pin = vec![];
        assert!(operator_plan(&layout, &OperatorOptions { connection }).is_err());
    }

    #[test]
    fn desinstalar_conservando_o_borrando_datos() {
        let layout = Layout::for_tests();
        let keep = uninstall_plan(&layout, UninstallOptions { keep_data: true });
        let text = rendered(&keep);
        assert!(text.contains(r#"schtasks.exe" /Delete /TN Awawa\Relay /F"#));
        let remove_service = Action::RemoveService(layout.exe("awawa-service.exe"));
        assert!(keep.contains(&remove_service));
        assert!(text.contains("delete rule name=Awawa-Relay-UDP-4433"));
        assert!(keep.contains(&Action::RemoveDir(layout.install_dir.clone())));
        assert!(!keep.contains(&Action::RemoveDir(layout.service_data_dir.clone())));
        assert!(!keep.contains(&Action::RemoveDir(layout.relay_data_dir.clone())));
        assert_eq!(keep.iter().filter(|a| matches!(a, Action::RemoveFile(p) if p.extension().is_some_and(|e| e == "lnk"))).count(), 5);
        // El servicio se quita antes de borrar sus binarios.
        let svc = keep.iter().position(|a| *a == remove_service).unwrap();
        let dir = keep
            .iter()
            .position(|a| *a == Action::RemoveDir(layout.install_dir.clone()))
            .unwrap();
        assert!(svc < dir);

        let purge = uninstall_plan(&layout, UninstallOptions { keep_data: false });
        assert!(purge.contains(&Action::RemoveDir(layout.service_data_dir.clone())));
        assert!(purge.contains(&Action::RemoveDir(layout.relay_data_dir.clone())));
    }

    #[test]
    fn direccion_publica_del_relay() {
        assert_eq!(
            public_relay_addr("192.168.1.20").unwrap(),
            "192.168.1.20:4433"
        );
        assert_eq!(
            public_relay_addr(" 10.0.0.1:5000 ").unwrap(),
            "10.0.0.1:5000"
        );
        assert_eq!(public_relay_addr("equipo.lan").unwrap(), "equipo.lan:4433");
        assert!(public_relay_addr("").is_err());
        assert!(public_relay_addr("1.2.3.4 x").is_err());
    }
}
