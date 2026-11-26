//! `Awawa-Setup`: instalador grafico de Awawa.
//!
//! Roles:
//! - **Equipo que recibe soporte (Host)**: `awawa-host` + `awawa-relay` local (tarea al iniciar el
//!   sistema como LOCAL SERVICE, UDP 4433 abierto solo para el relay), accesos directos y, con la
//!   casilla "Acceso desatendido", el servicio con su contrasena. Genera el archivo de conexion
//!   `.rrs` para el otro equipo.
//! - **Agente de soporte (operador)**: `awawa-operator` + el pin del relay y la clave del host
//!   importados del `.rrs` (o a mano).
//! - **Mantenimiento**: reconfigurar (volver a elegir rol) o desinstalar.
//!
//! Sin argumentos abre la interfaz. `--dry-run` imprime el plan de acciones sin ejecutar nada:
//!
//! ```text
//! awawa-installer --dry-run --host [--unattended] [--autostart] [--ip <IPv4|nombre>] [--out <archivo.rrs>]
//! awawa-installer --dry-run --operator --connection <archivo.rrs>
//! awawa-installer --dry-run --operator --relay <ip:puerto> --relay-pin <relay-cert.der> [--host-key <archivo>]
//! awawa-installer --dry-run --uninstall [--remove-data]
//! ```
//!
//! La contrasena desatendida solo se pide en la interfaz: nunca por argumentos, nunca en disco ni en
//! el registro del instalador.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod app;
mod cmdline;
mod connection;
mod ipv4;
mod paths;
mod payload;
mod plan;
mod real;
mod splash;
mod system;
mod win32;

use std::path::PathBuf;
use std::process::ExitCode;

use connection::ConnectionInfo;
use paths::Layout;
use plan::{HostOptions, OperatorOptions, UninstallOptions};

const USAGE: &str = "uso: awawa-installer [--dry-run (--host [--unattended] [--autostart] [--ip <IPv4|nombre>] [--out <archivo.rrs>] | --operator (--connection <archivo.rrs> | --relay <ip:puerto> --relay-pin <relay-cert.der> [--host-key <archivo>]) | --uninstall [--remove-data])]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleArgs {
    Host {
        unattended: bool,
        autostart: bool,
        ip: Option<String>,
        out: Option<PathBuf>,
    },
    Operator {
        connection: Option<PathBuf>,
        relay: Option<String>,
        pin: Option<PathBuf>,
        host_key: Option<PathBuf>,
    },
    Uninstall {
        remove_data: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Cli {
    Gui,
    DryRun(RoleArgs),
}

fn parse_cli(args: &[String]) -> Result<Cli, String> {
    if args.is_empty() {
        return Ok(Cli::Gui);
    }
    let mut it = args.iter();
    if it.next().map(String::as_str) != Some("--dry-run") {
        return Err("solo se admite --dry-run como primer argumento".into());
    }
    let mut role = match it.next().map(String::as_str) {
        Some("--host") => RoleArgs::Host {
            unattended: false,
            autostart: false,
            ip: None,
            out: None,
        },
        Some("--operator") => RoleArgs::Operator {
            connection: None,
            relay: None,
            pin: None,
            host_key: None,
        },
        Some("--uninstall") => RoleArgs::Uninstall { remove_data: false },
        _ => return Err("--dry-run necesita --host, --operator o --uninstall".into()),
    };
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("falta el valor de {flag}"))
        };
        match (&mut role, flag.as_str()) {
            (RoleArgs::Host { unattended, .. }, "--unattended") => *unattended = true,
            (RoleArgs::Host { autostart, .. }, "--autostart") => *autostart = true,
            (RoleArgs::Host { ip, .. }, "--ip") => *ip = Some(value()?),
            (RoleArgs::Host { out, .. }, "--out") => *out = Some(value()?.into()),
            (RoleArgs::Operator { connection, .. }, "--connection") => {
                *connection = Some(value()?.into());
            }
            (RoleArgs::Operator { relay, .. }, "--relay") => *relay = Some(value()?),
            (RoleArgs::Operator { pin, .. }, "--relay-pin") => *pin = Some(value()?.into()),
            (RoleArgs::Operator { host_key, .. }, "--host-key") => {
                *host_key = Some(value()?.into());
            }
            (RoleArgs::Uninstall { remove_data }, "--remove-data") => *remove_data = true,
            (_, other) => return Err(format!("opcion no valida para este rol: {other}")),
        }
    }
    if let RoleArgs::Operator {
        connection, relay, ..
    } = &role
        && connection.is_some() == relay.is_some()
    {
        return Err("--operator necesita --connection o bien --relay y --relay-pin".into());
    }
    Ok(Cli::DryRun(role))
}

/// Datos de conexion del rol operador desde la linea de comandos (solo lectura de archivos).
fn operator_connection(role: &RoleArgs) -> Result<ConnectionInfo, String> {
    match role {
        RoleArgs::Operator {
            connection: Some(file),
            ..
        } => connection::load_file(file),
        RoleArgs::Operator {
            relay: Some(relay),
            pin: Some(pin),
            host_key,
            ..
        } => connection::from_files(relay, pin, host_key.as_deref()),
        RoleArgs::Operator { .. } => Err("--relay necesita --relay-pin".into()),
        _ => Err("no es el rol operador".into()),
    }
}

/// Texto completo del `--dry-run`: rutas, plan numerado y notas. No ejecuta nada.
fn dry_run_text(role: &RoleArgs, layout: &Layout) -> Result<String, String> {
    let mut out = format!(
        "Awawa-Setup {} --dry-run: plan de acciones (NO se ejecuta nada)\n",
        env!("CARGO_PKG_VERSION")
    );
    out.push_str(&format!(
        "Carga embebida: {}\n",
        if payload::is_present() {
            payload::names().join(", ")
        } else {
            "ninguna (instalador de desarrollo: no puede instalar)".into()
        }
    ));
    let plan = match role {
        RoleArgs::Host {
            unattended,
            autostart,
            ip,
            out: file,
        } => {
            let host = match ip {
                Some(ip) => ip.clone(),
                None => ipv4::local_ipv4()
                    .first()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "127.0.0.1".into()),
            };
            let opts = HostOptions {
                unattended: *unattended,
                autostart: *autostart,
                public_relay: plan::public_relay_addr(&host)?,
                connection_file: file
                    .clone()
                    .unwrap_or_else(|| layout.default_connection_file()),
            };
            out.push_str(&format!(
                "Rol: Equipo que recibe soporte (Host). Desatendido: {}. Al iniciar sesion: {}.\nIPv4 detectadas: {}\n",
                si_no(opts.unattended),
                si_no(opts.autostart),
                ipv4::local_ipv4()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            if opts.unattended {
                out.push_str("La contrasena desatendida se pide en la interfaz (12-128 caracteres, con confirmacion); no aparece en el plan.\n");
            }
            plan::host_plan(layout, &opts)?
        }
        RoleArgs::Operator { .. } => {
            let connection = operator_connection(role)?;
            out.push_str(&format!(
                "Rol: Agente de soporte (operador). Relay {} | huella del pin {}\n",
                connection.relay_addr,
                connection::pin_fingerprint(&connection.relay_pin)
            ));
            if let Some(host) = &connection.host {
                out.push_str(&format!(
                    "Equipo desatendido: ID {} | huella de la clave {}\n",
                    host.id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "(sin ID)".into()),
                    connection::host_key_fingerprint(&host.key)
                ));
            }
            plan::operator_plan(layout, &OperatorOptions { connection })?
        }
        RoleArgs::Uninstall { remove_data } => {
            out.push_str(&format!(
                "Rol: Desinstalar. Conservar datos de ProgramData: {}\n",
                si_no(!remove_data)
            ));
            plan::uninstall_plan(
                layout,
                UninstallOptions {
                    keep_data: !remove_data,
                },
            )
        }
    };
    out.push('\n');
    out.push_str(&plan::render(&plan));
    Ok(out)
}

fn si_no(value: bool) -> &'static str {
    if value { "si" } else { "no" }
}

/// Un binario de subsistema Windows no tiene consola: si la salida no esta redirigida se adjunta a la
/// del proceso padre para que `--dry-run` se vea en la terminal.
fn attach_parent_console() {
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(n: u32) -> *mut core::ffi::c_void;
        fn AttachConsole(pid: u32) -> i32;
    }
    // SAFETY: constantes documentadas; sin punteros de entrada.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle as isize == -1 {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

fn main() -> ExitCode {
    // Primera instruccion: las cargas dinamicas (wgpu: d3d12, dxgi, d3dcompiler_47, vulkan-1...) y las
    // diferidas de build.rs (shell32, opengl32, user32...) solo buscan en System32, nunca en la carpeta
    // del Setup. Ninguna funcion de una DLL diferida debe llamarse antes de esta linea.
    win32::restrict_dll_search_to_system32();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(&args) {
        Ok(cli) => cli,
        Err(e) => {
            attach_parent_console();
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match cli {
        Cli::Gui => match app::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Cli::DryRun(role) => {
            attach_parent_console();
            match Layout::detect().and_then(|layout| dry_run_text(&role, &layout)) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sin_argumentos_abre_la_interfaz() {
        assert_eq!(parse_cli(&[]), Ok(Cli::Gui));
    }

    #[test]
    fn analiza_los_roles_del_dry_run() {
        assert_eq!(
            parse_cli(&args(&[
                "--dry-run",
                "--host",
                "--unattended",
                "--ip",
                "10.0.0.2"
            ])),
            Ok(Cli::DryRun(RoleArgs::Host {
                unattended: true,
                autostart: false,
                ip: Some("10.0.0.2".into()),
                out: None
            }))
        );
        assert_eq!(
            parse_cli(&args(&["--dry-run", "--uninstall", "--remove-data"])),
            Ok(Cli::DryRun(RoleArgs::Uninstall { remove_data: true }))
        );
        assert!(parse_cli(&args(&["--dry-run", "--operator", "--connection", "a.rrs"])).is_ok());
        assert!(parse_cli(&args(&["--dry-run", "--operator"])).is_err());
        assert!(
            parse_cli(&args(&[
                "--dry-run",
                "--operator",
                "--connection",
                "a",
                "--relay",
                "b"
            ]))
            .is_err()
        );
        assert!(parse_cli(&args(&["--dry-run"])).is_err());
        assert!(parse_cli(&args(&["--host"])).is_err());
        assert!(parse_cli(&args(&["--dry-run", "--host", "--remove-data"])).is_err());
        assert!(parse_cli(&args(&["--dry-run", "--host", "--ip"])).is_err());
        // La contrasena nunca se acepta por argumentos.
        assert!(parse_cli(&args(&["--dry-run", "--host", "--password", "x"])).is_err());
    }

    #[test]
    fn dry_run_del_host_y_de_desinstalar() {
        let layout = Layout::for_tests();
        let text = dry_run_text(
            &RoleArgs::Host {
                unattended: true,
                autostart: true,
                ip: Some("192.168.1.20".into()),
                out: None,
            },
            &layout,
        )
        .unwrap();
        assert!(text.contains("NO se ejecuta nada"));
        assert!(text.contains("relay=192.168.1.20:4433"));
        assert!(text.contains(r"C:\Users\Prueba\Desktop\Awawa-conexion.rrs"));
        let text = dry_run_text(&RoleArgs::Uninstall { remove_data: false }, &layout).unwrap();
        assert!(text.contains("Conservar datos de ProgramData: si"));
    }
}
