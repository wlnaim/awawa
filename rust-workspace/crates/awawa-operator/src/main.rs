//! Agente de Soporte (operador): formulario, espera de aprobacion y visor remoto.
//!
//! Uso:
//!
//! ```text
//! awawa-operator --relay <host:puerto> --relay-pin <relay-cert.der> [--host-key <archivo>]
//! ```
//!
//! - `--relay`: direccion del relay (por ejemplo `relay.example.org:4433` o `127.0.0.1:4433`).
//! - `--relay-pin`: archivo con el certificado DER del relay (`relay-cert.der`, el que genera
//!   `awawa-relay` en su carpeta). Solo se acepta ese certificado exacto.
//! - `--host-key` (opcional): clave publica Ed25519 del servicio del equipo desatendido, exportada por
//!   `awawa-admin status`: un archivo de exactamente 32 bytes crudos. Habilita el modo "Equipo
//!   desatendido" del formulario, que solo se conecta si el equipo prueba esa clave (no hay TOFU) y
//!   muestra su huella (8 primeros bytes de SHA-256, `xxxx-xxxx-xxxx-xxxx`) para compararla.
//!
//! El ID y la contrasena se escriben en el formulario; la contrasena solo entra al handshake
//! SPAKE2 y nunca viaja ni llega al relay.

mod app;
mod countdown;
mod form;
mod frame;
mod input_capture;
mod keymap;
mod net;
mod relay_transport;
mod session;
mod splash;
// Transporte simulado: ya no es modo de producto; se conserva con sus pruebas.
#[cfg(test)]
#[allow(dead_code)]
mod sim;
mod stats;
mod transport;
mod viewport;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use awawa_protocol::unattended_channel::VerifyingKey;
use awawa_relay::RelayPin;

use relay_transport::RelayTransport;
use transport::{OperatorTransport, TransportFactory};

const USAGE: &str =
    "Uso: awawa-operator --relay <host:puerto> --relay-pin <relay-cert.der> [--host-key <archivo>]";

/// Argumentos de linea de comandos ya separados (sin resolver ni leer archivos).
#[derive(Debug, PartialEq, Eq)]
struct RelayArgs {
    relay: String,
    pin_file: PathBuf,
    host_key_file: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<RelayArgs, String> {
    let (mut relay, mut pin_file, mut host_key_file) = (None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("Falta el valor de {flag}"))?;
        match flag.as_str() {
            "--relay" => relay = Some(value.clone()),
            "--relay-pin" => pin_file = Some(PathBuf::from(value)),
            "--host-key" => host_key_file = Some(PathBuf::from(value)),
            other => return Err(format!("Argumento desconocido: {other}")),
        }
    }
    match (relay, pin_file) {
        (Some(relay), Some(pin_file)) => Ok(RelayArgs {
            relay,
            pin_file,
            host_key_file,
        }),
        _ => Err("Faltan --relay y --relay-pin".to_string()),
    }
}

fn resolve(args: &RelayArgs) -> Result<(SocketAddr, RelayPin), String> {
    let addr = args
        .relay
        .to_socket_addrs()
        .map_err(|e| format!("Direccion del relay invalida ({}): {e}", args.relay))?
        .next()
        .ok_or_else(|| format!("Direccion del relay sin resolver: {}", args.relay))?;
    let der = std::fs::read(&args.pin_file)
        .map_err(|e| format!("No se pudo leer {}: {e}", args.pin_file.display()))?;
    if der.is_empty() {
        return Err(format!("{} esta vacio", args.pin_file.display()));
    }
    Ok((addr, RelayPin::from_cert_der(der)))
}

/// Lee y valida la clave publica del servicio (`--host-key`).
fn load_host_key(path: &Path) -> Result<VerifyingKey, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("No se pudo leer {}: {e}", path.display()))?;
    form::parse_host_key(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let loaded = parse_args(&args).and_then(|a| {
        let (addr, pin) = resolve(&a)?;
        let host_key = a.host_key_file.as_deref().map(load_host_key).transpose()?;
        Ok((addr, pin, host_key))
    });
    let (relay_addr, pin, host_key) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        // Ctrl+C/V/X, Ctrl+Insert, Shift+Insert y Shift+Supr deben llegar al visor como teclas
        // fisicas; el formulario obtiene copiar/pegar con `RequestCopy/Paste` (ver `app.rs`).
        clipboard_shortcuts: false,
        viewport: egui::ViewportBuilder::default()
            .with_title("Awawa - Agente de Soporte")
            .with_icon(splash::window_icon())
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "awawa-operator",
        options,
        Box::new(move |cc| {
            let fingerprint = host_key.as_ref().map(form::host_key_fingerprint);
            let factory: TransportFactory = Box::new(move |params, ctx| {
                Box::new(RelayTransport::spawn(
                    relay_addr,
                    pin.clone(),
                    host_key,
                    params,
                    ctx,
                )) as Box<dyn OperatorTransport>
            });
            Ok(Box::new(
                app::OperatorApp::new(cc.egui_ctx.clone(), factory)
                    .with_host_key_fingerprint(fingerprint)
                    .with_splash(),
            ))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error de interfaz: {e}");
            ExitCode::FAILURE
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
    fn relay_and_pin_are_required() {
        assert_eq!(
            parse_args(&args(&[
                "--relay-pin",
                "c.der",
                "--relay",
                "127.0.0.1:4433"
            ])),
            Ok(RelayArgs {
                relay: "127.0.0.1:4433".into(),
                pin_file: PathBuf::from("c.der"),
                host_key_file: None,
            })
        );
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&args(&["--relay", "127.0.0.1:4433"])).is_err());
    }

    #[test]
    fn host_key_is_optional_and_needs_a_value() {
        let parsed = parse_args(&args(&[
            "--relay",
            "127.0.0.1:4433",
            "--host-key",
            "svc.key",
            "--relay-pin",
            "c.der",
        ]))
        .unwrap();
        assert_eq!(parsed.host_key_file, Some(PathBuf::from("svc.key")));
        assert!(
            parse_args(&args(&[
                "--relay",
                "127.0.0.1:4433",
                "--relay-pin",
                "c.der",
                "--host-key"
            ]))
            .is_err()
        );
        // `--host-key` solo no basta: siguen siendo obligatorios --relay y --relay-pin.
        assert!(parse_args(&args(&["--host-key", "svc.key"])).is_err());
    }

    fn temp_key_file(name: &str, bytes: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("awawa-operator-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn host_key_file_must_be_32_valid_bytes() {
        let good = temp_key_file(
            "good.key",
            &[
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ],
        );
        assert!(load_host_key(&good).is_ok());
        let short = temp_key_file("short.key", &[7u8; 31]);
        assert!(load_host_key(&short).unwrap_err().contains("32 bytes"));
        let long = temp_key_file("long.key", &[7u8; 33]);
        assert!(load_host_key(&long).is_err());
        // y = 2 no corresponde a ningun punto de la curva.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        let off_curve = temp_key_file("bad.key", &bad);
        assert!(load_host_key(&off_curve).is_err());
        let missing = std::env::temp_dir().join("awawa-operator-no-existe.key");
        assert!(
            load_host_key(&missing)
                .unwrap_err()
                .contains("No se pudo leer")
        );
        for p in [good, short, long, off_curve] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn simulation_is_no_longer_a_product_mode() {
        assert!(parse_args(&args(&["--sim", "approve"])).is_err());
        assert!(parse_args(&args(&["--sim"])).is_err());
    }

    #[test]
    fn unreadable_pin_file_and_bad_address_are_reported() {
        let missing = RelayArgs {
            relay: "127.0.0.1:4433".into(),
            pin_file: PathBuf::from("no-existe-relay-cert.der"),
            host_key_file: None,
        };
        assert!(resolve(&missing).unwrap_err().contains("No se pudo leer"));
        let bad = RelayArgs {
            relay: "sin-puerto".into(),
            pin_file: PathBuf::from("x"),
            host_key_file: None,
        };
        assert!(resolve(&bad).is_err());
    }
}
