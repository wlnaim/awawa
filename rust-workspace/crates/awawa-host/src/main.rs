//! Cliente Receptor de soporte remoto bajo demanda (GUI).
//!
//! Genera ID y contrasena efimeros, los registra en el relay, muestra el modal de consentimiento
//! local obligatorio y, con la sesion activa, un banner siempre visible con el kill-switch.
//!
//! Uso:
//!
//! ```text
//! awawa-host --relay <host:puerto> --relay-pin <relay-cert.der>
//! ```
//!
//! - `--relay`: direccion del relay (por ejemplo `relay.example.org:4433` o `127.0.0.1:4433`).
//! - `--relay-pin`: archivo con el certificado DER del relay (`relay-cert.der`, el que genera
//!   `awawa-relay` en su carpeta). Solo se acepta ese certificado exacto.
//!
//! Sin esos argumentos (o si no son validos) el host no se conecta y lo indica en la ventana.

#![cfg_attr(not(test), windows_subsystem = "windows")]

mod app;
mod backends;
mod banner_geometry;
mod consent_timer;
mod controller;
mod display_name;
mod gate;
mod net;
#[cfg(test)]
mod net_tests;
mod revocation;
mod session_clock;
mod splash;
mod transport;
mod win;
mod window_registry;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;

use awawa_relay::RelayPin;
use capture_win::ConsentGatedCapturer;
use input_win::{ProtectedWindowGuard, windows_input_dispatcher};

use crate::app::HostApp;
use crate::backends::{CaptureSource, probe_input_desktop, protected_window_focused};
use crate::gate::SessionGate;
use crate::net::{HostNet, HostNetConfig, VideoSource, VideoSourceFactory};
use crate::transport::{DisconnectedTransport, HostTransport, RelayTransport};

const USAGE: &str = "Uso: awawa-host --relay <host:puerto> --relay-pin <relay-cert.der>";

/// Argumentos de linea de comandos ya separados (sin resolver ni leer archivos).
#[derive(Debug, PartialEq, Eq)]
struct RelayArgs {
    relay: String,
    pin_file: PathBuf,
}

fn parse_args(args: &[String]) -> Result<RelayArgs, String> {
    let (mut relay, mut pin_file) = (None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("falta el valor de {flag}"))?;
        match flag.as_str() {
            "--relay" => relay = Some(value.clone()),
            "--relay-pin" => pin_file = Some(PathBuf::from(value)),
            other => return Err(format!("argumento desconocido: {other}")),
        }
    }
    match (relay, pin_file) {
        (Some(relay), Some(pin_file)) => Ok(RelayArgs { relay, pin_file }),
        _ => Err("faltan --relay y --relay-pin".to_string()),
    }
}

fn resolve(args: &RelayArgs) -> Result<(SocketAddr, RelayPin), String> {
    let addr = args
        .relay
        .to_socket_addrs()
        .map_err(|e| format!("direccion del relay invalida ({}): {e}", args.relay))?
        .next()
        .ok_or_else(|| format!("direccion del relay sin resolver: {}", args.relay))?;
    let der = std::fs::read(&args.pin_file)
        .map_err(|e| format!("no se pudo leer {}: {e}", args.pin_file.display()))?;
    if der.is_empty() {
        return Err(format!("{} esta vacio", args.pin_file.display()));
    }
    Ok((addr, RelayPin::from_cert_der(der)))
}

/// Quita los atajos de teclado propios de egui: Ctrl+-/+/0 encogerian el boton de revocar y
/// Ctrl+Q cerraria el host desde el teclado.
fn disable_builtin_shortcuts(ctx: &egui::Context) {
    ctx.options_mut(|o| {
        o.zoom_with_keyboard = false;
        o.quit_shortcuts.clear();
    });
}

fn connect_relay(
    args: &[String],
    gate: &SessionGate,
    guard: &ProtectedWindowGuard,
    ctx: egui::Context,
) -> Result<Box<dyn HostTransport>, String> {
    let (relay_addr, pin) = resolve(&parse_args(args)?)?;
    let video: VideoSourceFactory = Arc::new(|| {
        let capturer = ConsentGatedCapturer::open_windows().map_err(|e| format!("{e:?}"))?;
        let source = CaptureSource::new(capturer, probe_input_desktop)?;
        Ok(Box::new(source) as Box<dyn VideoSource>)
    });
    let focus_guard = guard.clone();
    let net = HostNet::start(HostNetConfig {
        relay_addr,
        pin,
        gate: gate.clone(),
        video,
        keyboard_blocked: Arc::new(move || protected_window_focused(&focus_guard)),
        wake: Arc::new(move || ctx.request_repaint()),
    })?;
    Ok(Box::new(RelayTransport::new(net)))
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let guard = ProtectedWindowGuard::new();
    // Unica via de inyeccion real: el despachador con consentimiento, guardia y heartbeat.
    let gate = SessionGate::new(Box::new(windows_input_dispatcher(guard.clone())));

    let options = eframe::NativeOptions {
        viewport: app::main_viewport(),
        ..Default::default()
    };
    eframe::run_native(
        "Awawa - Este equipo",
        options,
        Box::new(move |cc| {
            disable_builtin_shortcuts(&cc.egui_ctx);
            let (transport, notice) = match connect_relay(&args, &gate, &guard, cc.egui_ctx.clone())
            {
                Ok(transport) => (transport, None),
                Err(e) => (
                    Box::new(DisconnectedTransport::default()) as Box<dyn HostTransport>,
                    Some(format!("{e}. {USAGE}")),
                ),
            };
            Ok(Box::new(HostApp::new(transport, gate, guard, notice)))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn builtin_zoom_and_quit_shortcuts_are_disabled() {
        let ctx = egui::Context::default();
        assert!(ctx.options(|o| o.zoom_with_keyboard && !o.quit_shortcuts.is_empty()));
        disable_builtin_shortcuts(&ctx);
        assert!(ctx.options(|o| !o.zoom_with_keyboard && o.quit_shortcuts.is_empty()));
    }

    #[test]
    fn relay_and_pin_are_required_and_simulation_is_gone() {
        assert_eq!(
            parse_args(&args(&[
                "--relay",
                "127.0.0.1:4433",
                "--relay-pin",
                "c.der"
            ])),
            Ok(RelayArgs {
                relay: "127.0.0.1:4433".into(),
                pin_file: PathBuf::from("c.der"),
            })
        );
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&args(&["--relay", "127.0.0.1:4433"])).is_err());
        assert!(parse_args(&args(&["--simulate"])).is_err());
    }

    #[test]
    fn unreadable_pin_file_is_reported() {
        let parsed = RelayArgs {
            relay: "127.0.0.1:4433".into(),
            pin_file: PathBuf::from("no-existe-relay-cert.der"),
        };
        assert!(resolve(&parsed).unwrap_err().contains("no se pudo leer"));
    }
}
