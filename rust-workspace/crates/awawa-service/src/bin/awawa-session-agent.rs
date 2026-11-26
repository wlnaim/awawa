//! Agente de sesion del acceso desatendido. Lo lanza el servicio (SYSTEM) con el token del usuario
//! de la sesion autorizada en `winsta0\default`:
//!
//! `awawa-session-agent --pipe \\.\pipe\Awawa.agent.<32 hex>`
//!
//! Abre la pipe del servicio (`GENERIC_READ | FILE_WRITE_DATA`), espera `Start` y solo entonces
//! activa la compuerta con `ApprovedActiveSession::for_session_agent`. Captura con
//! `ConsentGatedCapturer::open_windows()` e inyecta con `windows_input_dispatcher(guard)`, siempre
//! detras de la `SessionGate` del host (escritorio seguro, heartbeat, ventanas protegidas y
//! liberacion de teclas). Muestra el banner con el kill-switch mientras vive.
//!
//! Sin `--pipe` valido, o si la pipe no abre, sale sin capturar ni mostrar nada (falla cerrado).
//! `--once` hace un solo sondeo del escritorio de entrada e imprime el resultado (diagnostico).

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("awawa-session-agent solo esta disponible en Windows");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/backends.rs"]
#[allow(dead_code)]
mod backends;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/banner_geometry.rs"]
#[allow(dead_code)]
mod banner_geometry;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/gate.rs"]
#[allow(dead_code)]
mod gate;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/net.rs"]
#[allow(dead_code)]
mod net;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/session_clock.rs"]
#[allow(dead_code)]
mod session_clock;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/win.rs"]
#[allow(dead_code)]
mod win;
#[cfg(target_os = "windows")]
#[path = "../../../awawa-host/src/window_registry.rs"]
#[allow(dead_code)]
mod window_registry;

#[cfg(target_os = "windows")]
#[path = "awawa-session-agent/agent.rs"]
mod agent;
#[cfg(target_os = "windows")]
#[path = "awawa-session-agent/banner.rs"]
mod banner;

#[cfg(target_os = "windows")]
fn main() {
    use std::sync::{Arc, Mutex};

    use awawa_protocol::DesktopSessionMonitor;
    use awawa_service::input_desktop::probe_input_desktop;
    use capture_win::ConsentGatedCapturer;
    use input_win::{ProtectedWindowGuard, windows_input_dispatcher};

    use crate::agent::{AgentConfig, BannerInfo, KillSwitch, LocalStop, open_service_pipe};
    use crate::backends::{CaptureSource, protected_window_focused};
    use crate::gate::SessionGate;
    use crate::net::{VideoSource, VideoSourceFactory};

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--once") {
        let first = probe_input_desktop();
        let monitor = DesktopSessionMonitor::new(first);
        println!(
            "input_desktop={first:?} state={:?} capture_allowed={} input_allowed={}",
            monitor.state(),
            monitor.capture_allowed(),
            monitor.input_allowed()
        );
        return;
    }
    let pipe_name = match args.as_slice() {
        [flag, name] if flag == "--pipe" => name.clone(),
        _ => {
            eprintln!("uso: awawa-session-agent --pipe <nombre> (lo lanza el servicio)");
            std::process::exit(2);
        }
    };
    let pipe = match open_service_pipe(&pipe_name) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("awawa-session-agent: no se pudo abrir la pipe del servicio: {e}");
            std::process::exit(3);
        }
    };

    let guard = ProtectedWindowGuard::new();
    // Unica via de inyeccion real: el despachador con consentimiento, guardia y heartbeat.
    let gate = SessionGate::new(Box::new(windows_input_dispatcher(guard.clone())));
    let (kill, local_stop) = KillSwitch::new(gate.clone());
    // La sesion solo se activa cuando el banner esta pintado con el atajo global armado.
    let (ui_ready_tx, ui_ready) = tokio::sync::watch::channel(false);
    let info = Arc::new(Mutex::new(BannerInfo::default()));
    let video: VideoSourceFactory = Arc::new(|| {
        let capturer = ConsentGatedCapturer::open_windows().map_err(|e| format!("{e:?}"))?;
        let source = CaptureSource::new(capturer, crate::backends::probe_input_desktop)?;
        Ok(Box::new(source) as Box<dyn VideoSource>)
    });
    let focus_guard = guard.clone();
    let config = AgentConfig {
        gate: gate.clone(),
        video,
        keyboard_blocked: Arc::new(move || protected_window_focused(&focus_guard)),
        banner: info.clone(),
        local_stop,
        ui_ready,
        ui_ready_timeout: agent::UI_READY_TIMEOUT,
    };

    // La pipe y la sesion viven en su propio hilo: al terminar, el proceso sale sin esperar a la UI.
    let spawned = std::thread::Builder::new()
        .name("agent-pipe".to_string())
        .spawn(move || {
            let code = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(async move {
                    use std::os::windows::io::IntoRawHandle;
                    // SAFETY: manejador de pipe recien abierto con FILE_FLAG_OVERLAPPED, cuyo
                    // unico dueno pasa a ser tokio.
                    let client = unsafe {
                        tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(
                            pipe.into_raw_handle(),
                        )
                    };
                    match client {
                        Ok(client) => agent::run_agent(client, config).await.code(),
                        Err(_) => 4,
                    }
                }),
                Err(_) => 5,
            };
            std::process::exit(code);
        });
    if spawned.is_err() {
        std::process::exit(5);
    }

    let options = eframe::NativeOptions {
        viewport: banner::banner_viewport(),
        ..Default::default()
    };
    let ui_kill = kill.clone();
    let result = eframe::run_native(
        "Awawa - sesion desatendida",
        options,
        Box::new(move |cc| {
            Ok(Box::new(banner::BannerApp::new(
                &cc.egui_ctx,
                info,
                ui_kill,
                gate,
                guard,
                ui_ready_tx,
            )))
        }),
    );
    // Sin banner no hay sesion: se revoca y se deja salir al hilo de la pipe.
    if result.is_err() {
        kill.trigger(LocalStop::HotkeyUnavailable);
    } else {
        kill.trigger(LocalStop::KillSwitch);
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    std::process::exit(0);
}
