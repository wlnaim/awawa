//! Banner del agente de sesion: siempre visible y encima, con quien controla,
//! "Sesión desatendida", cronometro, boton "Revocar control ahora" y el atajo global
//! (Pausa / Ctrl+Alt+Fin). Reutiliza la geometria, el reloj, el atajo y el registro de ventanas
//! del banner del host (incluidos por ruta, sin modificarlos).
//!
//! Cerrar o minimizar el banner equivale a pulsar el boton. Sus ventanas se registran en la
//! `ProtectedWindowGuard`, y su rectangulo en la compuerta: el operador no puede pulsar el boton
//! ni teclear sobre el banner.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use awawa_protocol::ProtectedRect;
use egui::{Color32, RichText, ViewportBuilder, ViewportCommand};
use input_win::ProtectedWindowGuard;
use tokio::sync::watch;

use crate::agent::{BannerInfo, KillSwitch, LocalStop};
use crate::banner_geometry::{BANNER_SAFETY_MARGIN_PX, BANNER_SIZE_POINTS, banner_origin_px};
use crate::gate::SessionGate;
use crate::session_clock::SessionClock;
use crate::win::{self, KillSwitchHotkey};
use crate::window_registry::WindowRegistry;

pub const BANNER_TITLE: &str = "Awawa - sesion desatendida";
const RAISE_INTERVAL: Duration = Duration::from_millis(250);
/// Entrada de 128x128 del icono `awawa-hacker.ico`.
const ICON_PNG: &[u8] = include_bytes!("../../../../../assets/awawa-icon-128.png");

/// Ventana raiz: es el propio banner (sin decoraciones, encima de todo, sin barra de tareas).
pub fn banner_viewport() -> ViewportBuilder {
    ViewportBuilder::default()
        .with_title(BANNER_TITLE)
        .with_icon(eframe::icon_data::from_png_bytes(ICON_PNG).expect("icono embebido valido"))
        .with_inner_size([BANNER_SIZE_POINTS.0, BANNER_SIZE_POINTS.1])
        .with_position([0.0, 0.0])
        .with_resizable(false)
        .with_decorations(false)
        .with_always_on_top()
        .with_taskbar(false)
        .with_minimize_button(false)
        .with_maximize_button(false)
        .with_close_button(false)
}

pub struct BannerApp {
    info: Arc<Mutex<BannerInfo>>,
    kill: KillSwitch,
    gate: SessionGate,
    guard: ProtectedWindowGuard,
    registry: WindowRegistry,
    hotkey: Option<KillSwitchHotkey>,
    last_raise: Instant,
    /// Senal al agente: primer cuadro pintado con el atajo global armado.
    ui_ready: watch::Sender<bool>,
    /// Cuadros dibujados (eframe muestra la ventana tras el primero).
    frames: u32,
    /// El sistema informa la ventana del banner como visible (`IsWindowVisible`).
    visible: bool,
}

impl BannerApp {
    /// Arma el atajo global; si no se puede registrar ninguno, la sesion no sigue (falla cerrado).
    pub fn new(
        ctx: &egui::Context,
        info: Arc<Mutex<BannerInfo>>,
        kill: KillSwitch,
        gate: SessionGate,
        guard: ProtectedWindowGuard,
        ui_ready: watch::Sender<bool>,
    ) -> Self {
        // Sin atajos propios de egui: Ctrl+-/+ encogerian el boton y Ctrl+Q cerraria el banner.
        ctx.options_mut(|o| {
            o.zoom_with_keyboard = false;
            o.quit_shortcuts.clear();
        });
        let on_press = kill.clone();
        // El atajo corre en su hilo y revoca sin esperar a la UI.
        let hotkey = KillSwitchHotkey::arm(
            ctx.clone(),
            Arc::new(move || on_press.trigger(LocalStop::KillSwitch)),
        );
        if !hotkey.is_armed() {
            kill.trigger(LocalStop::HotkeyUnavailable);
        }
        Self {
            info,
            kill,
            gate,
            guard,
            registry: WindowRegistry::new(),
            hotkey: Some(hotkey),
            ui_ready,
            frames: 0,
            visible: false,
            last_raise: Instant::now() - RAISE_INTERVAL,
        }
    }

    /// Registra las ventanas del hilo en la guardia, mantiene el banner encima y centrado arriba
    /// y publica su rectangulo protegido en la compuerta.
    fn sync_windows(&mut self) {
        let windows = win::thread_windows();
        self.registry.sync(&windows, &self.guard);
        if self.last_raise.elapsed() < RAISE_INTERVAL {
            return;
        }
        self.last_raise = Instant::now();
        for hwnd in windows {
            if win::window_title(hwnd) != BANNER_TITLE {
                continue;
            }
            // SAFETY: `hwnd` lo acaba de devolver la enumeracion de ventanas de este hilo; si ya
            // no es valido la llamada devuelve FALSE.
            self.visible = unsafe {
                windows::Win32::UI::WindowsAndMessaging::IsWindowVisible(
                    windows::Win32::Foundation::HWND(hwnd as *mut core::ffi::c_void),
                )
            }
            .as_bool();
            if let Some((left, top, right, bottom)) = win::window_rect(hwnd) {
                let (width, height) = (right - left, bottom - top);
                let (x, y) = banner_origin_px(win::primary_screen_width(), width);
                win::place_topmost(hwnd, Some((x, y)));
                self.gate.update_protected_rect(ProtectedRect {
                    left: x,
                    top: y,
                    right: x + width,
                    bottom: y + height,
                    safety_margin_px: BANNER_SAFETY_MARGIN_PX,
                });
            }
        }
    }
}

impl eframe::App for BannerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Cerrar (Alt+F4) o minimizar el banner revoca; nunca lo cierra ni lo oculta.
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.kill.trigger(LocalStop::KillSwitch);
        }
        if ctx.input(|i| i.viewport().minimized == Some(true)) {
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            self.kill.trigger(LocalStop::KillSwitch);
        }
        let info = self.info.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let hotkey_text = self
            .hotkey
            .as_ref()
            .map(KillSwitchHotkey::description)
            .unwrap_or_default();
        let now = Instant::now();
        let mut clicked = false;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(150, 25, 25))
                    .inner_margin(8.0),
            )
            .show(ui, |ui| {
                clicked = draw_banner(ui, &info, &hotkey_text, now).0;
            });
        if clicked {
            self.kill.trigger(LocalStop::KillSwitch);
        }
        self.sync_windows();
        // La senal sale cuando el banner ya se pinto al menos una vez, la ventana es visible de
        // verdad y el atajo global esta armado: entonces el agente puede activar la sesion.
        self.frames = self.frames.saturating_add(1);
        if ready_to_signal(
            self.frames,
            self.visible,
            self.hotkey.as_ref().is_some_and(KillSwitchHotkey::is_armed),
        ) && !*self.ui_ready.borrow()
        {
            self.ui_ready.send_replace(true);
        }
        ctx.request_repaint_after(RAISE_INTERVAL);
    }

    fn on_exit(&mut self) {
        // La ventana se cerro por fuera (cierre de sesion de Windows): se revoca.
        self.kill.trigger(LocalStop::KillSwitch);
        self.registry.clear(&self.guard);
    }
}

/// Condicion de la senal al agente: un cuadro ya presentado (eframe muestra la ventana despues
/// del primero), ventana visible y atajo global armado.
fn ready_to_signal(frames: u32, visible: bool, hotkey_armed: bool) -> bool {
    frames >= 2 && visible && hotkey_armed
}

/// Texto de quien controla (o de la espera antes de `Start`).
pub fn controller_text(info: &BannerInfo) -> String {
    match &info.operator {
        Some(name) => format!("Sesión desatendida - Controla: {name}"),
        None => "Sesión desatendida - conectando con el servicio".to_string(),
    }
}

/// Dibuja el banner. Devuelve si se pulso el boton y su rectangulo.
fn draw_banner(
    ui: &mut egui::Ui,
    info: &BannerInfo,
    hotkey_text: &str,
    now: Instant,
) -> (bool, egui::Rect) {
    let white = Color32::WHITE;
    let mut clicked = false;
    let mut button_rect = egui::Rect::NOTHING;
    ui.vertical(|ui| {
        let row = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
        ui.allocate_ui_with_layout(
            row,
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                let button = egui::Button::new(RichText::new("Revocar control ahora").strong())
                    .fill(Color32::from_rgb(240, 240, 240));
                let response = ui.add(button);
                button_rect = response.rect;
                clicked = response.clicked();
                if let Some(started) = info.started_at {
                    let clock = SessionClock::start(started);
                    ui.label(RichText::new(clock.label(now)).color(white).monospace());
                }
                ui.add(
                    egui::Label::new(RichText::new(controller_text(info)).color(white).strong())
                        .truncate(),
                );
            },
        );
        ui.add(
            egui::Label::new(
                RichText::new(format!("Atajo global para revocar: {hotkey_text}"))
                    .color(white)
                    .small(),
            )
            .truncate(),
        );
    });
    (clicked, button_rect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_senal_exige_ventana_visible_tras_el_primer_cuadro_y_atajo_armado() {
        assert!(!ready_to_signal(1, true, true), "primer ui(): aun oculta");
        assert!(!ready_to_signal(2, false, true), "no visible");
        assert!(!ready_to_signal(2, true, false), "sin atajo");
        assert!(ready_to_signal(2, true, true));
    }

    #[test]
    fn el_banner_dice_que_la_sesion_es_desatendida_y_quien_controla() {
        let mut info = BannerInfo::default();
        assert!(controller_text(&info).contains("Sesión desatendida"));
        info.operator = Some("Tecnico".to_string());
        let text = controller_text(&info);
        assert!(text.contains("Sesión desatendida") && text.contains("Tecnico"));
    }

    /// El boton cabe en el banner con el nombre mas ancho (render sin ventana).
    #[test]
    fn el_boton_cabe_con_nombres_largos() {
        let ctx = egui::Context::default();
        let info = BannerInfo {
            operator: Some("W".repeat(64)),
            started_at: Some(Instant::now() - Duration::from_secs(100 * 3_600)),
        };
        let size = egui::vec2(BANNER_SIZE_POINTS.0, BANNER_SIZE_POINTS.1);
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        let mut button = egui::Rect::NOTHING;
        // Dos pasadas: la primera inicializa las fuentes.
        for _ in 0..2 {
            let mut output = ctx.run_ui(input.clone(), |ui| {
                egui::CentralPanel::default()
                    .frame(egui::Frame::new().inner_margin(8.0))
                    .show(ui, |ui| {
                        button = draw_banner(ui, &info, "Pausa / Ctrl+Alt+Fin", Instant::now()).1;
                    });
            });
            output.textures_delta.clear();
        }
        assert!(
            button.is_positive() && screen.contains_rect(button),
            "{button:?}"
        );
    }
}
