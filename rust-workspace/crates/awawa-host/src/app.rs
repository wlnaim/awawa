//! Capa egui del host: ventana principal, modal de consentimiento y banner de revocacion.
//!
//! No contiene reglas de negocio: dibuja `HostController::view()` y le reenvia las acciones del
//! usuario (Aceptar, Rechazar, Revocar). Los plazos, el rechazo por defecto, el saneado del nombre
//! y la decision de revocar viven en modulos puros con pruebas unitarias.
//!
//! Ventanas (viewports inmediatos, todos en el hilo de la UI):
//! - principal ~420x300: ID, contrasena, estado del relay;
//! - modal: ventana siempre al frente mientras hay una solicitud pendiente;
//! - banner: ventana siempre al frente, sin decoraciones, mientras la sesion esta activa.
//!
//! Cada ciclo se enumeran todas las ventanas del hilo (`EnumThreadWindows`) y se registran en
//! `ProtectedWindowGuard`, de modo que cualquier popup o viewport nuevo queda protegido.

use std::sync::Arc;
use std::time::{Duration, Instant};

use awawa_protocol::{ProtectedRect, ScopedCapabilities};
use egui::{Color32, RichText, ViewportBuilder, ViewportCommand, ViewportId};
use input_win::ProtectedWindowGuard;

use crate::banner_geometry::{BannerLayout, banner_layout, banner_origin_px};
use crate::consent_timer::{AcceptAvailability, ConsentModalTimer, ModalPhase};
use crate::controller::{HostController, HostView};
use crate::gate::SessionGate;
use crate::revocation::{RevocationSignals, RevocationTrigger};
use crate::session_clock::{SessionClock, format_elapsed};
use crate::splash::{self, Splash};
use crate::transport::{HostTransport, RelayStatus};
use crate::win::{self, KillSwitchHotkey};
use crate::window_registry::WindowRegistry;

const MAIN_TITLE: &str = "Awawa - Este equipo";
const MODAL_TITLE: &str = "Awawa - Solicitud de control";
const BANNER_TITLE: &str = "Awawa - Control activo";
/// Cada cuanto se reafirman las ventanas del modal y del banner por encima de las demas.
const RAISE_INTERVAL: Duration = Duration::from_millis(250);
const MODAL_SIZE: [f32; 2] = [480.0, 400.0];

/// Opciones de ventana principal para `eframe::run_native`.
pub fn main_viewport() -> ViewportBuilder {
    ViewportBuilder::default()
        .with_title(MAIN_TITLE)
        .with_icon(splash::window_icon())
        .with_inner_size([420.0, 300.0])
        .with_resizable(false)
        .with_maximize_button(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModalAction {
    None,
    Accept,
    Reject,
}

pub struct HostApp {
    controller: HostController,
    transport: Box<dyn HostTransport>,
    gate: SessionGate,
    guard: ProtectedWindowGuard,
    registry: WindowRegistry,
    hotkey: Option<KillSwitchHotkey>,
    signals: RevocationSignals,
    banner_layout: Option<BannerLayout>,
    last_raise: Instant,
    modal_focused: bool,
    notice: Option<String>,
    copy_feedback: Option<Instant>,
    splash: Splash,
}

impl HostApp {
    pub fn new(
        transport: Box<dyn HostTransport>,
        gate: SessionGate,
        guard: ProtectedWindowGuard,
        notice: Option<String>,
    ) -> Self {
        Self {
            controller: HostController::new(gate.clone()),
            transport,
            gate,
            guard,
            registry: WindowRegistry::new(),
            hotkey: None,
            signals: RevocationSignals::default(),
            banner_layout: None,
            last_raise: Instant::now(),
            modal_focused: false,
            notice,
            copy_feedback: None,
            splash: Splash::default(),
        }
    }

    fn kill_switch_armed(&self) -> bool {
        self.hotkey.as_ref().is_some_and(KillSwitchHotkey::is_armed)
    }

    /// Trabajo sin dibujo de cada ciclo: eventos, atajo, temporizadores y revocacion.
    fn step(&mut self, ctx: &egui::Context, now: Instant) {
        while let Some(event) = self.transport.poll_event() {
            self.controller.on_event(event, now);
        }
        // La red mantiene registrado el ID vigente (nuevo tras revocar o si el relay lo tenia ocupado).
        if let Some(id) = self.controller.session_id() {
            self.transport.set_session_id(id);
        }

        // El atajo solo existe mientras hay una solicitud pendiente o una sesion activa.
        let needs_hotkey = self.controller.is_pending() || self.controller.is_active();
        if needs_hotkey && self.hotkey.is_none() {
            // El atajo revoca en la compuerta desde su propio hilo: video y entrada se detienen
            // sin esperar a la UI. Sin sesion activa (modal) no hace nada ahi.
            let gate = self.gate.clone();
            let on_press = Arc::new(move || {
                gate.revoke(RevocationTrigger::Hotkey.reason(), Instant::now());
            });
            self.hotkey = Some(KillSwitchHotkey::arm(ctx.clone(), on_press));
        } else if !needs_hotkey {
            self.hotkey = None;
        }
        // Se consume siempre: una pulsacion durante el modal no debe revocar la sesion que nazca despues.
        let hotkey_pressed = self
            .hotkey
            .as_ref()
            .is_some_and(KillSwitchHotkey::take_pressed);
        if hotkey_pressed {
            on_kill_switch_pressed(&mut self.controller, &mut self.signals);
        }
        if self.controller.is_pending() || self.controller.is_active() {
            // Con la raiz minimizada y sin otras ventanas visibles eframe solo llama a `logic`:
            // se pide pintar igualmente para que el modal se muestre y para que un banner
            // minimizado se detecte y revoque la sesion.
            ctx.send_viewport_cmd_to(ViewportId::ROOT, ViewportCommand::RequestPaintWhileHidden);
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            // Cerrar la aplicacion rechaza el modal o revoca la sesion antes de salir.
            self.controller.shutdown(now);
            self.registry.clear(&self.guard);
        }

        self.controller.tick(now);
        self.apply_revocation(now);
        self.collect_notice();

        let delay = if self.controller.is_waiting() {
            Duration::from_millis(250)
        } else {
            Duration::from_millis(100)
        };
        ctx.request_repaint_after(delay);
    }

    fn apply_revocation(&mut self, now: Instant) {
        let signals = std::mem::take(&mut self.signals);
        if !self.controller.is_active() {
            return;
        }
        if let Some(trigger) = signals.decide() {
            self.controller.revoke(trigger, now);
            self.banner_layout = None;
        }
    }

    fn collect_notice(&mut self) {
        if let Some(notice) = self.controller.take_notice() {
            self.notice = Some(notice);
        }
        // Las liberaciones de teclas y botones (`pending_release_commands`) ya las entrego la
        // compuerta al despachador al revocar.
        if let Some(revocation) = self.controller.take_revocation() {
            self.notice = Some(format!(
                "Control remoto terminado tras {}: {}",
                format_elapsed(revocation.duration),
                revocation.reason
            ));
        }
    }

    /// Registra todas las ventanas del hilo en la guardia, refresca el rectangulo protegido del
    /// banner y reafirma modal y banner por encima de las demas ventanas.
    fn sync_windows(&mut self) {
        let windows = win::thread_windows();
        self.registry.sync(&windows, &self.guard);

        let raise = self.last_raise.elapsed() >= RAISE_INTERVAL;
        if raise {
            self.last_raise = Instant::now();
        }
        let active = self.controller.is_active();
        let pending = self.controller.is_pending();
        if !(raise || active) {
            return;
        }
        for hwnd in windows {
            let title = win::window_title(hwnd);
            if title == BANNER_TITLE && active {
                if let Some((mut left, mut top, mut right, mut bottom)) = win::window_rect(hwnd) {
                    if raise {
                        // Recentra en el monitor principal (DPI mixto o movimiento por SC_MOVE).
                        let (width, height) = (right - left, bottom - top);
                        let (x, y) = banner_origin_px(win::primary_screen_width(), width);
                        win::place_topmost(hwnd, Some((x, y)));
                        (left, top, right, bottom) = (x, y, x + width, y + height);
                    }
                    self.controller.update_banner_rect(ProtectedRect {
                        left,
                        top,
                        right,
                        bottom,
                        safety_margin_px: crate::banner_geometry::BANNER_SAFETY_MARGIN_PX,
                    });
                }
            } else if title == MODAL_TITLE && pending && raise {
                win::place_topmost(hwnd, None);
            }
        }
    }

    fn show_main(&mut self, ui: &mut egui::Ui, now: Instant) {
        let mut regenerate = false;
        let mut copy_id: Option<String> = None;
        let copied_recently = self
            .copy_feedback
            .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(2));

        egui::CentralPanel::default().show(ui, |ui| {
            match self.controller.view() {
                HostView::Waiting { id, password } => {
                    ui.label("ID de sesión");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&id).monospace().size(24.0).strong());
                        if ui.button(if copied_recently { "Copiado" } else { "Copiar" }).clicked() {
                            copy_id = Some(id.clone());
                        }
                    });
                    ui.add_space(4.0);
                    ui.label("Contraseña");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&password).monospace().size(24.0).strong());
                        if ui.button("Regenerar").clicked() {
                            regenerate = true;
                        }
                    });
                    ui.add_space(6.0);
                    ui.label("Comparta el ID y la contraseña con el agente de soporte. Ninguna conexión inicia el control sin su aprobación en este equipo.");
                }
                HostView::Authenticating => {
                    ui.heading("Verificando solicitud");
                    ui.label("Un operador se está identificando.");
                }
                HostView::Pending { .. } => {
                    ui.heading("Solicitud pendiente");
                    ui.label("Responda en la ventana de consentimiento.");
                }
                HostView::Active { name, .. } => {
                    ui.heading("Control remoto activo");
                    ui.label(format!("Controla este equipo: {name}"));
                    ui.label(format!(
                        "Para terminar use el botón rojo del banner superior o el atajo {}.",
                        self.hotkey
                            .as_ref()
                            .map(KillSwitchHotkey::description)
                            .unwrap_or_default()
                    ));
                }
                HostView::Faulted(message) => {
                    ui.colored_label(Color32::LIGHT_RED, message);
                }
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.label(relay_text(
                    self.controller.relay_status(),
                    self.transport.is_simulated(),
                ));
                if let Some(notice) = &self.notice {
                    ui.label(RichText::new(notice).italics());
                }
            });
        });

        if let Some(text) = copy_id
            && win::copy_to_clipboard(&text)
        {
            self.copy_feedback = Some(now);
        }
        if regenerate {
            self.controller.regenerate_credentials();
            self.notice = None;
        }
    }

    fn show_modal(&mut self, ctx: &egui::Context, now: Instant) {
        // El modal se pinta en este cuadro: desde aqui cuenta la inhabilitacion de Aceptar.
        self.controller.mark_modal_painted(now);
        let HostView::Pending {
            name,
            origin,
            fingerprint,
            sas,
            capabilities,
            timer,
        } = self.controller.view()
        else {
            self.modal_focused = false;
            return;
        };
        let (name, origin) = (name.to_string(), origin.to_string());
        let armed = self.kill_switch_armed();
        let hotkey_text = self
            .hotkey
            .as_ref()
            .map(KillSwitchHotkey::description)
            .unwrap_or_default();
        let first_frame = !self.modal_focused;

        let builder = ViewportBuilder::default()
            .with_title(MODAL_TITLE)
            .with_icon(splash::window_icon())
            .with_inner_size(MODAL_SIZE)
            .with_resizable(false)
            .with_decorations(false)
            .with_always_on_top()
            .with_minimize_button(false)
            .with_maximize_button(false);

        let action = ctx.show_viewport_immediate(
            ViewportId::from_hash_of("awawa-host-consent-modal"),
            builder,
            |ui, _class| {
                let ctx = ui.ctx().clone();
                let mut action = ModalAction::None;
                // Alt+F4 o cierre del modal = rechazo (el valor por defecto).
                if ctx.input(|i| i.viewport().close_requested()) {
                    ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                    action = ModalAction::Reject;
                }
                if ctx.input(|i| i.viewport().minimized == Some(true)) {
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                }
                if first_frame {
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                }
                egui::CentralPanel::default().show(ui, |ui| {
                    let clicked = draw_modal(
                        ui,
                        &ModalContent {
                            name: &name,
                            origin: &origin,
                            fingerprint: &fingerprint,
                            sas: &sas,
                            capabilities,
                            timer,
                            armed,
                            hotkey_text: &hotkey_text,
                        },
                        now,
                    );
                    // Si coinciden el cierre del modal y un clic, gana el rechazo.
                    if action == ModalAction::None {
                        action = clicked;
                    }
                });
                action
            },
        );
        self.modal_focused = true;

        match action {
            ModalAction::Accept => {
                let layout = banner_layout(win::primary_screen_width(), ctx.pixels_per_point());
                let armed = self.kill_switch_armed();
                if self.controller.accept(now, armed, layout.protected_rect) {
                    self.banner_layout = Some(layout);
                    self.signals = RevocationSignals::default();
                    self.notice = None;
                }
            }
            ModalAction::Reject => self.controller.reject("Solicitud rechazada"),
            ModalAction::None => {}
        }
        self.collect_notice();
    }

    fn show_banner(&mut self, ctx: &egui::Context, now: Instant) {
        let (HostView::Active { name, clock }, Some(layout)) =
            (self.controller.view(), self.banner_layout)
        else {
            return;
        };
        let name = name.to_string();
        let hotkey_text = self
            .hotkey
            .as_ref()
            .map(KillSwitchHotkey::description)
            .unwrap_or_default();

        let builder = ViewportBuilder::default()
            .with_title(BANNER_TITLE)
            .with_icon(splash::window_icon())
            .with_inner_size([layout.size_points.0, layout.size_points.1])
            .with_position([layout.position_points.0, layout.position_points.1])
            .with_resizable(false)
            .with_decorations(false)
            .with_always_on_top()
            .with_taskbar(false)
            .with_minimize_button(false)
            .with_maximize_button(false)
            .with_close_button(false);

        let signals = ctx.show_viewport_immediate(
            ViewportId::from_hash_of("awawa-host-revoke-banner"),
            builder,
            |ui, _class| {
                let ctx = ui.ctx().clone();
                let mut signals = RevocationSignals::default();
                // SC_CLOSE (Alt+F4) y SC_MINIMIZE sobre el banner revocan; nunca lo cierran ni ocultan.
                if ctx.input(|i| i.viewport().close_requested()) {
                    ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                    signals.banner_close_requested = true;
                }
                if ctx.input(|i| i.viewport().minimized == Some(true)) {
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                    signals.banner_minimized = true;
                }
                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::new()
                            .fill(Color32::from_rgb(150, 25, 25))
                            .inner_margin(8.0),
                    )
                    .show(ui, |ui| {
                        draw_banner(ui, &name, clock, &hotkey_text, now, &mut signals);
                    });
                signals
            },
        );

        self.signals.button_clicked |= signals.button_clicked;
        self.signals.banner_close_requested |= signals.banner_close_requested;
        self.signals.banner_minimized |= signals.banner_minimized;
    }
}

impl eframe::App for HostApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.step(ctx, Instant::now());
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let now = Instant::now();
        // El splash solo reemplaza la ventana principal: modal y banner siguen su curso normal.
        if !self.splash.show(ui) {
            self.show_main(ui, now);
        }
        self.show_modal(&ctx, now);
        self.show_banner(&ctx, now);
        // El boton del banner o un intento de cerrarlo/minimizarlo se atiende en este mismo ciclo.
        self.apply_revocation(now);
        self.collect_notice();
        self.sync_windows();
    }

    fn on_exit(&mut self) {
        self.controller.shutdown(Instant::now());
        self.registry.clear(&self.guard);
    }
}

/// Pulsacion del atajo global: con sesion activa marca la revocacion; durante el modal rechaza.
fn on_kill_switch_pressed(controller: &mut HostController, signals: &mut RevocationSignals) {
    if controller.is_active() {
        signals.hotkey_pressed = true;
    } else if controller.is_pending() {
        // Ante la duda se revoca: durante el modal el atajo equivale a Rechazar.
        controller.reject("Solicitud rechazada con el atajo de revocacion");
    }
}

fn relay_text(status: &RelayStatus, simulated: bool) -> String {
    let base = match status {
        RelayStatus::Disconnected => "Relay: sin conexión".to_string(),
        RelayStatus::Connecting => "Relay: conectando...".to_string(),
        RelayStatus::Registered => "Relay: registrado".to_string(),
    };
    if simulated {
        format!("{base} (transporte simulado)")
    } else {
        base
    }
}

struct ModalContent<'a> {
    name: &'a str,
    origin: &'a str,
    fingerprint: &'a str,
    sas: &'a str,
    capabilities: ScopedCapabilities,
    timer: ConsentModalTimer,
    armed: bool,
    hotkey_text: &'a str,
}

fn capabilities_text(caps: ScopedCapabilities) -> String {
    let mut parts = Vec::new();
    if caps.view_desktop {
        parts.push("ver la pantalla");
    }
    if caps.control_cursor {
        parts.push("controlar el mouse");
    }
    if caps.control_keyboard {
        parts.push("controlar el teclado");
    }
    parts.join(", ")
}

/// Fila "etiqueta: valor" cuyo valor se trunca al ancho restante.
fn detail_row(ui: &mut egui::Ui, label: &str, value: RichText) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::Label::new(value).truncate());
    });
}

fn draw_modal(ui: &mut egui::Ui, content: &ModalContent<'_>, now: Instant) -> ModalAction {
    let mut action = ModalAction::None;
    ui.heading("Un operador solicita control de este equipo");
    ui.add_space(6.0);
    detail_row(ui, "Operador:", RichText::new(content.name).strong());
    detail_row(ui, "Origen:", RichText::new(content.origin));
    detail_row(
        ui,
        "Huella:",
        RichText::new(content.fingerprint).monospace(),
    );
    detail_row(
        ui,
        "Permisos:",
        RichText::new(capabilities_text(content.capabilities)),
    );
    ui.add_space(6.0);
    ui.label("Código de verificación (debe coincidir con el que ve el operador):");
    ui.label(RichText::new(content.sas).monospace().size(32.0).strong());
    ui.add_space(6.0);

    let left = content.timer.seconds_left(now);
    ui.label(format!("Se rechazará automáticamente en {left} s"));
    ui.add(egui::ProgressBar::new(left as f32 / 60.0));
    ui.add_space(8.0);

    let availability = content.timer.accept_availability(now, content.armed);
    ui.horizontal(|ui| {
        if ui.button("Rechazar").clicked() {
            action = ModalAction::Reject;
        }
        let label = match content.timer.phase(now) {
            ModalPhase::Locked { remaining } => {
                format!("Aceptar (en {:.1} s)", remaining.as_secs_f32())
            }
            _ => "Aceptar".to_string(),
        };
        let enabled = availability == AcceptAvailability::Enabled;
        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
            action = ModalAction::Accept;
        }
    });
    if availability == AcceptAvailability::KillSwitchUnavailable {
        ui.colored_label(
            Color32::LIGHT_RED,
            "No se pudo registrar el atajo global de revocación: no se puede aceptar.",
        );
    } else if !content.hotkey_text.is_empty() {
        ui.label(format!(
            "Podrá revocar el control en cualquier momento con el banner o con {}.",
            content.hotkey_text
        ));
    }
    action
}

/// Dibuja el contenido del banner y devuelve el rectangulo del boton de revocar.
/// El boton va anclado a la derecha y la etiqueta con el nombre se trunca al ancho restante, de modo
/// que ningun nombre puede desplazarlo fuera de la ventana.
fn draw_banner(
    ui: &mut egui::Ui,
    name: &str,
    clock: SessionClock,
    hotkey_text: &str,
    now: Instant,
    signals: &mut RevocationSignals,
) -> egui::Rect {
    let white = Color32::WHITE;
    let mut button_rect = egui::Rect::NOTHING;
    ui.vertical(|ui| {
        // La fila principal mide lo que un control: sin limite ocuparia todo el alto y la linea del
        // atajo quedaria fuera de la ventana.
        let row = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
        ui.allocate_ui_with_layout(
            row,
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                let button = egui::Button::new(RichText::new("Revocar control ahora").strong())
                    .fill(Color32::from_rgb(240, 240, 240));
                let response = ui.add(button);
                button_rect = response.rect;
                if response.clicked() {
                    signals.button_clicked = true;
                }
                ui.label(RichText::new(clock.label(now)).color(white).monospace());
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Controla: {name}"))
                            .color(white)
                            .strong(),
                    )
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
    button_rect
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner_geometry::BANNER_SIZE_POINTS;
    use crate::controller::tests::{deliver, new_controller};
    use crate::display_name::{sanitize_operator_name, sanitize_origin};
    use egui::{Pos2, Rect, Vec2};

    /// Ejecuta `f` en un contexto egui sin ventana, sobre una pantalla de `size` puntos con
    /// `pixels_per_point` pixeles fisicos por punto.
    fn run_headless_scaled(size: Vec2, pixels_per_point: f32, mut f: impl FnMut(&mut egui::Ui)) {
        let ctx = egui::Context::default();
        let mut input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
            ..Default::default()
        };
        input.viewports.insert(
            ViewportId::ROOT,
            egui::ViewportInfo {
                native_pixels_per_point: Some(pixels_per_point),
                ..Default::default()
            },
        );
        // Dos pasadas: la primera inicializa las fuentes.
        for _ in 0..2 {
            let mut output = ctx.run_ui(input.clone(), |ui| f(ui));
            output.textures_delta.clear();
        }
        assert_eq!(ctx.pixels_per_point(), pixels_per_point);
    }

    fn run_headless(size: Vec2, f: impl FnMut(&mut egui::Ui)) {
        run_headless_scaled(size, 1.0, f);
    }

    fn worst_names() -> Vec<String> {
        ["W", "M", "\u{FF37}", "@", "\u{4E2D}"]
            .iter()
            .map(|c| sanitize_operator_name(&c.repeat(60)))
            .collect()
    }

    #[test]
    fn revoke_button_stays_inside_the_banner_for_the_widest_names() {
        let size = Vec2::new(BANNER_SIZE_POINTS.0, BANNER_SIZE_POINTS.1);
        let screen = Rect::from_min_size(Pos2::ZERO, size);
        let mut names = worst_names();
        names.push("Mesa de Ayuda TI - Operador #04".to_string());
        // Textos posibles del atajo: con la sesion activa al menos uno quedo registrado.
        let hotkeys = ["Pausa / Ctrl+Alt+Fin", "Pausa", "Ctrl+Alt+Fin"];
        let t0 = Instant::now();
        let elapsed = [0, 3_599, 100 * 3_600 + 3_599].map(Duration::from_secs);
        for scale in [1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0] {
            for name in &names {
                assert!(name.chars().count() <= 48);
                for hotkey in hotkeys {
                    for since_start in elapsed {
                        let mut button = Rect::NOTHING;
                        let mut content = Rect::NOTHING;
                        run_headless_scaled(size, scale, |ui| {
                            egui::CentralPanel::default()
                                .frame(egui::Frame::new().inner_margin(8.0))
                                .show(ui, |ui| {
                                    let mut signals = RevocationSignals::default();
                                    // `scope` mide solo lo que dibuja el banner (el panel ocupa
                                    // siempre toda la ventana).
                                    content = ui
                                        .scope(|ui| {
                                            button = draw_banner(
                                                ui,
                                                name,
                                                SessionClock::start(t0),
                                                hotkey,
                                                t0 + since_start,
                                                &mut signals,
                                            );
                                        })
                                        .response
                                        .rect;
                                });
                        });
                        let case = format!("escala {scale}, nombre {name:?}, atajo {hotkey:?}");
                        assert!(
                            screen.contains_rect(button),
                            "boton fuera del banner ({case}): {button:?}"
                        );
                        assert!(button.width() > 100.0, "boton demasiado estrecho ({case})");
                        assert!(
                            screen.contains_rect(content),
                            "contenido fuera del banner ({case}): {content:?}"
                        );
                    }
                }
            }
        }
    }

    /// Controlador con una solicitud valida ya autenticada y el modal pintado en `t0`.
    fn pending_controller(t0: Instant) -> HostController {
        let mut c = new_controller();
        let HostView::Waiting { password, .. } = c.view() else {
            panic!("se esperaba la fase Waiting");
        };
        let (mut transport, handle) = crate::transport::SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador de prueba", &password);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        assert!(c.is_pending());
        c.mark_modal_painted(t0);
        c
    }

    fn password_of(c: &HostController) -> String {
        match c.view() {
            HostView::Waiting { password, .. } => password,
            _ => panic!("se esperaba la fase Waiting"),
        }
    }

    #[test]
    fn kill_switch_during_the_modal_rejects_and_rotates_the_password() {
        let t0 = Instant::now();
        let mut c = new_controller();
        let before = password_of(&c);
        let (mut transport, handle) = crate::transport::SimulatedTransport::new();
        transport.poll_event();
        handle.request_operator("Operador de prueba", &before);
        deliver(&mut c, transport.poll_event().unwrap(), t0);
        assert!(c.is_pending());

        let mut signals = RevocationSignals::default();
        on_kill_switch_pressed(&mut c, &mut signals);
        assert!(c.is_waiting() && !c.is_active());
        assert_ne!(password_of(&c), before, "el atajo rota la contrasena");
        assert!(!signals.hotkey_pressed, "no queda una revocacion pendiente");
        assert!(c.take_notice().unwrap().contains("atajo de revocacion"));
    }

    #[test]
    fn kill_switch_during_the_session_marks_the_revocation() {
        let t0 = Instant::now();
        let mut c = pending_controller(t0);
        let rect = banner_layout(1920, 1.0).protected_rect;
        assert!(c.accept(t0 + Duration::from_millis(1500), true, rect));
        let mut signals = RevocationSignals::default();
        on_kill_switch_pressed(&mut c, &mut signals);
        assert!(signals.hotkey_pressed);
    }

    #[test]
    fn modal_name_and_origin_do_not_overflow_the_window() {
        let size = Vec2::new(MODAL_SIZE[0], MODAL_SIZE[1]);
        for name in worst_names() {
            let origin = sanitize_origin(&"W".repeat(100));
            let mut used = Rect::NOTHING;
            run_headless(size, |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    let content = ModalContent {
                        name: &name,
                        origin: &origin,
                        fingerprint: "4A:91:C2:08:7F:E3:11:5B",
                        sas: "ABCDEF",
                        capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
                        timer: ConsentModalTimer::new(Instant::now()),
                        armed: true,
                        hotkey_text: "Pausa / Ctrl+Alt+Fin",
                    };
                    let _ = draw_modal(ui, &content, Instant::now());
                    used = ui.min_rect();
                });
            });
            assert!(
                used.right() <= size.x && used.bottom() <= size.y,
                "el modal desborda con el nombre {name:?}: {used:?}"
            );
        }
    }
}
