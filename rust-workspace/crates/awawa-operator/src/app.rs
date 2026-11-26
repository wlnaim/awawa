//! Capa egui del operador. Solo dibuja y delega toda la logica en los modulos puros
//! (`form`, `session`, `viewport`, `input_capture`, `frame`).

use std::time::{Duration, Instant};

use awawa_protocol::RemoteInputCommand;
use egui::scroll_area::{DragScroll, ScrollSource};
use egui::{
    Align, Button, Color32, EventFilter, Key, Layout, RichText, ScrollArea, Sense, Stroke,
    StrokeKind, TextEdit, TextureHandle, TextureOptions, vec2,
};
use zeroize::Zeroize;

use crate::countdown::Countdown;
use crate::form::{self, ConnectMode, FormInput};
use crate::frame;
use crate::input_capture::{InputCapture, ViewContext};
use crate::keymap::{self, ClipboardAction};
use crate::session::{Phase, SessionModel, TickOutcome};
use crate::splash::Splash;
use crate::transport::{FrameUpdate, OperatorTransport, TransportEvent, TransportFactory};
use crate::viewport::{self, MonitorSelection, ScaleMode};

const DEFAULT_AGENT_NAME: &str = "Agente de Soporte";
const WAITING_REPAINT: Duration = Duration::from_millis(200);
const VIEWER_REPAINT: Duration = Duration::from_millis(100);
const TEXTURE_OPTIONS: TextureOptions = TextureOptions::LINEAR;
/// Aviso del visor mientras el equipo remoto muestra el escritorio seguro.
const LOCAL_APPROVAL_NOTICE: &str =
    "El equipo remoto requiere aprobación local (escritorio seguro); el control está en pausa";
/// Tope de eventos del transporte por cuadro: el resto queda para el siguiente.
const MAX_EVENTS_PER_FRAME: usize = 64;

/// Mensaje si se intenta el modo desatendido sin clave fijada (la UI no lo ofrece sin ella).
const UNATTENDED_NEEDS_KEY: &str = "El modo desatendido requiere iniciar con --host-key <archivo>.";

fn password_field_id() -> egui::Id {
    egui::Id::unique("connect_form_password")
}

pub struct OperatorApp {
    ctx: egui::Context,
    started: Instant,
    model: SessionModel,
    form: FormInput,
    form_error: Option<String>,
    factory: TransportFactory,
    transport: Option<Box<dyn OperatorTransport>>,
    capture: InputCapture,
    texture: Option<TextureHandle>,
    /// Fotogramas recibidos desde el ultimo pase de UI, fusionados en uno solo. La textura solo
    /// se toca en `ui`: con la ventana minimizada eframe corre solo `logic` y no retira los
    /// deltas de textura, que se acumularian sin tope.
    pending_frame: Option<FrameUpdate>,
    /// Huella de la clave del servicio cargada con `--host-key`; sin ella no hay modo desatendido.
    host_key_fingerprint: Option<String>,
    splash: Option<Splash>,
}

impl OperatorApp {
    pub fn new(ctx: egui::Context, factory: TransportFactory) -> Self {
        // Ctrl+Q y Ctrl+-/=/0 deben llegar al equipo remoto, no cerrar la app ni cambiar el zoom.
        ctx.options_mut(|o| {
            o.quit_shortcuts.clear();
            o.zoom_with_keyboard = false;
        });
        Self {
            ctx,
            started: Instant::now(),
            model: SessionModel::new(),
            form: {
                let mut form = FormInput::default();
                form.agent_name = DEFAULT_AGENT_NAME.to_string();
                form
            },
            form_error: None,
            factory,
            transport: None,
            capture: InputCapture::new(),
            texture: None,
            pending_frame: None,
            host_key_fingerprint: None,
            splash: None,
        }
    }

    /// Muestra la pantalla de presentacion al arrancar (las pruebas la omiten).
    pub fn with_splash(mut self) -> Self {
        self.splash = Some(Splash::default());
        self
    }

    /// Habilita el modo desatendido y muestra esta huella de la clave fijada para compararla.
    pub fn with_host_key_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.host_key_fingerprint = fingerprint;
        self
    }

    fn now(&self) -> Duration {
        self.started.elapsed()
    }

    fn send_all(&mut self, commands: Vec<RemoteInputCommand>) {
        if let Some(t) = self.transport.as_mut() {
            for c in commands {
                t.send_input(c);
            }
        }
    }

    /// Suelta teclas y botones pendientes y cierra el canal.
    fn close_transport(&mut self) {
        let releases = self.capture.release_all();
        self.send_all(releases);
        if let Some(mut t) = self.transport.take() {
            t.disconnect();
        }
    }

    fn connect(&mut self) {
        if self.form.mode == ConnectMode::Unattended && self.host_key_fingerprint.is_none() {
            self.form_error = Some(UNATTENDED_NEEDS_KEY.to_string());
            return;
        }
        match form::validate(&self.form) {
            Ok(params) => {
                self.form_error = None;
                // La contrasena sale del formulario (memoria y historial de deshacer del campo)
                // en cuanto se entrega al transporte.
                self.form.password.zeroize();
                if let Some(mut state) = TextEdit::load_state(&self.ctx, password_field_id()) {
                    state.clear_undoer();
                    state.store(&self.ctx, password_field_id());
                }
                self.texture = None;
                self.pending_frame = None;
                match params.mode {
                    ConnectMode::OnDemand => self.model.begin_connect(),
                    ConnectMode::Unattended => self.model.begin_connect_unattended(),
                }
                self.transport = Some((self.factory)(params, self.ctx.clone()));
            }
            Err(e) => self.form_error = Some(e.to_string()),
        }
    }

    fn disconnect(&mut self) {
        self.model.user_disconnect();
        self.close_transport();
    }

    fn poll_transport(&mut self) {
        let now = self.now();
        let mut handled = 0;
        while handled < MAX_EVENTS_PER_FRAME
            && let Some(event) = self.transport.as_mut().and_then(|t| t.poll_event())
        {
            handled += 1;
            let accepted = self.model.on_event(&event, now);
            if let (true, TransportEvent::Frame(update)) = (accepted, event) {
                self.pending_frame = Some(match self.pending_frame.take() {
                    Some(pending) => pending.merge(update),
                    None => update,
                });
            }
        }
        if handled == MAX_EVENTS_PER_FRAME {
            self.ctx.request_repaint();
        }
        if self.model.tick(now) == TickOutcome::ApprovalTimedOut {
            self.close_transport();
        }
        let live = matches!(self.model.phase(), Phase::Waiting { .. } | Phase::Viewing);
        if !live && self.transport.is_some() {
            self.close_transport();
        }
    }

    fn apply_frame(&mut self, update: &FrameUpdate) {
        let size = [update.frame.width as usize, update.frame.height as usize];
        let needs_full = self.texture.as_ref().is_none_or(|t| t.size() != size);
        if needs_full {
            if let Some(full) = frame::full_rgba(&update.frame) {
                let image = egui::ColorImage::from_rgba_unmultiplied(full.size, &full.rgba);
                self.texture = Some(self.ctx.load_texture(
                    "remote_desktop",
                    image,
                    TEXTURE_OPTIONS,
                ));
            }
            return;
        }
        if let Some(texture) = self.texture.as_mut() {
            for rect in &update.dirty {
                if let Some(region) = frame::region_to_rgba(&update.frame, rect) {
                    let image = egui::ColorImage::from_rgba_unmultiplied(region.size, &region.rgba);
                    texture.set_partial(region.pos, image, TEXTURE_OPTIONS);
                }
            }
        }
    }

    fn form_view(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.heading("Solicitar control remoto");
            ui.add_space(8.0);
            let has_key = self.host_key_fingerprint.is_some();
            ui.horizontal(|ui| {
                ui.label("Modo");
                ui.selectable_value(&mut self.form.mode, ConnectMode::OnDemand, "Bajo demanda");
                ui.add_enabled_ui(has_key, |ui| {
                    ui.selectable_value(
                        &mut self.form.mode,
                        ConnectMode::Unattended,
                        "Equipo desatendido",
                    );
                });
            });
            let unattended = self.form.mode == ConnectMode::Unattended;
            match (&self.host_key_fingerprint, unattended) {
                (Some(fingerprint), true) => {
                    ui.label("Huella de la clave fijada del equipo (compárela con la del administrador):");
                    ui.label(RichText::new(fingerprint).monospace().strong());
                }
                (None, _) => {
                    ui.label("Para el modo desatendido inicie con --host-key <archivo>.");
                }
                _ => {}
            }
            ui.add_space(8.0);
            let mut submit = false;
            egui::Grid::new("connect_form")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label(if unattended { "ID del equipo" } else { "ID del cliente" });
                    let id = ui.add(
                        TextEdit::singleline(&mut self.form.session_id)
                            .hint_text("482-910-337")
                            .desired_width(260.0),
                    );
                    ui.end_row();

                    ui.label("Contraseña");
                    let pw = ui.add(
                        TextEdit::singleline(&mut self.form.password)
                            .id(password_field_id())
                            .password(true)
                            .hint_text(if unattended {
                                "Contraseña del equipo"
                            } else {
                                "Contraseña temporal"
                            })
                            .desired_width(260.0),
                    );
                    ui.end_row();

                    ui.label("Nombre del agente");
                    let name = ui
                        .add(TextEdit::singleline(&mut self.form.agent_name).desired_width(260.0));
                    ui.end_row();

                    let enter = ui.input(|i| i.key_pressed(Key::Enter));
                    submit = enter && (id.lost_focus() || pw.lost_focus() || name.lost_focus());
                });
            ui.add_space(8.0);
            ui.label("Se solicitará ver la pantalla y controlar mouse y teclado.");
            ui.add_space(8.0);
            let label = if unattended {
                "Conectar al equipo"
            } else {
                "Solicitar Control Remoto"
            };
            if ui.button(label).clicked() {
                submit = true;
            }
            if let Some(error) = &self.form_error {
                ui.add_space(6.0);
                ui.colored_label(Color32::from_rgb(200, 60, 60), error);
            }
            if submit {
                self.connect();
            }
        });
    }

    fn waiting_view(
        &mut self,
        ui: &mut egui::Ui,
        sas: Option<String>,
        countdown: Option<Countdown>,
    ) {
        let now = self.now();
        ui.ctx().request_repaint_after(WAITING_REPAINT);
        let mut cancel = false;
        let unattended = self.model.is_unattended();
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.spinner();
                ui.add_space(8.0);
                if unattended {
                    ui.heading("Autenticando con el equipo");
                    ui.label("Verificando la identidad del equipo y la contraseña.");
                } else {
                    ui.heading("Esperando la aprobación del cliente");
                    ui.label("El usuario debe aceptar la solicitud en su equipo.");
                }
                ui.add_space(16.0);
                match &sas {
                    _ if unattended => {}
                    Some(code) => {
                        ui.label("Código de verificación (debe coincidir con el del cliente)");
                        ui.label(RichText::new(code).monospace().size(40.0).strong());
                    }
                    None => {
                        ui.label("Conectando…");
                    }
                }
                if let Some(c) = &countdown {
                    ui.add_space(16.0);
                    ui.add(
                        egui::ProgressBar::new(c.fraction_left(now))
                            .desired_width(320.0)
                            .text(format!("Tiempo restante: {} s", c.remaining_secs(now))),
                    );
                }
                ui.add_space(20.0);
                if ui.button("Cancelar").clicked() {
                    cancel = true;
                }
            });
        });
        if cancel {
            self.disconnect();
        }
    }

    fn ended_view(&mut self, ui: &mut egui::Ui, message: &str) {
        let mut back = false;
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.heading("Sesión finalizada");
                ui.label(message);
                ui.add_space(16.0);
                if ui.button("Volver al formulario").clicked() {
                    back = true;
                }
            });
        });
        if back {
            self.model.back_to_form();
        }
    }

    fn viewer_view(&mut self, ui: &mut egui::Ui) {
        let now = self.now();
        ui.ctx().request_repaint_after(VIEWER_REPAINT);
        let fps = self.model.fps(now);
        let rtt = self.model.rtt_ms();
        let monitor_indices: Vec<u8> = self.model.monitors().iter().map(|m| m.index).collect();
        let capturing = self.capture.is_capturing();
        let session_label = self
            .model
            .is_unattended()
            .then(|| match self.model.fingerprint() {
                Some(fingerprint) => format!("Sesión desatendida · huella {fingerprint}"),
                None => "Sesión desatendida".to_string(),
            });
        let mut disconnect = false;

        egui::Panel::top("viewer_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                let selected = match self.model.selection {
                    MonitorSelection::All => "Todos".to_string(),
                    MonitorSelection::Monitor(i) => format!("Monitor {}", u16::from(i) + 1),
                };
                egui::ComboBox::from_id_salt("monitor_selector")
                    .selected_text(selected)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.model.selection,
                            MonitorSelection::All,
                            "Todos",
                        );
                        for i in &monitor_indices {
                            ui.selectable_value(
                                &mut self.model.selection,
                                MonitorSelection::Monitor(*i),
                                format!("Monitor {}", u16::from(*i) + 1),
                            );
                        }
                    });
                ui.separator();
                ui.selectable_value(&mut self.model.scale_mode, ScaleMode::Fit, "Ajustar");
                ui.selectable_value(&mut self.model.scale_mode, ScaleMode::OneToOne, "1:1");
                ui.separator();
                match rtt {
                    Some(ms) => ui.label(format!("RTT: {ms} ms")),
                    None => ui.label("RTT: --"),
                };
                ui.label(format!("FPS: {fps}"));
                if let Some(label) = &session_label {
                    ui.separator();
                    ui.label(RichText::new(label).strong());
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let button = Button::new(RichText::new("Desconectar").color(Color32::WHITE))
                        .fill(Color32::from_rgb(170, 40, 40));
                    if ui.add(button).clicked() {
                        disconnect = true;
                    }
                    ui.label(if capturing {
                        "Entrada capturada"
                    } else {
                        "Clic en la pantalla para controlar"
                    });
                });
            });
        });

        if disconnect {
            self.disconnect();
            ui.ctx().request_repaint();
            return;
        }
        if self.model.awaiting_local_approval() {
            egui::Panel::top("local_approval_notice").show(ui, |ui| {
                ui.colored_label(
                    Color32::from_rgb(230, 160, 30),
                    RichText::new(LOCAL_APPROVAL_NOTICE).strong(),
                );
            });
        }
        egui::CentralPanel::no_frame().show(ui, |ui| self.canvas(ui));
    }

    fn canvas(&mut self, ui: &mut egui::Ui) {
        let Some(desktop) = self.model.desktop().copied() else {
            return;
        };
        let Some(texture) = self.texture.clone() else {
            ui.centered_and_justified(|ui| ui.label("Esperando el primer fotograma…"));
            return;
        };
        let tex_size = texture.size();
        let region = viewport::region_for(self.model.selection, self.model.monitors(), &desktop);
        let content_px = viewport::region_size_in_frame(
            &region,
            &desktop,
            tex_size[0] as u32,
            tex_size[1] as u32,
        );
        let uv = viewport::uv_rect(&region, &desktop);
        let mode = self.model.scale_mode;
        let canvas_size = ui.available_size();
        let ppp = ui.ctx().pixels_per_point();
        let size = viewport::display_size(content_px, canvas_size, mode, ppp);
        let (events, hover_pos) = ui.input(|i| (i.events.clone(), i.pointer.hover_pos()));

        let scroll = ScrollArea::both()
            .auto_shrink(false)
            .scroll_source(ScrollSource {
                scroll_bar: true,
                drag: DragScroll::Never,
                mouse_wheel: false,
            })
            .show(ui, |ui| {
                let alloc = vec2(
                    size.x.max(ui.available_width()),
                    size.y.max(ui.available_height()),
                );
                let (rect, response) = ui.allocate_exact_size(alloc, Sense::click_and_drag());
                let image_rect = viewport::place_in_canvas(rect, size);
                ui.painter()
                    .image(texture.id(), image_rect, uv, Color32::WHITE);
                (response, image_rect, ui.clip_rect())
            });
        let (response, image_rect, visible) = scroll.inner;

        // Solo se pide el foco si no se tiene: pedirlo de nuevo lo recrea con el filtro por defecto
        // y Esc borraria el foco (y abortaria el arrastre) en vez de llegar al remoto.
        if response.is_pointer_button_down_on() && !response.has_focus() {
            response.request_focus();
        }
        // Con el lienzo enfocado las flechas, Tab y Esc van al equipo remoto, no a la navegacion de egui.
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                response.id,
                EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            );
        });

        let mut commands = self.capture.set_focus(response.has_focus());
        let view = ViewContext {
            image_rect,
            visible,
            region,
            desktop,
            hover_pos,
            // `hovered` es falso si otro widget de la capa (p. ej. la barra flotante de
            // desplazamiento) tapa el lienzo; `contains_pointer` no lo distingue.
            pointer_on_canvas: response.hovered(),
        };
        if self.model.can_send_input() {
            commands.extend(self.capture.process(&events, &view));
        }
        self.send_all(commands);

        let color = if self.capture.is_capturing() {
            Color32::from_rgb(60, 180, 90)
        } else {
            Color32::from_gray(90)
        };
        ui.painter().rect_stroke(
            scroll.inner_rect,
            0.0,
            Stroke::new(2.0, color),
            StrokeKind::Inside,
        );
    }
}

impl eframe::App for OperatorApp {
    /// Corre en cada ciclo, incluso con la ventana minimizada (sin pase de UI): aqui se consume
    /// el transporte y se libera la entrada al perder el foco o minimizar.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let active = ctx.input(|i| {
            let viewport = i.viewport();
            viewport.focused.unwrap_or(i.focused) && viewport.visible() != Some(false)
        });
        let releases = self.capture.set_window_active(active);
        self.send_all(releases);
        self.poll_transport();
        if matches!(self.model.phase(), Phase::Waiting { .. }) {
            ctx.request_repaint_after(WAITING_REPAINT);
        }
    }

    /// Los atajos de portapapeles de egui-winit estan desactivados (ver `main.rs`) para que
    /// lleguen como teclas fisicas al visor. Fuera del visor enfocado (formulario) se piden
    /// al sistema para que copiar y pegar funcionen en los campos locales.
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if self.model.can_send_input() && self.capture.is_capturing() {
            return;
        }
        for event in &raw_input.events {
            if let egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } = event
            {
                let command = match keymap::clipboard_action(*key, *modifiers) {
                    Some(ClipboardAction::Cut) => egui::ViewportCommand::RequestCut,
                    Some(ClipboardAction::Copy) => egui::ViewportCommand::RequestCopy,
                    Some(ClipboardAction::Paste) => egui::ViewportCommand::RequestPaste,
                    None => continue,
                };
                ctx.send_viewport_cmd(command);
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(update) = self.pending_frame.take() {
            self.apply_frame(&update);
        }
        if self.splash.as_mut().is_some_and(|splash| splash.show(ui)) {
            return;
        }
        match self.model.phase().clone() {
            Phase::Form => self.form_view(ui),
            Phase::Waiting { sas, countdown } => self.waiting_view(ui, sas, countdown),
            Phase::Viewing => self.viewer_view(ui),
            Phase::Ended { message } => self.ended_view(ui, &message),
        }
    }

    fn on_exit(&mut self) {
        self.close_transport();
    }
}

#[cfg(test)]
mod tests {
    //! Cableado real de `OperatorApp` con un `egui::Context` sin ventana y entrada sintetica.

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use awawa_protocol::{ButtonState, MonitorDescriptor, MouseButton};
    use capture_win::{DecodedFrame, DirtyRect};
    use eframe::App as _;
    use egui::{
        Event, FullOutput, Modifiers, PointerButton, Pos2, RawInput, Rect, ViewportCommand,
        ViewportId, ViewportInfo, pos2,
    };

    use super::*;
    use crate::transport::MAX_PENDING_RECTS;

    const SCREEN_W: f32 = 800.0;
    const SCREEN_H: f32 = 600.0;
    const REMOTE_W: u32 = 1600;
    const REMOTE_H: u32 = 1200;

    #[derive(Default)]
    struct Shared {
        sent: Vec<RemoteInputCommand>,
        events: VecDeque<TransportEvent>,
    }

    struct FakeTransport(Rc<RefCell<Shared>>);

    impl OperatorTransport for FakeTransport {
        fn send_input(&mut self, command: RemoteInputCommand) {
            self.0.borrow_mut().sent.push(command);
        }
        fn disconnect(&mut self) {}
        fn poll_event(&mut self) -> Option<TransportEvent> {
            self.0.borrow_mut().events.pop_front()
        }
    }

    struct Harness {
        ctx: egui::Context,
        app: OperatorApp,
        frame: eframe::Frame,
        shared: Rc<RefCell<Shared>>,
        time: f64,
    }

    fn full_update() -> FrameUpdate {
        FrameUpdate {
            frame: DecodedFrame::new(REMOTE_W, REMOTE_H),
            dirty: vec![DirtyRect {
                x: 0,
                y: 0,
                width: REMOTE_W,
                height: REMOTE_H,
            }],
        }
    }

    fn partial_update(i: u32) -> FrameUpdate {
        FrameUpdate {
            frame: DecodedFrame::new(REMOTE_W, REMOTE_H),
            dirty: vec![DirtyRect {
                x: (i * 16) % REMOTE_W,
                y: 0,
                width: 16,
                height: 16,
            }],
        }
    }

    impl Harness {
        /// Sesion aprobada en el visor 1:1 (el escritorio remoto es mayor que la ventana, asi
        /// que aparecen las barras de desplazamiento) con el primer fotograma ya en la textura.
        fn viewing() -> Self {
            let ctx = egui::Context::default();
            let shared = Rc::new(RefCell::new(Shared::default()));
            let for_factory = Rc::clone(&shared);
            let factory: TransportFactory = Box::new(move |_params, _ctx| {
                Box::new(FakeTransport(Rc::clone(&for_factory))) as Box<dyn OperatorTransport>
            });
            let mut app = OperatorApp::new(ctx.clone(), factory);
            app.form.session_id = "482-910-337".to_string();
            app.form.password = "secreto".to_string();
            app.connect();
            app.model.scale_mode = ScaleMode::OneToOne;
            shared
                .borrow_mut()
                .events
                .push_back(TransportEvent::Approved {
                    monitors: vec![MonitorDescriptor {
                        index: 0,
                        is_primary: true,
                        origin_x: 0,
                        origin_y: 0,
                        width_px: REMOTE_W,
                        height_px: REMOTE_H,
                        dpi_scale_percent: 100,
                    }],
                });
            shared
                .borrow_mut()
                .events
                .push_back(TransportEvent::Frame(full_update()));
            let mut h = Self {
                ctx,
                app,
                frame: eframe::Frame::_new_kittest(),
                shared,
                time: 0.0,
            };
            for _ in 0..3 {
                h.step(vec![]);
            }
            assert_eq!(*h.app.model.phase(), Phase::Viewing);
            assert!(h.app.texture.is_some());
            h
        }

        fn raw(&mut self, events: Vec<Event>) -> RawInput {
            self.time += 1.0 / 60.0;
            RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(SCREEN_W, SCREEN_H))),
                time: Some(self.time),
                events,
                focused: true,
                ..Default::default()
            }
        }

        /// Un pase completo como el de eframe con la ventana visible: `logic` y luego `ui`.
        fn pass(&mut self, events: Vec<Event>) -> FullOutput {
            let raw = self.raw(events);
            let Self {
                ctx, app, frame, ..
            } = self;
            ctx.run_ui(raw, |ui| {
                app.logic(ui.ctx(), frame);
                app.ui(ui, frame);
            })
        }

        /// Pase completo; devuelve las ordenes de ventana emitidas.
        fn step(&mut self, events: Vec<Event>) -> Vec<ViewportCommand> {
            let mut out = self.pass(events);
            out.textures_delta.clear();
            out.viewport_output
                .remove(&ViewportId::ROOT)
                .map(|v| v.commands)
                .unwrap_or_default()
        }

        /// Ciclo de eframe con la ventana minimizada: solo `logic`, sin pase de UI.
        fn logic_only(&mut self) {
            let mut raw = self.raw(vec![]);
            raw.viewports.insert(
                ViewportId::ROOT,
                ViewportInfo {
                    minimized: Some(true),
                    ..Default::default()
                },
            );
            let Self {
                ctx, app, frame, ..
            } = self;
            let _ = ctx.run_logic(&raw, |ctx| app.logic(ctx, frame));
        }

        fn take_sent(&self) -> Vec<RemoteInputCommand> {
            std::mem::take(&mut self.shared.borrow_mut().sent)
        }

        fn click(&mut self, pos: Pos2) {
            self.step(vec![Event::PointerMoved(pos)]);
            self.step(vec![press(pos, true)]);
            self.step(vec![press(pos, false)]);
        }

        /// Presiona en `from`, arrastra hasta `to` y suelta, con varios pases intermedios.
        fn drag(&mut self, from: Pos2, to: Pos2) {
            self.step(vec![press(from, true)]);
            for i in 1..=4 {
                let p = from + (to - from) * (i as f32 / 4.0);
                self.step(vec![Event::PointerMoved(p)]);
            }
            assert!(
                self.ctx.dragged_id().is_some(),
                "la pulsacion debe estar arrastrando un widget"
            );
            self.step(vec![press(to, false)]);
        }

        /// Deja el puntero quieto en `pos` varios pases (la barra flotante se despliega).
        fn hover(&mut self, pos: Pos2) {
            self.step(vec![Event::PointerMoved(pos)]);
            for _ in 0..30 {
                self.step(vec![]);
            }
        }

        /// Enfoca el lienzo con un clic y descarta lo que ese clic haya enviado.
        fn focus_canvas(&mut self) {
            self.click(pos2(300.0, 300.0));
            assert!(self.app.capture.is_capturing());
            self.take_sent();
        }
    }

    fn press(pos: Pos2, pressed: bool) -> Event {
        Event::PointerButton {
            pos,
            button: PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        }
    }

    /// Ctrl+tecla tal como la entrega egui-winit en Windows (`ctrl` y `command`).
    fn ctrl_key(key: Key, pressed: bool) -> Event {
        Event::Key {
            key,
            physical_key: Some(key),
            pressed,
            repeat: false,
            modifiers: Modifiers::CTRL | Modifiers::COMMAND,
        }
    }

    fn left_button(cmds: &[RemoteInputCommand], state: ButtonState) -> usize {
        cmds.iter()
            .filter(|c| {
                matches!(
                    c,
                    RemoteInputCommand::MouseButton {
                        button: MouseButton::Left,
                        state: s,
                        ..
                    } if *s == state
                )
            })
            .count()
    }

    fn moves(cmds: &[RemoteInputCommand]) -> usize {
        cmds.iter()
            .filter(|c| matches!(c, RemoteInputCommand::MoveCursor { .. }))
            .count()
    }

    #[test]
    fn a_click_on_the_canvas_reaches_the_remote() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        h.click(pos2(400.0, 300.0));
        let sent = h.take_sent();
        assert_eq!(left_button(&sent, ButtonState::Pressed), 1, "{sent:?}");
        assert_eq!(left_button(&sent, ButtonState::Released), 1, "{sent:?}");
        assert!(moves(&sent) >= 1, "{sent:?}");
    }

    #[test]
    fn dragging_on_the_canvas_reaches_the_remote() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        h.drag(pos2(300.0, 300.0), pos2(400.0, 350.0));
        let sent = h.take_sent();
        assert_eq!(left_button(&sent, ButtonState::Pressed), 1, "{sent:?}");
        assert_eq!(left_button(&sent, ButtonState::Released), 1, "{sent:?}");
        assert!(moves(&sent) >= 2, "{sent:?}");
    }

    #[test]
    fn pressing_and_dragging_the_scroll_bars_sends_nothing_to_the_remote() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        let vertical = pos2(SCREEN_W - 4.0, 120.0);
        h.hover(vertical);
        h.take_sent();
        h.drag(vertical, pos2(SCREEN_W - 4.0, 300.0));
        assert_eq!(h.take_sent(), vec![], "barra vertical");

        h.focus_canvas();
        let horizontal = pos2(300.0, SCREEN_H - 4.0);
        h.hover(horizontal);
        h.take_sent();
        h.drag(horizontal, pos2(450.0, SCREEN_H - 4.0));
        assert_eq!(h.take_sent(), vec![], "barra horizontal");
    }

    #[test]
    fn ctrl_q_and_ctrl_zoom_keys_go_to_the_remote_without_closing_or_zooming() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        let zoom = h.ctx.zoom_factor();
        let mut commands = Vec::new();
        for key in [Key::Q, Key::Minus, Key::Plus, Key::Equals] {
            commands.extend(h.step(vec![ctrl_key(key, true)]));
            commands.extend(h.step(vec![ctrl_key(key, false)]));
        }
        commands.extend(h.step(vec![]));
        assert!(h.app.capture.is_capturing());
        assert_eq!(h.ctx.zoom_factor(), zoom);
        assert!(!commands.contains(&ViewportCommand::Close), "{commands:?}");
        assert!(
            !h.take_sent().is_empty(),
            "las teclas deben llegar al remoto"
        );
    }

    #[test]
    fn logic_only_cycles_do_not_accumulate_texture_deltas() {
        let mut h = Harness::viewing();
        let texture_id = h.app.texture.as_ref().unwrap().id();
        for i in 0..200 {
            h.shared
                .borrow_mut()
                .events
                .push_back(TransportEvent::Frame(partial_update(i)));
            h.logic_only();
        }
        let mut pending = h.ctx.tex_manager().write().take_delta();
        let pending_deltas: usize = pending.set.values().map(|d| d.len()).sum();
        pending.clear();
        assert_eq!(
            pending_deltas, 0,
            "deltas de textura pendientes sin pase de UI"
        );
        let merged = h
            .app
            .pending_frame
            .as_ref()
            .expect("un fotograma pendiente");
        assert!(merged.dirty.len() <= MAX_PENDING_RECTS);

        // El siguiente pase visible aplica el unico fotograma pendiente.
        let mut out = h.pass(vec![]);
        let deltas = out
            .textures_delta
            .set
            .get(&texture_id)
            .map_or(0, |d| d.len());
        out.textures_delta.clear();
        assert!((1..=MAX_PENDING_RECTS).contains(&deltas), "{deltas}");
        assert!(h.app.pending_frame.is_none());
    }

    #[test]
    fn release_all_drops_canvas_focus() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        assert!(h.app.capture.release_all().is_empty());
        assert!(!h.app.capture.is_capturing());
    }

    fn pointer(pos: Pos2, button: PointerButton, pressed: bool) -> Event {
        Event::PointerButton {
            pos,
            button,
            pressed,
            modifiers: Modifiers::NONE,
        }
    }

    fn plain_key(key: Key, pressed: bool) -> Event {
        Event::Key {
            key,
            physical_key: Some(key),
            pressed,
            repeat: false,
            modifiers: Modifiers::NONE,
        }
    }

    /// Mueve el puntero de `from` a `to` en varios pases.
    fn move_through(h: &mut Harness, from: Pos2, to: Pos2) {
        for i in 1..=4 {
            let p = from + (to - from) * (i as f32 / 4.0);
            h.step(vec![Event::PointerMoved(p)]);
        }
    }

    #[test]
    fn escape_during_a_canvas_drag_reaches_the_remote_and_keeps_the_drag() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        let start = pos2(300.0, 300.0);
        h.step(vec![press(start, true)]);
        move_through(&mut h, start, pos2(380.0, 340.0));
        assert!(h.ctx.dragged_id().is_some(), "arrastre decidido");
        h.take_sent();

        h.step(vec![plain_key(Key::Escape, true)]);
        h.step(vec![plain_key(Key::Escape, false)]);
        move_through(&mut h, pos2(380.0, 340.0), pos2(420.0, 360.0));
        let sent = h.take_sent();
        let esc_down = keymap::scancode_command(0x01, false, awawa_protocol::KeyState::Down);
        let esc_up = keymap::scancode_command(0x01, false, awawa_protocol::KeyState::Up);
        assert!(sent.contains(&esc_down), "{sent:?}");
        assert!(sent.contains(&esc_up), "{sent:?}");
        assert_eq!(left_button(&sent, ButtonState::Released), 0, "{sent:?}");
        assert!(h.app.capture.is_capturing());
        assert!(moves(&sent) >= 1, "{sent:?}");

        h.step(vec![press(pos2(420.0, 360.0), false)]);
        assert_eq!(left_button(&h.take_sent(), ButtonState::Released), 1);
    }

    /// Parametros que recibio la fabrica de transporte en el ultimo `connect`.
    fn connect_with_mode(
        mode: ConnectMode,
        fingerprint: Option<&str>,
    ) -> (OperatorApp, Rc<RefCell<Vec<ConnectMode>>>) {
        let modes = Rc::new(RefCell::new(Vec::new()));
        let for_factory = Rc::clone(&modes);
        let shared = Rc::new(RefCell::new(Shared::default()));
        let factory: TransportFactory = Box::new(move |params, _ctx| {
            for_factory.borrow_mut().push(params.mode);
            Box::new(FakeTransport(Rc::clone(&shared))) as Box<dyn OperatorTransport>
        });
        let mut app = OperatorApp::new(egui::Context::default(), factory)
            .with_host_key_fingerprint(fingerprint.map(str::to_string));
        app.form.mode = mode;
        app.form.session_id = "482-910-337".to_string();
        app.form.password = "clave-larga-del-equipo".to_string();
        app.connect();
        (app, modes)
    }

    #[test]
    fn unattended_connect_needs_the_pinned_key() {
        let (app, modes) = connect_with_mode(ConnectMode::Unattended, None);
        assert!(modes.borrow().is_empty(), "sin clave fijada no se conecta");
        assert!(app.transport.is_none());
        assert_eq!(app.form_error.as_deref(), Some(UNATTENDED_NEEDS_KEY));
        assert_eq!(*app.model.phase(), Phase::Form);
    }

    #[test]
    fn unattended_connect_with_key_starts_an_unattended_session_and_wipes_the_password() {
        let (app, modes) = connect_with_mode(ConnectMode::Unattended, Some("0102-0304-0506-0708"));
        assert_eq!(*modes.borrow(), vec![ConnectMode::Unattended]);
        assert!(app.model.is_unattended());
        assert!(matches!(app.model.phase(), Phase::Waiting { .. }));
        assert!(app.form.password.is_empty() || app.form.password.chars().all(|c| c == ' '));
    }

    #[test]
    fn on_demand_connect_is_unchanged_with_or_without_a_pinned_key() {
        for key in [None, Some("0102-0304-0506-0708")] {
            let (app, modes) = connect_with_mode(ConnectMode::OnDemand, key);
            assert_eq!(*modes.borrow(), vec![ConnectMode::OnDemand]);
            assert!(!app.model.is_unattended());
        }
    }

    #[test]
    fn moves_keep_flowing_while_dragging_after_a_second_button() {
        let mut h = Harness::viewing();
        h.focus_canvas();
        let start = pos2(300.0, 300.0);
        h.step(vec![press(start, true)]);
        move_through(&mut h, start, pos2(340.0, 320.0));
        let at = pos2(340.0, 320.0);
        h.step(vec![pointer(at, PointerButton::Secondary, true)]);
        h.step(vec![pointer(at, PointerButton::Secondary, false)]);
        h.take_sent();

        move_through(&mut h, at, pos2(420.0, 380.0));
        let sent = h.take_sent();
        assert!(moves(&sent) >= 2, "{sent:?}");

        h.step(vec![press(pos2(420.0, 380.0), false)]);
        assert_eq!(left_button(&h.take_sent(), ButtonState::Released), 1);
    }
}
