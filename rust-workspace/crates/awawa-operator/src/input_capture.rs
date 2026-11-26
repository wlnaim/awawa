//! Captura de entrada del visor: traduce eventos de egui a `RemoteInputCommand`.
//!
//! La captura solo esta activa cuando el lienzo tiene el foco **y** la ventana esta activa. Al
//! perder cualquiera de los dos, `set_focus`/`WindowFocused(false)` devuelven la liberacion de
//! todas las teclas y botones presionados para que no queden pegados en el equipo remoto.
//! Logica pura: recibe eventos ya capturados y no abre ventanas.

use awawa_protocol::{
    ActiveInputTracker, ButtonState, KeyState, MouseButton, RemoteInputCommand,
    VirtualDesktopBounds,
};
use egui::{Event, MouseWheelUnit, PointerButton, Pos2, Rect, Vec2};

use crate::keymap;
use crate::viewport::{self, DesktopRegion, MappedPoint};

/// Unidades de rueda de Windows por muesca (`WHEEL_DELTA`).
const WHEEL_DELTA: f32 = 120.0;
/// Puntos de egui equivalentes a una muesca cuando el desplazamiento llega en puntos.
const POINTS_PER_NOTCH: f32 = 40.0;

/// Geometria del lienzo en el fotograma actual.
#[derive(Debug, Clone, Copy)]
pub struct ViewContext {
    pub image_rect: Rect,
    pub visible: Rect,
    pub region: DesktopRegion,
    pub desktop: VirtualDesktopBounds,
    /// Posicion actual del puntero (para la rueda, cuyos eventos no traen posicion).
    pub hover_pos: Option<Pos2>,
    /// El lienzo es el widget bajo el puntero (no las barras de desplazamiento ni la barra).
    pub pointer_on_canvas: bool,
}

impl ViewContext {
    fn map(&self, pos: Pos2) -> Option<MappedPoint> {
        viewport::map_pointer(
            pos,
            self.image_rect,
            self.visible,
            &self.region,
            &self.desktop,
        )
    }
}

#[derive(Debug)]
pub struct InputCapture {
    canvas_focused: bool,
    window_focused: bool,
    tracker: ActiveInputTracker,
    pressed_buttons: Vec<MouseButton>,
    last_point: Option<MappedPoint>,
    suppress_text: bool,
}

impl Default for InputCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl InputCapture {
    pub fn new() -> Self {
        Self {
            canvas_focused: false,
            window_focused: true,
            tracker: ActiveInputTracker::new(),
            pressed_buttons: Vec::new(),
            last_point: None,
            suppress_text: false,
        }
    }

    pub fn is_capturing(&self) -> bool {
        self.canvas_focused && self.window_focused
    }

    #[cfg(test)]
    pub fn has_pressed_inputs(&self) -> bool {
        self.tracker.has_active_inputs() || !self.pressed_buttons.is_empty()
    }

    /// Informa si el lienzo tiene el foco. Al perderlo devuelve las liberaciones pendientes.
    pub fn set_focus(&mut self, focused: bool) -> Vec<RemoteInputCommand> {
        let was_capturing = self.is_capturing();
        self.canvas_focused = focused;
        if was_capturing && !self.is_capturing() {
            return self.release_pressed();
        }
        Vec::new()
    }

    /// Libera todas las teclas y botones presionados y limpia el estado de la captura, incluido
    /// el foco del lienzo (la siguiente sesion empieza sin capturar).
    pub fn release_all(&mut self) -> Vec<RemoteInputCommand> {
        self.canvas_focused = false;
        self.release_pressed()
    }

    fn release_pressed(&mut self) -> Vec<RemoteInputCommand> {
        self.pressed_buttons.clear();
        self.last_point = None;
        self.suppress_text = false;
        self.tracker.drain_release_commands()
    }

    /// Informa si la ventana esta activa (enfocada y visible, no minimizada). Se llama en cada
    /// ciclo de `App::logic`, que corre aunque no haya pase de UI. Al desactivarse devuelve las
    /// liberaciones pendientes.
    pub fn set_window_active(&mut self, active: bool) -> Vec<RemoteInputCommand> {
        let was_capturing = self.is_capturing();
        self.window_focused = active;
        if was_capturing && !self.is_capturing() {
            return self.release_pressed();
        }
        Vec::new()
    }

    /// Procesa los eventos del fotograma. Sin foco no emite nada (salvo las liberaciones que
    /// provoque la perdida de foco de la ventana).
    pub fn process(&mut self, events: &[Event], view: &ViewContext) -> Vec<RemoteInputCommand> {
        let mut out = Vec::new();
        self.suppress_text = false;
        for event in events {
            if let Event::WindowFocused(focused) = event {
                out.extend(self.set_window_active(*focused));
                continue;
            }
            if !self.is_capturing() {
                continue;
            }
            self.handle(event, view, &mut out);
        }
        out
    }

    fn emit(&mut self, out: &mut Vec<RemoteInputCommand>, cmd: RemoteInputCommand) {
        self.tracker.record_event(&cmd);
        out.push(cmd);
    }

    fn move_to(&mut self, out: &mut Vec<RemoteInputCommand>, point: MappedPoint) {
        if self.last_point.map(|p| p.norm) != Some(point.norm) {
            self.emit(
                out,
                RemoteInputCommand::MoveCursor {
                    norm_x: point.norm.x,
                    norm_y: point.norm.y,
                },
            );
        }
        self.last_point = Some(point);
    }

    fn handle(&mut self, event: &Event, view: &ViewContext, out: &mut Vec<RemoteInputCommand>) {
        match event {
            Event::PointerMoved(pos) => {
                // Con botones presionados los movimientos siguen llegando aunque egui deje de
                // considerar el lienzo bajo el puntero (p. ej. al pulsar un segundo boton).
                if !view.pointer_on_canvas && self.pressed_buttons.is_empty() {
                    return;
                }
                if let Some(point) = view.map(*pos) {
                    self.move_to(out, point);
                }
            }
            Event::PointerButton {
                pos,
                button,
                pressed,
                ..
            } => {
                let Some(button) = map_button(*button) else {
                    return;
                };
                if *pressed {
                    // Un clic sobre las barras de desplazamiento no es del remoto.
                    if !view.pointer_on_canvas {
                        return;
                    }
                    let Some(point) = view.map(*pos) else {
                        return;
                    };
                    self.move_to(out, point);
                    if !self.pressed_buttons.contains(&button) {
                        self.pressed_buttons.push(button);
                    }
                    self.emit(
                        out,
                        RemoteInputCommand::MouseButton {
                            button,
                            state: ButtonState::Pressed,
                            target_x: point.desktop_px.0,
                            target_y: point.desktop_px.1,
                        },
                    );
                } else if self.pressed_buttons.contains(&button) {
                    self.pressed_buttons.retain(|b| *b != button);
                    let point = view.map(*pos).or(self.last_point);
                    if let Some(p) = point {
                        self.move_to(out, p);
                    }
                    let (target_x, target_y) = point.map_or((0, 0), |p| p.desktop_px);
                    self.emit(
                        out,
                        RemoteInputCommand::MouseButton {
                            button,
                            state: ButtonState::Released,
                            target_x,
                            target_y,
                        },
                    );
                }
            }
            Event::MouseWheel { unit, delta, .. } => {
                if !view.pointer_on_canvas || view.hover_pos.and_then(|p| view.map(p)).is_none() {
                    return;
                }
                if let Some(cmd) = wheel_command(*unit, *delta) {
                    self.emit(out, cmd);
                }
            }
            Event::Key {
                key,
                physical_key,
                pressed,
                ..
            } => {
                // Los atajos de portapapeles de egui-winit estan desactivados (ver `main.rs`),
                // asi que Ctrl+C/V/X, Ctrl/Shift+Insert y Shift+Supr llegan como teclas fisicas.
                match keymap::translate_key(*key, *physical_key, *pressed) {
                    Some(cmd) => {
                        self.suppress_text = *pressed;
                        self.emit(out, cmd);
                    }
                    None => self.suppress_text = false,
                }
            }
            Event::Text(text) => {
                if self.suppress_text {
                    self.suppress_text = false;
                    return;
                }
                for c in text.chars() {
                    for state in [KeyState::Down, KeyState::Up] {
                        if let Some(cmd) = keymap::unicode_command(c, state) {
                            self.emit(out, cmd);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn map_button(button: PointerButton) -> Option<MouseButton> {
    Some(match button {
        PointerButton::Primary => MouseButton::Left,
        PointerButton::Secondary => MouseButton::Right,
        PointerButton::Middle => MouseButton::Middle,
        PointerButton::Extra1 => MouseButton::X1,
        PointerButton::Extra2 => MouseButton::X2,
    })
}

/// Convierte el desplazamiento de egui a unidades `WHEEL_DELTA`. El eje horizontal se invierte
/// porque egui indica hacia donde se mueve el contenido y Windows hacia donde gira la rueda.
fn wheel_command(unit: MouseWheelUnit, delta: Vec2) -> Option<RemoteInputCommand> {
    let notches = match unit {
        MouseWheelUnit::Line => 1.0,
        MouseWheelUnit::Point => 1.0 / POINTS_PER_NOTCH,
        MouseWheelUnit::Page => 10.0,
    };
    let to_units = |v: f32| {
        (v * notches * WHEEL_DELTA)
            .round()
            .clamp(-32_767.0, 32_767.0) as i16
    };
    let delta_y = to_units(delta.y);
    let delta_x = to_units(-delta.x);
    if delta_x == 0 && delta_y == 0 {
        return None;
    }
    Some(RemoteInputCommand::MouseWheel { delta_x, delta_y })
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::MonitorDescriptor;
    use egui::{Key, Modifiers, TouchPhase, pos2, vec2};

    fn view() -> ViewContext {
        let ms = [MonitorDescriptor {
            index: 0,
            is_primary: true,
            origin_x: 0,
            origin_y: 0,
            width_px: 1000,
            height_px: 500,
            dpi_scale_percent: 100,
        }];
        let desktop = VirtualDesktopBounds::from_monitors(&ms).unwrap();
        let image_rect = Rect::from_min_size(pos2(0.0, 0.0), vec2(500.0, 250.0));
        ViewContext {
            image_rect,
            visible: image_rect,
            region: DesktopRegion {
                left: 0,
                top: 0,
                width: 1000,
                height: 500,
            },
            desktop,
            hover_pos: Some(pos2(250.0, 125.0)),
            pointer_on_canvas: true,
        }
    }

    fn focused() -> InputCapture {
        let mut c = InputCapture::new();
        assert!(c.set_focus(true).is_empty());
        c
    }

    fn key(k: Key, pressed: bool) -> Event {
        Event::Key {
            key: k,
            physical_key: Some(k),
            pressed,
            repeat: false,
            modifiers: Modifiers::NONE,
        }
    }

    fn button(pos: Pos2, b: PointerButton, pressed: bool) -> Event {
        Event::PointerButton {
            pos,
            button: b,
            pressed,
            modifiers: Modifiers::NONE,
        }
    }

    fn kb(code: u16, ext: bool, state: KeyState) -> RemoteInputCommand {
        keymap::scancode_command(code, ext, state)
    }

    #[test]
    fn nothing_is_captured_without_focus() {
        let mut c = InputCapture::new();
        let events = [
            Event::PointerMoved(pos2(10.0, 10.0)),
            button(pos2(10.0, 10.0), PointerButton::Primary, true),
            key(Key::A, true),
            Event::Text("a".into()),
        ];
        assert!(c.process(&events, &view()).is_empty());
        assert!(!c.has_pressed_inputs());
    }

    #[test]
    fn pointer_move_is_normalized_and_deduplicated() {
        let mut c = focused();
        let out = c.process(
            &[
                Event::PointerMoved(pos2(250.0, 125.0)),
                Event::PointerMoved(pos2(250.0, 125.0)),
            ],
            &view(),
        );
        assert_eq!(out.len(), 1);
        let RemoteInputCommand::MoveCursor { norm_x, norm_y } = out[0] else {
            panic!("se esperaba MoveCursor");
        };
        assert!((i32::from(norm_x) - 32_768).abs() <= 40);
        assert!((i32::from(norm_y) - 32_768).abs() <= 80);
    }

    #[test]
    fn pointer_outside_the_image_is_ignored() {
        let mut c = focused();
        let out = c.process(&[Event::PointerMoved(pos2(600.0, 10.0))], &view());
        assert!(out.is_empty());
        let out = c.process(
            &[button(pos2(600.0, 10.0), PointerButton::Primary, true)],
            &view(),
        );
        assert!(out.is_empty());
        assert!(!c.has_pressed_inputs());
    }

    #[test]
    fn click_sends_move_then_press_with_desktop_pixels_and_release() {
        let mut c = focused();
        let p = pos2(100.0, 50.0);
        let out = c.process(
            &[
                button(p, PointerButton::Primary, true),
                button(p, PointerButton::Primary, false),
            ],
            &view(),
        );
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], RemoteInputCommand::MoveCursor { .. }));
        assert_eq!(
            out[1],
            RemoteInputCommand::MouseButton {
                button: MouseButton::Left,
                state: ButtonState::Pressed,
                target_x: 200,
                target_y: 100,
            }
        );
        assert_eq!(
            out[2],
            RemoteInputCommand::MouseButton {
                button: MouseButton::Left,
                state: ButtonState::Released,
                target_x: 200,
                target_y: 100,
            }
        );
        assert!(!c.has_pressed_inputs());
    }

    #[test]
    fn release_outside_the_image_is_still_forwarded_after_a_press() {
        let mut c = focused();
        c.process(
            &[button(pos2(100.0, 50.0), PointerButton::Secondary, true)],
            &view(),
        );
        let out = c.process(
            &[button(pos2(900.0, 900.0), PointerButton::Secondary, false)],
            &view(),
        );
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            RemoteInputCommand::MouseButton {
                button: MouseButton::Right,
                state: ButtonState::Released,
                target_x: 200,
                target_y: 100,
            }
        ));
    }

    #[test]
    fn release_without_a_prior_press_is_not_sent() {
        let mut c = focused();
        let out = c.process(
            &[button(pos2(100.0, 50.0), PointerButton::Primary, false)],
            &view(),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn losing_canvas_focus_releases_pressed_keys_and_buttons() {
        let mut c = focused();
        c.process(
            &[
                key(Key::ShiftLeft, true),
                key(Key::ArrowLeft, true),
                button(pos2(100.0, 50.0), PointerButton::Primary, true),
            ],
            &view(),
        );
        assert!(c.has_pressed_inputs());
        let out = c.set_focus(false);
        assert!(out.contains(&RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state: ButtonState::Released,
            target_x: 0,
            target_y: 0,
        }));
        assert!(out.contains(&kb(0x2A, false, KeyState::Up)));
        assert!(out.contains(&kb(0x4B, true, KeyState::Up)));
        assert_eq!(out.len(), 3);
        assert!(!c.has_pressed_inputs());
        assert!(!c.is_capturing());
        // Sin foco ya no se captura ni se vuelve a liberar.
        assert!(c.process(&[key(Key::A, true)], &view()).is_empty());
        assert!(c.set_focus(false).is_empty());
    }

    #[test]
    fn losing_window_focus_releases_and_regaining_resumes_capture() {
        let mut c = focused();
        c.process(&[key(Key::ControlLeft, true)], &view());
        let out = c.process(&[Event::WindowFocused(false)], &view());
        assert_eq!(out, vec![kb(0x1D, false, KeyState::Up)]);
        assert!(c.process(&[key(Key::A, true)], &view()).is_empty());
        assert!(c.process(&[Event::WindowFocused(true)], &view()).is_empty());
        assert_eq!(
            c.process(&[key(Key::A, true)], &view()),
            vec![kb(0x1E, false, KeyState::Down)]
        );
    }

    #[test]
    fn window_focus_events_after_the_canvas_lost_focus_do_not_release_twice() {
        let mut c = focused();
        c.process(&[key(Key::A, true)], &view());
        assert_eq!(c.set_focus(false).len(), 1);
        assert!(
            c.process(&[Event::WindowFocused(false)], &view())
                .is_empty()
        );
    }

    #[test]
    fn mapped_key_uses_scancode_and_drops_its_text() {
        let mut c = focused();
        let out = c.process(&[key(Key::A, true), Event::Text("a".into())], &view());
        assert_eq!(out, vec![kb(0x1E, false, KeyState::Down)]);
        let out = c.process(&[key(Key::A, false)], &view());
        assert_eq!(out, vec![kb(0x1E, false, KeyState::Up)]);
    }

    #[test]
    fn text_without_a_mapped_key_goes_as_unicode_down_up() {
        let mut c = focused();
        let out = c.process(&[Event::Text("\u{00F1}".into())], &view());
        assert_eq!(out.len(), 2);
        for (cmd, expected) in out.iter().zip([KeyState::Down, KeyState::Up]) {
            assert_eq!(
                *cmd,
                RemoteInputCommand::Keyboard {
                    scancode: 0,
                    extended: false,
                    unicode_char: Some('\u{00F1}'),
                    state: expected,
                }
            );
        }
        assert!(!c.has_pressed_inputs());
    }

    #[test]
    fn unicode_after_an_unmapped_key_is_not_suppressed() {
        let mut c = focused();
        let out = c.process(
            &[
                Event::Key {
                    key: Key::Pause,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Modifiers::NONE,
                },
                Event::Text("\u{00E1}".into()),
            ],
            &view(),
        );
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn no_command_mixes_scancode_and_unicode_nor_has_neither() {
        let mut c = focused();
        let out = c.process(
            &[
                key(Key::Q, true),
                Event::Text("q".into()),
                Event::Text("\u{00F1}".into()),
                key(Key::Enter, true),
                Event::Text("\n".into()),
                Event::Text("\u{0008}".into()),
            ],
            &view(),
        );
        for cmd in out {
            if let RemoteInputCommand::Keyboard {
                scancode,
                unicode_char,
                ..
            } = cmd
            {
                assert!(
                    (scancode != 0) ^ unicode_char.is_some(),
                    "scancode y Unicode deben ser excluyentes"
                );
            }
        }
    }

    #[test]
    fn clipboard_chords_reach_the_remote_as_physical_keys() {
        let mut c = focused();
        let out = c.process(
            &[
                key(Key::ControlLeft, true),
                key(Key::V, true),
                key(Key::Insert, true),
                key(Key::Delete, true),
            ],
            &view(),
        );
        assert_eq!(
            out,
            vec![
                kb(0x1D, false, KeyState::Down),
                kb(0x2F, false, KeyState::Down),
                kb(0x52, true, KeyState::Down),
                kb(0x53, true, KeyState::Down),
            ]
        );
    }

    #[test]
    fn stray_clipboard_events_never_become_remote_input() {
        let mut c = focused();
        let out = c.process(
            &[Event::Copy, Event::Cut, Event::Paste("secreto".into())],
            &view(),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn window_deactivation_without_a_ui_pass_releases_everything() {
        let mut c = focused();
        c.process(&[key(Key::ShiftLeft, true)], &view());
        // Sin llamar a `process` (no hay pase de UI): solo el ciclo de logica avisa.
        assert_eq!(
            c.set_window_active(false),
            vec![kb(0x2A, false, KeyState::Up)]
        );
        assert!(!c.has_pressed_inputs());
        assert!(c.set_window_active(false).is_empty());
        assert!(!c.is_capturing());
        assert!(c.set_window_active(true).is_empty());
        assert!(c.is_capturing());
    }

    #[test]
    fn a_new_session_captures_after_the_window_is_reported_active() {
        let mut c = InputCapture::new();
        c.set_window_active(false);
        c.set_focus(true);
        assert!(c.process(&[key(Key::A, true)], &view()).is_empty());
        c.set_window_active(true);
        assert_eq!(c.process(&[key(Key::A, true)], &view()).len(), 1);
    }

    #[test]
    fn pointer_not_on_the_canvas_sends_no_moves_presses_or_wheel() {
        let mut c = focused();
        let mut v = view();
        v.pointer_on_canvas = false;
        let p = pos2(100.0, 50.0);
        let wheel = Event::MouseWheel {
            unit: MouseWheelUnit::Line,
            delta: vec2(0.0, 1.0),
            phase: TouchPhase::Move,
            source: egui::MouseWheelSource::Wheel,
            modifiers: Modifiers::NONE,
        };
        let out = c.process(
            &[
                Event::PointerMoved(p),
                button(p, PointerButton::Primary, true),
                wheel,
            ],
            &v,
        );
        assert!(out.is_empty());
        assert!(!c.has_pressed_inputs());
    }

    #[test]
    fn release_after_leaving_the_canvas_is_still_sent() {
        let mut c = focused();
        let p = pos2(100.0, 50.0);
        c.process(&[button(p, PointerButton::Primary, true)], &view());
        let mut v = view();
        v.pointer_on_canvas = false;
        let out = c.process(&[button(p, PointerButton::Primary, false)], &v);
        assert!(out.iter().any(|cmd| matches!(
            cmd,
            RemoteInputCommand::MouseButton {
                state: ButtonState::Released,
                ..
            }
        )));
    }

    #[test]
    fn wheel_requires_pointer_over_the_image_and_converts_units() {
        let mut c = focused();
        let wheel = |unit, delta| Event::MouseWheel {
            unit,
            delta,
            phase: TouchPhase::Move,
            source: egui::MouseWheelSource::Wheel,
            modifiers: Modifiers::NONE,
        };
        let out = c.process(&[wheel(MouseWheelUnit::Line, vec2(0.0, 1.0))], &view());
        assert_eq!(
            out,
            vec![RemoteInputCommand::MouseWheel {
                delta_x: 0,
                delta_y: 120
            }]
        );
        let out = c.process(&[wheel(MouseWheelUnit::Point, vec2(40.0, -80.0))], &view());
        assert_eq!(
            out,
            vec![RemoteInputCommand::MouseWheel {
                delta_x: -120,
                delta_y: -240
            }]
        );
        let mut outside = view();
        outside.hover_pos = Some(pos2(900.0, 900.0));
        assert!(
            c.process(&[wheel(MouseWheelUnit::Line, vec2(0.0, 1.0))], &outside)
                .is_empty()
        );
        outside.hover_pos = None;
        assert!(
            c.process(&[wheel(MouseWheelUnit::Line, vec2(0.0, 1.0))], &outside)
                .is_empty()
        );
    }

    #[test]
    fn tiny_wheel_deltas_round_to_nothing() {
        assert_eq!(wheel_command(MouseWheelUnit::Point, vec2(0.0, 0.1)), None);
    }

    #[test]
    fn release_all_is_idempotent() {
        let mut c = focused();
        c.process(&[key(Key::A, true)], &view());
        assert_eq!(c.release_all().len(), 1);
        assert!(c.release_all().is_empty());
    }
}
