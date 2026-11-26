//! Pantalla de presentacion de Awawa (3 s) e icono de las ventanas.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Tiempo que se muestra la imagen antes de la interfaz normal.
const SPLASH_DURATION: Duration = Duration::from_secs(3);
const SPLASH_PNG: &[u8] = include_bytes!("../../../assets/awawa-hacker.png");
/// Entrada de 128x128 del icono `awawa-hacker.ico`.
const ICON_PNG: &[u8] = include_bytes!("../../../assets/awawa-icon-128.png");

/// `true` mientras no se cumplan los 3 s desde el primer cuadro.
fn splash_visible(elapsed: Duration) -> bool {
    elapsed < SPLASH_DURATION
}

/// Icono de ventana; se decodifica una sola vez por proceso.
pub fn window_icon() -> Arc<egui::IconData> {
    static ICON: OnceLock<Arc<egui::IconData>> = OnceLock::new();
    ICON.get_or_init(|| {
        Arc::new(eframe::icon_data::from_png_bytes(ICON_PNG).expect("icono embebido valido"))
    })
    .clone()
}

#[derive(Default)]
pub struct Splash {
    started: Option<Instant>,
    texture: Option<egui::TextureHandle>,
    done: bool,
}

impl Splash {
    /// Pinta la imagen mientras dure la presentacion y devuelve `true`; despues devuelve `false`.
    pub fn show(&mut self, ui: &mut egui::Ui) -> bool {
        if self.done {
            return false;
        }
        let started = *self.started.get_or_insert_with(Instant::now);
        let elapsed = started.elapsed();
        if !splash_visible(elapsed) {
            self.done = true;
            self.texture = None;
            ui.ctx().request_repaint();
            return false;
        }
        if self.texture.is_none() {
            match eframe::icon_data::from_png_bytes(SPLASH_PNG) {
                Ok(img) => {
                    let image = egui::ColorImage::from_rgba_unmultiplied(
                        [img.width as usize, img.height as usize],
                        &img.rgba,
                    );
                    self.texture = Some(ui.ctx().load_texture(
                        "awawa-splash",
                        image,
                        egui::TextureOptions::LINEAR,
                    ));
                }
                Err(_) => {
                    self.done = true;
                    return false;
                }
            }
        }
        if let Some(texture) = &self.texture {
            egui::CentralPanel::default().show(ui, |ui| {
                let size = ui.available_size();
                ui.centered_and_justified(|ui| {
                    ui.add(egui::Image::from_texture(texture).fit_to_exact_size(size));
                });
            });
        }
        ui.ctx()
            .request_repaint_after(SPLASH_DURATION.saturating_sub(elapsed));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splash_dura_exactamente_tres_segundos() {
        assert!(splash_visible(Duration::ZERO));
        assert!(splash_visible(Duration::from_millis(2999)));
        assert!(!splash_visible(Duration::from_secs(3)));
        assert!(!splash_visible(Duration::from_secs(4)));
    }
}
