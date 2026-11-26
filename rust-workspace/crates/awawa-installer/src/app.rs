//! Asistente grafico (eframe/egui): elegir rol, opciones, ejecutar el plan en un hilo aparte y mostrar
//! el resultado. La contrasena desatendida vive solo en memoria: se mueve a `Secrets` al instalar y los
//! campos se borran (`zeroize`) al enviarla y al cerrar. El historial de deshacer de sus `TextEdit`
//! se vacia en cada cuadro y al enviar. Limitacion: las reasignaciones del `String` mientras se
//! escribe pueden dejar copias liberadas sin borrar.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use awawa_service::admin_pipe::password_len_ok;
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::connection::{self, ConnectionInfo};
use crate::paths::Layout;
use crate::plan::{self, Action, HostOptions, OperatorOptions, UninstallOptions};
use crate::real::RealSystem;
use crate::splash::{self, Splash};
use crate::system::{Outcome, Secrets, run_plan};
use crate::{ipv4, payload};

const TITLE: &str = "Awawa - Instalador";

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(TITLE)
            .with_icon(splash::window_icon())
            .with_inner_size([640.0, 600.0])
            .with_min_inner_size([520.0, 440.0]),
        ..Default::default()
    };
    eframe::run_native(
        TITLE,
        options,
        Box::new(|_cc| Ok(Box::new(InstallerApp::new()))),
    )
}

fn password_id() -> egui::Id {
    egui::Id::unique("installer_password")
}

fn confirm_id() -> egui::Id {
    egui::Id::unique("installer_password_confirm")
}

/// Vacia el historial de deshacer de los dos campos de contrasena (como el formulario del operador).
fn clear_password_undo(ctx: &egui::Context) {
    for id in [password_id(), confirm_id()] {
        if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
            state.clear_undoer();
            state.store(ctx, id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Role,
    Host,
    Operator,
    Maintenance,
    Running,
    Finished,
}

enum WorkerMsg {
    Line(String),
    Done(Result<Outcome, String>),
}

struct InstallerApp {
    layout: Result<Layout, String>,
    screen: Screen,
    splash: Splash,
    // Host
    unattended: bool,
    autostart: bool,
    ips: Vec<String>,
    relay_host: String,
    out_path: String,
    password: String,
    confirm: String,
    // Operador
    use_file: bool,
    conn_path: String,
    manual_relay: String,
    manual_pin: String,
    manual_key: String,
    imported: Option<ConnectionInfo>,
    // Mantenimiento
    keep_data: bool,
    // Comun
    error: Option<String>,
    job: &'static str,
    log: Vec<String>,
    rx: Option<Receiver<WorkerMsg>>,
    result: Option<Result<Outcome, String>>,
    log_path: PathBuf,
}

impl Drop for InstallerApp {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm.zeroize();
    }
}

impl InstallerApp {
    fn new() -> Self {
        let layout = Layout::detect();
        let ips: Vec<String> = ipv4::local_ipv4().iter().map(ToString::to_string).collect();
        let out_path = layout
            .as_ref()
            .map(|l| l.default_connection_file().display().to_string())
            .unwrap_or_default();
        Self {
            layout,
            screen: Screen::Role,
            splash: Splash::default(),
            unattended: false,
            autostart: false,
            relay_host: ips.first().cloned().unwrap_or_default(),
            ips,
            out_path,
            password: String::new(),
            confirm: String::new(),
            use_file: true,
            conn_path: String::new(),
            manual_relay: String::new(),
            manual_pin: String::new(),
            manual_key: String::new(),
            imported: None,
            keep_data: true,
            error: None,
            job: "",
            log: Vec::new(),
            rx: None,
            result: None,
            log_path: PathBuf::new(),
        }
    }

    fn start(
        &mut self,
        ctx: &egui::Context,
        job: &'static str,
        plan: Vec<Action>,
        secrets: Secrets,
    ) {
        let Ok(layout) = self.layout.clone() else {
            return;
        };
        let log_path = layout.new_log_file();
        self.log_path = log_path.clone();
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&log_path)
                .ok();
            let stamp = || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            };
            let mut log = |line: &str| {
                if let Some(f) = file.as_mut() {
                    let _ = writeln!(f, "{} {line}", stamp());
                }
                let _ = tx.send(WorkerMsg::Line(line.to_owned()));
                ctx.request_repaint();
            };
            log(&format!(
                "=== Awawa-Setup {} - {job} ===",
                env!("CARGO_PKG_VERSION")
            ));
            let mut sys = RealSystem::new(&layout);
            let result = run_plan(&plan, &mut sys, &secrets, &mut log);
            drop(secrets);
            let _ = tx.send(WorkerMsg::Done(result));
            ctx.request_repaint();
        });
        self.job = job;
        self.log.clear();
        self.result = None;
        self.error = None;
        self.rx = Some(rx);
        self.screen = Screen::Running;
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.rx else { return };
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMsg::Line(line) => self.log.push(line),
                WorkerMsg::Done(result) => {
                    self.result = Some(result);
                    self.screen = Screen::Finished;
                }
            }
        }
        if self.screen == Screen::Finished {
            self.rx = None;
        }
    }

    fn install_host(&mut self, ctx: &egui::Context) -> Result<(), String> {
        let layout = self.layout.clone()?;
        let public_relay = plan::public_relay_addr(&self.relay_host)?;
        let mut connection_file = PathBuf::from(self.out_path.trim());
        if connection_file.is_dir() {
            connection_file.push(connection::DEFAULT_FILE_NAME);
        }
        if self.unattended {
            if !password_len_ok(&self.password) {
                return Err("la contrasena debe tener entre 12 y 128 caracteres".into());
            }
            if self.password != self.confirm {
                return Err("las contrasenas no coinciden".into());
            }
        }
        let opts = HostOptions {
            unattended: self.unattended,
            autostart: self.autostart,
            public_relay,
            connection_file,
        };
        let plan = plan::host_plan(&layout, &opts)?;
        let secrets = Secrets {
            password: self
                .unattended
                .then(|| Zeroizing::new(std::mem::take(&mut self.password))),
        };
        self.password.zeroize();
        self.confirm.zeroize();
        clear_password_undo(ctx);
        self.start(ctx, "Host", plan, secrets);
        Ok(())
    }

    fn import(&mut self) -> Result<(), String> {
        let info = if self.use_file {
            connection::load_file(&PathBuf::from(self.conn_path.trim()))?
        } else {
            let key = self.manual_key.trim();
            connection::from_files(
                &self.manual_relay,
                &PathBuf::from(self.manual_pin.trim()),
                (!key.is_empty()).then(|| PathBuf::from(key)).as_deref(),
            )?
        };
        self.imported = Some(info);
        Ok(())
    }

    fn install_operator(&mut self, ctx: &egui::Context) -> Result<(), String> {
        let layout = self.layout.clone()?;
        let connection = self
            .imported
            .clone()
            .ok_or("primero cargue el archivo de conexion o los datos manuales")?;
        let plan = plan::operator_plan(&layout, &OperatorOptions { connection })?;
        self.start(ctx, "Agente de soporte", plan, Secrets::default());
        Ok(())
    }

    fn uninstall(&mut self, ctx: &egui::Context) -> Result<(), String> {
        let layout = self.layout.clone()?;
        let plan = plan::uninstall_plan(
            &layout,
            UninstallOptions {
                keep_data: self.keep_data,
            },
        );
        self.start(ctx, "Desinstalar", plan, Secrets::default());
        Ok(())
    }

    fn can_install(&self) -> bool {
        payload::is_present() && self.layout.is_ok()
    }

    fn show_error(&self, ui: &mut egui::Ui) {
        if let Some(e) = &self.error {
            ui.colored_label(egui::Color32::from_rgb(200, 40, 40), e);
        }
    }

    fn role_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Que desea hacer en este equipo?");
        ui.add_space(8.0);
        if ui
            .button("Equipo que recibe soporte (Host)")
            .on_hover_text("awawa-host + relay local; acceso desatendido opcional")
            .clicked()
        {
            self.screen = Screen::Host;
        }
        ui.label("Recibe conexiones remotas. Incluye el relay en este mismo equipo.");
        ui.add_space(8.0);
        if ui.button("Agente de soporte (operador)").clicked() {
            self.screen = Screen::Operator;
        }
        ui.label("Se conecta al Host con el archivo de conexion que este genera.");
        ui.add_space(8.0);
        if ui
            .button("Mantenimiento (reconfigurar o desinstalar)")
            .clicked()
        {
            self.screen = Screen::Maintenance;
        }
    }

    fn host_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Equipo que recibe soporte (Host)");
        ui.label("Instala awawa-host y el relay (UDP 4433, tarea al iniciar el sistema como LOCAL SERVICE).");
        ui.add_space(6.0);
        ui.checkbox(&mut self.autostart, "Abrir awawa-host al iniciar sesion");
        ui.checkbox(
            &mut self.unattended,
            "Acceso desatendido (servicio de Windows con contrasena persistente)",
        );
        if self.unattended {
            egui::Grid::new("pw").num_columns(2).show(ui, |ui| {
                ui.label("Contrasena (12-128):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .id(password_id())
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
                ui.label("Confirmar:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.confirm)
                        .id(confirm_id())
                        .password(true)
                        .desired_width(260.0),
                );
                ui.end_row();
            });
            // Sin historial de deshacer: sus copias del texto no se podrian borrar.
            clear_password_undo(ui.ctx());
        }
        ui.add_space(6.0);
        ui.label("Direccion de este equipo para el otro equipo (IPv4 o nombre):");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("ips")
                .selected_text("IPv4 detectadas")
                .show_ui(ui, |ui| {
                    for ip in &self.ips {
                        ui.selectable_value(&mut self.relay_host, ip.clone(), ip);
                    }
                });
            ui.add(egui::TextEdit::singleline(&mut self.relay_host).desired_width(200.0));
            ui.label(":4433");
        });
        ui.label("Archivo de conexion a generar:");
        ui.add(egui::TextEdit::singleline(&mut self.out_path).desired_width(f32::INFINITY));
        ui.add_space(8.0);
        self.show_error(ui);
        ui.horizontal(|ui| {
            if ui.button("Atras").clicked() {
                self.error = None;
                self.screen = Screen::Role;
            }
            if ui
                .add_enabled(self.can_install(), egui::Button::new("Instalar"))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                if let Err(e) = self.install_host(&ctx) {
                    self.error = Some(e);
                }
            }
        });
    }

    fn operator_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Agente de soporte (operador)");
        ui.radio_value(
            &mut self.use_file,
            true,
            "Importar el archivo de conexion del Host (.rrs)",
        );
        ui.radio_value(&mut self.use_file, false, "Introducir los datos a mano");
        if self.use_file {
            ui.label("Ruta del archivo .rrs:");
            ui.add(egui::TextEdit::singleline(&mut self.conn_path).desired_width(f32::INFINITY));
        } else {
            egui::Grid::new("manual").num_columns(2).show(ui, |ui| {
                ui.label("Relay (ip:4433):");
                ui.text_edit_singleline(&mut self.manual_relay);
                ui.end_row();
                ui.label("Pin (relay-cert.der):");
                ui.text_edit_singleline(&mut self.manual_pin);
                ui.end_row();
                ui.label("Clave del host (opcional, 32 bytes):");
                ui.text_edit_singleline(&mut self.manual_key);
                ui.end_row();
            });
        }
        if ui.button("Cargar y validar").clicked() {
            self.imported = None;
            self.error = self.import().err();
        }
        if let Some(info) = &self.imported {
            ui.separator();
            ui.label(format!("Relay: {}", info.relay_addr));
            ui.label(format!(
                "Huella del pin: {}",
                connection::pin_fingerprint(&info.relay_pin)
            ));
            match &info.host {
                Some(host) => ui.label(format!(
                    "Equipo desatendido: ID {} | huella de la clave {}",
                    host.id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "(sin ID)".into()),
                    connection::host_key_fingerprint(&host.key)
                )),
                None => ui.label("Sin clave de equipo desatendido (solo bajo demanda)."),
            };
            ui.label("Compare las huellas con las que muestra el Host.");
        }
        ui.add_space(8.0);
        self.show_error(ui);
        ui.horizontal(|ui| {
            if ui.button("Atras").clicked() {
                self.error = None;
                self.screen = Screen::Role;
            }
            let ready = self.can_install() && self.imported.is_some();
            if ui
                .add_enabled(ready, egui::Button::new("Instalar"))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                if let Err(e) = self.install_operator(&ctx) {
                    self.error = Some(e);
                }
            }
        });
    }

    fn maintenance_screen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Mantenimiento");
        ui.label("Reconfigurar: vuelva a elegir un rol; la instalacion existente se actualiza.");
        if ui.button("Reconfigurar").clicked() {
            self.screen = Screen::Role;
        }
        ui.separator();
        ui.label("Desinstalar: quita accesos directos, la tarea del relay, el servicio, la regla de firewall y los archivos de Program Files.");
        ui.checkbox(
            &mut self.keep_data,
            "Conservar %ProgramData%\\Awawa y Awawa-Relay (verificador, identidad y clave del relay)",
        );
        self.show_error(ui);
        ui.horizontal(|ui| {
            if ui.button("Atras").clicked() {
                self.screen = Screen::Role;
            }
            if ui
                .add_enabled(self.layout.is_ok(), egui::Button::new("Desinstalar"))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                if let Err(e) = self.uninstall(&ctx) {
                    self.error = Some(e);
                }
            }
        });
    }

    fn log_view(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .max_height(260.0)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.monospace(line);
                }
            });
    }

    fn finished_screen(&mut self, ui: &mut egui::Ui) {
        match &self.result {
            Some(Ok(outcome)) => {
                ui.heading(format!("{}: completado", self.job));
                if let (Some(path), Some(info)) = (&outcome.connection_file, &outcome.connection) {
                    ui.label("Archivo de conexion para el otro equipo:");
                    ui.monospace(path.display().to_string());
                    ui.label(format!("Relay: {}", info.relay_addr));
                    ui.label(format!(
                        "Huella del pin: {}",
                        connection::pin_fingerprint(&info.relay_pin)
                    ));
                    if let Some(host) = &info.host {
                        ui.label(format!(
                            "ID del equipo: {} | huella de la clave: {}",
                            host.id.map(|id| id.to_string()).unwrap_or_default(),
                            connection::host_key_fingerprint(&host.key)
                        ));
                    }
                    ui.label("Copie el archivo al otro equipo y ejecute alli este instalador con el rol Agente de soporte.");
                }
            }
            Some(Err(e)) => {
                ui.heading(format!("{}: con errores", self.job));
                ui.colored_label(egui::Color32::from_rgb(200, 40, 40), e);
            }
            None => {}
        }
        ui.label(format!("Registro: {}", self.log_path.display()));
        self.log_view(ui);
        ui.horizontal(|ui| {
            if ui.button("Volver al inicio").clicked() {
                self.imported = None;
                self.screen = Screen::Role;
            }
            if ui.button("Cerrar").clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }
}

impl eframe::App for InstallerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.splash.show(ui) {
            return;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            if let Err(e) = &self.layout {
                ui.colored_label(egui::Color32::from_rgb(200, 40, 40), format!("No se pudieron leer las carpetas del sistema: {e}"));
            }
            if !payload::is_present() {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 120, 0),
                    "Instalador de desarrollo sin carga: no puede instalar. Use dist\\Awawa-Setup-<version>.exe (scripts\\package.ps1).",
                );
                ui.separator();
            }
            match self.screen {
                Screen::Role => self.role_screen(ui),
                Screen::Host => self.host_screen(ui),
                Screen::Operator => self.operator_screen(ui),
                Screen::Maintenance => self.maintenance_screen(ui),
                Screen::Running => {
                    ui.heading(format!("{}: en curso...", self.job));
                    ui.label("No cierre esta ventana.");
                    self.log_view(ui);
                }
                Screen::Finished => self.finished_screen(ui),
            }
        });
    }
}
