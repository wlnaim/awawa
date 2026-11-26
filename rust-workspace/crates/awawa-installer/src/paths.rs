//! Rutas del instalador. En produccion salen de las carpetas conocidas de Windows
//! (`SHGetKnownFolderPath`); las pruebas usan `Layout::for_tests`.

use std::path::{Path, PathBuf};

/// Carpeta de datos del relay. Es hermana de `%ProgramData%\Awawa` y no hija: el relay
/// corre como LOCAL SERVICE y su `relay-key.der` queda con ese dueno; dentro de
/// `Awawa` haria fallar `awawa-service install`, que exige dueno SYSTEM o
/// Administradores en todo el arbol (`harden_protected_dir`).
pub const RELAY_DATA_DIR_NAME: &str = "Awawa-Relay";
pub const SERVICE_DATA_DIR_NAME: &str = "Awawa";
pub const INSTALL_DIR_NAME: &str = "Awawa";
pub const START_MENU_DIR_NAME: &str = "Awawa";
pub const LOG_FILE_PREFIX: &str = "Awawa-Setup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// `%ProgramFiles%\Awawa`.
    pub install_dir: PathBuf,
    /// `%ProgramData%\Awawa` (verificador, identidad, configuracion del servicio).
    pub service_data_dir: PathBuf,
    /// `%ProgramData%\Awawa-Relay` (identidad del relay).
    pub relay_data_dir: PathBuf,
    /// `...\Start Menu\Programs\Awawa` (todos los usuarios).
    pub start_menu_dir: PathBuf,
    /// Escritorio publico.
    pub public_desktop: PathBuf,
    /// Carpeta Inicio comun (al iniciar sesion).
    pub common_startup: PathBuf,
    /// Escritorio del usuario que ejecuta el instalador (destino por defecto del archivo de conexion).
    pub user_desktop: PathBuf,
    /// `%SystemRoot%\System32` (netsh, schtasks).
    pub system32: PathBuf,
    /// Temporal del usuario (registro del instalador).
    pub temp_dir: PathBuf,
}

impl Layout {
    pub fn detect() -> Result<Self, String> {
        let program_files = known::program_files()?;
        let program_data = known::program_data()?;
        Ok(Self {
            install_dir: program_files.join(INSTALL_DIR_NAME),
            service_data_dir: program_data.join(SERVICE_DATA_DIR_NAME),
            relay_data_dir: program_data.join(RELAY_DATA_DIR_NAME),
            start_menu_dir: known::common_programs()?.join(START_MENU_DIR_NAME),
            public_desktop: known::public_desktop()?,
            common_startup: known::common_startup()?,
            user_desktop: known::user_desktop()?,
            system32: known::system32()?,
            temp_dir: std::env::temp_dir(),
        })
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            install_dir: r"C:\Program Files\Awawa".into(),
            service_data_dir: r"C:\ProgramData\Awawa".into(),
            relay_data_dir: r"C:\ProgramData\Awawa-Relay".into(),
            start_menu_dir: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Awawa".into(),
            public_desktop: r"C:\Users\Public\Desktop".into(),
            common_startup: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp".into(),
            user_desktop: r"C:\Users\Prueba\Desktop".into(),
            system32: r"C:\Windows\System32".into(),
            temp_dir: r"C:\Users\Prueba\AppData\Local\Temp".into(),
        }
    }

    pub fn exe(&self, name: &str) -> PathBuf {
        self.install_dir.join(name)
    }

    pub fn relay_cert(&self) -> PathBuf {
        self.relay_data_dir.join("relay-cert.der")
    }

    /// Carpeta de los datos importados por el Agente de soporte (solo escribible por Administradores).
    pub fn operator_conn_dir(&self) -> PathBuf {
        self.install_dir.join("conexion")
    }

    pub fn tool(&self, name: &str) -> PathBuf {
        self.system32.join(name)
    }

    /// Registro de una ejecucion: nombre no predecible (hora en ms y PID); se abre con `create_new`,
    /// que falla si ya existe algo con ese nombre (no sigue un enlace plantado).
    pub fn new_log_file(&self) -> PathBuf {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        self.temp_dir
            .join(format!("{LOG_FILE_PREFIX}-{ms}-{}.log", std::process::id()))
    }

    pub fn default_connection_file(&self) -> PathBuf {
        self.user_desktop.join(crate::connection::DEFAULT_FILE_NAME)
    }

    pub fn shortcut(&self, dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("{name}.lnk"))
    }
}

mod known {
    use std::path::PathBuf;

    use crate::win32::{
        FOLDERID_COMMON_PROGRAMS, FOLDERID_COMMON_STARTUP, FOLDERID_DESKTOP, FOLDERID_PROGRAM_DATA,
        FOLDERID_PROGRAM_FILES_X64, FOLDERID_PUBLIC_DESKTOP, FOLDERID_SYSTEM, known_folder,
    };

    pub fn program_files() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_PROGRAM_FILES_X64, "Program Files")
    }
    pub fn program_data() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_PROGRAM_DATA, "ProgramData")
    }
    pub fn common_programs() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_COMMON_PROGRAMS, "menu Inicio")
    }
    pub fn common_startup() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_COMMON_STARTUP, "Inicio comun")
    }
    pub fn public_desktop() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_PUBLIC_DESKTOP, "escritorio publico")
    }
    pub fn user_desktop() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_DESKTOP, "escritorio")
    }
    pub fn system32() -> Result<PathBuf, String> {
        known_folder(&FOLDERID_SYSTEM, "System32")
    }
}
