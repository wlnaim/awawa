//! Configuracion protegida del relay del servicio.
//!
//! `awawa-service install --relay <host:puerto> --relay-pin <relay-cert.der>` copia el
//! certificado DER fijado a `%ProgramData%\Awawa\relay.pin` y escribe la direccion
//! (una linea `host:puerto` en UTF-8) en `relay.addr`, ambos con la DACL SY/BA. Al arrancar, el
//! servicio los lee con la misma validacion de ubicacion que el verificador ([`crate::trust`]):
//! un archivo plantado o con DACL laxa deja el servicio sin red (falla cerrado). Sin
//! configuracion el servicio no se registra en ningun relay.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::dpapi_store::{FILE_DACL_SDDL, FileMode, StoreError, create_protected_file};
use crate::trust::{TrustPolicy, validate_location};

pub const ADDR_FILE: &str = "relay.addr";
pub const PIN_FILE: &str = "relay.pin";
/// Tope del certificado fijado (un DER autofirmado ocupa menos de 1 KiB).
pub const MAX_PIN_LEN: usize = 64 * 1024;

/// Direccion y certificado DER fijado del relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySettings {
    pub addr: String,
    pub pin_der: Vec<u8>,
}

/// Comprueba la forma `host:puerto` (puerto 1..=65535) sin resolver nombres.
pub fn validate_addr(addr: &str) -> Result<(), String> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| format!("direccion del relay sin puerto: {addr}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("puerto del relay invalido: {addr}"))?;
    if host.is_empty() || port == 0 || addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("direccion del relay invalida: {addr}"));
    }
    Ok(())
}

/// Archivos de configuracion del relay en un directorio de confianza.
#[derive(Debug, Clone)]
pub struct RelayConfigStore {
    dir: PathBuf,
    dacl: String,
    policy: TrustPolicy,
}

impl RelayConfigStore {
    /// Produccion: DACL SY/BA y politica SYSTEM/Administradores.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self::with_policy(dir, FILE_DACL_SDDL, TrustPolicy::production())
    }

    pub fn with_policy(dir: impl Into<PathBuf>, sddl: &str, policy: TrustPolicy) -> Self {
        Self {
            dir: dir.into(),
            dacl: sddl.to_owned(),
            policy,
        }
    }

    /// Escribe la configuracion (sustituye la anterior). Solo `install` (administrador).
    pub fn save(&self, settings: &RelaySettings) -> Result<(), StoreError> {
        validate_addr(&settings.addr).map_err(StoreError::Io)?;
        if settings.pin_der.is_empty() || settings.pin_der.len() > MAX_PIN_LEN {
            return Err(StoreError::Io(
                "certificado del relay vacio o demasiado grande".into(),
            ));
        }
        validate_location(&self.dir, &self.policy)?;
        self.write(PIN_FILE, &settings.pin_der)?;
        self.write(ADDR_FILE, settings.addr.as_bytes())
    }

    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let target = self.dir.join(name);
        let temp = self.dir.join(format!("{name}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&temp);
        let written = (|| -> Result<(), StoreError> {
            let mut file = create_protected_file(&temp, &self.dacl, FileMode::CreateNew)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            validate_location(&temp, &self.policy)?;
            std::fs::rename(&temp, &target)?;
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }

    /// Lee la configuracion. `Ok(None)` si no hay ninguno de los dos archivos; error si falta uno,
    /// la ubicacion no es de confianza o el contenido no es valido.
    pub fn load(&self) -> Result<Option<RelaySettings>, StoreError> {
        let addr_path = self.dir.join(ADDR_FILE);
        let pin_path = self.dir.join(PIN_FILE);
        let exists = |p: &Path| std::fs::symlink_metadata(p).is_ok();
        match (exists(&addr_path), exists(&pin_path)) {
            (false, false) => return Ok(None),
            (true, true) => {}
            _ => return Err(StoreError::Io("configuracion del relay incompleta".into())),
        }
        validate_location(&self.dir, &self.policy)?;
        validate_location(&addr_path, &self.policy)?;
        validate_location(&pin_path, &self.policy)?;
        let addr = String::from_utf8(std::fs::read(&addr_path)?)
            .map_err(|_| StoreError::Io("relay.addr no es UTF-8".into()))?
            .trim()
            .to_string();
        validate_addr(&addr).map_err(StoreError::Io)?;
        let pin_der = std::fs::read(&pin_path)?;
        if pin_der.is_empty() || pin_der.len() > MAX_PIN_LEN {
            return Err(StoreError::Io("relay.pin vacio o demasiado grande".into()));
        }
        Ok(Some(RelaySettings { addr, pin_der }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};

    #[test]
    fn guarda_y_lee_con_validacion() {
        let tmp = TempDir::new("relaycfg");
        let dir = safe_dir(&tmp);
        let store = RelayConfigStore::with_policy(&dir, &test_file_dacl(), test_policy());
        assert_eq!(store.load().unwrap(), None);
        let settings = RelaySettings {
            addr: "relay.example:4433".into(),
            pin_der: vec![0x30, 0x82, 1, 2],
        };
        store.save(&settings).unwrap();
        assert_eq!(store.load().unwrap(), Some(settings.clone()));
        // Reinstalar sustituye la configuracion.
        let other = RelaySettings {
            addr: "127.0.0.1:5000".into(),
            pin_der: vec![9; 10],
        };
        store.save(&other).unwrap();
        assert_eq!(store.load().unwrap(), Some(other));
    }

    #[test]
    fn rechaza_direcciones_invalidas_y_configuracion_incompleta() {
        for bad in ["sin-puerto", "host:0", ":4433", "host:99999", "ho st:1"] {
            assert!(validate_addr(bad).is_err(), "{bad}");
        }
        assert!(validate_addr("[::1]:4433").is_ok());
        let tmp = TempDir::new("relaycfg-bad");
        let dir = safe_dir(&tmp);
        let store = RelayConfigStore::with_policy(&dir, &test_file_dacl(), test_policy());
        create_protected_file(&dir.join(ADDR_FILE), &test_file_dacl(), FileMode::CreateNew)
            .unwrap();
        assert!(store.load().is_err());
    }
}
