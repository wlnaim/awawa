//! Ayudas de prueba: directorio temporal unico que se elimina al terminar, y DACL/politica de prueba.
//! Las pruebas corren sin elevar: el usuario actual se agrega como titular de confianza.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dpapi_store::ensure_protected_dir_with;
use crate::identity::current_user_sid_string;
use crate::trust::TrustPolicy;

pub(crate) fn current_sid() -> String {
    current_user_sid_string().expect("SID del usuario actual")
}

/// DACL de archivos de prueba: SYSTEM, Administradores y el usuario actual.
pub(crate) fn test_file_dacl() -> String {
    format!("D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", current_sid())
}

/// DACL de directorios de prueba (heredable).
pub(crate) fn test_dir_dacl() -> String {
    format!(
        "D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        current_sid()
    )
}

/// Politica de pruebas: produccion mas el usuario actual.
pub(crate) fn test_policy() -> TrustPolicy {
    TrustPolicy::production().with_trustee(&current_sid())
}

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("rrs-test-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("crear directorio temporal");
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Subdirectorio "safe" creado con DACL protegida y validado: ubicacion de confianza para las pruebas.
pub(crate) fn safe_dir(tmp: &TempDir) -> PathBuf {
    let dir = tmp.path().join("safe");
    ensure_protected_dir_with(&dir, &test_dir_dacl(), &test_policy()).expect("directorio seguro");
    dir
}
