//! Operaciones de administrador sobre la contrasena desatendida persistente: configurar, cambiar, revocar, consultar.
//!
//! Cada operacion carga el estado desde el almacen, aplica la regla de dominio de `awawa-protocol`,
//! persiste el registro y audita el hecho SIN la contrasena (solo la generacion). La verificacion de que el
//! invocador es administrador la hace el binario llamador.

use core::fmt;

use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, AuditSinkError};
use awawa_protocol::unattended::{
    PasswordKdf, UnattendedCredentialState, UnattendedError, UnattendedStatus,
};

use crate::dpapi_store::{StoreError, VerifierFileStore};
use crate::winutil::unix_ms_now;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    Store(StoreError),
    Unattended(UnattendedError),
    /// El cambio se aplico y persistio, pero no se pudo registrar en la auditoria.
    AuditAfterChange(AuditSinkError),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "{e}"),
            Self::Unattended(e) => write!(f, "{e}"),
            Self::AuditAfterChange(e) => {
                write!(f, "el cambio se aplico pero la auditoria fallo: {e}")
            }
        }
    }
}

impl std::error::Error for AdminError {}

impl From<StoreError> for AdminError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<UnattendedError> for AdminError {
    fn from(e: UnattendedError) -> Self {
        Self::Unattended(e)
    }
}

/// Contexto de las operaciones: almacen, KDF, destino de auditoria y nombre del operador a registrar.
pub struct AdminOps<'a> {
    pub store: &'a VerifierFileStore,
    pub kdf: &'a dyn PasswordKdf,
    pub sink: &'a mut dyn AuditSink,
    pub operator: &'a str,
}

impl AdminOps<'_> {
    fn load_state(&self) -> Result<UnattendedCredentialState, AdminError> {
        Ok(match self.store.load()? {
            Some(record) => UnattendedCredentialState::from_record(record),
            None => UnattendedCredentialState::not_configured(),
        })
    }

    /// Bloqueo exclusivo entre procesos para toda la operacion cargar-modificar-guardar-auditar.
    fn lock(&self) -> Result<crate::dpapi_store::StoreLock, AdminError> {
        Ok(self.store.lock()?)
    }

    fn persist_and_audit(
        &mut self,
        state: &UnattendedCredentialState,
        event: AuditEvent,
    ) -> Result<(), AdminError> {
        if let Some(record) = state.record() {
            self.store.save(record)?;
        }
        let audit = AuditRecord::new(unix_ms_now(), event, self.operator);
        self.sink
            .write_record(&audit)
            .map_err(AdminError::AuditAfterChange)
    }

    /// Configura la contrasena (primera vez o tras revocar). Devuelve la generacion.
    pub fn set_password(&mut self, password: &str) -> Result<u32, AdminError> {
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        let generation = state.configure(password, self.kdf)?;
        self.persist_and_audit(&state, AuditEvent::PasswordConfigured { generation })?;
        Ok(generation)
    }

    /// Cambia la contrasena activa; la anterior deja de verificar. Devuelve la generacion.
    pub fn change_password(&mut self, password: &str) -> Result<u32, AdminError> {
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        let generation = state.rotate(password, self.kdf)?;
        self.persist_and_audit(&state, AuditEvent::PasswordRotated { generation })?;
        Ok(generation)
    }

    /// Revoca la contrasena: se guarda el registro revocado (sin salt ni clave derivada).
    pub fn revoke_password(&mut self) -> Result<u32, AdminError> {
        let _lock = self.lock()?;
        let mut state = self.load_state()?;
        let generation = state.revoke()?;
        self.persist_and_audit(&state, AuditEvent::PasswordRevoked { generation })?;
        Ok(generation)
    }

    pub fn status(&self) -> Result<UnattendedStatus, AdminError> {
        Ok(self.load_state()?.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_sink::JsonLinesFileSink;
    use crate::dpapi_store::ensure_protected_dir;
    use crate::kdf_argon2::ServiceKdf;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};
    use crate::trust::{TrustPolicy, validate_location};
    use awawa_protocol::audit::MemoryAuditSink;
    use awawa_protocol::unattended::UnattendedAuthenticator;
    use std::time::Instant;

    #[test]
    fn flujo_set_change_revoke_con_verificador_persistido_y_auditoria_sin_secretos() {
        let tmp = TempDir::new("admin");
        let dir = safe_dir(&tmp);
        let store = VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        );
        let audit_path = dir.join("audit.jsonl");
        let mut sink =
            JsonLinesFileSink::open_with(&audit_path, &test_file_dacl(), &test_policy()).unwrap();
        let kdf = ServiceKdf;
        let first = "clave-inicial-segura";
        let second = "clave-nueva-segura!!";

        let mut ops = AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut sink,
            operator: "admin:test",
        };
        assert_eq!(ops.status(), Ok(UnattendedStatus::NotConfigured));
        assert_eq!(ops.set_password(first), Ok(1));
        assert_eq!(
            ops.set_password(first),
            Err(AdminError::Unattended(UnattendedError::AlreadyConfigured))
        );
        assert_eq!(ops.change_password(second), Ok(2));

        // Un autenticador que carga el archivo persistido acepta la nueva clave y rechaza la anterior.
        let loaded = UnattendedCredentialState::from_record(store.load().unwrap().unwrap());
        let mut auth = UnattendedAuthenticator::new(loaded);
        let now = Instant::now();
        assert!(auth.authenticate("op", second, &kdf, now).is_ok());
        assert!(auth.authenticate("op", first, &kdf, now).is_err());

        assert_eq!(ops.revoke_password(), Ok(3));
        assert_eq!(
            ops.status(),
            Ok(UnattendedStatus::Revoked { generation: 3 })
        );
        let loaded = UnattendedCredentialState::from_record(store.load().unwrap().unwrap());
        let mut auth = UnattendedAuthenticator::new(loaded);
        assert!(auth.authenticate("op", second, &kdf, now).is_err());

        // Reconfigurar tras revocar sube la generacion.
        let mut ops = AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut sink,
            operator: "admin:test",
        };
        assert_eq!(ops.set_password(first), Ok(4));
        drop(sink);

        let audit = std::fs::read_to_string(&audit_path).unwrap();
        assert_eq!(audit.lines().count(), 4);
        assert!(!audit.contains(first) && !audit.contains(second));
        assert!(
            audit.contains("password_configured")
                && audit.contains("password_rotated")
                && audit.contains("password_revoked")
        );
    }

    /// Un v1 en disco autentica sin reescribirse (sin migracion silenciosa); el siguiente `change` escribe v2
    /// con la generacion siguiente, y la auditoria no contiene la contrasena ni el material de ninguno.
    #[test]
    fn v1_en_disco_autentica_sin_cambios_y_change_lo_migra_a_v2() {
        use crate::kdf_argon2::{V1_VECTOR_PASSWORD, v1_vector_bytes};
        use awawa_protocol::unattended::{PasswordVerifierRecord, VerifierKdfParams};

        let tmp = TempDir::new("migra");
        let dir = safe_dir(&tmp);
        let store = VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        );
        let v1 = v1_vector_bytes();
        store
            .save(&PasswordVerifierRecord::from_bytes(&v1).unwrap())
            .unwrap();
        let blob_before = std::fs::read(store.path()).unwrap();

        let kdf = ServiceKdf;
        let mut auth = UnattendedAuthenticator::default();
        let mut auth_sink = MemoryAuditSink::new();
        let granted = crate::unattended_auth::authenticate_unattended(
            &store,
            &mut auth,
            &mut auth_sink,
            "remote",
            "relay",
            V1_VECTOR_PASSWORD,
            &kdf,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(granted.generation(), 7);
        assert_eq!(std::fs::read(store.path()).unwrap(), blob_before);
        assert_eq!(store.load().unwrap().unwrap().to_bytes(), v1);

        let audit_path = dir.join("audit.jsonl");
        let mut sink =
            JsonLinesFileSink::open_with(&audit_path, &test_file_dacl(), &test_policy()).unwrap();
        let new_password = "clave-migrada-a-v2!";
        let mut ops = AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut sink,
            operator: "admin:test",
        };
        assert_eq!(ops.change_password(new_password), Ok(8));
        drop(sink);

        let migrated = store.load().unwrap().unwrap();
        assert_eq!(migrated.version(), 2);
        assert_eq!(migrated.kdf_params(), VerifierKdfParams::PRODUCTION);
        assert_eq!(
            UnattendedCredentialState::from_record(migrated).status(),
            UnattendedStatus::Enabled { generation: 8 }
        );
        let v2 = store.load().unwrap().unwrap().to_bytes();
        let loaded = UnattendedCredentialState::from_record(store.load().unwrap().unwrap());
        let mut auth = UnattendedAuthenticator::new(loaded);
        let now = Instant::now();
        assert!(auth.authenticate("op", new_password, &kdf, now).is_ok());
        assert!(
            auth.authenticate("op", V1_VECTOR_PASSWORD, &kdf, now)
                .is_err()
        );

        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut text = std::fs::read_to_string(&audit_path).unwrap();
        for line in &auth_sink.lines {
            text.push_str(line);
        }
        assert!(text.contains("password_rotated"));
        for secret in [
            new_password.to_string(),
            V1_VECTOR_PASSWORD.to_string(),
            hex(&v1[16..32]),
            hex(&v1[32..64]),
            hex(&v2[24..40]),
            hex(&v2[40..72]),
        ] {
            assert!(!text.contains(&secret), "secreto en la auditoria");
        }
    }

    /// Politica de produccion (solo SY+BA, dueno fijado a Administradores al crear): el resultado NO depende
    /// del TokenOwner del proceso. Elevado, el flujo completo funciona y `load` lo acepta; sin elevar no se
    /// puede fijar el dueno BA, por lo que todo falla cerrado, sin exito reportado ni auditado.
    #[test]
    fn flujo_con_politica_de_produccion() {
        let tmp = TempDir::new("prod");
        let dir = tmp.path().join("Awawa");
        let store = VerifierFileStore::new(dir.join("unattended.verifier"));
        let kdf = ServiceKdf;
        let mut sink = MemoryAuditSink::new();

        if crate::identity::is_administrator() {
            ensure_protected_dir(&dir).expect("elevado: dir con dueno BA");
            let mut ops = AdminOps {
                store: &store,
                kdf: &kdf,
                sink: &mut sink,
                operator: "admin:test",
            };
            assert_eq!(ops.status(), Ok(UnattendedStatus::NotConfigured));
            assert_eq!(ops.set_password("clave-inicial-segura"), Ok(1));
            assert_eq!(
                ops.status(),
                Ok(UnattendedStatus::Enabled { generation: 1 })
            );
            assert_eq!(ops.change_password("clave-nueva-segura!!"), Ok(2));
            assert_eq!(
                ops.status(),
                Ok(UnattendedStatus::Enabled { generation: 2 })
            );
            assert_eq!(ops.revoke_password(), Ok(3));
            assert_eq!(
                ops.status(),
                Ok(UnattendedStatus::Revoked { generation: 3 })
            );
            assert_eq!(sink.lines.len(), 3);
            // El archivo resultante pasa la validacion de produccion (dueno BA, DACL SY/BA).
            assert!(validate_location(store.path(), &TrustPolicy::production()).is_ok());
            assert!(JsonLinesFileSink::open(&dir.join("audit.jsonl")).is_ok());
        } else {
            // Sin elevar no se puede crear el directorio con dueno BA: error y nada queda creado.
            assert!(ensure_protected_dir(&dir).is_err());
            assert!(!dir.exists());
            let mut ops = AdminOps {
                store: &store,
                kdf: &kdf,
                sink: &mut sink,
                operator: "admin:test",
            };
            assert!(ops.set_password("clave-inicial-segura").is_err());
            assert!(sink.lines.is_empty());
            assert!(!store.path().exists());
        }
    }

    /// En cualquier token, un directorio que no cumple la politica de produccion (aqui: creado por la prueba con
    /// el usuario en la DACL) impide guardar: error, sin archivo y sin auditoria de exito.
    #[test]
    fn set_en_directorio_no_confiable_no_reporta_exito() {
        let tmp = TempDir::new("untrusted");
        let dir = safe_dir(&tmp); // valida con la politica de pruebas, no con la de produccion
        let store = VerifierFileStore::new(dir.join("unattended.verifier"));
        let mut sink = MemoryAuditSink::new();
        let mut ops = AdminOps {
            store: &store,
            kdf: &ServiceKdf,
            sink: &mut sink,
            operator: "admin:test",
        };
        assert!(matches!(
            ops.set_password("clave-inicial-segura"),
            Err(AdminError::Store(
                crate::dpapi_store::StoreError::InsecureLocation(_)
            ))
        ));
        assert!(sink.lines.is_empty());
        assert!(!store.path().exists());
    }
}
