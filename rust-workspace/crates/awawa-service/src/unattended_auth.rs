//! Autenticacion desatendida contra el verificador VIGENTE en disco.
//!
//! Cada intento recarga el verificador (con la validacion de ubicacion de confianza), de modo que un
//! cambio o una revocacion hechos por el administrador surten efecto de inmediato. El limitador de
//! intentos vive dentro del `UnattendedAuthenticator` que conserva el proceso: solo se reemplazan sus
//! credenciales, nunca se recrea el autenticador (se perderian los contadores de bloqueo).

use core::fmt;
use std::time::Instant;

use awawa_protocol::unattended::{
    PasswordKdf, UnattendedAuthenticator, UnattendedAuthorization, UnattendedCredentialState,
    UnattendedError, UnattendedStatus,
};

use awawa_protocol::audit::{AuditEvent, AuditRecord, AuditSink, AuditSinkError};

use crate::dpapi_store::{StoreError, VerifierFileStore};
use crate::winutil::unix_ms_now;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAuthError {
    /// El verificador no se pudo cargar con confianza: acceso desatendido deshabilitado (fail closed).
    Store(StoreError),
    Auth(UnattendedError),
    /// No se pudo registrar el intento: se deniega (fail closed).
    Audit(AuditSinkError),
}

impl fmt::Display for ServiceAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "verificador rechazado: {e}"),
            Self::Auth(e) => write!(f, "{e}"),
            Self::Audit(e) => write!(f, "acceso denegado: {e}"),
        }
    }
}

impl std::error::Error for ServiceAuthError {}

/// Recarga el verificador del disco en las credenciales del autenticador. Si falla (ubicacion insegura,
/// manipulado, ilegible) deja las credenciales como no configuradas: se rechaza todo.
pub fn reload_credentials(
    store: &VerifierFileStore,
    authenticator: &mut UnattendedAuthenticator,
) -> Result<(), StoreError> {
    match store.load() {
        Ok(Some(record)) => {
            *authenticator.credentials_mut() = UnattendedCredentialState::from_record(record);
            Ok(())
        }
        Ok(None) => {
            *authenticator.credentials_mut() = UnattendedCredentialState::not_configured();
            Ok(())
        }
        Err(e) => {
            *authenticator.credentials_mut() = UnattendedCredentialState::not_configured();
            Err(e)
        }
    }
}

/// Estado vigente del verificador en disco (para `SessionTracker::revalidate`).
pub fn current_status(store: &VerifierFileStore) -> Result<UnattendedStatus, StoreError> {
    Ok(match store.load()? {
        Some(record) => UnattendedCredentialState::from_record(record).status(),
        None => UnattendedStatus::NotConfigured,
    })
}

/// Autentica `candidate` desde `source` contra el verificador actual en disco y AUDITA siempre el resultado
/// (un registro por intento, sin la contrasena): exito -> `AuthSucceeded`; contrasena invalida, fuera de politica
/// o acceso deshabilitado -> `AuthFailed`; bloqueo -> `AuthThrottled`; verificador rechazado -> `VerifierRejected`.
/// Si la auditoria no se puede escribir, falla cerrado: no se devuelve autorizacion.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_unattended(
    store: &VerifierFileStore,
    authenticator: &mut UnattendedAuthenticator,
    sink: &mut dyn AuditSink,
    operator: &str,
    source: &str,
    candidate: &str,
    kdf: &dyn PasswordKdf,
    now: Instant,
) -> Result<UnattendedAuthorization, ServiceAuthError> {
    let outcome = match reload_credentials(store, authenticator) {
        Err(e) => Err(ServiceAuthError::Store(e)),
        Ok(()) => authenticator
            .authenticate(source, candidate, kdf, now)
            .map_err(ServiceAuthError::Auth),
    };
    let event = match &outcome {
        Ok(_) => AuditEvent::AuthSucceeded,
        Err(ServiceAuthError::Store(_)) => AuditEvent::VerifierRejected,
        Err(ServiceAuthError::Auth(UnattendedError::Throttled { retry_after, .. })) => {
            AuditEvent::AuthThrottled {
                retry_after_secs: retry_after.as_secs().max(1),
            }
        }
        Err(_) => AuditEvent::AuthFailed,
    };
    let record = AuditRecord::new(unix_ms_now(), event, operator).with_source(source);
    sink.write_record(&record)
        .map_err(ServiceAuthError::Audit)?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_ops::AdminOps;
    use crate::audit_sink::JsonLinesFileSink;
    use crate::kdf_argon2::ServiceKdf;
    use crate::session_tracker::SessionTracker;
    use crate::testutil::{TempDir, safe_dir, test_file_dacl, test_policy};
    use awawa_protocol::audit::MemoryAuditSink;
    use awawa_protocol::desktop_session::InputDesktopKind;
    use awawa_protocol::unattended::{PasswordKdf, UnattendedAuthorization};

    /// Autentica descartando la auditoria (las pruebas de flujo no la inspeccionan).
    fn try_auth(
        store: &VerifierFileStore,
        auth: &mut UnattendedAuthenticator,
        source: &str,
        pw: &str,
        kdf: &dyn PasswordKdf,
        now: Instant,
    ) -> Result<UnattendedAuthorization, ServiceAuthError> {
        authenticate_unattended(
            store,
            auth,
            &mut MemoryAuditSink::new(),
            "remote",
            source,
            pw,
            kdf,
            now,
        )
    }

    fn store_in(dir: &std::path::Path) -> VerifierFileStore {
        VerifierFileStore::with_policy(
            dir.join("unattended.verifier"),
            &test_file_dacl(),
            test_policy(),
        )
    }

    #[test]
    fn cambiar_y_revocar_surten_efecto_sobre_autenticacion_y_sesion_previa() {
        let tmp = TempDir::new("authflow");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        let kdf = ServiceKdf;
        let (first, second) = ("clave-inicial-segura", "clave-nueva-segura!!");
        let mut sink = MemoryAuditSink::new();
        let mut ops = AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut sink,
            operator: "admin:test",
        };
        let mut auth = UnattendedAuthenticator::default();
        let now = Instant::now();

        // Sin verificador: rechazado.
        assert!(matches!(
            try_auth(&store, &mut auth, "op", first, &kdf, now),
            Err(ServiceAuthError::Auth(UnattendedError::UnattendedDisabled))
        ));

        // set -> autentica y se abre una sesion con esa generacion.
        ops.set_password(first).unwrap();
        let grant = try_auth(&store, &mut auth, "op", first, &kdf, now).unwrap();
        let mut tracker = SessionTracker::new();
        tracker
            .start_session(2, Some(grant.generation()), InputDesktopKind::Default)
            .unwrap();
        assert_eq!(
            tracker.revalidate(current_status(&store).unwrap()),
            crate::session_tracker::TrackerStep::default()
        );

        // change -> la vieja falla, la nueva funciona y la sesion previa deja de estar vigente.
        ops.change_password(second).unwrap();
        assert!(matches!(
            try_auth(&store, &mut auth, "op", first, &kdf, now),
            Err(ServiceAuthError::Auth(UnattendedError::InvalidPassword))
        ));
        let step = tracker.revalidate(current_status(&store).unwrap());
        assert!(step.audit.is_some() && !tracker.is_active());
        assert!(try_auth(&store, &mut auth, "op2", second, &kdf, now).is_ok());

        // revoke -> cualquier intento falla.
        ops.revoke_password().unwrap();
        for pw in [first, second] {
            assert!(matches!(
                try_auth(&store, &mut auth, "op3", pw, &kdf, now),
                Err(ServiceAuthError::Auth(UnattendedError::UnattendedDisabled))
            ));
        }
    }

    #[test]
    fn el_limitador_persiste_entre_recargas() {
        let tmp = TempDir::new("throttle");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        let kdf = ServiceKdf;
        let mut sink = MemoryAuditSink::new();
        AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut sink,
            operator: "admin:test",
        }
        .set_password("clave-inicial-segura")
        .unwrap();
        let mut auth = UnattendedAuthenticator::default();
        let now = Instant::now();
        for _ in 0..3 {
            let _ = try_auth(
                &store,
                &mut auth,
                "atacante",
                "incorrecta-larga-1",
                &kdf,
                now,
            );
        }
        // Tras 3 fallos el origen queda bloqueado aun con la clave correcta (el estado no se perdio al recargar).
        assert!(matches!(
            try_auth(
                &store,
                &mut auth,
                "atacante",
                "clave-inicial-segura",
                &kdf,
                now
            ),
            Err(ServiceAuthError::Auth(UnattendedError::Throttled { .. }))
        ));
    }

    #[test]
    fn verificador_en_ubicacion_insegura_deshabilita_el_acceso() {
        let tmp = TempDir::new("insecure");
        let dir = tmp.path().join("lax");
        let sid = crate::testutil::current_sid();
        let lax = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;WD)");
        crate::dpapi_store::create_dir_with_sddl(&dir, &lax).unwrap();
        let store = store_in(&dir);
        crate::dpapi_store::create_protected_file(
            store.path(),
            &test_file_dacl(),
            crate::dpapi_store::FileMode::CreateNew,
        )
        .unwrap();
        let mut auth = UnattendedAuthenticator::default();
        assert!(matches!(
            try_auth(
                &store,
                &mut auth,
                "op",
                "clave-inicial-segura",
                &ServiceKdf,
                Instant::now()
            ),
            Err(ServiceAuthError::Store(StoreError::InsecureLocation(_)))
        ));
        // El sink de auditoria tampoco se abre ahi.
        assert!(
            JsonLinesFileSink::open_with(&dir.join("a.jsonl"), &test_file_dacl(), &test_policy())
                .is_err()
        );
    }

    struct FailingSink;
    impl AuditSink for FailingSink {
        fn write_record(&mut self, _r: &AuditRecord) -> Result<(), AuditSinkError> {
            Err(AuditSinkError::Io("disco lleno".into()))
        }
    }

    #[test]
    fn cada_rama_audita_exactamente_un_registro_sin_secretos() {
        let tmp = TempDir::new("auditbranches");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        let kdf = ServiceKdf;
        let good = "clave-inicial-segura";
        let bad = "clave-incorrecta-1";
        let mut admin_sink = MemoryAuditSink::new();
        let mut sink = MemoryAuditSink::new();
        let mut auth = UnattendedAuthenticator::default();
        let now = Instant::now();
        let run = |store: &VerifierFileStore,
                   sink: &mut MemoryAuditSink,
                   auth: &mut UnattendedAuthenticator,
                   src: &str,
                   pw: &str| {
            let before = sink.lines.len();
            let r = authenticate_unattended(store, auth, sink, "remote", src, pw, &kdf, now);
            assert_eq!(sink.lines.len(), before + 1, "un registro por intento");
            r
        };

        // Deshabilitado (sin verificador) -> AuthFailed.
        assert!(run(&store, &mut sink, &mut auth, "ip-1", good).is_err());
        assert!(sink.lines[0].contains("auth_failed") && sink.lines[0].contains("ip-1"));

        AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut admin_sink,
            operator: "admin:test",
        }
        .set_password(good)
        .unwrap();
        // Fuera de politica -> AuthFailed.
        assert!(run(&store, &mut sink, &mut auth, "ip-2", "corta").is_err());
        assert!(sink.lines[1].contains("auth_failed"));
        // Exito -> AuthSucceeded.
        assert!(run(&store, &mut sink, &mut auth, "ip-3", good).is_ok());
        assert!(sink.lines[2].contains("auth_succeeded") && sink.lines[2].contains("ip-3"));
        // Contrasena invalida -> AuthFailed; tras 3 fallos -> AuthThrottled.
        for _ in 0..3 {
            assert!(run(&store, &mut sink, &mut auth, "ip-4", bad).is_err());
        }
        assert!(run(&store, &mut sink, &mut auth, "ip-4", good).is_err());
        let last = sink.lines.last().unwrap();
        assert!(
            last.contains("auth_throttled") && last.contains("retry_after_secs"),
            "{last}"
        );

        // Verificador rechazado -> VerifierRejected.
        let lax_dir = tmp.path().join("lax");
        let sid = crate::testutil::current_sid();
        let lax = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;WD)");
        crate::dpapi_store::create_dir_with_sddl(&lax_dir, &lax).unwrap();
        let bad_store = store_in(&lax_dir);
        crate::dpapi_store::create_protected_file(
            bad_store.path(),
            &test_file_dacl(),
            crate::dpapi_store::FileMode::CreateNew,
        )
        .unwrap();
        let mut auth2 = UnattendedAuthenticator::default();
        assert!(run(&bad_store, &mut sink, &mut auth2, "ip-5", good).is_err());
        assert!(sink.lines.last().unwrap().contains("verifier_rejected"));

        let all = sink.lines.join("\n");
        assert!(!all.contains(good) && !all.contains(bad) && !all.contains("corta"));
    }

    #[test]
    fn si_la_auditoria_falla_no_se_devuelve_autorizacion() {
        let tmp = TempDir::new("auditfail");
        let dir = safe_dir(&tmp);
        let store = store_in(&dir);
        let kdf = ServiceKdf;
        let mut admin_sink = MemoryAuditSink::new();
        AdminOps {
            store: &store,
            kdf: &kdf,
            sink: &mut admin_sink,
            operator: "admin:test",
        }
        .set_password("clave-inicial-segura")
        .unwrap();
        let mut auth = UnattendedAuthenticator::default();
        let r = authenticate_unattended(
            &store,
            &mut auth,
            &mut FailingSink,
            "remote",
            "ip-1",
            "clave-inicial-segura",
            &kdf,
            Instant::now(),
        );
        assert!(matches!(r, Err(ServiceAuthError::Audit(_))));
    }
}
