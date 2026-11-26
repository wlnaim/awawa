use std::time::{Duration, Instant};

use crate::credentials::{CredentialsError, HostCredentials, SessionId};
use crate::geometry::ProtectedRect;
use crate::handshake::{
    HostAuthReply, HostKeyExchange, PROTOCOL_VERSION, PakeChallenge, PakeConfirm, PakeHello,
    SasCode,
};
use crate::input_safety::ActiveInputTracker;
use crate::messages::{RemoteInputCommand, ScopedCapabilities};
use crate::secure_channel::SecureChannel;
use crate::unattended::{UnattendedAuthorization, UnattendedStatus};
use crate::video_channel::VideoSealer;

/// Máximo de intentos fallidos de contraseña antes de rotar automáticamente la contraseña efímera.
pub const MAX_FAILED_PASSWORD_ATTEMPTS: u8 = 3;

/// Ventana mínima anti-clickjacking (1.5 s) desde que se muestra el modal local hasta que se acepta clic en "Aprobar".
pub const ANTI_CLICKJACK_GRACE_PERIOD: Duration = Duration::from_millis(1500);

/// Tiempo máximo para que el usuario cliente apruebe localmente la solicitud entrante.
pub const LOCAL_CONSENT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentError {
    SessionIdMismatch,
    InvalidPassword {
        failed_attempts: u8,
        password_rotated: bool,
    },
    CredentialsError(CredentialsError),
    AntiClickjackGracePeriodActive,
    ApprovalTimedOut,
    CapabilityDenied(&'static str),
    ProtectedHostWindowHit,
    /// Mensaje de handshake inválido (no cuenta como intento de contraseña).
    MalformedHandshake(&'static str),
    /// Versión de protocolo del `PakeHello` distinta de `PROTOCOL_VERSION` (no cuenta como intento
    /// de contraseña).
    UnsupportedProtocolVersion(u16),
}

/// Datos de la petición del Agente de Soporte. No transporta la contraseña: esta solo entra al
/// handshake SPAKE2 (`OperatorHandshake::start`).
#[derive(Debug, Clone)]
pub struct OperatorConnectionRequest {
    pub target_session_id: SessionId,
    pub operator_display_name: String,
    pub operator_ed25519_fingerprint: [u8; 8],
    pub requested_capabilities: ScopedCapabilities,
}

/// Estado 1: El Cliente Receptor inició la app, generó sus credenciales y espera peticiones.
/// En este estado NO existe API para capturar pantalla ni inyectar entrada.
#[derive(Debug)]
pub struct WaitingForRequest {
    credentials: HostCredentials,
    failed_attempts: u8,
}

/// Estado intermedio: el host respondió al `PakeHello` y espera la confirmación de clave del operador.
/// En este estado NO existe API para capturar pantalla ni inyectar entrada.
#[derive(Debug)]
pub struct AuthenticatingPake {
    waiting: WaitingForRequest,
    request: OperatorConnectionRequest,
    exchange: HostKeyExchange,
}

/// Estado 2: El Agente de Soporte autenticó ID + Contraseña correctamente, pero la sesión está
/// BLOQUEADA esperando **Aprobación Local Mandatoria** del usuario frente al equipo cliente.
/// Solo se construye a partir de un handshake SPAKE2 exitoso.
#[derive(Debug)]
pub struct PendingLocalConsent {
    credentials: HostCredentials,
    request: OperatorConnectionRequest,
    prompt_displayed_at: Instant,
    sas: SasCode,
}

/// Resultado de un handshake exitoso en el host: la sesión queda pendiente de aprobación local,
/// `reply` se envía al operador, `channel` cifra el tráfico de control posterior y `video` sella los
/// streams de video (solo se usa tras la aprobación local).
#[derive(Debug)]
pub struct HostAuthenticated {
    pub pending: PendingLocalConsent,
    pub reply: HostAuthReply,
    pub channel: SecureChannel,
    pub video: VideoSealer,
}

/// Origen de la autorización de una sesión activa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Bajo demanda: el usuario local aprobó explícitamente en el diálogo modal.
    Attended,
    /// Desatendido: el operador presentó la contraseña persistente configurada por un administrador.
    Unattended,
}

/// Estado 3: El usuario local aprobó explícitamente la conexión.
/// Único tipo en todo el sistema capaz de autorizar captura y validar comandos de Cursor/Teclado.
#[derive(Debug)]
pub struct ApprovedActiveSession {
    session_id: SessionId,
    operator_display_name: String,
    operator_fingerprint: [u8; 8],
    granted_capabilities: ScopedCapabilities,
    approved_at: Instant,
    protected_host_ui: Option<ProtectedRect>,
    input_tracker: ActiveInputTracker,
    access_mode: AccessMode,
    /// Generación del verificador con la que se autorizó una sesión desatendida (`None` en bajo demanda).
    unattended_generation: Option<u32>,
}

/// Concesión desatendida que el servicio entrega al agente de sesión por la pipe local (mensaje
/// `Start`): generación del verificador con la que se autenticó el operador, nombre ya saneado y
/// huella de la sesión. Solo con la feature `session-agent` (ver
/// [`ApprovedActiveSession::for_session_agent`]).
#[cfg(any(test, feature = "session-agent"))]
#[derive(Debug)]
pub struct SessionAgentGrant {
    generation: u32,
    operator_display_name: String,
    operator_fingerprint: [u8; 8],
}

#[cfg(any(test, feature = "session-agent"))]
impl SessionAgentGrant {
    /// Solo la llama el cliente de la pipe del agente al recibir `Start` del servicio.
    pub fn from_service_pipe(
        generation: u32,
        operator_display_name: String,
        operator_fingerprint: [u8; 8],
    ) -> Self {
        Self {
            generation,
            operator_display_name,
            operator_fingerprint,
        }
    }
}

/// Resultado de revocar/cerrar una sesión activa, incluyendo los eventos de limpieza (*Dead-Man Switch*).
#[derive(Debug)]
pub struct SessionRevocation {
    pub reason: String,
    pub duration: Duration,
    pub pending_release_commands: Vec<RemoteInputCommand>,
}

impl WaitingForRequest {
    pub fn start_client_reception() -> Result<Self, CredentialsError> {
        Ok(Self {
            credentials: HostCredentials::generate_for_client_host()?,
            failed_attempts: 0,
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.credentials.session_id()
    }

    pub fn display_password(&self) -> String {
        self.credentials.password().expose_formatted()
    }

    /// Rota solo la contraseña efímera (conserva el ID) y reinicia el contador de fallos.
    pub fn rotate_password(&mut self) -> Result<(), CredentialsError> {
        self.credentials.rotate_password()?;
        self.failed_attempts = 0;
        Ok(())
    }

    /// Procesa el `PakeHello` del operador. Rechaza una versión de protocolo distinta, un ID de
    /// sesión distinto, capacidades fuera de la máscara permitida o un mensaje SPAKE2 inválido sin
    /// contarlos como intento de contraseña.
    pub fn accept_operator_hello(
        self,
        hello: &PakeHello,
    ) -> Result<(AuthenticatingPake, PakeChallenge), (Self, ConsentError)> {
        if hello.protocol_version != PROTOCOL_VERSION {
            let received = hello.protocol_version;
            return Err((self, ConsentError::UnsupportedProtocolVersion(received)));
        }
        let session_id = self.credentials.session_id();
        if hello.target_session_id != session_id.raw_u32() {
            return Err((self, ConsentError::SessionIdMismatch));
        }
        let requested_capabilities = match hello.requested_capabilities.validate() {
            Ok(caps) => caps,
            Err(reason) => return Err((self, ConsentError::CapabilityDenied(reason))),
        };
        let (exchange, challenge) = match HostKeyExchange::respond(
            session_id,
            self.credentials.password().normalized_bytes(),
            hello,
        ) {
            Ok(pair) => pair,
            Err(reason) => return Err((self, ConsentError::MalformedHandshake(reason))),
        };
        let request = OperatorConnectionRequest {
            target_session_id: session_id,
            operator_display_name: hello.operator_display_name.clone(),
            operator_ed25519_fingerprint: hello.operator_fingerprint,
            requested_capabilities,
        };
        Ok((
            AuthenticatingPake {
                waiting: self,
                request,
                exchange,
            },
            challenge,
        ))
    }

    /// Registra un intento fallido y rota la contraseña al llegar a `MAX_FAILED_PASSWORD_ATTEMPTS`.
    fn register_failed_password(mut self) -> (Self, ConsentError) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        let mut rotated = false;
        if self.failed_attempts >= MAX_FAILED_PASSWORD_ATTEMPTS {
            if let Err(e) = self.credentials.rotate_password() {
                return (self, ConsentError::CredentialsError(e));
            }
            self.failed_attempts = 0;
            rotated = true;
        }
        let attempts = if rotated {
            MAX_FAILED_PASSWORD_ATTEMPTS
        } else {
            self.failed_attempts
        };
        (
            self,
            ConsentError::InvalidPassword {
                failed_attempts: attempts,
                password_rotated: rotated,
            },
        )
    }
}

impl AuthenticatingPake {
    /// Verifica la confirmación de clave del operador. Si es válida, transiciona a
    /// `PendingLocalConsent` (Aprobación Local Mandatoria). Si no, cuenta el fallo sin mostrar
    /// ningún diálogo local y devuelve la respuesta de rechazo para el operador.
    pub fn verify_operator_confirmation(
        self,
        confirm: &PakeConfirm,
        now: Instant,
    ) -> Result<HostAuthenticated, (WaitingForRequest, ConsentError, HostAuthReply)> {
        if !self.exchange.verify_operator(confirm) {
            let (waiting, err) = self.waiting.register_failed_password();
            let remaining_attempts = match err {
                ConsentError::InvalidPassword {
                    failed_attempts, ..
                } => MAX_FAILED_PASSWORD_ATTEMPTS.saturating_sub(failed_attempts),
                _ => 0,
            };
            return Err((waiting, err, HostAuthReply::Rejected { remaining_attempts }));
        }
        let sas = self.exchange.sas();
        let (reply, channel, video) = self.exchange.into_accepted();
        Ok(HostAuthenticated {
            pending: PendingLocalConsent {
                credentials: self.waiting.credentials,
                request: self.request,
                prompt_displayed_at: now,
                sas,
            },
            reply,
            channel,
            video,
        })
    }

    /// El operador abandonó el handshake antes de confirmar: se vuelve a esperar sin contar fallo
    /// (sin confirmación no obtuvo información sobre la contraseña).
    pub fn abort(self) -> WaitingForRequest {
        self.waiting
    }
}

impl PendingLocalConsent {
    pub fn operator_display_name(&self) -> &str {
        &self.request.operator_display_name
    }

    pub fn operator_fingerprint_hex(&self) -> String {
        self.request
            .operator_ed25519_fingerprint
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn requested_capabilities(&self) -> ScopedCapabilities {
        self.request.requested_capabilities
    }

    /// Código de verificación que el modal muestra y que el operador ve en su consola.
    pub fn sas(&self) -> SasCode {
        self.sas
    }

    /// El usuario local pulsa "Rechazar" en el diálogo modal: se regenera la contraseña por seguridad
    /// y se regresa al estado de espera.
    pub fn reject_locally(mut self) -> Result<WaitingForRequest, CredentialsError> {
        self.credentials.rotate_password()?;
        Ok(WaitingForRequest {
            credentials: self.credentials,
            failed_attempts: 0,
        })
    }

    /// El usuario local pulsa físicamente "Aceptar y Ceder Control" en el diálogo modal.
    /// Valida tanto el timeout máximo (60 s) como el periodo de gracia anti-clickjacking (1.5 s).
    pub fn approve_locally(
        self,
        decision_instant: Instant,
        protected_host_ui: Option<ProtectedRect>,
    ) -> Result<ApprovedActiveSession, (WaitingForRequest, ConsentError)> {
        let elapsed = decision_instant.saturating_duration_since(self.prompt_displayed_at);

        if elapsed < ANTI_CLICKJACK_GRACE_PERIOD {
            return Err((
                WaitingForRequest {
                    credentials: self.credentials,
                    failed_attempts: 0,
                },
                ConsentError::AntiClickjackGracePeriodActive,
            ));
        }

        if elapsed > LOCAL_CONSENT_TIMEOUT {
            let mut creds = self.credentials;
            let _ = creds.rotate_password();
            return Err((
                WaitingForRequest {
                    credentials: creds,
                    failed_attempts: 0,
                },
                ConsentError::ApprovalTimedOut,
            ));
        }

        Ok(ApprovedActiveSession {
            session_id: self.credentials.session_id(),
            operator_display_name: self.request.operator_display_name,
            operator_fingerprint: self.request.operator_ed25519_fingerprint,
            granted_capabilities: self.request.requested_capabilities,
            approved_at: decision_instant,
            protected_host_ui,
            input_tracker: ActiveInputTracker::new(),
            access_mode: AccessMode::Attended,
            unattended_generation: None,
        })
    }
}

impl ApprovedActiveSession {
    /// Crea una sesión activa desatendida. Solo es posible consumiendo una `UnattendedAuthorization`,
    /// que únicamente emite `UnattendedAuthenticator` tras verificar la contraseña persistente.
    pub fn from_unattended_authorization(
        authorization: UnattendedAuthorization,
        session_id: SessionId,
        operator_display_name: String,
        operator_fingerprint: [u8; 8],
        granted_capabilities: ScopedCapabilities,
        now: Instant,
        protected_host_ui: Option<ProtectedRect>,
    ) -> Self {
        Self {
            session_id,
            operator_display_name,
            operator_fingerprint,
            granted_capabilities,
            approved_at: now,
            protected_host_ui,
            input_tracker: ActiveInputTracker::new(),
            access_mode: AccessMode::Unattended,
            unattended_generation: Some(authorization.generation()),
        }
    }

    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Generación del verificador que autorizó la sesión desatendida (`None` en bajo demanda).
    pub fn unattended_generation(&self) -> Option<u32> {
        self.unattended_generation
    }

    /// Indica si la autorización sigue vigente frente al estado actual de la credencial desatendida.
    /// Bajo demanda siempre es vigente; desatendida solo si sigue habilitada con la misma generación
    /// (un cambio o una revocación de la contraseña la invalidan).
    pub fn is_unattended_grant_current(&self, status: UnattendedStatus) -> bool {
        match self.unattended_generation {
            None => true,
            Some(granted) => {
                status
                    == UnattendedStatus::Enabled {
                        generation: granted,
                    }
            }
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn operator_display_name(&self) -> &str {
        &self.operator_display_name
    }

    pub fn operator_fingerprint(&self) -> [u8; 8] {
        self.operator_fingerprint
    }

    pub fn can_capture_desktop(&self) -> bool {
        self.granted_capabilities.view_desktop
    }

    pub fn update_protected_host_ui(&mut self, rect: Option<ProtectedRect>) {
        self.protected_host_ui = rect;
    }

    /// Valida un comando de Cursor o Teclado contra las capacidades aprobadas y el rectángulo protegido
    /// de la ventana local del cliente receptor, registrándolo en el *Dead-Man Switch*.
    pub fn authorize_remote_input(&mut self, cmd: &RemoteInputCommand) -> Result<(), ConsentError> {
        match cmd {
            RemoteInputCommand::MoveCursor { .. } | RemoteInputCommand::MouseWheel { .. } => {
                if !self.granted_capabilities.control_cursor {
                    return Err(ConsentError::CapabilityDenied(
                        "control de cursor no autorizado",
                    ));
                }
            }
            RemoteInputCommand::MouseButton {
                target_x, target_y, ..
            } => {
                if !self.granted_capabilities.control_cursor {
                    return Err(ConsentError::CapabilityDenied(
                        "control de cursor no autorizado",
                    ));
                }
                if let Some(protected) = self.protected_host_ui
                    && protected.contains_with_margin(*target_x, *target_y)
                {
                    return Err(ConsentError::ProtectedHostWindowHit);
                }
            }
            RemoteInputCommand::Keyboard { .. } => {
                if !self.granted_capabilities.control_keyboard {
                    return Err(ConsentError::CapabilityDenied(
                        "control de teclado no autorizado",
                    ));
                }
            }
        }

        self.input_tracker.record_event(cmd);
        Ok(())
    }

    /// Drena los comandos de liberación de teclas y botones retenidos sin cerrar la sesión
    /// (suspensión por escritorio seguro o bloqueo de sesión).
    pub fn drain_held_input_releases(&mut self) -> Vec<RemoteInputCommand> {
        self.input_tracker.drain_release_commands()
    }

    /// Crea la sesión activa del **agente de sesión** desatendido.
    ///
    /// Motivo de seguridad del sellado: en el acceso desatendido la contraseña la verifica el
    /// servicio (SYSTEM), que es el único que posee `UnattendedAuthorization`; el agente corre en
    /// otro proceso con el token del usuario y solo recibe por la pipe con DACL la concesión del
    /// servicio. Este constructor no verifica nada por sí mismo, así que solo existe con la feature
    /// `session-agent` (la activa únicamente `awawa-service`, dueño del agente) y exige una
    /// [`SessionAgentGrant`], que solo construye el cliente de la pipe del agente. Ningún otro
    /// crate del workspace declara la feature: compilado por separado no ve este constructor.
    ///
    /// No salta el resto de la compuerta: las capacidades quedan fijas en pantalla, ratón y
    /// teclado; la captura y la entrada siguen exigiendo el `DesktopSessionMonitor` en `Streaming`
    /// (escritorio seguro), el heartbeat, la guardia de ventanas protegidas (`protected_host_ui`) y
    /// la liberación de teclas al suspender o revocar, igual que una sesión aprobada localmente.
    #[cfg(any(test, feature = "session-agent"))]
    pub fn for_session_agent(
        grant: SessionAgentGrant,
        session_id: SessionId,
        now: Instant,
        protected_host_ui: Option<ProtectedRect>,
    ) -> Self {
        Self {
            session_id,
            operator_display_name: grant.operator_display_name,
            operator_fingerprint: grant.operator_fingerprint,
            granted_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
            approved_at: now,
            protected_host_ui,
            input_tracker: ActiveInputTracker::new(),
            access_mode: AccessMode::Unattended,
            unattended_generation: Some(grant.generation),
        }
    }

    /// Revoca inmediatamente el control remoto (por botón local, tecla de pánico o desconexión)
    /// y devuelve los eventos `KeyUp` / `ButtonReleased` obligatorios para limpiar el estado del SO.
    pub fn revoke_immediately(
        mut self,
        now: Instant,
        reason: impl Into<String>,
    ) -> SessionRevocation {
        SessionRevocation {
            reason: reason.into(),
            duration: now.saturating_duration_since(self.approved_at),
            pending_release_commands: self.input_tracker.drain_release_commands(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::{MonitorDescriptor, VirtualDesktopBounds};
    use crate::handshake::run_in_memory_handshake;
    use crate::messages::{ButtonState, KeyState, MouseButton};

    #[test]
    fn sesion_del_agente_es_desatendida_con_capacidades_fijas_y_sin_saltar_la_guardia() {
        let id = SessionId::parse("123456789").unwrap();
        let now = Instant::now();
        let banner = ProtectedRect {
            left: 0,
            top: 0,
            right: 100,
            bottom: 50,
            safety_margin_px: 8,
        };
        let grant = SessionAgentGrant::from_service_pipe(7, "Tecnico".to_string(), [3; 8]);
        let mut session = ApprovedActiveSession::for_session_agent(grant, id, now, Some(banner));
        assert_eq!(session.access_mode(), AccessMode::Unattended);
        assert_eq!(session.unattended_generation(), Some(7));
        assert_eq!(session.operator_display_name(), "Tecnico");
        assert_eq!(session.operator_fingerprint(), [3; 8]);
        assert!(session.can_capture_desktop());
        // La generacion sigue atada a la credencial vigente.
        assert!(session.is_unattended_grant_current(UnattendedStatus::Enabled { generation: 7 }));
        assert!(!session.is_unattended_grant_current(UnattendedStatus::Enabled { generation: 8 }));
        // La ventana protegida (banner) sigue bloqueando los clics remotos.
        let click = RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state: ButtonState::Pressed,
            target_x: 10,
            target_y: 10,
        };
        assert_eq!(
            session.authorize_remote_input(&click),
            Err(ConsentError::ProtectedHostWindowHit)
        );
        // Las teclas retenidas se liberan al revocar.
        let key = RemoteInputCommand::Keyboard {
            scancode: 0x1E,
            extended: false,
            unicode_char: None,
            state: KeyState::Down,
        };
        session.authorize_remote_input(&key).unwrap();
        let revocation = session.revoke_immediately(now, "kill-switch");
        assert_eq!(revocation.pending_release_commands.len(), 1);
    }

    #[test]
    fn host_exclusively_generates_valid_credentials_and_rotates_after_3_failures() {
        let mut waiting = WaitingForRequest::start_client_reception().expect("CSPRNG ok");
        let id = waiting.session_id();
        let initial_pw = waiting.display_password();
        assert_eq!(id.formatted().len(), 11);
        assert_eq!(initial_pw.len(), 11);

        let now = Instant::now();
        for expected_attempt in 1..=3 {
            let bad_req = OperatorConnectionRequest {
                target_session_id: id,
                operator_display_name: "Agente Soporte".to_string(),
                operator_ed25519_fingerprint: [0xAA; 8],
                requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
            };
            let (next_waiting, err) =
                run_in_memory_handshake(waiting, &bad_req, "WRONG-PASS2", now)
                    .expect_err("debe rechazar password invalido");
            waiting = next_waiting;
            assert_eq!(
                err,
                ConsentError::InvalidPassword {
                    failed_attempts: expected_attempt,
                    password_rotated: expected_attempt == 3,
                }
            );
        }

        assert_ne!(
            waiting.display_password(),
            initial_pw,
            "la contrasena efimera debe rotar automaticamente al tercer intento fallido"
        );
    }

    #[test]
    fn rotate_password_keeps_the_id_changes_the_password_and_resets_failures() {
        let mut waiting = WaitingForRequest::start_client_reception().unwrap();
        let id = waiting.session_id();
        let old_pw = waiting.display_password();
        let req = OperatorConnectionRequest {
            target_session_id: id,
            operator_display_name: "Agente".to_string(),
            operator_ed25519_fingerprint: [9; 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };
        let now = Instant::now();
        for _ in 0..2 {
            waiting = run_in_memory_handshake(waiting, &req, "WRONG-PASS2", now)
                .expect_err("password invalido")
                .0;
        }
        waiting.rotate_password().unwrap();
        assert_eq!(waiting.session_id(), id);
        assert_ne!(waiting.display_password(), old_pw);
        // El contador volvió a cero: un fallo más no rota otra vez (necesitaría 3).
        let pw = waiting.display_password();
        let (waiting, err) = run_in_memory_handshake(waiting, &req, "WRONG-PASS2", now)
            .expect_err("password invalido");
        assert_eq!(
            err,
            ConsentError::InvalidPassword {
                failed_attempts: 1,
                password_rotated: false
            }
        );
        assert_eq!(waiting.display_password(), pw);
    }

    #[test]
    fn enforces_mandatory_local_approval_and_anti_clickjacking_grace_window() {
        let waiting = WaitingForRequest::start_client_reception().unwrap();
        let id = waiting.session_id();
        let pw = waiting.display_password();
        let t0 = Instant::now();

        let req = OperatorConnectionRequest {
            target_session_id: id,
            operator_display_name: "Soporte Nivel 2".to_string(),
            operator_ed25519_fingerprint: [1, 2, 3, 4, 5, 6, 7, 8],
            requested_capabilities: ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS,
        };

        let pending = run_in_memory_handshake(waiting, &req, &pw, t0)
            .unwrap()
            .0
            .pending;

        // Intento de aprobación antes de 1.5s (clickjacking accidental) debe fallar:
        let (waiting_again, err) = pending
            .approve_locally(t0 + Duration::from_millis(300), None)
            .expect_err("debe bloquear clic prematuro");
        assert_eq!(err, ConsentError::AntiClickjackGracePeriodActive);

        // Nuevo intento legítimo aprobado tras 2 segundos:
        let pending2 = run_in_memory_handshake(waiting_again, &req, &pw, t0)
            .unwrap()
            .0
            .pending;
        let banner_rect = ProtectedRect {
            left: 800,
            top: 0,
            right: 1120,
            bottom: 48,
            safety_margin_px: 8,
        };
        let mut active = pending2
            .approve_locally(t0 + Duration::from_secs(2), Some(banner_rect))
            .expect("aprobacion local valida");

        assert!(active.can_capture_desktop());

        // Clic sobre la ventana normal del cliente -> permitido
        let normal_click = RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state: ButtonState::Pressed,
            target_x: 400,
            target_y: 300,
        };
        active.authorize_remote_input(&normal_click).unwrap();

        // Clic remoto intentando pulsar el botón local "Revocar Control" -> bloqueado
        let hijack_click = RemoteInputCommand::MouseButton {
            button: MouseButton::Left,
            state: ButtonState::Pressed,
            target_x: 900,
            target_y: 20,
        };
        assert_eq!(
            active.authorize_remote_input(&hijack_click),
            Err(ConsentError::ProtectedHostWindowHit)
        );

        // Tecla Shift presionada antes de revocar -> debe liberarse en revoke_immediately
        active
            .authorize_remote_input(&RemoteInputCommand::Keyboard {
                scancode: 0x2A,
                extended: false,
                unicode_char: None,
                state: KeyState::Down,
            })
            .unwrap();

        let rev = active.revoke_immediately(t0 + Duration::from_secs(10), "Usuario pulso Revocar");
        assert_eq!(rev.pending_release_commands.len(), 2);
    }

    #[test]
    fn multimonitor_coordinate_normalization_roundtrip() {
        let monitors = vec![
            MonitorDescriptor {
                index: 0,
                is_primary: true,
                origin_x: 0,
                origin_y: 0,
                width_px: 1920,
                height_px: 1080,
                dpi_scale_percent: 100,
            },
            MonitorDescriptor {
                index: 1,
                is_primary: false,
                origin_x: -1920,
                origin_y: 0,
                width_px: 1920,
                height_px: 1080,
                dpi_scale_percent: 150,
            },
        ];
        let bounds = VirtualDesktopBounds::from_monitors(&monitors).unwrap();
        assert_eq!(bounds.left, -1920);
        assert_eq!(bounds.width, 3840);

        let norm = bounds.normalize_pixel(960, 540);
        let (rx, ry) = bounds.denormalize_point(norm);
        assert!((rx - 960).abs() <= 1);
        assert!((ry - 540).abs() <= 1);
    }

    #[test]
    fn rejects_out_of_scope_capabilities() {
        // Bit 0b1000 (ej. transferencia de archivos) está prohibido por alcance
        assert!(ScopedCapabilities::from_wire_bits(0b1111).is_err());
        assert_eq!(
            ScopedCapabilities::from_wire_bits(0b0111).unwrap(),
            ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS
        );
    }
}
