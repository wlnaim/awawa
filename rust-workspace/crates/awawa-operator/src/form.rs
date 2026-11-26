//! Validacion y saneado del formulario de conexion (ID, contrasena, nombre del agente).
//!
//! Logica pura: no depende de egui. Las capacidades solicitadas son siempre exactamente
//! pantalla + mouse + teclado; el formulario no ofrece ninguna otra.
//!
//! Dos modos: bajo demanda (ID de sesion + contrasena temporal) y equipo desatendido (ID del equipo
//! + contrasena persistente, sin normalizar, contra la clave del servicio fijada con `--host-key`).

use std::fmt;

use awawa_protocol::unattended_channel::VerifyingKey;
use awawa_protocol::{ScopedCapabilities, SessionId, UNATTENDED_PASSWORD_MAX_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Maximo de caracteres del nombre declarado (igual al limite de los campos de auditoria del host).
pub const MAX_NAME_CHARS: usize = 64;
/// Maximo de caracteres aceptados en el campo de contrasena.
pub const MAX_PASSWORD_CHARS: usize = 64;

/// Capacidades que solicita el operador: `VIEW_DESKTOP | CONTROL_MOUSE | CONTROL_KEYBOARD`.
pub const REQUESTED_CAPABILITIES: ScopedCapabilities = ScopedCapabilities {
    view_desktop: true,
    control_cursor: true,
    control_keyboard: true,
};

/// Modo de conexion elegido en el formulario.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectMode {
    /// ID y contrasena temporal que genera el host; exige la aprobacion local.
    #[default]
    OnDemand,
    /// ID del equipo y contrasena persistente; exige la clave del servicio fijada (`--host-key`).
    Unattended,
}

/// Contenido crudo de los campos tal como lo teclea el tecnico.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FormInput {
    pub mode: ConnectMode,
    pub session_id: String,
    pub password: String,
    pub agent_name: String,
}

impl fmt::Debug for FormInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormInput")
            .field("mode", &self.mode)
            .field("session_id", &self.session_id)
            .field("password", &"<oculta>")
            .field("agent_name", &self.agent_name)
            .finish()
    }
}

impl Drop for FormInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Datos validados y saneados, listos para iniciar la conexion.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionParams {
    pub mode: ConnectMode,
    pub session_id: SessionId,
    pub password: String,
    pub agent_name: String,
    /// Siempre [`REQUESTED_CAPABILITIES`].
    pub requested_capabilities: ScopedCapabilities,
}

impl Drop for ConnectionParams {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl fmt::Debug for ConnectionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionParams")
            .field("mode", &self.mode)
            .field("session_id", &self.session_id.formatted())
            .field("password", &"<oculta>")
            .field("agent_name", &self.agent_name)
            .field("requested_capabilities", &self.requested_capabilities)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    IdEmpty,
    IdInvalid,
    PasswordEmpty,
    PasswordTooLong,
    NameEmpty,
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IdEmpty => "Ingrese el ID del cliente.",
            Self::IdInvalid => "El ID debe tener 9 dígitos (XXX-XXX-XXX).",
            Self::PasswordEmpty => "Ingrese la contraseña temporal.",
            Self::PasswordTooLong => "La contraseña es demasiado larga.",
            Self::NameEmpty => "Ingrese el nombre del agente.",
        })
    }
}

/// Caracteres invisibles de formato (direccion de texto, ancho cero) que `char::is_control` no
/// cubre y que permitirian falsificar el nombre mostrado en el host.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Elimina caracteres de control e invisibles de formato, recorta espacios y acota a
/// `max_chars` caracteres. Sirve para el nombre declarado y para textos que llegan del host.
pub fn sanitize_text(raw: &str, max_chars: usize) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    let bounded: String = cleaned.trim().chars().take(max_chars).collect();
    bounded.trim_end().to_string()
}

/// Nombre del agente saneado y acotado a [`MAX_NAME_CHARS`].
pub fn sanitize_agent_name(raw: &str) -> String {
    sanitize_text(raw, MAX_NAME_CHARS)
}

/// Valida el formulario completo. El ID solo admite digitos, espacios y guiones.
pub fn validate(input: &FormInput) -> Result<ConnectionParams, FormError> {
    let id_text = input.session_id.trim();
    if id_text.is_empty() {
        return Err(FormError::IdEmpty);
    }
    if !id_text
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c.is_ascii_whitespace())
    {
        return Err(FormError::IdInvalid);
    }
    let session_id = SessionId::parse(id_text).map_err(|_| FormError::IdInvalid)?;

    // Bajo demanda la contrasena se normaliza (espacios y guiones no cuentan); la desatendida se
    // envia tal como se escribio, asi que solo se rechaza la vacia.
    let (significant, max_chars) = match input.mode {
        ConnectMode::OnDemand => (
            input
                .password
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .count(),
            MAX_PASSWORD_CHARS,
        ),
        ConnectMode::Unattended => (input.password.chars().count(), UNATTENDED_PASSWORD_MAX_LEN),
    };
    if significant == 0 {
        return Err(FormError::PasswordEmpty);
    }
    if input.password.chars().count() > max_chars {
        return Err(FormError::PasswordTooLong);
    }

    let agent_name = sanitize_agent_name(&input.agent_name);
    if agent_name.is_empty() {
        return Err(FormError::NameEmpty);
    }

    Ok(ConnectionParams {
        mode: input.mode,
        session_id,
        password: input.password.clone(),
        agent_name,
        requested_capabilities: REQUESTED_CAPABILITIES,
    })
}

/// Carga la clave publica del servicio (`--host-key`): exactamente 32 bytes crudos de una
/// `VerifyingKey` Ed25519 valida.
pub fn parse_host_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| {
        format!(
            "La clave del host debe tener exactamente 32 bytes (el archivo tiene {}).",
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| "La clave del host no es una clave Ed25519 valida.".to_string())
}

/// Ocho bytes en hexadecimal agrupado `xxxx-xxxx-xxxx-xxxx`.
pub fn format_fingerprint(bytes: &[u8; 8]) -> String {
    let groups: Vec<String> = bytes
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect();
    groups.join("-")
}

/// Huella de la clave del servicio: los 8 primeros bytes de SHA-256(clave publica).
pub fn host_key_fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    format_fingerprint(&first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use awawa_protocol::CapabilityMask;

    fn input(id: &str, pw: &str, name: &str) -> FormInput {
        FormInput {
            mode: ConnectMode::OnDemand,
            session_id: id.to_string(),
            password: pw.to_string(),
            agent_name: name.to_string(),
        }
    }

    #[test]
    fn requested_capabilities_are_exactly_view_mouse_keyboard() {
        let mask = CapabilityMask::from_capabilities(REQUESTED_CAPABILITIES);
        assert_eq!(mask, CapabilityMask(0b0111));
        assert_eq!(
            REQUESTED_CAPABILITIES,
            ScopedCapabilities::FULL_DESKTOP_AND_PERIPHERALS
        );
        assert!(mask.validate().is_ok());
    }

    #[test]
    fn valid_form_produces_params() {
        let p = validate(&input("482-910-337", "K9MP4-XQ72B", "Soporte N2")).unwrap();
        assert_eq!(p.requested_capabilities, REQUESTED_CAPABILITIES);
        assert_eq!(p.session_id.formatted(), "482-910-337");
        assert_eq!(p.agent_name, "Soporte N2");
    }

    #[test]
    fn id_accepts_plain_digits_and_spaces() {
        assert!(validate(&input("482910337", "K9MP4", "A")).is_ok());
        assert!(validate(&input(" 482 910 337 ", "K9MP4", "A")).is_ok());
    }

    #[test]
    fn id_rejects_empty_short_letters_and_out_of_range() {
        assert_eq!(validate(&input("  ", "x", "A")), Err(FormError::IdEmpty));
        assert_eq!(validate(&input("123", "x", "A")), Err(FormError::IdInvalid));
        assert_eq!(
            validate(&input("48a-910-337", "x", "A")),
            Err(FormError::IdInvalid)
        );
        assert_eq!(
            validate(&input("012-345-678", "x", "A")),
            Err(FormError::IdInvalid)
        );
        assert_eq!(
            validate(&input("482-910-3371", "x", "A")),
            Err(FormError::IdInvalid)
        );
    }

    #[test]
    fn password_must_have_content_and_bounded_length() {
        assert_eq!(
            validate(&input("482-910-337", " - ", "A")),
            Err(FormError::PasswordEmpty)
        );
        let long = "A".repeat(MAX_PASSWORD_CHARS + 1);
        assert_eq!(
            validate(&input("482-910-337", &long, "A")),
            Err(FormError::PasswordTooLong)
        );
        let max = "A".repeat(MAX_PASSWORD_CHARS);
        assert!(validate(&input("482-910-337", &max, "A")).is_ok());
    }

    #[test]
    fn name_is_trimmed_stripped_and_capped() {
        assert_eq!(sanitize_agent_name("  Ana\u{0007}\n Perez  "), "Ana Perez");
        assert_eq!(sanitize_agent_name("Ana\u{202E}Perez"), "AnaPerez");
        let long = "n".repeat(MAX_NAME_CHARS + 20);
        assert_eq!(sanitize_agent_name(&long).chars().count(), MAX_NAME_CHARS);
        let multibyte = "\u{00F1}".repeat(MAX_NAME_CHARS + 5);
        assert_eq!(
            sanitize_agent_name(&multibyte).chars().count(),
            MAX_NAME_CHARS
        );
    }

    #[test]
    fn name_empty_after_sanitizing_is_rejected() {
        assert_eq!(
            validate(&input("482-910-337", "K9MP4", " \u{200B}\t ")),
            Err(FormError::NameEmpty)
        );
    }

    #[test]
    fn validated_name_is_the_sanitized_one() {
        let p = validate(&input("482-910-337", "K9MP4", "  Luis\u{0000} ")).unwrap();
        assert_eq!(p.agent_name, "Luis");
    }

    #[test]
    fn form_debug_does_not_reveal_password() {
        let f = input("482-910-337", "SECRETO99", "A");
        assert!(!format!("{f:?}").contains("SECRETO99"));
    }

    #[test]
    fn debug_does_not_reveal_password() {
        let p = validate(&input("482-910-337", "SECRETO99", "A")).unwrap();
        assert!(!format!("{p:?}").contains("SECRETO99"));
    }

    fn unattended(id: &str, pw: &str) -> FormInput {
        let mut f = input(id, pw, "Soporte N2");
        f.mode = ConnectMode::Unattended;
        f
    }

    /// Clave publica del vector 1 de la RFC 8032.
    const RFC8032_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn on_demand_is_the_default_mode() {
        assert_eq!(FormInput::default().mode, ConnectMode::OnDemand);
        let p = validate(&input("482-910-337", "K9MP4", "A")).unwrap();
        assert_eq!(p.mode, ConnectMode::OnDemand);
    }

    #[test]
    fn unattended_password_is_kept_without_normalizing() {
        let p = validate(&unattended("482-910-337", " clave larga - 77 ")).unwrap();
        assert_eq!(p.mode, ConnectMode::Unattended);
        assert_eq!(p.password, " clave larga - 77 ");
        assert_eq!(p.requested_capabilities, REQUESTED_CAPABILITIES);
        assert_eq!(p.session_id.formatted(), "482-910-337");
    }

    #[test]
    fn unattended_password_bounds() {
        assert_eq!(
            validate(&unattended("482-910-337", "")),
            Err(FormError::PasswordEmpty)
        );
        let long = "A".repeat(UNATTENDED_PASSWORD_MAX_LEN + 1);
        assert_eq!(
            validate(&unattended("482-910-337", &long)),
            Err(FormError::PasswordTooLong)
        );
        let max = "A".repeat(UNATTENDED_PASSWORD_MAX_LEN);
        assert!(validate(&unattended("482-910-337", &max)).is_ok());
        // Mas de 64 caracteres solo es valido en modo desatendido.
        let mid = "A".repeat(MAX_PASSWORD_CHARS + 1);
        assert_eq!(
            validate(&input("482-910-337", &mid, "A")),
            Err(FormError::PasswordTooLong)
        );
        assert!(validate(&unattended("482-910-337", &mid)).is_ok());
    }

    #[test]
    fn unattended_still_validates_the_id() {
        assert_eq!(
            validate(&unattended("123", "clave-larga-1234")),
            Err(FormError::IdInvalid)
        );
    }

    #[test]
    fn unattended_debug_does_not_reveal_password() {
        let f = unattended("482-910-337", "SECRETO-LARGO-99");
        assert!(!format!("{f:?}").contains("SECRETO-LARGO-99"));
        let p = validate(&f).unwrap();
        assert!(!format!("{p:?}").contains("SECRETO-LARGO-99"));
    }

    #[test]
    fn host_key_requires_exactly_32_valid_bytes() {
        let err = parse_host_key(&[1u8; 31]).unwrap_err();
        assert!(err.contains("32 bytes") && err.contains("31"), "{err}");
        assert!(parse_host_key(&[1u8; 33]).is_err());
        assert!(parse_host_key(&[]).is_err());
        // y = 2 no corresponde a ningun punto de la curva.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        assert!(parse_host_key(&off_curve).is_err());
        assert!(parse_host_key(&RFC8032_KEY).is_ok());
    }

    #[test]
    fn key_fingerprint_is_the_first_8_bytes_of_sha256_in_groups() {
        let key = parse_host_key(&RFC8032_KEY).unwrap();
        let d = Sha256::digest(RFC8032_KEY);
        let expected = format!(
            "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        );
        assert_eq!(host_key_fingerprint(&key), expected);
        assert_eq!(
            format_fingerprint(&[0x01, 0x02, 0xab, 0xcd, 0xef, 0x00, 0x10, 0xff]),
            "0102-abcd-ef00-10ff"
        );
    }
}
