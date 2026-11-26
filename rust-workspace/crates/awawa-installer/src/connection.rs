//! Archivo de conexion `.rrs` que el Host genera y el Agente de soporte importa.
//!
//! Texto ASCII por lineas (`\n` o `\r\n`), sin secretos:
//!
//! ```text
//! Awawa-Conexion 1
//! # comentario opcional
//! relay=192.168.1.20:4433
//! relay-pin=3082...            (DER de relay-cert.der en hexadecimal)
//! host-id=123456789            (opcional, solo con acceso desatendido; exige host-key)
//! host-key=9f1c...             (opcional, 32 bytes Ed25519 en hexadecimal)
//! ```
//!
//! La lectura es estricta: cabecera exacta, claves conocidas sin repetir, `host-id` solo junto
//! con `host-key`, tope de tamano, DER con cabecera SEQUENCE y longitud coherente, y clave de 32
//! bytes que sea un punto Ed25519 valido. El pin y la clave del host son material publico.

use std::path::Path;

use awawa_protocol::unattended_channel::VerifyingKey;
use awawa_service::relay_config::MAX_PIN_LEN;
use sha2::{Digest, Sha256};

use crate::cmdline::check_relay_addr;

pub const HEADER: &str = "Awawa-Conexion 1";
/// Nombre por defecto del archivo exportado.
pub const DEFAULT_FILE_NAME: &str = "Awawa-conexion.rrs";
/// Tope del archivo: el pin en hexadecimal (2 x 64 KiB) mas las demas lineas.
pub const MAX_FILE_LEN: usize = 2 * MAX_PIN_LEN + 4096;
pub const HOST_KEY_LEN: usize = 32;

/// Identidad publica del servicio desatendido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    /// ID persistente (9 digitos); `None` si la clave se importo a mano sin el archivo.
    pub id: Option<u32>,
    pub key: [u8; HOST_KEY_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub relay_addr: String,
    pub relay_pin: Vec<u8>,
    pub host: Option<HostIdentity>,
}

impl ConnectionInfo {
    /// Valida todos los campos (lo mismo que exige `parse`).
    pub fn validate(&self) -> Result<(), String> {
        check_relay_addr(&self.relay_addr)?;
        validate_pin(&self.relay_pin)?;
        if let Some(host) = &self.host {
            if let Some(id) = host.id {
                validate_host_id(id)?;
            }
            validate_host_key(&host.key)?;
        }
        Ok(())
    }

    pub fn to_text(&self) -> String {
        let mut text = format!(
            "{HEADER}\n# Archivo de conexion de Awawa. No contiene contrasenas.\nrelay={}\nrelay-pin={}\n",
            self.relay_addr,
            hex(&self.relay_pin)
        );
        if let Some(host) = &self.host {
            if let Some(id) = host.id {
                text.push_str(&format!("host-id={id}\n"));
            }
            text.push_str(&format!("host-key={}\n", hex(&host.key)));
        }
        text
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_FILE_LEN {
            return Err("archivo de conexion demasiado grande".into());
        }
        let text = std::str::from_utf8(bytes)
            .ok()
            .filter(|t| t.is_ascii())
            .ok_or("el archivo de conexion no es texto ASCII")?;
        let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        if lines.next() != Some(HEADER) {
            return Err(format!("cabecera invalida: se esperaba \"{HEADER}\""));
        }
        let (mut relay, mut pin, mut id, mut key) = (None, None, None, None);
        for line in lines {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("linea sin '=': {}", truncate(line)))?;
            let slot = match name {
                "relay" => &mut relay,
                "relay-pin" => &mut pin,
                "host-id" => &mut id,
                "host-key" => &mut key,
                other => return Err(format!("clave desconocida: {}", truncate(other))),
            };
            if slot.replace(value).is_some() {
                return Err(format!("clave repetida: {name}"));
            }
        }
        let relay_addr = relay.ok_or("falta relay=")?.to_owned();
        let relay_pin =
            unhex(pin.ok_or("falta relay-pin=")?).ok_or("relay-pin no es hexadecimal")?;
        let host = match (id, key) {
            (None, None) => None,
            (Some(_), None) => return Err("host-id requiere host-key".into()),
            (id, Some(key)) => {
                let id = id.map(parse_host_id).transpose()?;
                let key = unhex(key).ok_or("host-key no es hexadecimal")?;
                Some(HostIdentity {
                    id,
                    key: validate_host_key(&key)?,
                })
            }
        };
        let info = Self {
            relay_addr,
            relay_pin,
            host,
        };
        info.validate()?;
        Ok(info)
    }
}

/// Lee un archivo con tope de tamano (sin cargar archivos enormes en memoria).
fn read_capped(path: &Path, max: usize, what: &str) -> Result<Vec<u8>, String> {
    let len = std::fs::metadata(path)
        .map_err(|e| format!("{what} {}: {e}", path.display()))?
        .len();
    if len > max as u64 {
        return Err(format!("{what} {}: demasiado grande", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("{what} {}: {e}", path.display()))
}

/// Importa un archivo `.rrs`.
pub fn load_file(path: &Path) -> Result<ConnectionInfo, String> {
    ConnectionInfo::parse(&read_capped(path, MAX_FILE_LEN, "archivo de conexion")?)
}

/// Importacion manual: direccion, `relay-cert.der` y, opcional, la clave del host (32 bytes crudos de
/// `awawa-admin status --export-key`).
pub fn from_files(
    relay: &str,
    pin: &Path,
    host_key: Option<&Path>,
) -> Result<ConnectionInfo, String> {
    let relay_pin = read_capped(pin, MAX_PIN_LEN, "pin del relay")?;
    let host = match host_key {
        Some(path) => Some(HostIdentity {
            id: None,
            key: validate_host_key(&read_capped(path, HOST_KEY_LEN, "clave del host")?)?,
        }),
        None => None,
    };
    let info = ConnectionInfo {
        relay_addr: relay.trim().to_owned(),
        relay_pin,
        host,
    };
    info.validate()?;
    Ok(info)
}

fn truncate(text: &str) -> String {
    text.chars().take(40).collect()
}

/// DER no vacio, como mucho `MAX_PIN_LEN`, con cabecera SEQUENCE y longitud igual al archivo.
pub fn validate_pin(der: &[u8]) -> Result<(), String> {
    if der.is_empty() {
        return Err("el pin del relay esta vacio".into());
    }
    if der.len() > MAX_PIN_LEN {
        return Err("el pin del relay es demasiado grande".into());
    }
    let bad = || "el pin del relay no es un certificado DER (relay-cert.der)".to_string();
    if der.len() < 2 || der[0] != 0x30 {
        return Err(bad());
    }
    let (len, header) = match der[1] {
        n if n < 0x80 => (usize::from(n), 2),
        0x81 if der.len() > 2 => (usize::from(der[2]), 3),
        0x82 if der.len() > 3 => (usize::from(der[2]) << 8 | usize::from(der[3]), 4),
        0x83 if der.len() > 4 => (
            usize::from(der[2]) << 16 | usize::from(der[3]) << 8 | usize::from(der[4]),
            5,
        ),
        _ => return Err(bad()),
    };
    if header + len != der.len() {
        return Err(bad());
    }
    Ok(())
}

/// 32 bytes que sean una clave publica Ed25519 valida.
pub fn validate_host_key(bytes: &[u8]) -> Result<[u8; HOST_KEY_LEN], String> {
    let key: [u8; HOST_KEY_LEN] = bytes.try_into().map_err(|_| {
        format!(
            "la clave del host debe tener {HOST_KEY_LEN} bytes (tiene {})",
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "la clave del host no es una clave Ed25519 valida")?;
    Ok(key)
}

/// ID persistente del servicio: 9 digitos (100000000..=999999999).
pub fn validate_host_id(id: u32) -> Result<(), String> {
    if (100_000_000..=999_999_999).contains(&id) {
        Ok(())
    } else {
        Err(format!("ID del equipo invalido: {id}"))
    }
}

fn parse_host_id(text: &str) -> Result<u32, String> {
    if text.len() != 9 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("host-id debe tener 9 digitos".into());
    }
    let id = text.parse().map_err(|_| "host-id invalido")?;
    validate_host_id(id)?;
    Ok(id)
}

/// Huella del pin para comparar a ojo: SHA-256 completo en grupos de 4 hexadecimales.
pub fn pin_fingerprint(der: &[u8]) -> String {
    let hex = hex(&Sha256::digest(der));
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Huella de la clave del host con el mismo formato que `awawa-admin status` y el operador.
pub fn host_key_fingerprint(key: &[u8; HOST_KEY_LEN]) -> String {
    match VerifyingKey::from_bytes(key) {
        Ok(key) => awawa_service::service_identity::key_fingerprint(&key),
        Err(_) => "clave invalida".into(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// DER minimo con cabecera SEQUENCE y longitud larga (como un certificado real).
    pub(crate) fn sample_pin() -> Vec<u8> {
        let mut der = vec![0x30, 0x81, 200];
        der.extend((0..200u8).map(|i| i.wrapping_mul(7)));
        der
    }

    /// Clave publica Ed25519 valida (punto base).
    pub(crate) fn sample_key() -> [u8; 32] {
        let mut key = [0x66u8; 32];
        key[0] = 0x58;
        key
    }

    fn sample(host: bool) -> ConnectionInfo {
        ConnectionInfo {
            relay_addr: "192.168.1.20:4433".into(),
            relay_pin: sample_pin(),
            host: host.then(|| HostIdentity {
                id: Some(123_456_789),
                key: sample_key(),
            }),
        }
    }

    #[test]
    fn ida_y_vuelta_con_y_sin_host() {
        for host in [false, true] {
            let info = sample(host);
            let text = info.to_text();
            assert!(text.starts_with(HEADER));
            assert_eq!(ConnectionInfo::parse(text.as_bytes()).unwrap(), info);
            let crlf = text.replace('\n', "\r\n");
            assert_eq!(ConnectionInfo::parse(crlf.as_bytes()).unwrap(), info);
        }
    }

    #[test]
    fn el_formato_es_estable() {
        let mut info = sample(true);
        info.relay_pin = vec![0x30, 0x01, 0xaa];
        assert_eq!(
            info.to_text(),
            "Awawa-Conexion 1\n# Archivo de conexion de Awawa. No contiene contrasenas.\nrelay=192.168.1.20:4433\nrelay-pin=3001aa\nhost-id=123456789\nhost-key=5866666666666666666666666666666666666666666666666666666666666666\n"
        );
    }

    #[test]
    fn rechaza_archivos_malformados() {
        let good = sample(true).to_text();
        let cases: Vec<(String, &str)> = vec![
            (good.replace(HEADER, "Otro 1"), "cabecera"),
            (format!("{good}relay=1.2.3.4:4433\n"), "repetida"),
            (format!("{good}extra=1\n"), "desconocida"),
            (format!("{good}sin igual\n"), "sin '='"),
            (
                good.replace(&format!("host-key={}\n", hex(&sample_key())), ""),
                "requiere host-key",
            ),
            (
                good.replace("host-id=123456789", "host-id=12345"),
                "9 digitos",
            ),
            (
                good.replace("host-id=123456789", "host-id=012345678"),
                "invalido",
            ),
            (
                good.replace("relay=192.168.1.20:4433", "relay=1.2.3.4"),
                "puerto",
            ),
            (
                good.replace("relay=192.168.1.20:4433", "relay=1.2.3.4:4433 x"),
                "invalid",
            ),
            (format!("{HEADER}\nrelay=1.2.3.4:4433\n"), "relay-pin"),
            (
                format!("{HEADER}\nrelay=1.2.3.4:4433\nrelay-pin=\n"),
                "vacio",
            ),
            (
                format!("{HEADER}\nrelay=1.2.3.4:4433\nrelay-pin=zz\n"),
                "hexadecimal",
            ),
            (
                format!("{HEADER}\nrelay=1.2.3.4:4433\nrelay-pin=300201\n"),
                "DER",
            ),
            (
                format!("{HEADER}\nrelay=1.2.3.4:4433\nrelay-pin=310100\n"),
                "DER",
            ),
        ];
        for (text, expected) in cases {
            let err = ConnectionInfo::parse(text.as_bytes()).unwrap_err();
            assert!(err.contains(expected), "{expected}: {err}");
        }
        let short_key = good.replace(&hex(&sample_key()), &hex(&[1u8; 31]));
        assert!(
            ConnectionInfo::parse(short_key.as_bytes())
                .unwrap_err()
                .contains("32 bytes")
        );
        assert!(ConnectionInfo::parse(&vec![b'a'; MAX_FILE_LEN + 1]).is_err());
        assert!(ConnectionInfo::parse(b"Awawa-Conexion 1\n\xff").is_err());
        assert!(ConnectionInfo::parse(b"").is_err());
    }

    #[test]
    fn clave_del_host_sin_id() {
        let mut info = sample(true);
        info.host.as_mut().unwrap().id = None;
        let text = info.to_text();
        assert!(!text.contains("host-id"));
        assert_eq!(ConnectionInfo::parse(text.as_bytes()).unwrap(), info);
    }

    #[test]
    fn valida_pin_y_clave() {
        assert!(validate_pin(&sample_pin()).is_ok());
        assert!(validate_pin(&[]).is_err());
        assert!(validate_pin(&[0x30]).is_err());
        assert!(validate_pin(&vec![0x30; MAX_PIN_LEN + 1]).is_err());
        assert!(validate_host_key(&sample_key()).is_ok());
        assert!(validate_host_key(&[0u8; 33]).is_err());
    }

    #[test]
    fn importacion_manual_y_desde_archivo() {
        let dir = std::env::temp_dir().join(format!("installer-conn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pin = dir.join("relay-cert.der");
        let key = dir.join("host-key.bin");
        std::fs::write(&pin, sample_pin()).unwrap();
        std::fs::write(&key, sample_key()).unwrap();

        let info = from_files(" 10.0.0.5:4433 ", &pin, Some(&key)).unwrap();
        assert_eq!(info.relay_addr, "10.0.0.5:4433");
        assert_eq!(info.host.as_ref().unwrap().id, None);
        assert!(
            from_files("10.0.0.5:4433", &pin, None)
                .unwrap()
                .host
                .is_none()
        );

        std::fs::write(&key, [1u8; 33]).unwrap();
        assert!(from_files("10.0.0.5:4433", &pin, Some(&key)).is_err());
        std::fs::write(&key, [1u8; 31]).unwrap();
        assert!(from_files("10.0.0.5:4433", &pin, Some(&key)).is_err());
        std::fs::write(&pin, b"").unwrap();
        assert!(from_files("10.0.0.5:4433", &pin, None).is_err());
        assert!(from_files("10.0.0.5:4433", &dir.join("no-existe.der"), None).is_err());

        let rrs = dir.join("c.rrs");
        std::fs::write(&rrs, sample(true).to_text()).unwrap();
        assert_eq!(load_file(&rrs).unwrap(), sample(true));
        std::fs::write(&rrs, vec![b'#'; MAX_FILE_LEN + 1]).unwrap();
        assert!(load_file(&rrs).unwrap_err().contains("demasiado grande"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn huellas() {
        let fp = pin_fingerprint(b"abc");
        assert_eq!(fp.split(' ').count(), 16);
        assert!(fp.starts_with("ba78 16bf 8f01 cfea"));
        assert_eq!(host_key_fingerprint(&sample_key()).len(), 19);
    }
}
