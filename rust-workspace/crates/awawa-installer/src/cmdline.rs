//! Construccion de lineas de comandos y argumentos de accesos directos.
//!
//! Regla: ninguna entrada del usuario llega a una linea de comandos sin validar. Las direcciones solo
//! admiten `[A-Za-z0-9.-]`, `:` y corchetes (IPv6) con puerto; las rutas deben ser absolutas, sin
//! comillas, sin caracteres de control y sin `\` final (que escaparia la comilla de cierre).

use std::fmt;
use std::path::{Path, PathBuf};

/// Comprueba la forma `host:puerto` y que solo use caracteres seguros para una linea de comandos.
pub fn check_relay_addr(addr: &str) -> Result<(), String> {
    awawa_service::relay_config::validate_addr(addr)?;
    if addr.len() > 255
        || !addr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err(format!(
            "direccion del relay con caracteres no permitidos: {addr}"
        ));
    }
    Ok(())
}

/// Texto de una ruta apta para una linea de comandos (ver reglas del modulo).
pub fn path_arg(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("ruta no representable: {}", path.display()))?;
    if !path.is_absolute() {
        return Err(format!("la ruta debe ser absoluta: {text}"));
    }
    if text.contains('"') || text.chars().any(char::is_control) || text.ends_with('\\') {
        return Err(format!(
            "ruta no permitida en una linea de comandos: {text}"
        ));
    }
    Ok(text.to_owned())
}

/// Entrecomilla `text` si tiene espacios (las reglas de `path_arg` ya excluyen comillas y `\` final).
pub fn quote(text: &str) -> String {
    if text.is_empty() || text.contains([' ', '\t']) {
        format!("\"{text}\"")
    } else {
        text.to_owned()
    }
}

/// Argumentos del acceso directo de `awawa-host`.
pub fn host_args(relay: &str, pin: &Path) -> Result<String, String> {
    check_relay_addr(relay)?;
    Ok(format!(
        "--relay {relay} --relay-pin {}",
        quote(&path_arg(pin)?)
    ))
}

/// Argumentos del acceso directo de `awawa-operator`.
pub fn operator_args(relay: &str, pin: &Path, host_key: Option<&Path>) -> Result<String, String> {
    let mut args = host_args(relay, pin)?;
    if let Some(key) = host_key {
        args.push_str(&format!(" --host-key {}", quote(&path_arg(key)?)));
    }
    Ok(args)
}

/// Proceso del sistema con argumentos fijos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// `true`: cada argumento se pasa tal cual (`raw_arg`), ya entrecomillado por quien lo construye.
    /// Solo `netsh`, que exige `program="..."` con la comilla tras el signo igual.
    pub raw: bool,
}

impl CommandSpec {
    pub fn new(program: PathBuf, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            raw: false,
        }
    }
}

impl fmt::Display for CommandSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.program.display())?;
        for arg in &self.args {
            if self.raw {
                write!(f, " {arg}")?;
            } else {
                write!(f, " {}", quote(arg))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direcciones_validas_e_invalidas() {
        assert!(check_relay_addr("192.168.1.20:4433").is_ok());
        assert!(check_relay_addr("relay.example.org:4433").is_ok());
        assert!(check_relay_addr("[fe80::1]:4433").is_ok());
        for bad in [
            "192.168.1.20",
            "192.168.1.20:0",
            "192.168.1.20:99999",
            ":4433",
            "1.2.3.4:4433 --host-key x",
            "1.2.3.4:4433\"",
            "a&b:4433",
            "a\tb:4433",
        ] {
            assert!(check_relay_addr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rutas_validas_e_invalidas() {
        assert_eq!(
            path_arg(Path::new(r"C:\Program Files\X\a.der")).unwrap(),
            r"C:\Program Files\X\a.der"
        );
        assert!(path_arg(Path::new("relativa.der")).is_err());
        assert!(path_arg(Path::new(r"C:\X\")).is_err());
        assert!(path_arg(Path::new("C:\\X\\a\"b.der")).is_err());
        assert!(path_arg(Path::new("C:\\X\\a\nb.der")).is_err());
    }

    #[test]
    fn argumentos_de_los_accesos_directos() {
        let pin = Path::new(r"C:\ProgramData\Awawa-Relay\relay-cert.der");
        assert_eq!(
            host_args("127.0.0.1:4433", pin).unwrap(),
            r"--relay 127.0.0.1:4433 --relay-pin C:\ProgramData\Awawa-Relay\relay-cert.der"
        );
        let pin = Path::new(r"C:\Program Files\Awawa\conexion\relay-cert.der");
        let key = Path::new(r"C:\Program Files\Awawa\conexion\host-key.bin");
        assert_eq!(
            operator_args("10.0.0.5:4433", pin, Some(key)).unwrap(),
            "--relay 10.0.0.5:4433 --relay-pin \"C:\\Program Files\\Awawa\\conexion\\relay-cert.der\" --host-key \"C:\\Program Files\\Awawa\\conexion\\host-key.bin\""
        );
        assert!(operator_args("10.0.0.5:4433 --x", pin, None).is_err());
    }

    #[test]
    fn el_comando_se_muestra_entrecomillado() {
        let cmd = CommandSpec::new(
            PathBuf::from(r"C:\Program Files\R\awawa-service.exe"),
            &["install", "--relay-pin", r"C:\Program Data\c.der"],
        );
        assert_eq!(
            cmd.to_string(),
            "\"C:\\Program Files\\R\\awawa-service.exe\" install --relay-pin \"C:\\Program Data\\c.der\""
        );
    }
}
