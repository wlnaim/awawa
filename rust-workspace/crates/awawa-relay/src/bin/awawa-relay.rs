//! Binario minimo del relay: escucha en UDP 4433 (o `--bind`) y usa el certificado de `--dir`.
//!
//! Uso: `awawa-relay [--bind IP:PUERTO] [--dir CARPETA]`
//!
//! En `--dir` (por defecto la carpeta actual) busca `relay-cert.der` y `relay-key.der`. Si ninguno
//! existe, genera una identidad nueva y la guarda; `relay-cert.der` es el material publico que se
//! fija en los clientes. `relay-key.der` es secreto: se escribe de forma atomica con una DACL que solo
//! concede acceso al usuario que ejecuta el relay, a SYSTEM y a Administradores, y al arrancar se
//! rechaza una clave existente con permisos mas amplios (ver `keyfile`). No se instala como servicio.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use awawa_relay::{RELAY_PORT, RelayConfig, RelayIdentity, RelayServer};

#[path = "awawa-relay/keyfile.rs"]
mod keyfile;

const CERT_FILE: &str = "relay-cert.der";
const KEY_FILE: &str = "relay-key.der";

struct Args {
    bind: SocketAddr,
    dir: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut bind: SocketAddr = ([0, 0, 0, 0], RELAY_PORT).into();
    let mut dir = PathBuf::from(".");
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("falta el valor de {flag}"))?;
        match flag.as_str() {
            "--bind" => {
                bind = value
                    .parse()
                    .map_err(|_| format!("direccion invalida: {value}"))?;
            }
            "--dir" => dir = PathBuf::from(value),
            other => return Err(format!("argumento desconocido: {other}")),
        }
    }
    Ok(Args { bind, dir })
}

fn load_or_create_identity(dir: &Path) -> Result<RelayIdentity, String> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            keyfile::check_key_acl(&key_path)?;
            let cert = std::fs::read(&cert_path).map_err(|e| e.to_string())?;
            let key = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            Ok(RelayIdentity::from_der(cert, key))
        }
        (false, false) => {
            let identity = RelayIdentity::generate().map_err(|e| e.to_string())?;
            // La clave primero: si se interrumpe entre ambos, queda solo la clave (el siguiente
            // arranque pide ambos o ninguno) y nunca un certificado sin su clave protegida.
            keyfile::write_key_atomic(&key_path, identity.key_pkcs8_der())?;
            keyfile::write_atomic(&cert_path, identity.cert_der())?;
            tracing::info!(cert = %cert_path.display(), "identidad nueva generada");
            Ok(identity)
        }
        _ => Err(format!(
            "falta {CERT_FILE} o {KEY_FILE} en {}: se necesitan ambos o ninguno",
            dir.display()
        )),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().init();
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}\nuso: awawa-relay [--bind IP:PUERTO] [--dir CARPETA]");
            return ExitCode::from(2);
        }
    };
    let identity = match load_or_create_identity(&args.dir) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("identidad del relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let server = match RelayServer::bind(args.bind, &identity, RelayConfig::default()) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // La clave ya esta en el servidor: se pone a cero la copia de la identidad.
    drop(identity);
    tracing::info!(addr = %args.bind, "relay escuchando");
    let handle = server.handle();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("cierre solicitado");
        handle.shutdown();
    });
    server.run().await;
    ExitCode::SUCCESS
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use awawa_protocol::SessionId;
    use awawa_relay::RelayClient;

    #[tokio::test]
    async fn crea_la_identidad_protegida_la_recarga_y_empareja() {
        let dir = std::env::temp_dir().join(format!("relay-bin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let created = load_or_create_identity(&dir).unwrap();
        let pin = created.pin();
        let reloaded = load_or_create_identity(&dir).unwrap();
        assert_eq!(reloaded.cert_der(), created.cert_der());
        assert_eq!(reloaded.key_pkcs8_der(), created.key_pkcs8_der());
        let tmp: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(tmp.is_empty(), "no debe quedar temporal");

        let server = RelayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            &reloaded,
            RelayConfig::default(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = server.handle();
        tokio::spawn(server.run());

        let id = SessionId::parse("123-456-789").unwrap();
        let host = RelayClient::new(addr, pin.clone()).unwrap();
        let operator = RelayClient::new(addr, pin).unwrap();
        let registration = host.register_host(id).await.unwrap();
        let host_task = tokio::spawn(async move {
            let mut stream = registration.wait_for_operator().await.unwrap();
            stream.send_frame(b"hola").await.unwrap();
            stream
        });
        let mut op = operator.connect_operator(id).await.unwrap();
        assert_eq!(op.recv_frame().await.unwrap(), b"hola");
        let _host_stream = host_task.await.unwrap();
        handle.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_clave_con_permisos_amplios_impide_arrancar() {
        let dir = std::env::temp_dir().join(format!("relay-bin-insegura-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = RelayIdentity::generate().unwrap();
        std::fs::write(dir.join(CERT_FILE), identity.cert_der()).unwrap();
        std::fs::write(dir.join(KEY_FILE), identity.key_pkcs8_der()).unwrap(); // DACL heredada
        let err = load_or_create_identity(&dir).unwrap_err();
        assert!(err.contains("permisos inseguros"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
