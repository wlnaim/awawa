//! 1. Embebe `awawa-installer.manifest` (`requireAdministrator` + `PerMonitorV2`) como `RT_MANIFEST`
//!    solo en el binario `awawa-installer`.
//! 2. Carga util: si `AWAWA_INSTALLER_PAYLOAD` apunta a una carpeta con los 6 `.exe` de release,
//!    comprime cada uno con zstd en `OUT_DIR` y genera `payload.rs` con su nombre, tamano, SHA-256 y
//!    `include_bytes!`. Sin la variable genera una tabla vacia: instalador de desarrollo sin carga.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Binarios que transporta el instalador (los mismos 6 que arma `scripts\package.ps1`).
const PAYLOAD_FILES: [&str; 6] = [
    "awawa-host.exe",
    "awawa-relay.exe",
    "awawa-service.exe",
    "awawa-session-agent.exe",
    "awawa-admin.exe",
    "awawa-operator.exe",
];
/// Nivel de zstd: determinista (un solo hilo) y razonable para ~60 MB.
const ZSTD_LEVEL: i32 = 12;
/// Importaciones directas del Setup que se cargan diferidas (`/DELAYLOAD`). Al arrancar el proceso
/// solo quedan ntdll, kernel32 y bcryptprimitives: el cargador resolveria las dependencias de segundo
/// nivel de estas DLL (por ejemplo opengl32 -> glu32, o UMPDC.dll que llega por SHELL32) con el
/// orden de busqueda por defecto, que incluye la carpeta del Setup. Diferidas, se cargan despues de
/// `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` y ellas y sus dependencias solo se
/// buscan en System32.
const DELAY_LOAD: [&str; 17] = [
    "advapi32.dll",
    "bcrypt.dll",
    "combase.dll",
    "crypt32.dll",
    "dwmapi.dll",
    "dxgi.dll",
    "gdi32.dll",
    "imm32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "opengl32.dll",
    "setupapi.dll",
    "shell32.dll",
    "uiautomationcore.dll",
    "user32.dll",
    "uxtheme.dll",
    "ws2_32.dll",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AWAWA_INSTALLER_PAYLOAD");
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    let mut code = String::from("pub static FILES: &[PayloadFile] = &[\n");
    if let Some(dir) = env::var_os("AWAWA_INSTALLER_PAYLOAD").filter(|d| !d.is_empty()) {
        let dir = PathBuf::from(dir);
        for name in PAYLOAD_FILES {
            let src = dir.join(name);
            println!("cargo:rerun-if-changed={}", src.display());
            let bytes = fs::read(&src).unwrap_or_else(|e| {
                panic!(
                    "AWAWA_INSTALLER_PAYLOAD: no se pudo leer {}: {e}",
                    src.display()
                )
            });
            assert!(!bytes.is_empty(), "{} esta vacio", src.display());
            let sha: [u8; 32] = Sha256::digest(&bytes).into();
            let zst = zstd::bulk::compress(&bytes, ZSTD_LEVEL).expect("comprimir con zstd");
            fs::write(out_dir.join(format!("{name}.zst")), zst).expect("escribir .zst");
            writeln!(
                code,
                "    PayloadFile {{ name: {name:?}, size: {}, sha256: {sha:?}, zst: include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.zst\")) }},",
                bytes.len()
            )
            .expect("formatear");
        }
    }
    code.push_str("];\n");
    fs::write(out_dir.join("payload.rs"), code).expect("escribir payload.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // El Setup corre elevado desde una carpeta que puede ser escribible por el usuario (Descargas):
    // las DLL de sus importaciones estaticas solo se buscan en System32 (LOAD_LIBRARY_SEARCH_SYSTEM32),
    // nunca junto al ejecutable. Las cargas dinamicas las cubre `SetDefaultDllDirectories` en `main`.
    println!("cargo:rustc-link-arg-bin=awawa-installer=/DEPENDENTLOADFLAG:0x800");
    for dll in DELAY_LOAD {
        println!("cargo:rustc-link-arg-bin=awawa-installer=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-arg-bin=awawa-installer=delayimp.lib");
    let manifest = manifest_dir.join("awawa-installer.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    // Recurso 1 de tipo 24: CREATEPROCESS_MANIFEST_RESOURCE_ID / RT_MANIFEST.
    let manifest_path = manifest.display().to_string().replace('\\', "/");
    let icon = manifest_dir.join("../../assets/awawa-hacker.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    let icon_path = icon.display().to_string().replace('\\', "/");
    let rc_path = out_dir.join("awawa-installer.rc");
    fs::write(
        &rc_path,
        format!("1 24 \"{manifest_path}\"\n1 ICON \"{icon_path}\"\n"),
    )
    .expect("escribir el .rc");
    embed_resource::compile_for(&rc_path, ["awawa-installer"], embed_resource::NONE)
        .manifest_required()
        .expect("embeber el manifiesto");
}
