//! Embebe el manifiesto `RT_MANIFEST` (`asInvoker`, sin DPI: es de consola) solo en el binario
//! `awawa-relay`; las pruebas y la biblioteca no lo reciben.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest = manifest_dir.join("awawa-relay.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());

    // Recurso 1 de tipo 24: CREATEPROCESS_MANIFEST_RESOURCE_ID / RT_MANIFEST.
    let manifest_path = manifest.display().to_string().replace('\\', "/");
    let icon = manifest_dir.join("../../assets/awawa-hacker.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    let icon_path = icon.display().to_string().replace('\\', "/");
    let rc_path = out_dir.join("awawa-relay.rc");
    fs::write(
        &rc_path,
        format!("1 24 \"{manifest_path}\"\n1 ICON \"{icon_path}\"\n"),
    )
    .expect("escribir el .rc");

    embed_resource::compile_for(&rc_path, ["awawa-relay"], embed_resource::NONE)
        .manifest_required()
        .expect("embeber el manifiesto");
}
