//! Embebe `awawa-operator.manifest` (`asInvoker` + `PerMonitorV2`) como `RT_MANIFEST` del ejecutable.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir.join("awawa-operator.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Recurso 1 de tipo 24: CREATEPROCESS_MANIFEST_RESOURCE_ID / RT_MANIFEST.
    let manifest_path = manifest.display().to_string().replace('\\', "/");
    let icon = manifest_dir.join("../../assets/awawa-hacker.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    let icon_path = icon.display().to_string().replace('\\', "/");
    let rc_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("awawa-operator.rc");
    fs::write(
        &rc_path,
        format!("1 24 \"{manifest_path}\"\n1 ICON \"{icon_path}\"\n"),
    )
    .expect("escribir awawa-operator.rc");

    embed_resource::compile(&rc_path, embed_resource::NONE)
        .manifest_required()
        .expect("embeber el manifiesto de awawa-operator");
}
