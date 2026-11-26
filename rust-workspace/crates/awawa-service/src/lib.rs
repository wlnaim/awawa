//! # `awawa-service`
//!
//! Piezas de Windows del acceso desatendido:
//! - [`kdf_cng`]: PBKDF2-HMAC-SHA256 con CNG (`BCryptDeriveKeyPBKDF2`) para el verificador v1.
//! - [`kdf_argon2`]: Argon2id para el verificador v2 y `ServiceKdf` (Argon2id para v2, CNG para v1).
//! - [`dpapi_store`]: proteccion en reposo del verificador (DPAPI + DACL protegida, escritura atomica).
//! - [`input_desktop`]: sonda del escritorio de entrada (detecta el escritorio seguro de UAC) sin cambiar de escritorio.
//! - [`session_events`]: mapeo puro de `WTS_*` (cambio de sesion) a eventos del monitor de escritorio.
//! - [`audit_sink`]: destinos de auditoria (archivo JSON Lines protegido y Event Log).
//! - [`agent_launcher`]: lanzamiento del agente en la sesion del usuario con su token.
//! - [`trust`]: validacion fail-closed de directorios y archivos (dueno, DACL, reparse points).
//! - [`session_tracker`]: sesion remota activa y su monitor; revalidacion ante cambio/revocacion.
//! - [`unattended_auth`]: autenticacion que recarga el verificador del disco en cada intento.
//! - [`identity`]: SID y nombre de cuenta desde el token.
//! - [`admin_ops`]: configurar/cambiar/revocar la contrasena persistente sobre el almacen.
//! - [`admin_pipe`]: pipe de administracion; `awawa-admin` entrega la contrasena y solo el servicio deriva y persiste.
//! - [`service_identity`]: ID persistente y par Ed25519 del servicio (DPAPI + DACL SY/BA).
//! - [`relay_config`]: direccion y certificado fijado del relay (configuracion protegida).
//! - [`agent_pipe`]: protocolo y pipe con DACL entre el servicio y el agente de sesion.
//! - [`unattended_net`]: registro en el relay, canal E2E, autenticacion, sesion y cierre ordenado.
//!
//! El crate es solo Windows: sus modulos usan FFI manual.
#![cfg(target_os = "windows")]

pub mod admin_ops;
pub mod admin_pipe;
pub mod agent_launcher;
pub mod agent_pipe;
pub mod audit_sink;
pub mod dpapi_store;
pub mod identity;
pub mod input_desktop;
pub mod kdf_argon2;
pub mod kdf_cng;
pub mod relay_config;
pub mod service_identity;
pub mod session_events;
pub mod session_tracker;
pub mod trust;
pub mod unattended_auth;
pub mod unattended_net;
pub mod winutil;

#[cfg(test)]
pub(crate) mod testutil;
