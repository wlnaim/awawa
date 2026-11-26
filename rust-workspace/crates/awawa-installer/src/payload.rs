//! Carga util embebida por `build.rs`: cada `.exe` comprimido con zstd junto con su tamano y su
//! SHA-256. La extraccion descomprime con un tope igual al tamano declarado y compara el SHA-256
//! antes de devolver los bytes: un binario alterado nunca llega al disco.

use sha2::{Digest, Sha256};

/// Un binario embebido.
pub struct PayloadFile {
    pub name: &'static str,
    pub size: u64,
    pub sha256: [u8; 32],
    pub zst: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/payload.rs"));

/// `true` si el instalador trae carga (compilado con `AWAWA_INSTALLER_PAYLOAD`).
pub fn is_present() -> bool {
    !FILES.is_empty()
}

/// Binarios disponibles.
pub fn names() -> Vec<&'static str> {
    FILES.iter().map(|f| f.name).collect()
}

/// Extrae `name` de la carga embebida y verifica su SHA-256.
pub fn extract(name: &str) -> Result<Vec<u8>, String> {
    let file = FILES.iter().find(|f| f.name == name).ok_or_else(|| {
        if is_present() {
            format!("{name} no esta en la carga del instalador")
        } else {
            "instalador de desarrollo sin carga: no puede instalar binarios".to_string()
        }
    })?;
    decompress_verified(file.zst, file.size, &file.sha256).map_err(|e| format!("{name}: {e}"))
}

/// Descomprime `zst` (como mucho `size` bytes) y exige tamano y SHA-256 exactos.
pub fn decompress_verified(zst: &[u8], size: u64, sha256: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cap = usize::try_from(size).map_err(|_| "tamano fuera de rango".to_string())?;
    let bytes =
        zstd::bulk::decompress(zst, cap).map_err(|e| format!("carga zstd invalida: {e}"))?;
    if bytes.len() != cap {
        return Err(format!(
            "tamano {} distinto del esperado {cap}",
            bytes.len()
        ));
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != sha256 {
        return Err("SHA-256 distinto del embebido: carga corrupta".into());
    }
    Ok(bytes)
}

/// SHA-256 en hexadecimal (minusculas).
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed(data: &[u8]) -> (Vec<u8>, u64, [u8; 32]) {
        (
            zstd::bulk::compress(data, 3).unwrap(),
            data.len() as u64,
            Sha256::digest(data).into(),
        )
    }

    #[test]
    fn extrae_y_verifica_el_sha256() {
        let data = b"MZ binario de prueba".repeat(100);
        let (zst, size, sha) = packed(&data);
        assert_eq!(decompress_verified(&zst, size, &sha).unwrap(), data);
    }

    #[test]
    fn rechaza_sha256_o_tamano_distintos_y_basura() {
        let data = b"contenido".repeat(50);
        let (zst, size, mut sha) = packed(&data);
        assert!(decompress_verified(&zst, size + 1, &sha).is_err());
        assert!(decompress_verified(&zst, size - 1, &sha).is_err());
        sha[0] ^= 1;
        assert!(
            decompress_verified(&zst, size, &sha)
                .unwrap_err()
                .contains("SHA-256")
        );
        assert!(decompress_verified(b"no es zstd", 10, &sha).is_err());
    }

    #[test]
    fn sin_carga_lo_indica() {
        if !is_present() {
            assert!(extract("awawa-host.exe").unwrap_err().contains("sin carga"));
            assert!(names().is_empty());
        }
    }
}
