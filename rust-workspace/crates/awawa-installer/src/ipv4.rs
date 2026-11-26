//! IPv4 locales candidatas para el archivo de conexion. Sin FFI: la de la ruta por defecto (un socket
//! UDP "conectado" a una direccion de documentacion, que no envia nada) y las que resuelve el nombre
//! del equipo. La lista solo se sugiere: el usuario la puede editar.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};

/// Direcciones utiles para otro equipo: ni loopback, ni sin especificar, ni enlace local, ni multicast.
pub fn usable(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast())
}

/// IPv4 locales, la de la ruta por defecto primero y sin repetir.
pub fn local_ipv4() -> Vec<Ipv4Addr> {
    let mut found = Vec::new();
    // 192.0.2.1 (TEST-NET-1): solo elige la interfaz de salida; no se envia ningun paquete.
    if let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        && socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).is_ok()
        && let Ok(SocketAddr::V4(addr)) = socket.local_addr()
    {
        found.push(*addr.ip());
    }
    if let Ok(name) = std::env::var("COMPUTERNAME")
        && let Ok(addrs) = (name.as_str(), 0).to_socket_addrs()
    {
        found.extend(addrs.filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }));
    }
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for ip in found {
        if usable(ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtra_direcciones_inutiles() {
        assert!(usable(Ipv4Addr::new(192, 168, 1, 20)));
        assert!(usable(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(!usable(Ipv4Addr::LOCALHOST));
        assert!(!usable(Ipv4Addr::UNSPECIFIED));
        assert!(!usable(Ipv4Addr::new(169, 254, 3, 4)));
        assert!(!usable(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!usable(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn la_lista_no_repite_ni_incluye_loopback() {
        let ips = local_ipv4();
        for (i, ip) in ips.iter().enumerate() {
            assert!(usable(*ip));
            assert!(!ips[i + 1..].contains(ip));
        }
    }
}
