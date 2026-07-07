use std::net::{TcpListener, IpAddr, UdpSocket};
use std::thread;
use std::time::Duration;

/// Factory class for generating unique file IDs.
///
/// Mirrors `ghidra.framework.store.FileIDFactory`.
pub struct FileIDFactory;

impl FileIDFactory {
    /// Creates a unique file ID using a combination of network information,
    /// port uniqueness, and system nanosecond precision.
    ///
    /// The returned ID is a hex string composed of:
    /// - Local host IP address bytes (as hex)
    /// - A uniquely assigned server port (as hex)
    /// - System nanosecond timestamp (as hex)
    ///
    /// If network information is unavailable, falls back to just the
    /// system nanosecond timestamp (as hex).
    pub fn create_file_id() -> String {
        thread::sleep(Duration::from_millis(2));

        match create_file_id_with_network() {
            Some(id) => id,
            None => fallback_file_id(),
        }
    }
}

fn get_local_ipv4() -> Option<std::net::Ipv4Addr> {
    UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|socket| {
            socket.connect("8.8.8.8:80").ok();
            socket.local_addr().ok()
        })
        .and_then(|addr| match addr.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            IpAddr::V6(_) => None,
        })
}

fn create_file_id_with_network() -> Option<String> {
    let listener = TcpListener::bind("0.0.0.0:0").ok()?;
    let addr = listener.local_addr().ok()?;
    let unique_port = addr.port();

    let local_ip = get_local_ipv4()?;
    let addr_bytes = local_ip.octets();
    let mut result = String::new();

    for b in addr_bytes {
        result.push_str(&format!("{:x}", b));
    }
    result.push_str(&format!("{:x}", unique_port));
    result.push_str(&format!("{:x}", system_nanos()));

    Some(result)
}

fn system_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn fallback_file_id() -> String {
    format!("{:x}", system_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_file_id_returns_hex_string() {
        let id = FileIDFactory::create_file_id();
        assert!(!id.is_empty());
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn create_file_id_different_calls_return_different_ids() {
        let id1 = FileIDFactory::create_file_id();
        thread::sleep(Duration::from_millis(10));
        let id2 = FileIDFactory::create_file_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn file_id_is_reasonably_long() {
        let id = FileIDFactory::create_file_id();
        assert!(id.len() > 8);
    }

    #[test]
    fn create_file_id_always_returns_string() {
        for _ in 0..5 {
            let id = FileIDFactory::create_file_id();
            assert!(!id.is_empty());
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
            thread::sleep(Duration::from_millis(2));
        }
    }
}
