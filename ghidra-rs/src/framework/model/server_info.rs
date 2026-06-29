use std::fmt;

/// Container for a host name and port number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    host: String,
    port: u16,
}

impl ServerInfo {
    /// Construct a new `ServerInfo`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }

    /// Get the server hostname or IP address as originally specified.
    pub fn server_name(&self) -> &str {
        &self.host
    }

    /// Get the port number.
    pub fn port_number(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for ServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    fn hash_of(v: &ServerInfo) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_server_name() {
        let info = ServerInfo::new("localhost", 13100);
        assert_eq!(info.server_name(), "localhost");
    }

    #[test]
    fn test_port_number() {
        let info = ServerInfo::new("localhost", 13100);
        assert_eq!(info.port_number(), 13100);
    }

    #[test]
    fn test_display() {
        let info = ServerInfo::new("myhost", 9999);
        assert_eq!(info.to_string(), "myhost:9999");
    }

    #[test]
    fn test_equality_same() {
        let a = ServerInfo::new("host", 80);
        let b = ServerInfo::new("host", 80);
        assert_eq!(a, b);
    }

    #[test]
    fn test_equality_different_host() {
        let a = ServerInfo::new("host1", 80);
        let b = ServerInfo::new("host2", 80);
        assert_ne!(a, b);
    }

    #[test]
    fn test_equality_different_port() {
        let a = ServerInfo::new("host", 80);
        let b = ServerInfo::new("host", 81);
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_consistent_for_equal_objects() {
        let a = ServerInfo::new("host", 80);
        let b = ServerInfo::new("host", 80);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn test_usable_as_hash_key() {
        let mut set = HashSet::new();
        let a = ServerInfo::new("host", 8080);
        set.insert(a.clone());
        assert!(set.contains(&a));
    }

    #[test]
    fn test_clone() {
        let a = ServerInfo::new("host", 443);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_debug() {
        let info = ServerInfo::new("host", 22);
        assert!(format!("{:?}", info).contains("ServerInfo"));
    }
}
