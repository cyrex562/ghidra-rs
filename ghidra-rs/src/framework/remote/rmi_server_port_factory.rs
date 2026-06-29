/// Computes the set of RMI-related ports derived from a single base port.
///
/// The three ports are laid out sequentially starting at `base_port`:
/// - `base_port + 0` — RMI Registry
/// - `base_port + 1` — RMI SSL
/// - `base_port + 2` — SSL Stream
pub struct RmiServerPortFactory {
    base_port: u16,
}

impl RmiServerPortFactory {
    /// Constructs a port factory using the specified `base_port`.
    pub fn new(base_port: u16) -> Self {
        Self { base_port }
    }

    /// Returns the RMI Registry port.
    pub fn rmi_registry_port(&self) -> u16 {
        self.base_port
    }

    /// Returns the SSL-protected RMI port.
    pub fn rmi_ssl_port(&self) -> u16 {
        self.base_port + 1
    }

    /// Returns the SSL Stream port.
    pub fn stream_port(&self) -> u16 {
        self.base_port + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_port_equals_base() {
        let f = RmiServerPortFactory::new(13100);
        assert_eq!(f.rmi_registry_port(), 13100);
    }

    #[test]
    fn ssl_port_is_base_plus_one() {
        let f = RmiServerPortFactory::new(13100);
        assert_eq!(f.rmi_ssl_port(), 13101);
    }

    #[test]
    fn stream_port_is_base_plus_two() {
        let f = RmiServerPortFactory::new(13100);
        assert_eq!(f.stream_port(), 13102);
    }

    #[test]
    fn ports_are_distinct() {
        let f = RmiServerPortFactory::new(9000);
        let ports = [f.rmi_registry_port(), f.rmi_ssl_port(), f.stream_port()];
        let unique: std::collections::HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn zero_base_port() {
        let f = RmiServerPortFactory::new(0);
        assert_eq!(f.rmi_registry_port(), 0);
        assert_eq!(f.rmi_ssl_port(), 1);
        assert_eq!(f.stream_port(), 2);
    }
}
