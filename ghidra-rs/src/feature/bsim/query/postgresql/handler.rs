use std::io;

/// The custom URL scheme used by the BSim PostgreSQL backend.
pub const POSTGRESQL_SCHEME: &str = "postgresql";

/// Registers the `"postgresql"` URL scheme so that `postgresql://…` URLs can be constructed.
///
/// Mirrors `Handler.registerHandler()` from
/// `ghidra.features.bsim.query.postgresql.Handler`. In Java this manipulates the
/// `java.protocol.handler.pkgs` system property so the JVM can locate `Handler` as the
/// stream handler for the `postgresql://` scheme. Rust's `url` crate accepts arbitrary
/// schemes without prior registration, so this function is a no-op retained for API
/// parity.
pub fn register_handler() {}

/// Attempts to open a connection for the given postgresql URL — always fails.
///
/// Mirrors `Handler.openConnection(URL)`, which unconditionally throws `IOException`
/// because `Handler` is a dummy stream handler whose only purpose is to let Java
/// construct `URL` objects with the `postgresql` scheme; actual network I/O goes through
/// a different path.
pub fn open_connection(_url: &str) -> Result<(), io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Trying to open connection with dummy handler",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgresql_scheme_constant() {
        assert_eq!(POSTGRESQL_SCHEME, "postgresql");
    }

    #[test]
    fn register_handler_is_idempotent() {
        register_handler();
        register_handler();
    }

    #[test]
    fn open_connection_always_errors() {
        let err = open_connection("postgresql://localhost:5432").unwrap_err();
        assert_eq!(err.to_string(), "Trying to open connection with dummy handler");
    }

    #[test]
    fn open_connection_error_kind() {
        let err = open_connection("postgresql://host").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
