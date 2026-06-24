use super::SqlStringTableError;

/// Provides a callback function to produce a statement of type `S`.
///
/// Rust equivalent of Java's `StatementSupplier<S extends Statement>` — a
/// functional interface used to generate a SQL statement for the current thread.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.StatementSupplier`.
pub trait StatementSupplier<S> {
    /// Return a statement for use within the current thread.
    ///
    /// # Errors
    /// Returns [`SqlStringTableError`] if the callback fails to produce the statement.
    fn get(&self) -> Result<S, SqlStringTableError>;
}

/// Blanket implementation for closures, mirroring Java's use of lambdas for functional interfaces.
impl<S, F: Fn() -> Result<S, SqlStringTableError>> StatementSupplier<S> for F {
    fn get(&self) -> Result<S, SqlStringTableError> {
        self()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_ok_returns_value() {
        let supplier = || -> Result<i32, SqlStringTableError> { Ok(42) };
        assert_eq!(supplier.get().unwrap(), 42);
    }

    #[test]
    fn closure_err_propagates() {
        let supplier =
            || -> Result<i32, SqlStringTableError> { Err(SqlStringTableError::Sql("db down".into())) };
        assert!(matches!(supplier.get(), Err(SqlStringTableError::Sql(_))));
    }

    #[test]
    fn struct_impl_ok() {
        struct FixedSupplier(u32);
        impl StatementSupplier<u32> for FixedSupplier {
            fn get(&self) -> Result<u32, SqlStringTableError> {
                Ok(self.0)
            }
        }
        assert_eq!(FixedSupplier(7).get().unwrap(), 7);
    }

    #[test]
    fn struct_impl_err() {
        struct FailingSupplier;
        impl StatementSupplier<u32> for FailingSupplier {
            fn get(&self) -> Result<u32, SqlStringTableError> {
                Err(SqlStringTableError::NoConnection)
            }
        }
        assert!(matches!(FailingSupplier.get(), Err(SqlStringTableError::NoConnection)));
    }
}
