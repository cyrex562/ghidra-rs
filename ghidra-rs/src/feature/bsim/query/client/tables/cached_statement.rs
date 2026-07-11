use std::thread::{self, ThreadId};

use crate::util::msg::Msg;

use super::{SqlStringTableError, StatementSupplier};

/// Minimal Rust equivalent of the `java.sql.Statement` surface that
/// [`CachedStatement`] depends on: the ability to be closed.
///
/// Concrete statement/prepared-statement types plug in by implementing this trait.
pub trait SqlStatement {
    /// Close the statement, releasing any associated resources.
    fn close(&mut self) -> Result<(), SqlStringTableError>;
}

/// [`CachedStatement`] provides a cached statement container which is intended to
/// supply a reusable instance for use within a single thread.  Attempts to use the
/// statement in multiple threads is considered unsafe.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.CachedStatement`.
pub struct CachedStatement<S: SqlStatement> {
    statement: Option<S>,
    owner_thread_id: Option<ThreadId>,
    owner_thread_name: String,
}

impl<S: SqlStatement> Default for CachedStatement<S> {
    fn default() -> Self {
        Self { statement: None, owner_thread_id: None, owner_thread_name: String::new() }
    }
}

impl<S: SqlStatement> CachedStatement<S> {
    /// Create an empty cached statement container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the associated cached statement or prepare one via the specified
    /// `statement_supplier` if not yet established.  If the supplier is used the
    /// owner thread for the statement is established based on the current thread.
    ///
    /// # Errors
    /// Returns [`SqlStringTableError`] if the supplier fails to produce a statement.
    ///
    /// # Panics
    /// Panics if the current thread does not correspond to the owner thread of a
    /// previously established statement.  This is considered a programming error.
    pub fn prepare_if_needed(
        &mut self,
        statement_supplier: &impl StatementSupplier<S>,
    ) -> Result<&mut S, SqlStringTableError> {
        if self.get_statement().is_none() {
            let s = statement_supplier.get()?;
            self.set_statement(s);
        }
        Ok(self.get_statement().expect("statement was just established"))
    }

    /// Set the associated statement instance.  This method may be used in place of
    /// [`Self::prepare_if_needed`] although it is not preferred since it can result
    /// in replacement of one previously established.  [`Self::get_statement`] should
    /// be used first to ensure one was not previously set.  An error is logged if the
    /// invocation replaces an existing statement, which is forced closed.
    ///
    /// The owner thread for the statement is established based on the current thread.
    pub fn set_statement(&mut self, s: S) {
        let old_statement = self.statement.take();
        self.statement = Some(s);
        self.owner_thread_id = Some(thread::current().id());
        self.owner_thread_name = current_thread_name();
        if let Some(mut old) = old_statement {
            Msg::error("CachedStatement", &"Statement cached more than once - closing old statement");
            let _ = old.close();
        }
    }

    /// Get the current cached statement, or `None` if not yet established.
    ///
    /// # Panics
    /// Panics if the current thread does not correspond to the owner thread of a
    /// previously established statement.  This is considered a programming error.
    pub fn get_statement(&mut self) -> Option<&mut S> {
        if self.statement.is_some() {
            let t = thread::current().id();
            let owner = self.owner_thread_id.expect("owner thread is set alongside the statement");
            if owner != t {
                Msg::error(
                    "CachedStatement",
                    &format!(
                        "BSim cached statement used in unsafe-thread manner:\n   Created in: {}\n   Used in: {}",
                        self.owner_thread_name,
                        current_thread_name()
                    ),
                );
                panic!("BSim cached statement used in unsafe-thread manner");
            }
        }
        self.statement.as_mut()
    }

    /// Close the currently cached statement.  This method may be invoked from any
    /// thread but should be properly coordinated with its use in the statement owner
    /// thread.
    pub fn close(&mut self) {
        if let Some(mut s) = self.statement.take() {
            let _ = s.close();
        }
    }
}

fn current_thread_name() -> String {
    thread::current().name().unwrap_or("<unnamed>").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Default)]
    struct TestStatement {
        closed: Rc<Cell<bool>>,
    }

    impl TestStatement {
        fn tracked() -> (Self, Rc<Cell<bool>>) {
            let closed = Rc::new(Cell::new(false));
            (Self { closed: closed.clone() }, closed)
        }
    }

    impl SqlStatement for TestStatement {
        fn close(&mut self) -> Result<(), SqlStringTableError> {
            self.closed.set(true);
            Ok(())
        }
    }

    struct FailingCloseStatement;

    impl SqlStatement for FailingCloseStatement {
        fn close(&mut self) -> Result<(), SqlStringTableError> {
            Err(SqlStringTableError::Sql("close failed".into()))
        }
    }

    #[test]
    fn get_statement_initially_none() {
        let mut cached = CachedStatement::<TestStatement>::new();
        assert!(cached.get_statement().is_none());
    }

    #[test]
    fn prepare_if_needed_invokes_supplier_only_once() {
        let mut cached = CachedStatement::<TestStatement>::new();
        let calls = Cell::new(0);
        let supplier = || -> Result<TestStatement, SqlStringTableError> {
            calls.set(calls.get() + 1);
            Ok(TestStatement::tracked().0)
        };

        cached.prepare_if_needed(&supplier).unwrap();
        cached.prepare_if_needed(&supplier).unwrap();

        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn prepare_if_needed_propagates_supplier_error() {
        let mut cached = CachedStatement::<TestStatement>::new();
        let supplier = || -> Result<TestStatement, SqlStringTableError> {
            Err(SqlStringTableError::NoConnection)
        };

        let result = cached.prepare_if_needed(&supplier);
        assert!(matches!(result, Err(SqlStringTableError::NoConnection)));
        assert!(cached.get_statement().is_none());
    }

    #[test]
    fn set_statement_closes_previous_statement() {
        let mut cached = CachedStatement::<TestStatement>::new();
        let (first, first_closed) = TestStatement::tracked();
        cached.set_statement(first);
        assert!(!first_closed.get());

        cached.set_statement(TestStatement::tracked().0);
        assert!(first_closed.get());
    }

    #[test]
    fn set_statement_swallows_close_error_on_replace() {
        let mut cached = CachedStatement::<FailingCloseStatement>::new();
        cached.set_statement(FailingCloseStatement);
        // Replacing must not panic even though the old statement fails to close.
        cached.set_statement(FailingCloseStatement);
        assert!(cached.get_statement().is_some());
    }

    #[test]
    fn close_clears_and_closes_statement() {
        let mut cached = CachedStatement::<TestStatement>::new();
        cached.set_statement(TestStatement::default());
        cached.close();
        assert!(cached.get_statement().is_none());
    }

    #[test]
    fn close_swallows_error() {
        let mut cached = CachedStatement::<FailingCloseStatement>::new();
        cached.set_statement(FailingCloseStatement);
        cached.close();
        assert!(cached.get_statement().is_none());
    }

    #[test]
    fn get_statement_panics_when_used_from_wrong_thread() {
        let mut cached = CachedStatement::<TestStatement>::new();
        cached.set_statement(TestStatement::default());

        let other_thread_id = thread::spawn(|| thread::current().id()).join().unwrap();
        cached.owner_thread_id = Some(other_thread_id);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cached.get_statement();
        }));
        assert!(result.is_err());
    }
}
