use std::io;

/// Recovery test harness for a database file-system, mirroring the public API of Java's
/// `db.RecoveryDBTest`: a `setUp`/`tearDown` pair around a fresh file-system, plus test methods
/// that exercise `DBHandle` recovery snapshots, undo, redo, and save against a `LocalFileSystem`.
///
/// Each Java `@Test` method took no arguments and declared `throws Exception`; that maps directly
/// to a parameterless `&mut self` method returning `io::Result<()>`, keeping the trait
/// object-safe. The original also relied on JUnit's `assert*` calls aborting the test on failure;
/// implementations here should return `Err` in the equivalent situations instead of panicking, so
/// that a caller driving the suite through `&mut dyn RecoveryDbTest` can observe failures.
pub trait RecoveryDbTest {
    /// Create a fresh, empty test directory and open a `LocalFileSystem` on it. Mirrors the
    /// JUnit `@Before` method.
    fn set_up(&mut self) -> io::Result<()>;

    /// Dispose of the file-system and remove the test directory. Mirrors the JUnit `@After`
    /// method.
    fn tear_down(&mut self) -> io::Result<()>;

    /// Verify that re-opening a database recovers the state left by the last recovery snapshot,
    /// without any undo/redo or explicit save in between.
    fn test_recovery(&mut self) -> io::Result<()>;

    /// Verify that undoing transactions and taking a new recovery snapshot causes a re-opened
    /// database to reflect the undone (earlier) state.
    fn test_recovery_with_undo(&mut self) -> io::Result<()>;

    /// Verify that undoing and then redoing transactions, with a recovery snapshot after each,
    /// causes a re-opened database to reflect the redone (later) state.
    fn test_recovery_with_undo_redo(&mut self) -> io::Result<()>;

    /// Verify that an explicit save discards the need for recovery, and that a subsequent
    /// re-open reflects the saved state.
    fn test_recovery_with_save(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-memory model of the recovery scenario `RecoveryDBTest` exercises: a linear
    /// history of committed transaction states plus a separate "last recovery snapshot" pointer,
    /// and undo/redo that walk the history without discarding it (matching `DBHandle`'s
    /// transaction/undo semantics closely enough to prove out the trait's shape).
    struct MockRecoveryDbTest {
        /// Transaction history; each entry is `(table1_present, table2_present)` where the bool
        /// vectors record which of `RECORD_COUNT` keys are present after that transaction.
        history: Vec<(Vec<bool>, Vec<bool>)>,
        /// Index into `history` for the current (possibly undone/redone) state.
        current: usize,
        /// Index into `history` captured by the last `takeRecoverySnapshot`.
        recovery_point: Option<usize>,
        /// What a re-opened handle would see: `None` until `set_up`, then the state as of the
        /// last recovery snapshot (or the saved state, once `save` is simulated).
        reopened: Option<(Vec<bool>, Vec<bool>)>,
    }

    const RECORD_COUNT: usize = 10;

    impl MockRecoveryDbTest {
        fn new() -> Self {
            Self { history: Vec::new(), current: 0, recovery_point: None, reopened: None }
        }

        fn current_state(&self) -> &(Vec<bool>, Vec<bool>) {
            &self.history[self.current]
        }

        fn push(&mut self, state: (Vec<bool>, Vec<bool>)) {
            self.history.truncate(self.current + 1);
            self.history.push(state);
            self.current = self.history.len() - 1;
        }

        fn init(&mut self) {
            let empty = vec![false; RECORD_COUNT];
            self.history = vec![(empty.clone(), empty.clone())];
            self.current = 0;

            // Transaction: create table1, fill.
            let mut t1 = vec![true; RECORD_COUNT];
            let t2 = empty.clone();
            self.push((t1.clone(), t2.clone()));

            // Transaction: delete evens from table1.
            for (i, present) in t1.iter_mut().enumerate() {
                if i % 2 == 0 {
                    *present = false;
                }
            }
            self.push((t1.clone(), t2.clone()));

            // Recovery snapshot.
            self.recovery_point = Some(self.current);

            // Transaction: create table2, fill.
            let mut t2 = vec![true; RECORD_COUNT];
            self.push((t1.clone(), t2.clone()));

            // Transaction: delete evens from table2.
            for (i, present) in t2.iter_mut().enumerate() {
                if i % 2 == 0 {
                    *present = false;
                }
            }
            self.push((t1, t2));

            // Recovery snapshot.
            self.recovery_point = Some(self.current);
        }

        fn undo(&mut self) -> bool {
            if self.current == 0 {
                return false;
            }
            self.current -= 1;
            true
        }

        fn redo(&mut self) -> bool {
            if self.current + 1 >= self.history.len() {
                return false;
            }
            self.current += 1;
            true
        }

        fn take_recovery_snapshot(&mut self) {
            self.recovery_point = Some(self.current);
        }

        fn can_recover(&self) -> bool {
            self.recovery_point.map(|p| p != self.current).unwrap_or(false)
        }

        /// Simulate closing the handle and re-opening it: a real re-open recovers up through the
        /// last recovery snapshot, not necessarily the very latest (unsaved) transaction.
        fn reopen(&mut self) {
            let point = self.recovery_point.unwrap_or(self.current);
            self.reopened = Some(self.history[point].clone());
        }

        fn save(&mut self) {
            self.reopened = Some(self.current_state().clone());
            self.recovery_point = Some(self.current);
        }
    }

    fn odds_only(present: &[bool]) -> bool {
        present.iter().enumerate().all(|(i, &p)| p == (i % 2 == 1))
    }

    fn all_absent(present: &[bool]) -> bool {
        present.iter().all(|&p| !p)
    }

    fn require(cond: bool, msg: &str) -> io::Result<()> {
        if cond {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, msg))
        }
    }

    impl RecoveryDbTest for MockRecoveryDbTest {
        fn set_up(&mut self) -> io::Result<()> {
            self.history = vec![(vec![false; RECORD_COUNT], vec![false; RECORD_COUNT])];
            self.current = 0;
            self.recovery_point = None;
            self.reopened = None;
            Ok(())
        }

        fn tear_down(&mut self) -> io::Result<()> {
            self.history.clear();
            self.reopened = None;
            Ok(())
        }

        fn test_recovery(&mut self) -> io::Result<()> {
            self.init();
            require(self.can_recover(), "expected recovery to be needed before reopen")?;
            self.reopen();
            let (t1, t2) = self.reopened.as_ref().unwrap();
            require(odds_only(t1), "table1 should retain only odd keys")?;
            require(odds_only(t2), "table2 should retain only odd keys")?;
            Ok(())
        }

        fn test_recovery_with_undo(&mut self) -> io::Result<()> {
            self.init();
            require(self.undo(), "first undo should succeed")?;
            require(self.undo(), "second undo should succeed")?;
            self.take_recovery_snapshot();

            require(self.can_recover(), "expected recovery to be needed before reopen")?;
            self.reopen();
            let (t1, t2) = self.reopened.as_ref().unwrap();
            require(odds_only(t1), "table1 should retain only odd keys after undo")?;
            require(all_absent(t2), "table2 should not exist after undoing its creation")?;
            require(all_absent(&self.current_state().1), "live table2 should be gone too")?;
            Ok(())
        }

        fn test_recovery_with_undo_redo(&mut self) -> io::Result<()> {
            self.init();
            require(self.undo(), "first undo should succeed")?;
            require(self.undo(), "second undo should succeed")?;
            self.take_recovery_snapshot();

            require(self.redo(), "first redo should succeed")?;
            require(self.redo(), "second redo should succeed")?;
            self.take_recovery_snapshot();

            require(!all_absent(&self.current_state().1), "table2 should be back after redo")?;

            self.reopen();
            let (t1, t2) = self.reopened.as_ref().unwrap();
            require(odds_only(t1), "table1 should retain only odd keys")?;
            require(odds_only(t2), "table2 should retain only odd keys after redo")?;
            Ok(())
        }

        fn test_recovery_with_save(&mut self) -> io::Result<()> {
            self.init();
            self.save();
            require(!self.can_recover(), "no recovery should be needed right after save")?;

            self.reopen();
            let (t1, t2) = self.reopened.as_ref().unwrap();
            require(odds_only(t1), "table1 should retain only odd keys after save+reopen")?;
            require(odds_only(t2), "table2 should retain only odd keys after save+reopen")?;
            Ok(())
        }
    }

    #[test]
    fn recovery_scenarios_pass_through_trait_object() {
        // Proves `RecoveryDbTest` is object-safe and drives the mock through the full JUnit
        // lifecycle (setUp -> test -> tearDown) for each of the four original test methods.
        let mut harness: Box<dyn RecoveryDbTest> = Box::new(MockRecoveryDbTest::new());

        harness.set_up().unwrap();
        harness.test_recovery().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_with_undo().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_with_undo_redo().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_with_save().unwrap();
        harness.tear_down().unwrap();
    }

    #[test]
    fn undo_past_start_of_history_fails() {
        let mut mock = MockRecoveryDbTest::new();
        mock.set_up().unwrap();
        mock.init();
        while mock.undo() {}
        assert!(!mock.undo());
        assert_eq!(mock.current, 0);
    }
}
