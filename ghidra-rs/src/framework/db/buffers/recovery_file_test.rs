use std::io;

/// Recovery test harness for the buffer-file recovery mechanism, mirroring the public API of
/// Java's `db.buffers.RecoveryFileTest`: a `setUp`/`tearDown` pair around a fresh test directory,
/// plus test methods that exercise `BufferMgr`/`RecoveryMgr` snapshot-and-recover behavior against
/// a `PrivateDatabase`-backed buffer file, with and without an intervening save or undo.
///
/// Each Java `@Test` method took no arguments and declared `throws Exception`; that maps directly
/// to a parameterless `&mut self` method returning `io::Result<()>`, keeping the trait
/// object-safe. The original also relied on JUnit's `assert*` calls aborting the test on failure;
/// implementations here should return `Err` in the equivalent situations instead of panicking, so
/// that a caller driving the suite through `&mut dyn RecoveryFileTest` can observe failures.
///
/// The Java `init(bufferCnt, growCnt)` helper (which builds up the buffer/recovery-snapshot
/// history shared by every test method) is not exposed as a trait method: like
/// [`RecoveryDbTest`](crate::framework::db::RecoveryDbTest), it is private test-fixture plumbing,
/// not part of the class's externally observable API.
pub trait RecoveryFileTest {
    /// Create a fresh, empty test directory. Mirrors the JUnit `@Before` method.
    fn set_up(&mut self) -> io::Result<()>;

    /// Remove the test directory. Mirrors the JUnit `@After` method.
    fn tear_down(&mut self) -> io::Result<()>;

    /// Verify that, after filling and growing a buffer file, freeing every other buffer, and
    /// modifying a subset of the survivors across several checkpoints (with a recovery snapshot
    /// taken after each), opening a second handle on the file recovers the exact same buffer
    /// contents without any explicit save.
    fn test_recovery(&mut self) -> io::Result<()>;

    /// As [`test_recovery`](Self::test_recovery), but after recovering into the second handle, an
    /// explicit save is performed and a *third* handle is opened on the saved file, which must
    /// also reflect the recovered content.
    fn test_recovery_with_save(&mut self) -> io::Result<()>;

    /// Verify that undoing the most recent checkpoint and taking a fresh recovery snapshot causes
    /// a re-opened handle to reflect the prior (pre-undo) checkpoint's state instead.
    fn test_recovery_after_undo(&mut self) -> io::Result<()>;

    /// Verify that undoing every checkpoint taken during setup (walking all the way back to the
    /// state immediately after the original buffers were created, before the file was grown or
    /// modified) and taking a fresh recovery snapshot causes a re-opened handle to reflect that
    /// original, pre-growth state.
    fn test_recovery_after_multi_undo(&mut self) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-memory model of the recovery scenario `RecoveryFileTest` exercises: a linear
    /// history of checkpoint states (each a fixed-size vector of buffer slots, `None` meaning
    /// freed and `Some(v)` meaning allocated holding `v`), plus a separate "last recovery
    /// snapshot" pointer, closely enough matching `BufferMgr`'s checkpoint/undo/recovery-snapshot
    /// semantics to prove out the trait's shape.
    struct MockRecoveryFileTest {
        /// Checkpoint history: `history[0]` is the state right after the original buffers are
        /// created (before growth); `history[1..]` are the states after each subsequent
        /// checkpoint (growth, then three rounds of delete/modify).
        history: Vec<Vec<Option<i32>>>,
        /// Index into `history` for the current (possibly undone) state.
        current: usize,
        /// Index into `history` captured by the last `takeRecoverySnapshot`.
        recovery_point: Option<usize>,
        /// What a re-opened handle would see: `None` until a `reopen`, then the state as of the
        /// last recovery snapshot (or the saved state, once `save` is simulated).
        reopened: Option<Vec<Option<i32>>>,
    }

    /// Buffers created before growth (mirrors the Java test's `bufferCnt` parameter to `init`).
    const ORIG_CNT: usize = 40;
    /// Buffers added during growth (mirrors `init`'s `growCnt` parameter).
    const GROW_CNT: usize = 20;
    /// Total buffer count once growth has been applied.
    const TOTAL_CNT: usize = ORIG_CNT + GROW_CNT;

    impl MockRecoveryFileTest {
        fn new() -> Self {
            Self { history: Vec::new(), current: 0, recovery_point: None, reopened: None }
        }

        /// Mirrors `RecoveryFileTest.init(ORIG_CNT, GROW_CNT)`: build up the checkpoint history
        /// used by every `@Test` method.
        fn init(&mut self) {
            // Original fill: bufferCnt buffers, -i stored at each.
            let mut state: Vec<Option<i32>> = (0..ORIG_CNT).map(|i| Some(-(i as i32))).collect();
            self.history = vec![state.clone()];
            self.current = 0;

            // Growth: growCnt more buffers, -i stored at each. Checkpoint + snapshot.
            state.extend((ORIG_CNT..TOTAL_CNT).map(|i| Some(-(i as i32))));
            self.push(state.clone());
            self.recovery_point = Some(self.current);

            // Delete every odd buffer; store +i at every buffer index divisible by 40.
            for (i, slot) in state.iter_mut().enumerate() {
                if i % 2 == 1 {
                    *slot = None;
                }
            }
            for i in (0..TOTAL_CNT).step_by(40) {
                state[i] = Some(i as i32);
            }
            self.push(state.clone());
            self.recovery_point = Some(self.current);

            // Store +i at every buffer index congruent to 20 mod 40.
            let mut i = 20;
            while i < TOTAL_CNT {
                state[i] = Some(i as i32);
                i += 40;
            }
            self.push(state.clone());
            self.recovery_point = Some(self.current);

            // Store +i at every buffer index congruent to 10 mod 20.
            let mut i = 10;
            while i < TOTAL_CNT {
                state[i] = Some(i as i32);
                i += 20;
            }
            self.push(state.clone());
            self.recovery_point = Some(self.current);
        }

        fn push(&mut self, state: Vec<Option<i32>>) {
            self.history.truncate(self.current + 1);
            self.history.push(state);
            self.current = self.history.len() - 1;
        }

        fn current_state(&self) -> &Vec<Option<i32>> {
            &self.history[self.current]
        }

        fn undo(&mut self) -> bool {
            if self.current == 0 {
                return false;
            }
            self.current -= 1;
            true
        }

        fn take_recovery_snapshot(&mut self) {
            self.recovery_point = Some(self.current);
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

    fn require(cond: bool, msg: &str) -> io::Result<()> {
        if cond {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, msg.to_string()))
        }
    }

    fn check_grown_recovered_state(state: &[Option<i32>]) -> io::Result<()> {
        require(state.len() == TOTAL_CNT, "expected recovered buffer count to match growth total")?;
        for i in (1..TOTAL_CNT).step_by(2) {
            require(state[i].is_none(), "expected odd-numbered buffer to be deleted")?;
        }
        for i in (0..TOTAL_CNT).step_by(10) {
            require(state[i] == Some(i as i32), "expected buffer to hold its positive index value")?;
        }
        Ok(())
    }

    impl RecoveryFileTest for MockRecoveryFileTest {
        fn set_up(&mut self) -> io::Result<()> {
            self.history.clear();
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
            require(self.recovery_point.is_some(), "expected a recovery snapshot to exist")?;
            self.reopen();
            let state = self.reopened.take().unwrap();
            check_grown_recovered_state(&state)
        }

        fn test_recovery_with_save(&mut self) -> io::Result<()> {
            self.init();
            self.reopen();
            let recovered = self.reopened.take().unwrap();
            check_grown_recovered_state(&recovered)?;

            // Simulate: recovered handle is saved, then a third handle opens the saved file.
            self.save();
            let saved = self.reopened.take().unwrap();
            check_grown_recovered_state(&saved)
        }

        fn test_recovery_after_undo(&mut self) -> io::Result<()> {
            self.init();
            require(self.undo(), "expected one checkpoint to be available to undo")?;
            self.take_recovery_snapshot();

            self.reopen();
            let state = self.reopened.take().unwrap();
            require(state.len() == TOTAL_CNT, "expected buffer count to still reflect growth")?;
            for i in (1..TOTAL_CNT).step_by(2) {
                require(state[i].is_none(), "expected odd-numbered buffer to be deleted")?;
            }
            for i in (0..TOTAL_CNT).step_by(20) {
                require(
                    state[i] == Some(i as i32),
                    "expected buffer to hold its positive index value after undo",
                )?;
            }
            for i in (10..TOTAL_CNT).step_by(20) {
                require(
                    state[i] == Some(-(i as i32)),
                    "expected buffer modified only by the undone checkpoint to revert",
                )?;
            }
            Ok(())
        }

        fn test_recovery_after_multi_undo(&mut self) -> io::Result<()> {
            self.init();
            for _ in 0..4 {
                require(self.undo(), "expected a checkpoint to be available to undo")?;
            }
            self.take_recovery_snapshot();

            self.reopen();
            let state = self.reopened.take().unwrap();
            require(state.len() == ORIG_CNT, "expected buffer count to reflect pre-growth state")?;
            for i in 0..ORIG_CNT {
                require(
                    state[i] == Some(-(i as i32)),
                    "expected every buffer to hold its original negative index value",
                )?;
            }
            Ok(())
        }
    }

    #[test]
    fn recovery_scenarios_pass_through_trait_object() {
        // Proves `RecoveryFileTest` is object-safe and drives the mock through the full JUnit
        // lifecycle (setUp -> test -> tearDown) for each of the four original test methods.
        let mut harness: Box<dyn RecoveryFileTest> = Box::new(MockRecoveryFileTest::new());

        harness.set_up().unwrap();
        harness.test_recovery().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_with_save().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_after_undo().unwrap();
        harness.tear_down().unwrap();

        harness.set_up().unwrap();
        harness.test_recovery_after_multi_undo().unwrap();
        harness.tear_down().unwrap();
    }

    #[test]
    fn undo_past_start_of_history_fails() {
        let mut mock = MockRecoveryFileTest::new();
        mock.set_up().unwrap();
        mock.init();
        while mock.undo() {}
        assert!(!mock.undo());
        assert_eq!(mock.current, 0);
    }

    #[test]
    fn multi_undo_loses_growth_and_modifications() {
        let mut mock = MockRecoveryFileTest::new();
        mock.set_up().unwrap();
        mock.test_recovery_after_multi_undo().unwrap();
        let state = mock.reopened.as_ref().unwrap();
        assert_eq!(state.len(), ORIG_CNT);
        assert!(state.iter().all(Option::is_some));
    }
}
