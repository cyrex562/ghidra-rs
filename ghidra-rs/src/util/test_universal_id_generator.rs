//! Port of `ghidra.util.TestUniversalIdGenerator`.
//!
//! Despite the "Test" name, Java ships this class in `Generic`'s `src/main/java` (not
//! `src/test/java`) -- it is a deterministic test double for
//! [`crate::util::universal_id_generator`], used by other modules' test harnesses (e.g.
//! `RealProgramMTFModel` in `Ghidra/Features/Base/src/test/java/...`) that need reproducible
//! [`UniversalID`]s across test runs. This port keeps it unconditionally compiled to match that
//! placement, rather than gating it behind `#[cfg(test)]`.
//!
//! Java's constructor calls the package-private `installGenerator(this)`, which swaps the process
//! -wide static singleton in `UniversalIdGenerator` so that every subsequent call to
//! `UniversalIdGenerator.nextID()` anywhere in the process is redirected to this deterministic
//! instance instead. This crate's [`crate::util::universal_id_generator`] port is a plain
//! `OnceLock`-backed singleton of free functions with no such install/swap hook (see
//! `universal_id_generator.rs`), and adding one is out of scope for this port (it would require
//! editing that already-ported, out-of-batch module). `TestUniversalIdGenerator` here is
//! therefore a faithful, standalone port of the class's *own* logic
//! (`getNextID()`/`restore()`/`checkpoint()`, starting at ID 1000) for callers that construct and
//! use it directly; it does not redirect the crate-wide [`crate::util::universal_id_generator::next_id`]
//! singleton the way Java's version transparently does.

use crate::util::universal_id::UniversalID;

/// Matches Java's `private static final int START_ID = 1000`.
const START_ID: i64 = 1000;

/// A deterministic, sequential [`UniversalID`] generator for use by test harnesses.
///
/// Port of `ghidra.util.TestUniversalIdGenerator`. See the module docs for the one deliberate
/// deviation from Java (no crate-wide singleton redirection).
pub struct TestUniversalIdGenerator {
    id: i64,
    checkpoint: i64,
}

impl TestUniversalIdGenerator {
    /// Constructs a new generator starting at ID 1000.
    ///
    /// Java's constructor also calls `installGenerator(this)`; see the module docs for why that
    /// step has no counterpart here.
    pub fn new() -> Self {
        TestUniversalIdGenerator {
            id: START_ID,
            checkpoint: START_ID,
        }
    }

    /// Returns the next sequential [`UniversalID`], starting at 1000 and incrementing by one each
    /// call.
    ///
    /// Port of `TestUniversalIdGenerator.getNextID()`.
    pub fn get_next_id(&mut self) -> UniversalID {
        let id = self.id;
        self.id += 1;
        UniversalID::new(id)
    }

    /// Rewinds the ID counter back to the most recent [`Self::checkpoint`] (or 1000, if
    /// `checkpoint` was never called).
    ///
    /// Port of `TestUniversalIdGenerator.restore()`.
    pub fn restore(&mut self) {
        self.id = self.checkpoint;
    }

    /// Records the current ID counter position, so a later [`Self::restore`] rewinds back to it.
    ///
    /// Port of `TestUniversalIdGenerator.checkpoint()`.
    pub fn checkpoint(&mut self) {
        self.checkpoint = self.id;
    }
}

impl Default for TestUniversalIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_one_thousand_and_increments_sequentially() {
        let mut gen = TestUniversalIdGenerator::new();
        assert_eq!(gen.get_next_id().value(), 1000);
        assert_eq!(gen.get_next_id().value(), 1001);
        assert_eq!(gen.get_next_id().value(), 1002);
    }

    #[test]
    fn restore_without_checkpoint_rewinds_to_start_id() {
        let mut gen = TestUniversalIdGenerator::new();
        gen.get_next_id();
        gen.get_next_id();
        gen.restore();
        assert_eq!(gen.get_next_id().value(), 1000);
    }

    #[test]
    fn checkpoint_then_restore_rewinds_to_the_checkpointed_position() {
        let mut gen = TestUniversalIdGenerator::new();
        gen.get_next_id(); // 1000
        gen.get_next_id(); // 1001
        gen.checkpoint(); // checkpoint == 1002
        gen.get_next_id(); // 1002
        gen.get_next_id(); // 1003
        gen.restore();
        assert_eq!(gen.get_next_id().value(), 1002);
    }

    #[test]
    fn multiple_checkpoints_only_the_latest_one_matters() {
        let mut gen = TestUniversalIdGenerator::new();
        gen.checkpoint(); // 1000
        gen.get_next_id(); // 1000
        gen.checkpoint(); // 1001
        gen.get_next_id(); // 1001
        gen.get_next_id(); // 1002
        gen.restore();
        assert_eq!(gen.get_next_id().value(), 1001);
    }

    #[test]
    fn two_independent_generators_produce_identical_sequences() {
        // Matches the deterministic-for-tests intent: two separate instances, used
        // independently, produce the same reproducible sequence rather than globally unique IDs
        // (unlike the real crate::util::universal_id_generator singleton).
        let mut a = TestUniversalIdGenerator::new();
        let mut b = TestUniversalIdGenerator::new();
        assert_eq!(a.get_next_id().value(), b.get_next_id().value());
        assert_eq!(a.get_next_id().value(), b.get_next_id().value());
    }
}
