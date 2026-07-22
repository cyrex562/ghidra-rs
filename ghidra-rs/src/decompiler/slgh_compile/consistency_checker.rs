//! Models `ghidra.pcodeCPort.slgh_compile.ConsistencyChecker`.

/// Validates and optimizes the p-code templates produced while compiling a SLEIGH constructor's
/// semantic sections.
///
/// Mirrors the (package-private) concrete class `ghidra.pcodeCPort.slgh_compile.ConsistencyChecker`.
/// The Java class is constructed with a `SleighCompile` (used only to report errors/warnings and
/// query endianness), a root `SubtableSymbol` to walk, and three warning-toggle flags; those are
/// implementation details of a concrete implementor's constructor rather than part of this
/// trait's object-safe surface, so only the Java class's `public` methods are represented here.
/// The many `private` helper methods (`sizeRestriction`, `checkOpMisuse`, `checkSubtable`,
/// `optimize`, and friends) that do the actual per-`Constructor`/`OpTpl`/`VarnodeTpl` walking are
/// deliberately left out of the trait: they operate on
/// [`crate::decompiler::seam_stubs::Constructor`] and [`crate::decompiler::seam_stubs::SubtableSymbol`]
/// (themselves still placeholder seams) and are an implementation concern of whichever concrete
/// type backs this trait, not part of the public contract other code depends on. This trait was
/// selected as a cycle cut-point: code that needs "run the consistency checks and read back their
/// counters" can now depend on `dyn ConsistencyChecker` without pulling in `SleighCompile`,
/// `SubtableSymbol`, or `Constructor`.
pub trait ConsistencyChecker: Send + Sync {
    /// Main entry point for the size-consistency check: walks every subtable reachable from the
    /// root in post-order, verifying that each `Constructor`'s p-code operations respect
    /// per-opcode size restrictions (e.g. `INT_ADD`'s inputs and output must all agree in size)
    /// and recording each subtable's export size along the way. Returns `true` only if every
    /// subtable passed (Java's `testSizeRestrictions`).
    fn test_size_restrictions(&mut self) -> bool;

    /// Once size restrictions have been checked (and each subtable's export size recorded), walks
    /// every constructor's p-code sections again, adjusting and validating any `offset_plus`
    /// (truncation) varnode templates against the now-known sizes. Returns `true` only if every
    /// truncation was valid (Java's `testTruncations`).
    fn test_truncations(&mut self) -> bool;

    /// Walks every constructor's p-code sections, reporting an error for any that uses a
    /// temporary varnode in the unique space larger than
    /// [`crate::decompiler::sleigh_base::MAX_UNIQUE_SIZE`] bytes (Java's `testLargeTemporary`).
    fn test_large_temporary(&mut self);

    /// Walks every constructor, eliminating temporaries that are written exactly once and read
    /// exactly once with nothing in between that could interfere, and reporting on temporaries
    /// that are written but never read (or read but never written) (Java's `optimizeAll`).
    fn optimize_all(&mut self);

    /// The number of `ZEXT`/`SEXT`/`SUBPIECE` operations rewritten into a plain `COPY` because
    /// they turned out not to change size (Java's `getNumUnnecessaryPcode`).
    fn get_num_unnecessary_pcode(&self) -> i32;

    /// The number of temporaries found to be read but never written during
    /// [`ConsistencyChecker::optimize_all`] (Java's `getNumReadNoWrite`).
    fn get_num_read_no_write(&self) -> i32;

    /// The number of temporaries found to be written but never read during
    /// [`ConsistencyChecker::optimize_all`] (Java's `getNumWriteNoRead`).
    fn get_num_write_no_read(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but real implementor: a handful of fake "operations" each carrying an
    /// input/output size (mirroring the size-restriction check on e.g. `CPUI_COPY`) and a handful
    /// of fake temporaries each carrying read/write counts (mirroring the dead-temporary check in
    /// `optimizeAll`). This exercises the trait's actual contract rather than asserting on stub
    /// return values.
    struct MockConsistencyChecker {
        // (input size, output size); a mismatch (when neither is the wildcard 0) is a size error.
        ops: Vec<(i32, i32)>,
        // (writecount, readcount) per temporary.
        temps: Vec<(i32, i32)>,
        unnecessary_pcode: i32,
        readnowrite: i32,
        writenoread: i32,
        truncations_ok: bool,
    }

    impl MockConsistencyChecker {
        fn new(ops: Vec<(i32, i32)>, temps: Vec<(i32, i32)>, truncations_ok: bool) -> Self {
            Self {
                ops,
                temps,
                unnecessary_pcode: 0,
                readnowrite: 0,
                writenoread: 0,
                truncations_ok,
            }
        }
    }

    impl ConsistencyChecker for MockConsistencyChecker {
        fn test_size_restrictions(&mut self) -> bool {
            let mut ok = true;
            for &(vin, vout) in &self.ops {
                if vin != 0 && vout != 0 && vin != vout {
                    ok = false;
                } else if vin == vout {
                    // Same-size copy-like op: nothing to rewrite here, unlike a same-size
                    // ZEXT/SEXT (that case is exercised via optimize_all below).
                }
            }
            ok
        }

        fn test_truncations(&mut self) -> bool {
            self.truncations_ok
        }

        fn test_large_temporary(&mut self) {
            // No temporary in this mock is oversized; nothing to report.
        }

        fn optimize_all(&mut self) {
            for &(writecount, readcount) in &self.temps {
                if readcount == 0 && writecount > 0 {
                    self.writenoread += 1;
                } else if writecount == 0 && readcount > 0 {
                    self.readnowrite += 1;
                } else if writecount == 1 && readcount == 1 {
                    // Written once, read once: the classic case ConsistencyChecker.optimize()
                    // collapses into a direct copy, counted as unnecessary pcode.
                    self.unnecessary_pcode += 1;
                }
            }
        }

        fn get_num_unnecessary_pcode(&self) -> i32 {
            self.unnecessary_pcode
        }

        fn get_num_read_no_write(&self) -> i32 {
            self.readnowrite
        }

        fn get_num_write_no_read(&self) -> i32 {
            self.writenoread
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let mut checker = MockConsistencyChecker::new(vec![(4, 4)], vec![(1, 1)], true);
        let dyn_checker: &mut dyn ConsistencyChecker = &mut checker;
        assert!(dyn_checker.test_size_restrictions());
        assert!(dyn_checker.test_truncations());
        dyn_checker.test_large_temporary();
        dyn_checker.optimize_all();
        assert_eq!(dyn_checker.get_num_unnecessary_pcode(), 1);
        assert_eq!(dyn_checker.get_num_read_no_write(), 0);
        assert_eq!(dyn_checker.get_num_write_no_read(), 0);
    }

    #[test]
    fn test_size_restrictions_flags_mismatched_sizes() {
        // A 4-byte input feeding an 8-byte output (e.g. mismatched CPUI_COPY sizes) must fail.
        let mut checker = MockConsistencyChecker::new(vec![(4, 8)], Vec::new(), true);
        assert!(!checker.test_size_restrictions());
    }

    #[test]
    fn test_size_restrictions_allows_wildcard_size_zero() {
        // A size of 0 stands in for "unknown/subtable export", which is never a mismatch on its
        // own (mirrors the `(vnout == 0) || (vn0 == 0)` short-circuit in the Java original).
        let mut checker = MockConsistencyChecker::new(vec![(0, 8), (4, 0)], Vec::new(), true);
        assert!(checker.test_size_restrictions());
    }

    #[test]
    fn optimize_all_counts_read_without_write_and_write_without_read() {
        let mut checker =
            MockConsistencyChecker::new(Vec::new(), vec![(0, 1), (1, 0), (1, 1)], true);
        checker.optimize_all();
        assert_eq!(checker.get_num_read_no_write(), 1);
        assert_eq!(checker.get_num_write_no_read(), 1);
        assert_eq!(checker.get_num_unnecessary_pcode(), 1);
    }

    #[test]
    fn test_truncations_reflects_implementor_state() {
        let mut ok_checker = MockConsistencyChecker::new(Vec::new(), Vec::new(), true);
        assert!(ok_checker.test_truncations());

        let mut failing_checker = MockConsistencyChecker::new(Vec::new(), Vec::new(), false);
        assert!(!failing_checker.test_truncations());
    }
}
