//! Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns`.

use std::collections::HashMap;
use std::sync::Arc;

use super::{AssemblyResolution, AssemblyResolvedBackfill};
use crate::app::plugin::assembler::sleigh::expr::RecursiveDescentSolver;
use crate::app::seam_stubs::{AssemblyConstructorSemantic, AssemblyPatternBlock, Constructor, MaskedLong};
use crate::program::model::lang::sleigh::constructor::ContextOp;
use crate::program::model::lang::sleigh::walker::ConstructState;

/// A resolved instruction/context encoding, possibly still carrying pending backfills or
/// forbidden patterns.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns`, promoted here from
/// the minimal placeholder trait of the same name that used to live in
/// [`crate::app::seam_stubs`] (see `STUBS.tsv` for its provenance) now that this cut-point is
/// being ported in full. Every importer that referenced the placeholder now references this trait
/// instead; the placeholder's three methods
/// ([`get_instruction_length`](Self::get_instruction_length), [`get_instruction`](Self::get_instruction),
/// [`get_context`](Self::get_context)) are kept as a subset of this trait's fuller surface, so
/// every existing implementor/caller still compiles unchanged.
///
/// Java's interface declares every method abstract (no default bodies), so every method below is
/// likewise a required trait method -- there is no default-method logic to port.
///
/// A handful of methods are renamed from their Java counterparts to avoid colliding with a
/// same-named [`AssemblyResolution`] supertrait method of a different return type, since Rust
/// trait objects cannot resolve an ambiguous same-named call across two traits in scope:
/// [`shift_patterns`](Self::shift_patterns) (Java's covariant `shift(int)` override),
/// [`parent_patterns`](Self::parent_patterns) (Java's covariant `parent(String, int)` override),
/// and [`with_right_patterns`](Self::with_right_patterns) (Java's `withRight(AssemblyResolution)`,
/// which would otherwise collide with [`AbstractAssemblyResolution::with_right`](
/// super::AbstractAssemblyResolution::with_right) on a type implementing both traits, mirroring
/// the same precedent already set by
/// [`AssemblyResolvedBackfill::shift_backfill`]/[`DefaultAssemblyResolvedBackfill::with_right_backfill`](
/// super::DefaultAssemblyResolvedBackfill::with_right_backfill)). Java's two overloaded `combine`
/// methods (one taking `AssemblyResolvedPatterns`, one taking `AssemblyResolvedBackfill`) are
/// similarly split into [`combine`](Self::combine) and [`combine_backfill`](Self::combine_backfill),
/// since Rust has no method overloading.
///
/// `ContextOp` and `ConstructState` are both already-ported, concrete types --
/// [`crate::program::model::lang::sleigh::constructor::ContextOp`] and
/// [`crate::program::model::lang::sleigh::walker::ConstructState`] respectively -- so they're
/// referenced directly rather than through a seam-stub placeholder.
/// [`AssemblyPatternBlock`](crate::app::seam_stubs::AssemblyPatternBlock),
/// [`Constructor`](crate::app::seam_stubs::Constructor), and
/// [`AssemblyConstructorSemantic`](crate::app::seam_stubs::AssemblyConstructorSemantic) are not
/// yet ported, so they continue to be referenced through their existing minimal placeholder
/// traits in [`crate::app::seam_stubs`].
///
/// Java's `Iterable<byte[]>` return of `possibleInsVals` becomes an owned `Vec<Vec<u8>>`: Java's
/// own doc comment already warns that its iterator reuses a single backing array per iterate (so
/// callers must copy anyway), and this crate has no lazy byte-array generator to mirror that
/// reuse, so returning fully-materialized copies is the simplest faithful equivalent. Likewise,
/// Java's `Collection<AssemblyResolvedBackfill>`/`Collection<AssemblyResolvedPatterns>` returns of
/// `getBackfills`/`getForbids`, and the `Set<AssemblyResolvedPatterns>` parameter of `withForbids`,
/// become plain `Vec`s, matching this crate's existing collection conventions (e.g.
/// [`AssemblyResolutionResults::iter_all`](crate::app::seam_stubs::AssemblyResolutionResults::iter_all)).
pub trait AssemblyResolvedPatterns: AssemblyResolution {
    /// Get the instruction block.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getInstruction()`.
    fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock>;

    /// Get the context block.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getContext()`.
    fn get_context(&self) -> Box<dyn AssemblyPatternBlock>;

    /// Create a copy of this resolution with a new context.
    ///
    /// Mirrors `AssemblyResolvedPatterns.withContext(AssemblyPatternBlock)`.
    fn with_context(&self, ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns>;

    /// Get the length of the instruction encoding.
    ///
    /// This is used to ensure each operand is encoded at the correct offset.
    ///
    /// **NOTE:** this DOES include the offset. **NOTE:** this DOES include pending backfills.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getInstructionLength()`.
    fn get_instruction_length(&self) -> i32;

    /// Get the length of the instruction encoding, excluding trailing undefined bytes.
    ///
    /// **NOTE:** this DOES include the offset. **NOTE:** this DOES NOT include pending backfills.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getDefinedInstructionLength()`.
    fn get_defined_instruction_length(&self) -> i32;

    /// Get the backfill records for this resolution, if any.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getBackfills()`.
    fn get_backfills(&self) -> Vec<Box<dyn AssemblyResolvedBackfill>>;

    /// Check if this resolution has pending backfills to apply.
    ///
    /// Mirrors `AssemblyResolvedPatterns.hasBackfills()`.
    fn has_backfills(&self) -> bool;

    /// Get the forbidden patterns for this resolution.
    ///
    /// These represent patterns included in the current resolution that would actually get
    /// matched by a more specific constructor somewhere in the resolved tree, and thus are
    /// subtracted.
    ///
    /// Mirrors `AssemblyResolvedPatterns.getForbids()`.
    fn get_forbids(&self) -> Vec<Box<dyn AssemblyResolvedPatterns>>;

    /// Decode a portion of the instruction block.
    ///
    /// `byte_start` is the first byte to decode, `size` the number of bytes to decode.
    ///
    /// Mirrors `AssemblyResolvedPatterns.readInstruction(int, int)`.
    fn read_instruction(&self, byte_start: i32, size: i32) -> MaskedLong;

    /// Decode a portion of the context block.
    ///
    /// `start` is the first byte to decode, `len` the number of bytes to decode.
    ///
    /// Mirrors `AssemblyResolvedPatterns.readContext(int, int)`.
    fn read_context(&self, start: i32, len: i32) -> MaskedLong;

    /// Decode the value from the context located where the given context operation would write.
    ///
    /// This is used to read the value from the left-hand-side "variable" of a context operation.
    /// It seems backward, because it is. When assembling, the right-hand-side expression of a
    /// context operation must be solved. This means the "variable" is known from the context(s)
    /// of the resolved children constructors. The value read is then used as the goal in solving
    /// the expression.
    ///
    /// `cop` is the context operation whose "variable" to read.
    ///
    /// Mirrors `AssemblyResolvedPatterns.readContextOp(ContextOp)`.
    fn read_context_op(&self, cop: &ContextOp) -> MaskedLong;

    /// Check if this and another resolution have equal encodings.
    ///
    /// This is like `Object.equals(Object)`, but it ignores backfill records and forbidden
    /// patterns.
    ///
    /// Mirrors `AssemblyResolvedPatterns.bitsEqual(AssemblyResolvedPatterns)`.
    fn bits_equal(&self, that: &dyn AssemblyResolvedPatterns) -> bool;

    /// Check if this assembled construct state is the same as the given dis-assembled construct
    /// state.
    ///
    /// Mirrors `AssemblyResolvedPatterns.equivalentConstructState(ConstructState)`.
    fn equivalent_construct_state(&self, state: &ConstructState) -> bool;

    /// Shift the instruction byte pattern right by `shamt` bytes.
    ///
    /// Named distinctly from [`AssemblyResolution::shift`] (also required, via this trait's
    /// supertrait bound) because Rust trait objects cannot resolve two same-named methods with
    /// different return types without an ambiguous-method-call error at the call site, mirroring
    /// [`AssemblyResolvedBackfill::shift_backfill`].
    ///
    /// Mirrors the covariant-return override `AssemblyResolvedPatterns.shift(int)` of
    /// `AssemblyResolution.shift(int)`.
    fn shift_patterns(&self, shamt: i32) -> Box<dyn AssemblyResolvedPatterns>;

    /// Create a copy of this resolution with a new description.
    ///
    /// Mirrors `AssemblyResolvedPatterns.withDescription(String)`.
    fn with_description(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns>;

    /// Create a copy of this resolution with a sibling to the right.
    ///
    /// The right sibling is a mechanism for collecting children of a parent yet to be created.
    /// See [`parent_patterns`](Self::parent_patterns).
    ///
    /// Named distinctly from a plain `with_right` (following the precedent set by
    /// [`DefaultAssemblyResolvedBackfill::with_right_backfill`](
    /// super::DefaultAssemblyResolvedBackfill::with_right_backfill)) so that a type implementing
    /// both this trait and [`AbstractAssemblyResolution`](super::AbstractAssemblyResolution) --
    /// exactly the shape of Java's `DefaultAssemblyResolvedPatterns extends
    /// AbstractAssemblyResolution implements AssemblyResolvedPatterns` -- doesn't hit an
    /// ambiguous-method-call error.
    ///
    /// Mirrors `AssemblyResolvedPatterns.withRight(AssemblyResolution)`.
    fn with_right_patterns(&self, right: Box<dyn AssemblyResolution>) -> Box<dyn AssemblyResolvedPatterns>;

    /// Create a copy of this resolution with a replaced constructor.
    ///
    /// Mirrors `AssemblyResolvedPatterns.withConstructor(Constructor)`.
    fn with_constructor(&self, cons: Arc<dyn Constructor>) -> Box<dyn AssemblyResolvedPatterns>;

    /// Combine the encodings and backfills of the given resolution into this one.
    ///
    /// This combines corresponding pattern blocks (assuming they agree), collects backfill
    /// records, and collects forbidden patterns. Returns `None` on failure, mirroring Java's
    /// nullable return.
    ///
    /// Mirrors `AssemblyResolvedPatterns.combine(AssemblyResolvedPatterns)`.
    fn combine(&self, pat: &dyn AssemblyResolvedPatterns) -> Option<Box<dyn AssemblyResolvedPatterns>>;

    /// Combine the given backfill record into this resolution.
    ///
    /// Named distinctly from [`combine`](Self::combine), since Rust has no method overloading and
    /// Java overloads `combine` on parameter type.
    ///
    /// Mirrors `AssemblyResolvedPatterns.combine(AssemblyResolvedBackfill)`.
    fn combine_backfill(&self, bf: &dyn AssemblyResolvedBackfill) -> Box<dyn AssemblyResolvedPatterns>;

    /// Combine a backfill result.
    ///
    /// When a backfill is successful, the result should be combined with the owning resolution.
    /// In addition, for bookkeeping's sake, the resolved record should be removed from the list
    /// of backfills. Returns `None` on failure, mirroring Java's nullable return.
    ///
    /// Mirrors `AssemblyResolvedPatterns.combineLessBackfill(AssemblyResolvedPatterns,
    /// AssemblyResolvedBackfill)`.
    fn combine_less_backfill(
        &self,
        that: &dyn AssemblyResolvedPatterns,
        bf: &dyn AssemblyResolvedBackfill,
    ) -> Option<Box<dyn AssemblyResolvedPatterns>>;

    /// Wrap this resolution as a child, pushing right-siblings down.
    ///
    /// Named distinctly from [`AssemblyResolution::parent`] (also required, via this trait's
    /// supertrait bound) for the same reason as [`shift_patterns`](Self::shift_patterns).
    ///
    /// Mirrors the covariant-return override `AssemblyResolvedPatterns.parent(String, int)` of
    /// `AssemblyResolution.parent(String, int)`.
    fn parent_patterns(&self, description: &str, op_count: i32) -> Box<dyn AssemblyResolvedPatterns>;

    /// Apply as many backfill records as possible.
    ///
    /// Each backfill record is resolved in turn; if the record cannot be resolved, it remains
    /// listed. If the record can be resolved, but it conflicts, an error record is returned. Each
    /// time a record is resolved and combined successfully, all remaining records are tried
    /// again. The result is the combined resolved backfills, with only the unresolved backfill
    /// records listed.
    ///
    /// `solver` is the solver, usually the same as the original attempt to solve. `vals` are the
    /// values.
    ///
    /// Mirrors `AssemblyResolvedPatterns.backfill(RecursiveDescentSolver, Map<String, Long>)`.
    fn backfill(
        &self,
        solver: &dyn RecursiveDescentSolver,
        vals: &HashMap<String, i64>,
    ) -> Box<dyn AssemblyResolution>;

    /// Check if the current encoding is forbidden by one of the attached patterns.
    ///
    /// The pattern becomes forbidden if this encoding's known bits are an overset of any
    /// forbidden pattern's known bits. Returns an error record if the pattern is forbidden.
    ///
    /// Mirrors `AssemblyResolvedPatterns.checkNotForbidden()`.
    fn check_not_forbidden(&self) -> Box<dyn AssemblyResolution>;

    /// Generate a new nop right this resolution to its right.
    ///
    /// Alternatively phrased: append a nop to the left of this list of siblings, returning the
    /// new head.
    ///
    /// Mirrors `AssemblyResolvedPatterns.nopLeftSibling()`.
    fn nop_left_sibling(&self) -> Box<dyn AssemblyResolvedPatterns>;

    /// Solve and apply context changes in reverse to forbidden patterns.
    ///
    /// To avoid circumstances where a context change during disassembly would invoke a more
    /// specific sub-constructor than was used to assembly the instruction, we must solve the
    /// forbidden patterns in tandem with the overall resolution. If the context of any forbidden
    /// pattern cannot be solved, we simply drop the forbidden pattern -- the lack of a solution
    /// implies there is no way the context change could produce the forbidden pattern.
    ///
    /// `sem` is the constructor whose context changes to solve, `vals` any defined symbols.
    ///
    /// Mirrors `AssemblyResolvedPatterns.solveContextChangesForForbids(AssemblyConstructorSemantic,
    /// Map<String, Long>)`.
    fn solve_context_changes_for_forbids(
        &self,
        sem: &dyn AssemblyConstructorSemantic,
        vals: &HashMap<String, i64>,
    ) -> Box<dyn AssemblyResolvedPatterns>;

    /// Get every possible filling of the instruction pattern given a context.
    ///
    /// This is similar to calling `possibleVals()` on [`get_instruction`](Self::get_instruction)'s
    /// result, *but* with forbidden patterns removed. A context is required so that only those
    /// forbidden patterns matching the given context are actually removed. This method should
    /// always be preferred to the sequence mentioned above, since a pattern block's raw possible
    /// values on their own may yield bytes that do not produce the desired instruction.
    ///
    /// `for_ctx` is the context at the assembly address.
    ///
    /// Mirrors `AssemblyResolvedPatterns.possibleInsVals(AssemblyPatternBlock)`, returning owned
    /// copies rather than Java's single-array-reusing `Iterable<byte[]>` (see this trait's own
    /// doc comment for why).
    fn possible_ins_vals(&self, for_ctx: &dyn AssemblyPatternBlock) -> Vec<Vec<u8>>;

    /// Used for testing and diagnostics: list the constructor line numbers used to resolve this
    /// encoding.
    ///
    /// This includes braces to describe the tree structure.
    ///
    /// Mirrors `AssemblyResolvedPatterns.dumpConstructorTree()`.
    fn dump_constructor_tree(&self) -> String;

    /// Truncate (unshift) the resolved instruction pattern from the left.
    ///
    /// **NOTE:** This drops all backfill and forbidden pattern records, since this method is
    /// typically used to read token fields rather than passed around for resolution.
    ///
    /// `shamt` is the number of bytes to remove from the left.
    ///
    /// Mirrors `AssemblyResolvedPatterns.truncate(int)`.
    fn truncate(&self, shamt: i32) -> Box<dyn AssemblyResolvedPatterns>;

    /// Create a new resolution from this one with the given forbidden patterns recorded.
    ///
    /// Mirrors `AssemblyResolvedPatterns.withForbids(Set<AssemblyResolvedPatterns>)`.
    fn with_forbids(&self, more: Vec<Box<dyn AssemblyResolvedPatterns>>) -> Box<dyn AssemblyResolvedPatterns>;

    /// Set all bits read by a given context operation to unknown.
    ///
    /// Mirrors `AssemblyResolvedPatterns.maskOut(ContextOp)`.
    fn mask_out(&self, cop: &ContextOp) -> Box<dyn AssemblyResolvedPatterns>;

    /// Encode the given value into the context block as specified by an operation.
    ///
    /// This is the forward (as in disassembly) direction of applying context operations. The
    /// pattern expression is evaluated, and the result is written as specified.
    ///
    /// `cop` is the context operation specifying the location of the value to encode, `val` the
    /// masked value to encode.
    ///
    /// Mirrors `AssemblyResolvedPatterns.writeContextOp(ContextOp, MaskedLong)`.
    fn write_context_op(&self, cop: &ContextOp, val: MaskedLong) -> Box<dyn AssemblyResolvedPatterns>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[derive(Clone, Debug)]
    struct MockBlock {
        vals: Vec<i8>,
    }

    impl AssemblyPatternBlock for MockBlock {
        fn get_vals(&self) -> Vec<i8> {
            self.vals.clone()
        }
        fn fill_mask(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: vec![-1; self.vals.len()] })
        }
    }

    /// A resolved pattern real enough to exercise [`bits_equal`](AssemblyResolvedPatterns::bits_equal)
    /// and [`combine`](AssemblyResolvedPatterns::combine) against genuine, non-trivial data,
    /// rather than only proving the trait compiles.
    #[derive(Clone, Debug)]
    struct MockPatterns {
        desc: String,
        instr: Vec<i8>,
        ctx: Vec<i8>,
        backfills: Vec<String>,
    }

    impl std::fmt::Display for MockPatterns {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.desc)
        }
    }

    impl AssemblyResolution for MockPatterns {
        fn get_description(&self) -> String {
            self.desc.clone()
        }
        fn get_children(&self) -> Vec<Box<dyn AssemblyResolution>> {
            vec![]
        }
        fn has_children(&self) -> bool {
            false
        }
        fn get_right(&self) -> Option<Box<dyn AssemblyResolution>> {
            None
        }
        fn line_to_string(&self) -> String {
            self.desc.clone()
        }
        fn is_backfill(&self) -> bool {
            false
        }
        fn is_error(&self) -> bool {
            false
        }
        fn shift(&self, _amt: i32) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn parent(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolution> {
            Box::new(MockPatterns { desc: description.to_string(), ..self.clone() })
        }
        fn collect_all_right(&self, into: &mut Vec<Box<dyn AssemblyResolution>>) {
            into.push(Box::new(self.clone()));
        }
        fn to_string_indented(&self, indent: &str) -> String {
            format!("{indent}{}", self.desc)
        }
        fn compare_to(&self, other: &dyn AssemblyResolution) -> Ordering {
            self.desc.cmp(&other.get_description())
        }
    }

    impl AssemblyResolvedPatterns for MockPatterns {
        fn get_instruction(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: self.instr.clone() })
        }
        fn get_context(&self) -> Box<dyn AssemblyPatternBlock> {
            Box::new(MockBlock { vals: self.ctx.clone() })
        }
        fn with_context(&self, ctx: Box<dyn AssemblyPatternBlock>) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { ctx: ctx.get_vals(), ..self.clone() })
        }
        fn get_instruction_length(&self) -> i32 {
            self.instr.len() as i32
        }
        fn get_defined_instruction_length(&self) -> i32 {
            self.instr.len() as i32
        }
        fn get_backfills(&self) -> Vec<Box<dyn AssemblyResolvedBackfill>> {
            vec![]
        }
        fn has_backfills(&self) -> bool {
            !self.backfills.is_empty()
        }
        fn get_forbids(&self) -> Vec<Box<dyn AssemblyResolvedPatterns>> {
            vec![]
        }
        fn read_instruction(&self, byte_start: i32, size: i32) -> MaskedLong {
            let mut val: i64 = 0;
            for i in 0..size {
                let byte = *self.instr.get((byte_start + i) as usize).unwrap_or(&0) as u8;
                val = (val << 8) | byte as i64;
            }
            MaskedLong::from_long(val)
        }
        fn read_context(&self, start: i32, len: i32) -> MaskedLong {
            self.read_instruction_like(&self.ctx, start, len)
        }
        fn read_context_op(&self, _cop: &ContextOp) -> MaskedLong {
            unimplemented!("not exercised by these tests")
        }
        fn bits_equal(&self, that: &dyn AssemblyResolvedPatterns) -> bool {
            self.get_instruction().get_vals() == that.get_instruction().get_vals()
                && self.get_context().get_vals() == that.get_context().get_vals()
        }
        fn equivalent_construct_state(&self, _state: &ConstructState) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn shift_patterns(&self, shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            let mut instr = vec![0i8; shamt as usize];
            instr.extend_from_slice(&self.instr);
            Box::new(MockPatterns { instr, ..self.clone() })
        }
        fn with_description(&self, description: &str) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string(), ..self.clone() })
        }
        fn with_right_patterns(
            &self,
            _right: Box<dyn AssemblyResolution>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn with_constructor(&self, _cons: Arc<dyn Constructor>) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn combine(&self, pat: &dyn AssemblyResolvedPatterns) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            if self.instr.len() != pat.get_instruction().get_vals().len() {
                return None;
            }
            Some(Box::new(MockPatterns {
                desc: self.desc.clone(),
                instr: pat.get_instruction().get_vals(),
                ctx: pat.get_context().get_vals(),
                backfills: self.backfills.clone(),
            }))
        }
        fn combine_backfill(&self, _bf: &dyn AssemblyResolvedBackfill) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn combine_less_backfill(
            &self,
            that: &dyn AssemblyResolvedPatterns,
            _bf: &dyn AssemblyResolvedBackfill,
        ) -> Option<Box<dyn AssemblyResolvedPatterns>> {
            self.combine(that)
        }
        fn parent_patterns(&self, description: &str, _op_count: i32) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { desc: description.to_string(), ..self.clone() })
        }
        fn backfill(
            &self,
            _solver: &dyn RecursiveDescentSolver,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn check_not_forbidden(&self) -> Box<dyn AssemblyResolution> {
            Box::new(self.clone())
        }
        fn nop_left_sibling(&self) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn solve_context_changes_for_forbids(
            &self,
            _sem: &dyn AssemblyConstructorSemantic,
            _vals: &HashMap<String, i64>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn possible_ins_vals(&self, _for_ctx: &dyn AssemblyPatternBlock) -> Vec<Vec<u8>> {
            vec![self.instr.iter().map(|b| *b as u8).collect()]
        }
        fn dump_constructor_tree(&self) -> String {
            self.desc.clone()
        }
        fn truncate(&self, shamt: i32) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(MockPatterns { instr: self.instr[shamt as usize..].to_vec(), ..self.clone() })
        }
        fn with_forbids(
            &self,
            _more: Vec<Box<dyn AssemblyResolvedPatterns>>,
        ) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn mask_out(&self, _cop: &ContextOp) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
        fn write_context_op(&self, _cop: &ContextOp, _val: MaskedLong) -> Box<dyn AssemblyResolvedPatterns> {
            Box::new(self.clone())
        }
    }

    impl MockPatterns {
        fn read_instruction_like(&self, bytes: &[i8], start: i32, len: i32) -> MaskedLong {
            let mut val: i64 = 0;
            for i in 0..len {
                let byte = *bytes.get((start + i) as usize).unwrap_or(&0) as u8;
                val = (val << 8) | byte as i64;
            }
            MaskedLong::from_long(val)
        }
    }

    fn patterns(desc: &str, instr: Vec<i8>, ctx: Vec<i8>) -> MockPatterns {
        MockPatterns { desc: desc.to_string(), instr, ctx, backfills: vec![] }
    }

    #[test]
    fn bits_equal_compares_instruction_and_context_bytes() {
        let a = patterns("a", vec![1, 2], vec![9]);
        let b = patterns("b", vec![1, 2], vec![9]);
        let c = patterns("c", vec![1, 3], vec![9]);
        assert!(a.bits_equal(&b));
        assert!(!a.bits_equal(&c));
    }

    #[test]
    fn combine_merges_encodings_when_lengths_agree() {
        let a = patterns("a", vec![0, 0], vec![0]);
        let b = patterns("b", vec![5, 6], vec![7]);
        let combined = a.combine(&b).expect("same instruction length, should combine");
        assert_eq!(combined.get_instruction().get_vals(), vec![5, 6]);
        assert_eq!(combined.get_context().get_vals(), vec![7]);
    }

    #[test]
    fn combine_fails_when_instruction_lengths_disagree() {
        let a = patterns("a", vec![0, 0], vec![0]);
        let b = patterns("b", vec![5], vec![7]);
        assert!(a.combine(&b).is_none());
    }

    #[test]
    fn shift_patterns_prepends_zero_bytes() {
        let a = patterns("a", vec![1, 2], vec![]);
        let shifted = a.shift_patterns(2);
        assert_eq!(shifted.get_instruction().get_vals(), vec![0, 0, 1, 2]);
    }

    #[test]
    fn truncate_removes_leading_bytes() {
        let a = patterns("a", vec![1, 2, 3], vec![]);
        let truncated = a.truncate(1);
        assert_eq!(truncated.get_instruction().get_vals(), vec![2, 3]);
    }

    #[test]
    fn read_instruction_reads_big_endian_value() {
        let a = patterns("a", vec![0x01, 0x02], vec![]);
        assert_eq!(a.read_instruction(0, 2), MaskedLong::from_long(0x0102));
    }

    #[test]
    fn has_backfills_reflects_pending_records() {
        let clean = patterns("a", vec![], vec![]);
        assert!(!clean.has_backfills());
        let pending = MockPatterns {
            desc: "b".to_string(),
            instr: vec![],
            ctx: vec![],
            backfills: vec!["inst_next".to_string()],
        };
        assert!(pending.has_backfills());
    }

    #[test]
    fn trait_is_object_safe() {
        let p: Box<dyn AssemblyResolvedPatterns> = Box::new(patterns("obj", vec![1], vec![2]));
        assert_eq!(p.get_instruction_length(), 1);
        assert!(!p.has_backfills());
        assert_eq!(p.dump_constructor_tree(), "obj");
    }
}
