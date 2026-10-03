//! Port of `ghidra.program.model.symbol.FlowType`.
//!
//! Java models `FlowType` as `public final class FlowType extends RefType`: every one of its
//! instances (`FlowType.INVALID`, `FlowType.FALL_THROUGH`, `FlowType.UNCONDITIONAL_JUMP`, ...) is
//! also declared as a `public static final FlowType` constant directly on `RefType` itself (see
//! `RefType.java`), each built via `FlowType.Builder` with the exact same `(byte value, String
//! name)` pair and boolean flags that this crate's [`RefType`](crate::program::model::symbol::RefType)
//! enum already reproduces one-for-one (see `ref_type.rs`, which folds `RefType`/`DataRefType`/
//! `FlowType` into a single enum, since Java's constants already partition cleanly into "flow"
//! and "data" kinds with no overlapping behavior).
//!
//! Rather than duplicate that data (composition over inheritance, and to keep a single source of
//! truth for the values/flags), `FlowType` here is a thin newtype over [`RefType`] that only ever
//! wraps a flow-kind value -- the same invariant Java's type system enforces by construction
//! (`FlowType` the Java class only ever *is* constructed with flow-kind bytes). Each method
//! `FlowType.java` declares (all of which just re-expose or override a `RefType` method to return
//! the *sub-type's* fixed answer -- see below) delegates to the wrapped [`RefType`]'s
//! already-ported, identically-behaving method.
//!
//! ## `isFlow()`/`isUnConditional()` overrides
//!
//! `FlowType.isFlow()` is hard-overridden to always return `true` (every `FlowType` is, tautologically,
//! a flow type) -- this matches [`RefType::is_flow`] anyway for every value `FlowType` can hold, so
//! [`FlowType::is_flow`] is a `true`-returning method here purely for signature fidelity with the
//! Java override, not because the delegation could ever disagree. `FlowType.isUnConditional()` is
//! `!isConditional()`, matching [`RefType::is_unconditional`] exactly (same delegation, no override
//! subtlety).
//!
//! ## Relationship to `crate::program::seam_stubs::FlowType`
//!
//! A separate, unrelated placeholder trait of the same name already exists at
//! `crate::program::seam_stubs::FlowType`, used as a `Box<dyn FlowType>` polymorphic return type by
//! several not-yet-fully-ported call sites (`CodeBlock::get_flow_type`, `CodeBlockReference`,
//! `SubroutineDestReferenceIterator`, `UndefinedFunction`, ...) with placeholder
//! `impl FlowType for Foo {}` implementations. That trait predates this port and serves those
//! call sites' current (trait-object-shaped) needs; migrating them onto this concrete,
//! `RefType`-backed `FlowType` is a separate, broader follow-up (each call site would need to
//! decide what concrete `RefType`/`FlowType` value it actually produces) and is out of scope for
//! this port, which targets `FlowType.java` itself.

use crate::program::model::symbol::RefType;

/// A [`RefType`] known to be flow-kind, matching Java's `FlowType extends RefType`.
///
/// Port of `ghidra.program.model.symbol.FlowType`. See the module docs for why this is a newtype
/// over [`RefType`] rather than a duplicate enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowType(RefType);

impl FlowType {
    /// Corresponds to an unknown `FlowType` which encountered an error when determining the
    /// flow-type of the instruction at the from address.
    pub const INVALID: FlowType = FlowType(RefType::Invalid);
    /// Corresponds to a complex or generic `FlowType`, used to describe the flow-type of an
    /// instruction or code-block containing multiple outbound flows of differing types. Should
    /// not be used for a specific flow `Reference`.
    pub const FLOW: FlowType = FlowType(RefType::Flow);
    /// Instruction fall-through override where modeling requires a fall-through instruction to
    /// convey a branch around other code units.
    pub const FALL_THROUGH: FlowType = FlowType(RefType::FallThrough);
    /// Unconditional jump/branch.
    pub const UNCONDITIONAL_JUMP: FlowType = FlowType(RefType::UnconditionalJump);
    /// Conditional jump/branch.
    pub const CONDITIONAL_JUMP: FlowType = FlowType(RefType::ConditionalJump);
    /// Unconditional call with fall-through.
    pub const UNCONDITIONAL_CALL: FlowType = FlowType(RefType::UnconditionalCall);
    /// Conditional call with fall-through.
    pub const CONDITIONAL_CALL: FlowType = FlowType(RefType::ConditionalCall);
    /// Terminal flow (e.g. return from a function).
    pub const TERMINATOR: FlowType = FlowType(RefType::Terminator);
    /// Computed jump/branch.
    pub const COMPUTED_JUMP: FlowType = FlowType(RefType::ComputedJump);
    /// Terminal flow with a conditional (e.g. conditional return from a function).
    pub const CONDITIONAL_TERMINATOR: FlowType = FlowType(RefType::ConditionalTerminator);
    /// Computed call with fall-through.
    pub const COMPUTED_CALL: FlowType = FlowType(RefType::ComputedCall);
    /// Flow reference placed on a pointer data location utilized indirectly by a computed
    /// jump/branch or call instruction.
    pub const INDIRECTION: FlowType = FlowType(RefType::Indirection);
    /// Unconditional call followed by a terminal without fall-through.
    pub const CALL_TERMINATOR: FlowType = FlowType(RefType::CallTerminator);
    /// Conditional jump/branch followed by a terminal without fall-through.
    pub const JUMP_TERMINATOR: FlowType = FlowType(RefType::JumpTerminator);
    /// Conditional computed jump/branch.
    pub const CONDITIONAL_COMPUTED_JUMP: FlowType = FlowType(RefType::ConditionalComputedJump);
    /// Conditional computed call with fall-through.
    pub const CONDITIONAL_COMPUTED_CALL: FlowType = FlowType(RefType::ConditionalComputedCall);
    /// Conditional call followed by a terminal without fall-through.
    pub const CONDITIONAL_CALL_TERMINATOR: FlowType = FlowType(RefType::ConditionalCallTerminator);
    /// Computed call followed by a terminal without fall-through.
    pub const COMPUTED_CALL_TERMINATOR: FlowType = FlowType(RefType::ComputedCallTerminator);
    /// Overrides the destination of a `CALL`/`CALLIND` pcode operation to an unconditional call.
    pub const CALL_OVERRIDE_UNCONDITIONAL: FlowType = FlowType(RefType::CallOverrideUnconditional);
    /// Overrides the destination of a `BRANCH`/`CBRANCH` pcode operation to an unconditional jump.
    pub const JUMP_OVERRIDE_UNCONDITIONAL: FlowType = FlowType(RefType::JumpOverrideUnconditional);
    /// Changes a `CALLOTHER` pcode operation to a `CALL` operation.
    pub const CALLOTHER_OVERRIDE_CALL: FlowType = FlowType(RefType::CallOtherOverrideCall);
    /// Changes a `CALLOTHER` pcode operation to a `BRANCH` operation.
    pub const CALLOTHER_OVERRIDE_JUMP: FlowType = FlowType(RefType::CallOtherOverrideJump);

    /// Attempts to view a general [`RefType`] as a `FlowType`. Returns `None` if `ref_type` is
    /// data-kind, mirroring the invariant Java enforces structurally (only `RefType`'s flow-kind
    /// constants are ever actually instances of the `FlowType` subclass).
    pub fn from_ref_type(ref_type: RefType) -> Option<Self> {
        if ref_type.is_flow() {
            Some(FlowType(ref_type))
        } else {
            None
        }
    }

    /// Returns the underlying [`RefType`], for callers that need the general reference-type API
    /// (e.g. [`RefType::value`], [`RefType::from_value`], [`RefType::display_string`]).
    pub fn ref_type(self) -> RefType {
        self.0
    }

    /// Returns the Java persistent byte value for this flow type.
    pub fn value(self) -> i8 {
        self.0.value()
    }

    /// Returns the Java reference type name.
    pub fn name(self) -> &'static str {
        self.0.name()
    }

    /// Returns a display string matching Ghidra's `getDisplayString`.
    pub fn display_string(self) -> &'static str {
        self.0.display_string()
    }

    /// Matches Java's `FlowType.hasFallthrough()` override.
    pub fn has_fallthrough(self) -> bool {
        self.0.has_fallthrough()
    }

    /// Matches Java's `FlowType.isCall()` override.
    pub fn is_call(self) -> bool {
        self.0.is_call()
    }

    /// Matches Java's `FlowType.isComputed()` override.
    pub fn is_computed(self) -> bool {
        self.0.is_computed()
    }

    /// Matches Java's `FlowType.isConditional()` override.
    pub fn is_conditional(self) -> bool {
        self.0.is_conditional()
    }

    /// Matches Java's `FlowType.isFlow()` override, which is hard-coded to always return `true`
    /// (see the module docs).
    pub fn is_flow(self) -> bool {
        true
    }

    /// Matches Java's `FlowType.isJump()` override.
    pub fn is_jump(self) -> bool {
        self.0.is_jump()
    }

    /// Matches Java's `FlowType.isTerminal()` override.
    pub fn is_terminal(self) -> bool {
        self.0.is_terminal()
    }

    /// Matches Java's `FlowType.isUnConditional()` override (`!isConditional()`).
    pub fn is_unconditional(self) -> bool {
        !self.is_conditional()
    }

    /// Matches Java's `FlowType.isOverride()` override.
    pub fn is_override(self) -> bool {
        self.0.is_override()
    }

    /// Not declared on `FlowType.java` itself (it lives on the `RefType` base), but exposed here
    /// too since `Indirection`/`DataInd`/`ReadInd`/etc. all route through it and several
    /// `FlowType` constants (e.g. [`FlowType::INDIRECTION`]) are indirection-flavored.
    pub fn is_indirect(self) -> bool {
        self.0.is_indirect()
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl From<FlowType> for RefType {
    fn from(flow_type: FlowType) -> Self {
        flow_type.0
    }
}

impl TryFrom<RefType> for FlowType {
    type Error = ();

    fn try_from(ref_type: RefType) -> Result<Self, Self::Error> {
        FlowType::from_ref_type(ref_type).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_ref_type_values() {
        assert_eq!(FlowType::INVALID.value(), -2);
        assert_eq!(FlowType::FLOW.value(), -1);
        assert_eq!(FlowType::FALL_THROUGH.value(), 0);
        assert_eq!(FlowType::UNCONDITIONAL_JUMP.value(), 1);
        assert_eq!(FlowType::CONDITIONAL_JUMP.value(), 2);
        assert_eq!(FlowType::UNCONDITIONAL_CALL.value(), 3);
        assert_eq!(FlowType::CONDITIONAL_CALL.value(), 4);
        assert_eq!(FlowType::TERMINATOR.value(), 5);
        assert_eq!(FlowType::COMPUTED_JUMP.value(), 6);
        assert_eq!(FlowType::CONDITIONAL_TERMINATOR.value(), 7);
        assert_eq!(FlowType::COMPUTED_CALL.value(), 8);
        assert_eq!(FlowType::INDIRECTION.value(), 9);
        assert_eq!(FlowType::CALL_TERMINATOR.value(), 10);
        assert_eq!(FlowType::JUMP_TERMINATOR.value(), 11);
        assert_eq!(FlowType::CONDITIONAL_COMPUTED_JUMP.value(), 12);
        assert_eq!(FlowType::CONDITIONAL_COMPUTED_CALL.value(), 13);
        assert_eq!(FlowType::CONDITIONAL_CALL_TERMINATOR.value(), 14);
        assert_eq!(FlowType::COMPUTED_CALL_TERMINATOR.value(), 15);
        assert_eq!(FlowType::CALL_OVERRIDE_UNCONDITIONAL.value(), 16);
        assert_eq!(FlowType::JUMP_OVERRIDE_UNCONDITIONAL.value(), 17);
        assert_eq!(FlowType::CALLOTHER_OVERRIDE_CALL.value(), 18);
        assert_eq!(FlowType::CALLOTHER_OVERRIDE_JUMP.value(), 19);
    }

    #[test]
    fn names_match_java_constants() {
        assert_eq!(FlowType::FALL_THROUGH.name(), "FALL_THROUGH");
        assert_eq!(FlowType::UNCONDITIONAL_JUMP.name(), "UNCONDITIONAL_JUMP");
        assert_eq!(
            FlowType::CONDITIONAL_COMPUTED_CALL.name(),
            "CONDITIONAL_COMPUTED_CALL"
        );
        assert_eq!(FlowType::FALL_THROUGH.to_string(), "FALL_THROUGH");
    }

    #[test]
    fn is_flow_is_always_true_matching_the_hard_override() {
        // Every FlowType constant reports true, matching Java's `isFlow()` override, which
        // ignores the underlying RefType's own kind check entirely.
        assert!(FlowType::INVALID.is_flow());
        assert!(FlowType::FALL_THROUGH.is_flow());
        assert!(FlowType::TERMINATOR.is_flow());
        assert!(FlowType::CALLOTHER_OVERRIDE_JUMP.is_flow());
    }

    #[test]
    fn query_methods_delegate_to_ref_type() {
        assert!(FlowType::CONDITIONAL_JUMP.has_fallthrough());
        assert!(FlowType::CONDITIONAL_JUMP.is_jump());
        assert!(FlowType::CONDITIONAL_JUMP.is_conditional());
        assert!(!FlowType::CONDITIONAL_JUMP.is_unconditional());
        assert!(FlowType::UNCONDITIONAL_CALL.is_call());
        assert!(FlowType::UNCONDITIONAL_CALL.is_unconditional());
        assert!(FlowType::COMPUTED_CALL.is_computed());
        assert!(FlowType::TERMINATOR.is_terminal());
        assert!(FlowType::CALL_OVERRIDE_UNCONDITIONAL.is_override());
        assert!(FlowType::INDIRECTION.is_indirect());
        assert!(!FlowType::UNCONDITIONAL_JUMP.is_indirect());
    }

    #[test]
    fn display_string_delegates_to_ref_type() {
        assert_eq!(FlowType::UNCONDITIONAL_CALL.display_string(), "Call");
        assert_eq!(FlowType::UNCONDITIONAL_JUMP.display_string(), "Jump");
        assert_eq!(FlowType::CONDITIONAL_JUMP.display_string(), "Branch");
        assert_eq!(FlowType::FALL_THROUGH.display_string(), "FallThrough");
    }

    #[test]
    fn from_ref_type_accepts_flow_kind_and_rejects_data_kind() {
        assert_eq!(
            FlowType::from_ref_type(RefType::UnconditionalJump),
            Some(FlowType::UNCONDITIONAL_JUMP)
        );
        assert_eq!(FlowType::from_ref_type(RefType::Read), None);
        assert_eq!(FlowType::from_ref_type(RefType::Thunk), None);

        assert_eq!(
            FlowType::try_from(RefType::ConditionalCall),
            Ok(FlowType::CONDITIONAL_CALL)
        );
        assert!(FlowType::try_from(RefType::Data).is_err());
    }

    #[test]
    fn ref_type_round_trips_through_from_and_into() {
        let flow: FlowType = FlowType::COMPUTED_JUMP;
        let ref_type: RefType = flow.into();
        assert_eq!(ref_type, RefType::ComputedJump);
        assert_eq!(FlowType::from_ref_type(ref_type), Some(flow));
    }
}
