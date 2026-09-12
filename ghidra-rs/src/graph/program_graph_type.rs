//! Port of `ghidra.graph.ProgramGraphType`.
//!
//! Defines a common set of vertex and edge type names for program code/data flow graphs. Java
//! models this as an abstract class subclassed by `BlockFlowGraphType`, `CallGraphType`,
//! `CodeFlowGraphType`, and `DataFlowGraphType` (each just supplying a name/description to
//! `super(...)`); per this crate's composition-over-inheritance convention (and mirroring the
//! already-ported [`BSimFeatureGraphType`](crate::feature::bsfv::bsim_feature_graph_type::BSimFeatureGraphType)),
//! [`ProgramGraphType`] is a struct that wraps and [`Deref`]s to [`GraphType`] rather than a base
//! class; a subclass becomes a thin wrapper around [`ProgramGraphType::new`] instead.
//!
//! # Static state becomes a pure computation
//!
//! Java builds `vertexTypes`/`edgeTypes`/`refTypeToEdgeTypeMap` as mutable `static` fields, with
//! sibling `vertex`/`edge`/`map` helper methods appending to them as a side effect of each
//! `public static final String XXX = vertex(...)`/`edge(...)` field initializer running exactly
//! once at class-load. Since those fields are computed once and never change afterward, this port
//! reproduces the *values* they end up holding via plain functions ([`vertex_types`],
//! [`edge_types`], [`get_edge_type`]) instead of mutable global state.
//!
//! # A faithful bug: four edge constants collapse to one value
//!
//! `CALL_OVERRIDE_UNCONDITIONAL`, `JUMP_OVERRIDE_UNCONDITIONAL`, `CALLOTHER_OVERRIDE_CALL`, and
//! `CALLOTHER_OVERRIDE_JUMP` are four *distinct* Java constants, but all four are initialized via
//! `edge(map(RefType.CALL_OVERRIDE_UNCONDITIONAL))` -- every one of them maps the *same*
//! `RefType.CALL_OVERRIDE_UNCONDITIONAL`, even though `RefType` has separate
//! `JUMP_OVERRIDE_UNCONDITIONAL`/`CALLOTHER_OVERRIDE_CALL`/`CALLOTHER_OVERRIDE_JUMP` constants of
//! its own that are never referenced here (`ProgramGraphType.java:70-73`). Two observable
//! consequences, both reproduced faithfully below rather than "fixed":
//! - All four Rust constants equal the same string, `"Call Override Unconditional"`.
//! - [`get_edge_type`] (mirroring `getEdgeType`, backed by `refTypeToEdgeTypeMap`) only ever
//!   associates that string with
//!   [`RefType::CallOverrideUnconditional`](crate::program::model::symbol::RefType::CallOverrideUnconditional);
//!   looking it up by [`RefType::JumpOverrideUnconditional`],
//!   [`RefType::CallOtherOverrideCall`], or [`RefType::CallOtherOverrideJump`] returns `None`,
//!   even though those `RefType`s have perfectly good display names of their own that this class
//!   just never calls `map()` on.

use std::ops::Deref;

use crate::program::model::symbol::RefType;
use crate::service::graph::GraphType;

// ---- Vertex type names (`ProgramGraphType.java:38-47`) ----
pub const BODY: &str = "Body";
pub const ENTRY: &str = "Entry";
pub const EXIT: &str = "Exit";
pub const SWITCH: &str = "Switch";
pub const EXTERNAL: &str = "External";
pub const BAD: &str = "Bad";
pub const INSTRUCTION: &str = "Instruction";
pub const DATA: &str = "Data";
pub const ENTRY_NEXUS: &str = "Entry-Nexus";
pub const STACK: &str = "Stack";

// ---- Edge type names -- flow (`ProgramGraphType.java:50-73`) ----
pub const ENTRY_EDGE: &str = "Entry";
pub const FALL_THROUGH: &str = "Fall Through";
pub const UNCONDITIONAL_JUMP: &str = "Unconditional Jump";
pub const UNCONDITIONAL_CALL: &str = "Unconditional Call";
pub const TERMINATOR: &str = "Terminator";
pub const JUMP_TERMINATOR: &str = "Jump Terminator";
pub const INDIRECTION: &str = "Indirection";
pub const CONDITIONAL_JUMP: &str = "Conditional Jump";
pub const CONDITIONAL_CALL: &str = "Conditional Call";
pub const CONDITIONAL_TERMINATOR: &str = "Conditional Terminator";
pub const CONDITIONAL_CALL_TERMINATOR: &str = "Conditional Call Terminator";
pub const COMPUTED_JUMP: &str = "Computed Jump";
pub const COMPUTED_CALL: &str = "Computed Call";
pub const COMPUTED_CALL_TERMINATOR: &str = "Computed Call Terminator";
pub const CONDITIONAL_COMPUTED_CALL: &str = "Conditional Computed Call";
pub const CONDITIONAL_COMPUTED_JUMP: &str = "Conditional Computed Jump";
/// See the [module docs](self) -- all four `*OVERRIDE*` constants below share this exact value,
/// faithfully reproducing a real bug in `ProgramGraphType.java:70-73`.
pub const CALL_OVERRIDE_UNCONDITIONAL: &str = "Call Override Unconditional";
pub const JUMP_OVERRIDE_UNCONDITIONAL: &str = CALL_OVERRIDE_UNCONDITIONAL;
pub const CALLOTHER_OVERRIDE_CALL: &str = CALL_OVERRIDE_UNCONDITIONAL;
pub const CALLOTHER_OVERRIDE_JUMP: &str = CALL_OVERRIDE_UNCONDITIONAL;

// ---- Edge type names -- data refs (`ProgramGraphType.java:76-88`) ----
pub const READ: &str = "Read";
pub const WRITE: &str = "Write";
pub const READ_WRITE: &str = "Read Write";
pub const UNKNOWN_DATA: &str = "Data";
/// `RefType.EXTERNAL_REF.getName()` is `"EXTERNAL"`, not `"EXTERNAL_REF"` -- the Java `RefType`
/// field name and the string passed to its constructor diverge (`RefType.java:445`:
/// `new DataRefType(__EXTERNAL_REF, "EXTERNAL", 0)`) -- so this fixes up to `"External"`, matching
/// [`EXTERNAL`], not `"External Ref"`.
pub const EXTERNAL_REF: &str = "External";
pub const READ_INDIRECT: &str = "Read Ind";
pub const WRITE_INDIRECT: &str = "Write Ind";
pub const READ_WRITE_INDIRECT: &str = "Read Write Ind";
pub const DATA_INDIRECT: &str = "Data Ind";
pub const PARAM: &str = "Param";
pub const THUNK: &str = "Thunk";

/// `ProgramGraphType.fixup(String)`: replaces `_` with a space, then title-cases each word.
///
/// Exposed so tests can verify every hardcoded edge constant above against a live computation
/// from [`RefType::name`], rather than trusting hand-transcribed literals.
fn fixup(name: &str) -> String {
    name.replace('_', " ")
        .split(' ')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `ProgramGraphType.map(RefType)`, minus the `refTypeToEdgeTypeMap` side effect (handled
/// separately by [`get_edge_type`]).
fn map(ref_type: RefType) -> String {
    fixup(ref_type.name())
}

/// The full, order-preserved list of vertex types, matching Java's static `vertexTypes` list
/// (`GraphType::new` deduplicates it exactly like Java's `LinkedHashSet`, so passing it verbatim
/// here is equivalent to Java's `List`).
fn vertex_types() -> Vec<String> {
    [BODY, ENTRY, EXIT, SWITCH, EXTERNAL, BAD, INSTRUCTION, DATA, ENTRY_NEXUS, STACK]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The full, order-preserved list of edge types, matching Java's static `edgeTypes` list
/// (declaration order, *before* `GraphType::new`'s deduplication -- so this includes all four
/// `*_OVERRIDE_*` duplicates, exactly like Java's raw field-initialization order).
fn edge_types() -> Vec<String> {
    [
        ENTRY_EDGE,
        FALL_THROUGH,
        UNCONDITIONAL_JUMP,
        UNCONDITIONAL_CALL,
        TERMINATOR,
        JUMP_TERMINATOR,
        INDIRECTION,
        CONDITIONAL_JUMP,
        CONDITIONAL_CALL,
        CONDITIONAL_TERMINATOR,
        CONDITIONAL_CALL_TERMINATOR,
        COMPUTED_JUMP,
        COMPUTED_CALL,
        COMPUTED_CALL_TERMINATOR,
        CONDITIONAL_COMPUTED_CALL,
        CONDITIONAL_COMPUTED_JUMP,
        CALL_OVERRIDE_UNCONDITIONAL,
        JUMP_OVERRIDE_UNCONDITIONAL,
        CALLOTHER_OVERRIDE_CALL,
        CALLOTHER_OVERRIDE_JUMP,
        READ,
        WRITE,
        READ_WRITE,
        UNKNOWN_DATA,
        EXTERNAL_REF,
        READ_INDIRECT,
        WRITE_INDIRECT,
        READ_WRITE_INDIRECT,
        DATA_INDIRECT,
        PARAM,
        THUNK,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// `ProgramGraphType.getEdgeType(RefType)`, backed by the (now-pure) equivalent of
/// `refTypeToEdgeTypeMap`.
///
/// Only returns `Some` for the exact set of `RefType`s Java's static initializers actually passed
/// to `map(...)`. See the [module docs](self) for why
/// [`RefType::JumpOverrideUnconditional`]/[`RefType::CallOtherOverrideCall`]/
/// [`RefType::CallOtherOverrideJump`] are faithfully *not* included, unlike
/// [`RefType::CallOverrideUnconditional`].
pub fn get_edge_type(ref_type: RefType) -> Option<String> {
    use RefType::*;
    match ref_type {
        FallThrough | UnconditionalJump | UnconditionalCall | Terminator | JumpTerminator
        | Indirection | ConditionalJump | ConditionalCall | ConditionalTerminator
        | ConditionalCallTerminator | ComputedJump | ComputedCall | ComputedCallTerminator
        | ConditionalComputedCall | ConditionalComputedJump | CallOverrideUnconditional | Read
        | Write | ReadWrite | Data | ExternalRef | ReadInd | WriteInd | ReadWriteInd | Param
        | Thunk => Some(map(ref_type)),
        _ => None,
    }
}

/// Port of the abstract `ghidra.graph.ProgramGraphType`.
///
/// A subclass (`BlockFlowGraphType`, `CallGraphType`, ...; none ported yet) is expected to be a
/// thin wrapper that calls [`ProgramGraphType::new`] with its own name/description, exactly as
/// each Java subclass's constructor does with `super(name, description)`.
pub struct ProgramGraphType {
    graph_type: GraphType,
}

impl ProgramGraphType {
    /// `ProgramGraphType(String, String)`.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            graph_type: GraphType::new(name.into(), description.into(), vertex_types(), edge_types()),
        }
    }

    /// `ProgramGraphType.getOptionsName()` -- overrides `GraphType`'s `"<name> Graph Type"`
    /// default with a fixed constant, same as Java.
    pub fn get_options_name(&self) -> &'static str {
        "Program Graph Display Options"
    }
}

impl Deref for ProgramGraphType {
    type Target = GraphType;

    fn deref(&self) -> &Self::Target {
        &self.graph_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixup_replaces_underscores_and_title_cases() {
        assert_eq!(fixup("FALL_THROUGH"), "Fall Through");
        assert_eq!(fixup("TERMINATOR"), "Terminator");
        assert_eq!(fixup("CONDITIONAL_CALL_TERMINATOR"), "Conditional Call Terminator");
    }

    #[test]
    fn edge_constants_match_a_live_fixup_of_the_backing_reftype_name() {
        assert_eq!(FALL_THROUGH, fixup(RefType::FallThrough.name()));
        assert_eq!(UNCONDITIONAL_JUMP, fixup(RefType::UnconditionalJump.name()));
        assert_eq!(UNCONDITIONAL_CALL, fixup(RefType::UnconditionalCall.name()));
        assert_eq!(TERMINATOR, fixup(RefType::Terminator.name()));
        assert_eq!(JUMP_TERMINATOR, fixup(RefType::JumpTerminator.name()));
        assert_eq!(INDIRECTION, fixup(RefType::Indirection.name()));
        assert_eq!(CONDITIONAL_JUMP, fixup(RefType::ConditionalJump.name()));
        assert_eq!(CONDITIONAL_CALL, fixup(RefType::ConditionalCall.name()));
        assert_eq!(CONDITIONAL_TERMINATOR, fixup(RefType::ConditionalTerminator.name()));
        assert_eq!(
            CONDITIONAL_CALL_TERMINATOR,
            fixup(RefType::ConditionalCallTerminator.name())
        );
        assert_eq!(COMPUTED_JUMP, fixup(RefType::ComputedJump.name()));
        assert_eq!(COMPUTED_CALL, fixup(RefType::ComputedCall.name()));
        assert_eq!(COMPUTED_CALL_TERMINATOR, fixup(RefType::ComputedCallTerminator.name()));
        assert_eq!(CONDITIONAL_COMPUTED_CALL, fixup(RefType::ConditionalComputedCall.name()));
        assert_eq!(CONDITIONAL_COMPUTED_JUMP, fixup(RefType::ConditionalComputedJump.name()));
        assert_eq!(CALL_OVERRIDE_UNCONDITIONAL, fixup(RefType::CallOverrideUnconditional.name()));
        assert_eq!(READ, fixup(RefType::Read.name()));
        assert_eq!(WRITE, fixup(RefType::Write.name()));
        assert_eq!(READ_WRITE, fixup(RefType::ReadWrite.name()));
        assert_eq!(UNKNOWN_DATA, fixup(RefType::Data.name()));
        assert_eq!(EXTERNAL_REF, fixup(RefType::ExternalRef.name()));
        assert_eq!(READ_INDIRECT, fixup(RefType::ReadInd.name()));
        assert_eq!(WRITE_INDIRECT, fixup(RefType::WriteInd.name()));
        assert_eq!(READ_WRITE_INDIRECT, fixup(RefType::ReadWriteInd.name()));
        assert_eq!(DATA_INDIRECT, fixup(RefType::DataInd.name()));
        assert_eq!(PARAM, fixup(RefType::Param.name()));
        assert_eq!(THUNK, fixup(RefType::Thunk.name()));
    }

    #[test]
    fn all_four_override_constants_collapse_to_the_same_value() {
        // Faithful bug reproduction: ProgramGraphType.java:70-73 maps all four of these to
        // RefType.CALL_OVERRIDE_UNCONDITIONAL, not their own distinct RefTypes.
        assert_eq!(CALL_OVERRIDE_UNCONDITIONAL, "Call Override Unconditional");
        assert_eq!(JUMP_OVERRIDE_UNCONDITIONAL, CALL_OVERRIDE_UNCONDITIONAL);
        assert_eq!(CALLOTHER_OVERRIDE_CALL, CALL_OVERRIDE_UNCONDITIONAL);
        assert_eq!(CALLOTHER_OVERRIDE_JUMP, CALL_OVERRIDE_UNCONDITIONAL);
    }

    #[test]
    fn get_edge_type_resolves_the_mapped_reftypes() {
        assert_eq!(get_edge_type(RefType::FallThrough), Some(FALL_THROUGH.to_string()));
        assert_eq!(
            get_edge_type(RefType::CallOverrideUnconditional),
            Some(CALL_OVERRIDE_UNCONDITIONAL.to_string())
        );
        assert_eq!(get_edge_type(RefType::Thunk), Some(THUNK.to_string()));
    }

    #[test]
    fn get_edge_type_is_none_for_reftypes_the_bug_never_registers() {
        // These RefTypes have real display names of their own, but ProgramGraphType.java never
        // calls map() on them (see the module docs), so getEdgeType returns null for them in
        // Java too.
        assert_eq!(get_edge_type(RefType::JumpOverrideUnconditional), None);
        assert_eq!(get_edge_type(RefType::CallOtherOverrideCall), None);
        assert_eq!(get_edge_type(RefType::CallOtherOverrideJump), None);
    }

    #[test]
    fn get_edge_type_is_none_for_reftypes_never_mapped_at_all() {
        assert_eq!(get_edge_type(RefType::Invalid), None);
        assert_eq!(get_edge_type(RefType::Flow), None);
    }

    #[test]
    fn new_builds_a_graph_type_with_name_and_description() {
        let gt = ProgramGraphType::new("Call Graph", "Shows relationships between functions");
        assert_eq!(gt.get_name(), "Call Graph");
        assert_eq!(gt.get_description(), "Shows relationships between functions");
    }

    #[test]
    fn new_contains_every_vertex_and_edge_type() {
        let gt = ProgramGraphType::new("Test", "d");
        for v in vertex_types() {
            assert!(gt.contains_vertex_type(&v), "missing vertex type {v}");
        }
        for e in edge_types() {
            assert!(gt.contains_edge_type(&e), "missing edge type {e}");
        }
    }

    #[test]
    fn the_four_duplicate_override_edges_collapse_to_one_entry() {
        // GraphType::new dedups edge_types() the same way Java's LinkedHashSet does, so despite
        // pushing "Call Override Unconditional" four times, the final edge type set contains it
        // exactly once.
        let gt = ProgramGraphType::new("Test", "d");
        let edges = gt.get_edge_types();
        let occurrences =
            edges.iter().filter(|e| e.as_str() == CALL_OVERRIDE_UNCONDITIONAL).count();
        assert_eq!(occurrences, 1);

        let raw_pushes =
            edge_types().iter().filter(|e| e.as_str() == CALL_OVERRIDE_UNCONDITIONAL).count();
        assert_eq!(raw_pushes, 4);
    }

    #[test]
    fn get_options_name_is_a_fixed_constant_not_derived_from_name() {
        let gt = ProgramGraphType::new("Anything", "d");
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
        // Sanity: GraphType's own default derivation would have said "Anything Graph Type" --
        // ProgramGraphType overrides it instead of inheriting that default.
        assert_ne!(gt.get_options_name(), gt.deref().get_options_name());
    }

    #[test]
    fn deref_exposes_the_wrapped_graph_type() {
        let gt = ProgramGraphType::new("Data Flow Graph", "Shows program data relationships");
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert!(!gt.contains_vertex_type("Not A Vertex"));
    }
}
