//! Port of `ghidra.program.model.listing.FlowOverride`.
//!
//! Java models this as a plain `enum` (`NONE`, `BRANCH`, `CALL`, `CALL_RETURN`, `RETURN`) whose
//! doc comment explicitly warns "New instances may be appended but not inserted in the list
//! below!!" -- i.e. ordinal values are persisted (e.g. to a database) and must never shift. This
//! port assigns explicit discriminants matching those Java ordinals one-for-one.
//!
//! `FlowOverride` describes how a decompiler should re-map the primary pcode flow operation(s) at
//! an instruction (e.g. treat a `CALL` as if it were a `BRANCH`); it is a distinct concept from
//! [`FlowType`](crate::program::model::symbol::FlowType), which instead classifies *what kind* of
//! flow a reference already is. `FlowOverride::get_modified_flow_type` bridges the two: given an
//! original [`FlowType`] and a `FlowOverride`, it computes the [`FlowType`] that results from
//! applying the override -- mirroring `FlowOverride.getModifiedFlowType(FlowType, FlowOverride)`
//! exactly, including its somewhat redundant (but harmless) repeated `isCall()` checks in the
//! `CALL` branch (see the inline comment there).
//!
//! ## Relationship to `crate::program::seam_stubs::FlowOverride`
//!
//! A placeholder `FlowOverride` enum with the same five variants already exists at
//! `crate::program::seam_stubs::FlowOverride`, used by `InstructionDB`
//! (`program/database/code/instruction_db.rs`) and the SARIF code manager
//! (`sarif/managers/code_sarif_mgr.rs`). Its doc comment already flags this: "the real enum
//! carr[ies] `getFlowOverride(int)`, `ordinal()` and `getModifiedFlowType(FlowType,
//! FlowOverride)`... omitted [from the placeholder]... belong on `FlowOverride` itself once that
//! placeholder is replaced by a real port of `FlowOverride.java`." `instruction_db.rs` in fact
//! already hand-rolls faithful copies of exactly those three statics
//! (`flow_override_from_ordinal`, `flow_override_ordinal`, `modified_flow_type`) as free
//! functions, duplicating what this module now provides as real methods. Migrating those two
//! call sites onto this module (and deleting the `seam_stubs` placeholder plus its duplicated
//! logic) is a mechanical follow-up, intentionally left out of this port to stay within this
//! session's file scope (both call sites sit in files owned by concurrent porting work).

use crate::program::model::symbol::FlowType;

/// How a decompiler should re-map the primary flow pcode-op(s) at an instruction.
///
/// Port of `ghidra.program.model.listing.FlowOverride`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum FlowOverride {
    /// No flow override has been established.
    None = 0,
    /// Override the primary CALL or RETURN with a suitable JUMP operation.
    ///
    /// Pcode mapping: `CALL -> BRANCH`, `CALLIND -> BRANCHIND`, `RETURN -> BRANCHIND`.
    Branch = 1,
    /// Override the primary BRANCH or RETURN with a suitable CALL operation.
    ///
    /// Pcode mapping: `BRANCH -> CALL`, `BRANCHIND -> CALLIND`, `RETURN -> CALLIND`, and a
    /// complex `CBRANCH <addr>,<cond>` mapping (negate the condition, branch around a `CALL
    /// <addr>`).
    Call = 2,
    /// Override the primary BRANCH, CALL, or RETURN with a suitable CALL/RETURN operation.
    CallReturn = 3,
    /// Override the primary BRANCH or CALL with a suitable RETURN operation.
    Return = 4,
}

impl FlowOverride {
    /// Returns the Java `ordinal()` value for this override.
    pub fn ordinal(self) -> i32 {
        self as i32
    }

    /// Returns the `FlowOverride` with the specified ordinal value. Returns [`FlowOverride::None`]
    /// for an unknown value.
    ///
    /// Port of `FlowOverride.getFlowOverride(int)`.
    pub fn get_flow_override(ordinal: i32) -> FlowOverride {
        match ordinal {
            0 => FlowOverride::None,
            1 => FlowOverride::Branch,
            2 => FlowOverride::Call,
            3 => FlowOverride::CallReturn,
            4 => FlowOverride::Return,
            _ => FlowOverride::None,
        }
    }

    /// Get the modified [`FlowType`] resulting from the application of the specified
    /// `flow_override` to `original_flow_type`.
    ///
    /// Port of `FlowOverride.getModifiedFlowType(FlowType, FlowOverride)`.
    pub fn get_modified_flow_type(
        original_flow_type: FlowType,
        flow_override: FlowOverride,
    ) -> FlowType {
        let flow_type = original_flow_type;
        if flow_override == FlowOverride::None
            || (!flow_type.is_jump() && !flow_type.is_terminal() && !flow_type.is_call())
        {
            return flow_type;
        }
        // NOTE: The following flow-type overrides assume that a return will always be the last
        // flow pcode-op -- since it is the first primary flow pcode-op that will get replaced.
        match flow_override {
            FlowOverride::Branch => {
                if flow_type.is_jump() {
                    return flow_type;
                }
                if flow_type.is_conditional() {
                    // Assume that we will never start with a complex flow with terminator, i.e.
                    // CONDITIONAL-JUMP-TERMINATOR.
                    if flow_type.is_terminal() {
                        // Assume return replaced.
                        return FlowType::CONDITIONAL_COMPUTED_JUMP;
                    }
                    return FlowType::CONDITIONAL_JUMP;
                }
                if flow_type.is_computed() {
                    return FlowType::COMPUTED_JUMP;
                }
                if flow_type.is_terminal() {
                    // Assume return replaced.
                    return FlowType::COMPUTED_JUMP;
                }
                FlowType::UNCONDITIONAL_JUMP
            }
            FlowOverride::Call => {
                if flow_type.is_call() {
                    return flow_type;
                }
                if flow_type.is_conditional() {
                    // At this point `flow_type.is_call()` is always false (handled above), so
                    // this mirrors Java's `isTerminal() && (isCall() || isJump())` literally even
                    // though the `isCall()` half can never be true here -- faithful transcription
                    // of the (harmless) redundancy in `FlowOverride.java`.
                    if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                        // Assume original return was preserved.
                        return FlowType::CONDITIONAL_CALL_TERMINATOR;
                    }
                    if flow_type.is_terminal() {
                        // Assume return was replaced.
                        return FlowType::CONDITIONAL_COMPUTED_CALL;
                    }
                    return FlowType::CONDITIONAL_CALL;
                }
                if flow_type.is_computed() {
                    if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                        // Assume original return was preserved.
                        return FlowType::COMPUTED_CALL_TERMINATOR;
                    }
                    return FlowType::COMPUTED_CALL;
                }
                if flow_type.is_terminal() && (flow_type.is_call() || flow_type.is_jump()) {
                    // Assume original return was preserved.
                    return FlowType::CALL_TERMINATOR;
                }
                if flow_type.is_terminal() {
                    // Assume return was replaced.
                    return FlowType::COMPUTED_CALL;
                }
                FlowType::UNCONDITIONAL_CALL
            }
            FlowOverride::CallReturn => {
                if flow_type.is_conditional() {
                    if flow_type.is_computed() {
                        return FlowType::CONDITIONAL_COMPUTED_CALL;
                    }
                    if flow_type.is_terminal() {
                        // Assume return was replaced.
                        return FlowType::COMPUTED_CALL_TERMINATOR;
                    }
                    return flow_type; // Don't replace.
                }
                if flow_type.is_computed() {
                    return FlowType::COMPUTED_CALL_TERMINATOR;
                }
                if flow_type.is_terminal() {
                    // Assume return was replaced.
                    return FlowType::COMPUTED_CALL_TERMINATOR;
                }
                FlowType::CALL_TERMINATOR
            }
            FlowOverride::Return => {
                if flow_type.is_conditional() {
                    return FlowType::CONDITIONAL_TERMINATOR;
                }
                FlowType::TERMINATOR
            }
            FlowOverride::None => flow_type,
        }
    }
}

impl std::fmt::Display for FlowOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            FlowOverride::None => "NONE",
            FlowOverride::Branch => "BRANCH",
            FlowOverride::Call => "CALL",
            FlowOverride::CallReturn => "CALL_RETURN",
            FlowOverride::Return => "RETURN",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinals_match_java_declaration_order() {
        assert_eq!(FlowOverride::None.ordinal(), 0);
        assert_eq!(FlowOverride::Branch.ordinal(), 1);
        assert_eq!(FlowOverride::Call.ordinal(), 2);
        assert_eq!(FlowOverride::CallReturn.ordinal(), 3);
        assert_eq!(FlowOverride::Return.ordinal(), 4);
    }

    #[test]
    fn get_flow_override_round_trips_known_ordinals() {
        assert_eq!(FlowOverride::get_flow_override(0), FlowOverride::None);
        assert_eq!(FlowOverride::get_flow_override(1), FlowOverride::Branch);
        assert_eq!(FlowOverride::get_flow_override(2), FlowOverride::Call);
        assert_eq!(FlowOverride::get_flow_override(3), FlowOverride::CallReturn);
        assert_eq!(FlowOverride::get_flow_override(4), FlowOverride::Return);
    }

    #[test]
    fn get_flow_override_falls_back_to_none_for_unknown_ordinal() {
        assert_eq!(FlowOverride::get_flow_override(99), FlowOverride::None);
        assert_eq!(FlowOverride::get_flow_override(-1), FlowOverride::None);
    }

    #[test]
    fn no_override_leaves_flow_type_unchanged() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(FlowType::UNCONDITIONAL_CALL, FlowOverride::None),
            FlowType::UNCONDITIONAL_CALL
        );
    }

    #[test]
    fn non_jump_non_terminal_non_call_flow_type_is_unaffected_by_any_override() {
        // FALL_THROUGH is none of isJump/isTerminal/isCall, so every override is a no-op on it.
        assert_eq!(
            FlowOverride::get_modified_flow_type(FlowType::FALL_THROUGH, FlowOverride::Branch),
            FlowType::FALL_THROUGH
        );
        assert_eq!(
            FlowOverride::get_modified_flow_type(FlowType::FALL_THROUGH, FlowOverride::Return),
            FlowType::FALL_THROUGH
        );
    }

    #[test]
    fn branch_override_maps_unconditional_call_to_unconditional_jump() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::UNCONDITIONAL_CALL,
                FlowOverride::Branch
            ),
            FlowType::UNCONDITIONAL_JUMP
        );
    }

    #[test]
    fn branch_override_is_a_no_op_on_an_existing_jump() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::CONDITIONAL_JUMP,
                FlowOverride::Branch
            ),
            FlowType::CONDITIONAL_JUMP
        );
    }

    #[test]
    fn branch_override_on_conditional_terminator_assumes_return_replaced() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::CONDITIONAL_TERMINATOR,
                FlowOverride::Branch
            ),
            FlowType::CONDITIONAL_COMPUTED_JUMP
        );
    }

    #[test]
    fn call_override_maps_unconditional_jump_to_unconditional_call() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::UNCONDITIONAL_JUMP,
                FlowOverride::Call
            ),
            FlowType::UNCONDITIONAL_CALL
        );
    }

    #[test]
    fn call_override_on_call_terminator_preserves_terminator_form() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::CALL_TERMINATOR,
                FlowOverride::Call
            ),
            FlowType::CALL_TERMINATOR
        );
    }

    #[test]
    fn call_return_override_maps_unconditional_jump_to_call_terminator() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::UNCONDITIONAL_JUMP,
                FlowOverride::CallReturn
            ),
            FlowType::CALL_TERMINATOR
        );
    }

    #[test]
    fn call_return_override_leaves_plain_conditional_call_unchanged() {
        // isConditional() true, isComputed() false, isTerminal() false -> "don't replace".
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::CONDITIONAL_CALL,
                FlowOverride::CallReturn
            ),
            FlowType::CONDITIONAL_CALL
        );
    }

    #[test]
    fn return_override_maps_conditional_jump_to_conditional_terminator() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::CONDITIONAL_JUMP,
                FlowOverride::Return
            ),
            FlowType::CONDITIONAL_TERMINATOR
        );
    }

    #[test]
    fn return_override_maps_unconditional_call_to_terminator() {
        assert_eq!(
            FlowOverride::get_modified_flow_type(
                FlowType::UNCONDITIONAL_CALL,
                FlowOverride::Return
            ),
            FlowType::TERMINATOR
        );
    }

    #[test]
    fn display_matches_java_enum_constant_names() {
        assert_eq!(FlowOverride::CallReturn.to_string(), "CALL_RETURN");
        assert_eq!(FlowOverride::None.to_string(), "NONE");
    }
}
