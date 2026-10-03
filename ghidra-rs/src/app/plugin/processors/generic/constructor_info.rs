//! Port of `ghidra.app.plugin.processors.generic.ConstructorInfo`.

use crate::program::model::symbol::FlowType;

/// Structure for collecting cached information about an instruction.
///
/// Port of `ghidra.app.plugin.processors.generic.ConstructorInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructorInfo {
    /// Length of the constructor.
    length: i32,
    /// Flags indicating the type of branching within this constructor.
    flow_flags: i32,
}

impl ConstructorInfo {
    /// Flow flag: the constructor returns.
    pub const RETURN: i32 = 1;
    /// Flow flag: the constructor calls indirectly.
    pub const CALL_INDIRECT: i32 = 2;
    /// Flow flag: the constructor branches indirectly.
    pub const BRANCH_INDIRECT: i32 = 4;
    /// Flow flag: the constructor calls.
    pub const CALL: i32 = 8;
    /// Flow flag: the constructor jumps out.
    pub const JUMPOUT: i32 = 16;
    /// Flow flag: flow cannot come out the bottom of the constructor.
    pub const NO_FALLTHRU: i32 = 32;
    /// Flow flag: the constructor branches to its own end.
    pub const BRANCH_TO_END: i32 = 64;

    /// Java: `ConstructorInfo(int ln, int fl)`.
    pub fn new(ln: i32, fl: i32) -> Self {
        ConstructorInfo { length: ln, flow_flags: fl }
    }

    /// Java: `getFlowFlags()`.
    pub fn get_flow_flags(&self) -> i32 {
        self.flow_flags
    }

    /// Java: `getLength()`.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Java: `addLength(int l)`.
    pub fn add_length(&mut self, l: i32) {
        self.length += l;
    }

    /// Convert flags to a standard flow type.
    ///
    /// Java: package-private `getFlowType()`. Kept `pub` since Rust has no package-private
    /// visibility tier narrower than the crate (matching the convention already used by e.g.
    /// [`crate::app::plugin::core::function::editor::FunctionVariableData`]).
    pub fn get_flow_type(&self) -> FlowType {
        match self.flow_flags {
            0 | Self::BRANCH_TO_END => FlowType::FALL_THROUGH,
            Self::CALL => FlowType::UNCONDITIONAL_CALL,
            // This could be wrong but doesn't matter much
            f if f == Self::CALL | Self::BRANCH_TO_END => FlowType::CONDITIONAL_CALL,
            Self::CALL_INDIRECT => FlowType::COMPUTED_CALL,
            // This could be COMPUTED_CONDITIONAL?
            f if f == Self::CALL_INDIRECT | Self::BRANCH_TO_END => FlowType::COMPUTED_CALL,
            f if f == Self::BRANCH_INDIRECT | Self::NO_FALLTHRU => FlowType::COMPUTED_JUMP,
            // This should be COMPUTED_CONDITONAL_JUMP but this doesn't exist so we make it a
            // fall thru so the disassembler can continue the flow
            f if f == Self::BRANCH_INDIRECT | Self::NO_FALLTHRU | Self::BRANCH_TO_END => {
                FlowType::FALL_THROUGH
            }
            f if f == Self::RETURN | Self::NO_FALLTHRU => FlowType::TERMINATOR,
            f if f == Self::RETURN | Self::NO_FALLTHRU | Self::BRANCH_TO_END => {
                FlowType::CONDITIONAL_TERMINATOR
            }
            Self::JUMPOUT => FlowType::CONDITIONAL_JUMP,
            f if f == Self::JUMPOUT | Self::NO_FALLTHRU => FlowType::UNCONDITIONAL_JUMP,
            f if f == Self::JUMPOUT | Self::NO_FALLTHRU | Self::BRANCH_TO_END => {
                FlowType::CONDITIONAL_JUMP
            }
            Self::NO_FALLTHRU => FlowType::TERMINATOR,
            f if f == Self::BRANCH_TO_END | Self::JUMPOUT => FlowType::CONDITIONAL_JUMP,
            f if f == Self::NO_FALLTHRU | Self::BRANCH_TO_END => FlowType::FALL_THROUGH,
            _ => FlowType::INVALID,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_stores_length_and_flags() {
        let info = ConstructorInfo::new(4, ConstructorInfo::CALL);
        assert_eq!(info.get_length(), 4);
        assert_eq!(info.get_flow_flags(), ConstructorInfo::CALL);
    }

    #[test]
    fn add_length_accumulates() {
        let mut info = ConstructorInfo::new(4, 0);
        info.add_length(2);
        info.add_length(3);
        assert_eq!(info.get_length(), 9);
    }

    #[test]
    fn flow_type_zero_and_branch_to_end_are_fall_through() {
        assert_eq!(ConstructorInfo::new(0, 0).get_flow_type(), FlowType::FALL_THROUGH);
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::BRANCH_TO_END).get_flow_type(),
            FlowType::FALL_THROUGH
        );
    }

    #[test]
    fn flow_type_call_variants() {
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::CALL).get_flow_type(),
            FlowType::UNCONDITIONAL_CALL
        );
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::CALL | ConstructorInfo::BRANCH_TO_END)
                .get_flow_type(),
            FlowType::CONDITIONAL_CALL
        );
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::CALL_INDIRECT).get_flow_type(),
            FlowType::COMPUTED_CALL
        );
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::CALL_INDIRECT | ConstructorInfo::BRANCH_TO_END
            )
            .get_flow_type(),
            FlowType::COMPUTED_CALL
        );
    }

    #[test]
    fn flow_type_branch_indirect_variants() {
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::BRANCH_INDIRECT | ConstructorInfo::NO_FALLTHRU
            )
            .get_flow_type(),
            FlowType::COMPUTED_JUMP
        );
        // Java quirk: COMPUTED_CONDITIONAL_JUMP doesn't exist, so this case falls back to
        // FALL_THROUGH so the disassembler can continue the flow. Preserved faithfully.
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::BRANCH_INDIRECT
                    | ConstructorInfo::NO_FALLTHRU
                    | ConstructorInfo::BRANCH_TO_END
            )
            .get_flow_type(),
            FlowType::FALL_THROUGH
        );
    }

    #[test]
    fn flow_type_return_variants() {
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::RETURN | ConstructorInfo::NO_FALLTHRU)
                .get_flow_type(),
            FlowType::TERMINATOR
        );
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::RETURN
                    | ConstructorInfo::NO_FALLTHRU
                    | ConstructorInfo::BRANCH_TO_END
            )
            .get_flow_type(),
            FlowType::CONDITIONAL_TERMINATOR
        );
    }

    #[test]
    fn flow_type_jumpout_variants() {
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::JUMPOUT).get_flow_type(),
            FlowType::CONDITIONAL_JUMP
        );
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::JUMPOUT | ConstructorInfo::NO_FALLTHRU)
                .get_flow_type(),
            FlowType::UNCONDITIONAL_JUMP
        );
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::JUMPOUT
                    | ConstructorInfo::NO_FALLTHRU
                    | ConstructorInfo::BRANCH_TO_END
            )
            .get_flow_type(),
            FlowType::CONDITIONAL_JUMP
        );
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::BRANCH_TO_END | ConstructorInfo::JUMPOUT
            )
            .get_flow_type(),
            FlowType::CONDITIONAL_JUMP
        );
    }

    #[test]
    fn flow_type_no_fallthru_variants() {
        assert_eq!(
            ConstructorInfo::new(0, ConstructorInfo::NO_FALLTHRU).get_flow_type(),
            FlowType::TERMINATOR
        );
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::NO_FALLTHRU | ConstructorInfo::BRANCH_TO_END
            )
            .get_flow_type(),
            FlowType::FALL_THROUGH
        );
    }

    #[test]
    fn flow_type_unrecognized_combo_is_invalid() {
        assert_eq!(
            ConstructorInfo::new(
                0,
                ConstructorInfo::CALL | ConstructorInfo::JUMPOUT | ConstructorInfo::RETURN
            )
            .get_flow_type(),
            FlowType::INVALID
        );
    }
}
