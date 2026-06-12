/// Reference type used to describe the relationship between a source and destination.
///
/// This mirrors Ghidra's `RefType`, `DataRefType`, and `FlowType` constants and query
/// methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    Invalid,
    Flow,
    FallThrough,
    UnconditionalJump,
    ConditionalJump,
    UnconditionalCall,
    ConditionalCall,
    Terminator,
    ComputedJump,
    ConditionalTerminator,
    ComputedCall,
    Indirection,
    CallTerminator,
    JumpTerminator,
    ConditionalComputedJump,
    ConditionalComputedCall,
    ConditionalCallTerminator,
    ComputedCallTerminator,
    CallOverrideUnconditional,
    JumpOverrideUnconditional,
    CallOtherOverrideCall,
    CallOtherOverrideJump,
    Thunk,
    Data,
    Param,
    DataInd,
    Read,
    Write,
    ReadWrite,
    ReadInd,
    WriteInd,
    ReadWriteInd,
    ExternalRef,
}

#[derive(Debug, Clone, Copy)]
struct RefTypeInfo {
    value: i8,
    name: &'static str,
    kind: RefTypeKind,
    read: bool,
    write: bool,
    indirect: bool,
    has_fallthrough: bool,
    call: bool,
    jump: bool,
    terminal: bool,
    conditional: bool,
    computed: bool,
    override_ref: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefTypeKind {
    Data,
    Flow,
}

impl RefType {
    /// Operand index corresponding to an instruction/data mnemonic.
    pub const MNEMONIC: i32 = -1;
    /// Operand index used when not applicable.
    pub const OTHER: i32 = -2;

    /// Returns the Java persistent byte value for this reference type.
    pub fn value(self) -> i8 {
        self.info().value
    }

    /// Returns the Java reference type name.
    pub fn name(self) -> &'static str {
        self.info().name
    }

    /// Returns a display string matching Ghidra's `getDisplayString`.
    pub fn display_string(self) -> &'static str {
        if self == Self::Thunk {
            return "Thunk";
        }
        if self == Self::FallThrough {
            return "FallThrough";
        }
        if self.is_read() && self.is_write() {
            return "RW";
        }
        if self.is_read() {
            return "Read";
        }
        if self.is_write() {
            return "Write";
        }
        if self.is_data() {
            return "Data";
        }
        if self.is_call() {
            return "Call";
        }
        if self.is_jump() {
            return if self.is_conditional() {
                "Branch"
            } else {
                "Jump"
            };
        }
        "Unknown"
    }

    /// Returns a public reference type for its Java byte value.
    pub fn from_value(value: i8) -> Option<Self> {
        ALL_REF_TYPES
            .iter()
            .copied()
            .find(|ref_type| ref_type.value() == value)
            .or_else(|| match value {
                110 => Some(Self::Read),
                111 => Some(Self::Write),
                _ => None,
            })
    }

    pub fn is_data(self) -> bool {
        self.info().kind == RefTypeKind::Data
    }

    pub fn is_read(self) -> bool {
        self.info().read
    }

    pub fn is_write(self) -> bool {
        self.info().write
    }

    pub fn is_flow(self) -> bool {
        self.info().kind == RefTypeKind::Flow
    }

    pub fn is_indirect(self) -> bool {
        self.info().indirect || self == Self::Indirection
    }

    pub fn is_fallthrough(self) -> bool {
        self == Self::FallThrough
    }

    pub fn has_fallthrough(self) -> bool {
        self.info().has_fallthrough
    }

    pub fn is_call(self) -> bool {
        self.info().call
    }

    pub fn is_jump(self) -> bool {
        self.info().jump
    }

    pub fn is_unconditional(self) -> bool {
        !self.is_conditional()
    }

    pub fn is_conditional(self) -> bool {
        self.info().conditional
    }

    pub fn is_computed(self) -> bool {
        self.info().computed
    }

    pub fn is_terminal(self) -> bool {
        self.info().terminal
    }

    pub fn is_override(self) -> bool {
        self.info().override_ref
    }

    fn info(self) -> RefTypeInfo {
        use RefType::*;
        match self {
            Invalid => flow(-2, "INVALID").fall(),
            Flow => flow(-1, "FLOW").fall(),
            FallThrough => flow(0, "FALL_THROUGH").fall(),
            UnconditionalJump => flow(1, "UNCONDITIONAL_JUMP").jump(),
            ConditionalJump => flow(2, "CONDITIONAL_JUMP").fall().jump().conditional(),
            UnconditionalCall => flow(3, "UNCONDITIONAL_CALL").fall().call(),
            ConditionalCall => flow(4, "CONDITIONAL_CALL").fall().call().conditional(),
            Terminator => flow(5, "TERMINATOR").terminal(),
            ComputedJump => flow(6, "COMPUTED_JUMP").jump().computed(),
            ConditionalTerminator => flow(7, "CONDITIONAL_TERMINATOR")
                .fall()
                .terminal()
                .conditional(),
            ComputedCall => flow(8, "COMPUTED_CALL").fall().call().computed(),
            Indirection => flow(9, "INDIRECTION"),
            CallTerminator => flow(10, "CALL_TERMINATOR").call().terminal(),
            JumpTerminator => flow(11, "JUMP_TERMINATOR").jump().terminal(),
            ConditionalComputedJump => flow(12, "CONDITIONAL_COMPUTED_JUMP")
                .fall()
                .jump()
                .computed()
                .conditional(),
            ConditionalComputedCall => flow(13, "CONDITIONAL_COMPUTED_CALL")
                .fall()
                .call()
                .computed()
                .conditional(),
            ConditionalCallTerminator => flow(14, "CONDITIONAL_CALL_TERMINATOR")
                .call()
                .terminal()
                .conditional(),
            ComputedCallTerminator => flow(15, "COMPUTED_CALL_TERMINATOR")
                .call()
                .terminal()
                .computed(),
            CallOverrideUnconditional => flow(16, "CALL_OVERRIDE_UNCONDITIONAL")
                .fall()
                .call()
                .override_ref(),
            JumpOverrideUnconditional => flow(17, "JUMP_OVERRIDE_UNCONDITIONAL")
                .jump()
                .override_ref(),
            CallOtherOverrideCall => flow(18, "CALLOTHER_OVERRIDE_CALL")
                .fall()
                .call()
                .override_ref(),
            CallOtherOverrideJump => flow(19, "CALLOTHER_OVERRIDE_JUMP").jump().override_ref(),
            Thunk => data(127, "THUNK"),
            Data => data(100, "DATA"),
            Param => data(107, "PARAM"),
            DataInd => data(114, "DATA_IND").indirect(),
            Read => data(101, "READ").read(),
            Write => data(102, "WRITE").write(),
            ReadWrite => data(103, "READ_WRITE").read().write(),
            ReadInd => data(104, "READ_IND").read().indirect(),
            WriteInd => data(105, "WRITE_IND").write().indirect(),
            ReadWriteInd => data(106, "READ_WRITE_IND").read().write().indirect(),
            ExternalRef => data(113, "EXTERNAL"),
        }
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

const ALL_REF_TYPES: &[RefType] = &[
    RefType::Invalid,
    RefType::Flow,
    RefType::FallThrough,
    RefType::UnconditionalJump,
    RefType::ConditionalJump,
    RefType::UnconditionalCall,
    RefType::ConditionalCall,
    RefType::Terminator,
    RefType::ComputedJump,
    RefType::ConditionalTerminator,
    RefType::ComputedCall,
    RefType::Indirection,
    RefType::CallTerminator,
    RefType::JumpTerminator,
    RefType::ConditionalComputedJump,
    RefType::ConditionalComputedCall,
    RefType::ConditionalCallTerminator,
    RefType::ComputedCallTerminator,
    RefType::CallOverrideUnconditional,
    RefType::JumpOverrideUnconditional,
    RefType::CallOtherOverrideCall,
    RefType::CallOtherOverrideJump,
    RefType::Thunk,
    RefType::Data,
    RefType::Param,
    RefType::DataInd,
    RefType::Read,
    RefType::Write,
    RefType::ReadWrite,
    RefType::ReadInd,
    RefType::WriteInd,
    RefType::ReadWriteInd,
    RefType::ExternalRef,
];

const fn data(value: i8, name: &'static str) -> RefTypeInfo {
    RefTypeInfo::new(value, name, RefTypeKind::Data)
}

const fn flow(value: i8, name: &'static str) -> RefTypeInfo {
    RefTypeInfo::new(value, name, RefTypeKind::Flow)
}

impl RefTypeInfo {
    const fn new(value: i8, name: &'static str, kind: RefTypeKind) -> Self {
        Self {
            value,
            name,
            kind,
            read: false,
            write: false,
            indirect: false,
            has_fallthrough: false,
            call: false,
            jump: false,
            terminal: false,
            conditional: false,
            computed: false,
            override_ref: false,
        }
    }

    const fn read(mut self) -> Self {
        self.read = true;
        self
    }

    const fn write(mut self) -> Self {
        self.write = true;
        self
    }

    const fn indirect(mut self) -> Self {
        self.indirect = true;
        self
    }

    const fn fall(mut self) -> Self {
        self.has_fallthrough = true;
        self
    }

    const fn call(mut self) -> Self {
        self.call = true;
        self
    }

    const fn jump(mut self) -> Self {
        self.jump = true;
        self
    }

    const fn terminal(mut self) -> Self {
        self.terminal = true;
        self
    }

    const fn conditional(mut self) -> Self {
        self.conditional = true;
        self
    }

    const fn computed(mut self) -> Self {
        self.computed = true;
        self
    }

    const fn override_ref(mut self) -> Self {
        self.override_ref = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_and_names_match_java_constants() {
        assert_eq!(RefType::Invalid.value(), -2);
        assert_eq!(RefType::Flow.value(), -1);
        assert_eq!(RefType::FallThrough.value(), 0);
        assert_eq!(RefType::UnconditionalJump.value(), 1);
        assert_eq!(RefType::ConditionalJump.value(), 2);
        assert_eq!(RefType::UnconditionalCall.value(), 3);
        assert_eq!(RefType::Read.value(), 101);
        assert_eq!(RefType::Write.value(), 102);
        assert_eq!(RefType::ExternalRef.value(), 113);
        assert_eq!(RefType::Thunk.value(), 127);
        assert_eq!(
            RefType::ConditionalComputedCall.name(),
            "CONDITIONAL_COMPUTED_CALL"
        );
        assert_eq!(RefType::ReadWriteInd.to_string(), "READ_WRITE_IND");
    }

    #[test]
    fn lookup_by_value_matches_public_and_upgrade_values() {
        assert_eq!(RefType::from_value(-2), Some(RefType::Invalid));
        assert_eq!(RefType::from_value(0), Some(RefType::FallThrough));
        assert_eq!(RefType::from_value(101), Some(RefType::Read));
        assert_eq!(RefType::from_value(110), Some(RefType::Read));
        assert_eq!(RefType::from_value(111), Some(RefType::Write));
        assert_eq!(RefType::from_value(112), None);
    }

    #[test]
    fn data_reference_flags_match_java() {
        assert!(RefType::Read.is_data());
        assert!(RefType::Read.is_read());
        assert!(!RefType::Read.is_write());
        assert!(RefType::Write.is_write());
        assert!(RefType::ReadWrite.is_read());
        assert!(RefType::ReadWrite.is_write());
        assert!(RefType::ReadInd.is_indirect());
        assert!(RefType::DataInd.is_indirect());
        assert!(RefType::Thunk.is_data());
    }

    #[test]
    fn flow_reference_flags_match_java() {
        assert!(RefType::ConditionalJump.is_flow());
        assert!(RefType::ConditionalJump.has_fallthrough());
        assert!(RefType::ConditionalJump.is_jump());
        assert!(RefType::ConditionalJump.is_conditional());
        assert!(RefType::UnconditionalCall.is_call());
        assert!(RefType::UnconditionalCall.is_unconditional());
        assert!(RefType::ComputedCall.is_computed());
        assert!(RefType::Terminator.is_terminal());
        assert!(RefType::CallOverrideUnconditional.is_override());
        assert!(RefType::Indirection.is_indirect());
    }

    #[test]
    fn display_strings_match_java() {
        assert_eq!(RefType::Thunk.display_string(), "Thunk");
        assert_eq!(RefType::FallThrough.display_string(), "FallThrough");
        assert_eq!(RefType::ReadWrite.display_string(), "RW");
        assert_eq!(RefType::Read.display_string(), "Read");
        assert_eq!(RefType::Write.display_string(), "Write");
        assert_eq!(RefType::Data.display_string(), "Data");
        assert_eq!(RefType::UnconditionalCall.display_string(), "Call");
        assert_eq!(RefType::UnconditionalJump.display_string(), "Jump");
        assert_eq!(RefType::ConditionalJump.display_string(), "Branch");
        assert_eq!(RefType::Flow.display_string(), "Unknown");
    }
}
