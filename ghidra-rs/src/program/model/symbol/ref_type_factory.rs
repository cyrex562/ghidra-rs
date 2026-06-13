use crate::program::model::symbol::RefType;

/// Reference type factory helpers.
///
/// This ports the static lookup and category lists from Ghidra's
/// `RefTypeFactory`. Instruction and pcode inference routines are intentionally
/// kept out of this model-level module until the corresponding listing and
/// language contracts are available.
pub struct RefTypeFactory;

const MEMORY_REF_TYPES: &[RefType] = &[
    RefType::Indirection,
    RefType::ComputedCall,
    RefType::ComputedJump,
    RefType::ConditionalCall,
    RefType::ConditionalJump,
    RefType::UnconditionalCall,
    RefType::UnconditionalJump,
    RefType::ConditionalComputedCall,
    RefType::ConditionalComputedJump,
    RefType::Param,
    RefType::Data,
    RefType::DataInd,
    RefType::Read,
    RefType::ReadInd,
    RefType::Write,
    RefType::WriteInd,
    RefType::ReadWrite,
    RefType::ReadWriteInd,
    RefType::CallOverrideUnconditional,
    RefType::JumpOverrideUnconditional,
    RefType::CallOtherOverrideCall,
    RefType::CallOtherOverrideJump,
];

const STACK_REF_TYPES: &[RefType] = &[
    RefType::Data,
    RefType::Read,
    RefType::Write,
    RefType::ReadWrite,
];

const DATA_REF_TYPES: &[RefType] = &[
    RefType::Data,
    RefType::Param,
    RefType::Read,
    RefType::Write,
    RefType::ReadWrite,
];

const EXTERNAL_REF_TYPES: &[RefType] = &[
    RefType::ComputedCall,
    RefType::ComputedJump,
    RefType::ConditionalCall,
    RefType::ConditionalJump,
    RefType::UnconditionalCall,
    RefType::UnconditionalJump,
    RefType::ConditionalComputedCall,
    RefType::ConditionalComputedJump,
    RefType::Data,
    RefType::DataInd,
    RefType::Read,
    RefType::ReadInd,
    RefType::Write,
    RefType::WriteInd,
    RefType::ReadWrite,
    RefType::ReadWriteInd,
    RefType::CallOverrideUnconditional,
    RefType::CallOtherOverrideCall,
    RefType::CallOtherOverrideJump,
];

impl RefTypeFactory {
    /// Returns the memory reference types accepted by Ghidra's factory.
    pub fn memory_ref_types() -> &'static [RefType] {
        MEMORY_REF_TYPES
    }

    /// Returns the stack reference types accepted by Ghidra's factory.
    pub fn stack_ref_types() -> &'static [RefType] {
        STACK_REF_TYPES
    }

    /// Returns the data reference types accepted by Ghidra's factory.
    pub fn data_ref_types() -> &'static [RefType] {
        DATA_REF_TYPES
    }

    /// Returns the external reference types accepted by Ghidra's factory.
    pub fn external_ref_types() -> &'static [RefType] {
        EXTERNAL_REF_TYPES
    }

    /// Looks up a static reference type by Java byte value.
    pub fn get(value: i8) -> Result<RefType, String> {
        RefType::from_value(value).ok_or_else(|| format!("RefType not defined: {value}"))
    }

    /// Returns true if the type is valid for memory references.
    pub fn is_valid_memory_ref_type(ref_type: RefType) -> bool {
        MEMORY_REF_TYPES.contains(&ref_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_ref_type_factory_static_map() {
        assert_eq!(RefTypeFactory::get(-2), Ok(RefType::Invalid));
        assert_eq!(RefTypeFactory::get(-1), Ok(RefType::Flow));
        assert_eq!(RefTypeFactory::get(0), Ok(RefType::FallThrough));
        assert_eq!(
            RefTypeFactory::get(16),
            Ok(RefType::CallOverrideUnconditional)
        );
        assert_eq!(RefTypeFactory::get(19), Ok(RefType::CallOtherOverrideJump));
        assert_eq!(RefTypeFactory::get(110), Ok(RefType::Read));
        assert_eq!(RefTypeFactory::get(111), Ok(RefType::Write));
        assert!(RefTypeFactory::get(112)
            .unwrap_err()
            .contains("not defined"));
    }

    #[test]
    fn memory_ref_types_match_java_order() {
        assert_eq!(
            RefTypeFactory::memory_ref_types(),
            &[
                RefType::Indirection,
                RefType::ComputedCall,
                RefType::ComputedJump,
                RefType::ConditionalCall,
                RefType::ConditionalJump,
                RefType::UnconditionalCall,
                RefType::UnconditionalJump,
                RefType::ConditionalComputedCall,
                RefType::ConditionalComputedJump,
                RefType::Param,
                RefType::Data,
                RefType::DataInd,
                RefType::Read,
                RefType::ReadInd,
                RefType::Write,
                RefType::WriteInd,
                RefType::ReadWrite,
                RefType::ReadWriteInd,
                RefType::CallOverrideUnconditional,
                RefType::JumpOverrideUnconditional,
                RefType::CallOtherOverrideCall,
                RefType::CallOtherOverrideJump,
            ]
        );
        assert!(RefTypeFactory::is_valid_memory_ref_type(RefType::Read));
        assert!(!RefTypeFactory::is_valid_memory_ref_type(
            RefType::FallThrough
        ));
    }

    #[test]
    fn stack_data_and_external_ref_type_groups_match_java_order() {
        assert_eq!(
            RefTypeFactory::stack_ref_types(),
            &[
                RefType::Data,
                RefType::Read,
                RefType::Write,
                RefType::ReadWrite
            ]
        );
        assert_eq!(
            RefTypeFactory::data_ref_types(),
            &[
                RefType::Data,
                RefType::Param,
                RefType::Read,
                RefType::Write,
                RefType::ReadWrite
            ]
        );
        assert_eq!(
            RefTypeFactory::external_ref_types().first(),
            Some(&RefType::ComputedCall)
        );
        assert_eq!(
            RefTypeFactory::external_ref_types().last(),
            Some(&RefType::CallOtherOverrideJump)
        );
        assert!(!RefTypeFactory::external_ref_types().contains(&RefType::Param));
        assert!(!RefTypeFactory::external_ref_types().contains(&RefType::JumpOverrideUnconditional));
    }
}
