//! Property key names recognized within a language's `.pspec`/`.cspec` `<properties>`
//! section. Ported as a trait (rather than a plain constant holder) because this type
//! was selected as a dependency-cycle cut-point: implementors can override any key to
//! customize behavior while still getting the standard Ghidra key names by default.

/// Mirrors `GhidraLanguagePropertyKeys` from Java. Every method has a default
/// implementation returning the standard Ghidra property key name, so any type can
/// implement this trait with an empty `impl` block to pick up the defaults, or override
/// individual keys.
pub trait GhidraLanguagePropertyKeys {
    /// Key for the maximum instruction length (including delay slots) a language may
    /// produce. Used by `PseudoInstruction` in support of Sleigh `inst_next2`
    /// processing. If not specified a computed estimate is used by each instruction
    /// parse.
    fn maximum_instruction_length(&self) -> &'static str {
        "maximumInstructionLength"
    }

    /// Key for the full class name of a language-specific disassembler implementation.
    /// The specified class must extend the generic `Disassembler` implementation and
    /// must implement the same set of constructors.
    fn custom_disassembler_class(&self) -> &'static str {
        "customDisassemblerClass"
    }

    /// Key for the boolean property indicating whether function bodies can actually
    /// start offcut. Default is false.
    fn allow_offcut_references_to_function_starts(&self) -> &'static str {
        "allowOffcutReferencesToFunctionStarts"
    }

    /// Key for the boolean property indicating whether a language should use the switch
    /// table analysis in the `OperandReferenceAnalyzer`. Default is false.
    fn use_operand_reference_analyzer_switch_tables(&self) -> &'static str {
        "useOperandReferenceAnalyzerSwitchTables"
    }

    /// Key for the boolean property indicating this language is part of the general
    /// TMS320 family. Default is false.
    fn is_tms320_family(&self) -> &'static str {
        "isTMS320Family"
    }

    /// Key for the full class name of a `ParallelInstructionLanguageHelper`
    /// implementation used to facilitate display of a `||` indicator within a listing
    /// view.
    fn parallel_instruction_helper_class(&self) -> &'static str {
        "parallelInstructionHelperClass"
    }

    /// Key for the boolean property indicating whether addresses don't appear directly
    /// in code. Supposedly applies to all RISC processors. Default is false.
    fn addresses_do_not_appear_directly_in_code(&self) -> &'static str {
        "addressesDoNotAppearDirectlyInCode"
    }

    /// Key for the boolean property indicating whether the `StackVariableAnalyzer`
    /// should use a newer function stack analysis command instead of the older one.
    /// Default is false.
    fn use_new_function_stack_analysis(&self) -> &'static str {
        "useNewFunctionStackAnalysis"
    }

    /// Key for the string property naming an `EmulateInstructionStateModifier`
    /// implementation used during emulation to assist with adjusting emulator state
    /// around each instruction. Default is null.
    fn emulate_instruction_state_modifier_class(&self) -> &'static str {
        "emulateInstructionStateModifierClass"
    }

    /// Key for the string property listing IDs for matching one or more p-code userop
    /// library factories, composed to form the library of custom userop implementations
    /// available to an emulator. A comma-separated list of IDs, not a class name.
    fn useroplibs(&self) -> &'static str {
        "useropLibs"
    }

    /// Key for the classname of a `PcodeInjectLibrary` implementation used to generate
    /// p-code injection payloads that can replace CALLs or CALLOTHERs during p-code
    /// analysis.
    fn pcode_inject_library_class(&self) -> &'static str {
        "pcodeInjectLibraryClass"
    }

    /// Key for shared-return analysis: at the end of one function, code jumps to
    /// another and uses the jumped-to subroutine's return. Enabled by default for all
    /// processors.
    fn enable_shared_return_analysis(&self) -> &'static str {
        "enableSharedReturnAnalysis"
    }

    /// Key for the shared-return-analysis option to assume contiguous functions where a
    /// function jumps to another function across the address space of another function.
    fn enable_assume_contiguous_functions_only(&self) -> &'static str {
        "enableContiguousFunctionsOnly"
    }

    /// Key for non-returning function analysis, where a function such as `exit()` is
    /// known not to return.
    fn enable_no_return_analysis(&self) -> &'static str {
        "enableNoReturnAnalysis"
    }

    /// Key for the property indicating that all stored instruction context should be
    /// cleared during a language upgrade operation which requires redisassembly.
    fn reset_context_on_upgrade(&self) -> &'static str {
        "resetContextOnUpgrade"
    }

    /// Key for the minimum recommended base address within the default data space for
    /// placing relocatable data sections, used by the ELF Loader for Harvard
    /// architectures when loading a relocatable ELF binary.
    fn minimum_data_image_base(&self) -> &'static str {
        "minimumDataImageBase"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default implementor: exercises the trait purely through default method bodies.
    struct DefaultKeys;
    impl GhidraLanguagePropertyKeys for DefaultKeys {}

    /// Overriding implementor, proving the trait is object-safe (usable as
    /// `Box<dyn GhidraLanguagePropertyKeys>`) and that individual keys can be
    /// customized without touching the others.
    struct CustomKeys;
    impl GhidraLanguagePropertyKeys for CustomKeys {
        fn maximum_instruction_length(&self) -> &'static str {
            "customMaximumInstructionLength"
        }
    }

    #[test]
    fn default_keys_match_ghidra_property_names() {
        let keys: Box<dyn GhidraLanguagePropertyKeys> = Box::new(DefaultKeys);
        assert_eq!(keys.maximum_instruction_length(), "maximumInstructionLength");
        assert_eq!(keys.custom_disassembler_class(), "customDisassemblerClass");
        assert_eq!(
            keys.allow_offcut_references_to_function_starts(),
            "allowOffcutReferencesToFunctionStarts"
        );
        assert_eq!(
            keys.use_operand_reference_analyzer_switch_tables(),
            "useOperandReferenceAnalyzerSwitchTables"
        );
        assert_eq!(keys.is_tms320_family(), "isTMS320Family");
        assert_eq!(
            keys.parallel_instruction_helper_class(),
            "parallelInstructionHelperClass"
        );
        assert_eq!(
            keys.addresses_do_not_appear_directly_in_code(),
            "addressesDoNotAppearDirectlyInCode"
        );
        assert_eq!(
            keys.use_new_function_stack_analysis(),
            "useNewFunctionStackAnalysis"
        );
        assert_eq!(
            keys.emulate_instruction_state_modifier_class(),
            "emulateInstructionStateModifierClass"
        );
        assert_eq!(keys.useroplibs(), "useropLibs");
        assert_eq!(keys.pcode_inject_library_class(), "pcodeInjectLibraryClass");
        assert_eq!(
            keys.enable_shared_return_analysis(),
            "enableSharedReturnAnalysis"
        );
        assert_eq!(
            keys.enable_assume_contiguous_functions_only(),
            "enableContiguousFunctionsOnly"
        );
        assert_eq!(keys.enable_no_return_analysis(), "enableNoReturnAnalysis");
        assert_eq!(keys.reset_context_on_upgrade(), "resetContextOnUpgrade");
        assert_eq!(keys.minimum_data_image_base(), "minimumDataImageBase");
    }

    #[test]
    fn custom_implementor_can_override_a_single_key_via_trait_object() {
        let keys: Box<dyn GhidraLanguagePropertyKeys> = Box::new(CustomKeys);
        assert_eq!(
            keys.maximum_instruction_length(),
            "customMaximumInstructionLength"
        );
        // Unoverridden keys still fall back to the default implementation.
        assert_eq!(keys.custom_disassembler_class(), "customDisassemblerClass");
    }

    #[test]
    fn all_default_keys_are_distinct() {
        let keys = DefaultKeys;
        let names = [
            keys.maximum_instruction_length(),
            keys.custom_disassembler_class(),
            keys.allow_offcut_references_to_function_starts(),
            keys.use_operand_reference_analyzer_switch_tables(),
            keys.is_tms320_family(),
            keys.parallel_instruction_helper_class(),
            keys.addresses_do_not_appear_directly_in_code(),
            keys.use_new_function_stack_analysis(),
            keys.emulate_instruction_state_modifier_class(),
            keys.useroplibs(),
            keys.pcode_inject_library_class(),
            keys.enable_shared_return_analysis(),
            keys.enable_assume_contiguous_functions_only(),
            keys.enable_no_return_analysis(),
            keys.reset_context_on_upgrade(),
            keys.minimum_data_image_base(),
        ];
        let mut seen = std::collections::HashSet::new();
        for name in &names {
            assert!(seen.insert(*name), "duplicate property key: {name}");
        }
    }
}
