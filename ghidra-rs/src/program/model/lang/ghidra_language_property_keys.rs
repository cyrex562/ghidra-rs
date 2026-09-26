//! Property key names recognized within a language's `.pspec`/`.cspec` `<properties>`
//! section.
//!
//! Port of `ghidra.program.model.lang.GhidraLanguagePropertyKeys`. The Java type is an
//! interface holding only `String` constants, so (per shape rule R7, as with other
//! constants-only Java types in this crate) it is ported as a plain module of `pub const`
//! items with no type of that name.

/// Maximum instruction length (including delay slots) a language may produce. Used by
/// `PseudoInstruction` in support of Sleigh `inst_next2` processing. If not specified a
/// computed estimate is used by each instruction parse.
pub const MAXIMUM_INSTRUCTION_LENGTH: &str = "maximumInstructionLength";

/// Full class name of a language-specific disassembler implementation. The specified class
/// must extend the generic `Disassembler` implementation and must implement the same set of
/// constructors.
pub const CUSTOM_DISASSEMBLER_CLASS: &str = "customDisassemblerClass";

/// Boolean property indicating whether function bodies can actually start offcut. Default is
/// false.
pub const ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS: &str =
    "allowOffcutReferencesToFunctionStarts";

/// Boolean property indicating whether a language should use the switch table analysis in the
/// `OperandReferenceAnalyzer`. Default is false.
pub const USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES: &str =
    "useOperandReferenceAnalyzerSwitchTables";

/// Boolean property indicating this language is part of the general TMS320 family. Default is
/// false. Used for general TMS320 analysis.
pub const IS_TMS320_FAMILY: &str = "isTMS320Family";

/// Full class name of a `ParallelInstructionLanguageHelper` implementation used to facilitate
/// display of a `||` indicator within a listing view.
pub const PARALLEL_INSTRUCTION_HELPER_CLASS: &str = "parallelInstructionHelperClass";

/// Boolean property indicating whether addresses don't appear directly in code. Supposedly
/// applies to all RISC processors. Default is false.
pub const ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE: &str = "addressesDoNotAppearDirectlyInCode";

/// Boolean property indicating whether the `StackVariableAnalyzer` should use a newer function
/// stack analysis command instead of the older one. Default is false.
pub const USE_NEW_FUNCTION_STACK_ANALYSIS: &str = "useNewFunctionStackAnalysis";

/// String property naming an `EmulateInstructionStateModifier` implementation used during
/// emulation to assist with adjusting emulator state around each instruction. Default is null.
pub const EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS: &str = "emulateInstructionStateModifierClass";

/// String property listing IDs for matching one or more p-code userop library factories,
/// composed to form the library of custom userop implementations available to an emulator. A
/// comma-separated list of IDs, not a class name.
pub const USEROP_LIBS: &str = "useropLibs";

/// Class name of a `PcodeInjectLibrary` implementation used to generate p-code injection
/// payloads that can replace CALLs or CALLOTHERs during p-code analysis.
pub const PCODE_INJECT_LIBRARY_CLASS: &str = "pcodeInjectLibraryClass";

/// Shared-return analysis: at the end of one function, code jumps to another and uses the
/// jumped-to subroutine's return. Enabled by default for all processors.
pub const ENABLE_SHARED_RETURN_ANALYSIS: &str = "enableSharedReturnAnalysis";

/// Shared-return-analysis option to assume contiguous functions where a function jumps to
/// another function across the address space of another function.
pub const ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY: &str = "enableContiguousFunctionsOnly";

/// Non-returning function analysis, where a function such as `exit()` is known not to return.
pub const ENABLE_NO_RETURN_ANALYSIS: &str = "enableNoReturnAnalysis";

/// Property indicating that all stored instruction context should be cleared during a
/// language upgrade operation which requires redisassembly.
pub const RESET_CONTEXT_ON_UPGRADE: &str = "resetContextOnUpgrade";

/// Minimum recommended base address within the default data space for placing relocatable
/// data sections, used by the ELF Loader for Harvard architectures when loading a relocatable
/// ELF binary.
pub const MINIMUM_DATA_IMAGE_BASE: &str = "minimumDataImageBase";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_match_java_property_names() {
        assert_eq!(MAXIMUM_INSTRUCTION_LENGTH, "maximumInstructionLength");
        assert_eq!(CUSTOM_DISASSEMBLER_CLASS, "customDisassemblerClass");
        assert_eq!(
            ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS,
            "allowOffcutReferencesToFunctionStarts"
        );
        assert_eq!(
            USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES,
            "useOperandReferenceAnalyzerSwitchTables"
        );
        assert_eq!(IS_TMS320_FAMILY, "isTMS320Family");
        assert_eq!(PARALLEL_INSTRUCTION_HELPER_CLASS, "parallelInstructionHelperClass");
        assert_eq!(
            ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE,
            "addressesDoNotAppearDirectlyInCode"
        );
        assert_eq!(USE_NEW_FUNCTION_STACK_ANALYSIS, "useNewFunctionStackAnalysis");
        assert_eq!(
            EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS,
            "emulateInstructionStateModifierClass"
        );
        assert_eq!(USEROP_LIBS, "useropLibs");
        assert_eq!(PCODE_INJECT_LIBRARY_CLASS, "pcodeInjectLibraryClass");
        assert_eq!(ENABLE_SHARED_RETURN_ANALYSIS, "enableSharedReturnAnalysis");
        // Java's constant name and value differ here; the value is what .pspec files use.
        assert_eq!(ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY, "enableContiguousFunctionsOnly");
        assert_eq!(ENABLE_NO_RETURN_ANALYSIS, "enableNoReturnAnalysis");
        assert_eq!(RESET_CONTEXT_ON_UPGRADE, "resetContextOnUpgrade");
        assert_eq!(MINIMUM_DATA_IMAGE_BASE, "minimumDataImageBase");
    }

    #[test]
    fn all_keys_are_distinct() {
        let names = [
            MAXIMUM_INSTRUCTION_LENGTH,
            CUSTOM_DISASSEMBLER_CLASS,
            ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS,
            USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES,
            IS_TMS320_FAMILY,
            PARALLEL_INSTRUCTION_HELPER_CLASS,
            ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE,
            USE_NEW_FUNCTION_STACK_ANALYSIS,
            EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS,
            USEROP_LIBS,
            PCODE_INJECT_LIBRARY_CLASS,
            ENABLE_SHARED_RETURN_ANALYSIS,
            ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY,
            ENABLE_NO_RETURN_ANALYSIS,
            RESET_CONTEXT_ON_UPGRADE,
            MINIMUM_DATA_IMAGE_BASE,
        ];
        let mut seen = std::collections::HashSet::new();
        for name in names {
            assert!(seen.insert(name), "duplicate property key: {name}");
        }
    }
}
