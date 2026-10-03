//! Compile2-flavor PDB symbol.
//!
//! Corresponds to the Java abstract class
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractCompile2MsSymbol`.
//!
//! Note: we do not necessarily understand each of these symbol type classes. Refer to the
//! base class for more information.
//!
//! Ported as a trait (rather than a struct extending a concrete `AbstractMsSymbol` parsing
//! pipeline) because this type was selected as a dependency-cycle cut-point: callers such as
//! `Compile2MsSymbol` and `Compile2StMsSymbol` (not yet ported) can depend on
//! `dyn AbstractCompile2MsSymbol` instead of a concrete class, so their crates don't need to see
//! `AbstractMsSymbol`/`AbstractPdb`/`PdbByteReader`'s full parsing machinery.

use crate::format::pdb2::pdbreader::processor::Processor;
use crate::format::pdb2::pdbreader::symbol::language_name::LanguageName;

/// The various flavors of Compile 2 symbol.
pub trait AbstractCompile2MsSymbol {
    /// Returns the packed flags.
    fn flags(&self) -> u32;

    /// Returns the language used.
    fn language(&self) -> &dyn LanguageName;

    /// Tells whether the target was compiled for "Edit and Continue."
    fn is_compiled_for_edit_and_continue(&self) -> bool;

    /// Tells whether the target was not compiled with debug information.
    fn is_not_compiled_with_debug_info(&self) -> bool;

    /// Tells whether the target was compiled with link-time code generation.
    fn is_compiled_with_link_time_code_generation(&self) -> bool;

    /// Tells whether the target was compiled with Bzalign.
    fn is_compiled_with_bzalign_no_data_align(&self) -> bool;

    /// Tells whether the target has managed code and/or data present.
    fn is_managed_code_data_present(&self) -> bool;

    /// Tells whether the target was compiled with /GS buffer security checks.
    fn is_compiled_with_gs_buffer_security_checks(&self) -> bool;

    /// Tells whether the target was compiled with /hotpatch.
    fn is_compiled_with_hot_patch(&self) -> bool;

    /// Tells whether the target was converted with CVTCIL.
    fn is_converted_with_cvtcil(&self) -> bool;

    /// Tells whether the target is a Microsoft Intermediate Language netmodule.
    fn is_microsoft_intermediate_language_net_module(&self) -> bool;

    /// Returns the processor.
    fn processor(&self) -> Processor;

    /// Returns the front end major version number.
    fn front_end_major_version_number(&self) -> i32;

    /// Returns the front end minor version number.
    fn front_end_minor_version_number(&self) -> i32;

    /// Returns the front end build version number.
    fn front_end_build_version_number(&self) -> i32;

    /// Returns the back end major version number.
    fn back_end_major_version_number(&self) -> i32;

    /// Returns the back end minor version number.
    fn back_end_minor_version_number(&self) -> i32;

    /// Returns the back end build version number.
    fn back_end_build_version_number(&self) -> i32;

    /// Returns the compiler version string.
    fn compiler_version_string(&self) -> &str;

    /// Returns the additional strings trailing the compiler version string.
    fn string_list(&self) -> &[String];

    /// Returns the string representation of the symbol type name, per API.
    ///
    /// Corresponds to the (protected, abstract) `AbstractMsSymbol.getSymbolTypeName()` that a
    /// concrete leaf symbol type (e.g. `Compile2MsSymbol`) implements and that this class's
    /// `emit` relies on.
    fn symbol_type_name(&self) -> String;

    /// Emits string output of this class into `builder`, matching the Java override of
    /// `AbstractMsSymbol.emit(StringBuilder)`.
    fn emit(&self, builder: &mut String) {
        builder.push_str(&self.symbol_type_name());
        builder.push_str(":\n   Language: ");
        builder.push_str(self.language().label());
        builder.push_str("\n   Target Processor: ");
        builder.push_str(&self.processor().to_string());

        builder.push_str("\n   Compiled for edit and continue: ");
        builder.push_str(if self.is_compiled_for_edit_and_continue() { "yes" } else { "no" });
        builder.push_str("\n   Compiled without debugging info: ");
        builder.push_str(if self.is_not_compiled_with_debug_info() { "yes" } else { "no" });
        builder.push_str("\n   Compiled with LTCG: ");
        builder.push_str(if self.is_compiled_with_link_time_code_generation() { "yes" } else { "no" });
        builder.push_str("\n   Compiled with /bzalign: ");
        builder.push_str(if self.is_compiled_with_bzalign_no_data_align() { "yes" } else { "no" });
        builder.push_str("\n   Managed code present: ");
        builder.push_str(if self.is_managed_code_data_present() { "yes" } else { "no" });
        builder.push_str("\n   Compiled with /GS: ");
        builder.push_str(if self.is_compiled_with_gs_buffer_security_checks() { "yes" } else { "no" });
        builder.push_str("\n   Compiled with /hotpatch: ");
        builder.push_str(if self.is_compiled_with_hot_patch() { "yes" } else { "no" });
        builder.push_str("\n   Converted by CVTCIL: ");
        builder.push_str(if self.is_converted_with_cvtcil() { "yes" } else { "no" });
        builder.push_str("\n   Microsoft Intermediate Language Module: ");
        builder.push_str(if self.is_microsoft_intermediate_language_net_module() { "yes" } else { "no" });

        builder.push_str(&format!(
            "\n   Frontend Version: Major = {}, Minor = {}, Build = {}",
            self.front_end_major_version_number(),
            self.front_end_minor_version_number(),
            self.front_end_build_version_number()
        ));
        builder.push_str(&format!(
            "\n   Backend Version: Major = {}, Minor = {}, Build = {}",
            self.back_end_major_version_number(),
            self.back_end_minor_version_number(),
            self.back_end_build_version_number()
        ));
        builder.push_str("\n   Version String:");
        builder.push_str(self.compiler_version_string());

        let string_list = self.string_list();
        if (string_list.len() & 0x0001) == 0x0001 {
            // Some sort of problem that we are not dealing with.
            return;
        }
        builder.push_str("\nCommand block: \n");
        let mut i = 0;
        while i < string_list.len() {
            builder.push_str(&format!("   {} = '{}'\n", string_list[i], string_list[i + 1]));
            i += 2;
        }
    }
}

/// The fields decoded from the packed `flags` value.
///
/// Corresponds to the fields that Java's `AbstractCompile2MsSymbol.processFlags(long)`
/// populates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedCompileFlags {
    pub language_value: i32,
    pub compiled_for_edit_and_continue: bool,
    pub not_compiled_with_debug_info: bool,
    pub compiled_with_link_time_code_generation: bool,
    pub compiled_with_bzalign_no_data_align: bool,
    pub managed_code_data_present: bool,
    pub compiled_with_gs_buffer_security_checks: bool,
    pub compiled_with_hot_patch: bool,
    pub converted_with_cvtcil: bool,
    pub microsoft_intermediate_language_net_module: bool,
}

/// Breaks out the flag values from the aggregate integral type, matching Java's
/// `AbstractCompile2MsSymbol.processFlags(long)`.
pub fn decode_flags(flags: u32) -> DecodedCompileFlags {
    let mut remaining = flags;

    let language_value = (remaining & 0xff) as i32;
    remaining >>= 8;

    let compiled_for_edit_and_continue = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let not_compiled_with_debug_info = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let compiled_with_link_time_code_generation = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let compiled_with_bzalign_no_data_align = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let managed_code_data_present = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let compiled_with_gs_buffer_security_checks = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let compiled_with_hot_patch = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let converted_with_cvtcil = (remaining & 0x0001) == 0x0001;
    remaining >>= 1;
    let microsoft_intermediate_language_net_module = (remaining & 0x0001) == 0x0001;

    DecodedCompileFlags {
        language_value,
        compiled_for_edit_and_continue,
        not_compiled_with_debug_info,
        compiled_with_link_time_code_generation,
        compiled_with_bzalign_no_data_align,
        managed_code_data_present,
        compiled_with_gs_buffer_security_checks,
        compiled_with_hot_patch,
        converted_with_cvtcil,
        microsoft_intermediate_language_net_module,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::symbol::language_name::StandardLanguageName;

    /// Mock impl proving the trait is object-safe and usable by a caller that only knows about
    /// `dyn AbstractCompile2MsSymbol`, matching how a cycle-breaking cut-point trait is
    /// consumed. Populated from [`decode_flags`], exercising the real bit-unpacking logic rather
    /// than hand-setting each field.
    struct MockCompile2Symbol {
        flags: u32,
        decoded: DecodedCompileFlags,
        language: StandardLanguageName,
        processor: Processor,
        front_end: (i32, i32, i32),
        back_end: (i32, i32, i32),
        compiler_version_string: String,
        string_list: Vec<String>,
    }

    impl MockCompile2Symbol {
        fn new(flags: u32, processor: Processor, string_list: Vec<String>) -> Self {
            let decoded = decode_flags(flags);
            let language = StandardLanguageName::from_value(decoded.language_value);
            MockCompile2Symbol {
                flags,
                decoded,
                language,
                processor,
                front_end: (1, 2, 3),
                back_end: (4, 5, 6),
                compiler_version_string: "Microsoft (R) Optimizing Compiler".to_string(),
                string_list,
            }
        }
    }

    impl AbstractCompile2MsSymbol for MockCompile2Symbol {
        fn flags(&self) -> u32 {
            self.flags
        }

        fn language(&self) -> &dyn LanguageName {
            &self.language
        }

        fn is_compiled_for_edit_and_continue(&self) -> bool {
            self.decoded.compiled_for_edit_and_continue
        }

        fn is_not_compiled_with_debug_info(&self) -> bool {
            self.decoded.not_compiled_with_debug_info
        }

        fn is_compiled_with_link_time_code_generation(&self) -> bool {
            self.decoded.compiled_with_link_time_code_generation
        }

        fn is_compiled_with_bzalign_no_data_align(&self) -> bool {
            self.decoded.compiled_with_bzalign_no_data_align
        }

        fn is_managed_code_data_present(&self) -> bool {
            self.decoded.managed_code_data_present
        }

        fn is_compiled_with_gs_buffer_security_checks(&self) -> bool {
            self.decoded.compiled_with_gs_buffer_security_checks
        }

        fn is_compiled_with_hot_patch(&self) -> bool {
            self.decoded.compiled_with_hot_patch
        }

        fn is_converted_with_cvtcil(&self) -> bool {
            self.decoded.converted_with_cvtcil
        }

        fn is_microsoft_intermediate_language_net_module(&self) -> bool {
            self.decoded.microsoft_intermediate_language_net_module
        }

        fn processor(&self) -> Processor {
            self.processor
        }

        fn front_end_major_version_number(&self) -> i32 {
            self.front_end.0
        }

        fn front_end_minor_version_number(&self) -> i32 {
            self.front_end.1
        }

        fn front_end_build_version_number(&self) -> i32 {
            self.front_end.2
        }

        fn back_end_major_version_number(&self) -> i32 {
            self.back_end.0
        }

        fn back_end_minor_version_number(&self) -> i32 {
            self.back_end.1
        }

        fn back_end_build_version_number(&self) -> i32 {
            self.back_end.2
        }

        fn compiler_version_string(&self) -> &str {
            &self.compiler_version_string
        }

        fn string_list(&self) -> &[String] {
            &self.string_list
        }

        fn symbol_type_name(&self) -> String {
            "COMPILE2".to_string()
        }
    }

    #[test]
    fn decode_flags_matches_java_bit_layout() {
        // language = Cpp (1), all boolean bits set from bit 8 upward.
        let flags: u32 = 0x1
            | (1 << 8)
            | (1 << 9)
            | (1 << 10)
            | (1 << 11)
            | (1 << 12)
            | (1 << 13)
            | (1 << 14)
            | (1 << 15)
            | (1 << 16);
        let decoded = decode_flags(flags);
        assert_eq!(decoded.language_value, 1);
        assert!(decoded.compiled_for_edit_and_continue);
        assert!(decoded.not_compiled_with_debug_info);
        assert!(decoded.compiled_with_link_time_code_generation);
        assert!(decoded.compiled_with_bzalign_no_data_align);
        assert!(decoded.managed_code_data_present);
        assert!(decoded.compiled_with_gs_buffer_security_checks);
        assert!(decoded.compiled_with_hot_patch);
        assert!(decoded.converted_with_cvtcil);
        assert!(decoded.microsoft_intermediate_language_net_module);
    }

    #[test]
    fn decode_flags_all_zero() {
        let decoded = decode_flags(0);
        assert_eq!(decoded.language_value, 0);
        assert!(!decoded.compiled_for_edit_and_continue);
        assert!(!decoded.not_compiled_with_debug_info);
        assert!(!decoded.compiled_with_link_time_code_generation);
        assert!(!decoded.compiled_with_bzalign_no_data_align);
        assert!(!decoded.managed_code_data_present);
        assert!(!decoded.compiled_with_gs_buffer_security_checks);
        assert!(!decoded.compiled_with_hot_patch);
        assert!(!decoded.converted_with_cvtcil);
        assert!(!decoded.microsoft_intermediate_language_net_module);
    }

    #[test]
    fn decode_flags_isolates_single_bit() {
        // Only "compiled with /GS" (bit 13) set; language stays C (0).
        let decoded = decode_flags(1 << 13);
        assert_eq!(decoded.language_value, 0);
        assert!(!decoded.compiled_for_edit_and_continue);
        assert!(decoded.compiled_with_gs_buffer_security_checks);
        assert!(!decoded.compiled_with_hot_patch);
    }

    #[test]
    fn accessors_match_java_fields() {
        let sym = MockCompile2Symbol::new(1 << 13, Processor::X64Amd64, vec![]);
        assert_eq!(sym.flags(), 1 << 13);
        assert_eq!(sym.language().label(), "C");
        assert!(sym.is_compiled_with_gs_buffer_security_checks());
        assert!(!sym.is_compiled_with_hot_patch());
        assert_eq!(sym.processor(), Processor::X64Amd64);
        assert_eq!(sym.front_end_major_version_number(), 1);
        assert_eq!(sym.back_end_build_version_number(), 6);
        assert_eq!(sym.compiler_version_string(), "Microsoft (R) Optimizing Compiler");
    }

    #[test]
    fn emit_matches_java_format_with_command_block() {
        let flags = 0x1 | (1 << 8); // Cpp, compiled for edit and continue.
        let sym = MockCompile2Symbol::new(
            flags,
            Processor::X64Amd64,
            vec!["cmd".to_string(), "-O2".to_string()],
        );
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert!(builder.starts_with("COMPILE2:\n   Language: C++\n   Target Processor: x64"));
        assert!(builder.contains("\n   Compiled for edit and continue: yes"));
        assert!(builder.contains("\n   Compiled without debugging info: no"));
        assert!(builder.contains("\n   Frontend Version: Major = 1, Minor = 2, Build = 3"));
        assert!(builder.contains("\n   Backend Version: Major = 4, Minor = 5, Build = 6"));
        assert!(builder.contains("\n   Version String:Microsoft (R) Optimizing Compiler"));
        assert!(builder.ends_with("\nCommand block: \n   cmd = '-O2'\n"));
    }

    #[test]
    fn emit_skips_command_block_on_odd_string_list() {
        let sym = MockCompile2Symbol::new(0, Processor::Unknown, vec!["orphan".to_string()]);
        let mut builder = String::new();
        sym.emit(&mut builder);
        assert!(!builder.contains("Command block"));
        assert!(builder.ends_with("Version String:Microsoft (R) Optimizing Compiler"));
    }

    #[test]
    fn is_object_safe() {
        let sym: Box<dyn AbstractCompile2MsSymbol> =
            Box::new(MockCompile2Symbol::new(0, Processor::Arm64, vec![]));
        assert_eq!(sym.processor(), Processor::Arm64);
        assert_eq!(sym.symbol_type_name(), "COMPILE2");
    }
}
