//! Port of `ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags`.
//!
//! The Java class is a pure namespace of fourteen `public static class CliEnumXxx extends
//! EnumDataType` nested types, each with a single no-arg constructor that builds a fixed set of
//! named flag values, plus a `public final static CliEnumXxx dataType = new CliEnumXxx()` eagerly
//! constructed singleton instance. Per this crate's composition-over-inheritance convention (a
//! Java `extends EnumDataType` with no additional state or overridden behavior needs nothing more
//! than the concrete [`EnumDataType`] itself -- see e.g.
//! [`InvertibleProtocolKind::to_data_type`](crate::format::swift::types::invertible_protocol_kind::InvertibleProtocolKind::to_data_type)
//! for the same "extends EnumDataType, no extra state" precedent), each nested class becomes a
//! free function here returning a freshly built [`EnumDataType`], rather than a dedicated wrapper
//! struct: there is no additional behavior to add, and (unlike Java, where `dataType` is one
//! process-wide identity shared by every `CliFlags` caller) nothing in this crate yet depends on
//! CLI flag enums being singletons, so a plain factory function is both simpler and sufficient.
//!
//! Every `add(name, value)` call is ported verbatim, including each class's own `prefix` variable
//! (folded into the literal name passed to [`EnumDataType::add`]). Java's own commented-out
//! `add(...)` lines (each marked `// TODO: this will not work (it will conflict with ...)`) are
//! *not* ported -- they are dead code in the original (never executed), so omitting them here is
//! not a behavior change, just not resurrecting code Ghidra's own authors deliberately disabled.

use once_cell::sync::Lazy;

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Java: `public static final String PATH = "/PE/CLI/Flags";`.
pub const PATH: &str = "/PE/CLI/Flags";

/// The parsed [`CategoryPath`] for [`PATH`], shared by every flag enum built in this module.
static CATEGORY_PATH: Lazy<CategoryPath> =
    Lazy::new(|| CategoryPath::parse(PATH).expect("CliFlags::PATH is a valid category path"));

/// Port of the nested class `CliFlags.CliEnumAssemblyFlags`.
pub fn cli_enum_assembly_flags() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "AssemblyFlags", 4);
    dt.add("PublicKey", 0x00000001);
    dt.add("Retargetable", 0x00000100);
    dt.add("DisableJITcompileOptimizer", 0x00004000);
    dt.add("EnableJITcompileTracking", 0x00008000);
    dt
}

/// Port of the nested class `CliFlags.CliEnumAssemblyHashAlgorithm`.
pub fn cli_enum_assembly_hash_algorithm() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "AssemblyHash", 4);
    dt.add("None", 0x00000000);
    dt.add("Reserved (MD5)", 0x00008003);
    dt.add("SHA1", 0x00008004);
    dt
}

/// Port of the nested class `CliFlags.CliEnumEventAttributes`.
pub fn cli_enum_event_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "EventAttributes", 2);
    dt.add("SpecialName", 0x0200);
    dt.add("RTSpecialName", 0x0400);
    dt
}

/// Port of the nested class `CliFlags.CliEnumFieldAttributes`.
pub fn cli_enum_field_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "FieldAttributes", 2);
    dt.add("Access_CompilerControlled", 0x0000);
    dt.add("Access_Private", 0x0001);
    dt.add("Access_FamANDAssem", 0x0002);
    dt.add("Access_Assembly", 0x0003);
    dt.add("Access_Family", 0x0004);
    dt.add("Access_FamORAssem", 0x0005);
    dt.add("Access_Public", 0x0006);
    dt.add("Static", 0x0010);
    dt.add("InitOnly", 0x0020);
    dt.add("Literal", 0x0040);
    dt.add("NotSerialized", 0x0080);
    dt.add("SpecialName", 0x0200);
    dt.add("PInvokeImpl", 0x2000);
    dt.add("RTSpecialName", 0x0400);
    dt.add("HasFieldMarshal", 0x1000);
    dt.add("HasDefault", 0x8000);
    dt.add("HasFieldRVA", 0x0100);
    dt
}

/// Port of the nested class `CliFlags.CliEnumFileAttributes`.
pub fn cli_enum_file_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "FileAttributes", 4);
    dt.add("ContainsMetaData", 0x0000);
    dt.add("ContainsNoMetaData", 0x0001);
    dt
}

/// Port of the nested class `CliFlags.CliEnumGenericParamAttributes`.
pub fn cli_enum_generic_param_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "GenericParamAttributes", 2);
    dt.add("Variance_None", 0x0000);
    dt.add("Covariant", 0x0001);
    dt.add("Contravariant", 0x0002);
    dt.add("ReferenceTypeConstraint", 0x0004);
    dt.add("NotNullableValueTypeConstraint", 0x0008);
    dt.add("DefaultConstructorContstraint", 0x0010);
    dt
}

/// Port of the nested class `CliFlags.CliEnumPInvokeAttributes`.
pub fn cli_enum_p_invoke_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "PInvokeAttributes", 2);
    dt.add("NoMangle", 0x0001);
    dt.add("CharSetNotSpec", 0x0000);
    dt.add("CharSetAnsi", 0x0002);
    dt.add("CharSetUnicode", 0x0004);
    dt.add("CharSetAuto", 0x0006);
    dt.add("SupportsLastError", 0x0040);
    dt.add("CallConvPlatformapi", 0x0100);
    dt.add("CallConvCdecl", 0x0200);
    dt.add("CallConvStdcall", 0x0300);
    dt.add("CallConvThiscall", 0x0400);
    dt.add("CallConvFastcall", 0x0500);
    dt
}

/// Port of the nested class `CliFlags.CliEnumManifestResourceAttributes`.
pub fn cli_enum_manifest_resource_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "ManifestResourceAttributes", 4);
    dt.add("Public", 0x0001);
    dt.add("Private", 0x0002);
    dt
}

/// Port of the nested class `CliFlags.CliEnumMethodAttributes`.
pub fn cli_enum_method_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "MethodAttributes", 2);
    dt.add("MAccess_CompilerControlled", 0x0000);
    dt.add("MAccess_Private", 0x0001);
    dt.add("MAccess_FamANDAssem", 0x0002);
    dt.add("MAccess_Assem", 0x0003);
    dt.add("MAccess_Family", 0x0004);
    dt.add("MAccess_FamORAssem", 0x0005);
    dt.add("MAccess_Public", 0x0006);

    dt.add("Static", 0x0010);
    dt.add("Final", 0x0020);
    dt.add("Virtual", 0x0040);
    dt.add("HideBySig", 0x0080);

    // Java: prefix "VtableLayout_"; "ReuseSlot" (0x0000) is commented out in Java (would conflict
    // with CompilerControlled) -- not ported, see the module docs.
    dt.add("VtableLayout_NewSlot", 0x0100);

    dt.add("Strict", 0x0200);
    dt.add("Abstract", 0x0400);
    dt.add("SpecialName", 0x0800);

    dt.add("PInvokeImpl", 0x2000);
    dt.add("UnmanagedExport", 0x0008);

    dt.add("RTSpecialName", 0x1000);
    dt.add("HasSecurity", 0x4000);
    dt.add("RequireSecObject", 0x8000);
    dt
}

/// Port of the nested class `CliFlags.CliEnumMethodImplAttributes`.
pub fn cli_enum_method_impl_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "MethodImplAttributes", 2);
    dt.add("CodeType_IL", 0x0000);
    dt.add("CodeType_Native", 0x0001);
    dt.add("CodeType_OPTIL", 0x0002);
    dt.add("CodeType_Runtime", 0x0003);

    dt.add("Unmanaged", 0x0004);
    // Java: "Managed" (0x0000) is commented out (would conflict with CodeType_IL) -- not ported.

    dt.add("ForwardRef", 0x0010);
    dt.add("PreserveSig", 0x0080);
    dt.add("InternalCall", 0x1000);
    dt.add("Synchronized", 0x0020);
    dt.add("NoInlining", 0x0008);
    dt.add("MaxMethodImplVal", 0xffff);
    dt.add("NoOptimization", 0x0040);
    dt
}

/// Port of the nested class `CliFlags.CliEnumMethodSemanticsAttributes`.
pub fn cli_enum_method_semantics_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "MethodSemanticsAttributes", 2);
    dt.add("Setter", 0x0001);
    dt.add("Getter", 0x0002);
    dt.add("Other", 0x0004);
    dt.add("AddOn", 0x0008);
    dt.add("RemoveOn", 0x0010);
    dt.add("Fire", 0x0020);
    dt
}

/// Port of the nested class `CliFlags.CliEnumParamAttributes`.
pub fn cli_enum_param_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "ParamAttributes", 2);
    dt.add("In", 0x0001);
    dt.add("Out", 0x0002);
    dt.add("Optional", 0x0010);
    dt.add("HasDefault", 0x1000);
    dt.add("HasFieldMarshal", 0x2000);
    dt.add("Unused", 0xcfe0);
    dt
}

/// Port of the nested class `CliFlags.CliEnumPropertyAttributes`.
pub fn cli_enum_property_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "PropertyAttributes", 2);
    dt.add("SpecialName", 0x0200);
    dt.add("RTSpecialName", 0x0400);
    dt.add("HasDefault", 0x1000);
    dt.add("Unused", 0xe9ff);
    dt
}

/// Port of the nested class `CliFlags.CliEnumTypeAttributes`.
pub fn cli_enum_type_attributes() -> EnumDataType {
    let mut dt = EnumDataType::new_in_category(CATEGORY_PATH.clone(), "TypeAttributes", 4);
    dt.add("Visibility_NotPublic", 0x00000000);
    dt.add("Visibility_Public", 0x00000001);
    dt.add("Visibility_NestedPublic", 0x00000002);
    dt.add("Visibility_NestedPrivate", 0x00000003);
    dt.add("Visibility_NestedFamily", 0x00000004);
    dt.add("Visibility_NestedAssembly", 0x00000005);
    dt.add("Visibility_NestedFamANDAssem", 0x00000006);
    dt.add("Visibility_NestedFamORAssem", 0x00000007);

    // Java: "AutoLayout" (0x00000000) is commented out (would conflict with
    // Visibility_NotPublic) -- not ported.
    dt.add("SequentialLayout", 0x00000008);
    dt.add("ExplicitLayout", 0x00000010);

    // Java: "Class" (0x00000000) is commented out (would conflict with Visibility_NotPublic) --
    // not ported.
    dt.add("Interface", 0x00000020);

    dt.add("Abstract", 0x00000080);
    dt.add("Sealed", 0x00000100);
    dt.add("SpecialName", 0x00000400);

    dt.add("Import", 0x00001000);
    dt.add("Serializable", 0x00002000);

    // Java: "AnsiClass" (0x00000000) is commented out (would conflict with
    // Visibility_NotPublic) -- not ported.
    dt.add("UnicodeClass", 0x00010000);
    dt.add("AutoClass", 0x00020000);
    dt.add("CustomFormatClass", 0x00030000);

    dt.add("CustomStringFormatMask", 0x00C00000);

    dt.add("BeforeFieldInit", 0x00100000);

    dt.add("RTSpecialName", 0x00000800);
    dt.add("HasSecurity", 0x00040000);
    dt.add("IsTypeForwarder", 0x00200000);
    dt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::enum_::Enum;

    #[test]
    fn path_matches_java_constant() {
        assert_eq!(PATH, "/PE/CLI/Flags");
    }

    #[test]
    fn cli_enum_assembly_flags_has_expected_name_length_and_values() {
        let dt = cli_enum_assembly_flags();
        assert_eq!(dt.get_name(), "AssemblyFlags");
        assert_eq!(dt.get_length(), 4);
        assert_eq!(dt.get_value_for_name("PublicKey"), Some(0x00000001));
        assert_eq!(dt.get_value_for_name("Retargetable"), Some(0x00000100));
        assert_eq!(dt.get_value_for_name("DisableJITcompileOptimizer"), Some(0x00004000));
        assert_eq!(dt.get_value_for_name("EnableJITcompileTracking"), Some(0x00008000));
        assert_eq!(dt.get_count(), 4);
    }

    #[test]
    fn cli_enum_assembly_hash_algorithm_uses_assembly_hash_as_its_name() {
        // Java quirk preserved: the EnumDataType's registered name is "AssemblyHash", not
        // "AssemblyHashAlgorithm" (which is only the *class* name).
        let dt = cli_enum_assembly_hash_algorithm();
        assert_eq!(dt.get_name(), "AssemblyHash");
        assert_eq!(dt.get_value_for_name("SHA1"), Some(0x00008004));
    }

    #[test]
    fn cli_enum_field_attributes_has_all_seventeen_members() {
        let dt = cli_enum_field_attributes();
        assert_eq!(dt.get_name(), "FieldAttributes");
        assert_eq!(dt.get_length(), 2);
        assert_eq!(dt.get_count(), 17);
        assert_eq!(dt.get_value_for_name("Access_CompilerControlled"), Some(0x0000));
        assert_eq!(dt.get_value_for_name("HasFieldRVA"), Some(0x0100));
    }

    #[test]
    fn cli_enum_method_attributes_prefixes_access_members_but_not_flag_members() {
        let dt = cli_enum_method_attributes();
        assert_eq!(dt.get_name(), "MethodAttributes");
        // Access members use the "MAccess_" prefix.
        assert_eq!(dt.get_value_for_name("MAccess_Public"), Some(0x0006));
        // Non-access members use no prefix at all (Java resets `prefix = ""`).
        assert_eq!(dt.get_value_for_name("Static"), Some(0x0010));
        assert_eq!(dt.get_value_for_name("RequireSecObject"), Some(0x8000));
        // The "VtableLayout_" prefixed member.
        assert_eq!(dt.get_value_for_name("VtableLayout_NewSlot"), Some(0x0100));
        // The commented-out "ReuseSlot" (which would have conflicted with
        // MAccess_CompilerControlled's value) must not exist.
        assert_eq!(dt.get_value_for_name("VtableLayout_ReuseSlot"), None);
        assert_eq!(dt.get_value_for_name("ReuseSlot"), None);
    }

    #[test]
    fn cli_enum_method_impl_attributes_omits_the_commented_out_managed_member() {
        let dt = cli_enum_method_impl_attributes();
        assert_eq!(dt.get_value_for_name("CodeType_IL"), Some(0x0000));
        assert_eq!(dt.get_value_for_name("Unmanaged"), Some(0x0004));
        assert_eq!(dt.get_value_for_name("Managed"), None);
        assert_eq!(dt.get_value_for_name("MaxMethodImplVal"), Some(0xffff));
    }

    #[test]
    fn cli_enum_type_attributes_omits_the_three_commented_out_zero_value_members() {
        let dt = cli_enum_type_attributes();
        assert_eq!(dt.get_name(), "TypeAttributes");
        assert_eq!(dt.get_length(), 4);
        assert_eq!(dt.get_value_for_name("Visibility_NotPublic"), Some(0x00000000));
        // AutoLayout / Class / AnsiClass are all commented out in Java (each would conflict with
        // Visibility_NotPublic's value 0).
        assert_eq!(dt.get_value_for_name("AutoLayout"), None);
        assert_eq!(dt.get_value_for_name("Class"), None);
        assert_eq!(dt.get_value_for_name("AnsiClass"), None);
        assert_eq!(dt.get_value_for_name("Interface"), Some(0x00000020));
        assert_eq!(dt.get_value_for_name("IsTypeForwarder"), Some(0x00200000));
        assert_eq!(dt.get_count(), 24);
    }

    #[test]
    fn every_enum_lands_under_the_shared_pe_cli_flags_category() {
        for dt in [
            cli_enum_assembly_flags(),
            cli_enum_assembly_hash_algorithm(),
            cli_enum_event_attributes(),
            cli_enum_field_attributes(),
            cli_enum_file_attributes(),
            cli_enum_generic_param_attributes(),
            cli_enum_p_invoke_attributes(),
            cli_enum_manifest_resource_attributes(),
            cli_enum_method_attributes(),
            cli_enum_method_impl_attributes(),
            cli_enum_method_semantics_attributes(),
            cli_enum_param_attributes(),
            cli_enum_property_attributes(),
            cli_enum_type_attributes(),
        ] {
            assert_eq!(dt.get_category_path(), CATEGORY_PATH.clone());
        }
    }
}
