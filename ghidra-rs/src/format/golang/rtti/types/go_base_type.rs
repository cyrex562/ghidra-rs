use super::go_kind::GoKind;
use crate::format::seam_stubs::{GoName, GoRttiMapper, GoType, GoTypeFlag, StructureContext};

/// Represents the fundamental Go rtti type information.
///
/// The in-memory instance will typically be part of a specialized type structure, depending
/// on the 'kind' of this type.
///
/// Additionally, there can be a `GoUncommonType` structure immediately after this type, if the
/// uncommon bit is set in `tflag`.
///
/// Mirrors Ghidra's `runtime._type` / `internal/abi.Type` structure (Java `GoBaseType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoBaseType {
    size: i64,
    ptrdata: i64,
    tflag: i32,
    kind: i32,
    /// Offset relative to the containing moduledata's type base addr (Java field `str`).
    str_off: i64,
    /// Offset relative to the containing moduledata's type base addr (Java field `ptrToThis`).
    ptr_to_this_off: i64,
}

impl GoBaseType {
    pub fn new(size: i64, ptrdata: i64, tflag: i32, kind: i32, str_off: i64, ptr_to_this_off: i64) -> Self {
        GoBaseType { size, ptrdata, tflag, kind, str_off, ptr_to_this_off }
    }

    /// Returns the size of the type being defined by this structure.
    pub fn get_size(&self) -> i64 {
        self.size
    }

    /// Returns the number of bytes of this type that contain pointer data.
    pub fn get_ptr_bytes(&self) -> i64 {
        self.ptrdata
    }

    /// Returns the [`GoKind`] enum assigned to this type definition.
    pub fn get_kind(&self) -> GoKind {
        GoKind::parse_byte(self.kind as u8)
    }

    /// Returns the [`GoTypeFlag`]s assigned to this type definition.
    pub fn get_flags(&self, program_context: &dyn GoRttiMapper) -> Vec<GoTypeFlag> {
        GoTypeFlag::parse_flags(self.tflag, program_context.get_go_ver())
    }

    /// Returns the raw flag value.
    pub fn get_tflag(&self) -> i32 {
        self.tflag
    }

    /// Returns true if this type definition's flags indicate there is a following
    /// `GoUncommonType` structure.
    pub fn has_uncommon_type(&self, program_context: &dyn GoRttiMapper) -> bool {
        GoTypeFlag::Uncommon.is_set(self.tflag, program_context.get_go_ver())
    }

    /// Returns the name of this type, as a [`GoName`].
    pub fn get_go_name(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoBaseType>,
    ) -> std::io::Result<Option<Box<dyn GoName>>> {
        program_context.resolve_name_off(context.get_structure_start(), self.str_off)
    }

    /// Returns the name of this type.
    pub fn get_name(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoBaseType>,
    ) -> String {
        let fallback_name = context.get_mapping_info().structure_name();
        let fallback_start = context.get_structure_start();
        let s = program_context.get_safe_name(
            &|| self.get_go_name(program_context, context),
            &fallback_name,
            fallback_start,
            "",
        );
        if GoTypeFlag::ExtraStar.is_set(self.tflag, program_context.get_go_ver()) && s.starts_with('*') {
            s[1..].to_string()
        }
        else {
            s
        }
    }

    /// Returns a reference to the [`GoType`] that represents a pointer to this type.
    pub fn get_ptr_to_this(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoBaseType>,
    ) -> std::io::Result<Box<dyn GoType>> {
        program_context
            .get_go_types()
            .resolve_type_off(context.get_structure_start(), self.ptr_to_this_off)
    }

    /// Mirrors the Java `StructureVerifier.isValid()` implementation. Not exposed as an
    /// implementation of the [`StructureVerifier`](crate::format::golang::structmapping::structure_verifier::StructureVerifier)
    /// trait: that trait's `is_valid(&self)` takes no arguments, but this check depends on the
    /// `@ContextField`-injected `GoRttiMapper` (for the binary's Go version), which -- following
    /// the same convention [`GoUncommonType`](super::go_uncommon_type::GoUncommonType) uses for
    /// its own `@ContextField`s -- is threaded through as a parameter rather than stored on the
    /// struct.
    pub fn is_valid(&self, program_context: &dyn GoRttiMapper) -> bool {
        0 <= self.ptrdata
            && self.ptrdata <= self.size
            && self.get_kind() != GoKind::Invalid
            && GoTypeFlag::is_valid(self.tflag, program_context.get_go_ver())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_ver::GoVer;
    use crate::format::seam_stubs::{GoTypeManager, StructureMappingInfo};
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::structure::Structure;
    use std::any::Any;

    struct MockGoName {
        name: String,
    }

    impl GoName for MockGoName {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockGoType;

    impl GoType for MockGoType {}

    struct MockGoTypeManager {
        resolved: bool,
    }

    impl GoTypeManager for MockGoTypeManager {
        fn resolve_type_off(&self, _ptr_in_module: i64, off: i64) -> std::io::Result<Box<dyn GoType>> {
            if self.resolved && off != 0 {
                Ok(Box::new(MockGoType))
            }
            else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no type at offset"))
            }
        }
    }

    struct MockGoRttiMapper {
        go_ver: GoVer,
        resolved_name: Option<String>,
        types_resolved: bool,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(&self, _ptr_in_module: i64, off: i64) -> std::io::Result<Option<Box<dyn GoName>>> {
            if off == 0 {
                return Ok(None);
            }
            Ok(self
                .resolved_name
                .clone()
                .map(|name| Box::new(MockGoName { name }) as Box<dyn GoName>))
        }

        fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn crate::format::seam_stubs::GoSlice> {
            unimplemented!()
        }

        fn go_method_structure_length(&self) -> i32 {
            unimplemented!()
        }

        fn get_go_ver(&self) -> GoVer {
            self.go_ver
        }

        fn get_safe_name(
            &self,
            supplier: &dyn Fn() -> std::io::Result<Option<Box<dyn GoName>>>,
            _fallback_structure_name: &str,
            _fallback_structure_start: i64,
            default_value: &str,
        ) -> String {
            match supplier() {
                Ok(Some(name)) => name.get_name(),
                _ => default_value.to_string(),
            }
        }

        fn get_go_types(&self) -> Box<dyn GoTypeManager> {
            Box::new(MockGoTypeManager { resolved: self.types_resolved })
        }
    }

    struct MockStructureContext {
        structure_start: i64,
    }

    impl StructureContext<GoBaseType> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<GoBaseType>> {
            struct Info;
            impl StructureMappingInfo<GoBaseType> for Info {
                fn structure_name(&self) -> String {
                    "runtime._type".to_string()
                }
            }
            Box::new(Info)
        }

        fn get_data_type_mapper(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_containing_field_data_type(&self) -> Box<dyn DataType> {
            unimplemented!()
        }

        fn get_structure_address(&self) -> Address {
            unimplemented!()
        }

        fn get_field_address(&self, _field_offset: i64) -> Address {
            unimplemented!()
        }

        fn get_field_location(&self, _field_offset: i64) -> i64 {
            unimplemented!()
        }

        fn get_structure_start(&self) -> i64 {
            self.structure_start
        }

        fn get_structure_end(&self) -> i64 {
            unimplemented!()
        }

        fn get_structure_length(&self) -> i32 {
            unimplemented!()
        }

        fn get_structure_instance(&self) -> &GoBaseType {
            unimplemented!()
        }

        fn get_reader(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_field_reader(&self, _field_offset: i64) -> Box<dyn Any> {
            unimplemented!()
        }

        fn create_field_context(&self, _fmi: &dyn Any, _include_reader: bool) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_structure_data_type(&self) -> std::io::Result<Box<dyn Structure>> {
            unimplemented!()
        }

        fn to_string(&self) -> String {
            "MockStructureContext".to_string()
        }
    }

    #[test]
    fn get_size_and_ptr_bytes_return_raw_fields() {
        let bt = GoBaseType::new(24, 8, 0, 25, 0x10, 0x20);
        assert_eq!(bt.get_size(), 24);
        assert_eq!(bt.get_ptr_bytes(), 8);
    }

    #[test]
    fn get_kind_parses_kind_byte() {
        let bt = GoBaseType::new(0, 0, 0, 25, 0, 0);
        assert_eq!(bt.get_kind(), GoKind::Struct);
    }

    #[test]
    fn has_uncommon_type_reflects_uncommon_bit() {
        let ver = GoVer::new(1, 21, 0);
        let with_flag = GoBaseType::new(0, 0, 0b1, 0, 0, 0);
        let without_flag = GoBaseType::new(0, 0, 0b10, 0, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: ver, resolved_name: None, types_resolved: true };
        assert!(with_flag.has_uncommon_type(&mapper));
        assert!(!without_flag.has_uncommon_type(&mapper));
    }

    #[test]
    fn get_flags_parses_all_set_bits() {
        // Uncommon (1) | Named (4)
        let bt = GoBaseType::new(0, 0, 0b101, 0, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        let flags = bt.get_flags(&mapper);
        assert_eq!(flags, vec![GoTypeFlag::Uncommon, GoTypeFlag::Named]);
    }

    #[test]
    fn get_name_strips_leading_star_when_extra_star_flag_set() {
        // ExtraStar bit (1 << 1) set
        let bt = GoBaseType::new(0, 0, 0b10, 0, 0x8, 0);
        let mapper = MockGoRttiMapper {
            go_ver: GoVer::new(1, 21, 0),
            resolved_name: Some("*mytype".to_string()),
            types_resolved: true,
        };
        let context = MockStructureContext { structure_start: 0x1000 };
        assert_eq!(bt.get_name(&mapper, &context), "mytype");
    }

    #[test]
    fn get_name_keeps_star_when_extra_star_flag_not_set() {
        let bt = GoBaseType::new(0, 0, 0, 0, 0x8, 0);
        let mapper = MockGoRttiMapper {
            go_ver: GoVer::new(1, 21, 0),
            resolved_name: Some("*mytype".to_string()),
            types_resolved: true,
        };
        let context = MockStructureContext { structure_start: 0x1000 };
        assert_eq!(bt.get_name(&mapper, &context), "*mytype");
    }

    #[test]
    fn get_name_falls_back_to_default_when_offset_zero() {
        let bt = GoBaseType::new(0, 0, 0, 0, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        let context = MockStructureContext { structure_start: 0x1000 };
        assert_eq!(bt.get_name(&mapper, &context), "");
    }

    #[test]
    fn get_ptr_to_this_resolves_via_go_type_manager() {
        let bt = GoBaseType::new(0, 0, 0, 0, 0, 0x30);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        let context = MockStructureContext { structure_start: 0x1000 };
        assert!(bt.get_ptr_to_this(&mapper, &context).is_ok());
    }

    #[test]
    fn is_valid_true_for_well_formed_type() {
        let bt = GoBaseType::new(16, 8, 0, 25, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        assert!(bt.is_valid(&mapper));
    }

    #[test]
    fn is_valid_false_when_ptrdata_exceeds_size() {
        let bt = GoBaseType::new(4, 8, 0, 25, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        assert!(!bt.is_valid(&mapper));
    }

    #[test]
    fn is_valid_false_for_invalid_kind() {
        let bt = GoBaseType::new(16, 8, 0, 0, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        assert!(!bt.is_valid(&mapper));
    }

    #[test]
    fn is_valid_false_for_unrecognized_tflag_bits() {
        // bit 6 (1 << 6) isn't defined by any GoTypeFlag variant.
        let bt = GoBaseType::new(16, 8, 1 << 6, 25, 0, 0);
        let mapper = MockGoRttiMapper { go_ver: GoVer::new(1, 21, 0), resolved_name: None, types_resolved: true };
        assert!(!bt.is_valid(&mapper));
    }
}
