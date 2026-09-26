use std::sync::Arc;

use super::go_kind::GoKind;
use crate::format::golang::structmapping::{StructureContext, StructureMapped, StructureVerifier};
use super::go_type_flag::GoTypeFlag;
use crate::format::seam_stubs::{GoName, GoRttiMapper, GoType};

/// Represents the fundamental Go rtti type information.
///
/// The in-memory instance will typically be part of a specialized type structure, depending
/// on the 'kind' of this type.
///
/// Additionally, there can be a `GoUncommonType` structure immediately after this type, if the
/// uncommon bit is set in `tflag`.
///
/// Mirrors Ghidra's `runtime._type` / `internal/abi.Type` structure (Java `GoBaseType`), read by
/// the structure mapper (`#[derive(StructureMapped)]`).
///
/// Java also marks up `getGoName()`/`getPtrToThis()` (`@Markup`) and places references from the
/// `str`/`ptrToThis` fields to them (`@MarkupReference`). Both return `GoName`/`GoType`, which
/// are still `seam_stubs` placeholders with no structure address; those four markup hooks are
/// attached when those classes are ported as structure mapped types.
#[derive(StructureMapped, Clone)]
#[structure_mapping(structure_name = ["runtime._type", "internal/abi.Type"], verifier)]
pub struct GoBaseType {
    /// `@ContextField` (Java field `context`).
    #[context_field]
    context: StructureContext<GoBaseType>,
    /// `@ContextField` injected Go binary context (Java field `programContext`).
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    #[field_mapping(field_name = ["size", "Size_"], signedness = Unsigned)]
    size: i64,
    #[field_mapping(field_name = ["ptrdata", "PtrBytes"])]
    ptrdata: i64,
    #[field_mapping]
    #[eol_comment(flags_comment)]
    tflag: i32,
    #[field_mapping(field_name = ["kind", "Kind_"])]
    #[eol_comment(kind_comment)]
    kind: i32,
    /// Offset relative to the containing moduledata's type base addr (Java field `str`).
    #[field_mapping(field_name = "str")]
    str_off: i64,
    /// Offset relative to the containing moduledata's type base addr (Java field `ptrToThis`).
    #[field_mapping(field_name = "ptrToThis")]
    ptr_to_this_off: i64,
}

impl GoBaseType {
    /// Returns the structure context this type was read with.
    pub fn get_structure_context(&self) -> &StructureContext<GoBaseType> {
        &self.context
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
    pub fn get_flags(&self) -> Vec<GoTypeFlag> {
        GoTypeFlag::parse_flags(self.tflag, self.program_context.get_go_ver())
    }

    /// The `@EOLComment("flags")` text: Java's `EnumSet.toString()` of [`get_flags`](Self::get_flags)
    /// (`[Uncommon, Named]`); an empty set adds no comment.
    fn flags_comment(&self) -> Option<String> {
        let flags = self.get_flags();
        if flags.is_empty() {
            return None;
        }
        let names: Vec<String> = flags.iter().map(|f| format!("{f:?}")).collect();
        Some(format!("[{}]", names.join(", ")))
    }

    /// The `@EOLComment` text of `kind`: `getKind().toString()`.
    fn kind_comment(&self) -> String {
        self.get_kind().to_string()
    }

    /// Returns the raw flag value.
    pub fn get_tflag(&self) -> i32 {
        self.tflag
    }

    /// Returns true if this type definition's flags indicate there is a following
    /// `GoUncommonType` structure.
    pub fn has_uncommon_type(&self) -> bool {
        GoTypeFlag::Uncommon.is_set(self.tflag, self.program_context.get_go_ver())
    }

    /// Returns the name of this type, as a [`GoName`].
    pub fn get_go_name(&self) -> std::io::Result<Option<Box<dyn GoName>>> {
        self.program_context.resolve_name_off(self.context.get_structure_start(), self.str_off)
    }

    /// Returns the name of this type (`getSafeName(this::getGoName, this, "")`), without the
    /// leading `*` that the `ExtraStar` flag says the stored name carries.
    pub fn get_name(&self) -> String {
        let s = self.program_context.get_safe_name(
            &|| self.get_go_name(),
            self.context.get_mapping_info().get_structure_name(),
            self.context.get_structure_start(),
            "",
        );
        if GoTypeFlag::ExtraStar.is_set(self.tflag, self.program_context.get_go_ver()) && s.starts_with('*') {
            s[1..].to_string()
        }
        else {
            s
        }
    }

    /// Returns a reference to the [`GoType`] that represents a pointer to this type.
    pub fn get_ptr_to_this(&self) -> std::io::Result<Box<dyn GoType>> {
        self.program_context
            .get_go_types()
            .resolve_type_off(self.context.get_structure_start(), self.ptr_to_this_off)
    }
}

impl StructureVerifier for GoBaseType {
    fn is_valid(&self) -> bool {
        0 <= self.ptrdata
            && self.ptrdata <= self.size
            && self.get_kind() != GoKind::Invalid
            && GoTypeFlag::is_valid(self.tflag, self.program_context.get_go_ver())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_ver::GoVer;
    use crate::format::golang::rtti::test_support::{go_mapper, try_read_at, Image};
    use crate::format::seam_stubs::GoTypeManager;
    use crate::program::model::address::Address;

    struct MockGoName {
        name: String,
    }

    impl GoName for MockGoName {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockGoType;

    impl GoType for MockGoType {
        fn get_name(&self) -> String {
            unimplemented!()
        }

        fn get_symbol_name(&self) -> Box<dyn crate::format::seam_stubs::GoSymbolName> {
            unimplemented!()
        }

        fn get_structure_namespace(&self) -> std::io::Result<String> {
            unimplemented!()
        }

        fn discover_go_types(&self, _discovered_types: &mut std::collections::HashSet<i64>) -> std::io::Result<bool> {
            unimplemented!()
        }

        fn get_base_type(&self) -> GoBaseType {
            unimplemented!()
        }

        fn get_package_path_string(&self) -> String {
            unimplemented!()
        }
    }

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

        fn get_type(&self, _offset: i64) -> std::io::Result<Box<dyn GoType>> {
            unimplemented!()
        }

        fn get_data_type(
            &self,
            _type_name: &str,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!()
        }

        fn get_data_type_for_type(
            &self,
            _typ: &dyn GoType,
        ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!()
        }

        fn get_cached_data_type(
            &self,
            _typ: &dyn GoType,
        ) -> std::io::Result<Option<Box<dyn crate::program::model::data::data_type::DataType>>> {
            unimplemented!()
        }

        fn get_dtm(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!()
        }

        fn get_generic_slice_dt(&self) -> Box<dyn crate::program::model::data::structure::Structure> {
            unimplemented!()
        }

        fn cache_recovered_data_type(
            &self,
            _typ: &dyn GoType,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) {
            unimplemented!()
        }

        fn get_cp(&self, _typ: &dyn GoType) -> crate::program::model::data::category_path::CategoryPath {
            unimplemented!()
        }

        fn get_type_name(&self, _typ: &dyn GoType) -> std::io::Result<String> {
            unimplemented!()
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

        fn get_ptr_size(&self) -> i32 {
            unimplemented!()
        }

        fn get_code_address(&self, _offset: i64) -> Address {
            unimplemented!()
        }

        fn is_loaded_and_initialized(&self, _addr: Address) -> bool {
            unimplemented!()
        }

        fn get_data_address(&self, _offset: i64) -> Address {
            unimplemented!()
        }

        fn get_reader(
            &self,
            _position: i64,
        ) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            unimplemented!()
        }

        fn find_containing_module_by_func_data(
            &self,
            _offset: i64,
        ) -> Option<Box<dyn crate::format::seam_stubs::GoModuledata>> {
            unimplemented!()
        }

        fn parse_symbol_name(
            &self,
            _s: &str,
        ) -> Box<dyn crate::format::seam_stubs::GoSymbolName> {
            unimplemented!()
        }

        fn get_function_at(
            &self,
            _addr: &Address,
        ) -> Option<std::sync::Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!()
        }

        fn new_array_data_type(
            &self,
            _element_type: &dyn crate::program::model::data::data_type::DataType,
            _num_elements: i32,
        ) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn add_source_file(
            &self,
            _source_file: &crate::program::database::sourcemap::SourceFile,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!()
        }

        fn add_source_map_entry(
            &self,
            _source_file: &crate::program::database::sourcemap::SourceFile,
            _line_number: i32,
            _base_addr: &Address,
            _length: i64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!()
        }
    }

    fn mapper(go_ver: GoVer, resolved_name: Option<&str>) -> Arc<dyn GoRttiMapper> {
        Arc::new(MockGoRttiMapper {
            go_ver,
            resolved_name: resolved_name.map(str::to_string),
            types_resolved: true,
        })
    }

    /// Reads a `runtime._type` at 0x100 of an image.
    fn read(
        rtti: Arc<dyn GoRttiMapper>,
        size: i64,
        ptrdata: i64,
        tflag: i64,
        kind: i64,
        str_off: i64,
        ptr_to_this: i64,
    ) -> std::io::Result<GoBaseType> {
        let mapper = go_mapper(rtti);
        let mut image = Image::default();
        image.put_base_type(0x100, size, ptrdata, tflag, kind, str_off, ptr_to_this);
        try_read_at(&mapper, &image, 0x100)
    }

    fn v121() -> GoVer {
        GoVer::new(1, 21, 0)
    }

    #[test]
    fn reads_the_runtime_type_fields() {
        let bt = read(mapper(v121(), None), 24, 8, 0, 25, 0x10, 0x20).unwrap();
        assert_eq!(bt.get_size(), 24);
        assert_eq!(bt.get_ptr_bytes(), 8);
        assert_eq!(bt.get_kind(), GoKind::Struct);
        assert_eq!(bt.str_off, 0x10);
        assert_eq!(bt.ptr_to_this_off, 0x20);
        let ctx = bt.get_structure_context();
        assert_eq!(ctx.get_structure_start(), 0x100);
        assert_eq!(ctx.get_structure_length(), 48);
        assert_eq!(ctx.get_mapping_info().get_structure_name(), "runtime._type");
    }

    #[test]
    fn get_kind_parses_kind_byte_with_flag_bits() {
        // DIRECT_IFACE (1 << 5) | Pointer (22)
        let bt = read(mapper(v121(), None), 8, 8, 0, 0x20 | 22, 0, 0).unwrap();
        assert_eq!(bt.get_kind(), GoKind::Pointer);
        assert_eq!(bt.kind_comment(), "Pointer");
    }

    #[test]
    fn has_uncommon_type_reflects_uncommon_bit() {
        let with_flag = read(mapper(v121(), None), 0, 0, 0b1, 25, 0, 0).unwrap();
        let without_flag = read(mapper(v121(), None), 0, 0, 0b10, 25, 0, 0).unwrap();
        assert!(with_flag.has_uncommon_type());
        assert!(!without_flag.has_uncommon_type());
    }

    #[test]
    fn get_flags_parses_all_set_bits() {
        // Uncommon (1) | Named (4)
        let bt = read(mapper(v121(), None), 0, 0, 0b101, 25, 0, 0).unwrap();
        assert_eq!(bt.get_flags(), vec![GoTypeFlag::Uncommon, GoTypeFlag::Named]);
        assert_eq!(bt.flags_comment().as_deref(), Some("[Uncommon, Named]"));
        let none = read(mapper(v121(), None), 0, 0, 0, 25, 0, 0).unwrap();
        assert_eq!(none.flags_comment(), None, "an empty flag set adds no comment");
    }

    #[test]
    fn get_name_strips_leading_star_when_extra_star_flag_set() {
        // ExtraStar bit (1 << 1) set
        let bt = read(mapper(v121(), Some("*mytype")), 0, 0, 0b10, 25, 0x8, 0).unwrap();
        assert_eq!(bt.get_name(), "mytype");
    }

    #[test]
    fn get_name_keeps_star_when_extra_star_flag_not_set() {
        let bt = read(mapper(v121(), Some("*mytype")), 0, 0, 0, 25, 0x8, 0).unwrap();
        assert_eq!(bt.get_name(), "*mytype");
    }

    #[test]
    fn get_name_falls_back_to_default_when_offset_zero() {
        let bt = read(mapper(v121(), None), 0, 0, 0, 25, 0, 0).unwrap();
        assert_eq!(bt.get_name(), "");
    }

    #[test]
    fn get_ptr_to_this_resolves_via_go_type_manager() {
        let bt = read(mapper(v121(), None), 0, 0, 0, 25, 0, 0x30).unwrap();
        assert!(bt.get_ptr_to_this().is_ok());
        let bt = read(mapper(v121(), None), 0, 0, 0, 25, 0, 0).unwrap();
        assert!(bt.get_ptr_to_this().is_err());
    }

    #[test]
    fn is_valid_true_for_well_formed_type() {
        assert!(read(mapper(v121(), None), 16, 8, 0, 25, 0, 0).unwrap().is_valid());
    }

    #[test]
    fn invalid_types_are_rejected_by_the_structure_verifier() {
        // ptrdata exceeds size
        let err = read(mapper(v121(), None), 4, 8, 0, 25, 0, 0).err().unwrap();
        assert_eq!(err.to_string(), "Invalid data for struct @0x100");
        // invalid kind
        assert!(read(mapper(v121(), None), 16, 8, 0, 0, 0, 0).is_err());
        // bit 6 (1 << 6) isn't defined by any GoTypeFlag variant.
        assert!(read(mapper(v121(), None), 16, 8, 1 << 6, 25, 0, 0).is_err());
        // DirectIFace (1 << 5) is a valid flag only from Go 1.24
        assert!(read(mapper(v121(), None), 16, 8, 1 << 5, 25, 0, 0).is_err());
        assert!(read(mapper(GoVer::new(1, 24, 0), None), 16, 8, 1 << 5, 25, 0, 0).is_ok());
    }

    #[test]
    fn descriptor_carries_the_java_annotations() {
        let d = GoBaseType::descriptor();
        assert_eq!(d.structure_names, &["runtime._type", "internal/abi.Type"]);
        assert!(d.is_valid.is_some());
        let names: Vec<&str> = d.fields.iter().map(|f| f.search_name).collect();
        assert_eq!(names, ["size", "ptrdata", "tflag", "kind", "str", "ptrToThis"]);
        assert!(d.fields[2].eol_comment.is_some());
        assert!(d.fields[3].eol_comment.is_some());
    }
}
