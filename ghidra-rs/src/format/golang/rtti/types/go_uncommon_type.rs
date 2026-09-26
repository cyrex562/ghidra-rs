use std::sync::Arc;

use crate::format::golang::structmapping::{StructureContext, StructureMapped};
use crate::format::seam_stubs::{GoMethod, GoName, GoRttiMapper, GoSlice};
use crate::util::msg::Msg;

/// Structure found immediately after a `GoType` structure, if it has the uncommon flag set.
///
/// Mirrors Ghidra's `runtime.uncommontype` / `internal/abi.UncommonType` structure (Java
/// `GoUncommonType`), read by the structure mapper.
///
/// Java also marks up `getPkgPath()` (`@Markup`, and a `@MarkupReference` from `pkgpath`); it
/// returns `GoName`, a `seam_stubs` placeholder with no structure address, so those hooks are
/// attached when `GoName` is ported as a structure mapped type.
#[derive(StructureMapped)]
#[structure_mapping(structure_name = ["runtime.uncommontype", "internal/abi.UncommonType"])]
pub struct GoUncommonType {
    /// `@ContextField` injected Go binary context (Java field `programContext`).
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`).
    #[context_field]
    context: StructureContext<GoUncommonType>,
    /// Name offset of the package path (Java field `pkgpath_nameOff`).
    #[field_mapping(field_name = "pkgpath")]
    #[eol_comment(package_path_string)]
    pub pkgpath_name_off: i64,
    /// Number of methods (Java field `mcount`).
    #[field_mapping]
    pub mcount: i32,
    /// Number of exported methods (Java field `xcount`).
    #[field_mapping]
    pub xcount: i32,
    /// Offset from this structure to the method array (Java field `moff`).
    #[field_mapping]
    pub moff: i64,
}

impl GoUncommonType {
    /// Returns the structure context this type was read with.
    pub fn get_structure_context(&self) -> &StructureContext<GoUncommonType> {
        &self.context
    }

    /// Returns the package path of the type.
    pub fn pkg_path(&self) -> std::io::Result<Option<Box<dyn GoName>>> {
        self.program_context.resolve_name_off(self.context.get_structure_start(), self.pkgpath_name_off)
    }

    /// Returns the package path of the type, or an empty string if it has none.
    pub fn package_path_string(&self) -> std::io::Result<String> {
        Ok(match self.pkg_path()? {
            Some(pkg_path) => pkg_path.get_name(),
            None => String::new(),
        })
    }

    /// Returns a slice containing the methods defined by the type.
    pub fn methods_slice(&self) -> Box<dyn GoSlice> {
        self.program_context.new_slice(
            self.context.get_field_location(self.moff),
            self.mcount as i64,
            self.mcount as i64,
        )
    }

    /// Returns a list of the methods defined by the type.
    pub fn methods(&self) -> std::io::Result<Vec<Box<dyn GoMethod>>> {
        let slice = self.methods_slice();
        if !slice.is_valid(self.program_context.go_method_structure_length()) {
            Msg::warn(
                "GoUncommonType",
                &format!("Bad uncommon method list: {}", self.context.get_structure_address()),
            );
            return Ok(Vec::new());
        }
        slice.read_go_methods()
    }

    /// Returns the location of where this object, and any known associated optional
    /// structures, ends.
    pub fn end_of_type_info(&self) -> i64 {
        if self.mcount == 0 {
            return self.context.get_structure_end();
        }
        // calc end of method array manually since methods_slice() is an artificial slice
        let method_array_start = self.context.get_field_location(self.moff);
        method_array_start + self.mcount as i64 * self.program_context.go_method_structure_length() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::rtti::test_support::{go_mapper, read_at, Image};
    use crate::program::model::data::data_type::DataType;

    struct MockGoName {
        name: String,
    }

    impl GoName for MockGoName {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockGoMethod {
        name: String,
    }

    impl GoMethod for MockGoMethod {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockGoSlice {
        valid: bool,
        methods: Vec<String>,
    }

    impl GoSlice for MockGoSlice {
        fn is_valid(&self, _element_size: i32) -> bool {
            self.valid
        }

        fn read_go_methods(&self) -> std::io::Result<Vec<Box<dyn GoMethod>>> {
            Ok(self
                .methods
                .iter()
                .map(|name| Box::new(MockGoMethod { name: name.clone() }) as Box<dyn GoMethod>)
                .collect())
        }

        fn get_len(&self) -> i64 {
            unimplemented!()
        }

        fn get_sub_slice(&self, _start_element: i64, _element_count: i64, _element_size: i64) -> Box<dyn GoSlice> {
            unimplemented!()
        }

        fn read_u_int_list(&self, _int_size: i32) -> std::io::Result<Vec<i64>> {
            unimplemented!()
        }

        fn markup_element_references(
            &self,
            _element_size: i32,
            _target_addrs: Vec<crate::program::model::address::Address>,
            _session: &mut crate::format::golang::structmapping::MarkupSession<'_>,
        ) -> std::io::Result<()> {
            unimplemented!()
        }

        fn markup_array(
            &self,
            _slice_name: &str,
            _namespace_name: &str,
            _element_type: Option<&dyn crate::program::model::data::data_type::DataType>,
            _ptr: bool,
            _session: &mut crate::format::golang::structmapping::MarkupSession<'_>,
        ) -> std::io::Result<()> {
            unimplemented!()
        }

        fn get_array_address(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_element_offset(&self, _element_size: i64, _element_index: i64) -> i64 {
            unimplemented!()
        }

        fn read_u_int_element(&self, _int_size: i32, _element_index: i32) -> std::io::Result<i64> {
            unimplemented!()
        }

        fn get_element_reader(
            &self,
            _element_size: i32,
            _element_index: i32,
        ) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            unimplemented!()
        }
    }

    struct MockGoRttiMapper {
        go_method_structure_length: i32,
        slice_valid: bool,
        methods: Vec<String>,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(&self, _ptr_in_module: i64, off: i64) -> std::io::Result<Option<Box<dyn GoName>>> {
            if off == 0 {
                return Ok(None);
            }
            Ok(Some(Box::new(MockGoName { name: "example.com/pkg".to_string() })))
        }

        fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn GoSlice> {
            Box::new(MockGoSlice { valid: self.slice_valid, methods: self.methods.clone() })
        }

        fn go_method_structure_length(&self) -> i32 {
            self.go_method_structure_length
        }

        fn get_go_ver(&self) -> crate::format::golang::go_ver::GoVer {
            unimplemented!()
        }

        fn get_safe_name(
            &self,
            _supplier: &dyn Fn() -> std::io::Result<Option<Box<dyn GoName>>>,
            _fallback_structure_name: &str,
            _fallback_structure_start: i64,
            _default_value: &str,
        ) -> String {
            unimplemented!()
        }

        fn get_go_types(&self) -> Box<dyn crate::format::seam_stubs::GoTypeManager> {
            unimplemented!()
        }

        fn get_ptr_size(&self) -> i32 {
            unimplemented!()
        }

        fn get_code_address(&self, _offset: i64) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn is_loaded_and_initialized(&self, _addr: crate::program::model::address::Address) -> bool {
            unimplemented!()
        }

        fn get_data_address(&self, _offset: i64) -> crate::program::model::address::Address {
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
            _addr: &crate::program::model::address::Address,
        ) -> Option<std::sync::Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!()
        }

        fn new_array_data_type(
            &self,
            _element_type: &dyn DataType,
            _num_elements: i32,
        ) -> Box<dyn DataType> {
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
            _base_addr: &crate::program::model::address::Address,
            _length: i64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!()
        }
    }

    /// A `runtime.uncommontype` read at 0x1000 (16 bytes long).
    fn read(pkgpath: i64, mcount: i64, moff: i64, method_len: i32, slice_valid: bool, methods: &[&str]) -> GoUncommonType {
        let rtti = MockGoRttiMapper {
            go_method_structure_length: method_len,
            slice_valid,
            methods: methods.iter().map(|m| m.to_string()).collect(),
        };
        let mapper = go_mapper(Arc::new(rtti));
        let mut image = Image::default();
        image.put(0x1000, 4, pkgpath).put(0x1004, 2, mcount).put(0x1006, 2, 0).put(0x1008, 4, moff).put(0x100c, 4, 0);
        read_at(&mapper, &image, 0x1000)
    }

    #[test]
    fn reads_the_uncommon_type_fields() {
        let uncommon = read(0x10, 2, 0x20, 24, true, &[]);
        assert_eq!((uncommon.pkgpath_name_off, uncommon.mcount, uncommon.xcount, uncommon.moff), (0x10, 2, 0, 0x20));
        assert_eq!(uncommon.get_structure_context().get_structure_start(), 0x1000);
        assert_eq!(uncommon.get_structure_context().get_structure_end(), 0x1010);
    }

    #[test]
    fn package_path_string_resolves_nonzero_offset() {
        assert_eq!(read(0x10, 2, 0x20, 24, true, &[]).package_path_string().unwrap(), "example.com/pkg");
    }

    #[test]
    fn package_path_string_empty_when_offset_zero() {
        assert_eq!(read(0, 0, 0, 24, true, &[]).package_path_string().unwrap(), "");
    }

    #[test]
    fn package_path_is_the_pkgpath_eol_comment() {
        let uncommon = read(0x10, 0, 0, 24, true, &[]);
        let fields = GoUncommonType::descriptor().fields;
        assert_eq!(fields[0].search_name, "pkgpath");
        assert_eq!((fields[0].eol_comment.unwrap())(&uncommon).unwrap().as_deref(), Some("example.com/pkg"));
    }

    #[test]
    fn end_of_type_info_with_no_methods_returns_structure_end() {
        assert_eq!(read(0, 0, 0, 24, true, &[]).end_of_type_info(), 0x1010);
    }

    #[test]
    fn end_of_type_info_with_methods_computes_manually() {
        // method_array_start (0x1000 + 0x40) + mcount (3) * structure_length (16) = 0x1070
        assert_eq!(read(0, 3, 0x40, 16, true, &[]).end_of_type_info(), 0x1070);
    }

    #[test]
    fn methods_slice_starts_at_moff_from_the_structure() {
        let uncommon = read(0, 2, 0x20, 24, true, &[]);
        assert_eq!(uncommon.get_structure_context().get_field_location(uncommon.moff), 0x1020);
    }

    #[test]
    fn methods_returns_empty_and_warns_when_slice_invalid() {
        assert!(read(0, 2, 0x20, 24, false, &["Foo"]).methods().unwrap().is_empty());
    }

    #[test]
    fn methods_returns_slice_contents_when_valid() {
        let methods = read(0, 2, 0x20, 24, true, &["Foo", "Bar"]).methods().unwrap();
        let names: Vec<String> = methods.iter().map(|m| m.get_name()).collect();
        assert_eq!(names, vec!["Foo".to_string(), "Bar".to_string()]);
    }
}
