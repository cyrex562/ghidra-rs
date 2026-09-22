use super::go_base_type::GoBaseType;
use crate::app::util::viewer::field::address_annotated_string_handler::AddressAnnotatedStringHandler;
use crate::format::golang::structmapping::structure_markup::StructureMarkup;
use crate::format::golang::structmapping::structure_verifier::StructureVerifier;
use crate::format::seam_stubs::{GoRttiMapper, GoSymbolName, GoType, MarkupSession, StructureContext};
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::typedef_data_type::TypedefDataType;

/// `GoType` structure that defines an array.
///
/// Mirrors Ghidra's `runtime.arraytype` / `internal/abi.ArrayType` structure (Java
/// `GoArrayType`, which `extends GoType`).
///
/// `GoType` itself is an abstract base class that is not yet ported (see `PORT_ORDER.tsv`), so
/// the fields it contributes (`programContext`, `context`, `typ`) are held here directly instead
/// of being inherited, following the same `Box<dyn GoRttiMapper>` / `Box<dyn StructureContext<Self>>`
/// convention [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) uses. A handful of
/// `GoType`'s base-class behaviors that `GoArrayType` relies on via `super.*()` calls
/// (`getPackagePathString`'s uncommon-type fallback, and `discoverGoTypes`' uncommon-type method
/// traversal) are simplified to skip the uncommon-type branch entirely, since resolving a
/// `GoUncommonType` at an arbitrary offset needs the generic `DataTypeMapper.readStructure<T>`
/// mechanism, which is part of the still-parked `structmapping` cluster (see
/// `DESCENT_PARKED.tsv`). Both fallbacks only matter for types that carry their own method set,
/// which is rare for a plain array/slice type; the element/slice-type fallback paths this class
/// itself implements are unaffected and fully faithful.
pub struct GoArrayType {
    /// `@ContextField` injected Go binary context (Java field `programContext`, inherited from
    /// `GoType`).
    program_context: Box<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`, inherited from
    /// `GoType`).
    context: Box<dyn StructureContext<GoArrayType>>,
    /// `@FieldMapping` shared type header (Java field `typ`, inherited from `GoType`).
    typ: GoBaseType,
    /// Pointer to the element type (Java field `elem`).
    elem: i64,
    /// Pointer to the slice-of-this-array type (Java field `slice`).
    slice: i64,
    /// Number of elements in the array (Java field `len`).
    len: i64,
}

impl GoArrayType {
    pub fn new(
        program_context: Box<dyn GoRttiMapper>,
        context: Box<dyn StructureContext<GoArrayType>>,
        typ: GoBaseType,
        elem: i64,
        slice: i64,
        len: i64,
    ) -> Self {
        Self { program_context, context, typ, elem, slice, len }
    }

    /// Returns a reference to the [`GoType`] of the elements of this array.
    ///
    /// Port of `GoArrayType.getElement()`.
    pub fn get_element(&self) -> std::io::Result<Box<dyn GoType>> {
        self.program_context.get_go_types().get_type(self.elem)
    }

    /// Returns a reference to the [`GoType`] that defines the slice version of this array.
    ///
    /// Port of `GoArrayType.getSliceType()`.
    pub fn get_slice_type(&self) -> std::io::Result<Box<dyn GoType>> {
        self.program_context.get_go_types().get_type(self.slice)
    }

    /// Port of `GoType.getName()`, which `GoArrayType` inherits unchanged (`typ.getName()`).
    fn base_name(&self) -> String {
        let fallback_name = self.context.get_mapping_info().structure_name();
        self.typ.name_at(self.program_context.as_ref(), self.context.get_structure_start(), &fallback_name)
    }

    /// `len >= 0 && len <= Integer.MAX_VALUE`.
    ///
    /// Port of `GoArrayType.isValidLength()`.
    fn is_valid_length(&self) -> bool {
        (0..=i32::MAX as i64).contains(&self.len)
    }

    /// Converts this Go RTTI array type structure into a Ghidra data type.
    ///
    /// Port of `GoArrayType.recoverDataType()`.
    pub fn recover_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        let go_types = self.program_context.get_go_types();
        let element_dt = go_types.get_data_type_for_type(self.get_element()?.as_ref())?;
        if let Some(cached) = go_types.get_cached_data_type(self)? {
            return Ok(cached);
        }
        if self.is_valid_length() {
            let arr = ArrayDataType::with_element_length(element_dt, self.len as i32, -1)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            Ok(Box::new(arr))
        }
        else {
            let category_path = element_dt.get_category_path();
            let elem_name = element_dt.get_name();
            let typedef_name = format!(".invalid_arraysize_{}_{}", self.len, elem_name);
            let one_elem_arr = ArrayDataType::with_element_length(element_dt, 1, -1)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let td = TypedefDataType::new(category_path, typedef_name, Box::new(one_elem_arr))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            Ok(Box::new(td))
        }
    }

    /// Port of `GoArrayType.getPackagePathString()`.
    pub fn package_path_string(&self) -> String {
        // Base case: `GoType.getPackagePathString()`'s uncommon-type branch is simplified away --
        // see the module docs.
        let pp_str = String::new();
        if pp_str.is_empty() {
            if let Ok(elem_type) = self.get_element() {
                return elem_type.get_package_path_string();
            }
        }
        pp_str
    }

    /// Port of `GoArrayType.getTypeDeclString()`: `type CustomArraytype [elementcount]elementType`.
    fn type_decl_string(&self) -> std::io::Result<String> {
        let self_name = self.base_name();
        let element_type = self.get_element()?;
        let elem_name = element_type.get_name();
        let array_def_str = format!("[{}]{}", self.len, elem_name);
        let def_str_with_links = format!(
            "[{}]{}",
            self.len,
            AddressAnnotatedStringHandler::create_address_annotation_string_for_offset(self.elem, &elem_name)
        );
        let has_name = array_def_str != self_name;
        Ok(format!("type {}{}", if has_name { format!("{self_name} ") } else { String::new() }, def_str_with_links))
    }
}

impl GoType for GoArrayType {
    fn get_name(&self) -> String {
        self.base_name()
    }

    fn get_symbol_name(&self) -> Box<dyn GoSymbolName> {
        // Simplified: real `GoSymbolName.parseTypeName` additionally splits generic-instantiation
        // syntax (e.g. `Foo[int]`) out of the name; no current caller needs that.
        struct Sym {
            name: String,
            package_path: String,
        }
        impl GoSymbolName for Sym {
            fn as_string(&self) -> String {
                self.name.clone()
            }
            fn package_path(&self) -> Option<String> {
                if self.package_path.is_empty() { None } else { Some(self.package_path.clone()) }
            }
        }
        Box::new(Sym { name: self.base_name(), package_path: self.package_path_string() })
    }

    fn get_structure_namespace(&self) -> std::io::Result<String> {
        let package_path = self.package_path_string();
        if !package_path.is_empty() {
            return Ok(package_path);
        }
        let element_type = self.get_element()?;
        element_type.get_structure_namespace()
    }

    fn discover_go_types(&self, discovered_types: &mut std::collections::HashSet<i64>) -> std::io::Result<bool> {
        if !discovered_types.insert(self.context.get_structure_start()) {
            return Ok(false);
        }
        // NOTE: `GoType.discoverGoTypes` additionally walks this type's uncommon-type method
        // list; omitted here -- see the module docs.
        self.get_element()?.discover_go_types(discovered_types)?;
        self.get_slice_type()?.discover_go_types(discovered_types)?;
        Ok(true)
    }

    fn get_base_type(&self) -> GoBaseType {
        self.typ
    }

    fn get_package_path_string(&self) -> String {
        self.package_path_string()
    }
}

impl StructureVerifier for GoArrayType {
    fn is_valid(&self) -> bool {
        match self.get_element() {
            Ok(element_type) => {
                self.typ.is_valid(self.program_context.as_ref())
                    && self.typ.get_size() == element_type.get_base_type().get_size() * self.len
            }
            Err(_) => false,
        }
    }
}

impl StructureMarkup<GoArrayType> for GoArrayType {
    fn structure_context(&self) -> &dyn StructureContext<GoArrayType> {
        self.context.as_ref()
    }

    fn structure_name(&self) -> std::io::Result<Option<String>> {
        Ok(Some(self.get_symbol_name().as_string()))
    }

    fn structure_namespace(&self) -> std::io::Result<Option<String>> {
        Ok(Some(self.get_structure_namespace()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{GoTypeManager, StructureMappingInfo};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::structure::Structure;
    use std::any::Any;
    use std::collections::HashSet;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[derive(Clone)]
    struct MockGoType {
        name: String,
        base_type: GoBaseType,
        structure_namespace: String,
        discover_marker: i64,
    }

    impl GoType for MockGoType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_symbol_name(&self) -> Box<dyn GoSymbolName> {
            unimplemented!()
        }

        fn get_structure_namespace(&self) -> std::io::Result<String> {
            Ok(self.structure_namespace.clone())
        }

        fn discover_go_types(&self, discovered_types: &mut HashSet<i64>) -> std::io::Result<bool> {
            Ok(discovered_types.insert(self.discover_marker))
        }

        fn get_base_type(&self) -> GoBaseType {
            self.base_type
        }

        fn get_package_path_string(&self) -> String {
            String::new()
        }
    }

    struct MockGoTypeManager {
        element: MockGoType,
        slice: MockGoType,
        cached: Option<()>,
    }

    impl GoTypeManager for MockGoTypeManager {
        fn resolve_type_off(&self, _ptr_in_module: i64, _off: i64) -> std::io::Result<Box<dyn GoType>> {
            unimplemented!()
        }

        fn get_type(&self, offset: i64) -> std::io::Result<Box<dyn GoType>> {
            if offset == 0x100 {
                Ok(Box::new(self.element.clone()))
            }
            else if offset == 0x200 {
                Ok(Box::new(self.slice.clone()))
            }
            else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no type at offset"))
            }
        }

        fn get_data_type(&self, _type_name: &str) -> std::io::Result<Box<dyn DataType>> {
            unimplemented!()
        }

        fn get_data_type_for_type(&self, typ: &dyn GoType) -> std::io::Result<Box<dyn DataType>> {
            struct Dt {
                name: String,
                length: i32,
            }
            impl DataType for Dt {
                fn get_name(&self) -> String {
                    self.name.clone()
                }
                fn get_length(&self) -> i32 {
                    self.length
                }
            }
            let length = typ.get_base_type().get_size().max(1) as i32;
            Ok(Box::new(Dt { name: typ.get_name(), length }))
        }

        fn get_cached_data_type(&self, _typ: &dyn GoType) -> std::io::Result<Option<Box<dyn DataType>>> {
            Ok(self.cached.map(|_| {
                struct Cached;
                impl DataType for Cached {
                    fn get_name(&self) -> String {
                        "cached".to_string()
                    }
                }
                Box::new(Cached) as Box<dyn DataType>
            }))
        }

        fn get_dtm(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!()
        }

        fn get_generic_slice_dt(&self) -> Box<dyn Structure> {
            unimplemented!()
        }

        fn cache_recovered_data_type(&self, _typ: &dyn GoType, _dt: Box<dyn DataType>) {}

        fn get_cp(&self, _typ: &dyn GoType) -> CategoryPath {
            unimplemented!()
        }

        fn get_type_name(&self, _typ: &dyn GoType) -> std::io::Result<String> {
            unimplemented!()
        }
    }

    struct MockGoRttiMapper {
        element: MockGoType,
        slice: MockGoType,
        cached: Option<()>,
        resolved_name: Option<String>,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(
            &self,
            _ptr_in_module: i64,
            off: i64,
        ) -> std::io::Result<Option<Box<dyn crate::format::seam_stubs::GoName>>> {
            struct N(String);
            impl crate::format::seam_stubs::GoName for N {
                fn get_name(&self) -> String {
                    self.0.clone()
                }
            }
            if off == 0 {
                return Ok(None);
            }
            Ok(self.resolved_name.clone().map(|n| Box::new(N(n)) as Box<dyn crate::format::seam_stubs::GoName>))
        }

        fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn crate::format::seam_stubs::GoSlice> {
            unimplemented!()
        }

        fn go_method_structure_length(&self) -> i32 {
            unimplemented!()
        }

        fn get_go_ver(&self) -> crate::format::golang::go_ver::GoVer {
            crate::format::golang::go_ver::GoVer::new(1, 21, 0)
        }

        fn get_safe_name(
            &self,
            supplier: &dyn Fn() -> std::io::Result<Option<Box<dyn crate::format::seam_stubs::GoName>>>,
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
            Box::new(MockGoTypeManager { element: self.element.clone(), slice: self.slice.clone(), cached: self.cached })
        }

        fn get_ptr_size(&self) -> i32 {
            8
        }

        fn get_code_address(&self, offset: i64) -> Address {
            test_address(offset)
        }

        fn is_loaded_and_initialized(&self, _addr: Address) -> bool {
            unimplemented!()
        }

        fn get_data_address(&self, _offset: i64) -> Address {
            unimplemented!()
        }

        fn get_reader(&self, _position: i64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            unimplemented!()
        }

        fn find_containing_module_by_func_data(
            &self,
            _offset: i64,
        ) -> Option<Box<dyn crate::format::seam_stubs::GoModuledata>> {
            unimplemented!()
        }

        fn parse_symbol_name(&self, _s: &str) -> Box<dyn crate::format::seam_stubs::GoSymbolName> {
            unimplemented!()
        }

        fn get_function_at(
            &self,
            _addr: &Address,
        ) -> Option<std::sync::Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!()
        }

        fn new_array_data_type(&self, _element_type: &dyn DataType, _num_elements: i32) -> Box<dyn DataType> {
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

    struct MockStructureContext {
        structure_start: i64,
    }

    impl StructureContext<GoArrayType> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<GoArrayType>> {
            struct Info;
            impl StructureMappingInfo<GoArrayType> for Info {
                fn structure_name(&self) -> String {
                    "runtime.arraytype".to_string()
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
            test_address(self.structure_start)
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

        fn get_structure_instance(&self) -> &GoArrayType {
            unimplemented!()
        }

        fn get_reader(&self) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            unimplemented!()
        }

        fn get_field_reader(&self, _field_offset: i64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
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

    fn element_type(name: &str, size: i64) -> MockGoType {
        MockGoType {
            name: name.to_string(),
            base_type: GoBaseType::new(size, 0, 0, 0, 0, 0),
            structure_namespace: String::new(),
            discover_marker: 1,
        }
    }

    fn slice_type() -> MockGoType {
        MockGoType {
            name: "[]int".to_string(),
            base_type: GoBaseType::new(24, 8, 0, 23, 0, 0),
            structure_namespace: String::new(),
            discover_marker: 2,
        }
    }

    fn make_array(len: i64, elem_size: i64, cached: Option<()>) -> GoArrayType {
        GoArrayType::new(
            Box::new(MockGoRttiMapper {
                element: element_type("int", elem_size),
                slice: slice_type(),
                cached,
                resolved_name: None,
            }),
            Box::new(MockStructureContext { structure_start: 0x9000 }),
            GoBaseType::new(elem_size * len, 0, 0, 17, 0, 0),
            0x100,
            0x200,
            len,
        )
    }

    #[test]
    fn is_valid_length_true_for_nonnegative_len() {
        let arr = make_array(5, 4, None);
        assert!(arr.is_valid_length());
    }

    #[test]
    fn is_valid_length_false_for_negative_len() {
        let arr = make_array(-1, 4, None);
        assert!(!arr.is_valid_length());
    }

    #[test]
    fn get_element_resolves_via_elem_offset() {
        let arr = make_array(3, 4, None);
        assert_eq!(arr.get_element().unwrap().get_name(), "int");
    }

    #[test]
    fn get_slice_type_resolves_via_slice_offset() {
        let arr = make_array(3, 4, None);
        assert_eq!(arr.get_slice_type().unwrap().get_name(), "[]int");
    }

    #[test]
    fn recover_data_type_builds_array_for_valid_length() {
        let arr = make_array(3, 4, None);
        let dt = arr.recover_data_type().unwrap();
        // ArrayDataType's default name is derived from its element type and count.
        assert!(dt.get_name().contains("int"));
    }

    #[test]
    fn recover_data_type_returns_cached_when_present() {
        let arr = make_array(3, 4, Some(()));
        let dt = arr.recover_data_type().unwrap();
        assert_eq!(dt.get_name(), "cached");
    }

    #[test]
    fn recover_data_type_builds_typedef_for_invalid_length() {
        let arr = make_array(-1, 4, None);
        let dt = arr.recover_data_type().unwrap();
        assert!(dt.get_name().starts_with(".invalid_arraysize_-1_int"));
    }

    #[test]
    fn is_valid_true_when_size_matches_element_times_len() {
        // typ.size == elem.size * len (4 * 3 = 12)
        let mut arr = make_array(3, 4, None);
        arr.typ = GoBaseType::new(12, 0, 0, 17, 0, 0);
        assert!(arr.is_valid());
    }

    #[test]
    fn is_valid_false_when_size_mismatches() {
        let mut arr = make_array(3, 4, None);
        arr.typ = GoBaseType::new(999, 0, 0, 17, 0, 0);
        assert!(!arr.is_valid());
    }

    #[test]
    fn discover_go_types_marks_self_element_and_slice() {
        let arr = make_array(3, 4, None);
        let mut discovered = HashSet::new();
        assert!(arr.discover_go_types(&mut discovered).unwrap());
        assert_eq!(discovered, HashSet::from([0x9000, 1, 2]));
    }

    #[test]
    fn discover_go_types_false_when_already_discovered() {
        let arr = make_array(3, 4, None);
        let mut discovered = HashSet::new();
        discovered.insert(0x9000);
        assert!(!arr.discover_go_types(&mut discovered).unwrap());
    }

    #[test]
    fn get_structure_namespace_falls_back_to_element_when_own_package_path_empty() {
        let arr = GoArrayType::new(
            Box::new(MockGoRttiMapper {
                element: MockGoType {
                    name: "int".to_string(),
                    base_type: GoBaseType::new(4, 0, 0, 0, 0, 0),
                    structure_namespace: "mypkg".to_string(),
                    discover_marker: 1,
                },
                slice: slice_type(),
                cached: None,
                resolved_name: None,
            }),
            Box::new(MockStructureContext { structure_start: 0x9000 }),
            GoBaseType::new(12, 0, 0, 17, 0, 0),
            0x100,
            0x200,
            3,
        );
        assert_eq!(arr.get_structure_namespace().unwrap(), "mypkg");
    }

    #[test]
    fn type_decl_string_includes_len_and_element_name() {
        let arr = make_array(3, 4, None);
        let decl = arr.type_decl_string().unwrap();
        assert!(decl.starts_with("type "));
        assert!(decl.contains("[3]"));
        assert!(decl.contains("int"));
    }
}
