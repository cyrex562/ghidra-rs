use std::sync::Arc;

use super::go_base_type::GoBaseType;
use crate::app::util::viewer::field::address_annotated_string_handler::AddressAnnotatedStringHandler;
use crate::format::golang::structmapping::{StructureContext, StructureMapped, StructureMarkup, StructureVerifier};
use crate::format::seam_stubs::{GoRttiMapper, GoSymbolName, GoType};
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::typedef_data_type::TypedefDataType;

/// `GoType` structure that defines an array.
///
/// Mirrors Ghidra's `runtime.arraytype` / `internal/abi.ArrayType` structure (Java
/// `GoArrayType`, which `extends GoType`), read by the structure mapper.
///
/// `GoType` itself is an abstract base class that is not yet ported (see `PORT_ORDER.tsv`), so
/// the fields it contributes (`programContext`, `context`, `typ`) are declared here directly
/// instead of being inherited. A handful of `GoType`'s base-class behaviors that `GoArrayType`
/// relies on via `super.*()` calls (`getPackagePathString`'s uncommon-type fallback,
/// `discoverGoTypes`' uncommon-type method traversal, `additionalMarkup`'s method-table markup,
/// and the type-level `@PlateComment` built from `toString()`) are left out, since they need the
/// unported `GoType`/`GoTypeManager`/`GoMethod` classes. Both fallbacks only matter for types
/// that carry their own method set, which is rare for a plain array/slice type; the
/// element/slice-type paths this class itself implements are unaffected and fully faithful.
///
/// Java's `@Markup`/`@MarkupReference` on `getElement()`/`getSliceType()` return `GoType`, a
/// `seam_stubs` placeholder with no structure address; those hooks are attached when `GoType` is
/// ported as a structure mapped type.
#[derive(StructureMapped)]
#[structure_mapping(
    structure_name = ["runtime.arraytype", "internal/abi.ArrayType"],
    verifier,
    structure_markup
)]
pub struct GoArrayType {
    /// `@ContextField` injected Go binary context (Java field `programContext`, inherited from
    /// `GoType`).
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`, inherited from
    /// `GoType`).
    #[context_field]
    context: StructureContext<GoArrayType>,
    /// `@FieldMapping` shared type header (Java field `typ`, inherited from `GoType`). Always
    /// `Some` once read: it is a mandatory mapped field.
    #[field_mapping(field_name = ["typ", "Type"])]
    #[markup]
    #[field_output]
    typ: Option<GoBaseType>,
    /// Pointer to the element type (Java field `elem`).
    #[field_mapping]
    elem: i64,
    /// Pointer to the slice-of-this-array type (Java field `slice`).
    #[field_mapping]
    slice: i64,
    /// Number of elements in the array (Java field `len`).
    #[field_mapping]
    len: i64,
}

impl GoArrayType {
    /// The `typ` base type header (`GoType.getBaseType()`).
    fn typ(&self) -> &GoBaseType {
        self.typ.as_ref().expect("GoArrayType.typ is a mandatory mapped field")
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
        self.typ().get_name()
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
        self.typ().clone()
    }

    fn get_package_path_string(&self) -> String {
        self.package_path_string()
    }
}

impl StructureVerifier for GoArrayType {
    fn is_valid(&self) -> bool {
        match self.get_element() {
            Ok(element_type) => {
                self.typ().is_valid()
                    && self.typ().get_size() == element_type.get_base_type().get_size() * self.len
            }
            Err(_) => false,
        }
    }
}

impl StructureMarkup for GoArrayType {
    /// `GoType.getStructureLabel()`: `"<fully qualified name>___<kind>_type"`.
    fn structure_label(&self) -> std::io::Result<Option<String>> {
        Ok(Some(format!("{}___{}_type", self.get_symbol_name().as_string(), self.typ().get_kind())))
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
    use crate::format::golang::go_ver::GoVer;
    use crate::format::golang::rtti::test_support::{base_type, go_mapper, read_at, try_read_at, Image};
    use crate::format::seam_stubs::{GoName, GoTypeManager};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::structure::Structure;
    use std::collections::HashSet;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[derive(Clone)]
    struct MockGoType {
        name: String,
        size: i64,
        structure_namespace: String,
        discover_marker: i64,
    }

    impl GoType for MockGoType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_symbol_name(&self) -> Box<dyn GoSymbolName> {
            unimplemented!("unused by GoArrayType")
        }

        fn get_structure_namespace(&self) -> std::io::Result<String> {
            Ok(self.structure_namespace.clone())
        }

        fn discover_go_types(&self, discovered_types: &mut HashSet<i64>) -> std::io::Result<bool> {
            Ok(discovered_types.insert(self.discover_marker))
        }

        fn get_base_type(&self) -> GoBaseType {
            base_type(self.size, 0, 0, 2)
        }

        fn get_package_path_string(&self) -> String {
            String::new()
        }
    }

    struct MockGoTypeManager {
        element: MockGoType,
        slice: MockGoType,
        cached: bool,
    }

    impl GoTypeManager for MockGoTypeManager {
        fn resolve_type_off(&self, _ptr_in_module: i64, _off: i64) -> std::io::Result<Box<dyn GoType>> {
            unimplemented!("unused by GoArrayType")
        }

        fn get_type(&self, offset: i64) -> std::io::Result<Box<dyn GoType>> {
            match offset {
                0x100 => Ok(Box::new(self.element.clone())),
                0x200 => Ok(Box::new(self.slice.clone())),
                _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no type at offset")),
            }
        }

        fn get_data_type(&self, _type_name: &str) -> std::io::Result<Box<dyn DataType>> {
            unimplemented!("unused by GoArrayType")
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
            struct Cached;
            impl DataType for Cached {
                fn get_name(&self) -> String {
                    "cached".to_string()
                }
            }
            Ok(self.cached.then(|| Box::new(Cached) as Box<dyn DataType>))
        }

        fn get_dtm(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!("unused by GoArrayType")
        }

        fn get_generic_slice_dt(&self) -> Box<dyn Structure> {
            unimplemented!("unused by GoArrayType")
        }

        fn cache_recovered_data_type(&self, _typ: &dyn GoType, _dt: Box<dyn DataType>) {}

        fn get_cp(&self, _typ: &dyn GoType) -> CategoryPath {
            unimplemented!("unused by GoArrayType")
        }

        fn get_type_name(&self, _typ: &dyn GoType) -> std::io::Result<String> {
            unimplemented!("unused by GoArrayType")
        }
    }

    struct MockGoRttiMapper {
        element: MockGoType,
        slice: MockGoType,
        cached: bool,
        resolved_name: Option<String>,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(&self, _ptr_in_module: i64, off: i64) -> std::io::Result<Option<Box<dyn GoName>>> {
            struct N(String);
            impl GoName for N {
                fn get_name(&self) -> String {
                    self.0.clone()
                }
            }
            if off == 0 {
                return Ok(None);
            }
            Ok(self.resolved_name.clone().map(|n| Box::new(N(n)) as Box<dyn GoName>))
        }

        fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn crate::format::seam_stubs::GoSlice> {
            unimplemented!("unused by GoArrayType")
        }

        fn go_method_structure_length(&self) -> i32 {
            unimplemented!("unused by GoArrayType")
        }

        fn get_go_ver(&self) -> GoVer {
            GoVer::new(1, 21, 0)
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
            Box::new(MockGoTypeManager { element: self.element.clone(), slice: self.slice.clone(), cached: self.cached })
        }

        fn get_ptr_size(&self) -> i32 {
            8
        }

        fn get_code_address(&self, offset: i64) -> Address {
            test_address(offset)
        }

        fn is_loaded_and_initialized(&self, _addr: Address) -> bool {
            unimplemented!("unused by GoArrayType")
        }

        fn get_data_address(&self, _offset: i64) -> Address {
            unimplemented!("unused by GoArrayType")
        }

        fn get_reader(&self, _position: i64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
            unimplemented!("unused by GoArrayType")
        }

        fn find_containing_module_by_func_data(
            &self,
            _offset: i64,
        ) -> Option<Box<dyn crate::format::seam_stubs::GoModuledata>> {
            unimplemented!("unused by GoArrayType")
        }

        fn parse_symbol_name(&self, _s: &str) -> Box<dyn GoSymbolName> {
            unimplemented!("unused by GoArrayType")
        }

        fn get_function_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("unused by GoArrayType")
        }

        fn new_array_data_type(&self, _element_type: &dyn DataType, _num_elements: i32) -> Box<dyn DataType> {
            unimplemented!("unused by GoArrayType")
        }

        fn add_source_file(
            &self,
            _source_file: &crate::program::database::sourcemap::SourceFile,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!("unused by GoArrayType")
        }

        fn add_source_map_entry(
            &self,
            _source_file: &crate::program::database::sourcemap::SourceFile,
            _line_number: i32,
            _base_addr: &Address,
            _length: i64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!("unused by GoArrayType")
        }
    }

    fn element_type(name: &str, size: i64, namespace: &str) -> MockGoType {
        MockGoType { name: name.to_string(), size, structure_namespace: namespace.to_string(), discover_marker: 1 }
    }

    fn slice_type() -> MockGoType {
        MockGoType { name: "[]int".to_string(), size: 24, structure_namespace: String::new(), discover_marker: 2 }
    }

    fn rtti(element: MockGoType, cached: bool, resolved_name: Option<&str>) -> Arc<dyn GoRttiMapper> {
        Arc::new(MockGoRttiMapper {
            element,
            slice: slice_type(),
            cached,
            resolved_name: resolved_name.map(str::to_string),
        })
    }

    /// A `runtime.arraytype` image at 0x9000: `typ` (kind Array, name at `str` 0x8 when named),
    /// `elem` 0x100, `slice` 0x200, `len`.
    fn image(typ_size: i64, len: i64, named: bool) -> Image {
        let mut image = Image::default();
        image
            .put_base_type(0x9000, typ_size, 0, 0, 17, if named { 0x8 } else { 0 }, 0)
            .put(0x9000 + 48, 8, 0x100)
            .put(0x9000 + 56, 8, 0x200)
            .put(0x9000 + 64, 8, len);
        image
    }

    fn make_array(len: i64, elem_size: i64, cached: bool) -> GoArrayType {
        let mapper = go_mapper(rtti(element_type("int", elem_size, ""), cached, None));
        read_at(&mapper, &image(elem_size * len, len, false), 0x9000)
    }

    #[test]
    fn reads_the_array_type_and_its_nested_base_type() {
        let arr = make_array(3, 4, false);
        assert_eq!((arr.elem, arr.slice, arr.len), (0x100, 0x200, 3));
        assert_eq!(arr.context.get_structure_start(), 0x9000);
        assert_eq!(arr.context.get_structure_length(), 72);
        let typ = arr.get_base_type();
        assert_eq!(typ.get_size(), 12);
        assert_eq!(typ.get_kind(), super::super::go_kind::GoKind::Array);
        // the nested base type has its own context, at the start of the array type
        assert_eq!(typ.get_structure_context().get_structure_start(), 0x9000);
        assert_eq!(typ.get_structure_context().get_containing_field_data_type().unwrap().get_name(), "runtime._type");
    }

    #[test]
    fn is_valid_length_true_for_nonnegative_len() {
        assert!(make_array(5, 4, false).is_valid_length());
    }

    #[test]
    fn is_valid_length_false_for_negative_len() {
        // typ.size (4 * -1) no longer matches, so read without the verifier's opinion mattering:
        // a negative size also fails GoBaseType's ptrdata <= size check
        let mapper = go_mapper(rtti(element_type("int", 4, ""), false, None));
        let err = try_read_at::<GoArrayType>(&mapper, &image(-4, -1, false), 0x9000).err().unwrap();
        assert_eq!(err.to_string(), "Invalid data for struct @0x9000");
    }

    #[test]
    fn get_element_resolves_via_elem_offset() {
        assert_eq!(make_array(3, 4, false).get_element().unwrap().get_name(), "int");
    }

    #[test]
    fn get_slice_type_resolves_via_slice_offset() {
        assert_eq!(make_array(3, 4, false).get_slice_type().unwrap().get_name(), "[]int");
    }

    #[test]
    fn recover_data_type_builds_array_for_valid_length() {
        let dt = make_array(3, 4, false).recover_data_type().unwrap();
        assert!(dt.get_name().contains("int"));
        assert_eq!(dt.get_length(), 12);
    }

    #[test]
    fn recover_data_type_returns_cached_when_present() {
        assert_eq!(make_array(3, 4, true).recover_data_type().unwrap().get_name(), "cached");
    }

    #[test]
    fn recover_data_type_builds_typedef_for_invalid_length() {
        // len > Integer.MAX_VALUE: the element size is 0 so typ.size still matches
        let mapper = go_mapper(rtti(element_type("int", 0, ""), false, None));
        let len = i32::MAX as i64 + 1;
        let arr: GoArrayType = read_at(&mapper, &image(0, len, false), 0x9000);
        let dt = arr.recover_data_type().unwrap();
        assert_eq!(dt.get_name(), format!(".invalid_arraysize_{len}_int"));
    }

    #[test]
    fn verifier_rejects_a_size_mismatch() {
        let mapper = go_mapper(rtti(element_type("int", 4, ""), false, None));
        assert!(try_read_at::<GoArrayType>(&mapper, &image(12, 3, false), 0x9000).is_ok());
        assert!(try_read_at::<GoArrayType>(&mapper, &image(999, 3, false), 0x9000).is_err());
    }

    #[test]
    fn discover_go_types_marks_self_element_and_slice() {
        let arr = make_array(3, 4, false);
        let mut discovered = HashSet::new();
        assert!(arr.discover_go_types(&mut discovered).unwrap());
        assert_eq!(discovered, HashSet::from([0x9000, 1, 2]));
    }

    #[test]
    fn discover_go_types_false_when_already_discovered() {
        let arr = make_array(3, 4, false);
        let mut discovered = HashSet::from([0x9000]);
        assert!(!arr.discover_go_types(&mut discovered).unwrap());
    }

    #[test]
    fn structure_markup_names_namespace_and_label() {
        let mapper = go_mapper(rtti(element_type("int", 4, "mypkg"), false, Some("main.Arr")));
        let arr: GoArrayType = read_at(&mapper, &image(12, 3, true), 0x9000);
        assert_eq!(arr.get_structure_namespace().unwrap(), "mypkg");
        assert_eq!(arr.structure_name().unwrap().as_deref(), Some("main.Arr"));
        assert_eq!(arr.structure_namespace().unwrap().as_deref(), Some("mypkg"));
        assert_eq!(arr.structure_label().unwrap().as_deref(), Some("main.Arr___Array_type"));
        assert!(GoArrayType::descriptor().structure_markup.is_some());
    }

    #[test]
    fn type_decl_string_includes_len_and_element_name() {
        let decl = make_array(3, 4, false).type_decl_string().unwrap();
        assert!(decl.starts_with("type "));
        assert!(decl.contains("[3]"));
        assert!(decl.contains("int"));
    }
}
