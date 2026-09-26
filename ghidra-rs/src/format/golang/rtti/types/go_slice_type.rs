use std::sync::Arc;

use super::go_base_type::GoBaseType;
use crate::app::util::viewer::field::address_annotated_string_handler::AddressAnnotatedStringHandler;
use crate::format::golang::structmapping::{StructureContext, StructureMapped, StructureMarkup, StructureVerifier};
use crate::format::seam_stubs::{GoRttiMapper, GoSymbolName, GoType};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// Go type information about a specific slice type.
///
/// Mirrors Ghidra's `runtime.slicetype` / `internal/abi.SliceType` structure (Java
/// `GoSliceType`, which `extends GoType`). See the "runtime.slice" type (or
/// `GoTypeManager::getGenericSliceDT`) for the layout of an actual slice variable in memory,
/// as opposed to this RTTI type-descriptor.
///
/// See [`GoArrayType`](super::go_array_type::GoArrayType)'s docs for why the fields `GoType`
/// contributes are declared here directly rather than inherited, for the same documented
/// simplification of `GoType`'s uncommon-type behavior, and for the `GoType`-returning markup
/// hooks (`getElement()`) that are attached once `GoType` is ported.
#[derive(StructureMapped)]
#[structure_mapping(
    structure_name = ["runtime.slicetype", "internal/abi.SliceType"],
    verifier,
    structure_markup
)]
pub struct GoSliceType {
    /// `@ContextField` injected Go binary context (Java field `programContext`, inherited from
    /// `GoType`).
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`, inherited from
    /// `GoType`).
    #[context_field]
    context: StructureContext<GoSliceType>,
    /// `@FieldMapping` shared type header (Java field `typ`, inherited from `GoType`). Always
    /// `Some` once read: it is a mandatory mapped field.
    #[field_mapping(field_name = ["typ", "Type"])]
    #[markup]
    #[field_output]
    typ: Option<GoBaseType>,
    /// Pointer to the element type (Java field `elem`).
    #[field_mapping]
    elem: i64,
}

/// Delegates every [`DataType`] method to a wrapped [`Pointer`]. Rust does not support coercing
/// `Box<dyn Pointer>` to `Box<dyn DataType>` for an arbitrary supertrait relationship; this
/// mirrors the same local adapter used at
/// [`parameter_db::PointerAsDataType`](crate::program::database::function::parameter_db) and its
/// other siblings.
struct PointerAsDataType(Box<dyn Pointer>);

impl DataType for PointerAsDataType {
    fn get_name(&self) -> String {
        DataType::get_name(self.0.as_ref())
    }

    fn get_length(&self) -> i32 {
        DataType::get_length(self.0.as_ref())
    }

    fn is_pointer(&self) -> bool {
        true
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        DataType::is_equivalent(self.0.as_ref(), dt)
    }

    fn clone_data_type(&self, dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn DataType> {
        DataType::clone_data_type(self.0.as_ref(), dtm)
    }
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

impl GoSliceType {
    /// The `typ` base type header (`GoType.getBaseType()`).
    fn typ(&self) -> &GoBaseType {
        self.typ.as_ref().expect("GoSliceType.typ is a mandatory mapped field")
    }

    /// Returns a reference to the element's type.
    ///
    /// Port of `GoSliceType.getElement()`.
    pub fn get_element(&self) -> std::io::Result<Box<dyn GoType>> {
        self.program_context.get_go_types().get_type(self.elem)
    }

    /// Port of `GoType.getName()`, which `GoSliceType` inherits unchanged (`typ.getName()`).
    fn base_name(&self) -> String {
        self.typ().get_name()
    }

    /// Converts this Go RTTI slice type structure into a Ghidra data type.
    ///
    /// Port of `GoSliceType.recoverDataType()`.
    ///
    /// Deviates from the Java in two respects, both around `StructureDataType`'s still-partial
    /// port:
    /// - Java pre-sizes `sliceDT` to `genericSliceDT`'s length and then calls
    ///   `sliceDT.replaceWith(genericSliceDT)` to bulk-copy every component in place. The
    ///   ported [`StructureDataTypeImpl`] doesn't yet implement `replace_with` (its default is a
    ///   no-op), and a structure pre-sized with implicit undefined filler bytes can't have real
    ///   components appended into that filler with `add`. Instead, this builds `slice_dt` from
    ///   zero length, appending each of `genericSliceDT`'s real components in order -- the void*
    ///   element field is appended as the real element-pointer type directly, rather than
    ///   appended generically and then replaced -- which reaches the identical final layout.
    /// - Java calls `cacheRecoveredDataType` on the in-progress structure *before* resolving the
    ///   element type (the cache entry and the eventual return value are the same object
    ///   reference in Java, so caching early lets a self-referential slice resolve the
    ///   in-progress structure instead of recursing forever). `Box<dyn DataType>` ownership
    ///   doesn't let one value be handed to both the cache and the return path here, and
    ///   `GoTypeManager`'s cache is still a forward-reference stub with no real backing store
    ///   (see `seam_stubs.rs`) for that early value to usefully occupy anyway, so the cache
    ///   write is dropped for now; the real `GoTypeManager` port, once its cache holds
    ///   `Rc`/`Arc`-shared entries, is the natural place to restore it.
    pub fn recover_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        let go_types = self.program_context.get_go_types();
        let dtm = go_types.get_dtm();
        let generic_slice_dt = go_types.get_generic_slice_dt();

        let category_path = go_types.get_cp(self);
        let type_name = go_types.get_type_name(self)?;
        let mut slice_dt = StructureDataTypeImpl::new_in_category(category_path, type_name, 0);

        let element_type = self.get_element()?;
        let element_dt = go_types.get_data_type_for_type(element_type.as_ref())?;
        let element_ptr_dt = dtm.get_pointer(element_dt.as_ref());
        let mut element_ptr_dt = Some(element_ptr_dt);

        const ARRAY_PTR_COMPONENT_INDEX: i32 = 0; // field ordinal of the void* data field in slice type
        for i in 0..generic_slice_dt.get_num_components() {
            let comp = Structure::get_component(generic_slice_dt.as_ref(), i).map_err(io_err)?;
            let (dt, length): (Box<dyn DataType>, i32) = if i == ARRAY_PTR_COMPONENT_INDEX {
                (Box::new(PointerAsDataType(element_ptr_dt.take().expect("array component visited once"))), -1)
            }
            else {
                (comp.get_data_type(), comp.get_length())
            };
            slice_dt.add_with_length_and_name(dt, length, comp.get_field_name(), comp.get_comment()).map_err(io_err)?;
        }

        Ok(Box::new(slice_dt))
    }

    /// Port of `GoSliceType.getPackagePathString()`.
    pub fn package_path_string(&self) -> String {
        let pp_str = String::new();
        if pp_str.is_empty() {
            if let Ok(elem_type) = self.get_element() {
                return elem_type.get_package_path_string();
            }
        }
        pp_str
    }

    /// Port of `GoSliceType.getTypeDeclString()`: `type CustomSliceType []elementType`.
    fn type_decl_string(&self) -> std::io::Result<String> {
        let self_name = self.base_name();
        let element_type = self.get_element()?;
        let elem_name = element_type.get_name();
        let def_str = format!("[]{elem_name}");
        let def_str_with_links = format!(
            "[]{}",
            AddressAnnotatedStringHandler::create_address_annotation_string_for_offset(self.elem, &elem_name)
        );
        let has_name = def_str != self_name;
        Ok(format!("type {}{}", if has_name { format!("{self_name} ") } else { String::new() }, def_str_with_links))
    }

    /// `typ.getSize() == programContext.getPtrSize() * 3 && typ.getPtrBytes() == programContext.getPtrSize()`.
    ///
    /// Port of `GoSliceType.isValidSize()`.
    fn is_valid_size(&self) -> bool {
        let ptr_size = self.program_context.get_ptr_size() as i64;
        self.typ().get_size() == ptr_size * 3 && self.typ().get_ptr_bytes() == ptr_size
    }
}

impl GoType for GoSliceType {
    fn get_name(&self) -> String {
        self.base_name()
    }

    fn get_symbol_name(&self) -> Box<dyn GoSymbolName> {
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
        self.get_element()?.discover_go_types(discovered_types)?;
        Ok(true)
    }

    fn get_base_type(&self) -> GoBaseType {
        self.typ().clone()
    }

    fn get_package_path_string(&self) -> String {
        self.package_path_string()
    }
}

impl StructureVerifier for GoSliceType {
    fn is_valid(&self) -> bool {
        self.typ().is_valid() && self.is_valid_size()
    }
}

impl StructureMarkup for GoSliceType {
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
    use crate::format::golang::rtti::test_support::{base_type, go_mapper, read_at, try_read_at, Image};
    use crate::format::seam_stubs::GoTypeManager;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
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
            unimplemented!()
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

    struct MockPointer {
        length: i32,
    }

    impl DataType for MockPointer {
        fn get_name(&self) -> String {
            "int *".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_pointer(&self) -> bool {
            true
        }
    }

    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!()
        }

        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!()
        }
    }

    struct MockDataTypeManager {
        ptr_length: i32,
    }

    impl crate::program::model::data::data_type_manager::DataTypeManager for MockDataTypeManager {
        fn get_pointer(&self, _datatype: &dyn DataType) -> Box<dyn Pointer> {
            Box::new(MockPointer { length: self.ptr_length })
        }
    }

    /// A generic slice structure with two components: `array void*` (index 0, replaced by the
    /// real element pointer) and `len int` (index 1, copied verbatim).
    struct MockGenericSliceDt {
        ptr_length: i32,
    }

    impl DataType for MockGenericSliceDt {
        fn get_name(&self) -> String {
            "GenericSlice".to_string()
        }
        fn get_length(&self) -> i32 {
            self.ptr_length + 8
        }
    }

    impl Composite for MockGenericSliceDt {
        fn get_num_components(&self) -> i32 {
            2
        }
        fn get_component(
            &self,
            ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::data::data_type_component::DataTypeComponent>, String> {
            match ordinal {
                0 => Ok(Box::new(DataTypeComponentImpl::new(
                    Box::new(MockPointer { length: self.ptr_length }),
                    None,
                    self.ptr_length,
                    0,
                    0,
                    Some("array".to_string()),
                    None,
                ))),
                1 => Ok(Box::new(DataTypeComponentImpl::new(
                    Box::new(MockPointer { length: 8 }),
                    None,
                    8,
                    1,
                    self.ptr_length,
                    Some("len".to_string()),
                    None,
                ))),
                _ => Err("out of bounds".to_string()),
            }
        }
    }

    impl Structure for MockGenericSliceDt {
        fn get_component(
            &self,
            ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::data::data_type_component::DataTypeComponent>, String> {
            Composite::get_component(self, ordinal)
        }
    }

    struct MockGoTypeManager {
        element: MockGoType,
        ptr_length: i32,
    }

    impl GoTypeManager for MockGoTypeManager {
        fn resolve_type_off(&self, _ptr_in_module: i64, _off: i64) -> std::io::Result<Box<dyn GoType>> {
            unimplemented!()
        }
        fn get_type(&self, offset: i64) -> std::io::Result<Box<dyn GoType>> {
            if offset == 0x100 {
                Ok(Box::new(self.element.clone()))
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
            Ok(Box::new(Dt { name: typ.get_name(), length: typ.get_base_type().get_size().max(1) as i32 }))
        }
        fn get_cached_data_type(&self, _typ: &dyn GoType) -> std::io::Result<Option<Box<dyn DataType>>> {
            Ok(None)
        }
        fn get_dtm(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            Box::new(MockDataTypeManager { ptr_length: self.ptr_length })
        }
        fn get_generic_slice_dt(&self) -> Box<dyn Structure> {
            Box::new(MockGenericSliceDt { ptr_length: self.ptr_length })
        }
        fn cache_recovered_data_type(&self, _typ: &dyn GoType, _dt: Box<dyn DataType>) {}
        fn get_cp(&self, _typ: &dyn GoType) -> CategoryPath {
            ROOT.clone()
        }
        fn get_type_name(&self, typ: &dyn GoType) -> std::io::Result<String> {
            Ok(format!("[]{}", typ.get_package_path_string()))
        }
    }

    struct MockGoRttiMapper {
        element: MockGoType,
        ptr_size: i32,
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
            Box::new(MockGoTypeManager { element: self.element.clone(), ptr_length: self.ptr_size })
        }
        fn get_ptr_size(&self) -> i32 {
            self.ptr_size
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

    fn element_type(name: &str, size: i64, namespace: &str) -> MockGoType {
        MockGoType { name: name.to_string(), size, structure_namespace: namespace.to_string(), discover_marker: 1 }
    }

    /// A `runtime.slicetype` image at 0x9000: `typ` (kind Slice, name at `str` 0x8 when named),
    /// `elem` 0x100.
    fn image(size: i64, ptrdata: i64, named: bool) -> Image {
        let mut image = Image::default();
        image.put_base_type(0x9000, size, ptrdata, 0, 23, if named { 0x8 } else { 0 }, 0).put(0x9000 + 48, 8, 0x100);
        image
    }

    fn mapper_for(element: MockGoType, ptr_size: i32, resolved_name: Option<&str>) -> crate::format::golang::structmapping::DataTypeMapper {
        go_mapper(Arc::new(MockGoRttiMapper { element, ptr_size, resolved_name: resolved_name.map(str::to_string) }))
    }

    fn make_slice(ptr_size: i32) -> GoSliceType {
        let mapper = mapper_for(element_type("int", 8, ""), ptr_size, None);
        read_at(&mapper, &image(ptr_size as i64 * 3, ptr_size as i64, false), 0x9000)
    }

    #[test]
    fn reads_the_slice_type_and_its_nested_base_type() {
        let slice = make_slice(8);
        assert_eq!(slice.elem, 0x100);
        assert_eq!(slice.context.get_structure_start(), 0x9000);
        assert_eq!(slice.context.get_structure_length(), 56);
        assert_eq!(slice.get_base_type().get_size(), 24);
        assert_eq!(slice.get_base_type().get_kind(), super::super::go_kind::GoKind::Slice);
    }

    #[test]
    fn get_element_resolves_via_elem_offset() {
        assert_eq!(make_slice(8).get_element().unwrap().get_name(), "int");
    }

    #[test]
    fn is_valid_true_for_wellformed_slice_header() {
        assert!(make_slice(8).is_valid());
        assert!(make_slice(4).is_valid());
    }

    #[test]
    fn verifier_rejects_a_size_that_is_not_three_pointers() {
        let mapper = mapper_for(element_type("int", 8, ""), 8, None);
        let err = try_read_at::<GoSliceType>(&mapper, &image(16, 8, false), 0x9000).err().unwrap();
        assert_eq!(err.to_string(), "Invalid data for struct @0x9000");
    }

    #[test]
    fn verifier_rejects_a_ptr_bytes_mismatch() {
        let mapper = mapper_for(element_type("int", 8, ""), 8, None);
        assert!(try_read_at::<GoSliceType>(&mapper, &image(24, 4, false), 0x9000).is_err());
    }

    #[test]
    fn recover_data_type_builds_structure_with_element_pointer_and_len() {
        let dt = make_slice(8).recover_data_type().unwrap();
        // Overall length matches the generic slice layout (ptr + int = 16 bytes for ptr_size=8).
        assert_eq!(dt.get_length(), 16);
    }

    #[test]
    fn discover_go_types_marks_self_and_element() {
        let slice = make_slice(8);
        let mut discovered = HashSet::new();
        assert!(slice.discover_go_types(&mut discovered).unwrap());
        assert_eq!(discovered, HashSet::from([0x9000, 1]));
    }

    #[test]
    fn discover_go_types_false_when_already_discovered() {
        let slice = make_slice(8);
        let mut discovered = HashSet::from([0x9000]);
        assert!(!slice.discover_go_types(&mut discovered).unwrap());
    }

    #[test]
    fn structure_markup_names_namespace_and_label() {
        let mapper = mapper_for(element_type("int", 8, "mypkg"), 8, Some("main.Ints"));
        let slice: GoSliceType = read_at(&mapper, &image(24, 8, true), 0x9000);
        assert_eq!(slice.get_structure_namespace().unwrap(), "mypkg");
        assert_eq!(slice.structure_name().unwrap().as_deref(), Some("main.Ints"));
        assert_eq!(slice.structure_label().unwrap().as_deref(), Some("main.Ints___Slice_type"));
    }

    #[test]
    fn type_decl_string_includes_brackets_and_element_name() {
        let decl = make_slice(8).type_decl_string().unwrap();
        assert!(decl.starts_with("type "));
        assert!(decl.contains("[]"));
        assert!(decl.contains("int"));
    }
}
