use super::method_info::MethodInfo;
use crate::format::golang::structmapping::structure_markup::StructureMarkup;
use crate::format::seam_stubs::{GoIMethod, GoInterfaceType, GoRttiMapper, GoSlice, GoType, MarkupSession, StructureContext};
use crate::program::model::address::Address;
use crate::util::msg::Msg;

/// Mirrors Ghidra's `GoIMethod.GoIMethodInfo` nested class, pairing the address of a method
/// implementation with the interface method it implements.
///
/// The Java class also stores a back-reference to the owning [`GoItab`], but nothing in this
/// codebase consumes it and holding it here would require `GoItab` to be cheaply cloneable
/// (it isn't, since it owns trait objects); the method address and the resolved `GoIMethod`
/// cover every current use.
pub struct GoIMethodInfo {
    pub method_info: MethodInfo,
    pub imethod: Box<dyn GoIMethod>,
}

/// Represents a mapping between a Go interface and a type that implements the methods of
/// the interface.
///
/// Mirrors Ghidra's `runtime.itab` / `internal/abi.ITab` structure (Java `GoItab`).
pub struct GoItab {
    /// `@ContextField` injected Go binary context (Java field `programContext`).
    program_context: Box<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`).
    context: Box<dyn StructureContext<GoItab>>,
    /// Offset of the `runtime.interfacetype` structure this itab implements (Java field `inter`).
    pub inter: i64,
    /// Offset of the `runtime._type` structure that implements the interface (Java field `_type`).
    pub type_off: i64,
    /// Inline varlen array, specced as `uintptr[1]`, treated as a single value (Java field `fun`).
    pub fun: i64,
}

impl GoItab {
    pub fn new(
        program_context: Box<dyn GoRttiMapper>,
        context: Box<dyn StructureContext<GoItab>>,
        inter: i64,
        type_off: i64,
        fun: i64,
    ) -> Self {
        Self { program_context, context, inter, type_off, fun }
    }

    /// Returns the interface implemented by the specified type.
    ///
    /// Returns `Ok(None)` if the referenced type is not a `GoInterfaceType`.
    pub fn get_interface_type(&self) -> std::io::Result<Option<Box<dyn GoInterfaceType>>> {
        let result = self.program_context.get_go_types().get_type(self.inter)?;
        Ok(result.into_interface_type())
    }

    /// Returns the type that implements the specified interface.
    pub fn get_type(&self) -> std::io::Result<Box<dyn GoType>> {
        self.program_context.get_go_types().get_type(self.type_off)
    }

    /// Returns the number of methods implemented.
    pub fn get_func_count(&self) -> std::io::Result<i64> {
        let iface = self.get_interface_type()?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "itab's inter offset is not a GoInterfaceType")
        })?;
        let methods = iface.get_methods_slice();
        Ok(std::cmp::max(1, methods.get_len()))
    }

    /// Returns an artificial slice that contains the address of the functions that implement
    /// the interface methods.
    pub fn get_fun_slice(&self) -> std::io::Result<Box<dyn GoSlice>> {
        let func_count = self.get_func_count()?;
        let fun_offset = self.context.get_structure_end() - self.program_context.get_ptr_size() as i64;
        Ok(self.program_context.new_slice(fun_offset, func_count, func_count))
    }

    fn get_interface_methods(&self) -> std::io::Result<Vec<(Address, Box<dyn GoIMethod>)>> {
        let function_addrs = self.get_fun_slice()?.read_u_int_list(self.program_context.get_ptr_size())?;
        let iface = match self.get_interface_type()? {
            Some(iface) => iface,
            None => {
                Msg::warn(
                    "GoItab",
                    &format!(
                        "Bad interface spec: {}, itab's inter offset is not a GoInterfaceType",
                        self.structure_label()?.unwrap_or_default()
                    ),
                );
                return Ok(Vec::new());
            }
        };
        let mut iface_methods = iface.get_methods()?;
        if function_addrs.len() != iface_methods.len() {
            Msg::warn(
                "GoItab",
                &format!(
                    "Bad interface spec: {}, iface length doesn't match function impl list",
                    self.structure_label()?.unwrap_or_default()
                ),
            );
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        for (i, func_offset) in function_addrs.into_iter().enumerate() {
            if func_offset == 0 {
                continue;
            }
            let addr = self.program_context.get_code_address(func_offset);
            if !self.program_context.is_loaded_and_initialized(addr.clone()) {
                continue;
            }
            results.push((addr, std::mem::replace(&mut iface_methods[i], placeholder_go_imethod())));
        }
        Ok(results)
    }

    /// Returns a list of [`GoIMethodInfo`] instances, that represent the methods implemented by
    /// the specified type / interface.
    pub fn get_method_info_list(&self) -> std::io::Result<Vec<GoIMethodInfo>> {
        Ok(self
            .get_interface_methods()?
            .into_iter()
            .map(|(addr, imethod)| GoIMethodInfo { method_info: MethodInfo::new(addr), imethod })
            .collect())
    }

    /// Adds the go types referenced by this itab's interface and implementing type to
    /// `discovered_types`. Mirrors the Java method's behavior of silently giving up (and not
    /// discovering the referenced types) if an `IOException` occurs while resolving them.
    pub fn discover_go_types(&self, discovered_types: &mut std::collections::HashSet<i64>) {
        let _: std::io::Result<()> = (|| {
            if let Some(iface_type) = self.get_interface_type()? {
                iface_type.discover_go_types(discovered_types)?;
            }
            self.get_type()?.discover_go_types(discovered_types)?;
            Ok(())
        })();
    }
}

/// Placeholder `GoIMethod` used to satisfy ownership when moving an entry out of the methods
/// list in [`GoItab::get_interface_methods`]; never observed since every slot is either moved
/// out exactly once or skipped entirely.
fn placeholder_go_imethod() -> Box<dyn GoIMethod> {
    struct Empty;
    impl GoIMethod for Empty {}
    Box::new(Empty)
}

impl StructureMarkup<GoItab> for GoItab {
    fn structure_context(&self) -> &dyn StructureContext<GoItab> {
        self.context.as_ref()
    }

    fn structure_name(&self) -> std::io::Result<Option<String>> {
        let type_symbol = self.get_type()?.get_symbol_name().as_string();
        let iface_name = self
            .get_interface_type()?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "itab has no interface type"))?
            .get_name();
        Ok(Some(format!("{}__implements__{}", type_symbol, iface_name)))
    }

    fn structure_label(&self) -> std::io::Result<Option<String>> {
        let name = self.structure_name()?.unwrap_or_default();
        Ok(Some(format!("{}__itab", name)))
    }

    fn structure_namespace(&self) -> std::io::Result<Option<String>> {
        Ok(Some(self.get_type()?.get_structure_namespace()?))
    }

    fn additional_markup(&self, session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: would be nice if we could override the base structure data type used to markup
        // ourself, and use a specialized itab (as created by GoInterfaceType).
        let fun_slice = self.get_fun_slice()?;
        let ptr_size = self.program_context.get_ptr_size();
        let func_addrs: Vec<Address> = fun_slice
            .read_u_int_list(ptr_size)?
            .into_iter()
            .map(|offset| self.program_context.get_code_address(offset))
            .collect();
        // this adds references from the elements of the artificial slice. However, the reference
        // from element[0] of the real "fun" array won't show anything in the UI even though
        // there is a outbound reference there.
        fun_slice.markup_element_references(ptr_size, func_addrs, session)?;

        let extra_fun_slice = fun_slice.get_sub_slice(1, fun_slice.get_len() - 1, ptr_size as i64);
        let structure_name = self.structure_name()?.unwrap_or_default();
        let namespace = self.structure_namespace()?.unwrap_or_default();
        extra_fun_slice.markup_array(
            &format!("{}_extra_itab_functions", structure_name),
            &namespace,
            None,
            true,
            session,
        )?;
        Ok(())
    }
}

impl std::fmt::Display for GoItab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rendered: std::io::Result<String> = (|| {
            let iface_type = self
                .get_interface_type()?
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "itab has no interface type"))?;
            let mut s = format!("itab for {} implements {}", self.get_type()?.get_name(), iface_type.get_name());
            let method_list_string = iface_type.get_method_list_string()?;
            if !method_list_string.is_empty() {
                s.push_str("\n// Methods\n");
                s.push_str(&method_list_string);
            }
            Ok(s)
        })();
        match rendered {
            Ok(s) => f.write_str(&s),
            Err(_) => f.write_str("GoItab"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{GoSymbolName, GoTypeManager, StructureMappingInfo};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::structure::Structure;
    use std::any::Any;
    use std::collections::HashSet;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    struct MockGoSymbolName {
        name: String,
    }

    impl GoSymbolName for MockGoSymbolName {
        fn as_string(&self) -> String {
            self.name.clone()
        }
    }

    #[derive(Clone)]
    struct MockGoType {
        name: String,
        is_iface: bool,
        methods_slice_len: i64,
        method_names: Vec<String>,
    }

    impl GoType for MockGoType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_symbol_name(&self) -> Box<dyn GoSymbolName> {
            Box::new(MockGoSymbolName { name: self.name.clone() })
        }

        fn get_structure_namespace(&self) -> std::io::Result<String> {
            Ok("mypkg".to_string())
        }

        fn discover_go_types(&self, discovered_types: &mut HashSet<i64>) -> std::io::Result<bool> {
            discovered_types.insert(if self.is_iface { 2 } else { 1 });
            Ok(true)
        }

        fn into_interface_type(self: Box<Self>) -> Option<Box<dyn GoInterfaceType>> {
            if self.is_iface { Some(Box::new(*self)) } else { None }
        }
    }

    struct MockGoSlice {
        len: i64,
        u_int_list: Vec<i64>,
    }

    impl GoSlice for MockGoSlice {
        fn is_valid(&self, _element_size: i32) -> bool {
            true
        }

        fn read_go_methods(&self) -> std::io::Result<Vec<Box<dyn crate::format::seam_stubs::GoMethod>>> {
            unimplemented!()
        }

        fn get_len(&self) -> i64 {
            self.len
        }

        fn get_sub_slice(&self, _start_element: i64, element_count: i64, _element_size: i64) -> Box<dyn GoSlice> {
            Box::new(MockGoSlice { len: element_count, u_int_list: Vec::new() })
        }

        fn read_u_int_list(&self, _int_size: i32) -> std::io::Result<Vec<i64>> {
            Ok(self.u_int_list.clone())
        }

        fn markup_element_references(
            &self,
            _element_size: i32,
            _target_addrs: Vec<Address>,
            _session: &dyn MarkupSession,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_array(
            &self,
            _slice_name: &str,
            _namespace_name: &str,
            _element_type: Option<&dyn DataType>,
            _ptr: bool,
            _session: &dyn MarkupSession,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MockGoIMethod;

    impl GoIMethod for MockGoIMethod {}

    impl GoInterfaceType for MockGoType {
        fn get_methods_slice(&self) -> Box<dyn GoSlice> {
            Box::new(MockGoSlice { len: self.methods_slice_len, u_int_list: Vec::new() })
        }

        fn get_methods(&self) -> std::io::Result<Vec<Box<dyn GoIMethod>>> {
            Ok(self.method_names.iter().map(|_| Box::new(MockGoIMethod) as Box<dyn GoIMethod>).collect())
        }

        fn get_method_list_string(&self) -> std::io::Result<String> {
            Ok(self.method_names.join(", "))
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn discover_go_types(&self, discovered_types: &mut HashSet<i64>) -> std::io::Result<bool> {
            discovered_types.insert(2);
            Ok(true)
        }
    }

    struct MockGoTypeManager {
        inter_type: Option<MockGoType>,
        type_type: MockGoType,
    }

    impl GoTypeManager for MockGoTypeManager {
        fn resolve_type_off(&self, _ptr_in_module: i64, _off: i64) -> std::io::Result<Box<dyn GoType>> {
            unimplemented!()
        }

        fn get_type(&self, offset: i64) -> std::io::Result<Box<dyn GoType>> {
            if offset == 0x10 {
                // A `None` `inter_type` still resolves to a real (non-interface) `GoType`,
                // mirroring `GoTypeManager.getType()`'s non-null contract; only the
                // `instanceof GoInterfaceType` check downstream can fail.
                Ok(Box::new(self.inter_type.clone().unwrap_or_else(|| {
                    let mut not_iface = self.type_type.clone();
                    not_iface.is_iface = false;
                    not_iface
                })))
            } else if offset == 0x20 {
                Ok(Box::new(self.type_type.clone()))
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no type at offset"))
            }
        }
    }

    /// Mock `GoRttiMapper` whose `new_slice` returns `fun_addrs` as the slice's readable
    /// contents, so `getFunSlice().readUIntList(...)` in [`GoItab`] resolves to real data.
    struct MockGoRttiMapper {
        inter_type: Option<MockGoType>,
        type_type: MockGoType,
        ptr_size: i32,
        fun_addrs: Vec<i64>,
        loaded_addrs: HashSet<i64>,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(
            &self,
            _ptr_in_module: i64,
            _off: i64,
        ) -> std::io::Result<Option<Box<dyn crate::format::seam_stubs::GoName>>> {
            unimplemented!()
        }

        fn new_slice(&self, _array: i64, len: i64, _cap: i64) -> Box<dyn GoSlice> {
            Box::new(MockGoSlice { len, u_int_list: self.fun_addrs.clone() })
        }

        fn go_method_structure_length(&self) -> i32 {
            unimplemented!()
        }

        fn get_go_ver(&self) -> crate::format::golang::go_ver::GoVer {
            unimplemented!()
        }

        fn get_safe_name(
            &self,
            _supplier: &dyn Fn() -> std::io::Result<Option<Box<dyn crate::format::seam_stubs::GoName>>>,
            _fallback_structure_name: &str,
            _fallback_structure_start: i64,
            _default_value: &str,
        ) -> String {
            unimplemented!()
        }

        fn get_go_types(&self) -> Box<dyn GoTypeManager> {
            Box::new(MockGoTypeManager { inter_type: self.inter_type.clone(), type_type: self.type_type.clone() })
        }

        fn get_ptr_size(&self) -> i32 {
            self.ptr_size
        }

        fn get_code_address(&self, offset: i64) -> Address {
            test_address(offset)
        }

        fn is_loaded_and_initialized(&self, addr: Address) -> bool {
            self.loaded_addrs.contains(&addr.offset())
        }
    }

    struct MockStructureContext {
        structure_end: i64,
    }

    impl StructureContext<GoItab> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<GoItab>> {
            struct Info;
            impl StructureMappingInfo<GoItab> for Info {
                fn structure_name(&self) -> String {
                    "runtime.itab".to_string()
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
            test_address(0x9000)
        }

        fn get_field_address(&self, _field_offset: i64) -> Address {
            unimplemented!()
        }

        fn get_field_location(&self, _field_offset: i64) -> i64 {
            unimplemented!()
        }

        fn get_structure_start(&self) -> i64 {
            0x9000
        }

        fn get_structure_end(&self) -> i64 {
            self.structure_end
        }

        fn get_structure_length(&self) -> i32 {
            unimplemented!()
        }

        fn get_structure_instance(&self) -> &GoItab {
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

    fn iface_type(methods_slice_len: i64, method_names: Vec<&str>) -> MockGoType {
        MockGoType {
            name: "MyIface".to_string(),
            is_iface: true,
            methods_slice_len,
            method_names: method_names.into_iter().map(str::to_string).collect(),
        }
    }

    fn impl_type() -> MockGoType {
        MockGoType { name: "MyStruct".to_string(), is_iface: false, methods_slice_len: 0, method_names: vec![] }
    }

    fn make_itab(inter_type: Option<MockGoType>, fun_addrs: Vec<i64>, loaded_addrs: HashSet<i64>) -> GoItab {
        GoItab::new(
            Box::new(MockGoRttiMapper {
                inter_type,
                type_type: impl_type(),
                ptr_size: 8,
                fun_addrs,
                loaded_addrs,
            }),
            Box::new(MockStructureContext { structure_end: 0x9010 }),
            0x10,
            0x20,
            0,
        )
    }

    #[test]
    fn get_type_resolves_via_type_offset() {
        let itab = make_itab(None, Vec::new(), HashSet::new());
        assert_eq!(itab.get_type().unwrap().get_name(), "MyStruct");
    }

    #[test]
    fn get_interface_type_none_when_not_an_interface() {
        let mut not_iface = iface_type(0, vec![]);
        not_iface.is_iface = false;
        let itab = make_itab(Some(not_iface), Vec::new(), HashSet::new());
        assert!(itab.get_interface_type().unwrap().is_none());
    }

    #[test]
    fn get_func_count_is_at_least_one() {
        let itab = make_itab(Some(iface_type(0, vec![])), Vec::new(), HashSet::new());
        assert_eq!(itab.get_func_count().unwrap(), 1);
    }

    #[test]
    fn get_func_count_reflects_methods_slice_len() {
        let itab = make_itab(Some(iface_type(3, vec![])), Vec::new(), HashSet::new());
        assert_eq!(itab.get_func_count().unwrap(), 3);
    }

    #[test]
    fn structure_name_combines_type_and_interface_names() {
        let itab = make_itab(Some(iface_type(0, vec![])), Vec::new(), HashSet::new());
        assert_eq!(itab.structure_name().unwrap().as_deref(), Some("MyStruct__implements__MyIface"));
    }

    #[test]
    fn structure_label_appends_itab_suffix() {
        let itab = make_itab(Some(iface_type(0, vec![])), Vec::new(), HashSet::new());
        assert_eq!(itab.structure_label().unwrap().as_deref(), Some("MyStruct__implements__MyIface__itab"));
    }

    #[test]
    fn structure_namespace_delegates_to_type() {
        let itab = make_itab(None, Vec::new(), HashSet::new());
        assert_eq!(itab.structure_namespace().unwrap().as_deref(), Some("mypkg"));
    }

    #[test]
    fn get_method_info_list_pairs_addresses_with_methods() {
        let mut loaded = HashSet::new();
        loaded.insert(0x2000);
        loaded.insert(0x3000);
        let itab =
            make_itab(Some(iface_type(2, vec!["Foo", "Bar"])), vec![0x2000, 0x3000], loaded);

        let infos = itab.get_method_info_list().unwrap();
        assert_eq!(infos.len(), 2);
        let mut addrs: Vec<i64> = infos.iter().map(|i| i.method_info.address().offset()).collect();
        addrs.sort();
        assert_eq!(addrs, vec![0x2000, 0x3000]);
    }

    #[test]
    fn get_method_info_list_skips_zero_and_unloaded_addresses() {
        let mut loaded = HashSet::new();
        loaded.insert(0x3000);
        // function_addrs[0] == 0 -> skipped; [1] not in `loaded` -> skipped; [2] kept.
        let itab = make_itab(
            Some(iface_type(3, vec!["Foo", "Bar", "Baz"])),
            vec![0, 0x2000, 0x3000],
            loaded,
        );

        let infos = itab.get_method_info_list().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].method_info.address().offset(), 0x3000);
    }

    #[test]
    fn get_method_info_list_empty_when_lengths_mismatch() {
        // 2 function addresses but only 1 interface method -> "bad interface spec" -> empty.
        let itab = make_itab(Some(iface_type(1, vec!["Foo"])), vec![0x2000, 0x3000], {
            let mut s = HashSet::new();
            s.insert(0x2000);
            s.insert(0x3000);
            s
        });
        assert!(itab.get_method_info_list().unwrap().is_empty());
    }

    #[test]
    fn discover_go_types_collects_from_type_and_interface() {
        let itab = make_itab(Some(iface_type(0, vec![])), Vec::new(), HashSet::new());
        let mut discovered = HashSet::new();
        itab.discover_go_types(&mut discovered);
        assert_eq!(discovered, HashSet::from([1, 2]));
    }

    #[test]
    fn display_falls_back_when_no_interface_type() {
        let itab = make_itab(None, Vec::new(), HashSet::new());
        assert_eq!(itab.to_string(), "GoItab");
    }

    #[test]
    fn display_lists_methods_when_present() {
        let itab = make_itab(Some(iface_type(0, vec!["Foo"])), Vec::new(), HashSet::new());
        let s = itab.to_string();
        assert!(s.starts_with("itab for MyStruct implements MyIface"));
        assert!(s.contains("// Methods\nFoo"));
    }
}
