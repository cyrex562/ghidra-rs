use std::sync::Arc;

use crate::format::golang::rtti::go_func_data::GoFuncData;
use crate::format::golang::structmapping::{StructureContext, StructureMapped};
use crate::format::seam_stubs::{GoModuledata, GoRttiMapper};
use crate::program::model::address::Address;

/// A structure that Go generates that maps between a function's entry point and the location of
/// the function's [`GoFuncData`] structure.
///
/// Mirrors Ghidra's `runtime.functab` structure mapping (Java `GoFunctabEntry`), read by the
/// structure mapper.
///
/// `entryoff`, `entry`, and `funcoff` are `pub` rather than hidden behind getter/setter pairs
/// because Java populates them by reflection during structure deserialization, following the same
/// precedent as [`GoFuncData`]; [`set_entryoff`] and [`set_entry`] remain methods because the
/// deserializer calls them (`setter = ..`) for their side effect of computing
/// [`func_address`](Self::get_func_address).
///
/// [`set_entryoff`]: Self::set_entryoff
/// [`set_entry`]: Self::set_entry
#[derive(StructureMapped)]
#[structure_mapping(structure_name = "runtime.functab", markup = get_func_data)]
pub struct GoFunctabEntry {
    /// `@ContextField` injected Go binary context (Java field `programContext`).
    #[context_field]
    program_context: Arc<dyn GoRttiMapper>,
    /// `@ContextField` injected structure-read context (Java field `context`).
    #[context_field]
    context: StructureContext<GoFunctabEntry>,
    /// Relative offset of the function; present in Go 1.18+ (Java field `entryoff`).
    #[field_mapping(present_when = "1.18+", setter = set_entryoff)]
    #[markup_reference(get_func_address)]
    pub entryoff: i64,
    /// Absolute location of the function; present up to Go 1.17 (Java field `entry`).
    #[field_mapping(present_when = "-1.17", setter = set_entry)]
    #[markup_reference(get_func_address)]
    pub entry: i64,
    /// Offset into the pclntable where the function's [`GoFuncData`] starts (Java field
    /// `funcoff`).
    #[field_mapping]
    #[markup_reference(get_func_data)]
    pub funcoff: i64,

    /// Set when `entryoff` or `entry` are set (Java field `funcAddress`).
    func_address: Option<Address>,
}

impl GoFunctabEntry {
    /// Returns the structure context this entry was read with.
    pub fn get_structure_context(&self) -> &StructureContext<GoFunctabEntry> {
        &self.context
    }

    /// Sets the function's entry point using a relative offset.
    ///
    /// Called via deserialization for the `entryoff` field mapping annotation. An offset that
    /// runs off the end of the moduledata's text address space, or a missing moduledata, yields
    /// no address (Java lets `Address.add` throw here instead).
    pub fn set_entryoff(&mut self, entryoff: i64) {
        self.entryoff = entryoff;
        self.func_address =
            self.get_moduledata().and_then(|moduledata| moduledata.get_text().add(entryoff).ok());
    }

    /// Sets the function's entry point using the absolute address.
    ///
    /// Called via deserialization for the `entry` field mapping annotation.
    pub fn set_entry(&mut self, entry: i64) {
        self.entry = entry;
        self.func_address = Some(self.program_context.get_code_address(entry));
    }

    /// Returns the address of the function's entry point.
    pub fn get_func_address(&self) -> Option<&Address> {
        self.func_address.as_ref()
    }

    /// Returns the [`GoFuncData`] structure that contains metadata about the function, or `None`
    /// if this entry has no funcdata offset or its module could not be located.
    pub fn get_func_data(&self) -> std::io::Result<Option<GoFuncData>> {
        let moduledata = self.get_moduledata();
        let mut result = match &moduledata {
            Some(moduledata) if self.funcoff != 0 => {
                Some(moduledata.get_func_data_instance(self.funcoff)?)
            }
            _ => None,
        };

        if let Some(result) = result.as_mut() {
            if result.get_func_address() != self.func_address.as_ref() {
                // defeat obfuscated GoFuncData func address values with the good address
                // recovered from the functab entry
                if let Some(func_address) = &self.func_address {
                    if self.program_context.is_loaded_and_initialized(func_address.clone()) {
                        result.set_func_address_override(func_address.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    /// Returns the offset of the [`GoFuncData`] structure.
    pub fn get_funcoff(&self) -> i64 {
        self.funcoff
    }

    fn get_moduledata(&self) -> Option<Box<dyn GoModuledata>> {
        self.program_context
            .find_containing_module_by_func_data(self.context.get_structure_start())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::golang::rtti::test_support::{go_mapper, read_at, Image};
    use crate::format::seam_stubs::{GoName, GoPcValueEvaluator, GoSlice, GoSymbolName, GoTypeManager};
    use crate::program::database::sourcemap::SourceFile;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::Function;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    /// A moduledata double whose `getFuncDataInstance` reads a fresh [`GoFuncData`] and seeds its
    /// address via `set_entry`, mirroring the (possibly obfuscated) address a real
    /// `runtime._func` structure would carry.
    #[derive(Default, Clone)]
    struct MockModuledata {
        text_offset: i64,
        func_data_entry: Option<i64>,
    }

    impl GoModuledata for MockModuledata {
        fn get_text(&self) -> Address {
            test_address(self.text_offset)
        }
        fn get_gofunc(&self) -> i64 {
            unimplemented!()
        }
        fn get_funcnametab(&self) -> Option<Box<dyn GoSlice>> {
            unimplemented!()
        }
        fn get_cutab(&self) -> Option<Box<dyn GoSlice>> {
            unimplemented!()
        }
        fn get_filetab(&self) -> Option<Box<dyn GoSlice>> {
            unimplemented!()
        }
        fn get_pclntable(&self) -> Option<Box<dyn GoSlice>> {
            unimplemented!()
        }
        fn get_pctab(&self) -> Option<Box<dyn GoSlice>> {
            unimplemented!()
        }
        fn new_pc_value_evaluator(
            &self,
            _offset: i64,
            _func_entry: i64,
        ) -> std::io::Result<Box<dyn GoPcValueEvaluator>> {
            unimplemented!()
        }
        fn get_func_data_instance(&self, offset: i64) -> std::io::Result<GoFuncData> {
            let mapper = go_mapper(Arc::new(MockGoRttiMapper::default()));
            let mut image = Image::default();
            image.put(offset + 43, 1, 0);
            let mut func_data: GoFuncData = read_at(&mapper, &image, offset);
            if let Some(entry) = self.func_data_entry {
                func_data.set_entry(entry);
            }
            Ok(func_data)
        }
    }

    #[derive(Default, Clone)]
    struct MockGoRttiMapper {
        moduledata: Option<MockModuledata>,
        loaded: bool,
    }

    impl GoRttiMapper for MockGoRttiMapper {
        fn resolve_name_off(&self, _p: i64, _o: i64) -> std::io::Result<Option<Box<dyn GoName>>> {
            unimplemented!()
        }
        fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn GoSlice> {
            unimplemented!()
        }
        fn go_method_structure_length(&self) -> i32 {
            unimplemented!()
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
        fn get_go_types(&self) -> Box<dyn GoTypeManager> {
            unimplemented!()
        }
        fn get_ptr_size(&self) -> i32 {
            unimplemented!()
        }
        fn get_code_address(&self, offset: i64) -> Address {
            test_address(offset)
        }
        fn is_loaded_and_initialized(&self, _addr: Address) -> bool {
            self.loaded
        }
        fn get_data_address(&self, offset: i64) -> Address {
            test_address(offset)
        }
        fn get_reader(&self, _position: i64) -> Box<dyn BinaryReader> {
            unimplemented!()
        }
        fn find_containing_module_by_func_data(
            &self,
            _offset: i64,
        ) -> Option<Box<dyn GoModuledata>> {
            self.moduledata.clone().map(|m| Box::new(m) as Box<dyn GoModuledata>)
        }
        fn parse_symbol_name(&self, _s: &str) -> Box<dyn GoSymbolName> {
            unimplemented!()
        }
        fn get_function_at(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn new_array_data_type(
            &self,
            _element_type: &dyn DataType,
            _num_elements: i32,
        ) -> Box<dyn DataType> {
            unimplemented!()
        }
        fn add_source_file(&self, _f: &SourceFile) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
        fn add_source_map_entry(
            &self,
            _f: &SourceFile,
            _line_number: i32,
            _base_addr: &Address,
            _length: i64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    /// A `runtime.functab` read at 0x2000 with `entryoff` 0 and `funcoff` 0.
    fn entry(mapper: MockGoRttiMapper) -> GoFunctabEntry {
        read_entry(mapper, 0, 0)
    }

    fn read_entry(mapper: MockGoRttiMapper, entryoff: i64, funcoff: i64) -> GoFunctabEntry {
        let dtm = go_mapper(Arc::new(mapper));
        let mut image = Image::default();
        image.put(0x2000, 4, entryoff).put(0x2004, 4, funcoff);
        read_at(&dtm, &image, 0x2000)
    }

    #[test]
    fn reads_the_functab_through_the_entryoff_setter() {
        let mapper = MockGoRttiMapper {
            moduledata: Some(MockModuledata { text_offset: 0x4000, func_data_entry: Some(0x4120) }),
            loaded: true,
        };
        let e = read_entry(mapper, 0x120, 0x30);
        assert_eq!((e.entryoff, e.entry, e.funcoff), (0x120, 0, 0x30));
        assert_eq!(e.get_func_address(), Some(&test_address(0x4120)));
        assert_eq!(e.get_structure_context().get_structure_start(), 0x2000);
        assert_eq!(e.get_structure_context().get_structure_length(), 8);

        let d = GoFunctabEntry::descriptor();
        assert_eq!(d.markup_getters.len(), 1, "@Markup getFuncData");
        let reference = |n: &str| (d.fields.iter().find(|f| f.name == n).unwrap().markup_reference.unwrap())(&e);
        assert_eq!(reference("entryoff").unwrap(), Some(test_address(0x4120)));
        // funcoff references the GoFuncData structure, read at the funcoff offset
        let func_data_addr = reference("funcoff").unwrap().unwrap();
        assert_eq!(func_data_addr.offset(), 0x30);
    }

    #[test]
    fn set_entryoff_computes_address_from_moduledata_text() {
        let mapper = MockGoRttiMapper {
            moduledata: Some(MockModuledata { text_offset: 0x4000, func_data_entry: None }),
            loaded: false,
        };
        let mut e = entry(mapper);
        e.set_entryoff(0x120);
        assert_eq!(e.get_func_address(), Some(&test_address(0x4120)));
    }

    #[test]
    fn set_entryoff_with_no_moduledata_leaves_address_unset() {
        let mut e = entry(MockGoRttiMapper::default());
        e.set_entryoff(0x10);
        assert_eq!(e.get_func_address(), None);
    }

    #[test]
    fn set_entry_uses_program_context_code_address() {
        let mut e = entry(MockGoRttiMapper::default());
        e.set_entry(0x8000);
        assert_eq!(e.get_func_address(), Some(&test_address(0x8000)));
    }

    #[test]
    fn get_func_data_returns_none_when_funcoff_is_zero() {
        let mapper = MockGoRttiMapper {
            moduledata: Some(MockModuledata::default()),
            loaded: true,
        };
        let e = entry(mapper);
        assert!(e.get_func_data().unwrap().is_none());
        assert_eq!(e.get_funcoff(), 0);
    }

    #[test]
    fn get_func_data_overrides_obfuscated_address_when_loaded() {
        let mapper = MockGoRttiMapper {
            moduledata: Some(MockModuledata {
                text_offset: 0x4000,
                func_data_entry: Some(0xdead),
            }),
            loaded: true,
        };
        let mut e = entry(mapper);
        e.funcoff = 8;
        e.set_entryoff(0x120);

        let func_data = e.get_func_data().unwrap().unwrap();
        assert_eq!(func_data.get_func_address(), Some(&test_address(0x4120)));
    }

    #[test]
    fn get_func_data_leaves_obfuscated_address_when_not_loaded() {
        let mapper = MockGoRttiMapper {
            moduledata: Some(MockModuledata {
                text_offset: 0x4000,
                func_data_entry: Some(0xdead),
            }),
            loaded: false,
        };
        let mut e = entry(mapper);
        e.funcoff = 8;
        e.set_entryoff(0x120);

        let func_data = e.get_func_data().unwrap().unwrap();
        assert_eq!(func_data.get_func_address(), Some(&test_address(0xdead)));
    }
}
