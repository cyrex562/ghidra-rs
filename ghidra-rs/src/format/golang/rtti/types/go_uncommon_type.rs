use crate::format::seam_stubs::{GoMethod, GoName, GoRttiMapper, GoSlice, StructureContext};
use crate::util::msg::Msg;

/// Structure found immediately after a `GoType` structure, if it has the uncommon flag set.
///
/// Mirrors Ghidra's `runtime.uncommontype` / `internal/abi.UncommonType` structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GoUncommonType {
    pub pkgpath_name_off: i64,
    pub mcount: i32,
    pub xcount: i32,
    pub moff: i64,
}

impl GoUncommonType {
    pub fn new(pkgpath_name_off: i64, mcount: i32, xcount: i32, moff: i64) -> Self {
        Self { pkgpath_name_off, mcount, xcount, moff }
    }

    /// Returns the package path of the type.
    pub fn pkg_path(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoUncommonType>,
    ) -> std::io::Result<Option<Box<dyn GoName>>> {
        program_context.resolve_name_off(context.get_structure_start(), self.pkgpath_name_off)
    }

    /// Returns the package path of the type, or an empty string if it has none.
    pub fn package_path_string(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoUncommonType>,
    ) -> std::io::Result<String> {
        Ok(match self.pkg_path(program_context, context)? {
            Some(pkg_path) => pkg_path.get_name(),
            None => String::new(),
        })
    }

    /// Returns a slice containing the methods defined by the type.
    pub fn methods_slice(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoUncommonType>,
    ) -> Box<dyn GoSlice> {
        program_context.new_slice(
            context.get_field_location(self.moff),
            self.mcount as i64,
            self.mcount as i64,
        )
    }

    /// Returns a list of the methods defined by the type.
    pub fn methods(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoUncommonType>,
    ) -> std::io::Result<Vec<Box<dyn GoMethod>>> {
        let slice = self.methods_slice(program_context, context);
        if !slice.is_valid(program_context.go_method_structure_length()) {
            Msg::warn(
                "GoUncommonType",
                &format!("Bad uncommon method list: {}", context.get_structure_address()),
            );
            return Ok(Vec::new());
        }
        slice.read_go_methods()
    }

    /// Returns the location of where this object, and any known associated optional
    /// structures, ends.
    pub fn end_of_type_info(
        &self,
        program_context: &dyn GoRttiMapper,
        context: &dyn StructureContext<GoUncommonType>,
    ) -> i64 {
        if self.mcount == 0 {
            return context.get_structure_end();
        }
        // calc end of method array manually since methods_slice() is an artificial slice
        let method_array_start = context.get_field_location(self.moff);
        method_array_start + self.mcount as i64 * program_context.go_method_structure_length() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::StructureMappingInfo;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::structure::Structure;
    use std::any::Any;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

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
    }

    struct MockStructureContext {
        structure_start: i64,
        structure_end: i64,
        structure_address: Address,
        field_location: i64,
    }

    impl StructureContext<GoUncommonType> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<GoUncommonType>> {
            unimplemented!()
        }

        fn get_data_type_mapper(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_containing_field_data_type(&self) -> Box<dyn DataType> {
            unimplemented!()
        }

        fn get_structure_address(&self) -> Address {
            self.structure_address.clone()
        }

        fn get_field_address(&self, _field_offset: i64) -> Address {
            unimplemented!()
        }

        fn get_field_location(&self, _field_offset: i64) -> i64 {
            self.field_location
        }

        fn get_structure_start(&self) -> i64 {
            self.structure_start
        }

        fn get_structure_end(&self) -> i64 {
            self.structure_end
        }

        fn get_structure_length(&self) -> i32 {
            (self.structure_end - self.structure_start) as i32
        }

        fn get_structure_instance(&self) -> &GoUncommonType {
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
    fn package_path_string_resolves_nonzero_offset() {
        let uncommon = GoUncommonType::new(0x10, 2, 0, 0x20);
        let program_context = MockGoRttiMapper { go_method_structure_length: 24, slice_valid: true, methods: vec![] };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x1020,
        };

        let result = uncommon.package_path_string(&program_context, &context).unwrap();
        assert_eq!(result, "example.com/pkg");
    }

    #[test]
    fn package_path_string_empty_when_offset_zero() {
        let uncommon = GoUncommonType::new(0, 0, 0, 0);
        let program_context = MockGoRttiMapper { go_method_structure_length: 24, slice_valid: true, methods: vec![] };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x1020,
        };

        let result = uncommon.package_path_string(&program_context, &context).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn end_of_type_info_with_no_methods_returns_structure_end() {
        let uncommon = GoUncommonType::new(0, 0, 0, 0);
        let program_context = MockGoRttiMapper { go_method_structure_length: 24, slice_valid: true, methods: vec![] };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x1020,
        };

        assert_eq!(uncommon.end_of_type_info(&program_context, &context), 0x1010);
    }

    #[test]
    fn end_of_type_info_with_methods_computes_manually() {
        let uncommon = GoUncommonType::new(0, 3, 0, 0x40);
        let program_context = MockGoRttiMapper { go_method_structure_length: 16, slice_valid: true, methods: vec![] };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x2000,
        };

        // method_array_start (0x2000) + mcount (3) * structure_length (16) = 0x2030
        assert_eq!(uncommon.end_of_type_info(&program_context, &context), 0x2030);
    }

    #[test]
    fn methods_returns_empty_and_warns_when_slice_invalid() {
        let uncommon = GoUncommonType::new(0, 2, 0, 0x20);
        let program_context = MockGoRttiMapper {
            go_method_structure_length: 24,
            slice_valid: false,
            methods: vec!["Foo".to_string()],
        };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x1020,
        };

        let methods = uncommon.methods(&program_context, &context).unwrap();
        assert!(methods.is_empty());
    }

    #[test]
    fn methods_returns_slice_contents_when_valid() {
        let uncommon = GoUncommonType::new(0, 2, 0, 0x20);
        let program_context = MockGoRttiMapper {
            go_method_structure_length: 24,
            slice_valid: true,
            methods: vec!["Foo".to_string(), "Bar".to_string()],
        };
        let context = MockStructureContext {
            structure_start: 0x1000,
            structure_end: 0x1010,
            structure_address: test_address(0x1000),
            field_location: 0x1020,
        };

        let methods = uncommon.methods(&program_context, &context).unwrap();
        let names: Vec<String> = methods.iter().map(|m| m.get_name()).collect();
        assert_eq!(names, vec!["Foo".to_string(), "Bar".to_string()]);
    }
}
