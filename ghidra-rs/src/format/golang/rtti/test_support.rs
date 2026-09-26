//! Test fixtures for the Go RTTI structure mapped types: the Go runtime structure data types
//! (64-bit layouts, as Go 1.18+ emits them), a [`DataTypeMapper`] with every ported Go RTTI type
//! registered against them, and a little-endian byte image builder.

use std::sync::Arc;

use crate::format::golang::rtti::go_func_data::GoFuncData;
use crate::format::golang::rtti::go_functab_entry::GoFunctabEntry;
use crate::format::golang::rtti::go_itab::GoItab;
use crate::format::golang::rtti::types::go_array_type::GoArrayType;
use crate::format::golang::rtti::types::go_base_type::GoBaseType;
use crate::format::golang::rtti::types::go_slice_type::GoSliceType;
use crate::format::golang::rtti::types::go_uncommon_type::GoUncommonType;
use crate::format::golang::structmapping::test_support::{byte_reader, simple, structure, test_mapper, TagContext};
use crate::format::golang::structmapping::{DataTypeMapper, StructureMapped};
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::golang::go_ver::GoVer;
use crate::format::seam_stubs::{GoModuledata, GoName, GoRttiMapper, GoSlice, GoSymbolName, GoTypeManager};
use crate::program::database::sourcemap::SourceFile;
use crate::program::model::address::Address;
use crate::program::model::listing::function::Function;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

type TypeFactory = Arc<dyn Fn() -> Box<dyn DataType> + Send + Sync>;

/// A structure whose components are plain integers of the given byte lengths.
fn int_struct(name: &str, fields: &[(&str, i32)]) -> StructureDataTypeImpl {
    structure(
        name,
        fields
            .iter()
            .map(|(n, len)| {
                let dt_name = match len {
                    1 => "uint8",
                    2 => "uint16",
                    4 => "uint32",
                    _ => "uint64",
                };
                (*n, simple(dt_name, *len))
            })
            .collect(),
    )
}

/// `runtime._type`, 48 bytes: `size`@0, `ptrdata`@8, `tflag`@20, `kind`@23, `str`@40,
/// `ptrToThis`@44.
pub fn base_type_struct() -> StructureDataTypeImpl {
    int_struct(
        "runtime._type",
        &[
            ("size", 8),
            ("ptrdata", 8),
            ("hash", 4),
            ("tflag", 1),
            ("align", 1),
            ("fieldAlign", 1),
            ("kind", 1),
            ("equal", 8),
            ("gcdata", 8),
            ("str", 4),
            ("ptrToThis", 4),
        ],
    )
}

/// A `GoType` specialization: the `typ` base type followed by `fields`.
fn go_type_struct(name: &str, fields: &[(&str, i32)]) -> StructureDataTypeImpl {
    let mut components: Vec<(&str, Box<dyn DataType>)> = vec![("typ", Box::new(base_type_struct()))];
    for (n, len) in fields {
        components.push((*n, simple("uint64", *len)));
    }
    structure(name, components)
}

/// `runtime.arraytype`, 72 bytes: `typ`@0, `elem`@48, `slice`@56, `len`@64.
pub fn array_type_struct() -> StructureDataTypeImpl {
    go_type_struct("runtime.arraytype", &[("elem", 8), ("slice", 8), ("len", 8)])
}

/// `runtime.slicetype`, 56 bytes: `typ`@0, `elem`@48.
pub fn slice_type_struct() -> StructureDataTypeImpl {
    go_type_struct("runtime.slicetype", &[("elem", 8)])
}

/// `runtime.uncommontype`, 16 bytes: `pkgpath`@0, `mcount`@4, `xcount`@6, `moff`@8.
pub fn uncommon_type_struct() -> StructureDataTypeImpl {
    int_struct("runtime.uncommontype", &[("pkgpath", 4), ("mcount", 2), ("xcount", 2), ("moff", 4), ("_", 4)])
}

/// `runtime.itab`, 32 bytes: `inter`@0, `_type`@8, `fun`@24.
pub fn itab_struct() -> StructureDataTypeImpl {
    int_struct("runtime.itab", &[("inter", 8), ("_type", 8), ("hash", 4), ("_", 4), ("fun", 8)])
}

/// `runtime._func` (Go 1.18+), 44 bytes: `entryOff`@0, `nameOff`@4, `deferreturn`@12,
/// `pcsp`@16, `pcfile`@20, `pcln`@24, `npcdata`@28, `cuOffset`@32, `funcID`@40, `flag`@41,
/// `nfuncdata`@43.
pub fn func_struct() -> StructureDataTypeImpl {
    int_struct(
        "runtime._func",
        &[
            ("entryOff", 4),
            ("nameOff", 4),
            ("args", 4),
            ("deferreturn", 4),
            ("pcsp", 4),
            ("pcfile", 4),
            ("pcln", 4),
            ("npcdata", 4),
            ("cuOffset", 4),
            ("startLine", 4),
            ("funcID", 1),
            ("flag", 1),
            ("_", 1),
            ("nfuncdata", 1),
        ],
    )
}

/// `runtime.functab` (Go 1.18+), 8 bytes: `entryoff`@0, `funcoff`@4.
pub fn functab_struct() -> StructureDataTypeImpl {
    int_struct("runtime.functab", &[("entryoff", 4), ("funcoff", 4)])
}

/// The `presentWhen` tags of a Go 1.18+ binary.
pub fn go118_tags() -> TagContext {
    TagContext(vec!["1.16+", "1.17+", "1.18+"])
}

/// A mapper whose program holds the Go runtime structures above, with every ported Go RTTI type
/// registered and `rtti` published as the `GoRttiMapper` `#[context_field]` value.
pub fn go_mapper(rtti: Arc<dyn GoRttiMapper>) -> DataTypeMapper {
    go_mapper_with_tags(rtti, go118_tags())
}

/// [`go_mapper`], registering the types with the given `presentWhen` tags.
pub fn go_mapper_with_tags(rtti: Arc<dyn GoRttiMapper>, ctx: TagContext) -> DataTypeMapper {
    let types: Vec<TypeFactory> = vec![
        Arc::new(|| Box::new(base_type_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(array_type_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(slice_type_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(uncommon_type_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(itab_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(func_struct()) as Box<dyn DataType>),
        Arc::new(|| Box::new(functab_struct()) as Box<dyn DataType>),
    ];
    let mut mapper = test_mapper(types);
    mapper.set_context_value::<Arc<dyn GoRttiMapper>>(rtti);
    mapper.register_structure::<GoBaseType>(&ctx).expect("register GoBaseType");
    mapper.register_structure::<GoArrayType>(&ctx).expect("register GoArrayType");
    mapper.register_structure::<GoSliceType>(&ctx).expect("register GoSliceType");
    mapper.register_structure::<GoUncommonType>(&ctx).expect("register GoUncommonType");
    mapper.register_structure::<GoItab>(&ctx).expect("register GoItab");
    mapper.register_structure::<GoFuncData>(&ctx).expect("register GoFuncData");
    mapper.register_structure::<GoFunctabEntry>(&ctx).expect("register GoFunctabEntry");
    mapper
}

/// A little-endian memory image under construction.
#[derive(Default, Clone)]
pub struct Image(pub Vec<u8>);

impl Image {
    /// Writes the low `len` bytes of `value` at `offset`, growing the image as needed.
    pub fn put(&mut self, offset: i64, len: usize, value: i64) -> &mut Self {
        let offset = offset as usize;
        if self.0.len() < offset + len {
            self.0.resize(offset + len, 0);
        }
        self.0[offset..offset + len].copy_from_slice(&value.to_le_bytes()[..len]);
        self
    }

    /// Writes a `runtime._type` at `offset`.
    #[allow(clippy::too_many_arguments)]
    pub fn put_base_type(
        &mut self,
        offset: i64,
        size: i64,
        ptrdata: i64,
        tflag: i64,
        kind: i64,
        str_off: i64,
        ptr_to_this: i64,
    ) -> &mut Self {
        self.put(offset, 8, size)
            .put(offset + 8, 8, ptrdata)
            .put(offset + 20, 1, tflag)
            .put(offset + 23, 1, kind)
            .put(offset + 40, 4, str_off)
            .put(offset + 44, 4, ptr_to_this)
            .put(offset + 47, 1, 0)
    }
}

/// Reads a `T` from `image` at `offset` with `mapper`.
pub fn read_at<T: StructureMapped>(mapper: &DataTypeMapper, image: &Image, offset: i64) -> T {
    try_read_at(mapper, image, offset).expect("read structure")
}

/// Reads a `T` from `image` at `offset` with `mapper`, returning the read error.
pub fn try_read_at<T: StructureMapped>(mapper: &DataTypeMapper, image: &Image, offset: i64) -> std::io::Result<T> {
    let mut reader = byte_reader(image.0.clone(), true);
    reader.set_pointer_index(offset as u64);
    mapper.read_structure(reader.as_mut())
}

/// A `GoBaseType` read from a fresh image (for the base types of mock `GoType`s), with a
/// [`VersionOnlyRtti`] of Go 1.21 as its `GoRttiMapper`.
pub fn base_type(size: i64, ptrdata: i64, tflag: i64, kind: i64) -> GoBaseType {
    let mapper = go_mapper(Arc::new(VersionOnlyRtti(GoVer::new(1, 21, 0))));
    let mut image = Image::default();
    image.put_base_type(0, size, ptrdata, tflag, kind, 0, 0);
    read_at(&mapper, &image, 0)
}

/// A `GoRttiMapper` test double that only knows its Go version; names resolve to nothing and
/// `getSafeName` returns its default. Every other member is unused by its callers.
pub struct VersionOnlyRtti(pub GoVer);

impl GoRttiMapper for VersionOnlyRtti {
    fn resolve_name_off(&self, _ptr_in_module: i64, _off: i64) -> std::io::Result<Option<Box<dyn GoName>>> {
        Ok(None)
    }
    fn new_slice(&self, _array: i64, _len: i64, _cap: i64) -> Box<dyn GoSlice> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn go_method_structure_length(&self) -> i32 {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn get_go_ver(&self) -> GoVer {
        self.0
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
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn get_ptr_size(&self) -> i32 {
        8
    }
    fn get_code_address(&self, _offset: i64) -> Address {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn is_loaded_and_initialized(&self, _addr: Address) -> bool {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn get_data_address(&self, _offset: i64) -> Address {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn get_reader(&self, _position: i64) -> Box<dyn BinaryReader> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn find_containing_module_by_func_data(&self, _offset: i64) -> Option<Box<dyn GoModuledata>> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn parse_symbol_name(&self, _s: &str) -> Box<dyn GoSymbolName> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn get_function_at(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn new_array_data_type(&self, _element_type: &dyn DataType, _num_elements: i32) -> Box<dyn DataType> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn add_source_file(&self, _source_file: &SourceFile) -> Result<(), Box<dyn std::error::Error>> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
    fn add_source_map_entry(
        &self,
        _source_file: &SourceFile,
        _line_number: i32,
        _base_addr: &Address,
        _length: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        unimplemented!("unused by VersionOnlyRtti callers")
    }
}
