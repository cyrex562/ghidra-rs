//! Tests of the derive-driven structure mapping framework: the generated descriptor tables,
//! reading structures through [`DataTypeMapper`], variable length structure data types, and
//! markup through a [`MarkupSession`].

use std::sync::Arc;

use super::structure_mapped::{FieldValueKind, OutputDataType, PrimitiveKind, StructureMapped};
use super::test_support::{byte_reader, simple, structure, test_program, TagContext};
use super::{DataTypeMapper, Signedness, StructureContext, StructureMapped as DeriveStructureMapped};
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::category_path::ROOT;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;

// ---------------------------------------------------------------------------------------------
// fixtures

#[derive(DeriveStructureMapped)]
#[structure_mapping(structure_name = "inner", verifier)]
struct TestInner {
    #[context_field]
    context: StructureContext<TestInner>,
    #[field_mapping]
    value: u8,
}

impl super::StructureVerifier for TestInner {
    fn is_valid(&self) -> bool {
        self.value != 0xff
    }
}

#[derive(DeriveStructureMapped)]
#[structure_mapping(
    structure_name = ["runtime.functab", "internal/abi.Functab"],
    after_read = after_read,
    markup = get_nested
)]
pub(crate) struct TestFunctab {
    #[context_field]
    context: StructureContext<TestFunctab>,
    #[context_field]
    tag: Arc<String>,
    #[field_mapping(present_when = "1.18+", setter = set_entryoff)]
    #[markup_reference(get_entry_address)]
    entryoff: i64,
    #[field_mapping(field_name = ["funcOff", "funcoff"], signedness = Unsigned)]
    #[eol_comment]
    pub(crate) funcoff: u32,
    #[field_mapping]
    ptr_to_this: i32,
    #[field_mapping(length = 2, signedness = Unsigned)]
    #[plate_comment(describe)]
    short_len: i64,
    #[field_mapping(optional)]
    not_in_structure: i64,
    #[field_mapping]
    #[markup]
    nested: Option<TestInner>,

    entry_plus_one: i64,
    after_called: bool,
}

impl TestFunctab {
    fn set_entryoff(&mut self, entryoff: i64) {
        self.entryoff = entryoff;
        self.entry_plus_one = entryoff + 1;
    }

    fn after_read(&mut self) {
        self.after_called = true;
    }

    fn get_entry_address(&self) -> Option<crate::program::model::address::Address> {
        Some(self.context.get_structure_address().add_wrap(self.entryoff))
    }

    fn get_nested(&self) -> &Option<TestInner> {
        &self.nested
    }

    fn describe(&self) -> String {
        format!("len={}", self.short_len)
    }
}

/// `runtime.functab`: entryoff@0 (8), funcOff@8 (4), ptrToThis@12 (4), shortLen@16 (4),
/// nested@20 (1).
fn functab_types() -> Vec<Arc<dyn Fn() -> Box<dyn DataType> + Send + Sync>> {
    vec![
        Arc::new(|| {
            Box::new(structure(
                "runtime.functab",
                vec![
                    ("entryoff", simple("long", 8)),
                    ("funcOff", simple("uint", 4)),
                    ("ptrToThis", simple("int", 4)),
                    ("shortLen", simple("int", 4)),
                    ("nested", Box::new(structure("inner", vec![("value", simple("byte", 1))]))),
                ],
            )) as Box<dyn DataType>
        }),
        Arc::new(|| Box::new(structure("inner", vec![("value", simple("byte", 1))])) as Box<dyn DataType>),
        Arc::new(|| simple("byte", 1)),
    ]
}

fn functab_bytes() -> Vec<u8> {
    let mut b = vec![0xAA; 4]; // 4 bytes of padding before the structure
    b.extend_from_slice(&0x1000i64.to_le_bytes()); // entryoff
    b.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff]); // funcOff (unsigned)
    b.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff]); // ptrToThis (signed)
    b.extend_from_slice(&[0x34, 0x12, 0x99, 0x99]); // shortLen, only 2 bytes read
    b.push(0x07); // nested.value
    b.extend_from_slice(&[0xBB; 3]);
    b
}

/// A mapper with `TestFunctab` registered, and an instance read from [`functab_bytes`] at 4.
pub(crate) fn read_test_functab() -> (DataTypeMapper, TestFunctab) {
    let mapper = functab_mapper(vec!["1.18+"]);
    let mut reader = byte_reader(functab_bytes(), true);
    reader.set_pointer_index(4);
    let ft = mapper.read_structure(reader.as_mut()).unwrap();
    (mapper, ft)
}

fn functab_mapper(tags: Vec<&'static str>) -> DataTypeMapper {
    let (program, _) = test_program(functab_types());
    let mut mapper = DataTypeMapper::new(program, None).unwrap();
    mapper.add_program_search_category_path(&[ROOT.clone()]);
    mapper.set_context_value(Arc::new("injected".to_string()));
    let ctx = TagContext(tags);
    mapper.register_structure::<TestInner>(&ctx).unwrap();
    mapper.register_structure::<TestFunctab>(&ctx).unwrap();
    mapper
}

// ---------------------------------------------------------------------------------------------
// generated descriptor tables

#[test]
fn derived_descriptor_mirrors_the_annotations() {
    let d = TestFunctab::descriptor();
    assert_eq!(d.type_name, "TestFunctab");
    assert_eq!(d.structure_names, &["runtime.functab", "internal/abi.Functab"]);
    assert!(!d.is_structure_reader);
    assert!(d.is_valid.is_none());
    assert!(d.structure_markup.is_none());
    assert_eq!(d.after_read.len(), 1);
    assert_eq!(d.markup_getters.len(), 1);

    let names: Vec<&str> = d.fields.iter().map(|f| f.name).collect();
    assert_eq!(names, ["entryoff", "funcoff", "ptr_to_this", "short_len", "not_in_structure", "nested"]);

    let entryoff = &d.fields[0];
    let m = entryoff.mapping.unwrap();
    assert_eq!(m.present_when, "1.18+");
    assert_eq!(m.length, -1);
    assert_eq!(m.signedness, Signedness::Unspecified);
    assert!(m.field_names.is_empty());
    assert_eq!(entryoff.search_name, "entryoff");
    assert_eq!(entryoff.kind, FieldValueKind::Primitive(PrimitiveKind::Long));
    assert!(entryoff.markup_reference.is_some());
    assert!(entryoff.eol_comment.is_none());

    let funcoff = &d.fields[1];
    assert_eq!(funcoff.mapping.unwrap().field_names, &["funcOff", "funcoff"]);
    assert_eq!(funcoff.mapping.unwrap().signedness, Signedness::Unsigned);
    assert_eq!(funcoff.kind, FieldValueKind::Primitive(PrimitiveKind::Int));
    assert!(funcoff.eol_comment.is_some());

    // Rust snake_case field names are searched for under the Java (lower camel case) name
    assert_eq!(d.fields[2].search_name, "ptrToThis");
    assert_eq!(d.fields[3].mapping.unwrap().length, 2);
    assert!(d.fields[3].plate_comment.is_some());
    assert!(d.fields[4].mapping.unwrap().optional);

    let nested = &d.fields[5];
    assert_eq!(nested.kind, FieldValueKind::StructureMapped);
    assert!(nested.read_nested.is_some());
    assert!(nested.markup_nested.is_some());

    let inner = TestInner::descriptor();
    assert!(inner.is_valid.is_some());
    assert_eq!(inner.fields[0].kind, FieldValueKind::Primitive(PrimitiveKind::Byte));
}

#[test]
fn mapping_info_binds_fields_to_the_ghidra_structure() {
    let mapper = functab_mapper(vec!["1.18+"]);
    let smi = mapper.get_structure_mapping_info::<TestFunctab>().unwrap();
    assert_eq!(smi.get_structure_name(), "runtime.functab");
    assert_eq!(smi.get_description(), "TestFunctab-runtime.functab");
    assert_eq!(smi.get_structure_length(), 21);
    // the optional field that the structure lacks is skipped
    let names: Vec<&str> = smi.get_fields().iter().map(|f| f.get_field().name).collect();
    assert_eq!(names, ["entryoff", "funcoff", "ptr_to_this", "short_len", "nested"]);

    let funcoff = smi.get_field_info("funcoff").unwrap();
    assert_eq!(funcoff.get_field_name(), "funcOff");
    assert_eq!(funcoff.get_dtc().unwrap().offset, 8);
    assert_eq!(funcoff.get_length(), 4);
    assert!(funcoff.is_unsigned());
    // a non-integer structure field defaults to signed
    let ptr = smi.get_field_info("ptr_to_this").unwrap();
    assert_eq!(ptr.get_signedness(), Signedness::Signed);
    // an explicit length overrides the structure field's
    assert_eq!(smi.get_field_info("short_len").unwrap().get_length(), 2);
    assert!(smi.get_field_info("nope").is_err());

    use super::field_mapping_info::FieldMarkupKind;
    assert_eq!(smi.get_field_info("entryoff").unwrap().get_markup_funcs(), [FieldMarkupKind::Reference]);
    assert_eq!(smi.get_field_info("short_len").unwrap().get_markup_funcs(), [FieldMarkupKind::PlateComment]);
    assert_eq!(smi.get_field_info("nested").unwrap().get_markup_funcs(), [FieldMarkupKind::Nested]);
    assert_eq!(mapper.get_structure_data_type_name::<TestFunctab>().as_deref(), Some("runtime.functab"));
}

// ---------------------------------------------------------------------------------------------
// reading

#[test]
fn reads_a_structure_from_a_byte_buffer() {
    let mapper = functab_mapper(vec!["1.18+"]);
    let mut reader = byte_reader(functab_bytes(), true);
    reader.set_pointer_index(4);
    let ft: TestFunctab = mapper.read_structure(reader.as_mut()).unwrap();

    assert_eq!(ft.entryoff, 0x1000);
    assert_eq!(ft.entry_plus_one, 0x1001, "setter was used");
    assert_eq!(ft.funcoff, 0xffff_fffe, "unsigned 4 byte read");
    assert_eq!(ft.ptr_to_this, -2, "signed 4 byte read");
    assert_eq!(ft.short_len, 0x1234, "length override reads only 2 bytes");
    assert_eq!(ft.not_in_structure, 0);
    assert_eq!(ft.nested.as_ref().unwrap().value, 7);
    assert!(ft.after_called);
    assert_eq!(*ft.tag, "injected");

    // the reader is left at the end of the structure
    assert_eq!(reader.get_pointer_index(), 4 + 21);

    let ctx = ft.structure_context().unwrap();
    assert_eq!(ctx.get_structure_start(), 4);
    assert_eq!(ctx.get_structure_end(), 25);
    assert_eq!(ctx.get_structure_length(), 21);
    assert_eq!(ctx.get_structure_address().offset(), 4);
    assert_eq!(ctx.get_field_location(8), 12);
    assert_eq!(ctx.to_string(), "StructureContext<TestFunctab> { offset: 4}");

    // the nested structure has its own context, and knows the field it was read from
    let inner_ctx = ft.nested.as_ref().unwrap().structure_context().unwrap();
    assert_eq!(inner_ctx.get_structure_start(), 24);
    assert_eq!(inner_ctx.get_containing_field_data_type().unwrap().get_name(), "inner");
    assert_eq!(mapper.get_address_of_structure(&ft).unwrap().offset(), 4);
    assert_eq!(mapper.get_max_address_of_structure(&ft).unwrap().offset(), 24);
}

#[test]
fn big_endian_reads_and_absent_fields() {
    // without the "1.18+" tag, entryoff is not present and is not read
    let mapper = functab_mapper(vec![]);
    let smi = mapper.get_structure_mapping_info::<TestFunctab>().unwrap();
    assert!(smi.get_field_info("entryoff").is_err());

    let mut bytes = vec![0u8; 8];
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // funcOff BE
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xfd]); // ptrToThis BE
    bytes.extend_from_slice(&[0x12, 0x34, 0x00, 0x00]); // shortLen BE, 2 bytes
    bytes.push(0x09);
    let mut reader = byte_reader(bytes, false);
    let ft: TestFunctab = mapper.read_structure(reader.as_mut()).unwrap();
    assert_eq!(ft.entryoff, 0);
    assert_eq!(ft.entry_plus_one, 0, "setter not called for an absent field");
    assert_eq!(ft.funcoff, 0x0102);
    assert_eq!(ft.ptr_to_this, -3);
    assert_eq!(ft.short_len, 0x1234);
    assert_eq!(ft.nested.unwrap().value, 9);
}

#[test]
fn verifier_rejects_invalid_nested_data() {
    let mapper = functab_mapper(vec!["1.18+"]);
    let mut bytes = functab_bytes();
    bytes[4 + 20] = 0xff; // TestInner::is_valid fails
    let mut reader = byte_reader(bytes, true);
    reader.set_pointer_index(4);
    let err = mapper.read_structure::<TestFunctab>(reader.as_mut()).err().unwrap();
    assert_eq!(err.to_string(), "Invalid data for struct @0x18");
}

#[test]
fn registration_errors_match_java() {
    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = "inner")]
    struct NeedsMissingField {
        #[field_mapping]
        value: u8,
        #[field_mapping]
        absent: u8,
    }

    let (program, _) = test_program(functab_types());
    let mut mapper = DataTypeMapper::new(program, None).unwrap();
    mapper.add_program_search_category_path(&[ROOT.clone()]);
    let ctx = TagContext(vec![]);
    let err = mapper.register_structure::<NeedsMissingField>(&ctx).unwrap_err();
    assert_eq!(err.to_string(), "Missing structure field: inner.[\"absent\"] for NeedsMissingField.absent");

    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = ["nope1", "nope2"])]
    struct NoStruct {
        #[field_mapping]
        value: u8,
    }
    let err = mapper.register_structure::<NoStruct>(&ctx).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Missing struct definition for class NoStruct, structure name: [nope1|nope2]"
    );

    // reading an unregistered type
    let mut reader = byte_reader(vec![0; 4], true);
    let err = mapper.read_structure::<TestInner>(reader.as_mut()).err().unwrap();
    assert_eq!(err.to_string(), "Unknown structure mapped class: TestInner");

    // a missing context value
    mapper.register_structure::<TestInner>(&ctx).unwrap();
    mapper.register_structure::<TestFunctab>(&TagContext(vec!["1.18+"])).unwrap();
    let mut reader = byte_reader(functab_bytes(), true);
    let err = mapper.read_structure::<TestFunctab>(reader.as_mut()).err().unwrap();
    assert!(err.to_string().starts_with("Unsupported context field: TestFunctab.tag"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// variable length structures

#[derive(DeriveStructureMapped)]
#[structure_mapping(structure_name = "GoVarlen", reader)]
struct TestVarlen {
    #[context_field]
    context: StructureContext<TestVarlen>,
    #[field_output(ordinal = 1, data_type_name = "byte")]
    tag: u8,
    #[field_output(ordinal = 2, variable_length, getter = data_data_type)]
    data: Vec<u8>,
    #[field_output(ordinal = 0, data_type_name = "byte")]
    len: u8,
}

impl TestVarlen {
    fn data_data_type(&self) -> std::io::Result<OutputDataType> {
        let arr = ArrayDataType::with_element_length(simple("byte", 1), self.data.len() as i32, -1)
            .map_err(std::io::Error::other)?;
        Ok(OutputDataType::DataType(Box::new(arr)))
    }
}

impl super::StructureReader for TestVarlen {
    fn read_structure(&mut self, reader: &mut dyn BinaryReader, _mapper: &DataTypeMapper) -> std::io::Result<()> {
        self.len = reader.read_next_byte()?;
        self.tag = reader.read_next_byte()?;
        self.data = reader.read_next_byte_array(self.len as usize)?;
        Ok(())
    }
}

#[test]
fn variable_length_structure_data_type_matches_java_layout() {
    let (program, _) = test_program(vec![Arc::new(|| simple("byte", 1))]);
    let mut mapper = DataTypeMapper::new(program, None).unwrap();
    mapper.add_program_search_category_path(&[ROOT.clone()]);
    // a StructureReader with a single structure name registers without a structure data type
    mapper.register_structure::<TestVarlen>(&TagContext(vec![])).unwrap();
    let smi = mapper.get_structure_mapping_info::<TestVarlen>().unwrap();
    assert!(smi.get_structure_data_type().is_none());
    // output fields are ordered by ordinal
    let order: Vec<&str> = smi.get_output_fields().iter().map(|f| f.get_field().name).collect();
    assert_eq!(order, ["len", "tag", "data"]);

    let mut reader = byte_reader(vec![3, 0x42, b'a', b'b', b'c', 0xEE], true);
    let v: TestVarlen = mapper.read_structure(reader.as_mut()).unwrap();
    assert_eq!((v.len, v.tag, v.data.as_slice()), (3, 0x42, &b"abc"[..]));
    assert_eq!(reader.get_pointer_index(), 5, "self-reading structure positions the reader");

    let ctx = v.structure_context().unwrap();
    assert_eq!(ctx.get_structure_length(), 0, "no data type until one is created");
    let dt = ctx.get_structure_data_type_for(&v, &mapper).unwrap();
    // Java: "GoVarlen" + "_%d" per variable length field, sized by that field
    assert_eq!(dt.get_name(), "GoVarlen_3");
    assert_eq!(dt.get_length(), 5);
    let s: &dyn Structure = dt.as_structure().unwrap();
    let fields: Vec<(Option<String>, i32, i32)> = s
        .get_defined_components()
        .iter()
        .map(|c| (c.get_field_name(), c.get_offset(), c.get_length()))
        .collect();
    assert_eq!(
        fields,
        [(Some("len".to_string()), 0, 1), (Some("tag".to_string()), 1, 1), (Some("data".to_string()), 2, 3)]
    );
    // cached on the instance's context afterwards
    assert_eq!(v.structure_context().unwrap().get_structure_length(), 5);
}

#[test]
fn primitive_output_needs_a_matching_integer_type() {
    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = "Prim", reader)]
    struct Prim {
        #[context_field]
        context: StructureContext<Prim>,
        #[field_output]
        value: u8,
    }
    impl super::StructureReader for Prim {
        fn read_structure(&mut self, reader: &mut dyn BinaryReader, _m: &DataTypeMapper) -> std::io::Result<()> {
            self.value = reader.read_next_byte()?;
            Ok(())
        }
    }
    let (program, _) = test_program(vec![Arc::new(|| simple("byte", 1))]);
    let mut mapper = DataTypeMapper::new(program, None).unwrap();
    mapper.add_program_search_category_path(&[ROOT.clone()]);
    mapper.register_structure::<Prim>(&TagContext(vec![])).unwrap();
    let mut reader = byte_reader(vec![1], true);
    let p: Prim = mapper.read_structure(reader.as_mut()).unwrap();
    // "byte" is found but is not an integer data type of the requested signedness, and the
    // built-in fallback is unported: reported, not guessed
    let err = p.structure_context().unwrap().get_structure_data_type_for(&p, &mapper).err().unwrap();
    assert!(err.to_string().contains("getSignedDataType is not ported"), "{err}");
}

#[test]
fn nested_output_uses_the_nested_structure_data_type() {
    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = "Outer", reader)]
    struct Outer {
        #[context_field]
        context: StructureContext<Outer>,
        #[field_output(variable_length)]
        inner: Option<TestVarlen>,
    }
    impl super::StructureReader for Outer {
        fn read_structure(&mut self, reader: &mut dyn BinaryReader, m: &DataTypeMapper) -> std::io::Result<()> {
            self.inner = Some(m.read_structure(reader)?);
            Ok(())
        }
    }
    let (program, _) = test_program(vec![Arc::new(|| simple("byte", 1))]);
    let mut mapper = DataTypeMapper::new(program, None).unwrap();
    mapper.add_program_search_category_path(&[ROOT.clone()]);
    mapper.register_structure::<TestVarlen>(&TagContext(vec![])).unwrap();
    mapper.register_structure::<Outer>(&TagContext(vec![])).unwrap();

    let mut reader = byte_reader(vec![2, 0x10, b'h', b'i'], true);
    let outer: Outer = mapper.read_structure(reader.as_mut()).unwrap();
    let dt = outer.structure_context().unwrap().get_structure_data_type_for(&outer, &mapper).unwrap();
    assert_eq!(dt.get_name(), "Outer_4");
    let s = dt.as_structure().unwrap();
    let comps = s.get_defined_components();
    assert_eq!(comps.len(), 1);
    assert_eq!(comps[0].get_field_name().as_deref(), Some("inner"));
    assert_eq!(comps[0].get_data_type().get_name(), "GoVarlen_2");
    assert_eq!(comps[0].get_length(), 4);

    // a nested value that is absent adds nothing
    let empty = Outer {
        context: mapper.create_artificial_structure_context::<Outer>().unwrap(),
        inner: None,
    };
    let dt = empty.structure_context().unwrap().get_structure_data_type_for(&empty, &mapper).unwrap();
    // Java still appends the (zero) size of a variable length field that added nothing
    assert_eq!(dt.get_name(), "Outer_0");
    assert_eq!(empty.structure_context().unwrap().get_structure_start(), -1);
}

// ---------------------------------------------------------------------------------------------
// markup

/// A `ProgramDB` over the small test language `program_db.rs`'s own tests decode.
fn test_program_db() -> crate::program::database::program_db::ProgramDB {
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;
    let mut data = vec![];
    data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
    data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
    data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
    data.extend_from_slice(&[
        0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA, 0x21,
        1, 0xA0, 0xA5,
    ]);
    data.extend_from_slice(&[0xA0, 0x80 | 34]);
    data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
    data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
    data.extend_from_slice(&[0xA0, 0x80 | 38]);
    data.extend_from_slice(&[0xA0, 0x80 | 33]);
    let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![]));
    let decoder = PackedDecode::new(factory, data);
    let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());
    crate::program::database::program_db::ProgramDB::new("golang".to_string(), language).unwrap()
}

#[test]
fn markup_session_labels_structures_in_a_program_db() {
    use crate::program::model::symbol::SymbolTable;
    use crate::util::task::DummyMonitor;

    let program = Arc::new(test_program_db());
    let symbols = program.get_symbol_table();
    let mut mapper = DataTypeMapper::new(program.clone(), None).unwrap();
    // a StructureReader type needs no structure data type in the program
    mapper.register_structure::<TestVarlen>(&TagContext(vec![])).unwrap();
    let mut bytes = vec![0u8; 0x40];
    bytes.extend_from_slice(&[1, 0x42, b'z']);
    let mut reader = byte_reader(bytes, true);
    reader.set_pointer_index(0x40);
    let v: TestVarlen = mapper.read_structure(reader.as_mut()).unwrap();

    let monitor = DummyMonitor;
    let mut session = mapper.create_markup_session(&monitor);
    session.label_structure(&v, "go:varlen name", None).unwrap();
    let addr = mapper.get_data_address(0x40);
    session.label_address(&mapper.get_data_address(0x41), "second").unwrap();

    let table = symbols.read().unwrap();
    let names: Vec<String> = table.get_symbols(&addr).unwrap().iter().map(|s| s.get_name().to_string()).collect();
    // SymbolUtilities.replaceInvalidChars(name, true) turns the space into an underscore
    assert_eq!(names, ["go:varlen_name"]);
    let names: Vec<String> = table
        .get_symbols(&mapper.get_data_address(0x41))
        .unwrap()
        .iter()
        .map(|s| s.get_name().to_string())
        .collect();
    assert_eq!(names, ["second"]);
}

#[test]
fn markup_session_runs_field_markup_in_java_order() {
    use crate::util::task::DummyMonitor;

    let mapper = functab_mapper(vec!["1.18+"]);
    let mut reader = byte_reader(functab_bytes(), true);
    reader.set_pointer_index(4);
    let ft: TestFunctab = mapper.read_structure(reader.as_mut()).unwrap();
    let monitor = DummyMonitor;
    let mut session = mapper.create_markup_session(&monitor);
    // the first field markup function is entryoff's @MarkupReference, which needs the
    // program's reference manager; the test program has none
    let err = session.markup(&ft, true).unwrap_err();
    assert_eq!(err.to_string(), "Program has no reference manager");

    // without the reference field, the next markup function is funcoff's @EOLComment
    let mapper = functab_mapper(vec![]);
    let mut reader = byte_reader(functab_bytes()[4..].to_vec(), true);
    let ft: TestFunctab = mapper.read_structure(reader.as_mut()).unwrap();
    let mut session = mapper.create_markup_session(&monitor);
    let err = session.markup(Some(&ft), true).unwrap_err();
    assert_eq!(err.to_string(), "Program has no listing to add comments to");

    // the reference getter and comment values themselves
    let d = TestFunctab::descriptor();
    assert_eq!((d.fields[0].markup_reference.unwrap())(&ft).unwrap().unwrap().offset(), 0);
    assert_eq!((d.fields[1].eol_comment.unwrap())(&ft).unwrap().as_deref(), Some("4294967294"));
    assert_eq!((d.fields[3].plate_comment.unwrap())(&ft).unwrap().as_deref(), Some("len=4660"));
}

#[test]
fn comment_values_render_like_java_to_string() {
    use super::structure_mapped::CommentValue;
    assert_eq!(vec![1, 2, 3].comment_text().unwrap().as_deref(), Some("[1, 2, 3]"));
    assert_eq!(Vec::<i32>::new().comment_text().unwrap(), None, "empty collections add no comment");
    assert_eq!(Option::<String>::None.comment_text().unwrap(), None);
    assert_eq!((&-5i64).comment_text().unwrap().as_deref(), Some("-5"));
    let err: std::io::Result<String> = Err(std::io::Error::other("boom"));
    assert!(err.comment_text().is_err());
}
