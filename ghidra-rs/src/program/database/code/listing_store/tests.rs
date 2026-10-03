//! `ListingStore` tests over the toy sleigh language (`decode_tests`), in a real `ProgramDB`'s
//! memory.

use super::*;
use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
use crate::program::database::mem::MemoryMapDB;
use crate::program::model::lang::language::Language;
use std::sync::RwLock;

/// ```text
/// 0x1000: 11 2a   mov r1, 0x2a
/// 0x1002: 61 00   add r1, r0
/// 0x1004: 20 05   jmp 0x100b
/// 0x1006: 31 00   ret
/// ```
const CODE: [u8; 8] = [0x11, 0x2a, 0x61, 0x00, 0x20, 0x05, 0x31, 0x00];

struct Fixture {
    language: Arc<SleighLanguage>,
    // keeps the program (and so the memory's database) alive
    _program: crate::program::database::program_db::ProgramDB,
    memory: Arc<RwLock<MemoryMapDB>>,
    store: ListingStore,
}

impl Fixture {
    /// `CODE` at 0x1000 (initialized), and an uninitialized block of 4 bytes at 0x2000.
    fn new() -> Self {
        let language = decode_tests::language();
        let program = crate::program::database::program_db::ProgramDB::new("toy".into(), language.clone()).unwrap();
        let memory = program.get_memory();
        {
            let mut mem = memory.write().unwrap();
            let start = Address::new(language.get_default_space(), 0x1000);
            mem.create_initialized_block("code", &start, Some(&mut &CODE[..]), CODE.len() as i64, None, false)
                .unwrap();
            let bss = Address::new(language.get_default_space(), 0x2000);
            Memory::create_uninitialized_block(&mut *mem, "bss", &bss, 4, false).unwrap();
        }
        let store = ListingStore::new(language.clone());
        Fixture { language, _program: program, memory, store }
    }

    fn at(&self, offset: i64) -> Address {
        Address::new(self.language.get_default_space(), offset)
    }

    fn proto(&self, offset: i64) -> SharedPrototype {
        let addr = self.at(offset);
        let start = (offset - 0x1000) as usize;
        let buf = Arc::new(ByteMemBufferImpl::new(addr, CODE[start..].to_vec(), true));
        Arc::new(self.language.parse_prototype(buf, Vec::new(), false).unwrap())
    }

    fn create(&mut self, offset: i64) -> Result<InstructionId, CodeUnitInsertionException> {
        let proto = self.proto(offset);
        let at = self.at(offset);
        let memory = Arc::clone(&self.memory);
        let mem = memory.read().unwrap();
        self.store.create_instruction(&*mem, at, proto, None, 0)
    }

    fn units(&self, start: i64, end: i64) -> Vec<CodeUnitSummary> {
        let mem = self.memory.read().unwrap();
        self.store.code_units(&*mem, &self.at(start), &self.at(end)).collect()
    }
}

#[test]
fn a_created_instruction_is_found_at_and_within_its_range() {
    let mut f = Fixture::new();
    let id = f.create(0x1000).unwrap();
    assert_eq!(f.store.instruction_at(&f.at(0x1000)), Some(id));
    assert_eq!(f.store.instruction_at(&f.at(0x1001)), None);
    assert_eq!(f.store.instruction_containing(&f.at(0x1001)), Some(id));
    assert_eq!(f.store.instruction_containing(&f.at(0x1002)), None);
    assert_eq!(f.store.num_instructions(), 1);
    assert_eq!(f.store.record(id).length(), 2);
    assert!(f.store.context_value(id).is_none());

    let mem = f.memory.read().unwrap();
    let snapshot = f.store.snapshot(id, &*mem);
    let view = InstructionView::new(f.store.record(id), &snapshot);
    assert_eq!(view.display_string(), "mov r1,0x2a");
}

#[test]
fn neighbours_are_found_in_address_order() {
    let mut f = Fixture::new();
    let a = f.create(0x1000).unwrap();
    let c = f.create(0x1006).unwrap();
    let b = f.create(0x1002).unwrap();
    assert_eq!(f.store.instruction_after(&f.at(0x1000)), Some(b));
    assert_eq!(f.store.instruction_after(&f.at(0x1003)), Some(c));
    assert_eq!(f.store.instruction_after(&f.at(0x1006)), None);
    assert_eq!(f.store.instruction_before(&f.at(0x1006)), Some(b));
    assert_eq!(f.store.instruction_before(&f.at(0x1000)), None);
    assert_eq!(f.store.instructions_in(&f.at(0x1000), &f.at(0x1006)).collect::<Vec<_>>(), vec![a, b, c]);
    assert_ne!(a, b, "ids are never reused");
}

#[test]
fn overlapping_an_instruction_is_a_conflict_with_javas_message() {
    let mut f = Fixture::new();
    f.create(0x1002).unwrap();
    let err = f.create(0x1002).unwrap_err();
    assert_eq!(err.message(), "Conflicting instruction exists at address ram:0x1002 to ram:0x1003");
    // an instruction whose end overlaps the next one's start
    let proto = f.proto(0x1000);
    let mem = f.memory.read().unwrap();
    let at = f.at(0x1001);
    let err = f.store.create_instruction(&*mem, at, proto, None, 0).unwrap_err();
    assert_eq!(err.message(), "Conflicting instruction exists at address ram:0x1002 to ram:0x1003");
}

#[test]
fn an_instruction_must_lie_in_memory() {
    let mut f = Fixture::new();
    let proto = f.proto(0x1006);
    let mem = f.memory.read().unwrap();
    let err = f.store.create_instruction(&*mem, f.at(0x1007), proto.clone(), None, 0).unwrap_err();
    assert_eq!(err.message(), "Insufficent memory at address ram:0x1007 (length: 2 bytes)");
    // longer than the prototype: no override, but the longer range must lie in memory (Java)
    let err = f.store.create_instruction(&*mem, f.at(0x1006), proto.clone(), None, 3).unwrap_err();
    assert_eq!(err.message(), "Insufficent memory at address ram:0x1006 (length: 3 bytes)");
    assert_eq!(
        f.store.create_instruction(&*mem, f.at(0x1006), proto.clone(), None, -1).unwrap_err().message(),
        "Negative length not permitted"
    );
    let id = f.store.create_instruction(&*mem, f.at(0x1006), proto, None, 1).unwrap();
    assert_eq!((f.store.record(id).length(), f.store.record(id).parsed_length()), (1, 2));
}

#[test]
fn clearing_removes_every_instruction_the_range_touches() {
    let mut f = Fixture::new();
    f.create(0x1000).unwrap();
    f.create(0x1002).unwrap();
    let c = f.create(0x1004).unwrap();
    assert!(!f.store.is_undefined(&f.at(0x1001), &f.at(0x1001)));
    f.store.clear_code_units(&f.at(0x1001), &f.at(0x1002));
    assert!(f.store.is_undefined(&f.at(0x1000), &f.at(0x1003)));
    assert_eq!(f.store.instruction_at(&f.at(0x1004)), Some(c));
    assert_eq!(f.store.num_instructions(), 1);
}

#[test]
fn code_units_walk_instructions_and_undefined_bytes_in_address_order() {
    let mut f = Fixture::new();
    let mov = f.create(0x1000).unwrap();
    let jmp = f.create(0x1004).unwrap();
    let units = f.units(0x1001, 0x1007);
    let rows: Vec<(i64, usize, Vec<u8>, &str, String)> = units
        .iter()
        .map(|u| (u.address.offset(), u.length, u.bytes.clone(), u.mnemonic.as_str(), u.operand_text.clone()))
        .collect();
    assert_eq!(
        rows,
        vec![
            // the instruction containing the start comes first
            (0x1000, 2, vec![0x11, 0x2a], "mov", "r1,0x2a".to_string()),
            (0x1002, 1, vec![0x61], "??", "61h".to_string()),
            (0x1003, 1, vec![0x00], "??", "00h".to_string()),
            (0x1004, 2, vec![0x20, 0x05], "jmp", "0x100b".to_string()),
            (0x1006, 1, vec![0x31], "??", "31h".to_string()),
            (0x1007, 1, vec![0x00], "??", "00h".to_string()),
        ]
    );
    assert_eq!(units[0].kind, CodeUnitKind::Instruction(mov));
    assert_eq!(units[0].operands, vec!["r1".to_string(), "0x2a".to_string()]);
    assert_eq!(units[3].kind, CodeUnitKind::Instruction(jmp));
    assert!(units[3].is_instruction());
    assert_eq!(units[1].kind, CodeUnitKind::Undefined);
    assert_eq!(units[1].operands, vec!["61h".to_string()]);
}

#[test]
fn code_units_skip_gaps_between_blocks_and_show_uninitialized_bytes_as_unknown() {
    let f = Fixture::new();
    let units = f.units(0x1006, 0x2001);
    assert_eq!(
        units.iter().map(|u| (u.address.offset(), u.bytes.clone(), u.operand_text.clone())).collect::<Vec<_>>(),
        vec![
            (0x1006, vec![0x31], "31h".to_string()),
            (0x1007, vec![0x00], "00h".to_string()),
            (0x2000, vec![], "??".to_string()),
            (0x2001, vec![], "??".to_string()),
        ]
    );
    assert!(f.units(0x3000, 0x3010).is_empty());
}

#[test]
fn instruction_summaries_list_only_instructions_in_the_range() {
    let mut f = Fixture::new();
    f.create(0x1000).unwrap();
    f.create(0x1004).unwrap();
    f.create(0x1006).unwrap();
    let mem = f.memory.read().unwrap();
    let rows: Vec<(i64, String, String)> = f
        .store
        .instruction_summaries(&*mem, &f.at(0x1001), &f.at(0x1004))
        .map(|u| (u.address.offset(), u.mnemonic, u.operand_text))
        .collect();
    // starts at or after the range start: the instruction containing 0x1001 is not included
    assert_eq!(rows, vec![(0x1004, "jmp".to_string(), "0x100b".to_string())]);
    assert_eq!(f.store.instruction_summaries(&*mem, &f.at(0x1000), &f.at(0x1fff)).count(), 3);
}

#[test]
fn undefined_ranges_are_initialized_memory_without_instructions() {
    let mut f = Fixture::new();
    f.create(0x1002).unwrap();
    let mut set = crate::program::model::address::AddressSet::new();
    set.add_range(&f.at(0x0ff0), &f.at(0x2003));
    let mem = f.memory.read().unwrap();
    let undefined = f.store.undefined_ranges(&*mem, &set);
    let mut expected = crate::program::model::address::AddressSet::new();
    expected.add_range(&f.at(0x1000), &f.at(0x1001));
    expected.add_range(&f.at(0x1004), &f.at(0x1007));
    assert_eq!(undefined, expected);
}

#[test]
fn a_snapshot_answers_repeated_queries_from_its_cached_parser_context() {
    let mut f = Fixture::new();
    let id = f.create(0x1004).unwrap();
    let mem = f.memory.read().unwrap();
    let snapshot = f.store.snapshot(id, &*mem);
    assert!(snapshot.own_context.get().is_none());
    let view = InstructionView::new(f.store.record(id), &snapshot);
    assert_eq!(view.display_string(), "jmp 0x100b");
    assert!(matches!(snapshot.own_context.get(), Some(Some(_))), "the sleigh context is cached");
    // answered again from the cache, identically
    assert_eq!(view.display_string(), "jmp 0x100b");
    assert_eq!(view.operand_address(0).unwrap().offset(), 0x100b);
}

/// A stored instruction handed out as an `Instruction` trait object (over an owned snapshot),
/// for the code that asks instructions questions through the trait (`CodeUnitFormat`, p-code).
#[test]
fn a_stored_instruction_answers_through_the_instruction_trait() {
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::code_unit::CodeUnit;
    let mut f = Fixture::new();
    let id = f.create(0x1004).unwrap();
    let factory: Arc<dyn crate::program::model::address::AddressFactory> =
        SleighLanguage::get_address_factory(&f.language);
    let mem = f.memory.read().unwrap();
    let insn = f.store.to_instruction(id, &*mem, None, factory.clone()).expect("no length override");
    assert_eq!(insn.get_mnemonic_string(), "jmp");
    assert_eq!(insn.get_length(), 2);
    assert_eq!(insn.get_min_address().offset(), 0x1004);
    assert_eq!(insn.get_flows().unwrap()[0].offset(), 0x100b);
    assert_eq!(insn.to_string(), "jmp 0x100b");

    // a length-overridden record has no faithful pseudo form
    let proto = f.proto(0x1000);
    let short = f.store.create_instruction(&*mem, f.at(0x1000), proto, None, 1).unwrap();
    assert!(f.store.to_instruction(short, &*mem, None, factory).is_none());
}

// ---- defined data (CodeManager.createCodeUnit(Address, DataType, int)) ----

/// Pointers and integers at 0x3000: a pointer to 0x1006, a null pointer, then 0x12345678.
const DATA: [u8; 12] = [0x00, 0x00, 0x10, 0x06, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78];

impl Fixture {
    fn with_data() -> Self {
        let f = Fixture::new();
        {
            let mut mem = f.memory.write().unwrap();
            mem.create_initialized_block("data", &f.at(0x3000), Some(&mut &DATA[..]), DATA.len() as i64, None, false)
                .unwrap();
        }
        f
    }

    fn create_data(&mut self, offset: i64, dt: Arc<dyn DataType>) -> Result<DefinedData, CodeUnitInsertionException> {
        let memory = Arc::clone(&self.memory);
        let mem = memory.read().unwrap();
        let at = self.at(offset);
        self.store.create_data(&*mem, at, dt, -1)
    }
}

fn pointer32() -> Arc<dyn DataType> {
    Arc::new(crate::program::model::data::pointer_data_type::PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None).unwrap())
}

fn dword() -> Arc<dyn DataType> {
    Arc::new(crate::program::model::data::dword_data_type::DWordDataType::new(None))
}

#[test]
fn created_data_is_found_at_and_within_its_range() {
    let mut f = Fixture::with_data();
    let data = f.create_data(0x3000, pointer32()).unwrap();
    assert_eq!((data.address().clone(), data.length(), data.max_address()), (f.at(0x3000), 4, f.at(0x3003)));
    assert!(data.is_pointer());
    assert_eq!(f.store.defined_data_at(&f.at(0x3000)).map(|d| d.address().clone()), Some(f.at(0x3000)));
    assert!(f.store.defined_data_at(&f.at(0x3001)).is_none());
    assert_eq!(f.store.defined_data_containing(&f.at(0x3003)).map(|d| d.address().clone()), Some(f.at(0x3000)));
    assert!(f.store.defined_data_containing(&f.at(0x3004)).is_none());
    assert_eq!(f.store.num_defined_data(), 1);
    assert_eq!(f.store.num_instructions(), 0);
    assert!(!f.store.is_undefined(&f.at(0x3002), &f.at(0x3002)));
    assert!(f.store.is_undefined(&f.at(0x3004), &f.at(0x3007)));
}

#[test]
fn pointer_data_gets_a_default_data_reference_to_its_value() {
    let mut f = Fixture::with_data();
    let data = f.create_data(0x3000, pointer32()).unwrap();
    let mem = f.memory.read().unwrap();
    assert_eq!(data.pointer_value(&*mem, true), Some(f.at(0x1006)));
    drop(mem);
    let refs = f.store.references().read().unwrap().references_from(&f.at(0x3000));
    assert_eq!(refs.len(), 1);
    use crate::program::model::symbol::Reference;
    assert_eq!((refs[0].to_address(), refs[0].reference_type(), refs[0].source(), refs[0].operand_index()), (f.at(0x1006), RefType::Data, SourceType::Default, 0));
    // a null pointer gets none (Java treats 0 and all f's as an uninitialized pointer value)
    f.create_data(0x3004, pointer32()).unwrap();
    assert!(f.store.references().read().unwrap().references_from(&f.at(0x3004)).is_empty());
    // nor does non-pointer data
    f.create_data(0x3008, dword()).unwrap();
    assert!(f.store.references().read().unwrap().references_from(&f.at(0x3008)).is_empty());
}

#[test]
fn data_conflicts_with_instructions_and_other_data_with_javas_messages() {
    let mut f = Fixture::with_data();
    f.create(0x1000).unwrap();
    assert_eq!(
        f.create_data(0x0fff + 1, dword()).unwrap_err().message(),
        "Conflicting instruction exists at address ram:0x1000 to ram:0x1001"
    );
    assert_eq!(
        f.create_data(0x1001, dword()).unwrap_err().message(),
        "Conflicting instruction exists at address ram:0x1000 to ram:0x1001"
    );
    f.create_data(0x1002, dword()).unwrap();
    assert_eq!(
        f.create(0x1004).unwrap_err().message(),
        "Conflicting data exists at address ram:0x1002 to ram:0x1005"
    );
    assert_eq!(f.create(0x1002).unwrap_err().message(), "Conflicting data exists at address ram:0x1002 to ram:0x1005");
    assert_eq!(
        f.create_data(0x1003, pointer32()).unwrap_err().message(),
        "Conflicting data exists at address ram:0x1002 to ram:0x1005"
    );
    assert_eq!(
        f.create_data(0x300a, dword()).unwrap_err().message(),
        "Insufficent memory at address ram:0x300a (length: 4 bytes)"
    );
}

#[test]
fn data_reads_as_its_types_mnemonic_and_value_among_the_code_units() {
    let mut f = Fixture::with_data();
    f.create_data(0x3000, pointer32()).unwrap();
    f.create_data(0x3008, dword()).unwrap();
    let units = f.units(0x3001, 0x300b);
    let shown: Vec<(&str, &str, usize)> =
        units.iter().map(|u| (u.mnemonic.as_str(), u.operand_text.as_str(), u.length)).collect();
    assert_eq!(
        shown,
        vec![
            ("addr", "ram:0x1006", 4), // the data containing the range's start
            ("??", "00h", 1),
            ("??", "00h", 1),
            ("??", "00h", 1),
            ("??", "00h", 1),
            ("ddw", "12345678h", 4), // DWordDataType's assembly mnemonic
        ]
    );
    assert!(units[0].is_defined_data() && units[0].kind == CodeUnitKind::Data);
    assert_eq!(units[0].bytes, DATA[..4].to_vec());
    assert_eq!(units[0].operands, vec!["ram:0x1006".to_string()]);
    let mem = f.memory.read().unwrap();
    let only_data: Vec<Address> =
        f.store.data_summaries(&*mem, &f.at(0x3000), &f.at(0x3fff)).map(|u| u.address).collect();
    assert_eq!(only_data, vec![f.at(0x3000), f.at(0x3008)]);
    let mut set = AddressSet::new();
    set.add_range(&f.at(0x3000), &f.at(0x300b));
    let undefined = f.store.undefined_ranges(&*mem, &set);
    assert_eq!(undefined.num_addresses(), 4);
}

#[test]
fn clearing_removes_data_and_its_references() {
    let mut f = Fixture::with_data();
    f.create_data(0x3000, pointer32()).unwrap();
    f.create_data(0x3008, dword()).unwrap();
    f.store.clear_code_units(&f.at(0x3002), &f.at(0x3002));
    assert!(f.store.defined_data_at(&f.at(0x3000)).is_none());
    assert!(f.store.references().read().unwrap().references_from(&f.at(0x3000)).is_empty());
    assert_eq!(f.store.num_defined_data(), 1);
    // the cleared bytes are free again
    f.create(0x1000).unwrap();
    f.create_data(0x3000, pointer32()).unwrap();
}
