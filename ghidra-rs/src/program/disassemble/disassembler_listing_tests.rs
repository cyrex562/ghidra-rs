//! The program path of [`Disassembler`]: flow-following disassembly into a [`ListingStore`],
//! over the toy sleigh language (`decode_tests`) in a real `ProgramDB`'s memory.

use std::sync::{Arc, Mutex, RwLock};

use super::*;
use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
use crate::program::database::code::listing_store::ListingStore;
use crate::program::database::mem::MemoryMapDB;
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::AddressSet;
use crate::program::model::listing::instruction_record::InstructionView;
use crate::util::task::DummyMonitor;
use crate::program::model::symbol::{RefType, SourceType};

/// Records every message the disassembler reports.
#[derive(Default)]
struct Messages(Mutex<Vec<String>>);

impl DisassemblerMessageListener for Messages {
    fn disassemble_message_reported(&self, msg: &str) {
        self.0.lock().unwrap().push(msg.to_string());
    }
}

struct Fixture {
    language: Arc<SleighLanguage>,
    program: ProgramDB,
    memory: Arc<RwLock<MemoryMapDB>>,
    listing: ListingStore,
    disassembler: Disassembler,
    messages: Arc<Messages>,
}

impl Fixture {
    /// `code` at 0x1000 (initialized) and 4 uninitialized bytes at 0x2000.
    fn new(code: &[u8]) -> Self {
        Self::with_language(decode_tests::language(), code)
    }

    fn with_language(language: Arc<SleighLanguage>, code: &[u8]) -> Self {
        let program = ProgramDB::new("toy".into(), language.clone()).unwrap();
        let memory = program.get_memory();
        {
            let mut mem = memory.write().unwrap();
            let start = Address::new(language.get_default_space(), 0x1000);
            mem.create_initialized_block("code", &start, Some(&mut &code[..]), code.len() as i64, None, false)
                .unwrap();
            let bss = Address::new(language.get_default_space(), 0x2000);
            Memory::create_uninitialized_block(&mut *mem, "bss", &bss, 4, false).unwrap();
        }
        let messages = Arc::new(Messages::default());
        let factory: Arc<dyn AddressFactory> = SleighLanguage::get_address_factory(&language);
        let disassembler = Disassembler::get_disassembler(
            Arc::clone(&language),
            factory,
            Arc::new(DummyMonitor),
            Some(messages.clone() as Arc<dyn DisassemblerMessageListener>),
        );
        let listing = ListingStore::new(language.clone());
        Fixture { language, program, memory, listing, disassembler, messages }
    }

    fn at(&self, offset: i64) -> Address {
        Address::new(self.language.get_default_space(), offset)
    }

    fn disassemble(&mut self, offset: i64, restricted: Option<&dyn AddressSetView>, follow_flow: bool) -> DisassembleResult {
        let start = self.at(offset);
        let memory = MemoryMapDB::as_memory(&self.memory);
        self.disassembler.disassemble_into(&mut self.listing, memory, &start, restricted, None, follow_flow)
    }

    /// (offset, display string) of every instruction, in address order.
    fn instructions(&self) -> Vec<(i64, String)> {
        let mem = self.memory.read().unwrap();
        self.listing
            .instructions_in(&self.at(0), &self.at(0xffff))
            .map(|id| {
                let snapshot = self.listing.snapshot(id, &*mem);
                let view = InstructionView::new(self.listing.record(id), &snapshot);
                (self.listing.record(id).address().offset(), view.display_string())
            })
            .collect()
    }

    fn messages(&self) -> Vec<String> {
        self.messages.0.lock().unwrap().clone()
    }
}

fn set(f: &Fixture, ranges: &[(i64, i64)]) -> AddressSet {
    let mut s = AddressSet::new();
    for (a, b) in ranges {
        s.add_range(&f.at(*a), &f.at(*b));
    }
    s
}

/// ```text
/// 0x1000: 70 04   bz r0, 0x1006
/// 0x1002: 11 2a   mov r1, 0x2a
/// 0x1004: 20 02   jmp 0x1008
/// 0x1006: 61 00   add r1, r0
/// 0x1008: 31 00   ret
/// 0x100a: 11 07   mov r1, 0x7      (unreachable)
/// ```
const FLOWS: [u8; 12] = [0x70, 0x04, 0x11, 0x2a, 0x20, 0x02, 0x61, 0x00, 0x31, 0x00, 0x11, 0x07];

#[test]
fn following_flows_disassembles_every_reachable_instruction() {
    let mut f = Fixture::new(&FLOWS);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(
        f.instructions(),
        vec![
            (0x1000, "bz r0,0x1006".to_string()),
            (0x1002, "mov r1,0x2a".to_string()),
            (0x1004, "jmp 0x1008".to_string()),
            (0x1006, "add r1,r0".to_string()),
            (0x1008, "ret".to_string()),
        ]
    );
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1009)]));
    assert!(result.errors.is_empty());
    assert!(f.messages().is_empty());
    assert!(!f.disassembler.disassembler_context().is_flow_active());
}

#[test]
fn without_following_flows_only_fall_throughs_are_disassembled() {
    let mut f = Fixture::new(&FLOWS);
    let result = f.disassemble(0x1000, None, false);
    assert_eq!(f.instructions().iter().map(|(a, _)| *a).collect::<Vec<_>>(), vec![0x1000, 0x1002, 0x1004]);
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1005)]));
}

#[test]
fn existing_instructions_are_skipped_and_flows_join_them() {
    let mut f = Fixture::new(&FLOWS);
    let first = f.disassemble(0x1006, None, true);
    assert_eq!(first.disassembled, set(&f, &[(0x1006, 0x1009)]));
    let second = f.disassemble(0x1000, None, true);
    assert_eq!(second.disassembled, set(&f, &[(0x1000, 0x1005)]));
    assert_eq!(f.instructions().len(), 5);
    assert!(second.errors.is_empty(), "{:?}", second.errors);
    // nothing new the third time
    assert!(f.disassemble(0x1000, None, true).disassembled.is_empty());
}

#[test]
fn a_flow_into_the_middle_of_an_instruction_is_a_conflict() {
    // 0x1000: 20 01 jmp 0x1003 ; 0x1002: 11 2a mov r1,0x2a ; 0x1004: 31 00 ret
    let mut f = Fixture::new(&[0x20, 0x01, 0x11, 0x2a, 0x31, 0x00]);
    f.disassemble(0x1002, None, true);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1001)]));
    assert_eq!(
        result.errors,
        vec![(f.at(0x1003), "Failed to disassemble at ram:0x1003 due to conflicting instruction at ram:0x1002".to_string())]
    );
    assert_eq!(f.instructions().len(), 3);
}

#[test]
fn bytes_that_are_no_instruction_end_the_flow_with_an_error() {
    // mov r1,0x2a ; <bad>
    let mut f = Fixture::new(&[0x11, 0x2a, 0x00, 0x00]);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(f.instructions(), vec![(0x1000, "mov r1,0x2a".to_string())]);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].0, f.at(0x1002));
}

#[test]
fn delay_slots_are_disassembled_with_their_instruction() {
    // 0x1000: 40 02 jd 0x1004 ; 0x1002: 10 07 mov r0,0x7 (delay slot) ; 0x1004: 31 00 ret
    let mut f = Fixture::new(&[0x40, 0x02, 0x10, 0x07, 0x31, 0x00]);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(
        f.instructions(),
        vec![
            (0x1000, "jd 0x1004".to_string()),
            (0x1002, "_mov r0,0x7".to_string()),
            (0x1004, "ret".to_string()),
        ]
    );
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1005)]));
}

#[test]
fn the_restricted_set_bounds_disassembly() {
    let mut f = Fixture::new(&FLOWS);
    let restricted = set(&f, &[(0x1000, 0x1005)]);
    let result = f.disassemble(0x1000, Some(&restricted), true);
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1005)]));
    assert!(result.errors.is_empty(), "{:?}", result.errors);
}

#[test]
fn flows_into_uninitialized_memory_are_not_disassembled() {
    // 0x1000: 20 ff jmp 0x1101? no: rel is one byte; use bz to reach past the block end
    // mov r1,0x2a falls through off the end of the block into unmapped memory
    let mut f = Fixture::new(&[0x11, 0x2a]);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1001)]));
    let at_bss = f.disassemble(0x2000, None, true);
    assert!(at_bss.disassembled.is_empty());
    assert_eq!(
        at_bss.errors,
        vec![(f.at(0x2000), "Disassembly not permitted within uninitialized memory block".to_string())]
    );
    let _ = &f.program;
}

#[test]
fn a_global_context_commit_reaches_the_instruction_it_targets() {
    // 0x1000: setm 0x1002  (TMode=1; globalset(0x1002, TMode)) ; 0x1002: mov r0,0x7 ; 0x1004: ret
    let mut f = Fixture::with_language(decode_tests::context_language(), &[0x80, 0x00, 0x10, 0x07, 0x31, 0x00]);
    let result = f.disassemble(0x1000, None, true);
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x1005)]), "{:?}", result.errors);
    let tmode = |f: &Fixture, offset: i64| {
        let id = f.listing.instruction_at(&f.at(offset)).unwrap();
        f.listing.context_value(id).map(RegisterValue::unsigned_value_ignore_mask)
    };
    assert_eq!(tmode(&f, 0x1000), Some(0));
    // the commit is applied to the disassembler context at its target
    assert_eq!(tmode(&f, 0x1002), Some(0x8000_0000));
    // TMode is non-flowing: it does not reach the next instruction
    assert_eq!(tmode(&f, 0x1004), Some(0));
}

/// `/bin/ls` loaded as x86-64 through the language service with image base 0x100000, and its
/// entry point; `None` when the Ghidra distribution or an x86-64 `/bin/ls` is missing.
fn load_bin_ls() -> Option<(Arc<ProgramDB>, Arc<dyn crate::program::model::listing::Program>, Address)> {
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
    use crate::app::seam_stubs::new_string;
    use crate::app::util::importer::message_log::MessageLog;
    use crate::app::util::opinion::elf_loader::ElfLoader;
    use crate::app::util::opinion::elf_loader_options_factory::IMAGE_BASE_OPTION_NAME;
    use crate::format::elf::elf_test_image::provider;
    use crate::program::model::lang::LanguageID;
    use crate::program::model::listing::Program;
    use crate::program::util::default_language_service::DefaultLanguageService;

    let dist = ghidra_dist()?;
    let bytes = std::fs::read("/bin/ls").ok()?;
    if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 {
        return None; // not x86-64
    }
    let e_entry = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap());
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    // ET_DYN images are rebased to 0x100000; ET_EXEC keep their addresses
    let entry_offset = if e_type == 3 { e_entry + 0x100000 } else { e_entry } as i64;

    let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
    let language = service.get_sleigh_language(&LanguageID::new("x86:LE:64:default").unwrap()).unwrap();
    let program = Arc::new(ProgramDB::new("ls".into(), language.clone()).unwrap());
    let dyn_program: Arc<dyn Program> = program.clone();
    let log = Arc::new(MessageLog::new());
    let options = vec![new_string(IMAGE_BASE_OPTION_NAME).value(Box::new("100000".to_string())).build()];
    ElfLoader::new().load(provider(bytes), &dyn_program, &options, &log, &DummyMonitor).unwrap();
    let entry = Address::new(language.get_default_space(), entry_offset);
    let entries: Vec<i64> =
        dyn_program.get_symbol_table().unwrap().get_external_entry_point_iterator().map(|a| a.offset()).collect();
    assert!(entries.contains(&entry_offset), "entry {entry_offset:#x} not in {entries:x?}");
    Some((program, dyn_program, entry))
}

/// Acceptance (milestone C2): `x86:LE:64:default` from the language service over the local
/// Ghidra distribution -> `ProgramDB` -> `/bin/ls` through `ElfLoader` -> disassemble from the
/// ELF entry (`_start`) following flows -> the listing holds the entry's instructions with the
/// x86-64 encodings they must have. Skipped when the distribution or an x86-64 `/bin/ls` is
/// absent.
#[test]
fn bin_ls_disassembles_from_its_entry_point() {
    let Some((program, dyn_program, entry)) = load_bin_ls() else { return };
    let entry_offset = entry.offset();

    let mut disassembler = Disassembler::get_program_disassembler(&program, Arc::new(DummyMonitor), None);
    let result = disassembler.disassemble_program(&program, &entry, None, true);
    assert!(result.disassembled.contains(&entry));
    let count = program.get_listing_store().read().unwrap().num_instructions();
    assert!(count >= 10, "only {count} instructions: {:?}", result.errors);

    let summaries = program.instruction_summaries(&entry, &entry.add_wrap(15));
    assert_eq!(summaries.first().map(|u| u.address.clone()), Some(entry.clone()));
    let units = program.code_units(&entry, &entry.add_wrap(15));
    assert!(units.iter().take(4).all(|u| u.is_instruction()), "{units:#?}");
    // every instruction's bytes are the file's, and the known x86-64 encodings decode as such
    for u in units.iter().filter(|u| u.is_instruction()) {
        assert_eq!(u.bytes.len(), u.length);
        match u.bytes.as_slice() {
            [0xf3, 0x0f, 0x1e, 0xfa] => assert_eq!(u.mnemonic, "ENDBR64"),
            [0x31, 0xed] => assert_eq!((u.mnemonic.as_str(), u.operand_text.as_str()), ("XOR", "EBP,EBP")),
            [0x49, 0x89, 0xd1] => assert_eq!((u.mnemonic.as_str(), u.operand_text.as_str()), ("MOV", "R9,RDX")),
            [0x5e] => assert_eq!((u.mnemonic.as_str(), u.operand_text.as_str()), ("POP", "RSI")),
            [0x48, 0x89, 0xe2] => assert_eq!((u.mnemonic.as_str(), u.operand_text.as_str()), ("MOV", "RDX,RSP")),
            _ => {}
        }
    }
    {
        use crate::program::model::listing::code_unit_format::{CodeUnitFormat, DefaultCodeUnitFormat};
        let listing = program.get_listing_store();
        let listing = listing.read().unwrap();
        let mem = program.get_memory();
        let mem = mem.read().unwrap();
        let fmt = DefaultCodeUnitFormat::new();
        // the program's instructions answer through the Instruction trait, so CodeUnitFormat
        // (the listing's operand rendering) can format them; without references, register and
        // scalar operands read as the default representation
        for id in listing.instructions_in(&entry, &entry.add_wrap(0x10)) {
            let factory = dyn_program.get_address_factory().unwrap();
            let insn = listing.to_instruction(id, &*mem, Some(dyn_program.clone()), factory).unwrap();
            let summary = listing.instruction_summary(id, &*mem);
            if summary.operands.iter().all(|op| !op.contains("0x")) {
                assert_eq!(fmt.get_representation_string(&insn), insn.to_string());
            }
        }
    }
    // a typical glibc _start begins `endbr64; xor ebp,ebp`
    if units[0].bytes == [0xf3, 0x0f, 0x1e, 0xfa] {
        assert_eq!((units[0].length, units[0].mnemonic.as_str()), (4, "ENDBR64"));
        if units[1].bytes == [0x31, 0xed] {
            assert_eq!(units[1].address.offset(), entry_offset + 4);
        }
    }
}

/// Java's `disassemble(AddressSetView, ...)`: every undefined, aligned address of the start set
/// starts a flow, unless an earlier flow already reached it.
#[test]
fn a_start_set_disassembles_from_each_undefined_address() {
    let mut f = Fixture::new(&FLOWS);
    let start_set = set(&f, &[(0x1000, 0x100b)]);
    let memory = MemoryMapDB::as_memory(&f.memory);
    let result = f.disassembler.disassemble_set_into(&mut f.listing, memory.clone(), &start_set, None, None, true);
    // 0x1000 reaches 0x1000-0x1009; 0x100a starts its own flow
    assert_eq!(result.disassembled, set(&f, &[(0x1000, 0x100b)]));
    assert_eq!(f.instructions().last().unwrap(), &(0x100a, "mov r1,0x7".to_string()));
    // nothing undefined is left to start from
    let again = f.disassembler.disassemble_set_into(&mut f.listing, memory, &start_set, None, None, true);
    assert!(again.disassembled.is_empty());
}

/// (operand index, to offset, type, source, primary) of every reference from `offset`.
fn refs_from(f: &Fixture, offset: i64) -> Vec<(i32, i64, RefType, SourceType, bool)> {
    use crate::program::model::symbol::Reference;
    let refs = f.listing.references();
    let refs = refs.read().unwrap();
    refs.references_from(&f.at(offset))
        .iter()
        .map(|r| (r.operand_index(), r.to_address().offset(), r.reference_type(), r.source(), r.is_primary()))
        .collect()
}

/// `CodeManager.addReferencesForInstruction`: a flow whose address is an operand is a primary
/// default reference on that operand, typed by the instruction's flow; fall-throughs and
/// instructions without addresses get none.
#[test]
fn created_instructions_get_default_flow_references_on_their_operands() {
    let mut f = Fixture::new(&FLOWS);
    f.disassemble(0x1000, None, true);
    assert_eq!(refs_from(&f, 0x1000), vec![(1, 0x1006, RefType::ConditionalJump, SourceType::Default, true)]);
    assert_eq!(refs_from(&f, 0x1004), vec![(0, 0x1008, RefType::UnconditionalJump, SourceType::Default, true)]);
    for plain in [0x1002, 0x1006, 0x1008] {
        assert_eq!(refs_from(&f, plain), vec![], "{plain:#x}");
    }
    let refs = f.listing.references();
    let refs = refs.read().unwrap();
    assert_eq!(refs.len(), 2);
    let to: Vec<i64> = refs.references_to(&f.at(0x1008)).iter().map(|r| {
        use crate::program::model::symbol::Reference;
        r.from_address().offset()
    }).collect();
    assert_eq!(to, vec![0x1004]);
}

/// Java drops a mnemonic jump reference to the next instruction when the instruction falls
/// through, but a flow address an operand shows is an operand reference first, so a branch to the
/// next instruction written as an operand keeps its reference either way.
#[test]
fn a_branch_to_the_next_instruction_written_as_an_operand_is_a_reference() {
    // 0x1000: bz r0,0x1002 ; 0x1002: jmp 0x1004 ; 0x1004: ret
    let mut f = Fixture::new(&[0x70, 0x00, 0x20, 0x00, 0x31, 0x00]);
    f.disassemble(0x1000, None, true);
    assert_eq!(f.instructions().len(), 3);
    assert_eq!(refs_from(&f, 0x1000), vec![(1, 0x1002, RefType::ConditionalJump, SourceType::Default, true)]);
    assert_eq!(refs_from(&f, 0x1002), vec![(0, 0x1004, RefType::UnconditionalJump, SourceType::Default, true)]);
}

/// `CodeManager.clearCodeUnits` removes every reference from the cleared range, from the start
/// of the instruction containing its start, user references included.
#[test]
fn clearing_code_units_removes_the_references_from_them() {
    let mut f = Fixture::new(&FLOWS);
    f.disassemble(0x1000, None, true);
    {
        let refs = f.listing.references();
        let mut refs = refs.write().unwrap();
        refs.add_memory_reference(f.at(0x1002), f.at(0x2000), RefType::Write, SourceType::UserDefined, 0).unwrap();
    }
    // 0x1001 is inside the bz at 0x1000; the range ends inside the mov at 0x1002
    f.listing.clear_code_units(&f.at(0x1001), &f.at(0x1002));
    assert_eq!(f.instructions().iter().map(|(a, _)| *a).collect::<Vec<_>>(), vec![0x1004, 0x1006, 0x1008]);
    assert_eq!(refs_from(&f, 0x1000), vec![]);
    assert_eq!(refs_from(&f, 0x1002), vec![]);
    assert_eq!(refs_from(&f, 0x1004).len(), 1);
    // re-disassembly lays the default reference down again
    f.disassemble(0x1000, None, true);
    assert_eq!(refs_from(&f, 0x1000), vec![(1, 0x1006, RefType::ConditionalJump, SourceType::Default, true)]);
}

/// A `ProgramDB`'s listing maintains its default references in the program's reference store.
#[test]
fn a_program_listing_shares_the_programs_reference_store() {
    let f = Fixture::new(&FLOWS);
    let start = f.at(0x1000);
    let mut disassembler =
        Disassembler::get_disassembler(f.language.clone(), SleighLanguage::get_address_factory(&f.language), Arc::new(DummyMonitor), None);
    let memory = MemoryMapDB::as_memory(&f.memory);
    {
        let listing = f.program.get_listing_store();
        let mut listing = listing.write().unwrap();
        disassembler.disassemble_into(&mut listing, memory, &start, None, None, true);
    }
    use crate::program::model::symbol::Reference;
    let from = f.program.references_from(&f.at(0x1004));
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].to_address(), f.at(0x1008));
    assert_eq!(f.program.references_to(&f.at(0x1006)).len(), 1);
    assert!(Arc::ptr_eq(&f.program.get_reference_store(), &f.program.get_listing_store().read().unwrap().references()));
}

/// Acceptance (milestone C3): the `/bin/ls` instructions disassembled from `_start` and from
/// `main` carry the default references Java's `CodeManager` gives them: the `LEA RDI,[main]`
/// operand none (its address is a scalar), the `CALL qword ptr [GOT]` operand a primary read or
/// indirection reference to the GOT slot (no flow reference: the call is computed), direct calls
/// and jumps primary call / jump references on their operand, and nothing is a fall-through
/// reference. Skipped when the distribution or an x86-64 `/bin/ls` is absent.
#[test]
fn bin_ls_instructions_get_javas_default_references() {
    use crate::program::model::symbol::Reference;
    let Some((program, _, entry)) = load_bin_ls() else { return };
    let mut disassembler = Disassembler::get_program_disassembler(&program, Arc::new(DummyMonitor), None);
    disassembler.disassemble_program(&program, &entry, None, true);

    let rel32 = |b: &[u8]| i64::from(i32::from_le_bytes(b.try_into().unwrap()));
    let start_units = program.instruction_summaries(&entry, &entry.add_wrap(0x40));
    let (mut saw_lea, mut saw_call) = (None, false);
    for u in &start_units {
        let next = u.address.add_wrap(u.length as i64);
        let refs = program.references_from(&u.address);
        match u.bytes.as_slice() {
            // lea rdi,[rip+disp32]: x86-64's RIP-relative effective address is a constant
            // (a Scalar in the representation) and the instruction has no flows, so Java's
            // CodeManager lays down no default reference (the analyzers add one later)
            [0x48, 0x8d, 0x3d, d @ ..] => {
                assert!(refs.is_empty(), "{u:?} {refs:?}");
                saw_lea = Some(next.add_wrap(rel32(d)));
            }
            // call qword ptr [rip+disp32]
            [0xff, 0x15, d @ ..] => {
                let slot = next.add_wrap(rel32(d));
                assert_eq!(refs.len(), 1, "{refs:?}");
                let r = &refs[0];
                assert_eq!((r.operand_index(), r.to_address(), r.source(), r.is_primary()), (0, slot, SourceType::Default, true));
                assert!(matches!(r.reference_type(), RefType::Read | RefType::Indirection), "{:?}", r.reference_type());
                saw_call = true;
            }
            _ => assert!(refs.is_empty(), "{u:?} {refs:?}"),
        }
    }
    assert!(saw_call, "no CALL [GOT] in _start: {start_units:#?}");

    // direct calls and jumps carry their flow as a primary operand reference, in main and in
    // the C runtime helpers laid out after _start (each start of the range starts a flow)
    let mut checked: Vec<RefType> = Vec::new();
    let mut check = |start: &Address, end: &Address| {
        for u in program.instruction_summaries(start, end) {
            let next = u.address.add_wrap(u.length as i64);
            let refs = program.references_from(&u.address);
            assert!(refs.iter().all(|r| r.reference_type() != RefType::FallThrough && r.source() == SourceType::Default));
            let expected = match u.bytes.as_slice() {
                [0xe8, d @ ..] if d.len() == 4 => Some((next.add_wrap(rel32(d)), RefType::UnconditionalCall)),
                [0xe9, d @ ..] if d.len() == 4 => Some((next.add_wrap(rel32(d)), RefType::UnconditionalJump)),
                [0xeb, d] => Some((next.add_wrap(i64::from(*d as i8)), RefType::UnconditionalJump)),
                [0x70..=0x7f, d] => Some((next.add_wrap(i64::from(*d as i8)), RefType::ConditionalJump)),
                [0x0f, 0x80..=0x8f, d @ ..] if d.len() == 4 => Some((next.add_wrap(rel32(d)), RefType::ConditionalJump)),
                _ => None,
            };
            if let Some((target, ref_type)) = expected {
                let r: Vec<_> =
                    refs.iter().map(|r| (r.operand_index(), r.to_address(), r.reference_type(), r.is_primary())).collect();
                assert_eq!(r, vec![(0, target.clone(), ref_type, true)], "{u:?}");
                assert!(program.references_to(&target).iter().any(|r| r.from_address() == u.address));
                checked.push(ref_type);
            }
        }
    };
    if let Some(main) = saw_lea {
        let mut window = AddressSet::new();
        window.add_range(&main, &main.add_wrap(0x200));
        disassembler.disassemble_program(&program, &main, Some(&window), true);
        check(&main, &main.add_wrap(0x200));
    }
    let (crt_start, crt_end) = (entry.add_wrap(0x26), entry.add_wrap(0x100));
    let mut crt = AddressSet::new();
    crt.add_range(&crt_start, &crt_end);
    {
        let listing = program.get_listing_store();
        let mut listing = listing.write().unwrap();
        let memory = MemoryMapDB::as_memory(&program.get_memory());
        disassembler.disassemble_set_into(&mut listing, memory, &crt, Some(&crt), None, true);
    }
    check(&crt_start, &crt_end);
    assert!(
        checked.contains(&RefType::UnconditionalCall) && checked.contains(&RefType::ConditionalJump),
        "too few direct flows checked: {checked:?}"
    );
}

/// Milestone C4: `ProgramDB::operand_display` formats an instruction through `CodeUnitFormat`
/// over the program's stores -- an operand address with a reference reads as the destination's
/// symbol, a dynamic label (`LAB_`) when it has none, the stored label once one is created.
#[test]
fn operand_display_shows_referenced_addresses_by_symbol() {
    use crate::program::model::symbol::SymbolTable;
    let f = Fixture::new(&FLOWS);
    let space = f.language.get_default_space();
    let at = move |offset: i64| Address::new(space.clone(), offset);
    let mut disassembler =
        Disassembler::get_disassembler(f.language.clone(), SleighLanguage::get_address_factory(&f.language), Arc::new(DummyMonitor), None);
    let program = Arc::new(f.program);
    {
        let listing = program.get_listing_store();
        let mut listing = listing.write().unwrap();
        disassembler.disassemble_into(&mut listing, MemoryMapDB::as_memory(&program.get_memory()), &at(0x1000), None, None, true);
    }
    // 0x1000: bz r0,0x1006 ; 0x1002: mov r1,0x2a ; 0x1004: jmp 0x1008
    let bz = program.operand_display(&at(0x1000)).unwrap();
    assert_eq!(bz.mnemonic, "bz");
    assert_eq!(bz.operands, vec!["r0".to_string(), "LAB_00001006".to_string()]);
    assert_eq!(bz.operand_field, "r0,LAB_00001006");
    let mov = program.operand_display(&at(0x1002)).unwrap();
    assert_eq!(mov.operand_field, "r1,0x2a", "no reference, default representation");
    assert_eq!(program.operand_display(&at(0x1004)).unwrap().operand_field, "LAB_00001008");

    program.get_symbol_table().write().unwrap().create_label(&at(0x1008), "done", SourceType::UserDefined).unwrap();
    assert_eq!(program.operand_display(&at(0x1004)).unwrap().operand_field, "done");
    assert!(program.operand_display(&at(0x1001)).is_none(), "no instruction starts there");
}

/// Acceptance (milestone C4): `/bin/ls` disassembled from `_start` (and the C runtime helpers
/// after it) reads in the listing the way stock Ghidra shows it right after import, before
/// analysis: an operand address with a reference shows the destination's symbol -- a dynamic
/// one where the import creates none (`DAT_` for undefined data, `LAB_` for a jump target,
/// `SUB_` for a call target), `->` and the import for a GOT pointer to one -- and every
/// operand without a reference keeps its default representation.
///
/// `_start`'s call reads `CALL qword ptr [->__libc_start_main]` (milestone C5): the ELF import
/// defines a pointer at the GOT slot, and `CodeUnitFormat` follows a READ reference to a
/// pointer whose single data reference reaches a non-dynamic symbol. References to other
/// defined data (Java names it `PTR_...`) are not checked here. Skipped when the distribution
/// or an x86-64 `/bin/ls` is absent.
#[test]
fn bin_ls_operands_read_as_ghidras_listing_shows_them() {
    use crate::program::model::symbol::{Reference, SymbolTable};
    let Some((program, _, entry)) = load_bin_ls() else { return };
    let mut disassembler = Disassembler::get_program_disassembler(&program, Arc::new(DummyMonitor), None);
    disassembler.disassemble_program(&program, &entry, None, true);
    let (crt_start, crt_end) = (entry.add_wrap(0x26), entry.add_wrap(0x100));
    let mut crt = AddressSet::new();
    crt.add_range(&crt_start, &crt_end);
    {
        let listing = program.get_listing_store();
        let mut listing = listing.write().unwrap();
        let memory = MemoryMapDB::as_memory(&program.get_memory());
        disassembler.disassemble_set_into(&mut listing, memory, &crt, Some(&crt), None, true);
    }

    // the name Ghidra gives `to`: its stored symbol, else SymbolUtilities.getDynamicName's by
    // the highest reference level to it (a call SUB_, data DAT_, a jump LAB_), except that an
    // instruction start that is not called is a LAB_ (no functions exist before analysis)
    let name_of = |to: &Address| -> String {
        let stored = program.get_symbol_table().read().unwrap().get_primary_symbol(to).unwrap();
        if let Some(symbol) = stored.filter(|s| !s.is_dynamic()) {
            return symbol.get_name().to_string();
        }
        let is_instruction = program.get_listing_store().read().unwrap().instruction_at(to).is_some();
        let types: Vec<RefType> = program.references_to(to).iter().map(|r| r.reference_type()).collect();
        let prefix = if types.iter().any(|t| t.is_call()) {
            "SUB_"
        } else if is_instruction || !types.iter().any(|t| t.is_data()) {
            "LAB_"
        } else {
            "DAT_"
        };
        format!("{prefix}{:08x}", to.offset())
    };

    // CodeUnitFormat.getExtendedPointerReferenceMarkup: a READ (or indirect) reference to
    // defined data whose only reference is a DATA reference to a non-dynamic symbol reads as
    // `->` and that symbol
    let through_pointer = |to: &Address, ref_type: RefType| -> Option<String> {
        if !(ref_type.is_indirect() || ref_type == RefType::Read) {
            return None;
        }
        program.defined_data_at(to)?;
        let from_pointer = program.references_from(to);
        if from_pointer.len() != 1 || from_pointer[0].reference_type() != RefType::Data {
            return None;
        }
        let target = from_pointer[0].to_address();
        let symbol = program.get_symbol_table().read().unwrap().get_primary_symbol(&target).unwrap()?;
        (!symbol.is_dynamic()).then(|| format!("->{}", symbol.get_name()))
    };

    let rel32 = |b: &[u8]| i64::from(i32::from_le_bytes(b.try_into().unwrap()));
    let (mut saw_got_call, mut marked_up) = (false, Vec::new());
    for u in program.instruction_summaries(&entry, &crt_end) {
        let shown = program.operand_display(&u.address).unwrap();
        assert_eq!(shown.mnemonic, u.mnemonic);
        assert_eq!(shown.operands.len(), u.operands.len());
        let refs = program.references_from(&u.address);
        if refs.is_empty() {
            assert_eq!(shown.operand_field, u.operand_text, "{u:?}");
            assert_eq!(shown.operands, u.operands);
            continue;
        }
        assert_eq!(refs.len(), 1, "{u:?} {refs:?}");
        let to = refs[0].to_address();
        let name = match through_pointer(&to, refs[0].reference_type()) {
            Some(name) => name,
            // a reference to other defined data reads in Java as the data's dynamic name
            // (`PTR_...` for a pointer), which dynamic symbols do not answer yet
            None if program.defined_data_at(&to).is_some() => continue,
            None => name_of(&to),
        };
        let expected = u.operand_text.replacen(&format!("0x{:x}", to.offset()), &name, 1);
        assert_ne!(expected, u.operand_text, "{u:?} does not show {to}");
        assert_eq!(shown.operand_field, expected, "{u:?}");
        marked_up.push(shown.operand_field.clone());
        if let [0xff, 0x15, d @ ..] = u.bytes.as_slice() {
            let slot = u.address.add_wrap(u.length as i64 + rel32(d));
            assert_eq!(to, slot);
            assert_eq!((shown.mnemonic.as_str(), shown.operand_field.as_str()), ("CALL", "qword ptr [->__libc_start_main]"));
            saw_got_call = true;
        }
    }
    assert!(saw_got_call, "no CALL [GOT] in _start");
    for prefix in ["LAB_", "SUB_", "DAT_", "->"] {
        assert!(marked_up.iter().any(|t| t.contains(prefix)), "no {prefix} operand among {marked_up:?}");
    }
}

/// Acceptance (milestone C5): the ELF import types `/bin/ls`'s GOT slots as pointers (after
/// applying the x86-64 dynamic relocations that fill them), so the slot `_start` calls through
/// is pointer data whose DATA reference reaches `__libc_start_main` in the EXTERNAL block, and
/// `CodeUnitFormat` follows the call's reference through that pointer the way Java's listing
/// shows it: `CALL qword ptr [->__libc_start_main]`. Skipped when the distribution or an x86-64
/// `/bin/ls` is absent.
#[test]
fn bin_ls_start_calls_libc_start_main_through_a_got_pointer() {
    use crate::program::model::symbol::{Reference, SymbolTable};
    let Some((program, _, entry)) = load_bin_ls() else { return };
    let mut disassembler = Disassembler::get_program_disassembler(&program, Arc::new(DummyMonitor), None);
    disassembler.disassemble_program(&program, &entry, None, true);

    let call = program
        .instruction_summaries(&entry, &entry.add_wrap(0x40))
        .into_iter()
        .find(|u| u.bytes.starts_with(&[0xff, 0x15]))
        .expect("no CALL [GOT] in _start");
    let rel32 = i64::from(i32::from_le_bytes(call.bytes[2..6].try_into().unwrap()));
    let slot = call.address.add_wrap(call.length as i64 + rel32);

    let data = program.defined_data_at(&slot).expect("the GOT slot is not defined data");
    assert!(data.is_pointer());
    assert_eq!(data.length(), 8);
    let refs = program.references_from(&slot);
    assert_eq!(refs.len(), 1, "{refs:?}");
    assert_eq!(refs[0].reference_type(), RefType::Data);
    let target = refs[0].to_address();
    let symbol = program.get_symbol_table().read().unwrap().get_primary_symbol(&target).unwrap().expect("no symbol at the import");
    assert_eq!(symbol.get_name(), "__libc_start_main");
    let block = MemoryMapDB::as_memory(&program.get_memory()).get_block(&target).map(|b| b.get_name().to_string());
    assert_eq!(block.as_deref(), Some("EXTERNAL"));

    // every slot of the GOT is a pointer (ElfDefaultGotPltMarkup.processGOT)
    let got = MemoryMapDB::as_memory(&program.get_memory()).get_block(&slot).unwrap();
    assert!(got.get_name().starts_with(".got"));
    let (got_start, got_end) = (got.get_start(), got.get_end());
    let pointers = program.data_summaries(&got_start, &got_end);
    assert_eq!(pointers.len() as i64, (got_end.subtract(&got_start) + 1) / 8);
    assert!(pointers.iter().all(|p| p.mnemonic == "addr" && p.length == 8));

    let summary = program.data_summaries(&slot, &slot).pop().unwrap();
    assert_eq!((summary.mnemonic.as_str(), summary.operand_text.clone()), ("addr", target.to_string()));

    // the slot itself reads as Java's listing shows a pointer: `addr` and the symbol it reaches
    let pointer = program.operand_display(&slot).unwrap();
    assert_eq!((pointer.mnemonic.as_str(), pointer.operand_field.as_str()), ("addr", "__libc_start_main"));
    assert_eq!(pointer.operands, vec!["__libc_start_main".to_string()]);

    let shown = program.operand_display(&call.address).unwrap();
    assert_eq!((shown.mnemonic.as_str(), shown.operand_field.as_str()), ("CALL", "qword ptr [->__libc_start_main]"));
}
