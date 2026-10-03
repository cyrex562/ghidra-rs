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

/// Acceptance (milestone C2): `x86:LE:64:default` from the language service over the local
/// Ghidra distribution -> `ProgramDB` -> `/bin/ls` through `ElfLoader` -> disassemble from the
/// ELF entry (`_start`) following flows -> the listing holds the entry's instructions with the
/// x86-64 encodings they must have. Skipped when the distribution or an x86-64 `/bin/ls` is
/// absent.
#[test]
fn bin_ls_disassembles_from_its_entry_point() {
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

    let Some(dist) = ghidra_dist() else { return };
    let Ok(bytes) = std::fs::read("/bin/ls") else { return };
    if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 {
        return; // not x86-64
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
