//! `DisassembleCommand` over the toy sleigh language in a real `ProgramDB`.

use super::*;
use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
use crate::program::model::lang::language::Language;
use crate::program::model::mem::Memory;

/// ```text
/// 0x1000: 70 04   bz r0, 0x1006
/// 0x1002: 11 2a   mov r1, 0x2a
/// 0x1004: 20 02   jmp 0x1008
/// 0x1006: 61 00   add r1, r0
/// 0x1008: 31 00   ret
/// 0x100a: 11 07   mov r1, 0x7
/// 0x100c: 31 00   ret
/// ```
const CODE: [u8; 14] = [0x70, 0x04, 0x11, 0x2a, 0x20, 0x02, 0x61, 0x00, 0x31, 0x00, 0x11, 0x07, 0x31, 0x00];

fn program() -> ProgramDB {
    let language = decode_tests::language();
    let program = ProgramDB::new("toy".into(), language.clone()).unwrap();
    let start = Address::new(language.get_default_space(), 0x1000);
    program
        .get_memory()
        .write()
        .unwrap()
        .create_initialized_block("code", &start, Some(&mut &CODE[..]), CODE.len() as i64, None, false)
        .unwrap();
    let bss = Address::new(language.get_default_space(), 0x2000);
    Memory::create_uninitialized_block(&mut *program.get_memory().write().unwrap(), "bss", &bss, 4, false).unwrap();
    program
}

fn at(program: &ProgramDB, offset: i64) -> Address {
    Address::new(program.get_language().get_default_space(), offset)
}

fn range(program: &ProgramDB, start: i64, end: i64) -> AddressSet {
    AddressSet::from_start_end(at(program, start), at(program, end))
}

fn instruction_starts(program: &ProgramDB) -> Vec<i64> {
    program
        .instruction_summaries(&at(program, 0), &at(program, 0xffff))
        .iter()
        .map(|u| u.address.offset())
        .collect()
}

#[test]
fn disassembling_from_an_address_follows_its_flows() {
    let mut program = program();
    let mut cmd = DisassembleCommand::new(at(&program, 0x1000), None, true);
    assert_eq!(cmd.get_name(), "Disassemble");
    assert!(cmd.apply_to_unmonitored(&mut program));
    assert_eq!(instruction_starts(&program), vec![0x1000, 0x1002, 0x1004, 0x1006, 0x1008]);
    assert_eq!(cmd.get_disassembled_address_set(), &range(&program, 0x1000, 0x1009));
    assert_eq!(cmd.get_status_msg(), None);
}

#[test]
fn without_flow_only_the_fall_through_run_is_disassembled() {
    let program = program();
    let mut cmd = DisassembleCommand::new(at(&program, 0x1000), None, false);
    assert!(cmd.apply(&program, &DummyMonitor));
    assert_eq!(instruction_starts(&program), vec![0x1000, 0x1002, 0x1004]);
}

#[test]
fn a_start_set_disassembles_every_undefined_address_in_it() {
    let program = program();
    let mut cmd = DisassembleCommand::with_start_set(range(&program, 0x1000, 0x100d), None, true);
    assert!(cmd.apply(&program, &DummyMonitor));
    assert_eq!(instruction_starts(&program), vec![0x1000, 0x1002, 0x1004, 0x1006, 0x1008, 0x100a, 0x100c]);
    assert_eq!(cmd.get_disassembled_address_set(), &range(&program, 0x1000, 0x100d));
}

#[test]
fn a_start_on_existing_code_disassembles_nothing_and_says_why() {
    let program = program();
    DisassembleCommand::new(at(&program, 0x1000), None, true).apply(&program, &DummyMonitor);
    let mut cmd = DisassembleCommand::new(at(&program, 0x1002), None, true);
    // Java: no unaligned or non-executable start, so the command itself succeeds
    assert!(cmd.apply(&program, &DummyMonitor));
    assert!(cmd.get_disassembled_address_set().is_empty());
    assert_eq!(
        cmd.get_status_msg().as_deref(),
        Some("Disassembler requires a start which is an undefined code unit")
    );
}

#[test]
fn the_restricted_set_bounds_the_flows() {
    let program = program();
    let restricted = range(&program, 0x1000, 0x1003);
    let mut cmd = DisassembleCommand::new(at(&program, 0x1000), Some(restricted), true);
    assert!(cmd.apply(&program, &DummyMonitor));
    assert_eq!(instruction_starts(&program), vec![0x1000, 0x1002]);
}

#[test]
fn an_empty_start_set_does_nothing() {
    let program = program();
    let mut cmd = DisassembleCommand::with_start_set(AddressSet::new(), None, true);
    assert!(cmd.apply(&program, &DummyMonitor));
    assert!(instruction_starts(&program).is_empty());
}

/// AARCH64 from the local Ghidra distribution (skipped when absent): a small function decodes
/// to the instructions stock Ghidra shows for these encodings.
#[test]
fn aarch64_code_disassembles_with_the_distribution_language() {
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
    use crate::program::model::lang::LanguageID;
    use crate::program::util::default_language_service::DefaultLanguageService;

    let Some(dist) = ghidra_dist() else { return };
    let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
    let language = service.get_sleigh_language(&LanguageID::new("AARCH64:LE:64:v8A").unwrap()).unwrap();
    let program = ProgramDB::new("a64".into(), language.clone()).unwrap();
    // stp x29,x30,[sp,#-0x10]! ; mov x29,sp ; mov x0,x1 ; nop ; bl +0xc ; ldp x29,x30,[sp],#0x10 ; ret ; (bl target:) ret
    let words: [u32; 8] =
        [0xa9bf7bfd, 0x910003fd, 0xaa0103e0, 0xd503201f, 0x94000003, 0xa8c17bfd, 0xd65f03c0, 0xd65f03c0];
    let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let start = Address::new(language.get_default_space(), 0x10000);
    program
        .get_memory()
        .write()
        .unwrap()
        .create_initialized_block("text", &start, Some(&mut &code[..]), code.len() as i64, None, false)
        .unwrap();

    let mut cmd = DisassembleCommand::new(start.clone(), None, true);
    assert!(cmd.apply(&program, &DummyMonitor));
    let rows: Vec<(i64, String)> = program
        .instruction_summaries(&start, &start.add_wrap(0x1f))
        .into_iter()
        .map(|u| (u.address.offset() - 0x10000, format!("{} {}", u.mnemonic, u.operand_text).trim_end().to_string()))
        .collect();
    assert_eq!(
        rows,
        vec![
            (0x00, "stp x29,x30,[sp, #-0x10]!".to_string()),
            (0x04, "mov x29,sp".to_string()),
            (0x08, "mov x0,x1".to_string()),
            (0x0c, "nop".to_string()),
            (0x10, "bl 0x1001c".to_string()),
            (0x14, "ldp x29,x30,[sp], #0x10".to_string()),
            (0x18, "ret".to_string()),
            (0x1c, "ret".to_string()),
        ]
    );
}

/// ARM from the local Ghidra distribution (skipped when absent): `blx` into Thumb code commits
/// `TMode=1` at its target through the instruction's global context set, so the target decodes
/// as Thumb.
#[test]
fn arm_blx_switches_its_target_to_thumb() {
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
    use crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
    use crate::program::model::lang::LanguageID;
    use crate::program::util::default_language_service::DefaultLanguageService;

    let Some(dist) = ghidra_dist() else { return };
    let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
    let language = service.get_sleigh_language(&LanguageID::new("ARM:LE:32:v8").unwrap()).unwrap();
    let program = ProgramDB::new("arm".into(), language.clone()).unwrap();
    // ARM: blx 0x1000c ; bx lr ; (pad) ; Thumb at 0x1000c: movs r0,#1 ; bx lr
    let mut code = Vec::new();
    for w in [0xfa000001u32, 0xe12fff1e, 0xe320f000] {
        code.extend_from_slice(&w.to_le_bytes());
    }
    for h in [0x2001u16, 0x4770] {
        code.extend_from_slice(&h.to_le_bytes());
    }
    let start = Address::new(language.get_default_space(), 0x10000);
    program
        .get_memory()
        .write()
        .unwrap()
        .create_initialized_block("text", &start, Some(&mut &code[..]), code.len() as i64, None, false)
        .unwrap();

    let mut cmd = DisassembleCommand::new(start.clone(), None, true);
    assert!(cmd.apply(&program, &DummyMonitor));
    let rows: Vec<(i64, usize, String)> = program
        .instruction_summaries(&start, &start.add_wrap(0x0f))
        .into_iter()
        .map(|u| (u.address.offset() - 0x10000, u.length, format!("{} {}", u.mnemonic, u.operand_text).trim_end().to_string()))
        .collect();
    assert_eq!(
        rows,
        vec![
            (0x0, 4, "blx 0x1000c".to_string()),
            (0x4, 4, "bx lr".to_string()),
            // 2-byte Thumb instructions: TMode reached the blx target
            (0xc, 2, "movs r0,#0x1".to_string()),
            (0xe, 2, "bx lr".to_string()),
        ]
    );
}
