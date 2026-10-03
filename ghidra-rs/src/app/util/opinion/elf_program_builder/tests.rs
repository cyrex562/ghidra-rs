//! `ElfProgramBuilder` phase-1 tests: synthetic ELF images loaded into a real `ProgramDB`, with
//! the block layout Java's `ElfProgramBuilder` produces for the same image.

use super::*;
use crate::app::seam_stubs::new_string;
use crate::app::util::memory_block_utils::tests::test_language;
use crate::format::elf::elf_section_header_constants::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use crate::format::elf::elf_test_image::{provider, ElfImage};
use crate::program::database::program_db::ProgramDB;
use crate::util::task::DummyMonitor;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// One block as the tests compare it: name, start, size, r/w/x, initialized, comment.
#[derive(Debug, PartialEq)]
struct B {
    name: String,
    start: i64,
    size: u64,
    rwx: &'static str,
    init: bool,
    comment: String,
}

fn rwx(r: bool, w: bool, x: bool) -> &'static str {
    match (r, w, x) {
        (true, false, false) => "r--",
        (true, true, false) => "rw-",
        (true, false, true) => "r-x",
        (true, true, true) => "rwx",
        (false, false, false) => "---",
        (false, true, false) => "-w-",
        (false, false, true) => "--x",
        (false, true, true) => "-wx",
    }
}

fn blocks(program: &dyn Program) -> Vec<B> {
    program
        .get_memory()
        .unwrap()
        .get_block_handles()
        .iter()
        .map(|b| {
            let b = b.read().unwrap();
            B {
                name: b.get_name().to_string(),
                start: b.get_start().offset(),
                size: b.get_size(),
                rwx: rwx(b.is_read(), b.is_write(), b.is_execute()),
                init: b.is_initialized(),
                comment: b.get_comment().unwrap_or("").to_string(),
            }
        })
        .collect()
}

fn b(name: &str, start: i64, size: u64, rwx: &'static str, init: bool, comment: &str) -> B {
    B { name: name.into(), start, size, rwx, init, comment: comment.into() }
}

fn image_base_option(hex: &str) -> Vec<Box<dyn Option>> {
    vec![new_string(options_factory::IMAGE_BASE_OPTION_NAME)
        .value(Box::new(hex.to_string()))
        .build()]
}

/// Loads `bytes` the way `ElfLoader.load` does, into a fresh `ProgramDB` whose default space is
/// `space_bytes` wide.
fn load(bytes: Vec<u8>, space_bytes: u8, options: &[Box<dyn Option>]) -> (Arc<dyn Program>, Arc<MessageLog>) {
    let program: Arc<dyn Program> =
        Arc::new(ProgramDB::new("elf".into(), test_language(space_bytes, false)).unwrap());
    let log = Arc::new(MessageLog::new());
    let elf = ElfHeader::new(provider(bytes), None).unwrap();
    load_elf(elf, Arc::clone(&program), options, &log, &DummyMonitor).unwrap();
    (program, log)
}

/// A typical small executable: `.text` (RX), `.rodata` (R), `.data` + `.bss` (RW), a
/// non-allocated `.comment`, each allocated section covered by its own PT_LOAD.
fn typical_image(is64: bool, e_machine: u16, base: u64) -> (ElfImage, Vec<u8>) {
    let mut img = ElfImage::new(is64, true);
    img.e_machine = e_machine;
    img.e_entry = base + 0x1000;
    let text: Vec<u8> = (0..0x40u8).collect();
    let rodata: Vec<u8> = (0x80..0xA0u8).collect();
    let data: Vec<u8> = vec![0x11; 0x10];
    let t = img.add_section(".text", 1, (SHF_ALLOC | SHF_EXECINSTR) as u64, base + 0x1000, &text);
    let r = img.add_section(".rodata", 1, SHF_ALLOC as u64, base + 0x2000, &rodata);
    let d = img.add_section(".data", 1, (SHF_ALLOC | SHF_WRITE) as u64, base + 0x3000, &data);
    let bss = img.add_section(".bss", 8, (SHF_ALLOC | SHF_WRITE) as u64, base + 0x3010, &[]);
    img.section_mut(bss).sh_size = 0x100;
    img.add_section(".comment", 1, 0, 0, b"GCC: test\0");
    let (t_off, r_off, d_off) = (
        img.section_mut(t).sh_offset,
        img.section_mut(r).sh_offset,
        img.section_mut(d).sh_offset,
    );
    img.add_segment(1, PF_R | PF_X, t_off, base + 0x1000, 0x40, 0x40);
    img.add_segment(1, PF_R, r_off, base + 0x2000, 0x20, 0x20);
    img.add_segment(1, PF_R | PF_W, d_off, base + 0x3000, 0x10, 0x110);
    let bytes = img.build();
    (img, bytes)
}

#[test]
fn elf64_x86_64_sections_become_blocks() {
    let (_, bytes) = typical_image(true, 62, 0x400000);
    let (program, log) = load(bytes, 8, &image_base_option("401000"));
    assert_eq!(
        blocks(program.as_ref()),
        vec![
            b(".text", 0x401000, 0x40, "r-x", true, "SHT_PROGBITS  [0x401000 - 0x40103f]"),
            b(".rodata", 0x402000, 0x20, "r--", true, "SHT_PROGBITS  [0x402000 - 0x40201f]"),
            b(".data", 0x403000, 0x10, "rw-", true, "SHT_PROGBITS  [0x403000 - 0x40300f]"),
            b(".bss", 0x403010, 0x100, "rw-", false, "SHT_NOBITS  [0x403010 - 0x40310f]"),
        ]
    );
    let memory = program.get_memory().unwrap();
    let ram = program.get_image_base().unwrap().space().clone();
    let mut text = [0u8; 0x40];
    assert_eq!(memory.get_bytes(&ram.address(0x401000), &mut text), 0x40);
    assert_eq!(text.to_vec(), (0..0x40u8).collect::<Vec<_>>());
    assert_eq!(memory.get_byte(&ram.address(0x402005)).unwrap(), 0x85);
    assert!(memory.get_byte(&ram.address(0x403020)).is_err(), ".bss is uninitialized");
    let source = memory.get_block_handle(&ram.address(0x401000)).unwrap();
    assert_eq!(source.read().unwrap().get_source_name(), Some(BLOCK_SOURCE_NAME));
    // the non-allocated sections would be OTHER overlays in Java; overlays are not ported
    let text = log.to_string();
    assert!(text.contains("Failed to create '.comment' memory block"), "{text}");
    assert!(program.get_memory().unwrap().has_file_bytes());
}

#[test]
fn image_base_option_sets_program_image_base() {
    let (_, bytes) = typical_image(true, 62, 0x400000);
    let (program, _) = load(bytes, 8, &image_base_option("401000"));
    assert_eq!(program.get_image_base().unwrap().offset(), 0x401000);
}

#[test]
fn without_image_base_option_blocks_are_relative_to_existing_base() {
    // Java: "Using existing program image base of 00000000"; addresses are rebased by
    // (programImageBase - elfImageBase) = -0x401000.
    let (_, bytes) = typical_image(true, 62, 0x400000);
    let (program, log) = load(bytes, 8, &[]);
    assert!(log.to_string().contains("Using existing program image base of"));
    let starts: Vec<i64> = blocks(program.as_ref()).iter().map(|b| b.start).collect();
    assert_eq!(starts, vec![0x0, 0x1000, 0x2000, 0x2010]);
}

#[test]
fn elf64_aarch64_rebased_image() {
    // AArch64 (EM_AARCH64 = 183) shared-object-style image loaded at a chosen image base.
    let (_, bytes) = typical_image(true, 183, 0x0);
    let (program, _) = load(bytes, 8, &image_base_option("101000"));
    let got: Vec<(String, i64, &str)> =
        blocks(program.as_ref()).into_iter().map(|b| (b.name, b.start, b.rwx)).collect();
    assert_eq!(
        got,
        vec![
            (".text".into(), 0x101000, "r-x"),
            (".rodata".into(), 0x102000, "r--"),
            (".data".into(), 0x103000, "rw-"),
            (".bss".into(), 0x103010, "rw-"),
        ]
    );
}

#[test]
fn segments_only_image_keeps_execute_and_zero_extends() {
    let mut img = ElfImage::new(true, true);
    img.no_sections = true;
    let code: Vec<u8> = (1..=0x40u8).collect();
    let code_off = img.append(&code);
    let data_off = img.append(&[0x22; 0x10]);
    img.add_segment(1, PF_R | PF_X, code_off, 0x400000, 0x40, 0x40);
    img.add_segment(1, PF_R | PF_W, data_off, 0x401000, 0x10, 0x100);
    let (program, _) = load(img.build(), 8, &image_base_option("400000"));
    assert_eq!(
        blocks(program.as_ref()),
        vec![
            b("segment_0", 0x400000, 0x40, "r-x", true, "Loadable segment  [0x400000 - 0x40003f]"),
            b(
                "segment_1",
                0x401000,
                0x100,
                "rw-",
                true,
                "Loadable segment  [0x401000 - 0x4010ff] (zero-extended)"
            ),
        ]
    );
    let memory = program.get_memory().unwrap();
    let ram = program.get_image_base().unwrap().space().clone();
    assert_eq!(memory.get_byte(&ram.address(0x400000)).unwrap(), 1);
    assert_eq!(memory.get_byte(&ram.address(0x401050)).unwrap(), 0);
}

#[test]
fn segment_with_sections_disables_execute_and_fragments() {
    // A PT_LOAD that covers .text plus bytes no section claims: the segment's leftover bytes
    // become `segment_0.N` blocks without execute (sections present => execute bit disabled).
    let mut img = ElfImage::new(true, true);
    let pre: Vec<u8> = vec![0x90; 0x20];
    let pre_off = img.append(&pre);
    let text: Vec<u8> = vec![0xC3; 0x20];
    let t = img.add_section(".text", 1, (SHF_ALLOC | SHF_EXECINSTR) as u64, 0x400020, &text);
    let t_off = img.section_mut(t).sh_offset;
    assert_eq!(t_off, pre_off + 0x20);
    img.add_segment(1, PF_R | PF_X, pre_off, 0x400000, 0x40, 0x40);
    let (program, _) = load(img.build(), 8, &image_base_option("400000"));
    assert_eq!(
        blocks(program.as_ref()),
        vec![
            b(
                "segment_0.1",
                0x400000,
                0x20,
                "r--",
                true,
                "Loadable segment  [0x400000 - 0x40003f] (disabled execute bit)"
            ),
            b(".text", 0x400020, 0x20, "r-x", true, "SHT_PROGBITS  [0x400020 - 0x40003f]"),
        ]
    );
}

#[test]
fn zero_filler_segment_fragment_is_discarded() {
    // Same as above but the segment-only bytes are zero and smaller than the 0xff discard
    // size: Java drops them ("Discarding ... alignment/filler").
    let mut img = ElfImage::new(true, true);
    let pre_off = img.append(&[0u8; 0x20]);
    let t = img.add_section(".text", 1, (SHF_ALLOC | SHF_EXECINSTR) as u64, 0x400020, &[0xC3; 0x20]);
    assert_eq!(img.section_mut(t).sh_offset, pre_off + 0x20);
    img.add_segment(1, PF_R | PF_X, pre_off, 0x400000, 0x40, 0x40);
    let (program, _) = load(img.build(), 8, &image_base_option("400000"));
    let names: Vec<String> = blocks(program.as_ref()).into_iter().map(|b| b.name).collect();
    assert_eq!(names, vec![".text".to_string()]);
}

#[test]
fn relocatable_object_sections_are_packed_at_image_base() {
    // ET_REL: allocated sections at address 0 are packed from the image base, each aligned.
    let mut img = ElfImage::new(true, true);
    img.e_type = 1;
    let t = img.add_section(".text", 1, (SHF_ALLOC | SHF_EXECINSTR) as u64, 0, &[0xC3; 0x13]);
    img.section_mut(t).sh_addralign = 0x10;
    let d = img.add_section(".data", 1, (SHF_ALLOC | SHF_WRITE) as u64, 0, &[0x5A; 0x8]);
    img.section_mut(d).sh_addralign = 0x10;
    let (program, _) = load(img.build(), 8, &image_base_option("100000"));
    let got: Vec<(String, i64, u64)> =
        blocks(program.as_ref()).into_iter().map(|b| (b.name, b.start, b.size)).collect();
    assert_eq!(got, vec![(".text".into(), 0x100000, 0x13), (".data".into(), 0x100020, 0x8)]);
}

#[test]
fn elf32_little_endian_layout() {
    let (_, bytes) = typical_image(false, 3, 0x8048000);
    let (program, _) = load(bytes, 4, &image_base_option("8049000"));
    let got: Vec<(String, i64)> = blocks(program.as_ref()).into_iter().map(|b| (b.name, b.start)).collect();
    assert_eq!(
        got,
        vec![
            (".text".into(), 0x8049000),
            (".rodata".into(), 0x804a000),
            (".data".into(), 0x804b000),
            (".bss".into(), 0x804b010),
        ]
    );
}

#[test]
fn section_comment_matches_java_format() {
    assert_eq!(get_section_comment(0x1000, 0x10, 1, Some("SHT_PROGBITS"), true), "SHT_PROGBITS  [0x1000 - 0x100f]");
    assert_eq!(get_section_comment(0x1000, 0x10, 2, None, true), "[0x1000 - 0x1007]");
    assert_eq!(get_section_comment(0, 4, 1, Some("SHT_STRTAB"), false), "SHT_STRTAB [not-loaded]");
}

/// Loads the host's `/bin/ls` (when present) with the image base Ghidra's options would pick.
#[test]
fn bin_ls_smoke() {
    let path = std::path::Path::new("/bin/ls");
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 {
        return; // not a 64-bit little-endian ELF
    }
    let probe = ElfHeader::new(provider(bytes.clone()), None).unwrap();
    let mut image_base = probe.find_image_base();
    if image_base == 0 && (probe.is_relocatable() || probe.is_shared_object()) {
        image_base = options_factory::IMAGE64_BASE_DEFAULT;
    }
    let entry = probe.e_entry();
    let elf_image_base = {
        let mut h = ElfHeader::new(provider(bytes.clone()), None).unwrap();
        h.parse().unwrap();
        h.get_image_base()
    };
    let (program, _) = load(bytes, 8, &image_base_option(&format!("{image_base:x}")));
    let all = blocks(program.as_ref());
    assert!(!all.is_empty());
    let entry_addr = entry - elf_image_base + image_base;
    let entry_block = all
        .iter()
        .find(|b| b.start <= entry_addr && entry_addr < b.start + b.size as i64)
        .unwrap_or_else(|| panic!("no block contains entry {entry_addr:#x}: {all:?}"));
    assert!(entry_block.rwx.ends_with('x'), "{entry_block:?}");
    assert!(entry_block.init);
    assert!(all.iter().any(|b| b.name == ".text"));
}

/// End to end with a real language: `/bin/ls` into a `ProgramDB` built on the decoded
/// `x86-64.sla` from the local Ghidra distribution (both optional on the host). The bytes at the
/// entry point must be the file's bytes at the entry's file offset.
#[test]
fn bin_ls_with_real_x86_64_language() {
    use crate::pcode::utils::sla_format::{build_decoder, tests::dist_sla};
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::lang::sleigh::SleighLanguage;

    let Some(sla) = dist_sla("x86", "x86-64.sla") else {
        return;
    };
    let Ok(bytes) = std::fs::read("/bin/ls") else {
        return;
    };
    if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 {
        return; // not x86-64
    }
    let decoder = build_decoder(&sla, Arc::new(DefaultAddressFactory::new(vec![]))).unwrap();
    let language = Arc::new(SleighLanguage::decode(&decoder, "x86:LE:64:default".to_string()).unwrap());
    let program: Arc<dyn Program> = Arc::new(ProgramDB::new("ls".into(), language).unwrap());

    let parsed = {
        let mut h = ElfHeader::new(provider(bytes.clone()), None).unwrap();
        h.parse().unwrap();
        h
    };
    let mut image_base = parsed.find_image_base();
    if image_base == 0 && parsed.is_shared_object() {
        image_base = options_factory::IMAGE64_BASE_DEFAULT;
    }
    let adjust = image_base - parsed.get_image_base();
    let text = parsed.get_section(".text").unwrap().expect(".text");
    let entry = parsed.e_entry();
    let entry_file_offset = (entry - text.get_address() + text.get_offset()) as usize;

    let log = Arc::new(MessageLog::new());
    let elf = ElfHeader::new(provider(bytes.clone()), None).unwrap();
    load_elf(elf, Arc::clone(&program), &image_base_option(&format!("{image_base:x}")), &log, &DummyMonitor).unwrap();

    let memory = program.get_memory().unwrap();
    let ram = program.get_image_base().unwrap().space().clone();
    let entry_addr = ram.address(entry + adjust);
    let block = memory.get_block_handle(&entry_addr).expect("entry is in memory");
    {
        let b = block.read().unwrap();
        assert_eq!(b.get_name(), ".text");
        assert!(b.is_execute() && b.is_read() && !b.is_write());
    }
    let mut got = [0u8; 16];
    assert_eq!(memory.get_bytes(&entry_addr, &mut got), 16);
    assert_eq!(&got[..], &bytes[entry_file_offset..entry_file_offset + 16]);
    let names: Vec<String> = blocks(program.as_ref()).into_iter().map(|b| b.name).collect();
    for expected in [".text", ".rodata", ".data", ".bss", ".dynamic", ".got"] {
        assert!(names.iter().any(|n| n == expected), "missing {expected}: {names:?}");
    }
}

#[test]
fn original_value_reads_memory_without_relocations() {
    let (_, bytes) = typical_image(true, 62, 0x400000);
    let program: Arc<dyn Program> =
        Arc::new(ProgramDB::new("elf".into(), test_language(8, false)).unwrap());
    let log = Arc::new(MessageLog::new());
    let elf = ElfHeader::new(provider(bytes), None).unwrap();
    let options = image_base_option("401000");
    let mut builder = ElfProgramBuilder::new(elf, Arc::clone(&program), &options, log).unwrap();
    builder.load(&DummyMonitor).unwrap();
    let ram = program.get_image_base().unwrap().space().clone();
    // .rodata holds 0x80, 0x81, ... little-endian
    assert_eq!(builder.get_original_value(ram.address(0x402000), false).unwrap(), 0x8786858483828180u64 as i64);
    assert_eq!(builder.get_original_value(ram.address(0x402000), true).unwrap(), 0x8786858483828180u64 as i64);
    assert!(builder.get_original_value(ram.address(0x403020), false).is_err(), "uninitialized .bss");
    assert_eq!(data_value(&[0xff, 0xfe], true, true), -2);
    assert_eq!(data_value(&[0xff, 0xfe], true, false), 0xfffe);
    assert_eq!(data_value(&[0xfe, 0xff, 0xff, 0xff], false, true), -2);
    assert_eq!(builder.get_default_address(0x10).offset(), 0x10);
    assert_eq!(builder.get_image_base_word_adjustment_offset(), 0);
}

/// Robustness sweep over host ELF files (`/usr/bin`, `/usr/lib/x86_64-linux-gnu`): every
/// 64-bit little-endian image must load without panicking and produce memory. Ignored by default
/// (host-dependent and slow); run with `--ignored`.
#[test]
#[ignore]
fn host_elf_sweep() {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for dir in ["/usr/bin", "/usr/lib/x86_64-linux-gnu"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut v: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            v.sort();
            files.extend(v.into_iter().step_by(7).take(150));
        }
    }
    let mut failures = Vec::new();
    let mut loaded = 0;
    for path in files {
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if !meta.is_file() || meta.len() > 32 << 20 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 {
            continue;
        }
        let result = std::panic::catch_unwind(|| {
            let probe = ElfHeader::new(provider(bytes.clone()), None).ok()?;
            let mut image_base = probe.find_image_base();
            if image_base == 0 && (probe.is_relocatable() || probe.is_shared_object()) {
                image_base = options_factory::IMAGE64_BASE_DEFAULT;
            }
            let program: Arc<dyn Program> =
                Arc::new(ProgramDB::new("sweep".into(), test_language(8, false)).unwrap());
            let log = Arc::new(MessageLog::new());
            let elf = ElfHeader::new(provider(bytes.clone()), None).ok()?;
            load_elf(elf, Arc::clone(&program), &image_base_option(&format!("{image_base:x}")), &log, &DummyMonitor)
                .ok()?;
            Some(program.get_memory().unwrap().get_block_handles().len())
        });
        match result {
            Ok(Some(n)) if n > 0 => loaded += 1,
            Ok(other) => failures.push(format!("{}: {other:?}", path.display())),
            Err(_) => failures.push(format!("{}: PANIC", path.display())),
        }
    }
    eprintln!("loaded {loaded}, failures {}: {failures:#?}", failures.len());
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------------------------------
// Phase 2: symbols, the EXTERNAL block, entry points (Java's processSymbolTables /
// evaluateElfSymbol / createSymbol / checkPrimary / processEntryPoints).
// ---------------------------------------------------------------------------------------------

mod phase2 {
    use super::*;
    use crate::format::elf::elf_section_header_constants::{SHN_ABS, SHT_DYNSYM, SHT_STRTAB, SHT_SYMTAB};
    use crate::format::elf::elf_symbol::{STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION, STT_TLS};
    use crate::format::elf::elf_test_image::StrTab;
    use crate::program::model::mem::memory_block::EXTERNAL_BLOCK_NAME;
    use crate::program::model::symbol::SourceType;

    const BASE: u64 = 0x400000;

    fn info(bind: u8, ty: u8) -> u8 {
        (bind << 4) | ty
    }

    /// One symbol as the tests compare it: name, address offset, primary, pinned.
    #[derive(Debug, PartialEq)]
    struct S {
        name: String,
        addr: i64,
        primary: bool,
        pinned: bool,
    }

    fn s(name: &str, addr: i64, primary: bool, pinned: bool) -> S {
        S { name: name.into(), addr, primary, pinned }
    }

    /// Every symbol in the program's symbol table, in address order.
    fn symbols(program: &dyn Program) -> Vec<S> {
        let table = program.get_symbol_table().unwrap();
        let mut it = table.get_all_symbols(true);
        let mut out = Vec::new();
        while let Some(sym) = it.next_symbol() {
            assert_eq!(sym.get_source(), SourceType::Imported, "{}", sym.get_name());
            out.push(s(sym.get_name(), sym.get_address().offset(), sym.is_primary(), sym.is_pinned()));
        }
        out
    }

    fn entry_points(program: &dyn Program) -> Vec<i64> {
        program.get_symbol_table().unwrap().get_external_entry_point_iterator().map(|a| a.offset()).collect()
    }

    /// A static executable with `.text` (RX, 0x401000) and `.data` (RW, 0x403000), a `.dynsym`
    /// importing `puts` and a `.symtab` with a file symbol, a section symbol, `$x` + `main` at
    /// the same address, a weak function, a local object, an absolute symbol, a TLS symbol, the
    /// `puts` import again and a versioned `puts@GLIBC_2.2.5`.
    fn symbol_image() -> Vec<u8> {
        let mut img = ElfImage::new(true, true);
        img.e_entry = BASE + 0x1000;
        let e = img.enc;
        let t = img.add_section(".text", 1, (SHF_ALLOC | SHF_EXECINSTR) as u64, BASE + 0x1000, &[0x90; 0x40]);
        let d = img.add_section(".data", 1, (SHF_ALLOC | SHF_WRITE) as u64, BASE + 0x3000, &[0x11; 0x10]);

        let mut dynstr = StrTab::new();
        let dputs = dynstr.add("puts");
        let dynstr_idx = img.add_section(".dynstr", SHT_STRTAB, 0, 0, &dynstr.bytes());
        let mut dsyms = e.sym(0, 0, 0, 0, 0, 0);
        dsyms.extend(e.sym(dputs, 0, 0, info(STB_GLOBAL, STT_FUNC), 0, 0));
        let dynsym = img.add_section(".dynsym", SHT_DYNSYM, 0, 0, &dsyms);
        img.section_mut(dynsym).sh_link = dynstr_idx;
        img.section_mut(dynsym).sh_info = 1;
        img.section_mut(dynsym).sh_entsize = e.sym_size();

        let mut strtab = StrTab::new();
        let file = strtab.add("a.c");
        let dollar_x = strtab.add("$x");
        let main = strtab.add("main");
        let weak_fn = strtab.add("weak_fn");
        let local_obj = strtab.add("local_obj");
        let abs_sym = strtab.add("abs_sym");
        let tls_var = strtab.add("tls_var");
        let puts = strtab.add("puts");
        let puts_v = strtab.add("puts@GLIBC_2.2.5");
        let strtab_idx = img.add_section(".strtab", SHT_STRTAB, 0, 0, &strtab.bytes());
        let mut syms = e.sym(0, 0, 0, 0, 0, 0);
        syms.extend(e.sym(file, 0, 0, info(STB_LOCAL, STT_FILE), 0, SHN_ABS));
        syms.extend(e.sym(0, BASE + 0x1000, 0, info(STB_LOCAL, STT_SECTION), 0, t as u16));
        syms.extend(e.sym(dollar_x, BASE + 0x1010, 0, info(STB_LOCAL, STT_NOTYPE), 0, t as u16));
        syms.extend(e.sym(local_obj, BASE + 0x3000, 8, info(STB_LOCAL, STT_OBJECT), 0, d as u16));
        syms.extend(e.sym(tls_var, 0, 4, info(STB_LOCAL, STT_TLS), 0, d as u16));
        syms.extend(e.sym(main, BASE + 0x1010, 0x10, info(STB_GLOBAL, STT_FUNC), 0, t as u16));
        syms.extend(e.sym(weak_fn, BASE + 0x1020, 0x10, info(STB_WEAK, STT_FUNC), 0, t as u16));
        syms.extend(e.sym(abs_sym, 0x5000, 0, info(STB_GLOBAL, STT_OBJECT), 0, SHN_ABS));
        syms.extend(e.sym(puts, 0, 0, info(STB_GLOBAL, STT_FUNC), 0, 0));
        syms.extend(e.sym(puts_v, 0, 0, info(STB_GLOBAL, STT_FUNC), 0, 0));
        let symtab = img.add_section(".symtab", SHT_SYMTAB, 0, 0, &syms);
        img.section_mut(symtab).sh_link = strtab_idx;
        img.section_mut(symtab).sh_info = 5;
        img.section_mut(symtab).sh_entsize = e.sym_size();

        let (t_off, d_off) = (img.section_mut(t).sh_offset, img.section_mut(d).sh_offset);
        img.add_segment(1, PF_R | PF_X, t_off, BASE + 0x1000, 0x40, 0x40);
        img.add_segment(1, PF_R | PF_W, d_off, BASE + 0x3000, 0x10, 0x10);
        img.build()
    }

    #[test]
    fn symbol_tables_become_program_symbols() {
        let (program, log) = load(symbol_image(), 8, &image_base_option("401000"));
        assert_eq!(
            symbols(program.as_ref()),
            vec![
                s("abs_sym", 0x5000, true, true),
                s("$x", 0x401010, false, false),
                s("main", 0x401010, true, false),
                s("weak_fn", 0x401020, true, false),
                s("local_obj", 0x403000, true, false),
                s("puts", 0x404000, true, false),
            ],
            "{log}"
        );
        let text = log.to_string();
        assert!(text.contains("Unsupported Thread-Local Symbol not loaded: tls_var"), "{text}");
    }

    #[test]
    fn imports_are_allocated_in_an_artificial_external_block() {
        let (program, _) = load(symbol_image(), 8, &image_base_option("401000"));
        let memory = program.get_memory().unwrap();
        let ram = program.get_image_base().unwrap().space().clone();
        let block = memory.get_block_handle(&ram.address(0x404000)).expect("EXTERNAL block");
        let block = block.read().unwrap();
        assert_eq!(block.get_name(), EXTERNAL_BLOCK_NAME);
        assert_eq!(block.get_size(), 8);
        assert!(block.is_artificial());
        assert!(block.is_write());
        assert!(!block.is_initialized());
        assert_eq!(block.get_source_name(), Some(BLOCK_SOURCE_NAME));
        assert_eq!(
            block.get_comment(),
            Some("NOTE: This block is artificial and allows ELF Relocations to work correctly")
        );
    }

    #[test]
    fn global_and_weak_symbols_and_the_entry_are_external_entry_points() {
        let (program, log) = load(symbol_image(), 8, &image_base_option("401000"));
        // e_entry (0x401000, executable) + main + weak_fn + abs_sym; not the fake-external puts
        // nor the local symbols
        assert_eq!(entry_points(program.as_ref()), vec![0x5000, 0x401000, 0x401010, 0x401020]);
        let text = log.to_string();
        assert!(text.contains("ELF function creation is not supported by this loader yet"), "{text}");
        assert_eq!(text.matches("ELF function creation is not supported").count(), 1, "logged once");
    }

    #[test]
    fn entry_outside_executable_memory_is_not_an_entry_point() {
        let bytes = {
            let mut img = ElfImage::new(true, true);
            img.e_entry = BASE + 0x3004;
            let d = img.add_section(".data", 1, (SHF_ALLOC | SHF_WRITE) as u64, BASE + 0x3000, &[0x11; 0x10]);
            let d_off = img.section_mut(d).sh_offset;
            img.add_segment(1, PF_R | PF_W, d_off, BASE + 0x3000, 0x10, 0x10);
            img.build()
        };
        let (program, _) = load(bytes, 8, &image_base_option("403000"));
        assert!(entry_points(program.as_ref()).is_empty());
        assert!(symbols(program.as_ref()).is_empty());
    }

    #[test]
    fn elf_symbol_addresses_are_remembered() {
        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("elf".into(), test_language(8, false)).unwrap());
        let log = Arc::new(MessageLog::new());
        let elf = ElfHeader::new(provider(symbol_image()), None).unwrap();
        let options = image_base_option("401000");
        let mut builder = ElfProgramBuilder::new(elf, Arc::clone(&program), &options, log).unwrap();
        builder.load(&DummyMonitor).unwrap();
        let tables = builder.get_elf_header().get_symbol_tables().to_vec();
        let at = |table: usize, name: &str| {
            let sym = tables[table]
                .get_symbols()
                .iter()
                .find(|s| s.get_name_as_string() == Some(name))
                .unwrap_or_else(|| panic!("{name}"));
            builder.get_elf_symbol_address(sym).map(|a| a.offset())
        };
        let (dynsym, symtab) = if tables[0].is_dynamic() { (0, 1) } else { (1, 0) };
        assert_eq!(at(symtab, "main"), Some(0x401010));
        assert_eq!(at(dynsym, "puts"), Some(0x404000));
        // duplicate and versioned externals reuse the first allocation
        assert_eq!(at(symtab, "puts"), Some(0x404000));
        assert_eq!(at(symtab, "puts@GLIBC_2.2.5"), Some(0x404000));
        assert_eq!(at(symtab, "tls_var"), None);
        assert_eq!(at(symtab, "a.c"), None);
    }

    #[test]
    fn got_value_falls_back_to_the_global_offset_table_symbol() {
        let mut img = ElfImage::new(true, true);
        let e = img.enc;
        let d = img.add_section(".got", 1, (SHF_ALLOC | SHF_WRITE) as u64, BASE + 0x3000, &[0; 0x10]);
        let mut strtab = StrTab::new();
        let got = strtab.add("_GLOBAL_OFFSET_TABLE_");
        let strtab_idx = img.add_section(".strtab", SHT_STRTAB, 0, 0, &strtab.bytes());
        let mut syms = e.sym(0, 0, 0, 0, 0, 0);
        syms.extend(e.sym(got, BASE + 0x3008, 0, info(STB_LOCAL, STT_OBJECT), 0, d as u16));
        let symtab = img.add_section(".symtab", SHT_SYMTAB, 0, 0, &syms);
        img.section_mut(symtab).sh_link = strtab_idx;
        img.section_mut(symtab).sh_info = 2;
        img.section_mut(symtab).sh_entsize = e.sym_size();
        let d_off = img.section_mut(d).sh_offset;
        img.add_segment(1, PF_R | PF_W, d_off, BASE + 0x3000, 0x10, 0x10);

        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("elf".into(), test_language(8, false)).unwrap());
        let elf = ElfHeader::new(provider(img.build()), None).unwrap();
        let options = image_base_option("403000");
        let mut builder = ElfProgramBuilder::new(elf, Arc::clone(&program), &options, Arc::new(MessageLog::new())).unwrap();
        builder.load(&DummyMonitor).unwrap();
        assert_eq!(builder.get_got_value(), Some(0x403008));
    }

    #[test]
    fn linkage_blocks_avoid_memory_and_earlier_allocations() {
        let (_, bytes) = typical_image(true, 62, BASE);
        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("elf".into(), test_language(4, false)).unwrap());
        let elf = ElfHeader::new(provider(bytes), None).unwrap();
        let options = image_base_option("401000");
        let mut builder = ElfProgramBuilder::new(elf, Arc::clone(&program), &options, Arc::new(MessageLog::new())).unwrap();
        builder.load(&DummyMonitor).unwrap();
        // blocks end at .bss 0x40310f: the last free range [0x403110, 0xffffffff] is the biggest
        let first = builder.allocate_linkage_block(0x1000, 0x100, "test").unwrap();
        assert_eq!((first.min_address().offset(), first.max_address().offset()), (0x404000, 0x4040ff));
        let second = builder.allocate_linkage_block(0x1000, 0x100, "test").unwrap();
        assert_eq!(second.min_address().offset(), 0x405000);
        // size <= 0: the whole free range, not recorded as allocated
        let open = builder.allocate_linkage_block(0x1000, -1, "EXTERNAL block").unwrap();
        assert_eq!((open.min_address().offset(), open.max_address().offset()), (0x406000, 0xffffffff));
    }

    /// Acceptance: `x86:LE:64:default` from the language service over the local Ghidra
    /// distribution -> `ProgramDB` -> `/bin/ls` through `ElfLoader`: the imports become symbols
    /// in the EXTERNAL block, `_start` (when the binary still has a `.symtab`) is a symbol, and
    /// the ELF entry is a registered entry point. Skipped when the distribution or an x86-64
    /// `/bin/ls` is absent.
    #[test]
    fn bin_ls_symbols_and_entry_via_language_service() {
        use crate::app::plugin::processors::sleigh::sleigh_language_provider::tests::ghidra_dist;
        use crate::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
        use crate::app::util::opinion::elf_loader::ElfLoader;
        use crate::program::model::lang::LanguageID;
        use crate::program::util::default_language_service::DefaultLanguageService;

        let Some(dist) = ghidra_dist() else {
            return;
        };
        let Ok(bytes) = std::fs::read("/bin/ls") else {
            return;
        };
        if bytes.len() < 0x40 || bytes[..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 {
            return; // not x86-64
        }
        let parsed = {
            let mut h = ElfHeader::new(provider(bytes.clone()), None).unwrap();
            h.parse().unwrap();
            h
        };
        let import = parsed
            .get_symbol_tables()
            .iter()
            .filter(|t| t.is_dynamic())
            .flat_map(|t| t.get_symbols().iter())
            .find(|s| {
                s.get_section_header_index() == 0
                    && s.get_type() == STT_FUNC
                    && s.get_name_as_string().is_some_and(|n| !n.is_empty() && !n.contains('@'))
            })
            .and_then(|s| s.get_name_as_string())
            .expect("a dynamic function import")
            .to_string();
        let has_start = parsed
            .get_symbol_tables()
            .iter()
            .flat_map(|t| t.get_symbols().iter())
            .any(|s| s.get_name_as_string() == Some("_start"));
        let entry = parsed.e_entry() + 0x100000 - parsed.get_image_base();

        let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(&dist));
        let language = service.get_sleigh_language(&LanguageID::new("x86:LE:64:default").unwrap()).unwrap();
        let program: Arc<dyn Program> = Arc::new(ProgramDB::new("ls".into(), language).unwrap());
        let log = Arc::new(MessageLog::new());
        ElfLoader::new()
            .load(provider(bytes), &program, &image_base_option("100000"), &log, &DummyMonitor)
            .unwrap();

        let all = symbols(program.as_ref());
        let external = program
            .get_memory()
            .unwrap()
            .get_block_handles()
            .into_iter()
            .find(|b| b.read().unwrap().get_name() == EXTERNAL_BLOCK_NAME)
            .expect("EXTERNAL block");
        let external = external.read().unwrap();
        let sym = all.iter().find(|s| s.name == import).unwrap_or_else(|| panic!("no {import}: {log}"));
        assert!(external.contains(&program.get_image_base().unwrap().space().address(sym.addr)), "{import} at {:#x}", sym.addr);
        if has_start {
            assert!(all.iter().any(|s| s.name == "_start"));
        }
        let entries = entry_points(program.as_ref());
        assert!(entries.contains(&entry), "entry {entry:#x} not in {entries:x?}");
    }
}
