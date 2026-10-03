//! Opening a real ELF for the shell (`ghidra-qt --open`): ELF → language from
//! a compiled `.sla` of a local Ghidra distribution (user ruling 2026-10-02:
//! the dist `.sla` files may back tests and the dev app until the Rust sleigh
//! compiler produces them) → `ProgramDB` via the ported `ElfLoader` → a
//! memory snapshot for the listing.

use std::path::{Path, PathBuf};

use crate::code_unit_listing::{BlockHeader, InstructionSnapshot, OperandRef};
use crate::listing::MemoryBlockSnapshot;
use ghidra_rs::program::database::program_db::ProgramDB;
use std::sync::Arc;
use ghidra_rs::program::model::mem::memory_block_type::MemoryBlockType;

/// What the shell shows of an imported program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedProgram {
    /// File name.
    pub name: String,
    /// Language id, e.g. `x86:LE:64:default`.
    pub language: String,
    /// Address size in bits.
    pub address_bits: u32,
    /// Loaded-memory blocks for the listing.
    pub blocks: Vec<MemoryBlockSnapshot>,
    /// Block names in address order (Program Tree).
    pub block_names: Vec<String>,
    /// Each named block's start, parallel to `block_names`.
    pub block_starts: Vec<u64>,
    /// The symbol table in loaded memory, address order (Symbols pane).
    pub symbols: Vec<ImportedSymbol>,
    /// Each loaded block's `//` start header.
    pub block_headers: Vec<BlockHeader>,
    /// Decoded instructions (empty until the disassembler runs).
    pub instructions: Vec<crate::code_unit_listing::InstructionSnapshot>,
    /// The open program behind this snapshot, for edits (none for fixtures).
    pub live: Option<LiveProgram>,
}

/// The open program an [`ImportedProgram`] was taken from. Equal only to
/// itself (the same program).
#[derive(Clone)]
pub struct LiveProgram(Arc<ProgramDB>);

impl LiveProgram {
    /// Wraps an open program.
    pub fn new(program: Arc<ProgramDB>) -> Self {
        Self(program)
    }

    /// The program.
    pub fn program(&self) -> &Arc<ProgramDB> {
        &self.0
    }
}

impl PartialEq for LiveProgram {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for LiveProgram {}

impl std::fmt::Debug for LiveProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LiveProgram").finish_non_exhaustive()
    }
}

/// The instructions starting in `start..=end`, in address order.
pub fn instructions_in(
    program: &Arc<ProgramDB>,
    start: &ghidra_rs::program::model::address::Address,
    end: &ghidra_rs::program::model::address::Address,
) -> Vec<InstructionSnapshot> {
    use ghidra_rs::program::model::symbol::reference::Reference;
    let summaries = program.instruction_summaries(start, end);
    let references: Vec<Vec<OperandRef>> = {
        let refs = program.get_reference_store();
        let refs = refs.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        summaries
            .iter()
            .map(|u| {
                (0..u.operands.len() as i32)
                    .filter_map(|op| refs.primary_reference_from(&u.address, op))
                    .filter(|r| r.is_memory_reference())
                    .map(|r| OperandRef { op_index: r.operand_index(), to: r.to_address().offset() as u64 })
                    .collect()
            })
            .collect()
    };
    // CodeUnitFormat text (symbols, dynamic labels) where an operand has a
    // reference; plain text otherwise. No store lock is held here.
    summaries
        .into_iter()
        .zip(references)
        .map(|(u, references)| {
            let operands = if references.is_empty() {
                u.operand_text
            } else {
                program.operand_display(&u.address).map_or(u.operand_text, |d| d.operand_field)
            };
            InstructionSnapshot {
                references,
                start: u.address.offset() as u64,
                len: u32::try_from(u.length).unwrap_or(u32::MAX),
                mnemonic: u.mnemonic,
                operands,
            }
        })
        .collect()
}

/// Every instruction in the program's loaded memory, in address order.
pub fn snapshot_instructions(program: &Arc<ProgramDB>) -> Vec<InstructionSnapshot> {
    use ghidra_rs::program::model::listing::Program;
    let Some(memory) = Program::get_memory(program.as_ref()) else { return Vec::new() };
    let mut instructions: Vec<InstructionSnapshot> = memory
        .get_block_handles()
        .iter()
        .filter_map(|h| h.read().ok().map(|b| (b.get_start(), b.get_end())))
        .filter(|(start, _)| start.space().is_loaded_memory_space())
        .flat_map(|(start, end)| instructions_in(program, &start, &end))
        .collect();
    instructions.sort_by_key(|i| i.start);
    instructions
}

/// One symbol as the Symbols pane shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSymbol {
    /// Name.
    pub name: String,
    /// Address offset.
    pub address: u64,
    /// Symbol type ("Label", "Function", ...).
    pub kind: String,
    /// Source ("Imported", "Analysis", ...).
    pub source: String,
    /// The address's primary symbol.
    pub primary: bool,
    /// The symbol's id in the program (0 for fixtures).
    pub id: i64,
}

/// The Ghidra distribution whose compiled languages back imports:
/// `$GHIDRA_RS_GHIDRA_DIST`, else `tools/ghidra-dist/ghidra_12.1.2_PUBLIC`
/// (fetched by `scripts/fixtures/setup_ghidra.sh`).
pub fn default_ghidra_dist() -> Option<PathBuf> {
    let p = std::env::var_os("GHIDRA_RS_GHIDRA_DIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/ghidra-dist/ghidra_12.1.2_PUBLIC")));
    p.is_dir().then_some(p)
}

/// The Source column text (Java `SourceType.getDisplayString`).
fn source_display(source: ghidra_rs::program::model::symbol::SourceType) -> String {
    source.display_string().to_owned()
}

/// (processor dir, .sla file, language id) for an ELF's class
/// (`EI_CLASS`: 1 = 32-bit, 2 = 64-bit), data encoding (`EI_DATA`: 1 = LE,
/// 2 = BE) and `e_machine`.
fn language_for(class: u8, data: u8, machine: u16) -> Result<(&'static str, &'static str, &'static str), String> {
    match (machine, class, data) {
        (62, 2, 1) => Ok(("x86", "x86-64.sla", "x86:LE:64:default")),
        (62, 1, _) => Err("unsupported ELF: 32-bit x86-64 (x32)".into()),
        (183, 2, 1) => Ok(("AARCH64", "AARCH64.sla", "AARCH64:LE:64:v8A")),
        (183, 2, 2) => Ok(("AARCH64", "AARCH64BE.sla", "AARCH64:BE:64:v8A")),
        (m @ (62 | 183), c, d) => Err(format!("unsupported ELF machine {m} (class {c}, data encoding {d})")),
        (m, _, _) => Err(format!("unsupported ELF machine {m}")),
    }
}

/// The entry points Ghidra's EntryPointAnalyzer disassembles: those inside an
/// executable block (`[start, end]` ranges), or all when no block is executable.
fn executable_entries(entries: &[u64], exec: &[(u64, u64)]) -> Vec<u64> {
    entries.iter().copied().filter(|&a| exec.is_empty() || exec.iter().any(|&(lo, hi)| lo <= a && a <= hi)).collect()
}

/// Imports the ELF at `path` using the compiled languages under `dist`.
pub fn import_elf(path: &Path, dist: &Path) -> Result<ImportedProgram, String> {
    use ghidra_rs::app::seam_stubs::{new_string, Option as LoaderOption};
    use ghidra_rs::app::util::bin::byte_array_provider::ByteArrayProvider;
    use ghidra_rs::app::util::bin::byte_provider::ByteProvider;
    use ghidra_rs::app::util::importer::message_log::MessageLog;
    use ghidra_rs::app::util::opinion::elf_loader::ElfLoader;
    use ghidra_rs::app::util::opinion::elf_loader_options_factory::{
        IMAGE32_BASE_DEFAULT, IMAGE64_BASE_DEFAULT, IMAGE_BASE_OPTION_NAME,
    };
    use ghidra_rs::format::elf::elf_header::ElfHeader;
    use ghidra_rs::app::plugin::processors::sleigh::sleigh_language_provider::SleighLanguageProvider;
    use ghidra_rs::program::model::lang::LanguageID;
    use ghidra_rs::program::util::default_language_service::DefaultLanguageService;
    use ghidra_rs::program::disassemble::disassembler::Disassembler;
    use ghidra_rs::program::model::listing::Program;
    use ghidra_rs::util::task::DummyMonitor;
    use std::rc::Rc;

    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() < 20 || bytes[..4] != *b"\x7fELF" {
        return Err(format!("not an ELF file: {}", path.display()));
    }
    let machine = if bytes[5] == 2 { u16::from_be_bytes([bytes[18], bytes[19]]) } else { u16::from_le_bytes([bytes[18], bytes[19]]) };
    let (processor, sla_file, language) = language_for(bytes[4], bytes[5], machine)?;
    let sla = dist.join("Ghidra/Processors").join(processor).join("data/languages").join(sla_file);
    if !sla.is_file() {
        return Err(format!(
            "no compiled language {} (set GHIDRA_RS_GHIDRA_DIST to a Ghidra 12.1.2 install)",
            sla.display()
        ));
    }
    // The language service applies the .ldefs/.pspec context and shares the
    // language, as the disassembler needs.
    let service = DefaultLanguageService::from_sleigh_provider(SleighLanguageProvider::from_ghidra_installation(dist));
    let id = LanguageID::new(language).map_err(|e| format!("{language}: {e:?}"))?;
    let lang = service.get_sleigh_language(&id).map_err(|e| format!("{language}: {e:?}"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let db = Arc::new(ProgramDB::new(name.clone(), lang).map_err(|e| e.to_string())?);
    let program: Arc<dyn Program> = db.clone();

    // The image base Ghidra's ELF options pick (ElfLoaderOptionsFactory).
    let provider = || -> Rc<dyn ByteProvider> { Rc::new(ByteArrayProvider::new(bytes.clone())) };
    let probe = ElfHeader::new(provider(), None).map_err(|e| format!("bad ELF header: {e:?}"))?;
    let mut image_base = probe.find_image_base();
    if image_base == 0 && (probe.is_relocatable() || probe.is_shared_object()) {
        image_base = if bytes[4] == 2 { IMAGE64_BASE_DEFAULT } else { IMAGE32_BASE_DEFAULT };
    }
    let options: Vec<Box<dyn LoaderOption>> =
        vec![new_string(IMAGE_BASE_OPTION_NAME).value(Box::new(format!("{image_base:x}"))).build()];
    let log = Arc::new(MessageLog::new());
    ElfLoader::new()
        .load(provider(), &program, &options, &log, &DummyMonitor)
        .map_err(|e| format!("ELF load failed: {e}"))?;

    // Disassemble from the entry points (the start of Ghidra's auto-analysis).
    let entries: Vec<_> = program
        .get_symbol_table()
        .map(|t| t.get_external_entry_point_iterator().collect())
        .unwrap_or_default();
    let exec: Vec<(u64, u64)> = program
        .get_memory()
        .map(|m| {
            m.get_block_handles()
                .iter()
                .filter_map(|h| h.read().ok())
                .filter(|b| b.is_execute())
                .map(|b| (b.get_start().offset() as u64, b.get_end().offset() as u64))
                .collect()
        })
        .unwrap_or_default();
    let keep = executable_entries(&entries.iter().map(|a| a.offset() as u64).collect::<Vec<_>>(), &exec);
    let mut disassembler = Disassembler::get_program_disassembler(&db, Arc::new(DummyMonitor), None);
    for entry in entries.iter().filter(|a| keep.contains(&(a.offset() as u64))) {
        // errors stay local to their flow; the rest still disassembles
        let _ = disassembler.disassemble_program(&db, entry, None, true);
    }

    let memory = program.get_memory().ok_or_else(|| "program has no memory".to_string())?;
    let handles = memory.get_block_handles();
    let (address_bits, blocks) = crate::listing::snapshot_blocks(&handles);
    let mut block_headers: Vec<BlockHeader> = handles
        .iter()
        .filter_map(|h| h.read().ok())
        .filter(|b| b.get_start().space().is_loaded_memory_space())
        .map(|b| BlockHeader {
            start: b.get_start().offset() as u64,
            // Java names a mapped block's source; the type stands in for it here.
            name: match b.get_type() {
                MemoryBlockType::Default => b.get_name().to_owned(),
                t => format!("{} ({t})", b.get_name()),
            },
            comment: b.get_comment().unwrap_or("").to_owned(),
            space: b.get_start().space().name().to_owned(),
        })
        .collect();
    block_headers.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.name.cmp(&b.name)));
    let block_starts: Vec<(u64, String)> = handles
        .iter()
        .filter_map(|h| h.read().ok())
        .filter(|b| b.get_start().space().is_loaded_memory_space())
        .map(|b| (b.get_start().offset() as u64, b.get_name().to_owned()))
        .collect::<Vec<_>>();
    let (block_starts, block_names) = {
        let mut named = block_starts;
        named.sort();
        named.into_iter().unzip()
    };
    // Collect first: the display-name helper takes the symbol table itself.
    let mut defined = Vec::new();
    if let Some(table) = program.get_symbol_table() {
        let mut it = table.get_all_symbols(false);
        while let Some(sym) = it.next_symbol() {
            if sym.get_address().space().is_loaded_memory_space() {
                defined.push(sym);
            }
        }
    }
    use ghidra_rs::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
    let mut symbols: Vec<ImportedSymbol> = defined
        .iter()
        .map(|sym| ImportedSymbol {
            name: sym.get_name().to_owned(),
            address: sym.get_address().offset() as u64,
            kind: DefaultSymbolUtilities
                .get_symbol_type_display_name(program.as_ref(), sym.as_ref())
                .unwrap_or_else(|| sym.get_symbol_type().name().to_owned()),
            source: source_display(sym.get_source()),
            primary: sym.is_primary(),
            id: sym.get_id(),
        })
        .collect();
    symbols.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)));
    Ok(ImportedProgram {
        name,
        language: language.to_owned(),
        address_bits,
        blocks,
        block_names,
        block_starts,
        symbols,
        block_headers,
        instructions: snapshot_instructions(&db),
        live: Some(LiveProgram::new(db.clone())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/tmp/program_import");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn sources_read_as_java_displays_them() {
        use ghidra_rs::program::model::symbol::SourceType;
        assert_eq!(source_display(SourceType::UserDefined), "User Defined");
        assert_eq!(source_display(SourceType::Imported), "Imported");
    }

    #[test]
    fn a_non_elf_file_is_refused() {
        let p = scratch("not-elf.bin", b"hello, world");
        let err = import_elf(&p, Path::new("/nonexistent")).unwrap_err();
        assert!(err.contains("not an ELF file"), "{err}");
        assert!(import_elf(Path::new("/nonexistent/x"), Path::new("/")).unwrap_err().contains("cannot read"));
    }

    #[test]
    fn an_unsupported_machine_is_refused_by_name() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 1; // ELFCLASS32
        h[5] = 1; // little-endian
        h[18] = 40; // EM_ARM
        let err = import_elf(&scratch("arm.elf", &h), Path::new("/nonexistent")).unwrap_err();
        assert!(err.contains("unsupported ELF machine 40"), "{err}");
    }

    #[test]
    fn a_missing_language_names_the_sla_it_needs() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[18] = 62; // EM_X86_64
        let err = import_elf(&scratch("x64.elf", &h), Path::new("/nonexistent-dist")).unwrap_err();
        assert!(err.contains("x86-64.sla") && err.contains("GHIDRA_RS_GHIDRA_DIST"), "{err}");
    }

    fn header(class: u8, data: u8, machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = class;
        h[5] = data;
        let m = if data == 2 { machine.to_be_bytes() } else { machine.to_le_bytes() };
        h[18..20].copy_from_slice(&m);
        h
    }

    #[test]
    fn big_endian_aarch64_needs_the_big_endian_language() {
        let err = import_elf(&scratch("a64be.elf", &header(2, 2, 183)), Path::new("/nonexistent-dist")).unwrap_err();
        assert!(err.contains("AARCH64BE.sla"), "{err}");
    }

    #[test]
    fn x32_and_big_endian_x86_64_are_refused() {
        let err = import_elf(&scratch("x32.elf", &header(1, 1, 62)), Path::new("/nonexistent-dist")).unwrap_err();
        assert!(err.contains("unsupported") && err.contains("x32"), "{err}");
        let err = import_elf(&scratch("x64be.elf", &header(2, 2, 62)), Path::new("/nonexistent-dist")).unwrap_err();
        assert!(err.contains("unsupported"), "{err}");
    }

    #[test]
    fn bin_ls_imports_with_its_blocks() {
        let Some(dist) = default_ghidra_dist() else { return };
        let Ok(bytes) = std::fs::read("/bin/ls") else { return };
        if bytes.len() < 64 || bytes[..4] != *b"\x7fELF" || bytes[18] != 62 {
            return;
        }
        let p = import_elf(Path::new("/bin/ls"), &dist).unwrap();
        assert_eq!((p.name.as_str(), p.language.as_str(), p.address_bits), ("ls", "x86:LE:64:default", 64));
        assert!(p.block_names.iter().any(|n| n == ".text"), "{:?}", p.block_names);
        assert_eq!(p.blocks.len(), p.block_names.len());
        assert_eq!(p.block_starts.len(), p.block_names.len());
        assert!(p.block_starts.windows(2).all(|w| w[0] <= w[1]));
        let text = p.block_names.iter().position(|n| n == ".text").unwrap();
        assert!(p.blocks.iter().any(|b| b.start == p.block_starts[text]));
        assert_eq!(p.block_headers.len(), p.block_names.len());
        let text_header = p.block_headers.iter().find(|h| h.name == ".text").expect(".text header");
        assert_eq!(text_header.space, "ram");
        assert!(!p.symbols.is_empty(), "ELF symbols are imported");
        assert!(p.symbols.iter().any(|s| s.source == "Imported"));
        // Java display names (SymbolUtilities.getSymbolTypeDisplayName / SourceType.getDisplayString)
        let known = ["Label", "Function", "Data Label", "Instruction Label", "External Data", "External Function", "Thunk Function"];
        assert!(p.symbols.iter().all(|s| known.contains(&s.kind.as_str())), "{:?}", p.symbols.iter().map(|s| &s.kind).collect::<std::collections::BTreeSet<_>>());
        assert!(p.symbols.windows(2).all(|w| w[0].address <= w[1].address));
        assert!(p.symbols.iter().all(|s| p.blocks.iter().any(|b| b.start <= s.address && s.address < b.start + b.len())));
        assert!(p.blocks.iter().all(|b| b.start >= 0x10_0000), "image base 0x100000");
    }

    #[test]
    fn only_entry_points_in_executable_blocks_are_disassembled() {
        let exec = [(0x1000, 0x1fff)];
        assert_eq!(executable_entries(&[0x1000, 0x5000, 0x1ff0], &exec), vec![0x1000, 0x1ff0]);
        // EntryPointAnalyzer: no executable block at all means no filtering
        assert_eq!(executable_entries(&[0x5000], &[]), vec![0x5000]);
    }

    #[test]
    fn bin_ls_is_disassembled_from_its_entry_point() {
        let Some(dist) = default_ghidra_dist() else { return };
        let Ok(bytes) = std::fs::read("/bin/ls") else { return };
        if bytes.len() < 64 || bytes[..4] != *b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 || bytes[18] != 62 {
            return;
        }
        let e_entry = u64::from_le_bytes(bytes[0x18..0x20].try_into().unwrap());
        let entry = if u16::from_le_bytes([bytes[16], bytes[17]]) == 3 { e_entry + 0x10_0000 } else { e_entry };
        let p = import_elf(Path::new("/bin/ls"), &dist).unwrap();
        assert!(p.instructions.len() >= 10, "{} instructions", p.instructions.len());
        assert!(p.instructions.windows(2).all(|w| w[0].start + u64::from(w[0].len) <= w[1].start));
        let live = p.live.as_ref().expect("the live program stays open");
        assert_eq!(snapshot_instructions(live.program()), p.instructions, "re-snapshot of the live program");
        // EntryPointAnalyzer: entry points intersect the executable blocks
        use ghidra_rs::program::model::listing::Program;
        let memory = Program::get_memory(live.program().as_ref()).unwrap();
        let exec: Vec<(u64, u64)> = memory
            .get_block_handles()
            .iter()
            .filter_map(|h| h.read().ok())
            .filter(|b| b.is_execute())
            .map(|b| (b.get_start().offset() as u64, b.get_end().offset() as u64))
            .collect();
        assert!(!exec.is_empty(), "the ELF loader marks code blocks executable");
        let stray: Vec<u64> =
            p.instructions.iter().map(|i| i.start).filter(|&a| !exec.iter().any(|&(lo, hi)| lo <= a && a <= hi)).collect();
        assert!(stray.is_empty(), "instructions outside executable blocks: {:x?}", &stray[..stray.len().min(5)]);
        // CodeManager's default references: _start's CALL [GOT] reads its slot
        let call = p
            .instructions
            .iter()
            .find(|i| i.mnemonic == "CALL" && (i.operands.contains('[') || i.operands.starts_with("0x")))
            .expect("a CALL through memory or to an address");
        assert!(call.references.iter().any(|r| r.op_index == 0), "{call:?}");
        assert!(p.instructions.iter().filter(|i| i.mnemonic == "PUSH" && !i.operands.contains('[')).all(|i| i.references.is_empty()));
        // CodeUnitFormat: referenced addresses read as symbols or dynamic labels
        assert!(
            p.instructions.iter().any(|i| ["LAB_", "SUB_", "DAT_"].iter().any(|d| i.operands.contains(d))),
            "operands show Ghidra's names"
        );
        assert!(p.instructions.iter().filter(|i| i.references.is_empty()).all(|i| !i.operands.contains("DAT_")));
        let first = p.instructions.iter().find(|i| i.start == entry).expect("an instruction at the entry");
        if bytes.windows(4).any(|w| w == [0xf3, 0x0f, 0x1e, 0xfa]) && first.len == 4 {
            assert_eq!(first.mnemonic, "ENDBR64");
        }
    }
}
