//! Opening a real ELF for the shell (`ghidra-qt --open`): ELF → language from
//! a compiled `.sla` of a local Ghidra distribution (user ruling 2026-10-02:
//! the dist `.sla` files may back tests and the dev app until the Rust sleigh
//! compiler produces them) → `ProgramDB` via the ported `ElfLoader` → a
//! memory snapshot for the listing.

use std::path::{Path, PathBuf};

use crate::listing::MemoryBlockSnapshot;

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
    use ghidra_rs::pcode::utils::sla_format::build_decoder;
    use ghidra_rs::program::database::program_db::ProgramDB;
    use ghidra_rs::program::model::address::DefaultAddressFactory;
    use ghidra_rs::program::model::lang::sleigh::SleighLanguage;
    use ghidra_rs::program::model::listing::Program;
    use ghidra_rs::util::task::DummyMonitor;
    use std::rc::Rc;
    use std::sync::Arc;

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
    let decoder = build_decoder(&sla, Arc::new(DefaultAddressFactory::new(vec![]))).map_err(|e| format!("{}: {e:?}", sla.display()))?;
    let lang = SleighLanguage::decode(&decoder, language.to_string()).map_err(|e| format!("{language}: {e:?}"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let program: Arc<dyn Program> = Arc::new(ProgramDB::new(name.clone(), Arc::new(lang)).map_err(|e| e.to_string())?);

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

    let memory = program.get_memory().ok_or_else(|| "program has no memory".to_string())?;
    let handles = memory.get_block_handles();
    let (address_bits, blocks) = crate::listing::snapshot_blocks(&handles);
    let mut named: Vec<(u64, String)> = handles
        .iter()
        .filter_map(|h| h.read().ok())
        .filter(|b| b.get_start().space().is_loaded_memory_space())
        .map(|b| (b.get_start().offset() as u64, b.get_name().to_owned()))
        .collect();
    named.sort();
    let (block_starts, block_names) = named.into_iter().unzip();
    let mut symbols = Vec::new();
    if let Some(table) = program.get_symbol_table() {
        let mut it = table.get_all_symbols(false);
        while let Some(sym) = it.next_symbol() {
            let address = sym.get_address();
            if !address.space().is_loaded_memory_space() {
                continue;
            }
            symbols.push(ImportedSymbol {
                name: sym.get_name().to_owned(),
                address: address.offset() as u64,
                kind: format!("{:?}", sym.get_symbol_type()),
                source: format!("{:?}", sym.get_source()),
            });
        }
    }
    symbols.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)));
    Ok(ImportedProgram { name, language: language.to_owned(), address_bits, blocks, block_names, block_starts, symbols })
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
        assert!(!p.symbols.is_empty(), "ELF symbols are imported");
        assert!(p.symbols.iter().any(|s| s.source == "Imported"));
        assert!(p.symbols.windows(2).all(|w| w[0].address <= w[1].address));
        assert!(p.symbols.iter().all(|s| p.blocks.iter().any(|b| b.start <= s.address && s.address < b.start + b.len())));
        assert!(p.blocks.iter().all(|b| b.start >= 0x10_0000), "image base 0x100000");
    }
}
