//! Port of `ghidra.app.util.bin.format.golang.rtti.GoRttiMapper`.
//!
//! This module currently holds the class's static helpers (Go section / symbol lookup, version
//! support); the mapper instance itself is still the
//! [`GoRttiMapper`](crate::format::seam_stubs::GoRttiMapper) seam.

use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::format::golang::go_build_info::{MACHO_SECTION_NAME, SECTION_NAME};
use crate::format::golang::go_constants::GOLANG_CSPEC_NAME;
use crate::format::golang::go_ver::GoVer;
use crate::format::golang::go_ver_range::GoVerRange;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::program::model::symbol::{Symbol, SymbolType};
use crate::util::msg::Msg;

/// `SUPPORTED_VERSIONS`: the Go versions this analyzer was tested against.
pub static SUPPORTED_VERSIONS: Lazy<GoVerRange> = Lazy::new(|| GoVerRange::parse("1.15-1.26"));

/// `ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME`.
pub const ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME: &str = "ARTIFICIAL.runtime.zerobase";

/// `SYMBOL_SEARCH_PREFIXES`: `""`, and `"_"` for macho symbols.
const SYMBOL_SEARCH_PREFIXES: [&str; 2] = ["", "_"];

/// `SECTION_PREFIXES`: `"."` (ELF) and `"__"` (macho sections).
const SECTION_PREFIXES: [&str; 2] = [".", "__"];

/// `isGolangProgram(Program)`: the program uses the `golang` compiler spec.
pub fn is_golang_program(program: &dyn Program) -> bool {
    program
        .get_compiler_spec()
        .is_some_and(|cs| cs.get_compiler_spec_description().get_compiler_spec_name() == GOLANG_CSPEC_NAME)
}

/// `hasGolangSections(List<String>)`: any of the section names is a Go pclntab or buildinfo
/// section.
pub fn has_golang_sections(section_names: &[String]) -> bool {
    section_names.iter().any(|name| {
        name.contains("gopclntab") || name.contains(MACHO_SECTION_NAME) || name.contains(SECTION_NAME)
    })
}

/// `getGoSymbol(Program, String)`: the single global symbol with the name (also trying the
/// macho `_` prefix), or `None`.
pub fn get_go_symbol(program: &dyn Program, symbol_name: &str) -> Option<Arc<dyn Symbol>> {
    let global_ns = program.get_global_namespace()?;
    let symbol_table = program.get_symbol_table()?;
    for prefix in SYMBOL_SEARCH_PREFIXES {
        let symbols = symbol_table
            .get_symbols_by_name_namespace(&format!("{prefix}{symbol_name}"), global_ns.as_ref())
            .unwrap_or_default();
        if symbols.len() == 1 {
            return symbols.into_iter().next();
        }
    }
    None
}

/// `getGoSection(Program, String)`: the memory block of a Go section, trying the ELF (`.`) and
/// macho (`__`) prefixes.
pub fn get_go_section(program: &dyn Program, section_name: &str) -> Option<Arc<dyn MemoryBlock>> {
    let memory = program.get_memory()?;
    SECTION_PREFIXES
        .iter()
        .find_map(|prefix| memory.get_block_by_name(&format!("{prefix}{section_name}")))
}

/// `getFirstGoSection(Program, String...)`: the first of the named Go sections that exists.
pub fn get_first_go_section(program: &dyn Program, section_names: &[&str]) -> Option<Arc<dyn MemoryBlock>> {
    section_names.iter().find_map(|name| get_go_section(program, name))
}

/// Returns the address of the Go `runtime.zerobase` symbol, or an artificial substitute
/// (`getZerobaseAddress(Program)`).
///
/// The zerobase symbol is used as the location of parameters that are zero-length.
pub fn get_zerobase_address(prog: &dyn Program) -> Option<Address> {
    let zerobase_addr = match get_go_symbol(prog, "runtime.zerobase") {
        Some(sym) => Some(sym.get_address()),
        None => get_artificial_zerobase_address(prog),
    };
    if zerobase_addr.is_some() {
        return zerobase_addr;
    }
    // ICKY HACK
    let fallback = prog.get_image_base().map(|base| base.space().min_address());
    if let Some(addr) = &fallback {
        Msg::warn("GoRttiMapper", &format!("Unable to find Go runtime.zerobase, using {addr}"));
    }
    fallback
}

fn get_artificial_zerobase_address(program: &dyn Program) -> Option<Address> {
    get_go_symbol(program, ARTIFICIAL_RUNTIME_ZEROBASE_SYMBOLNAME).map(|s| s.get_address())
}

/// `getAllSupportedVersions()`: every minor version in [`SUPPORTED_VERSIONS`].
pub fn get_all_supported_versions() -> Vec<GoVer> {
    SUPPORTED_VERSIONS.as_list().unwrap_or_default()
}

/// `isAbi0Func(Address, Program)`: the function at `func_entry` has a label ending in `abi0`.
pub fn is_abi0_func(func_entry: &Address, program: &dyn Program) -> bool {
    let Some(symbol_table) = program.get_symbol_table() else {
        return false;
    };
    symbol_table
        .get_symbols(func_entry)
        .unwrap_or_default()
        .iter()
        .any(|symbol| symbol.get_symbol_type() == SymbolType::Label && symbol.get_name().ends_with("abi0"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golang_section_names() {
        assert!(has_golang_sections(&[".gopclntab".to_string()]));
        assert!(has_golang_sections(&["__go_buildinfo".to_string()]));
        assert!(has_golang_sections(&[".go.buildinfo".to_string()]));
        assert!(!has_golang_sections(&[".text".to_string(), ".data".to_string()]));
    }

    #[test]
    fn supported_versions() {
        let vers = get_all_supported_versions();
        assert_eq!(vers.first(), Some(&GoVer::new(1, 15, 0)));
        assert_eq!(vers.last(), Some(&GoVer::new(1, 26, 0)));
        assert_eq!(vers.len(), 12);
        assert!(SUPPORTED_VERSIONS.contains(GoVer::new(1, 21, 4)));
        assert!(!SUPPORTED_VERSIONS.contains(GoVer::new(1, 14, 0)));
    }
}
