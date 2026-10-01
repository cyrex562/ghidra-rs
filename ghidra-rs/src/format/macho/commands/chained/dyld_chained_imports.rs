//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports`.
//!
//! Represents a `dyld_chained_import` array. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::macho::commands::chained::dyld_chained_import::DyldChainedImport;
use crate::format::macho::commands::dyld::binding_table::Binding;

/// A `dyld_chained_import` array.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DyldChainedImports {
    imports_count: i64,
    imports_format: i32,
    imports_offset: i64,
    chained_imports: Vec<DyldChainedImport>,
}

impl DyldChainedImports {
    /// Java's package-private `DyldChainedImports(BinaryReader, DyldChainedFixupHeader)`; the
    /// header supplies `importsCount`/`importsFormat`, passed here directly.
    pub fn new(reader: &mut BinaryReader, imports_count: i64, imports_format: i32) -> io::Result<Self> {
        let imports_offset = reader.get_pointer_index() as i64;
        let mut chained_imports = Vec::new();
        // Java: `for (int i = 0; i < importsCount; i++)`.
        let mut i: i32 = 0;
        while (i as i64) < imports_count {
            chained_imports.push(DyldChainedImport::new(reader, imports_format)?);
            i = i.wrapping_add(1);
        }
        Ok(DyldChainedImports { imports_count, imports_format, imports_offset, chained_imports })
    }

    /// Java `DyldChainedImports(List<Binding>)`: imports synthesized from classic bindings.
    pub fn from_bindings(bindings: &[Binding]) -> Self {
        DyldChainedImports {
            imports_count: bindings.len() as i64,
            imports_format: 0,
            imports_offset: 0,
            chained_imports: bindings.iter().map(DyldChainedImport::from_binding).collect(),
        }
    }

    /// Java `getImportsCount()`.
    pub fn get_imports_count(&self) -> i64 {
        self.imports_count
    }

    /// Java `getImportsOffset()`.
    pub fn get_imports_offset(&self) -> i64 {
        self.imports_offset
    }

    /// Java `getChainedImports()`.
    pub fn get_chained_imports(&self) -> &[DyldChainedImport] {
        &self.chained_imports
    }

    /// Java `getChainedImport(int)`: `None` (Java `null`) for an out-of-range ordinal.
    pub fn get_chained_import(&self, ordinal: i32) -> Option<&DyldChainedImport> {
        if ordinal < 0 || ordinal as i64 >= self.imports_count {
            return None;
        }
        self.chained_imports.get(ordinal as usize)
    }

    /// Java `initSymbols(BinaryReader, DyldChainedFixupHeader)`: reads every import's name from
    /// the symbol pool starting at `reader`'s current position.
    pub fn init_symbols(&mut self, reader: &mut BinaryReader) -> io::Result<()> {
        let ptr_index = reader.get_pointer_index() as i64;
        for imp in &mut self.chained_imports {
            reader.set_pointer_index(ptr_index.wrapping_add(imp.get_name_offset()) as u64);
            imp.init_string(reader)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_imports_and_symbol_pool() {
        // Two DYLD_CHAINED_IMPORT entries: ordinal 1 name@1, ordinal 2 name@6.
        let mut v = Vec::new();
        v.extend_from_slice(&(1u32 | (1 << 9)).to_le_bytes());
        v.extend_from_slice(&(2u32 | (6 << 9)).to_le_bytes());
        let pool_at = v.len() as u64;
        v.extend_from_slice(b"\0_foo\0_bar\0");
        let mut r = BinaryReader::from_bytes(v, true);
        let mut imports = DyldChainedImports::new(&mut r, 2, 1).unwrap();
        assert_eq!(imports.get_imports_count(), 2);
        assert_eq!(imports.get_imports_offset(), 0);
        r.set_pointer_index(pool_at);
        imports.init_symbols(&mut r).unwrap();
        let names: Vec<_> = imports.get_chained_imports().iter().map(|i| i.get_name().unwrap()).collect();
        assert_eq!(names, ["_foo", "_bar"]);
        assert_eq!(imports.get_chained_import(1).unwrap().get_lib_ordinal(), 2);
        assert!(imports.get_chained_import(2).is_none());
        assert!(imports.get_chained_import(-1).is_none());
    }

    #[test]
    fn from_bindings() {
        let b = [
            Binding::with_symbol(Some("_a".to_string()), 1, false),
            Binding::with_symbol(Some("_b".to_string()), 2, true),
        ];
        let imports = DyldChainedImports::from_bindings(&b);
        assert_eq!(imports.get_imports_count(), 2);
        assert_eq!(imports.get_chained_import(1).unwrap().get_name(), Some("_b"));
        assert!(imports.get_chained_import(1).unwrap().is_weak_import());
    }
}
