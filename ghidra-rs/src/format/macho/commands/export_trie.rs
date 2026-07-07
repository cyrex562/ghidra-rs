//! Mach-O export trie.
//!
//! Mirrors `ghidra.app.util.bin.format.macho.commands.ExportTrie`.
//!
//! See <https://github.com/qyang-nj/llios/blob/main/exported_symbol/README.md>.
//! See <https://github.com/opensource-apple/dyld/blob/master/launch-cache/MachOTrie.hpp>.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::macho::commands::dyld_info_command_constants::{
    EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER,
};

/// A single exported symbol parsed from an [`ExportTrie`].
///
/// Mirrors `ExportTrie.ExportEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    name: String,
    address: u64,
    flags: u64,
    other: u64,
    import_name: Option<String>,
}

impl ExportEntry {
    /// Returns the export name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the export address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the export flags.
    pub fn flags(&self) -> u64 {
        self.flags
    }

    /// Returns the export "other" info.
    pub fn other(&self) -> u64 {
        self.other
    }

    /// Returns the export import name (`None` if not a re-export).
    pub fn import_name(&self) -> Option<&str> {
        self.import_name.as_deref()
    }

    /// Checks to see if the export is a "re-export".
    pub fn is_re_export(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT as u64) != 0
    }
}

impl fmt::Display for ExportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} addr: {:#x}, flags: {:#x}, other: {:#x}, importName: {}",
            self.name,
            self.address,
            self.flags,
            self.other,
            self.import_name.as_deref().unwrap_or("<null>")
        )
    }
}

/// A trie node awaiting expansion: the symbol name substring for its edge, and the offset (from
/// the trie's data base) where the node starts.
///
/// Mirrors `ExportTrie.Node`.
struct Node {
    name: String,
    offset: u64,
}

/// Mach-O export trie.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportTrie {
    exports: Vec<ExportEntry>,
    uleb_offsets: Vec<u64>,
    string_offsets: Vec<u64>,
}

impl ExportTrie {
    /// Creates an empty `ExportTrie`. This is useful for export trie load commands that are
    /// defined but do not point to any data.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates and parses a new `ExportTrie` from `reader`, positioned at the start of the
    /// export trie.
    pub fn from_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let mut trie = Self::new();
        let base = reader.get_pointer_index();
        trie.parse_trie(reader, base)?;
        Ok(trie)
    }

    /// Gets the list of [`ExportEntry`] exports.
    pub fn exports(&self) -> &[ExportEntry] {
        &self.exports
    }

    /// Gets the list of [`ExportEntry`] exports matching `filter`.
    pub fn exports_matching(&self, filter: impl Fn(&ExportEntry) -> bool) -> Vec<ExportEntry> {
        self.exports.iter().filter(|e| filter(e)).cloned().collect()
    }

    /// Returns ULEB128 offsets from the start of the export trie.
    pub fn uleb_offsets(&self) -> &[u64] {
        &self.uleb_offsets
    }

    /// Returns string offsets from the start of the export trie.
    pub fn string_offsets(&self) -> &[u64] {
        &self.string_offsets
    }

    /// Parses the export trie.
    fn parse_trie(&mut self, reader: &mut dyn BinaryReader, base: u64) -> io::Result<()> {
        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(0);
        let mut remaining_nodes = self.parse_node(reader, base, String::new(), 0)?;
        while let Some(parent) = remaining_nodes.pop_front() {
            if !visited.insert(parent.offset) {
                continue; // skip already-visited offsets
            }
            let children = self.parse_node(reader, base, parent.name.clone(), parent.offset)?;
            for child in children {
                remaining_nodes.push_back(Node {
                    name: format!("{}{}", parent.name, child.name),
                    offset: child.offset,
                });
            }
        }
        Ok(())
    }

    /// Parses a node of the export trie, returning its child nodes.
    fn parse_node(
        &mut self,
        reader: &mut dyn BinaryReader,
        base: u64,
        name: String,
        offset: u64,
    ) -> io::Result<VecDeque<Node>> {
        let mut children = VecDeque::new();
        reader.set_pointer_index(base + offset);
        self.uleb_offsets.push(reader.get_pointer_index() - base);
        let terminal_size = LEB128Info::unsigned(reader)?.as_u_int32()?;
        let children_index = reader.get_pointer_index() + terminal_size as u64;
        if terminal_size != 0 {
            self.uleb_offsets.push(reader.get_pointer_index() - base);
            let flags = LEB128Info::unsigned(reader)?.as_long() as u64;
            let mut address = 0u64;
            let mut other = 0u64;
            let mut import_name = None;
            if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT as u64) != 0 {
                self.uleb_offsets.push(reader.get_pointer_index() - base);
                other = LEB128Info::unsigned(reader)?.as_long() as u64; // dylib ordinal
                self.string_offsets.push(reader.get_pointer_index() - base);
                import_name = Some(reader.read_next_ascii_string()?);
            } else {
                self.uleb_offsets.push(reader.get_pointer_index() - base);
                address = LEB128Info::unsigned(reader)?.as_long() as u64;
                if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER as u64) != 0 {
                    self.uleb_offsets.push(reader.get_pointer_index() - base);
                    other = LEB128Info::unsigned(reader)?.as_long() as u64;
                }
            }
            self.exports.push(ExportEntry { name, address, flags, other, import_name });
        }
        reader.set_pointer_index(children_index);
        self.uleb_offsets.push(reader.get_pointer_index() - base);
        let num_children = LEB128Info::unsigned(reader)?.as_u_int32()?;
        for _ in 0..num_children {
            self.string_offsets.push(reader.get_pointer_index() - base);
            let child_name = reader.read_next_ascii_string()?;
            self.uleb_offsets.push(reader.get_pointer_index() - base);
            let child_offset = LEB128Info::unsigned(reader)?.as_u_int32()?;
            children.push_back(Node { name: child_name, offset: child_offset as u64 });
        }
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }

        fn is_little_endian(&self) -> bool {
            self.little_endian
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    fn uleb(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut v = value;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if v == 0 {
                break;
            }
        }
        buf
    }

    #[test]
    fn empty_trie_has_no_exports_or_offsets() {
        let trie = ExportTrie::new();
        assert!(trie.exports().is_empty());
        assert!(trie.uleb_offsets().is_empty());
        assert!(trie.string_offsets().is_empty());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(ExportTrie::new(), ExportTrie::default());
    }

    #[test]
    fn parses_single_root_export() {
        // Root node: terminal size, flags (regular), address, then zero children.
        let mut data = Vec::new();
        let mut terminal = Vec::new();
        terminal.extend(uleb(0)); // flags: regular
        terminal.extend(uleb(0x1000)); // address
        data.push(terminal.len() as u8); // terminal size
        data.extend(terminal);
        data.push(0); // num children

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();

        assert_eq!(trie.exports().len(), 1);
        let export = &trie.exports()[0];
        assert_eq!(export.name(), "");
        assert_eq!(export.address(), 0x1000);
        assert_eq!(export.flags(), 0);
        assert!(!export.is_re_export());
        assert_eq!(export.import_name(), None);
    }

    #[test]
    fn parses_child_export_with_concatenated_name() {
        // Layout:
        // offset 0: root node, no terminal (terminal size 0), 1 child "foo" -> offset X
        // offset X: child node, terminal (address 0x2000), no children
        let mut child = Vec::new();
        let mut child_terminal = Vec::new();
        child_terminal.extend(uleb(0)); // flags: regular
        child_terminal.extend(uleb(0x2000)); // address
        child.push(child_terminal.len() as u8);
        child.extend(child_terminal);
        child.push(0); // num children

        let mut root = Vec::new();
        root.push(0); // terminal size 0 (no export at root)
        root.push(1); // num children
        root.extend(b"foo");
        root.push(0); // null terminator for ascii string
        let child_offset = root.len() as u64 + 1; // +1 for the child's own offset uleb byte
        root.extend(uleb(child_offset));

        let mut data = root;
        let child_start = data.len();
        assert_eq!(child_start as u64, child_offset);
        data.extend(child);

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();

        assert_eq!(trie.exports().len(), 1);
        let export = &trie.exports()[0];
        assert_eq!(export.name(), "foo");
        assert_eq!(export.address(), 0x2000);
    }

    #[test]
    fn re_export_reads_dylib_ordinal_and_import_name() {
        let mut data = Vec::new();
        let mut terminal = Vec::new();
        terminal.extend(uleb(EXPORT_SYMBOL_FLAGS_REEXPORT as u64)); // flags: re-export
        terminal.extend(uleb(3)); // dylib ordinal
        terminal.extend(b"orig_name");
        terminal.push(0); // null terminator
        data.push(terminal.len() as u8);
        data.extend(terminal);
        data.push(0); // num children

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();

        let export = &trie.exports()[0];
        assert!(export.is_re_export());
        assert_eq!(export.other(), 3);
        assert_eq!(export.address(), 0);
        assert_eq!(export.import_name(), Some("orig_name"));
    }

    #[test]
    fn stub_and_resolver_flag_reads_extra_other_value() {
        let mut data = Vec::new();
        let mut terminal = Vec::new();
        terminal.extend(uleb(EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER as u64));
        terminal.extend(uleb(0x3000)); // address
        terminal.extend(uleb(0x4000)); // other (resolver)
        data.push(terminal.len() as u8);
        data.extend(terminal);
        data.push(0); // num children

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();

        let export = &trie.exports()[0];
        assert_eq!(export.address(), 0x3000);
        assert_eq!(export.other(), 0x4000);
    }

    #[test]
    fn cyclic_offsets_do_not_infinite_loop() {
        // Root node has no terminal, one child "a" pointing back to offset 0 (itself).
        let mut data = Vec::new();
        data.push(0); // terminal size 0
        data.push(1); // num children
        data.extend(b"a");
        data.push(0); // null terminator
        data.extend(uleb(0)); // child offset points back to root

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();
        assert!(trie.exports().is_empty());
    }

    #[test]
    fn export_entry_display_formats_fields() {
        let export = ExportEntry {
            name: "sym".to_string(),
            address: 0x10,
            flags: 0x2,
            other: 0x3,
            import_name: None,
        };
        assert_eq!(
            export.to_string(),
            "sym addr: 0x10, flags: 0x2, other: 0x3, importName: <null>"
        );
    }

    #[test]
    fn export_entry_display_shows_import_name() {
        let export = ExportEntry {
            name: "sym".to_string(),
            address: 0,
            flags: EXPORT_SYMBOL_FLAGS_REEXPORT as u64,
            other: 1,
            import_name: Some("real_sym".to_string()),
        };
        assert_eq!(
            export.to_string(),
            "sym addr: 0x0, flags: 0x8, other: 0x1, importName: real_sym"
        );
    }

    #[test]
    fn exports_matching_filters_by_predicate() {
        let mut data = Vec::new();
        let mut terminal = Vec::new();
        terminal.extend(uleb(0));
        terminal.extend(uleb(0x42));
        data.push(terminal.len() as u8);
        data.extend(terminal);
        data.push(0);

        let mut reader = TestReader::new(data);
        let trie = ExportTrie::from_reader(&mut reader).unwrap();

        let matches = trie.exports_matching(|e| e.address() == 0x42);
        assert_eq!(matches.len(), 1);
        let no_matches = trie.exports_matching(|e| e.address() == 0x99);
        assert!(no_matches.is_empty());
    }
}
