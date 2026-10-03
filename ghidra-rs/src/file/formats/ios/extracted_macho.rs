//! Port of `ghidra.file.formats.ios.ExtractedMacho`.
//!
//! An extracted Mach-O that was once living inside of a Mach-O container file (a DYLD cache or a
//! Mach-O file set). The Mach-O layout is manipulated so all of its segments are adjacent in the
//! resulting binary, and a container-specific footer is appended so Ghidra can recognize the
//! extracted component when it is imported.
//!
//! # Shape
//!
//! Java's `ExtractedMacho` is a concrete class with one (private) subclass,
//! `DyldCacheExtractor.DyldPackedSegments`, which overrides two hooks: `getSegmentProvider`
//! (which byte provider holds a segment) and `getExtraSymbols` (symbols to append to the symbol
//! table). Per the shape rules this is a struct the subclass embeds; the two hooks become an
//! optional segment-provider closure ([`with_segment_provider`](ExtractedMacho::with_segment_provider))
//! and an extra-symbol list ([`with_extra_symbols`](ExtractedMacho::with_extra_symbols)).
//!
//! Java keys its bookkeeping maps by `SegmentCommand`/`LoadCommand` object identity; here they
//! are keyed by the command's position in the (owned) [`MachHeader`]'s load-command list, which
//! is stable for the header's lifetime.

use std::collections::HashMap;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::format::macho::commands::dynamic_symbol_table_command::DynamicSymbolTableCommand;
use crate::format::macho::commands::link_edit_data_command::LinkEditDataCommand;
use crate::format::macho::commands::load_command::LoadCommand;
use crate::format::macho::commands::load_command_kind::{LoadCommandKind, LoadCommandVariant};
use crate::format::macho::commands::load_command_types::get_load_command_name;
use crate::format::macho::commands::n_list::NList;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::commands::segment_names;
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::mach_header::MachHeader;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Why [`ExtractedMacho::pack`] failed (Java: `IOException`, `CancelledException`).
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

impl From<ExtractError> for io::Error {
    fn from(e: ExtractError) -> io::Error {
        match e {
            ExtractError::Io(e) => e,
            ExtractError::Cancelled(c) => io::Error::new(io::ErrorKind::Interrupted, c),
        }
    }
}

/// Java's `getSegmentProvider` override hook.
pub type SegmentProviderFn<'a> = Box<dyn Fn(&SegmentCommand) -> io::Result<Rc<dyn ByteProvider>> + 'a>;

/// Java's `NotFoundException` from `getPackedOffset`.
struct NotFound(String);

/// Port of `ghidra.file.formats.ios.ExtractedMacho`.
pub struct ExtractedMacho<'a> {
    provider: Rc<dyn ByteProvider>,
    provider_offset: i64,
    footer: Vec<u8>,
    reader: BinaryReader,
    macho_header: MachHeader,
    /// Load-command index of each segment, in `getAllSegments()` order.
    segment_cmds: Vec<usize>,
    /// Segment ordinal (into `segment_cmds`) of `__TEXT`, if present.
    text_segment: Option<usize>,
    /// Segment ordinal of `__LINKEDIT`, if present.
    link_edit_segment: Option<usize>,
    packed_segment_starts: HashMap<usize, i32>,
    packed_segment_adjustments: HashMap<usize, i32>,
    /// Keyed by load-command index.
    packed_link_edit_data_starts: HashMap<usize, i32>,
    packed: Vec<u8>,
    monitor: &'a dyn TaskMonitor,
    segment_provider: Option<SegmentProviderFn<'a>>,
    extra_symbols: Vec<NList>,
}

impl<'a> ExtractedMacho<'a> {
    /// Java `ExtractedMacho(ByteProvider, long, MachHeader, byte[], TaskMonitor)`.
    ///
    /// `provider` holds the Mach-O header at `provider_offset`; `macho_header` is the parsed
    /// header (owned: packing edits its segments and symbol table in place, as Java does);
    /// `footer` is appended to the packed result.
    pub fn new(
        provider: Rc<dyn ByteProvider>,
        provider_offset: i64,
        macho_header: MachHeader,
        footer: &[u8],
        monitor: &'a dyn TaskMonitor,
    ) -> Self {
        let segment_cmds: Vec<usize> = macho_header
            .get_load_commands()
            .iter()
            .enumerate()
            .filter(|(_, c)| SegmentCommand::from_kind(c).is_some())
            .map(|(i, _)| i)
            .collect();
        let find = |name: &str| {
            segment_cmds.iter().position(|&ci| {
                SegmentCommand::from_kind(&macho_header.get_load_commands()[ci])
                    .is_some_and(|s| s.get_segment_name() == name)
            })
        };
        let text_segment = find(segment_names::TEXT);
        let link_edit_segment = find(segment_names::LINKEDIT);
        let reader = BinaryReader::new(Rc::clone(&provider), macho_header.is_little_endian());
        ExtractedMacho {
            provider,
            provider_offset,
            footer: footer.to_vec(),
            reader,
            macho_header,
            segment_cmds,
            text_segment,
            link_edit_segment,
            packed_segment_starts: HashMap::new(),
            packed_segment_adjustments: HashMap::new(),
            packed_link_edit_data_starts: HashMap::new(),
            packed: Vec::new(),
            monitor,
            segment_provider: None,
            extra_symbols: Vec::new(),
        }
    }

    /// Overrides Java's `getSegmentProvider(SegmentCommand)` (which defaults to the provider the
    /// Mach-O header lives in).
    pub fn with_segment_provider(mut self, f: SegmentProviderFn<'a>) -> Self {
        self.segment_provider = Some(f);
        self
    }

    /// Overrides Java's `getExtraSymbols()` (which defaults to none).
    pub fn with_extra_symbols(mut self, symbols: Vec<NList>) -> Self {
        self.extra_symbols = symbols;
        self
    }

    /// The (possibly packing-modified) Mach-O header.
    pub fn get_mach_header(&self) -> &MachHeader {
        &self.macho_header
    }

    /// The `__TEXT` segment, if the Mach-O has one (Java's `textSegment` field).
    pub fn get_text_segment(&self) -> Option<&SegmentCommand> {
        self.text_segment.map(|i| self.seg(i))
    }

    fn seg(&self, i: usize) -> &SegmentCommand {
        SegmentCommand::from_kind(&self.macho_header.get_load_commands()[self.segment_cmds[i]])
            .expect("segment_cmds indexes segment commands")
    }

    fn seg_mut(&mut self, i: usize) -> &mut SegmentCommand {
        let ci = self.segment_cmds[i];
        SegmentCommand::from_kind_mut(&mut self.macho_header.get_load_commands_mut()[ci])
            .expect("segment_cmds indexes segment commands")
    }

    /// Java `pack()`: lays every segment out back to back (with a freshly packed `__LINKEDIT`
    /// holding only this Mach-O's linker data), fixes up the load commands' file offsets to
    /// match, and appends the footer.
    pub fn pack(&mut self) -> Result<(), ExtractError> {
        // Keep track of each segment's file offset in the container, and a running total of
        // each segment's size so we know how big to make the packed array.
        let mut packed_size: i32 = 0;
        let mut packed_link_edit_size: i32 = 0;
        for i in 0..self.segment_cmds.len() {
            self.monitor.check_cancelled()?;
            self.packed_segment_starts.insert(i, packed_size);

            // The __LINKEDIT segment is shared across all Mach-O's, so it is very large. Create
            // a new packed __LINKEDIT with only the relevant info for this Mach-O.
            if Some(i) == self.link_edit_segment {
                let extra = self.extra_symbols.clone();
                for (ci, cmd) in self.macho_header.get_load_commands_mut().iter_mut().enumerate() {
                    if let Some(symbol_table) = SymbolTableCommand::from_kind_mut(cmd) {
                        symbol_table.add_symbols(extra.clone());
                    }
                    let offset = cmd.get_linker_data_offset();
                    let size = cmd.get_linker_data_size();
                    if offset == 0 || size == 0 {
                        continue;
                    }
                    self.packed_link_edit_data_starts.insert(ci, packed_link_edit_size);
                    packed_link_edit_size = packed_link_edit_size.wrapping_add(size as i32);
                }
                packed_size = packed_size.wrapping_add(packed_link_edit_size);
                let seg = self.seg_mut(i);
                seg.set_file_size(packed_link_edit_size as i64);
                seg.set_vm_size(packed_link_edit_size as i64);
            } else {
                packed_size = packed_size.wrapping_add(self.seg(i).get_file_size() as i32);
            }

            // Some older containers use a file offset of 0 for their __TEXT segment, despite
            // being in the middle of the container. Make it consistent with the other segments'
            // absolute container offsets, remembering the adjustment.
            if Some(i) == self.text_segment && self.seg(i).get_file_offset() == 0 {
                let provider_offset = self.provider_offset;
                self.seg_mut(i).set_file_offset(provider_offset);
                self.packed_segment_adjustments.insert(i, provider_offset as i32);
            }
        }

        // Account for the size of the footer.
        packed_size = packed_size.wrapping_add(self.footer.len() as i32);
        if packed_size < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packed Mach-O too large").into());
        }
        self.packed = vec![0u8; packed_size as usize];

        // Copy each segment into the packed array (leaving no gaps).
        for i in 0..self.segment_cmds.len() {
            self.monitor.check_cancelled()?;
            let (file_offset, mut segment_size, name) = {
                let s = self.seg(i);
                (s.get_file_offset(), s.get_file_size(), s.get_segment_name().to_string())
            };
            let segment_provider = self.get_segment_provider(self.seg(i))?;
            if file_offset + segment_size > segment_provider.length() as i64 {
                segment_size = segment_provider.length() as i64 - file_offset;
                Msg::warn(
                    "ExtractedMacho",
                    &format!("{name} segment extends beyond end of file.  Truncating..."),
                );
            }
            let bytes = if Some(i) == self.link_edit_segment {
                let bytes =
                    self.create_packed_link_edit_segment(segment_provider.as_ref(), packed_link_edit_size)?;
                self.adjust_link_edit_address();
                bytes
            } else {
                if segment_size < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{name} segment starts beyond end of file"),
                    )
                    .into());
                }
                segment_provider.read_bytes(file_offset as u64, segment_size as u64)?
            };
            let start = self.packed_segment_starts[&i] as usize;
            copy_into(&mut self.packed, start, &bytes)?;
        }

        // Fixup various fields in the packed array.
        self.fixup_load_commands()?;

        // Add footer.
        let footer_start = self.packed.len() - self.footer.len();
        self.packed[footer_start..].copy_from_slice(&self.footer);
        Ok(())
    }

    /// Java `getByteProvider(FSRL)`: the packed Mach-O, carrying `fsrl`.
    pub fn get_byte_provider(&self, fsrl: Option<Fsrl>) -> ByteArrayProvider {
        ByteArrayProvider::with_fsrl(self.packed.clone(), fsrl)
    }

    /// The packed bytes (empty before [`pack`](Self::pack)).
    pub fn get_packed(&self) -> &[u8] {
        &self.packed
    }

    /// Java `getSegmentProvider(SegmentCommand)`.
    fn get_segment_provider(&self, segment: &SegmentCommand) -> io::Result<Rc<dyn ByteProvider>> {
        match &self.segment_provider {
            Some(f) => f(segment),
            None => Ok(Rc::clone(&self.provider)),
        }
    }

    /// Java `getPackedOffset(long, SegmentCommand)`: converts a Mach-O file offset within
    /// `segment` (an ordinal; `None` for Java's `null`) to an offset into the packed Mach-O.
    fn get_packed_offset(&self, file_offset: i64, segment: Option<usize>) -> Result<i64, NotFound> {
        if let Some(i) = segment {
            if let Some(&segment_start) = self.packed_segment_starts.get(&i) {
                return Ok(file_offset - self.seg(i).get_file_offset() + segment_start as i64);
            }
        }
        Err(NotFound(format!(
            "Failed to convert Mach-O file offset to packed offset: 0x{file_offset:x}"
        )))
    }

    /// Java `createPackedLinkEditSegment(ByteProvider, int)`.
    fn create_packed_link_edit_segment(
        &self,
        link_edit_segment_provider: &dyn ByteProvider,
        packed_link_edit_size: i32,
    ) -> io::Result<Vec<u8>> {
        let mut packed_link_edit = vec![0u8; packed_link_edit_size.max(0) as usize];
        let commands = self.macho_header.get_load_commands();
        for (&ci, &start) in &self.packed_link_edit_data_starts {
            let cmd = &commands[ci];
            match SymbolTableCommand::from_kind(cmd) {
                Some(symbol_table) if symbol_table.get_number_of_symbols() > 0 => {
                    let symbols = symbol_table.get_symbols();
                    let mut table = vec![0u8; NList::get_total_size(symbols).max(0) as usize];
                    let mut nlist_index = 0usize;
                    let string_index_orig = symbols[0].get_size() * symbols.len() as i32;
                    let mut string_index = string_index_orig + 1; // First byte is always 0
                    for nlist in symbols {
                        let nlist_array = self.nlist_to_array(nlist, string_index - string_index_orig);
                        let string_array: Vec<u8> =
                            nlist.get_string().chars().map(|c| if c.is_ascii() { c as u8 } else { b'?' }).collect();
                        copy_into(&mut table, nlist_index, &nlist_array)?;
                        copy_into(&mut table, string_index as usize, &string_array)?;
                        nlist_index += nlist_array.len();
                        string_index += string_array.len() as i32 + 1; // null terminate
                    }
                    copy_into(&mut packed_link_edit, start as usize, &table)?;
                }
                _ => {
                    let bytes = link_edit_segment_provider.read_bytes(
                        cmd.get_linker_data_offset() as u64,
                        cmd.get_linker_data_size() as u64,
                    )?;
                    copy_into(&mut packed_link_edit, start as usize, &bytes)?;
                }
            }
        }
        Ok(packed_link_edit)
    }

    /// Java `nlistToArray(NList, int)`: `nlist` in the header's byte order, with its string
    /// index replaced by `string_index`.
    fn nlist_to_array(&self, nlist: &NList, string_index: i32) -> Vec<u8> {
        let big = !self.macho_header.is_little_endian();
        let mut ret = Vec::with_capacity(nlist.get_size() as usize);
        ret.extend(if big { string_index.to_be_bytes() } else { string_index.to_le_bytes() });
        ret.push(nlist.get_type() as u8);
        ret.push(nlist.get_section() as u8);
        let desc = nlist.get_description();
        ret.extend(if big { desc.to_be_bytes() } else { desc.to_le_bytes() });
        if nlist.is32bit() {
            let v = nlist.get_value() as i32;
            ret.extend(if big { v.to_be_bytes() } else { v.to_le_bytes() });
        } else {
            let v = nlist.get_value();
            ret.extend(if big { v.to_be_bytes() } else { v.to_le_bytes() });
        }
        ret
    }

    /// Java `fixupLoadCommands()`.
    fn fixup_load_commands(&mut self) -> io::Result<()> {
        for ci in 0..self.macho_header.get_load_commands().len() {
            if self.monitor.is_cancelled() {
                break;
            }
            let kind = &self.macho_header.get_load_commands()[ci];
            match kind {
                LoadCommandKind::Segment(_) => {
                    let i = self.segment_cmds.iter().position(|&c| c == ci).expect("segment ordinal");
                    self.fixup_segment(i)?;
                }
                LoadCommandKind::SymbolTable(_) => self.fixup_symbol_table(ci)?,
                LoadCommandKind::DynamicSymbolTable(_) => self.fixup_dynamic_symbol_table(ci)?,
                LoadCommandKind::DyldInfo(_) => self.fixup_dyld_info(ci)?,
                LoadCommandKind::Corrupt(cmd) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Error fixing corrupt {} at 0x{:x}",
                            get_load_command_name(cmd.get_command_type() as u32),
                            cmd.get_start_index()
                        ),
                    ));
                }
                k if LinkEditDataCommand::from_kind(k).is_some() => self.fixup_link_edit_data(ci)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Java `fixupSegment(SegmentCommand)`.
    fn fixup_segment(&mut self, i: usize) -> io::Result<()> {
        let adjustment = *self.packed_segment_adjustments.get(&i).unwrap_or(&0) as i64;
        let (is64bit, start, vmaddr, vmsize, filesize, sections) = {
            let s = self.seg(i);
            let sections: Vec<(i32, i64, i32)> = s
                .get_sections()
                .iter()
                .map(|sec| (sec.get_offset(), sec.get_size(), sec.get_relocation_offset()))
                .collect();
            (!s.is32bit(), s.get_start_index() as i64, s.get_vm_address(), s.get_vm_size(), s.get_file_size(), sections)
        };
        let size = if is64bit { 8 } else { 4 };
        self.set(start + 0x18, vmaddr, size)?;
        self.set(start + if is64bit { 0x20 } else { 0x1c }, vmsize, size)?;
        self.fixup(start + if is64bit { 0x28 } else { 0x20 }, adjustment, size, Some(i))?;
        self.set(start + if is64bit { 0x30 } else { 0x24 }, filesize, size)?;
        let mut section_start_index = start + if is64bit { 0x48 } else { 0x38 };
        for (offset, sec_size, reloff) in sections {
            if self.monitor.is_cancelled() {
                break;
            }
            // For some reason the section file offsets in the iOS 10 DYLD cache do not want the
            // adjustment despite the segment needing it (Java comment).
            if offset > 0 && sec_size > 0 {
                self.fixup(section_start_index + if is64bit { 0x30 } else { 0x28 }, adjustment, 4, Some(i))?;
            }
            if reloff > 0 {
                self.fixup(section_start_index + if is64bit { 0x38 } else { 0x30 }, adjustment, 4, Some(i))?;
            }
            section_start_index += if is64bit { 0x50 } else { 0x44 };
        }
        Ok(())
    }

    /// Java `fixupSymbolTable(SymbolTableCommand)`.
    fn fixup_symbol_table(&mut self, ci: usize) -> io::Result<()> {
        let (start, symoff, nsyms, stroff, strsize, entry_size) = {
            let cmd = SymbolTableCommand::from_kind(&self.macho_header.get_load_commands()[ci]).expect("symtab");
            (
                cmd.get_start_index() as i64,
                cmd.get_symbol_offset(),
                cmd.get_number_of_symbols(),
                cmd.get_string_table_offset(),
                cmd.get_string_table_size(),
                cmd.get_symbol_at(0).map(|s| s.get_size() as i64).unwrap_or(0),
            )
        };
        if symoff > 0 {
            let adjustment = self.get_link_edit_adjustment(ci);
            let symbol_offset = self.fixup(start + 0x8, adjustment, 4, self.link_edit_segment)?;
            self.set(start + 0xc, nsyms, 4)?;
            if stroff > 0 {
                if nsyms > 0 {
                    self.set(start + 0x10, symbol_offset + nsyms * entry_size, 4)?;
                    self.set(start + 0x14, strsize, 4)?;
                } else {
                    self.set(start + 0x10, symbol_offset, 4)?;
                    self.set(start + 0x14, 0, 4)?;
                }
            }
        }
        Ok(())
    }

    /// Java `fixupDynamicSymbolTable(DynamicSymbolTableCommand)`. Only the indirect symbol table
    /// is extracted, so the other data-pointing fields are zeroed.
    fn fixup_dynamic_symbol_table(&mut self, ci: usize) -> io::Result<()> {
        let adjustment = self.get_link_edit_adjustment(ci);
        let (start, toc, modtab, refsym, indirect, extrel, locrel) = {
            let cmd = DynamicSymbolTableCommand::from_kind(&self.macho_header.get_load_commands()[ci])
                .expect("dysymtab");
            (
                cmd.get_start_index() as i64,
                cmd.get_table_of_contents_offset(),
                cmd.get_module_table_offset(),
                cmd.get_referenced_symbol_table_offset(),
                cmd.get_indirect_symbol_table_offset(),
                cmd.get_external_relocation_offset(),
                cmd.get_local_relocation_offset(),
            )
        };
        if toc > 0 {
            self.set(start + 0x20, 0, 8)?;
        }
        if modtab > 0 {
            self.set(start + 0x28, 0, 8)?;
        }
        if refsym > 0 {
            self.set(start + 0x30, 0, 8)?;
        }
        if indirect > 0 {
            self.fixup(start + 0x38, adjustment, 4, self.link_edit_segment)?;
        }
        if extrel > 0 {
            self.set(start + 0x40, 0, 8)?;
        }
        if locrel > 0 {
            self.set(start + 0x48, 0, 8)?;
        }
        Ok(())
    }

    /// Java `fixupDyldInfo(DyldInfoCommand)`. This load command is not extracted, so all its
    /// fields are zeroed.
    fn fixup_dyld_info(&mut self, ci: usize) -> io::Result<()> {
        let LoadCommandKind::DyldInfo(cmd) = &self.macho_header.get_load_commands()[ci] else {
            return Ok(());
        };
        let start = cmd.get_start_index() as i64;
        let fields = [
            (cmd.rebase_offset(), 0x8),
            (cmd.bind_offset(), 0x10),
            (cmd.weak_bind_offset(), 0x18),
            (cmd.lazy_bind_offset(), 0x20),
            (cmd.export_offset(), 0x28),
        ];
        for (offset, field) in fields {
            if offset > 0 {
                self.set(start + field, 0, 8)?;
            }
        }
        Ok(())
    }

    /// Java `fixupLinkEditData(LinkEditDataCommand)`.
    fn fixup_link_edit_data(&mut self, ci: usize) -> io::Result<()> {
        let kind = &self.macho_header.get_load_commands()[ci];
        let (start, dataoff) = (kind.get_start_index() as i64, kind.get_linker_data_offset());
        if dataoff > 0 {
            let adjustment = self.get_link_edit_adjustment(ci);
            self.fixup(start + 0x8, adjustment, 4, self.link_edit_segment)?;
        }
        Ok(())
    }

    /// Java `getLinkEditAdjustment(LoadCommand)`: what to add to a container file offset into
    /// `__LINKEDIT` to account for the packed `__LINKEDIT`.
    fn get_link_edit_adjustment(&self, ci: usize) -> i64 {
        let packed_start = *self.packed_link_edit_data_starts.get(&ci).unwrap_or(&0) as i64;
        let data_offset = self.macho_header.get_load_commands()[ci].get_linker_data_offset();
        let link_edit_offset = self.link_edit_segment.map(|i| self.seg(i).get_file_offset()).unwrap_or(0);
        packed_start - (data_offset - link_edit_offset)
    }

    /// Java `set(long, long, int)`: overwrites the load-command field at container offset
    /// `file_offset` with `value` (little-endian, as Java writes it).
    fn set(&mut self, file_offset: i64, value: i64, size: usize) -> io::Result<()> {
        let new_bytes = to_bytes(value, size)?;
        match self.get_packed_offset(file_offset, self.text_segment) {
            Ok(off) => copy_into(&mut self.packed, off as usize, &new_bytes),
            Err(NotFound(msg)) => {
                Msg::warn("ExtractedMacho", &msg);
                Ok(())
            }
        }
    }

    /// Java `fixup(long, long, int, SegmentCommand)`: rewrites the container file offset stored
    /// at `file_offset` (plus `adjustment`) as the matching packed offset within `segment`.
    /// Returns the new value, or the original value on a graceful failure.
    fn fixup(&mut self, file_offset: i64, adjustment: i64, size: usize, segment: Option<usize>) -> io::Result<i64> {
        to_bytes(0, size)?; // Java's up-front size check (IllegalArgumentException)
        let mut value = self.reader.read_unsigned_value(file_offset as u64, size)? as i64;
        let mut ret = value;
        value = value.wrapping_add(adjustment);
        let result: Result<(), NotFound> = (|| {
            ret = self.get_packed_offset(value, segment)?;
            let new_bytes = to_bytes(ret, size).expect("size checked above");
            let off = self.get_packed_offset(file_offset, self.text_segment)?;
            copy_into(&mut self.packed, off as usize, &new_bytes)
                .map_err(|e| NotFound(e.to_string()))?;
            Ok(())
        })();
        if let Err(NotFound(msg)) = result {
            Msg::warn("ExtractedMacho", &msg);
        }
        Ok(ret)
    }

    /// Java `adjustLinkEditAddress()`: moves the packed `__LINKEDIT` far away from every other
    /// Mach-O's so several extracted components can share one program (64-bit only).
    fn adjust_link_edit_address(&mut self) {
        if self.macho_header.is32bit() {
            return;
        }
        if let (Some(text), Some(link_edit)) = (self.text_segment, self.link_edit_segment) {
            let addr = self.seg(text).get_vm_address() << 4;
            self.seg_mut(link_edit).set_vm_address(addr);
        }
    }
}

/// Java `ExtractedMacho.toBytes(long, int)`: `value` as 4 or 8 little-endian bytes.
///
/// # Errors
/// `InvalidInput` (Java: `IllegalArgumentException`) for any other `size`.
pub fn to_bytes(value: i64, size: usize) -> io::Result<Vec<u8>> {
    match size {
        8 => Ok(value.to_le_bytes().to_vec()),
        4 => Ok((value as i32).to_le_bytes().to_vec()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Size must be 4 or 8 (got {size})"),
        )),
    }
}

/// `System.arraycopy(src, 0, dest, start, src.length)`, with Java's bounds check as an error.
fn copy_into(dest: &mut [u8], start: usize, src: &[u8]) -> io::Result<()> {
    let end = start.checked_add(src.len()).filter(|&e| e <= dest.len()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("copy of {} bytes at {start} exceeds packed size {}", src.len(), dest.len()),
        )
    })?;
    dest[start..end].copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::commands::load_command_types::{LC_SEGMENT_64, LC_SYMTAB};
    use crate::format::macho::mach_constants::MH_MAGIC_64;
    use crate::format::macho::mach_header::test_support::Bytes;

    /// Writes a 64-bit LE Mach-O (header at `base`, absolute file offsets) into `b`:
    /// `__TEXT` (vm `text_vm`, file `[base, base+0x1000)`), `__LINKEDIT` (vm `text_vm+0x2000`,
    /// file `[linkedit_off, +0x800)`) and an `LC_SYMTAB` with one symbol `name` at
    /// `linkedit_off`. Returns nothing; `b` is padded as needed.
    pub(crate) fn write_macho(b: &mut Bytes, base: usize, text_vm: u64, linkedit_off: u32, name: &str) {
        b.pad_to(base);
        b.u32(MH_MAGIC_64).u32(0x0100_000c).u32(0).u32(6).u32(3).u32(72 + 72 + 24).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72).name("__TEXT", 16);
        b.u64(text_vm).u64(0x1000).u64(base as u64).u64(0x1000).u32(5).u32(5).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72).name("__LINKEDIT", 16);
        b.u64(text_vm + 0x2000).u64(0x1000).u64(linkedit_off as u64).u64(0x800).u32(1).u32(1).u32(0).u32(0);
        let strsize = (name.len() as u32 + 2 + 7) & !7;
        b.u32(LC_SYMTAB).u32(24).u32(linkedit_off).u32(1).u32(linkedit_off + 16).u32(strsize);
        // Recognizable __TEXT payload after the load commands.
        b.raw(b"TEXTDATA");
        b.pad_to(linkedit_off as usize);
        b.u32(1).u8(0x0f).u8(1).u16(0).u64(text_vm + 0x100);
        b.u8(0).raw(name.as_bytes()).u8(0);
        b.pad_to(linkedit_off as usize + 0x800);
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::write_macho;
    use super::*;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::util::task::DummyMonitor;

    fn le32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn le64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn to_bytes_is_little_endian_and_checks_size() {
        assert_eq!(to_bytes(0x1122_3344_5566_7788, 8).unwrap(), 0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(to_bytes(0x1_0000_0002, 4).unwrap(), [2, 0, 0, 0]);
        assert_eq!(to_bytes(1, 2).unwrap_err().to_string(), "Size must be 4 or 8 (got 2)");
    }

    #[test]
    fn packs_segments_adjacent_and_fixes_up_offsets() {
        let mut b = Bytes::new(true);
        write_macho(&mut b, 0x1000, 0x1_0000_0000, 0x3000, "_main");
        b.pad_to(0x4000);
        let p = provider(b.buf);
        let mut header = MachHeader::with_start_index_relative(Rc::clone(&p), 0x1000, false).unwrap();
        header.parse().unwrap();

        let mut em = ExtractedMacho::new(p, 0x1000, header, b"FOOT", &DummyMonitor);
        em.pack().unwrap();
        let out = em.get_packed();

        // __TEXT (0x1000) + packed __LINKEDIT (16-byte nlist + "\0_main\0" = 23) + footer (4)
        assert_eq!(out.len(), 0x1000 + 23 + 4);
        assert_eq!(&out[out.len() - 4..], b"FOOT");
        assert_eq!(le32(out, 0), 0xfeed_facf);
        assert_eq!(&out[0x20 + 168..0x20 + 168 + 8], b"TEXTDATA");

        // __TEXT segment command at packed 0x20: fileoff -> 0, filesize unchanged.
        assert_eq!(le64(out, 0x20 + 0x18), 0x1_0000_0000);
        assert_eq!(le64(out, 0x20 + 0x28), 0);
        assert_eq!(le64(out, 0x20 + 0x30), 0x1000);
        // __LINKEDIT segment command at packed 0x68: moved far away, packed size, fileoff 0x1000.
        assert_eq!(le64(out, 0x68 + 0x18), 0x1_0000_0000 << 4);
        assert_eq!(le64(out, 0x68 + 0x20), 23);
        assert_eq!(le64(out, 0x68 + 0x28), 0x1000);
        assert_eq!(le64(out, 0x68 + 0x30), 23);
        // LC_SYMTAB at packed 0xb0: symoff 0x1000, nsyms 1, stroff 0x1010, strsize unchanged.
        assert_eq!(le32(out, 0xb0 + 0x8), 0x1000);
        assert_eq!(le32(out, 0xb0 + 0xc), 1);
        assert_eq!(le32(out, 0xb0 + 0x10), 0x1010);
        assert_eq!(le32(out, 0xb0 + 0x14), 8);
        // Packed symbol table: nlist with string index 1, then "\0_main\0".
        assert_eq!(le32(out, 0x1000), 1);
        assert_eq!(out[0x1004], 0x0f);
        assert_eq!(le64(out, 0x1008), 0x1_0000_0100);
        assert_eq!(&out[0x1010..0x1017], b"\0_main\0");

        // The repacked bytes parse back as a Mach-O whose symbol resolves.
        let mut reparsed = MachHeader::new(provider(out.to_vec())).unwrap();
        reparsed.parse().unwrap();
        let symtab = reparsed.get_first_load_command::<SymbolTableCommand>().unwrap();
        assert_eq!(symtab.get_symbols()[0].get_string(), "_main");
        assert_eq!(reparsed.get_segment("__LINKEDIT").unwrap().get_file_offset(), 0x1000);
    }

    #[test]
    fn extra_symbols_and_custom_segment_provider() {
        let mut b = Bytes::new(true);
        write_macho(&mut b, 0, 0x2000, 0x2000, "_a");
        let bytes = b.buf.clone();
        let p = provider(bytes.clone());
        let mut header = MachHeader::new(Rc::clone(&p)).unwrap();
        header.parse().unwrap();
        let extra = header.get_first_load_command::<SymbolTableCommand>().unwrap().get_symbols()[0].clone();

        let calls = std::cell::Cell::new(0);
        let alt = provider(bytes);
        let mut em = ExtractedMacho::new(p, 0, header, b"", &DummyMonitor)
            .with_extra_symbols(vec![extra])
            .with_segment_provider(Box::new(|_s: &SegmentCommand| {
                calls.set(calls.get() + 1);
                Ok(Rc::clone(&alt))
            }));
        em.pack().unwrap();
        assert_eq!(calls.get(), 2);
        // Two 16-byte nlists + "\0_a\0_a\0" (7)
        assert_eq!(em.get_packed().len(), 0x1000 + 32 + 7);
        let symtab = em.get_mach_header().get_first_load_command::<SymbolTableCommand>().unwrap();
        assert_eq!(symtab.get_number_of_symbols(), 2);
    }
}
