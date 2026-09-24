//! Port of `ghidra.program.model.lang.ParamEntry`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::address_xml::{self, AddressXml, DefaultAddressXml};
use crate::program::model::pcode::{
    Encoder, Varnode, ATTRIB_ALIGN, ATTRIB_EXTENSION, ATTRIB_MAXSIZE, ATTRIB_METATYPE,
    ATTRIB_MINSIZE, ATTRIB_SIZE, ATTRIB_STORAGE, ELEM_PENTRY,
};
use crate::program::seam_stubs::ParameterPieces;
use crate::util::xml::spec_xml_utils::decode_int;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Big endian values are left justified within their slot.
const FORCE_LEFT_JUSTIFY: i32 = 1;
/// Slots from the stack section are allocated in reverse order.
const REVERSE_STACK: i32 = 2;
/// Assume values that are below max size are zero extended.
const SMALLSIZE_ZEXT: i32 = 4;
/// Assume values that are below max size are sign extended.
const SMALLSIZE_SEXT: i32 = 8;
/// Interpret values in this container as big endian.
const IS_BIG_ENDIAN: i32 = 16;
/// Assume values that are below max size are extended based on integer type.
const SMALLSIZE_INTTYPE: i32 = 32;
/// Assume values smaller than max size are floating-point extended to full size.
const SMALLSIZE_FLOAT: i32 = 64;
/// The entry is grouped with other entries.
const IS_GROUPED: i32 = 512;
/// This overlaps an earlier entry.
const OVERLAPPING: i32 = 0x100;

/// A resource within a parameter list: a memory range (register, stack region, or "join" of
/// several pieces) that can hold all or part of a single parameter or return value.
///
/// Built from a `<pentry>` tag of a compiler specification by [`ParamEntry::restore_xml`] and
/// immutable afterwards; a [`ParamListStandard`](super::param_list_standard::ParamListStandard)
/// holds its entries as `Arc<ParamEntry>` so `protorules` actions can keep references to the
/// same entries (Java shares the objects the same way).
///
/// Port of `ghidra.program.model.lang.ParamEntry`.
#[derive(Clone, Debug)]
pub struct ParamEntry {
    flags: i32,
    /// Restriction on the data-type this entry must match (`ParamEntry.type`).
    storage_type: StorageClass,
    /// Group(s) this entry belongs to (`ParamEntry.groupSet`); never empty.
    group_set: Vec<i32>,
    /// Space of this range (`ParamEntry.spaceid`).
    spaceid: Arc<AddressSpace>,
    /// Start of the range (`ParamEntry.addressbase`).
    addressbase: i64,
    /// Size of the range (`ParamEntry.size`).
    size: i32,
    /// Minimum allowable match (`ParamEntry.minsize`).
    minsize: i32,
    /// How much alignment; 0 means use only once (`ParamEntry.alignment`).
    alignment: i32,
    /// (Maximum) number of slots that can store separate parameters (`ParamEntry.numslots`).
    numslots: i32,
    /// Pieces of a "join" entry, most significant first (`ParamEntry.joinrec`).
    joinrec: Option<Vec<Varnode>>,
}

/// Field values for [`ParamEntry::from_parts`], mirroring the private fields `restoreXml` fills.
#[derive(Clone)]
pub struct ParamEntryParts {
    pub space: Arc<AddressSpace>,
    pub addressbase: i64,
    pub size: i32,
    pub minsize: i32,
    pub alignment: i32,
    pub numslots: i32,
    pub storage_type: StorageClass,
    pub group_set: Vec<i32>,
    pub big_endian: bool,
    pub reverse_stack: bool,
    pub force_left_justify: bool,
    pub grouped: bool,
    pub overlapping: bool,
    pub joinrec: Option<Vec<Varnode>>,
}

impl ParamEntryParts {
    /// A single-group, general-purpose, little-endian entry covering `size` bytes at
    /// `space:addressbase`. `alignment == 0` makes it an exclusion (single slot) entry; otherwise
    /// the number of slots is `size / alignment`, exactly as `restoreXml` computes it.
    pub fn new(space: Arc<AddressSpace>, addressbase: i64, size: i32, alignment: i32, group: i32) -> Self {
        ParamEntryParts {
            space,
            addressbase,
            size,
            minsize: 1,
            alignment,
            numslots: if alignment != 0 { size / alignment } else { 1 },
            storage_type: StorageClass::General,
            group_set: vec![group],
            big_endian: false,
            reverse_stack: false,
            force_left_justify: false,
            grouped: false,
            overlapping: false,
            joinrec: None,
        }
    }
}

impl ParamEntry {
    /// Build an entry directly from its field values, for code that synthesizes parameter
    /// resources rather than reading them from a compiler specification.
    pub fn from_parts(parts: ParamEntryParts) -> Self {
        let mut flags = 0;
        if parts.big_endian {
            flags |= IS_BIG_ENDIAN;
        }
        if parts.reverse_stack {
            flags |= REVERSE_STACK;
        }
        if parts.force_left_justify {
            flags |= FORCE_LEFT_JUSTIFY;
        }
        if parts.grouped {
            flags |= IS_GROUPED;
        }
        if parts.overlapping {
            flags |= OVERLAPPING;
        }
        assert!(!parts.group_set.is_empty(), "a ParamEntry belongs to at least one group");
        ParamEntry {
            flags,
            storage_type: parts.storage_type,
            group_set: parts.group_set,
            spaceid: parts.space,
            addressbase: parts.addressbase,
            size: parts.size,
            minsize: parts.minsize,
            alignment: parts.alignment,
            numslots: parts.numslots,
            joinrec: parts.joinrec,
        }
    }

    /// The group this entry is part of (the first, if it belongs to several).
    ///
    /// Port of `ParamEntry.getGroup`.
    pub fn get_group(&self) -> i32 {
        self.group_set[0]
    }

    /// All groups this entry belongs to, in ascending order.
    ///
    /// Port of `ParamEntry.getAllGroups`.
    pub fn get_all_groups(&self) -> &[i32] {
        &self.group_set
    }

    /// The maximum size, in bytes, of the whole memory range.
    ///
    /// Port of `ParamEntry.getSize`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// The minimum size of data that can be stored here.
    ///
    /// Port of `ParamEntry.getMinSize`.
    pub fn get_min_size(&self) -> i32 {
        self.minsize
    }

    /// The byte alignment of consecutive slots, or 0 for a single "exclusion" slot.
    ///
    /// Port of `ParamEntry.getAlign`.
    pub fn get_align(&self) -> i32 {
        self.alignment
    }

    /// The starting offset of the range within [`get_space`](Self::get_space).
    ///
    /// Port of `ParamEntry.getAddressBase`.
    pub fn get_address_base(&self) -> i64 {
        self.addressbase
    }

    /// The restriction on data-type this entry can match.
    ///
    /// Port of `ParamEntry.getType`.
    pub fn get_type(&self) -> StorageClass {
        self.storage_type
    }

    /// The (maximum) number of slots that can store separate parameters. Java reads the private
    /// `numslots` field directly; exposed because `protorules` actions size their consumption
    /// from it.
    pub fn num_slots(&self) -> i32 {
        self.numslots
    }

    /// True if this is a single, non-aligned "exclusion" slot.
    ///
    /// Port of `ParamEntry.isExclusion`.
    pub fn is_exclusion(&self) -> bool {
        self.alignment == 0
    }

    /// True if slots from the stack section are allocated in reverse order.
    ///
    /// Port of `ParamEntry.isReverseStack`.
    pub fn is_reverse_stack(&self) -> bool {
        (self.flags & REVERSE_STACK) != 0
    }

    /// True if this entry is grouped with other entries.
    ///
    /// Port of `ParamEntry.isGrouped`.
    pub fn is_grouped(&self) -> bool {
        (self.flags & IS_GROUPED) != 0
    }

    /// True if this entry overlaps an earlier entry.
    ///
    /// Port of `ParamEntry.isOverlap`.
    pub fn is_overlap(&self) -> bool {
        (self.flags & OVERLAPPING) != 0
    }

    /// True if values in this container are interpreted as big endian.
    ///
    /// Port of `ParamEntry.isBigEndian`.
    pub fn is_big_endian(&self) -> bool {
        (self.flags & IS_BIG_ENDIAN) != 0
    }

    /// True if big-endian values are nonetheless left justified within their slot.
    pub fn is_force_left_justify(&self) -> bool {
        (self.flags & FORCE_LEFT_JUSTIFY) != 0
    }

    /// True if values below the max size are assumed sign extended.
    pub fn is_sign_extend(&self) -> bool {
        (self.flags & SMALLSIZE_SEXT) != 0
    }

    /// True if values below the max size are assumed zero extended.
    pub fn is_zero_extend(&self) -> bool {
        (self.flags & SMALLSIZE_ZEXT) != 0
    }

    /// True if values below the max size are extended based on their integer type.
    pub fn is_int_type_extend(&self) -> bool {
        (self.flags & SMALLSIZE_INTTYPE) != 0
    }

    /// True if values smaller than the max size are floating-point extended to full size.
    pub fn is_float_extend(&self) -> bool {
        (self.flags & SMALLSIZE_FLOAT) != 0
    }

    /// The pieces of a "join" entry, most significant first, or `None` for an ordinary range.
    pub fn get_join_record(&self) -> Option<&[Varnode]> {
        self.joinrec.as_deref()
    }

    /// True if data smaller than a slot is left justified within it.
    ///
    /// Port of the private `ParamEntry.isLeftJustified`.
    pub fn is_left_justified(&self) -> bool {
        (self.flags & IS_BIG_ENDIAN) == 0 || (self.flags & FORCE_LEFT_JUSTIFY) != 0
    }

    /// The address space of this entry's range.
    ///
    /// Port of `ParamEntry.getSpace`.
    pub fn get_space(&self) -> Arc<AddressSpace> {
        self.spaceid.clone()
    }

    /// Collect pieces from the join list, in endian order, until the given size is covered. The
    /// last piece is trimmed to match the size exactly. Returns `None` if the size is too big to
    /// be covered by this entry, or if this is not a join entry.
    ///
    /// Port of the private `ParamEntry.getJoinPieces`.
    ///
    /// # Deviation
    /// Java trims `res[replace]` where, on the little-endian path, `replace` is an index into
    /// `joinrec` (`joinrec.length - num`) rather than into the `num`-element result, so any
    /// little-endian request that stops short of the most significant piece throws
    /// `ArrayIndexOutOfBoundsException` (or trims the wrong piece). The trimmed piece is always the
    /// last one consumed -- the first element of the result on this path -- and that is the piece
    /// trimmed here.
    pub fn get_join_pieces_for_size(&self, sz: i32) -> Option<Vec<Varnode>> {
        let joinrec = self.joinrec.as_deref()?;
        let mut num: usize = 0;
        let first: usize;
        let replace: usize;
        let mut vn: Option<&Varnode> = None;
        let mut remaining = sz;

        if self.is_big_endian() {
            while remaining > 0 {
                if num >= joinrec.len() {
                    return None;
                }
                let v = &joinrec[num];
                vn = Some(v);
                if v.get_size() > remaining {
                    num += 1;
                    break;
                }
                remaining -= v.get_size();
                num += 1;
            }
            first = 0;
            replace = num.wrapping_sub(1);
        } else {
            while remaining > 0 {
                if num >= joinrec.len() {
                    return None;
                }
                let v = &joinrec[joinrec.len() - 1 - num];
                vn = Some(v);
                if v.get_size() > remaining {
                    num += 1;
                    break;
                }
                remaining -= v.get_size();
                num += 1;
            }
            first = joinrec.len() - num;
            replace = first;
        }
        if remaining == 0 && num == joinrec.len() {
            return Some(joinrec.to_vec());
        }
        let mut res: Vec<Varnode> = joinrec[first..first + num].to_vec();
        if remaining > 0 {
            if let Some(v) = vn {
                res[replace - first] = Varnode::new(v.get_address().clone(), remaining);
            }
        }
        Some(res)
    }

    /// Is this entry, as a memory range, contained by the given memory range.
    ///
    /// Port of `ParamEntry.containedBy`.
    pub fn contained_by(&self, addr: &Address, sz: i32) -> bool {
        if self.spaceid.as_ref() != addr.space().as_ref() {
            return false;
        }
        if (self.addressbase as u64) < (addr.offset() as u64) {
            return false;
        }
        let range_end = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
        let this_end = self.addressbase.wrapping_add(self.size as i64).wrapping_sub(1);
        (this_end as u64) <= (range_end as u64)
    }

    /// Does this entry intersect the given range in some way.
    ///
    /// Port of `ParamEntry.intersects`.
    pub fn intersects(&self, addr: &Address, sz: i32) -> bool {
        if let Some(joinrec) = &self.joinrec {
            let rangeend = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
            for vn in joinrec {
                if addr.space().space_id() != vn.get_space_id() {
                    continue;
                }
                let vnend = vn.get_offset().wrapping_add(vn.get_size() as i64).wrapping_sub(1);
                if (addr.offset() as u64) < (vn.get_offset() as u64) && (rangeend as u64) < (vnend as u64) {
                    continue;
                }
                if (addr.offset() as u64) > (vn.get_offset() as u64) && (rangeend as u64) > (vnend as u64) {
                    continue;
                }
                return true;
            }
        }
        if self.spaceid.space_id() != addr.space().space_id() {
            return false;
        }
        let rangeend = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
        let thisend = self.addressbase.wrapping_add(self.size as i64).wrapping_sub(1);
        if (addr.offset() as u64) < (self.addressbase as u64) && (rangeend as u64) < (thisend as u64) {
            return false;
        }
        if (addr.offset() as u64) > (self.addressbase as u64) && (rangeend as u64) > (thisend as u64) {
            return false;
        }
        true
    }

    /// Return -1 if `(addr, sz)` is not properly, endian-aware contained in this entry.
    /// Otherwise return the endian-aware offset of `(addr, sz)` within this entry.
    ///
    /// Port of `ParamEntry.justifiedContain`.
    pub fn justified_contain(&self, addr: &Address, sz: i32) -> i32 {
        if let Some(joinrec) = &self.joinrec {
            let mut res = 0i32;
            // Move from least significant to most
            for vdata in joinrec.iter().rev() {
                let cur = justified_contain_address(
                    vdata.get_address().space(),
                    vdata.get_offset(),
                    vdata.get_size(),
                    addr.space(),
                    addr.offset(),
                    sz,
                    false,
                    self.is_big_endian(),
                );
                if cur < 0 {
                    res += vdata.get_size(); // We skipped this many less significant bytes
                } else {
                    return res + cur;
                }
            }
            return -1; // Not contained at all
        }
        if self.alignment == 0 {
            // Ordinary endian containment
            return justified_contain_address(
                &self.spaceid,
                self.addressbase,
                self.size,
                addr.space(),
                addr.offset(),
                sz,
                self.is_force_left_justify(),
                self.is_big_endian(),
            );
        }
        if self.spaceid.as_ref() != addr.space().as_ref() {
            return -1;
        }
        let startaddr = addr.offset();
        if (startaddr as u64) < (self.addressbase as u64) {
            return -1;
        }
        let endaddr = startaddr.wrapping_add(sz as i64).wrapping_sub(1);
        if (endaddr as u64) < (startaddr as u64) {
            return -1; // Don't allow wrap around
        }
        let this_last = self.addressbase.wrapping_add(self.size as i64).wrapping_sub(1);
        if (this_last as u64) < (endaddr as u64) {
            return -1;
        }
        let startaddr = startaddr.wrapping_sub(self.addressbase);
        let endaddr = endaddr.wrapping_sub(self.addressbase);
        let align = self.alignment as i64;
        if !self.is_left_justified() {
            // For right justified (big endian), endaddr must be aligned
            let res = ((endaddr + 1) % align) as i32;
            if res == 0 {
                return 0;
            }
            return self.alignment - res;
        }
        (startaddr % align) as i32
    }

    /// Does this entry contain another entry (as a subpiece).
    ///
    /// Port of `ParamEntry.contains`.
    pub fn contains(&self, other_entry: &ParamEntry) -> bool {
        if other_entry.joinrec.is_some() {
            return false; // Assume a join entry cannot be contained
        }
        match &self.joinrec {
            None => {
                let addr = Address::new(self.spaceid.clone(), self.addressbase);
                other_entry.contained_by(&addr, self.size)
            }
            Some(joinrec) => joinrec
                .iter()
                .any(|vn| other_entry.contained_by(vn.get_address(), vn.get_size())),
        }
    }

    /// Assuming the address is contained in this entry and we `skip` to a certain byte, return
    /// the slot associated with that byte.
    ///
    /// Port of `ParamEntry.getSlot`.
    pub fn get_slot(&self, addr: &Address, skip: i32) -> i32 {
        let mut res = self.group_set[0];
        if self.alignment != 0 {
            let diff = addr.offset().wrapping_add(skip as i64).wrapping_sub(self.addressbase);
            // Java: `(int) diff / alignment` -- the cast binds before the division.
            let baseslot = (diff as i32) / self.alignment;
            if self.is_reverse_stack() {
                res += (self.numslots - 1) - baseslot;
            } else {
                res += baseslot;
            }
        } else if skip != 0 {
            res = self.group_set[self.group_set.len() - 1];
        }
        res
    }

    /// Assign the storage address when allocating something of size `sz` assuming `slot_num`
    /// slots have already been assigned, justifying per this entry's endianness.
    ///
    /// Port of the 4-argument `ParamEntry.getAddrBySlot`.
    pub fn get_addr_by_slot(&self, slot_num: i32, sz: i32, type_align: i32, res: &mut ParameterPieces) -> i32 {
        self.get_addr_by_slot_justified(slot_num, sz, type_align, res, !self.is_left_justified())
    }

    /// Assign the storage address when allocating something of size `sz` assuming `slot_num`
    /// slots have already been assigned. `res.address` is left `None` if `sz` is too small or
    /// there are not enough slots left. Returns the slot number after the allocation.
    ///
    /// Port of the 5-argument `ParamEntry.getAddrBySlot`.
    pub fn get_addr_by_slot_justified(
        &self,
        mut slot_num: i32,
        sz: i32,
        type_align: i32,
        res: &mut ParameterPieces,
        justify_right: bool,
    ) -> i32 {
        res.address = None; // Start with an invalid result
        if sz < self.minsize {
            return slot_num;
        }
        let spaceused: i32;
        let mut offset: i64;
        if self.alignment == 0 {
            // If not an aligned entry (allowing multiple slots)
            if slot_num != 0 {
                return slot_num; // Can only allocate slot 0
            }
            if sz > self.size {
                return slot_num; // Check on maximum size
            }
            offset = self.addressbase; // Get base address of the slot
            spaceused = self.size;
            if (self.flags & SMALLSIZE_FLOAT) != 0 && sz != self.size {
                let addr = self.spaceid.address(offset);
                res.join_pieces = Some(vec![Varnode::new(addr.clone(), self.size)]);
                res.address = Some(addr);
                return slot_num;
            }
        } else {
            if type_align > self.alignment {
                let tmp = (slot_num * self.alignment) % type_align;
                if tmp != 0 {
                    slot_num += (type_align - tmp) / self.alignment; // Waste slots to achieve typeAlign
                }
            }
            let mut slotsused = sz / self.alignment; // How many slots does a -sz- byte object need
            if sz % self.alignment != 0 {
                slotsused += 1;
            }
            if slot_num + slotsused > self.numslots {
                return slot_num;
            }
            spaceused = slotsused * self.alignment;
            let index = if self.is_reverse_stack() {
                self.numslots - slot_num - slotsused
            } else {
                slot_num
            };
            offset = self.addressbase.wrapping_add(index as i64 * self.alignment as i64);
            slot_num += slotsused; // Inform caller of number of slots used
        }
        if justify_right {
            offset = offset.wrapping_add((spaceused - sz) as i64);
        }
        let addr = self.spaceid.address(offset);
        if addr.space().space_type() == AddressSpaceType::Join {
            res.join_pieces = self.get_join_pieces_for_size(sz);
        }
        res.address = Some(addr);
        slot_num
    }

    /// Search backward through `cur_list` for an entry whose range is exactly `varnode`.
    ///
    /// Port of the private static `ParamEntry.findEntryByStorage`.
    fn find_entry_by_storage<'a>(cur_list: &'a [Arc<ParamEntry>], varnode: &Varnode) -> Option<&'a ParamEntry> {
        cur_list
            .iter()
            .rev()
            .map(|e| e.as_ref())
            .find(|e| {
                e.spaceid.space_id() == varnode.get_space_id()
                    && e.addressbase == varnode.get_offset()
                    && e.size == varnode.get_size()
            })
    }

    /// Make adjustments for a join entry, which is considered to overlap the earlier entries
    /// holding its pieces: its group set becomes the union of theirs.
    ///
    /// Port of the private `ParamEntry.resolveJoin`.
    fn resolve_join(&mut self, cur_list: &[Arc<ParamEntry>]) -> Result<(), XmlParseException> {
        let Some(joinrec) = &self.joinrec else {
            return Ok(());
        };
        let mut new_group_set = Vec::new();
        for piece in joinrec {
            if let Some(entry) = Self::find_entry_by_storage(cur_list, piece) {
                new_group_set.extend_from_slice(&entry.group_set);
            }
        }
        if new_group_set.is_empty() {
            return Err(XmlParseException::new("<pentry> join must overlap at least one previous entry"));
        }
        new_group_set.sort_unstable();
        self.group_set = new_group_set;
        self.flags |= OVERLAPPING;
        Ok(())
    }

    /// Search for earlier entries this one overlaps; if it contains them, it inherits their
    /// groups. Partial overlaps are an error.
    ///
    /// Port of the private `ParamEntry.resolveOverlap`. `cur_list` holds the entries restored
    /// before this one (Java's list also contains `this`, which the loop skips).
    fn resolve_overlap(&mut self, cur_list: &[Arc<ParamEntry>]) -> Result<(), XmlParseException> {
        if self.joinrec.is_some() {
            return Ok(());
        }
        let mut new_group_set = Vec::new();
        let addr = Address::new(self.spaceid.clone(), self.addressbase);
        for entry in cur_list {
            if !entry.intersects(&addr, self.size) {
                continue;
            }
            if self.contains(entry) {
                if entry.is_overlap() {
                    continue; // Don't count resources (already counted overlapped pentry)
                }
                new_group_set.extend_from_slice(&entry.group_set);
            } else {
                return Err(XmlParseException::new("Illegal overlap of <pentry> in compiler spec"));
            }
        }
        if new_group_set.is_empty() {
            return Ok(()); // No overlaps
        }
        new_group_set.sort_unstable();
        self.group_set = new_group_set;
        self.flags |= OVERLAPPING;
        Ok(())
    }

    /// Encode this entry as a `<pentry>` element.
    ///
    /// Port of `ParamEntry.encode`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_PENTRY)?;
        encoder.write_signed_integer(ATTRIB_MINSIZE, self.minsize as i64)?;
        encoder.write_signed_integer(ATTRIB_MAXSIZE, self.size as i64)?;
        if self.alignment != 0 {
            encoder.write_signed_integer(ATTRIB_ALIGN, self.alignment as i64)?;
        }
        if self.storage_type != StorageClass::General {
            encoder.write_string(ATTRIB_STORAGE, &self.storage_type.to_string())?;
        }
        let ext_string = if (self.flags & SMALLSIZE_SEXT) != 0 {
            Some("sign")
        } else if (self.flags & SMALLSIZE_ZEXT) != 0 {
            Some("zero")
        } else if (self.flags & SMALLSIZE_INTTYPE) != 0 {
            Some("inttype")
        } else if (self.flags & SMALLSIZE_FLOAT) != 0 {
            Some("float")
        } else {
            None
        };
        if let Some(ext) = ext_string {
            encoder.write_string(ATTRIB_EXTENSION, ext)?;
        }
        let address_size = match &self.joinrec {
            // Treat as unsized address with no size
            None => DefaultAddressXml::new(self.spaceid.clone(), self.addressbase, 0),
            Some(pieces) => {
                DefaultAddressXml::with_join(self.spaceid.clone(), self.addressbase, self.size, pieces.clone())
            }
        };
        address_size.encode(encoder)?;
        encoder.close_element(ELEM_PENTRY)?;
        Ok(())
    }

    /// Restore an entry from a `<pentry>` element.
    ///
    /// `cur_list` holds the entries of the enclosing parameter list restored so far (used to
    /// resolve join and overlap groups); `group` is the group this entry is assigned if it
    /// overlaps nothing, and `grouped` marks an entry that came from inside a `<group>` tag.
    ///
    /// Port of `ParamEntry(int)` followed by `ParamEntry.restoreXml(XmlPullParser, CompilerSpec,
    /// List<ParamEntry>, boolean)`.
    ///
    /// # Errors
    /// Returns an error for badly formed or inconsistent XML.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        parser: &mut P,
        cspec: &dyn CompilerSpec,
        cur_list: &[Arc<ParamEntry>],
        grouped: bool,
        group: i32,
    ) -> Result<ParamEntry, XmlParseException> {
        let mut flags = 0;
        let mut storage_type = StorageClass::General;
        let mut size = -1; // Must be filled in
        let mut minsize = -1;
        let mut alignment = 0; // default
        let mut numslots = 1;
        let el = parser.start(&[ELEM_PENTRY.name])?;
        for (name, value) in el.get_attribute_iter() {
            if name == ATTRIB_MINSIZE.name {
                minsize = decode_int(Some(&value));
            } else if name == ATTRIB_SIZE.name || name == ATTRIB_ALIGN.name {
                // "size" is the old-style spelling of "align"
                alignment = decode_int(Some(&value));
            } else if name == ATTRIB_MAXSIZE.name {
                size = decode_int(Some(&value));
            } else if name == ATTRIB_STORAGE.name || name == ATTRIB_METATYPE.name {
                storage_type = StorageClass::from_str(&value)?;
            } else if name == ATTRIB_EXTENSION.name {
                flags &= !(SMALLSIZE_ZEXT | SMALLSIZE_SEXT | SMALLSIZE_INTTYPE | SMALLSIZE_FLOAT);
                match value.as_str() {
                    "sign" => flags |= SMALLSIZE_SEXT,
                    "zero" => flags |= SMALLSIZE_ZEXT,
                    "inttype" => flags |= SMALLSIZE_INTTYPE,
                    "float" => flags |= SMALLSIZE_FLOAT,
                    "none" => {}
                    _ => return Err(XmlParseException::new(format!("Bad extension attribute: {value}"))),
                }
            } else {
                return Err(XmlParseException::new(format!("Unknown paramentry attribute: {name}")));
            }
        }
        if minsize < 1 || size < minsize {
            return Err(XmlParseException::new(format!(
                "paramentry size not specified properly: minsize={minsize} maxsize={size}"
            )));
        }
        if alignment == size {
            alignment = 0;
        }
        let subel = parser.start(&[])?;
        let address_sized = address_xml::restore_xml(&subel, cspec)?;
        parser.end_matching(&subel)?;
        if address_sized.get_size() != 0 && (size as i64) > address_sized.get_size() {
            return Err(XmlParseException::new("<pentry> maxsize is bigger than memory range"));
        }
        let spaceid = address_sized
            .get_address_space()
            .ok_or_else(|| XmlParseException::new("<pentry> has no address space"))?;
        let addressbase = address_sized.get_offset();
        let joinrec = address_sized.get_join_record().map(|j| j.to_vec());
        let isbigendian = cspec.get_language().is_big_endian();
        if isbigendian {
            flags |= IS_BIG_ENDIAN;
        }
        if alignment != 0 {
            numslots = size / alignment;
        }
        if spaceid.space_type() == AddressSpaceType::Stack && !cspec.is_stack_right_justified() && isbigendian {
            flags |= FORCE_LEFT_JUSTIFY;
        }
        if !cspec.stack_grows_negative() {
            flags |= REVERSE_STACK;
            if alignment != 0 && (size % alignment) != 0 {
                return Err(XmlParseException::new(
                    "For positive stack growth, <pentry> size must match alignment",
                ));
            }
        }
        if grouped {
            flags |= IS_GROUPED;
        }
        let mut entry = ParamEntry {
            flags,
            storage_type,
            group_set: vec![group],
            spaceid,
            addressbase,
            size,
            minsize,
            alignment,
            numslots,
            joinrec,
        };
        entry.resolve_join(cur_list)?;
        entry.resolve_overlap(cur_list)?;
        parser.end_matching(&el)?;
        Ok(entry)
    }

    /// Determine if this entry is configured identically to another.
    ///
    /// Port of `ParamEntry.isEquivalent`.
    pub fn is_equivalent(&self, obj: &ParamEntry) -> bool {
        if self.spaceid.as_ref() != obj.spaceid.as_ref() || self.addressbase != obj.addressbase {
            return false;
        }
        if self.size != obj.size || self.minsize != obj.minsize || self.alignment != obj.alignment {
            return false;
        }
        if self.storage_type != obj.storage_type || self.flags != obj.flags {
            return false;
        }
        if self.numslots != obj.numslots {
            return false;
        }
        if self.group_set != obj.group_set {
            return false;
        }
        self.joinrec == obj.joinrec
    }
}

/// Return -1 if `(offset2, sz2)` is not properly contained in `(offset1, sz1)`. If it is
/// contained, return the endian-aware offset of `(offset2, sz2)`: 0 if the least significant byte
/// of the second range falls on the least significant byte of the first, 1 if it falls on the
/// second least significant, and so on.
///
/// Port of the static `ParamEntry.justifiedContainAddress`.
#[allow(clippy::too_many_arguments)]
pub fn justified_contain_address(
    spc1: &Arc<AddressSpace>,
    offset1: i64,
    sz1: i32,
    spc2: &Arc<AddressSpace>,
    offset2: i64,
    sz2: i32,
    forceleft: bool,
    is_big_endian: bool,
) -> i32 {
    if spc1.as_ref() != spc2.as_ref() {
        return -1;
    }
    if (offset2 as u64) < (offset1 as u64) {
        return -1;
    }
    let off1 = offset1.wrapping_add((sz1 - 1) as i64);
    let off2 = offset2.wrapping_add((sz2 - 1) as i64);
    if (off1 as u64) < (off2 as u64) {
        return -1;
    }
    if is_big_endian && !forceleft {
        return off1.wrapping_sub(off2) as i32;
    }
    offset2.wrapping_sub(offset1) as i32
}

/// Entries within a group must be distinguishable by size or by type.
///
/// Port of the static `ParamEntry.orderWithinGroup`.
///
/// # Errors
/// Returns an error if the pair is not distinguishable.
pub fn order_within_group(entry1: &ParamEntry, entry2: &ParamEntry) -> Result<(), XmlParseException> {
    if entry2.minsize > entry1.size || entry1.minsize > entry2.size {
        return Ok(());
    }
    if entry1.storage_type != entry2.storage_type {
        if entry1.storage_type == StorageClass::General {
            return Err(XmlParseException::new(
                "<pentry> tags with a specific type must come before the general type",
            ));
        }
        return Ok(());
    }
    Err(XmlParseException::new(
        "<pentry> tags within a group must be distinguished by size or type",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::cspec_test_support::{
        join_space, parser, register_space, stack_space, TestCompilerSpec, TestCspecLanguage,
    };

    fn restore(xml: &str, cspec: &TestCompilerSpec, cur: &[Arc<ParamEntry>], group: i32) -> Result<ParamEntry, XmlParseException> {
        let mut p = parser(xml);
        ParamEntry::restore_xml(&mut p, cspec, cur, false, group)
    }

    fn register_entry() -> ParamEntry {
        let cspec = TestCompilerSpec::x86_64();
        restore(r#"<pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>"#, &cspec, &[], 0).unwrap()
    }

    fn stack_entry() -> ParamEntry {
        let cspec = TestCompilerSpec::x86_64();
        restore(
            r#"<pentry minsize="1" maxsize="500" align="8"><addr offset="8" space="stack"/></pentry>"#,
            &cspec,
            &[],
            2,
        )
        .unwrap()
    }

    #[test]
    fn restore_register_pentry() {
        let e = register_entry();
        assert_eq!(e.get_space().space_type(), AddressSpaceType::Register);
        assert_eq!(e.get_address_base(), 0x38); // RDI
        assert_eq!(e.get_size(), 8);
        assert_eq!(e.get_min_size(), 1);
        assert!(e.is_exclusion());
        assert_eq!(e.num_slots(), 1);
        assert_eq!(e.get_type(), StorageClass::General);
        assert_eq!(e.get_all_groups(), &[0]);
        assert!(!e.is_big_endian());
        assert!(!e.is_reverse_stack());
    }

    #[test]
    fn restore_stack_pentry_computes_slots() {
        let e = stack_entry();
        assert_eq!(e.get_space().space_type(), AddressSpaceType::Stack);
        assert_eq!(e.get_address_base(), 8);
        assert_eq!(e.get_align(), 8);
        assert_eq!(e.num_slots(), 500 / 8);
        assert_eq!(e.get_group(), 2);
        assert!(!e.is_exclusion());
    }

    #[test]
    fn restore_float_storage_and_extension() {
        let cspec = TestCompilerSpec::x86_64();
        let e = restore(
            r#"<pentry minsize="4" maxsize="8" storage="float" extension="float"><register name="XMM0_Qa"/></pentry>"#,
            &cspec,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(e.get_type(), StorageClass::Float);
        assert!(e.is_float_extend());
        assert_eq!(e.get_address_base(), 0x1200);
        // A 4-byte float in an 8-byte float-extended register gets a one-piece join of the full
        // register.
        let mut res = ParameterPieces::default();
        e.get_addr_by_slot(0, 4, 4, &mut res);
        assert_eq!(res.address.as_ref().unwrap().offset(), 0x1200);
        assert_eq!(res.join_pieces.as_ref().unwrap()[0].get_size(), 8);
    }

    #[test]
    fn restore_rejects_bad_attributes() {
        let cspec = TestCompilerSpec::x86_64();
        let err = restore(r#"<pentry minsize="1" maxsize="8" bogus="1"><register name="RDI"/></pentry>"#, &cspec, &[], 0);
        assert!(err.unwrap_err().message().contains("Unknown paramentry attribute: bogus"));
        let err = restore(r#"<pentry minsize="4" maxsize="2"><register name="RDI"/></pentry>"#, &cspec, &[], 0);
        assert!(err.unwrap_err().message().contains("minsize=4 maxsize=2"));
        let err = restore(r#"<pentry minsize="1" maxsize="16"><register name="RDI"/></pentry>"#, &cspec, &[], 0);
        assert!(err.unwrap_err().message().contains("maxsize is bigger"));
        let err = restore(
            r#"<pentry minsize="1" maxsize="8" extension="odd"><register name="RDI"/></pentry>"#,
            &cspec,
            &[],
            0,
        );
        assert!(err.unwrap_err().message().contains("Bad extension attribute: odd"));
    }

    #[test]
    fn align_equal_to_size_is_exclusion() {
        let cspec = TestCompilerSpec::x86_64();
        let e = restore(r#"<pentry minsize="1" maxsize="8" align="8"><register name="RSI"/></pentry>"#, &cspec, &[], 0)
            .unwrap();
        assert!(e.is_exclusion());
    }

    #[test]
    fn big_endian_stack_is_left_justified_and_positive_growth_reverses() {
        let cspec = TestCompilerSpec {
            language: TestCspecLanguage { big_endian: true },
            stack_grows_negative: false,
            stack_right_justified: false,
        };
        let e = restore(
            r#"<pentry minsize="1" maxsize="16" align="4"><addr offset="0" space="stack"/></pentry>"#,
            &cspec,
            &[],
            0,
        )
        .unwrap();
        assert!(e.is_big_endian());
        assert!(e.is_force_left_justify());
        assert!(e.is_left_justified());
        assert!(e.is_reverse_stack());
        // Reverse stack: slot 0 is the highest slot in the region.
        let mut res = ParameterPieces::default();
        assert_eq!(e.get_addr_by_slot(0, 4, 4, &mut res), 1);
        assert_eq!(res.address.unwrap().offset(), 12);

        let err = restore(
            r#"<pentry minsize="1" maxsize="10" align="4"><addr offset="0" space="stack"/></pentry>"#,
            &cspec,
            &[],
            0,
        );
        assert!(err.unwrap_err().message().contains("positive stack growth"));
    }

    #[test]
    fn overlap_inherits_groups_of_contained_entries() {
        let cspec = TestCompilerSpec::x86_64();
        let eax = Arc::new(restore(r#"<pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>"#, &cspec, &[], 0).unwrap());
        let rax = restore(r#"<pentry minsize="5" maxsize="8"><register name="RAX"/></pentry>"#, &cspec, &[eax.clone()], 1)
            .unwrap();
        assert!(rax.is_overlap());
        assert_eq!(rax.get_all_groups(), &[0]);
        // An entry inside an earlier one (rather than containing it) is illegal.
        let rdi = Arc::new(register_entry());
        let err = restore(
            r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="0x3c" size="4"/></pentry>"#,
            &cspec,
            &[rdi],
            1,
        );
        assert!(err.unwrap_err().message().contains("Illegal overlap"));
    }

    #[test]
    fn join_entry_takes_groups_of_its_pieces() {
        let cspec = TestCompilerSpec::x86_64();
        let rax = Arc::new(restore(r#"<pentry minsize="1" maxsize="8"><register name="RAX"/></pentry>"#, &cspec, &[], 0).unwrap());
        let rdx = Arc::new(restore(r#"<pentry minsize="1" maxsize="8"><register name="RDX"/></pentry>"#, &cspec, &[rax.clone()], 1).unwrap());
        let join = restore(
            r#"<pentry minsize="9" maxsize="16"><addr space="join" piece1="RDX" piece2="RAX"/></pentry>"#,
            &cspec,
            &[rax, rdx],
            2,
        )
        .unwrap();
        assert_eq!(join.get_space().space_type(), AddressSpaceType::Join);
        assert!(join.is_overlap());
        assert_eq!(join.get_all_groups(), &[0, 1]);
        assert_eq!(join.get_join_record().unwrap().len(), 2);
        // Little endian: 12 bytes takes all of RAX (least significant) and 4 bytes of RDX.
        let pieces = join.get_join_pieces_for_size(12).unwrap();
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].get_offset(), 0x10);
        assert_eq!(pieces[0].get_size(), 4);
        assert_eq!(pieces[1].get_offset(), 0);
        assert_eq!(pieces[1].get_size(), 8);
        // 4 bytes fit in the least significant piece alone, trimmed to its low 4 bytes.
        let pieces = join.get_join_pieces_for_size(4).unwrap();
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].get_offset(), 0);
        assert_eq!(pieces[0].get_size(), 4);
        assert!(join.get_join_pieces_for_size(17).is_none());
        // A join that overlaps nothing is rejected.
        let err = restore(
            r#"<pentry minsize="9" maxsize="16"><addr space="join" piece1="RDX" piece2="RAX"/></pentry>"#,
            &cspec,
            &[],
            0,
        );
        assert!(err.unwrap_err().message().contains("join must overlap"));
    }

    #[test]
    fn contained_by_checks_space_and_range() {
        let entry = register_entry();
        let addr = Address::new(register_space(), 0x38);
        assert!(entry.contained_by(&addr, 8));
        assert!(entry.contained_by(&Address::new(register_space(), 0x30), 16));
        assert!(!entry.contained_by(&Address::new(register_space(), 0x3c), 8));
        assert!(!entry.contained_by(&Address::new(stack_space(), 0x38), 8));
    }

    #[test]
    fn justified_contain_little_endian_offset_within_slot() {
        let entry = register_entry();
        assert_eq!(entry.justified_contain(&Address::new(register_space(), 0x38), 4), 0);
        assert_eq!(entry.justified_contain(&Address::new(register_space(), 0x3c), 4), 4);
        assert_eq!(entry.justified_contain(&Address::new(register_space(), 0x100), 4), -1);
        let stack = stack_entry();
        assert_eq!(stack.justified_contain(&Address::new(stack_space(), 0x10), 4), 0);
        assert_eq!(stack.justified_contain(&Address::new(stack_space(), 0x14), 4), 4);
    }

    #[test]
    fn get_slot_advances_with_aligned_offset() {
        let entry = stack_entry();
        assert_eq!(entry.get_slot(&Address::new(stack_space(), 8), 0), 2);
        assert_eq!(entry.get_slot(&Address::new(stack_space(), 0x10), 0), 3);
        assert_eq!(entry.get_slot(&Address::new(stack_space(), 8), 8), 3);
    }

    #[test]
    fn get_addr_by_slot_allocates_sequential_slots_and_stops_when_full() {
        let entry = stack_entry();
        let mut res = ParameterPieces::default();
        assert_eq!(entry.get_addr_by_slot(0, 4, 4, &mut res), 1);
        assert_eq!(res.address.unwrap().offset(), 8);
        let mut res = ParameterPieces::default();
        assert_eq!(entry.get_addr_by_slot(1, 16, 16, &mut res), 4); // wastes slot 1 for alignment
        assert_eq!(res.address.unwrap().offset(), 8 + 16);
        let mut res = ParameterPieces::default();
        assert_eq!(entry.get_addr_by_slot(62, 8, 8, &mut res), 62);
        assert!(res.address.is_none());
        let mut res = ParameterPieces::default();
        assert_eq!(entry.get_addr_by_slot(0, 0, 4, &mut res), 0); // below minsize
        assert!(res.address.is_none());
    }

    #[test]
    fn is_equivalent_compares_all_state() {
        assert!(register_entry().is_equivalent(&register_entry()));
        assert!(!register_entry().is_equivalent(&stack_entry()));
    }

    #[test]
    fn order_within_group_allows_distinct_sizes_or_types() {
        let cspec = TestCompilerSpec::x86_64();
        let small = restore(r#"<pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>"#, &cspec, &[], 0).unwrap();
        let large = restore(r#"<pentry minsize="5" maxsize="8"><register name="RAX"/></pentry>"#, &cspec, &[], 0).unwrap();
        assert!(order_within_group(&small, &large).is_ok());
        assert!(order_within_group(&register_entry(), &register_entry()).is_err());
        let float = restore(
            r#"<pentry minsize="1" maxsize="8" storage="float"><register name="XMM0_Qa"/></pentry>"#,
            &cspec,
            &[],
            0,
        )
        .unwrap();
        assert!(order_within_group(&float, &register_entry()).is_ok());
        assert!(order_within_group(&register_entry(), &float).is_err());
    }

    #[test]
    fn from_parts_matches_restored_entry() {
        let parts = ParamEntryParts {
            minsize: 1,
            ..ParamEntryParts::new(stack_space(), 8, 500, 8, 2)
        };
        assert!(ParamEntry::from_parts(parts).is_equivalent(&stack_entry()));
        let _ = join_space();
    }

    struct RecordingEncoder {
        opened: Vec<&'static str>,
        ints: Vec<(&'static str, i64)>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ElementId) -> std::io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, _elem_id: crate::program::model::pcode::ElementId) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: crate::program::model::pcode::AttributeId, val: i64) -> std::io::Result<()> {
            self.ints.push((attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: crate::program::model::pcode::AttributeId, val: u64) -> std::io::Result<()> {
            self.ints.push((attrib_id.name, val as i64));
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _val: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _val: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _spc: &AddressSpace) -> std::io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _index: i32,
            _name: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::AttributeId, _opcode: i32) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_pentry_and_addr() {
        let mut enc = RecordingEncoder { opened: Vec::new(), ints: Vec::new() };
        stack_entry().encode(&mut enc).unwrap();
        assert_eq!(enc.opened, vec!["pentry", "addr"]);
        assert!(enc.ints.contains(&("minsize", 1)));
        assert!(enc.ints.contains(&("maxsize", 500)));
        assert!(enc.ints.contains(&("align", 8)));
    }
}
