use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::storage_class::StorageClass;
use crate::program::model::pcode::{
    Encoder, Varnode, ATTRIB_ALIGN, ATTRIB_EXTENSION, ATTRIB_MAXSIZE, ATTRIB_MINSIZE,
    ATTRIB_STORAGE, ELEM_PENTRY,
};
use crate::program::model::pcode::address_xml::{AddressXml, DefaultAddressXml};
use crate::program::seam_stubs::ParameterPieces;
use crate::util::xml::xml_parse_exception::XmlParseException;

/// Describes a memory range (register, stack slot, or "join" of several pieces) that can be used
/// to store all or part of a single parameter, as one resource in a [`ParamListStandard`]'s
/// resource list.
///
/// In Java, `ParamEntry` is a concrete class whose behavior is entirely driven by private fields
/// (`flags`, `type`, `groupSet`, `spaceid`, `addressbase`, `size`, `minsize`, `alignment`,
/// `numslots`, `joinrec`) set up once by `restoreXml` and never mutated afterward. Since a Rust
/// trait has no fields, every private field becomes a defaulted accessor method here (mirroring
/// the pattern already used for
/// [`VariableStorage`](crate::program::seam_stubs::VariableStorage)), and the class's query
/// methods (`containedBy`, `intersects`, `justifiedContain`, `contains`, `getSlot`,
/// `getAddrBySlot`, `encode`, `isEquivalent`) become provided default methods implemented purely
/// in terms of those accessors. `restoreXml` and the private helpers it alone drives
/// (`resolveJoin`, `resolveOverlap`) are NOT provided: they construct a `ParamEntry` (and mutate
/// `groupSet`/`flags` while doing so) from an XML stream plus the not-yet-ported `AddressXML`
/// utility and a `List<ParamEntry>` of siblings, which needs a real constructor rather than
/// read-only accessors on a trait object. `getBasicTypeClass` (a static helper that only inspects
/// a `DataType`, not any `ParamEntry` instance) already lives on
/// [`param_list_standard::get_basic_type_class`](crate::program::model::lang::param_list_standard::get_basic_type_class).
///
/// Port of `ghidra.program.model.lang.ParamEntry`.
pub trait ParamEntry {
    /// The address space this entry's range lives in (`ParamEntry.spaceid`). Left required since
    /// there is no universally sensible placeholder address space.
    fn get_space(&self) -> Arc<AddressSpace>;

    /// The (first/primary) resource group this entry belongs to (`ParamEntry.groupSet[0]`, via
    /// `ParamEntry.getGroup()`).
    fn get_group(&self) -> i32 {
        0
    }

    /// All resource groups this entry belongs to (`ParamEntry.groupSet`, via
    /// `ParamEntry.getAllGroups()`).
    fn get_all_groups(&self) -> Vec<i32> {
        vec![self.get_group()]
    }

    /// The minimum size, in bytes, of data that can be stored here (`ParamEntry.minsize`, via
    /// `ParamEntry.getMinSize()`).
    fn get_min_size(&self) -> i32 {
        0
    }

    /// The maximum size, in bytes, of the whole memory range (`ParamEntry.size`, via
    /// `ParamEntry.getSize()`).
    fn get_size(&self) -> i32 {
        0
    }

    /// The byte alignment of consecutive slots, or 0 if this entry is a single "exclusion" slot
    /// (`ParamEntry.alignment`, via `ParamEntry.getAlign()`).
    fn get_align(&self) -> i32 {
        0
    }

    /// The starting offset, within [`get_space`](Self::get_space), of the range
    /// (`ParamEntry.addressbase`, via `ParamEntry.getAddressBase()`).
    fn get_address_base(&self) -> i64 {
        0
    }

    /// The restriction on data-type this entry can match (`ParamEntry.type`, via
    /// `ParamEntry.getType()`).
    fn get_type(&self) -> StorageClass {
        StorageClass::General
    }

    /// The (maximum) number of slots that can store separate parameters (`ParamEntry.numslots`).
    /// Has no direct Java getter; needed here (unlike the rest of this trait, which was promoted
    /// from the pre-existing `ParamEntryLike` placeholder) to implement
    /// [`get_slot`](Self::get_slot) and [`get_addr_by_slot_justified`](Self::get_addr_by_slot_justified).
    fn num_slots(&self) -> i32 {
        1
    }

    /// True if slots from the stack section are allocated in reverse order
    /// (`ParamEntry.flags & REVERSE_STACK`, via `ParamEntry.isReverseStack()`).
    fn is_reverse_stack(&self) -> bool {
        false
    }

    /// True if this entry is grouped with other entries (`ParamEntry.flags & IS_GROUPED`, via
    /// `ParamEntry.isGrouped()`).
    fn is_grouped(&self) -> bool {
        false
    }

    /// True if this entry overlaps an earlier entry (`ParamEntry.flags & OVERLAPPING`, via
    /// `ParamEntry.isOverlap()`).
    fn is_overlap(&self) -> bool {
        false
    }

    /// True if values in this container are interpreted as big endian
    /// (`ParamEntry.flags & IS_BIG_ENDIAN`, via `ParamEntry.isBigEndian()`).
    fn is_big_endian(&self) -> bool {
        false
    }

    /// True if big-endian values are nonetheless left justified within their slot
    /// (`ParamEntry.flags & FORCE_LEFT_JUSTIFY`). Has no public Java getter (only the derived
    /// [`is_left_justified`](Self::is_left_justified) is exposed there, via the private
    /// `isLeftJustified()`); exposed here since it is one of the private flags
    /// [`get_addr_by_slot_justified`](Self::get_addr_by_slot_justified)'s default caller and
    /// [`justified_contain`](Self::justified_contain) need.
    fn is_force_left_justify(&self) -> bool {
        false
    }

    /// True if values below the max size are assumed sign extended
    /// (`ParamEntry.flags & SMALLSIZE_SEXT`). Has no public Java getter; exposed here (like
    /// [`is_force_left_justify`](Self::is_force_left_justify)) since [`encode`](Self::encode)
    /// needs it.
    fn is_sign_extend(&self) -> bool {
        false
    }

    /// True if values below the max size are assumed zero extended
    /// (`ParamEntry.flags & SMALLSIZE_ZEXT`). See [`is_sign_extend`](Self::is_sign_extend).
    fn is_zero_extend(&self) -> bool {
        false
    }

    /// True if values below the max size are extended based on integer type
    /// (`ParamEntry.flags & SMALLSIZE_INTTYPE`). See [`is_sign_extend`](Self::is_sign_extend).
    fn is_int_type_extend(&self) -> bool {
        false
    }

    /// True if values smaller than the max size are floating-point extended to full size
    /// (`ParamEntry.flags & SMALLSIZE_FLOAT`). See [`is_sign_extend`](Self::is_sign_extend); also
    /// drives a special case in [`get_addr_by_slot_justified`](Self::get_addr_by_slot_justified).
    fn is_float_extend(&self) -> bool {
        false
    }

    /// If non-`None`, the separate address ranges being bonded together in the "join" space that
    /// this entry represents (`ParamEntry.joinrec`, via the private `getJoinPieces` and the
    /// class-internal reads of `joinrec` in `intersects`/`justifiedContain`/`contains`).
    fn get_join_record(&self) -> Option<&[Varnode]> {
        None
    }

    /// True if this is a single, non-aligned "exclusion" slot rather than one of several aligned
    /// slots (`ParamEntry.isExclusion()`, i.e. `alignment == 0`).
    fn is_exclusion(&self) -> bool {
        self.get_align() == 0
    }

    /// True if data smaller than this entry's slot is left-justified within it (the private
    /// `ParamEntry.isLeftJustified()`).
    fn is_left_justified(&self) -> bool {
        !self.is_big_endian() || self.is_force_left_justify()
    }

    /// Collect pieces from the join list, in endian order, until the given size is covered. The
    /// last piece is trimmed to match the size exactly. Returns `None` if the size is too big to
    /// be covered by this entry, or if this entry has no join record.
    ///
    /// Port of the private `ParamEntry.getJoinPieces`.
    fn get_join_pieces_for_size(&self, sz: i32) -> Option<Vec<Varnode>> {
        let joinrec = self.get_join_record()?;
        let mut num: usize = 0;
        let first: usize;
        let replace: usize;
        let mut vn: Option<Varnode> = None;
        let mut remaining = sz;

        if self.is_big_endian() {
            while remaining > 0 {
                if num >= joinrec.len() {
                    return None;
                }
                let v = joinrec[num].clone();
                if v.get_size() > remaining {
                    vn = Some(v);
                    num += 1;
                    break;
                }
                remaining -= v.get_size();
                vn = Some(v);
                num += 1;
            }
            first = 0;
            replace = num.wrapping_sub(1);
        } else {
            while remaining > 0 {
                if num >= joinrec.len() {
                    return None;
                }
                let v = joinrec[joinrec.len() - 1 - num].clone();
                if v.get_size() > remaining {
                    vn = Some(v);
                    num += 1;
                    break;
                }
                remaining -= v.get_size();
                vn = Some(v);
                num += 1;
            }
            first = joinrec.len() - num;
            replace = first;
        }

        if remaining == 0 && num == joinrec.len() {
            return Some(joinrec.to_vec());
        }

        let mut res: Vec<Varnode> = (0..num).map(|i| joinrec[first + i].clone()).collect();
        if remaining > 0 {
            if let Some(v) = vn {
                res[replace] = Varnode::new(v.get_address().clone(), remaining);
            }
        }
        Some(res)
    }

    /// Is this entry, as a memory range, contained by the given memory range.
    ///
    /// Port of `ParamEntry.containedBy`.
    fn contained_by(&self, addr: &Address, sz: i32) -> bool {
        if self.get_space().as_ref() != addr.space().as_ref() {
            return false;
        }
        let addressbase = self.get_address_base();
        if (addressbase as u64) < (addr.offset() as u64) {
            return false;
        }
        let range_end = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
        let this_end = addressbase
            .wrapping_add(self.get_size() as i64)
            .wrapping_sub(1);
        (this_end as u64) <= (range_end as u64)
    }

    /// Does this entry intersect the given range in some way.
    ///
    /// Port of `ParamEntry.intersects`.
    fn intersects(&self, addr: &Address, sz: i32) -> bool {
        if let Some(joinrec) = self.get_join_record() {
            let rangeend = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
            for vn in joinrec {
                if addr.space().space_id() != vn.get_space_id() {
                    continue;
                }
                let vnend = vn
                    .get_offset()
                    .wrapping_add(vn.get_size() as i64)
                    .wrapping_sub(1);
                if (addr.offset() as u64) < (vn.get_offset() as u64)
                    && (rangeend as u64) < (vnend as u64)
                {
                    continue;
                }
                if (addr.offset() as u64) > (vn.get_offset() as u64)
                    && (rangeend as u64) > (vnend as u64)
                {
                    continue;
                }
                return true;
            }
        }
        if self.get_space().space_id() != addr.space().space_id() {
            return false;
        }
        let rangeend = addr.offset().wrapping_add(sz as i64).wrapping_sub(1);
        let addressbase = self.get_address_base();
        let thisend = addressbase
            .wrapping_add(self.get_size() as i64)
            .wrapping_sub(1);
        if (addr.offset() as u64) < (addressbase as u64) && (rangeend as u64) < (thisend as u64) {
            return false;
        }
        if (addr.offset() as u64) > (addressbase as u64) && (rangeend as u64) > (thisend as u64) {
            return false;
        }
        true
    }

    /// Return -1 if `(addr, sz)` is not properly, endian-aware contained in this entry.
    /// Otherwise, return the endian aware offset of `(addr, sz)` within this entry.
    ///
    /// Port of `ParamEntry.justifiedContain`.
    fn justified_contain(&self, addr: &Address, sz: i32) -> i32 {
        if let Some(joinrec) = self.get_join_record() {
            let mut res = 0i32;
            for vdata in joinrec.iter().rev() {
                let cur = justified_contain_address(
                    vdata.get_address().space(),
                    vdata.get_address().offset(),
                    vdata.get_size(),
                    addr.space(),
                    addr.offset(),
                    sz,
                    false,
                    self.is_big_endian(),
                );
                if cur < 0 {
                    res += vdata.get_size();
                } else {
                    return res + cur;
                }
            }
            return -1;
        }
        if self.get_align() == 0 {
            return justified_contain_address(
                &self.get_space(),
                self.get_address_base(),
                self.get_size(),
                addr.space(),
                addr.offset(),
                sz,
                self.is_force_left_justify(),
                self.is_big_endian(),
            );
        }
        if self.get_space().as_ref() != addr.space().as_ref() {
            return -1;
        }
        let addressbase = self.get_address_base();
        let startaddr = addr.offset();
        if (startaddr as u64) < (addressbase as u64) {
            return -1;
        }
        let endaddr = startaddr.wrapping_add(sz as i64).wrapping_sub(1);
        if (endaddr as u64) < (startaddr as u64) {
            return -1; // Don't allow wrap around
        }
        let this_last = addressbase
            .wrapping_add(self.get_size() as i64)
            .wrapping_sub(1);
        if (this_last as u64) < (endaddr as u64) {
            return -1;
        }
        let startaddr = startaddr - addressbase;
        let endaddr = endaddr - addressbase;
        let align = self.get_align() as i64;
        if !self.is_left_justified() {
            // For right justified (big endian), endaddr must be aligned
            let res = ((endaddr + 1) % align) as i32;
            if res == 0 {
                return 0;
            }
            return (align as i32) - res;
        }
        (startaddr % align) as i32
    }

    /// Does this entry contain another entry (as a subpiece).
    ///
    /// Port of `ParamEntry.contains`.
    fn contains(&self, other_entry: &dyn ParamEntry) -> bool {
        if other_entry.get_join_record().is_some() {
            return false; // Assume a join entry cannot be contained
        }
        match self.get_join_record() {
            None => {
                let addr = Address::new(self.get_space(), self.get_address_base());
                other_entry.contained_by(&addr, self.get_size())
            }
            Some(joinrec) => joinrec
                .iter()
                .any(|vn| other_entry.contained_by(vn.get_address(), vn.get_size())),
        }
    }

    /// Assuming the address is contained in this entry and we -skip- to a certain byte, return
    /// the slot associated with that byte.
    ///
    /// Port of `ParamEntry.getSlot`.
    fn get_slot(&self, addr: &Address, skip: i32) -> i32 {
        let mut res = self.get_group();
        let align = self.get_align();
        if align != 0 {
            let diff = addr.offset() + skip as i64 - self.get_address_base();
            let baseslot = (diff / align as i64) as i32;
            if self.is_reverse_stack() {
                res += (self.num_slots() - 1) - baseslot;
            } else {
                res += baseslot;
            }
        } else if skip != 0 {
            let groups = self.get_all_groups();
            res = *groups.last().unwrap_or(&res);
        }
        res
    }

    /// Assign the storage address when allocating something of size `sz` assuming `slot_num`
    /// slots have already been assigned, using this entry's own left/right justification.
    ///
    /// Port of the 4-argument `ParamEntry.getAddrBySlot`.
    fn get_addr_by_slot(
        &self,
        slot_num: i32,
        sz: i32,
        type_align: i32,
        res: &mut ParameterPieces,
    ) -> i32 {
        self.get_addr_by_slot_justified(slot_num, sz, type_align, res, !self.is_left_justified())
    }

    /// Assign the storage address when allocating something of size `sz` assuming `slot_num`
    /// slots have already been assigned. Sets `res.address` to `None` if `sz` is too small or if
    /// there are not enough slots left.
    ///
    /// Port of the 5-argument `ParamEntry.getAddrBySlot`.
    fn get_addr_by_slot_justified(
        &self,
        mut slot_num: i32,
        sz: i32,
        type_align: i32,
        res: &mut ParameterPieces,
        justify_right: bool,
    ) -> i32 {
        res.address = None;
        if sz < self.get_min_size() {
            return slot_num;
        }
        let align = self.get_align();
        let spaceused: i32;
        let mut offset: i64;
        if align == 0 {
            // Not an aligned entry (allowing multiple slots)
            if slot_num != 0 {
                return slot_num; // Can only allocate slot 0
            }
            if sz > self.get_size() {
                return slot_num; // Check on maximum size
            }
            offset = self.get_address_base();
            spaceused = self.get_size();
            if self.is_float_extend() && sz != self.get_size() {
                let addr = Address::new(self.get_space(), offset);
                res.join_pieces = Some(vec![Varnode::new(addr.clone(), self.get_size())]);
                res.address = Some(addr);
                return slot_num;
            }
        } else {
            if type_align > align {
                let tmp = (slot_num * align) % type_align;
                if tmp != 0 {
                    slot_num += (type_align - tmp) / align;
                }
            }
            let mut slotsused = sz / align; // How many slots does a -sz- byte object need
            if sz % align != 0 {
                slotsused += 1;
            }
            if slot_num + slotsused > self.num_slots() {
                return slot_num;
            }
            spaceused = slotsused * align;
            let index = if self.is_reverse_stack() {
                self.num_slots() - slot_num - slotsused
            } else {
                slot_num
            };
            offset = self.get_address_base() + (index as i64) * (align as i64);
            slot_num += slotsused; // Inform caller of number of slots used
        }
        if justify_right {
            offset += (spaceused - sz) as i64;
        }
        let addr = Address::new(self.get_space(), offset);
        if addr.space().space_type() == AddressSpaceType::Join {
            res.join_pieces = self.get_join_pieces_for_size(sz);
        }
        res.address = Some(addr);
        slot_num
    }

    /// Encode this entry to the stream as a `<pentry>` element.
    ///
    /// Port of `ParamEntry.encode`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        encoder.open_element(ELEM_PENTRY)?;
        encoder.write_signed_integer(ATTRIB_MINSIZE, self.get_min_size() as i64)?;
        encoder.write_signed_integer(ATTRIB_MAXSIZE, self.get_size() as i64)?;
        if self.get_align() != 0 {
            encoder.write_signed_integer(ATTRIB_ALIGN, self.get_align() as i64)?;
        }
        if self.get_type() != StorageClass::General {
            encoder.write_string(ATTRIB_STORAGE, &self.get_type().to_string())?;
        }
        let ext_string = if self.is_sign_extend() {
            Some("sign")
        } else if self.is_zero_extend() {
            Some("zero")
        } else if self.is_int_type_extend() {
            Some("inttype")
        } else if self.is_float_extend() {
            Some("float")
        } else {
            None
        };
        if let Some(ext) = ext_string {
            encoder.write_string(ATTRIB_EXTENSION, ext)?;
        }
        let address_size = match self.get_join_record() {
            // Treat as unsized address with no size
            None => DefaultAddressXml::new(self.get_space(), self.get_address_base(), 0),
            Some(pieces) => DefaultAddressXml::with_join(
                self.get_space(),
                self.get_address_base(),
                self.get_size(),
                pieces.to_vec(),
            ),
        };
        address_size.encode(encoder)?;
        encoder.close_element(ELEM_PENTRY)?;
        Ok(())
    }

    /// Determine if this entry is equivalent to another instance.
    ///
    /// Port of `ParamEntry.isEquivalent`.
    fn is_equivalent(&self, obj: &dyn ParamEntry) -> bool {
        if self.get_space().as_ref() != obj.get_space().as_ref()
            || self.get_address_base() != obj.get_address_base()
        {
            return false;
        }
        if self.get_size() != obj.get_size()
            || self.get_min_size() != obj.get_min_size()
            || self.get_align() != obj.get_align()
        {
            return false;
        }
        if self.get_type() != obj.get_type() {
            return false;
        }
        if self.is_force_left_justify() != obj.is_force_left_justify()
            || self.is_reverse_stack() != obj.is_reverse_stack()
            || self.is_zero_extend() != obj.is_zero_extend()
            || self.is_sign_extend() != obj.is_sign_extend()
            || self.is_big_endian() != obj.is_big_endian()
            || self.is_int_type_extend() != obj.is_int_type_extend()
            || self.is_float_extend() != obj.is_float_extend()
            || self.is_grouped() != obj.is_grouped()
            || self.is_overlap() != obj.is_overlap()
        {
            return false;
        }
        if self.num_slots() != obj.num_slots() {
            return false;
        }
        if self.get_all_groups() != obj.get_all_groups() {
            return false;
        }
        match (self.get_join_record(), obj.get_join_record()) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.len() == b.len()
                    && a.iter().zip(b.iter()).all(|(x, y)| {
                        x.get_space_id() == y.get_space_id()
                            && x.get_offset() == y.get_offset()
                            && x.get_size() == y.get_size()
                    })
            }
            _ => false,
        }
    }
}

/// Return -1 if `(offset2, sz2)` is not properly contained in `(offset1, sz1)`. If it is
/// contained, return the endian aware offset of `(offset2, sz2)`: i.e. if the least significant
/// byte of the second range falls on the least significant byte of the first range, return 0. If
/// it intersects the second least significant, return 1, etc.
///
/// Port of the static `ParamEntry.justifiedContainAddress`.
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
        return (off1 - off2) as i32;
    }
    (offset2 - offset1) as i32
}

/// `ParamEntry`s within a group must be distinguishable by size or by type.
///
/// Port of the static `ParamEntry.orderWithinGroup`.
///
/// # Errors
/// Returns an error if the pair is not distinguishable.
pub fn order_within_group(
    entry1: &dyn ParamEntry,
    entry2: &dyn ParamEntry,
) -> Result<(), XmlParseException> {
    if entry2.get_min_size() > entry1.get_size() || entry1.get_min_size() > entry2.get_size() {
        return Ok(());
    }
    if entry1.get_type() != entry2.get_type() {
        if entry1.get_type() == StorageClass::General {
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
    use crate::program::model::address::AddressSpaceType;

    #[derive(Clone)]
    struct MockParamEntry {
        space: Arc<AddressSpace>,
        group: i32,
        min_size: i32,
        size: i32,
        align: i32,
        addressbase: i64,
        numslots: i32,
        ty: StorageClass,
        reverse_stack: bool,
        big_endian: bool,
        join: Option<Vec<Varnode>>,
    }

    impl ParamEntry for MockParamEntry {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
        fn get_group(&self) -> i32 {
            self.group
        }
        fn get_min_size(&self) -> i32 {
            self.min_size
        }
        fn get_size(&self) -> i32 {
            self.size
        }
        fn get_align(&self) -> i32 {
            self.align
        }
        fn get_address_base(&self) -> i64 {
            self.addressbase
        }
        fn get_type(&self) -> StorageClass {
            self.ty
        }
        fn num_slots(&self) -> i32 {
            self.numslots
        }
        fn is_reverse_stack(&self) -> bool {
            self.reverse_stack
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_join_record(&self) -> Option<&[Varnode]> {
            self.join.as_deref()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn register_entry() -> MockParamEntry {
        MockParamEntry {
            space: ram_space(),
            group: 0,
            min_size: 1,
            size: 4,
            align: 4,
            addressbase: 0x1000,
            numslots: 1,
            ty: StorageClass::General,
            reverse_stack: false,
            big_endian: false,
            join: None,
        }
    }

    fn stack_entry() -> MockParamEntry {
        MockParamEntry {
            space: ram_space(),
            group: 2,
            min_size: 1,
            size: 4,
            align: 4,
            addressbase: 0x2000,
            numslots: 8,
            ty: StorageClass::General,
            reverse_stack: false,
            big_endian: false,
            join: None,
        }
    }

    #[test]
    fn contained_by_checks_space_and_range() {
        let entry = register_entry();
        let addr = Address::new(entry.space.clone(), 0x1000);
        assert!(entry.contained_by(&addr, 4)); // exact match
        assert!(entry.contained_by(&addr, 8)); // requested range is bigger, still covers entry

        let too_small = Address::new(entry.space.clone(), 0x1002);
        assert!(!entry.contained_by(&too_small, 4)); // starts after entry's base

        let other_space = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let wrong_space = Address::new(other_space, 0x1000);
        assert!(!entry.contained_by(&wrong_space, 4));
    }

    #[test]
    fn justified_contain_little_endian_offset_within_slot() {
        let entry = register_entry();
        let addr = Address::new(entry.space.clone(), 0x1000);
        assert_eq!(entry.justified_contain(&addr, 4), 0);

        let miss = Address::new(entry.space.clone(), 0x3000);
        assert_eq!(entry.justified_contain(&miss, 4), -1);
    }

    #[test]
    fn contains_checks_subpiece() {
        let outer = stack_entry();
        let inner = MockParamEntry {
            addressbase: 0x2000,
            size: 2,
            ..stack_entry()
        };
        assert!(outer.contains(&inner));

        let disjoint = MockParamEntry {
            addressbase: 0x5000,
            ..stack_entry()
        };
        assert!(!outer.contains(&disjoint));
    }

    #[test]
    fn get_slot_advances_with_aligned_offset() {
        let entry = stack_entry();
        let base = Address::new(entry.space.clone(), 0x2000);
        assert_eq!(entry.get_slot(&base, 0), 2); // group + 0 slots in
        let next = Address::new(entry.space.clone(), 0x2004);
        assert_eq!(entry.get_slot(&next, 0), 3); // one slot further in
    }

    #[test]
    fn get_addr_by_slot_allocates_sequential_slots_and_stops_when_full() {
        let entry = stack_entry();
        let mut res = ParameterPieces::default();

        let next_slot = entry.get_addr_by_slot(0, 4, 4, &mut res);
        assert_eq!(next_slot, 1);
        assert_eq!(res.address.unwrap().offset(), 0x2000);

        let mut res2 = ParameterPieces::default();
        let next_slot2 = entry.get_addr_by_slot(1, 4, 4, &mut res2);
        assert_eq!(next_slot2, 2);
        assert_eq!(res2.address.unwrap().offset(), 0x2004);

        // Only 8 slots total; asking to allocate at slot 8 leaves no room.
        let mut res3 = ParameterPieces::default();
        let next_slot3 = entry.get_addr_by_slot(8, 4, 4, &mut res3);
        assert_eq!(next_slot3, 8);
        assert!(res3.address.is_none());
    }

    #[test]
    fn get_addr_by_slot_rejects_undersized_request() {
        let entry = stack_entry();
        let mut res = ParameterPieces::default();
        let next_slot = entry.get_addr_by_slot(0, 0, 4, &mut res);
        assert_eq!(next_slot, 0);
        assert!(res.address.is_none());
    }

    #[test]
    fn is_equivalent_compares_all_observable_state() {
        let a = stack_entry();
        let b = stack_entry();
        assert!(a.is_equivalent(&b));

        let different_size = MockParamEntry { size: 8, ..stack_entry() };
        assert!(!a.is_equivalent(&different_size));
    }

    #[test]
    fn order_within_group_allows_distinct_sizes_but_rejects_overlap() {
        let small = MockParamEntry { min_size: 1, size: 2, ..register_entry() };
        let large = MockParamEntry { min_size: 4, size: 8, ..register_entry() };
        assert!(order_within_group(&small, &large).is_ok());

        let overlap_a = MockParamEntry { min_size: 1, size: 4, ..register_entry() };
        let overlap_b = MockParamEntry { min_size: 1, size: 4, ..register_entry() };
        assert!(order_within_group(&overlap_a, &overlap_b).is_err());
    }

    struct MockEncoder {
        opened: Vec<&'static str>,
    }

    impl Encoder for MockEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(
            &mut self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: bool,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: i64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: u64,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _val: &str,
        ) -> std::io::Result<()> {
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
        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _spc: &AddressSpace,
        ) -> std::io::Result<()> {
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
        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::AttributeId,
            _opcode: i32,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_pentry_and_addr_elements() {
        let entry = register_entry();
        let mut encoder = MockEncoder { opened: Vec::new() };
        entry.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["pentry", "addr"]);
    }

    #[test]
    fn get_join_pieces_for_size_trims_most_significant_piece_for_big_endian() {
        let space = ram_space();
        let piece0 = Varnode::new(Address::new(space.clone(), 0x100), 4); // most significant
        let piece1 = Varnode::new(Address::new(space.clone(), 0x200), 4); // least significant
        let entry = MockParamEntry {
            join: Some(vec![piece0, piece1]),
            big_endian: true,
            ..register_entry()
        };

        // Requesting fewer bytes than the whole join trims the most significant piece down.
        let pieces = entry.get_join_pieces_for_size(2).unwrap();
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].get_size(), 2);
        assert_eq!(pieces[0].get_address().offset(), 0x100);

        // Requesting more than the whole join record covers returns None.
        assert!(entry.get_join_pieces_for_size(100).is_none());

        // Requesting exactly the full size returns the original pieces untouched.
        let full = entry.get_join_pieces_for_size(8).unwrap();
        assert_eq!(full.len(), 2);
        assert_eq!(full[0].get_address().offset(), 0x100);
        assert_eq!(full[1].get_address().offset(), 0x200);
    }

    #[test]
    fn usable_as_trait_object() {
        let entry: Box<dyn ParamEntry> = Box::new(register_entry());
        assert_eq!(entry.get_group(), 0);
        assert!(entry.is_exclusion() == false); // align is nonzero here
        assert_eq!(entry.get_all_groups(), vec![0]);
    }
}
