use std::cell::Cell;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use crate::util::datastruct::NoSuchIndexException;
use crate::util::exception::AssertException;
use crate::util::map::{ValueStoragePage, ValueStoragePageIndex};
use crate::util::LongIterator;

/// Default number of bits used for the per-page address offset, mirroring
/// `ValueMap.DEFAULT_NUMBER_PAGE_BITS`.
pub const DEFAULT_NUMBER_PAGE_BITS: u32 = 12;
/// Minimum number of bits allowed for the per-page address offset, mirroring
/// `ValueMap.MIN_NUMBER_PAGE_BITS`.
pub const MIN_NUMBER_PAGE_BITS: u32 = 8;
/// Maximum number of bits allowed for the per-page address offset, mirroring
/// `ValueMap.MAX_NUMBER_PAGE_BITS`.
pub const MAX_NUMBER_PAGE_BITS: u32 = 15;

/// Clamps a requested page-bit count into `[MIN_NUMBER_PAGE_BITS, MAX_NUMBER_PAGE_BITS]`,
/// mirroring the clamping the `ValueMap(String, int, Class)` constructor performs. Intended for
/// implementors computing `num_page_bits`/`page_mask`/`page_size` in their own constructor.
pub fn clamp_num_page_bits(num_page_bits: u32) -> u32 {
    num_page_bits.clamp(MIN_NUMBER_PAGE_BITS, MAX_NUMBER_PAGE_BITS)
}

/// Computes the page mask for a given (already clamped) page-bit count, mirroring the
/// constructor's `pageMask = (-1L) >>> (64 - numPageBits)`.
pub fn compute_page_mask(num_page_bits: u32) -> i64 {
    ((-1i64) as u64 >> (64 - num_page_bits)) as i64
}

/// Computes the number of elements per page from the page mask, mirroring
/// `pageSize = (short) (pageMask + 1)`. Truncates like the Java narrowing cast (so, matching
/// the original, this wraps negative at `num_page_bits == MAX_NUMBER_PAGE_BITS`).
pub fn compute_page_size(page_mask: i64) -> i16 {
    (page_mask + 1) as i16
}

/// Base behavior for managing data values that are accessed by an ordered `i64` index key.
/// Specific data value types are determined by the implementor.
///
/// Cut to a trait to break a dependency cycle: concrete property maps (`IntValueMap`,
/// `ObjectValueMap`, ...) extend `ValueMap<T>` and are themselves depended on elsewhere, so
/// `ValueMap` cannot stay tied to one concrete page-storage implementation. Page storage (the
/// `Map<Long, ValueStoragePage<T>>` field in Java) is therefore left to implementors via
/// [`ValueMap::get_page`]/[`ValueMap::get_page_mut`]/[`ValueMap::get_or_create_page`]/
/// [`ValueMap::remove_page_storage`], with pages themselves referenced through `dyn
/// ValueStoragePage<T>` rather than a concrete storage-page type.
///
/// `getObjectClass()`'s `Class<T>` reflection accessor has no Rust equivalent (page
/// construction -- the only place Java threads it through -- is entirely up to implementors
/// here) and is therefore not part of this trait.
///
/// Port of `ghidra.util.map.ValueMap`.
pub trait ValueMap<T> {
    /// Returns the size (in bytes) of the data stored in this property set.
    fn get_data_size(&self) -> i32;

    /// Moves the property at `from` to `to`, as used by [`ValueMap::move_range`].
    fn move_index(&mut self, from: i64, to: i64);

    /// Writes the property value stored at `addr` to `out`.
    fn save_property(&self, out: &mut dyn Write, addr: i64) -> io::Result<()>;

    /// Reads a property value from `input` and stores it at `addr`.
    fn restore_property(&mut self, input: &mut dyn Read, addr: i64) -> io::Result<()>;

    /// Returns the name for this property manager.
    fn name(&self) -> &str;

    /// Number of bits from the index used as the page offset.
    fn num_page_bits(&self) -> u32;

    /// Mask for the page-offset bits (has a 1 bit for every bit that is part of the offset).
    fn page_mask(&self) -> i64;

    /// Max elements in each page.
    fn page_size(&self) -> i16;

    /// Number of properties currently stored.
    fn num_properties(&self) -> i32;

    /// Mutable access to the property count, for the default methods below to maintain.
    fn num_properties_mut(&mut self) -> &mut i32;

    /// Table of page IDs currently in use.
    fn page_index(&self) -> &ValueStoragePageIndex;

    /// Mutable access to the table of page IDs currently in use.
    fn page_index_mut(&mut self) -> &mut ValueStoragePageIndex;

    /// Returns the page with the given ID, if one has been created.
    fn get_page(&self, page_id: i64) -> Option<&dyn ValueStoragePage<T>>;

    /// Returns a mutable reference to the page with the given ID, if one has been created.
    fn get_page_mut(&mut self, page_id: i64) -> Option<&mut dyn ValueStoragePage<T>>;

    /// Returns the page with the given ID, creating (and indexing) it first if necessary.
    fn get_or_create_page(&mut self, page_id: i64) -> &mut dyn ValueStoragePage<T>;

    /// Removes the page with the given ID from storage only (not from [`ValueMap::page_index`]);
    /// used by the default [`ValueMap::remove_page`].
    fn remove_page_storage(&mut self, page_id: i64);

    // ---- default methods mirroring ValueMap's concrete Java methods ----

    /// Extract the page ID from the given index.
    fn get_page_id(&self, index: i64) -> i64 {
        ((index as u64) >> self.num_page_bits()) as i64
    }

    /// Extract the page offset from the given index.
    fn get_page_offset(&self, index: i64) -> i16 {
        (index & self.page_mask()) as i16
    }

    /// Create an index from the page ID and the offset within the page.
    fn get_index(&self, page_id: i64, offset: i16) -> i64 {
        (page_id << self.num_page_bits()) | (offset as i64)
    }

    /// Removes `page_id` from storage and from the page index.
    fn remove_page(&mut self, page_id: i64) {
        self.remove_page_storage(page_id);
        self.page_index_mut().remove(page_id);
    }

    /// Get the number of properties in the set.
    fn get_size(&self) -> i32 {
        self.num_properties()
    }

    /// Returns whether there is a property value at `index`.
    fn has_property(&self, index: i64) -> bool {
        match self.get_page(self.get_page_id(index)) {
            Some(page) => page.has_property(self.get_page_offset(index)),
            None => false,
        }
    }

    /// Given two indices, indicates whether there is an index in that range (inclusive) having
    /// the property.
    fn intersects(&self, start: i64, end: i64) -> bool {
        if self.has_property(start) {
            return true;
        }
        match self.get_next_property_index(start) {
            Ok(index) => index <= end,
            Err(_) => false,
        }
    }

    /// Removes the property on `page_id` at `offset`. If the page is now empty, removes it too.
    /// Returns `true` if a property value was removed.
    fn remove_from_page(&mut self, page_id: i64, offset: i16) -> bool {
        let outcome = self.get_page_mut(page_id).map(|page| (page.remove(offset), page.is_empty()));
        match outcome {
            Some((removed, is_empty)) => {
                if removed {
                    *self.num_properties_mut() -= 1;
                }
                if is_empty {
                    self.remove_page(page_id);
                }
                removed
            }
            None => false,
        }
    }

    /// Removes the property value at the given index. Returns `true` if a property value was
    /// removed, `false` otherwise.
    fn remove(&mut self, index: i64) -> bool {
        let page_id = self.get_page_id(index);
        let offset = self.get_page_offset(index);
        self.remove_from_page(page_id, offset)
    }

    /// Removes all property values within `[start, end]`. Returns `true` if any property value
    /// was removed.
    fn remove_range(&mut self, start: i64, end: i64) -> bool {
        let mut start = start;
        let mut status = false;

        while start <= end {
            let page_id = self.get_page_id(start);
            let offset = self.get_page_offset(start);

            if self.get_page(page_id).is_none() {
                let next_page_id = self.page_index().get_next(page_id);
                if next_page_id < 0 {
                    break;
                }
                start = next_page_id << self.num_page_bits();
                continue;
            }

            let page_size = self.page_size();
            if offset == 0 && (page_size as i64 + start) <= end {
                let removed_count = self.get_page(page_id).expect("checked above").get_size() as i32;
                *self.num_properties_mut() -= removed_count;
                self.remove_page(page_id);
                status = true;
                let next_page_id = self.page_index().get_next(page_id);
                start = next_page_id << self.num_page_bits();
            } else {
                let mut off = offset;
                while off < page_size && start <= end {
                    if self.remove_from_page(page_id, off) {
                        status = true;
                    }
                    off += 1;
                    start += 1;
                }
            }
        }

        status
    }

    /// Get the next index (exclusive of `index`) where a property value exists.
    fn get_next_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException> {
        let page_id = self.get_page_id(index);
        let offset = self.get_page_offset(index);

        if let Some(page) = self.get_page(page_id) {
            if let Some(next_offset) = page.get_next(offset) {
                return Ok(self.get_index(page_id, next_offset));
            }
        }

        let next_page_id = self.page_index().get_next(page_id);
        if next_page_id >= 0 {
            if let Some(page) = self.get_page(next_page_id) {
                return match page.get_first() {
                    Some(first_offset) => Ok(self.get_index(next_page_id, first_offset)),
                    None => panic!(
                        "{}",
                        AssertException::with_message(format!(
                            "Page ({next_page_id}) exists but there is no 'first' offset"
                        ))
                    ),
                };
            }
        }

        Err(NoSuchIndexException::new())
    }

    /// Get the previous index (exclusive of `index`) where a property value exists.
    fn get_previous_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException> {
        let page_id = self.get_page_id(index);
        let offset = self.get_page_offset(index);

        if let Some(page) = self.get_page(page_id) {
            if let Some(prev_offset) = page.get_previous(offset) {
                return Ok(self.get_index(page_id, prev_offset));
            }
        }

        let prev_page_id = self.page_index().get_previous(page_id);
        if prev_page_id >= 0 {
            if let Some(page) = self.get_page(prev_page_id) {
                return match page.get_last() {
                    Some(last_offset) => Ok(self.get_index(prev_page_id, last_offset)),
                    None => panic!(
                        "{}",
                        AssertException::with_message(format!(
                            "Page ({prev_page_id}) exists but there is no 'last' offset"
                        ))
                    ),
                };
            }
        }

        Err(NoSuchIndexException::new())
    }

    /// Get the first index where a property value exists.
    fn get_first_property_index(&self) -> Result<i64, NoSuchIndexException> {
        if self.has_property(0) {
            return Ok(0);
        }
        self.get_next_property_index(0)
    }

    /// Get the last index where a property value exists.
    fn get_last_property_index(&self) -> Result<i64, NoSuchIndexException> {
        if self.has_property(-1) {
            return Ok(-1);
        }
        self.get_previous_property_index(-1)
    }

    /// Moves the range of properties `[start, end]` to begin at `new_start`.
    ///
    /// Unlike the Java original -- which mutates while a live iterator walks the map -- this
    /// collects the source indexes up front (a pure query pass) and then applies the moves. The
    /// two passes are equivalent here because a source index is only ever read looking strictly
    /// "ahead" of the last-moved index (forward when shifting left, backward when shifting
    /// right), while every destination lands strictly "behind" it, so no move can affect a read
    /// that hasn't happened yet.
    fn move_range(&mut self, start: i64, end: i64, new_start: i64) {
        if new_start < start {
            let mut clear_size = end - start + 1;
            let offset = start - new_start;
            if offset < clear_size {
                clear_size = offset;
            }
            self.remove_range(new_start, new_start + clear_size - 1);

            let mut indexes = Vec::new();
            if self.has_property(start) {
                indexes.push(start);
            }
            let mut cursor = start;
            while let Ok(next) = self.get_next_property_index(cursor) {
                if next > end {
                    break;
                }
                indexes.push(next);
                cursor = next;
            }

            for index in indexes {
                self.move_index(index, index - offset);
            }
        } else {
            let mut clear_size = end - start + 1;
            let offset = new_start - start;
            if offset < clear_size {
                clear_size = offset;
            }
            if new_start > end {
                self.remove_range(new_start, new_start + clear_size - 1);
            } else {
                self.remove_range(end + 1, end + clear_size);
            }

            let mut indexes = Vec::new();
            let mut cursor = end + 1;
            while let Ok(prev) = self.get_previous_property_index(cursor) {
                if prev < start {
                    break;
                }
                indexes.push(prev);
                cursor = prev;
            }

            for index in indexes {
                self.move_index(index, index + offset);
            }
        }
    }

    /// Creates an iterator over all indexes with a property, within `[start, end]`.
    fn get_property_iterator_range(&self, start: i64, end: i64) -> ValueMapIter<'_, T, Self>
    where
        Self: Sized,
    {
        ValueMapIter::with_range(self, start, end, true)
    }

    /// Creates an iterator over all indexes with a property, within `[start, end]`. If
    /// `at_start` is `false`, the iterator walks backward from `end` instead of forward from
    /// `start`.
    fn get_property_iterator_range_at(&self, start: i64, end: i64, at_start: bool) -> ValueMapIter<'_, T, Self>
    where
        Self: Sized,
    {
        ValueMapIter::with_range(self, start, end, at_start)
    }

    /// Creates an iterator over all indexes with a property.
    fn get_property_iterator(&self) -> ValueMapIter<'_, T, Self>
    where
        Self: Sized,
    {
        ValueMapIter::unbounded(self, 0, true)
    }

    /// Creates an iterator over all indexes with a property, starting at `start`.
    fn get_property_iterator_from(&self, start: i64) -> ValueMapIter<'_, T, Self>
    where
        Self: Sized,
    {
        ValueMapIter::unbounded(self, start, true)
    }

    /// Creates an iterator over all indexes with a property, starting at `start`. If `before` is
    /// `true`, `start` will be the first index returned from a call to `next`; if `false`,
    /// `start` will be the first index returned from a call to `previous`.
    fn get_property_iterator_before(&self, start: i64, before: bool) -> ValueMapIter<'_, T, Self>
    where
        Self: Sized,
    {
        ValueMapIter::unbounded(self, start, before)
    }

    /// Saves all property values in `[start, end]` to `out`.
    fn save_properties(&self, out: &mut dyn Write, start: i64, end: i64) -> io::Result<()> {
        out.write_all(&start.to_be_bytes())?;
        out.write_all(&end.to_be_bytes())?;

        if self.has_property(start) {
            out.write_all(&[1])?;
            out.write_all(&start.to_be_bytes())?;
            self.save_property(out, start)?;
        }

        let mut index = start;
        while let Ok(next) = self.get_next_property_index(index) {
            if next > end {
                break;
            }
            out.write_all(&[1])?;
            out.write_all(&next.to_be_bytes())?;
            self.save_property(out, next)?;
            index = next;
        }

        out.write_all(&[0])
    }

    /// Restores all properties from `input`, first removing any existing properties in the
    /// restored range.
    fn restore_properties(&mut self, input: &mut dyn Read) -> io::Result<()> {
        let mut buf = [0u8; 8];
        input.read_exact(&mut buf)?;
        let start = i64::from_be_bytes(buf);
        input.read_exact(&mut buf)?;
        let end = i64::from_be_bytes(buf);
        self.remove_range(start, end);

        loop {
            let mut flag = [0u8; 1];
            input.read_exact(&mut flag)?;
            if flag[0] == 0 {
                break;
            }
            input.read_exact(&mut buf)?;
            let index = i64::from_be_bytes(buf);
            self.restore_property(input, index)?;
        }

        Ok(())
    }
}

/// Iterator over the indexes of a [`ValueMap`] that have a property value set.
///
/// A small, self-contained cursor rather than a reuse of
/// [`crate::util::map::LongIteratorImpl`], so that implementing [`ValueMap`] does not also
/// require satisfying the separate [`crate::util::seam_stubs::ValueMapLike`] placeholder that
/// exists only to unblock [`crate::util::map::LongIteratorImpl`]'s own cycle. The cursor logic
/// mirrors it exactly, driven through [`ValueMap::has_property`]/
/// [`ValueMap::get_next_property_index`]/[`ValueMap::get_previous_property_index`] instead.
///
/// Port of `ghidra.util.map.LongIteratorImpl`, specialized to a generic [`ValueMap`].
pub struct ValueMapIter<'a, T, M: ValueMap<T> + ?Sized> {
    map: &'a M,
    start: i64,
    end: i64,
    has_boundaries: bool,
    current: Cell<i64>,
    does_have_next: Cell<bool>,
    does_have_previous: Cell<bool>,
    _marker: PhantomData<T>,
}

impl<'a, T, M: ValueMap<T> + ?Sized> ValueMapIter<'a, T, M> {
    fn unbounded(map: &'a M, start: i64, before: bool) -> Self {
        let field_start = if before { start } else { start.wrapping_add(1) };
        let iter = Self {
            map,
            start: field_start,
            end: 0,
            has_boundaries: false,
            current: Cell::new(start),
            does_have_next: Cell::new(false),
            does_have_previous: Cell::new(false),
            _marker: PhantomData,
        };
        iter.init(before);
        iter
    }

    fn with_range(map: &'a M, start: i64, end: i64, at_start: bool) -> Self {
        let current = if at_start { start } else { end };
        let iter = Self {
            map,
            start,
            end,
            has_boundaries: true,
            current: Cell::new(current),
            does_have_next: Cell::new(false),
            does_have_previous: Cell::new(false),
            _marker: PhantomData,
        };
        iter.init(at_start);
        iter
    }

    fn find_next(&self) {
        if let Ok(next_index) = self.map.get_next_property_index(self.current.get()) {
            if self.has_boundaries && next_index > self.end {
                self.does_have_next.set(false);
                return;
            }
            self.current.set(next_index);
            self.does_have_next.set(true);
            self.does_have_previous.set(false);
        }
    }

    fn find_previous(&self) {
        if let Ok(prev_index) = self.map.get_previous_property_index(self.current.get()) {
            if self.has_boundaries && prev_index < self.start {
                self.does_have_previous.set(false);
                return;
            }
            self.current.set(prev_index);
            self.does_have_previous.set(true);
            self.does_have_next.set(false);
        }
    }

    fn init(&self, at_start: bool) {
        if self.map.has_property(self.current.get()) {
            if at_start {
                self.does_have_next.set(true);
            } else {
                self.does_have_previous.set(true);
            }
        }
    }
}

impl<'a, T, M: ValueMap<T> + ?Sized> LongIterator for ValueMapIter<'a, T, M> {
    fn has_next(&self) -> bool {
        if self.does_have_next.get() {
            return true;
        }
        self.find_next();
        self.does_have_next.get()
    }

    fn next(&mut self) -> i64 {
        if self.has_next() {
            self.does_have_next.set(false);
            self.does_have_previous.set(true);
            return self.current.get();
        }
        panic!("No more indexes.");
    }

    fn has_previous(&self) -> bool {
        if self.does_have_previous.get() {
            return true;
        }
        self.find_previous();
        self.does_have_previous.get()
    }

    fn previous(&mut self) -> i64 {
        if self.has_previous() {
            self.does_have_previous.set(false);
            self.does_have_next.set(true);
            return self.current.get();
        }
        panic!("No more indexes.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Minimal in-memory [`ValueStoragePage`] backing [`MockValueMap`] below: a page just
    /// tracks which offsets have a value and, for the "object" property family, what `i32` is
    /// stored there (the only family this smoke test exercises).
    #[derive(Default)]
    struct MockPage {
        values: std::collections::BTreeMap<i16, i32>,
    }

    impl ValueStoragePage<i32> for MockPage {
        fn get_next(&self, offset: i16) -> Option<i16> {
            self.values.range((std::ops::Bound::Excluded(offset), std::ops::Bound::Unbounded)).next().map(|(&k, _)| k)
        }
        fn get_previous(&self, offset: i16) -> Option<i16> {
            self.values.range(..offset).next_back().map(|(&k, _)| k)
        }
        fn get_first(&self) -> Option<i16> {
            self.values.keys().next().copied()
        }
        fn get_last(&self) -> Option<i16> {
            self.values.keys().next_back().copied()
        }
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn has_property(&self, offset: i16) -> bool {
            self.values.contains_key(&offset)
        }
        fn add_key(&mut self, key: i16) {
            self.values.entry(key).or_insert(0);
        }
        fn get_size(&self) -> usize {
            self.values.len()
        }
        fn remove(&mut self, offset: i16) -> bool {
            self.values.remove(&offset).is_some()
        }
        fn get_saveable_object(
            &self,
            _offset: i16,
        ) -> Result<Option<Box<dyn crate::util::saveable::Saveable>>, crate::util::map::TypeMismatchException> {
            Err(crate::util::map::TypeMismatchException::new())
        }
        fn add_saveable_object(&mut self, _offset: i16, _value: Box<dyn crate::util::saveable::Saveable>) {}
        fn get_object(&self, offset: i16) -> Option<i32> {
            self.values.get(&offset).copied()
        }
        fn add_object(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
        fn get_string(&self, _offset: i16) -> Option<String> {
            None
        }
        fn add_string(&mut self, _offset: i16, _value: String) {}
        fn get_int(&self, offset: i16) -> Result<i32, crate::util::exception::NoValueException> {
            self.values.get(&offset).copied().ok_or_else(crate::util::exception::NoValueException::new)
        }
        fn add_int(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
        fn get_long(&self, _offset: i16) -> Result<i64, crate::util::exception::NoValueException> {
            Err(crate::util::exception::NoValueException::new())
        }
        fn add_long(&mut self, _offset: i16, _value: i64) {}
        fn get_short(&self, _offset: i16) -> Result<i16, crate::util::exception::NoValueException> {
            Err(crate::util::exception::NoValueException::new())
        }
        fn add_short(&mut self, _offset: i16, _value: i16) {}
        fn get_byte(&self, _offset: i16) -> Result<i8, crate::util::exception::NoValueException> {
            Err(crate::util::exception::NoValueException::new())
        }
        fn add_byte(&mut self, _offset: i16, _value: i8) {}
    }

    /// Minimal [`ValueMap<i32>`] implementation, proving the trait is object-safe (usable
    /// behind `Box<dyn ValueMap<i32>>`) and that the default page-indexed algorithms behave
    /// correctly end to end.
    #[derive(Default)]
    struct MockValueMap {
        name: String,
        num_page_bits: u32,
        page_mask: i64,
        page_size: i16,
        num_properties: i32,
        page_index: ValueStoragePageIndex,
        pages: HashMap<i64, MockPage>,
        moves: Vec<(i64, i64)>,
    }

    impl MockValueMap {
        fn new(name: &str, num_page_bits: u32) -> Self {
            let num_page_bits = clamp_num_page_bits(num_page_bits);
            let page_mask = compute_page_mask(num_page_bits);
            Self {
                name: name.to_string(),
                num_page_bits,
                page_mask,
                page_size: compute_page_size(page_mask),
                ..Default::default()
            }
        }

        fn put(&mut self, index: i64, value: i32) {
            let page_id = self.get_page_id(index);
            let offset = self.get_page_offset(index);
            let page = self.get_or_create_page(page_id);
            let before = page.get_size();
            page.add_object(offset, value);
            let added = page.get_size() - before;
            self.num_properties += added as i32;
        }

        fn get(&self, index: i64) -> Option<i32> {
            let page = self.get_page(self.get_page_id(index))?;
            page.get_object(self.get_page_offset(index))
        }
    }

    impl ValueMap<i32> for MockValueMap {
        fn get_data_size(&self) -> i32 {
            4
        }

        fn move_index(&mut self, from: i64, to: i64) {
            self.moves.push((from, to));
            if let Some(value) = self.get(from) {
                self.remove(from);
                self.put(to, value);
            }
        }

        fn save_property(&self, out: &mut dyn Write, addr: i64) -> io::Result<()> {
            let value = self.get(addr).expect("caller only saves indexes that have a property");
            out.write_all(&value.to_be_bytes())
        }

        fn restore_property(&mut self, input: &mut dyn Read, addr: i64) -> io::Result<()> {
            let mut buf = [0u8; 4];
            input.read_exact(&mut buf)?;
            self.put(addr, i32::from_be_bytes(buf));
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn num_page_bits(&self) -> u32 {
            self.num_page_bits
        }

        fn page_mask(&self) -> i64 {
            self.page_mask
        }

        fn page_size(&self) -> i16 {
            self.page_size
        }

        fn num_properties(&self) -> i32 {
            self.num_properties
        }

        fn num_properties_mut(&mut self) -> &mut i32 {
            &mut self.num_properties
        }

        fn page_index(&self) -> &ValueStoragePageIndex {
            &self.page_index
        }

        fn page_index_mut(&mut self) -> &mut ValueStoragePageIndex {
            &mut self.page_index
        }

        fn get_page(&self, page_id: i64) -> Option<&dyn ValueStoragePage<i32>> {
            self.pages.get(&page_id).map(|p| p as &dyn ValueStoragePage<i32>)
        }

        fn get_page_mut(&mut self, page_id: i64) -> Option<&mut dyn ValueStoragePage<i32>> {
            self.pages.get_mut(&page_id).map(|p| p as &mut dyn ValueStoragePage<i32>)
        }

        fn get_or_create_page(&mut self, page_id: i64) -> &mut dyn ValueStoragePage<i32> {
            if !self.pages.contains_key(&page_id) {
                self.pages.insert(page_id, MockPage::default());
                self.page_index.add(page_id);
            }
            self.pages.get_mut(&page_id).unwrap()
        }

        fn remove_page_storage(&mut self, page_id: i64) {
            self.pages.remove(&page_id);
        }
    }

    fn boxed_map(name: &str) -> Box<dyn ValueMap<i32>> {
        Box::new(MockValueMap::new(name, DEFAULT_NUMBER_PAGE_BITS))
    }

    #[test]
    fn page_bit_helpers_clamp_and_compute() {
        assert_eq!(clamp_num_page_bits(4), MIN_NUMBER_PAGE_BITS);
        assert_eq!(clamp_num_page_bits(30), MAX_NUMBER_PAGE_BITS);
        assert_eq!(clamp_num_page_bits(10), 10);
        assert_eq!(compute_page_mask(12), 0xFFF);
        assert_eq!(compute_page_size(0xFFF), 4096);
    }

    #[test]
    fn put_and_has_property_round_trip() {
        let mut map = boxed_map("prop");
        assert_eq!(map.name(), "prop");
        assert!(!map.has_property(42));

        let mut concrete = MockValueMap::new("prop", DEFAULT_NUMBER_PAGE_BITS);
        concrete.put(42, 99);
        assert!(concrete.has_property(42));
        assert_eq!(concrete.get(42), Some(99));
        assert_eq!(concrete.get_size(), 1);
        let _ = map.get_data_size();
    }

    #[test]
    fn get_next_and_previous_property_index_cross_pages() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        let page_span = 1i64 << DEFAULT_NUMBER_PAGE_BITS;
        map.put(5, 1);
        map.put(page_span + 3, 2);

        assert_eq!(map.get_next_property_index(0), Ok(5));
        assert_eq!(map.get_next_property_index(5), Ok(page_span + 3));
        assert!(map.get_next_property_index(page_span + 3).is_err());

        assert_eq!(map.get_previous_property_index(page_span + 3), Ok(5));
        assert_eq!(map.get_previous_property_index(5), Err(NoSuchIndexException::new()));
    }

    #[test]
    fn first_and_last_property_index() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        assert!(map.get_first_property_index().is_err());

        map.put(10, 1);
        map.put(20, 2);
        assert_eq!(map.get_first_property_index(), Ok(10));
        assert_eq!(map.get_last_property_index(), Ok(20));
    }

    #[test]
    fn intersects_checks_inclusive_range() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(50, 1);
        assert!(map.intersects(0, 50));
        assert!(map.intersects(40, 60));
        assert!(!map.intersects(51, 100));
    }

    #[test]
    fn remove_clears_property_and_empties_page() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(7, 1);
        assert_eq!(map.get_size(), 1);
        assert!(map.remove(7));
        assert!(!map.remove(7));
        assert_eq!(map.get_size(), 0);
        assert!(!map.has_property(7));
        assert!(map.get_page(map.get_page_id(7)).is_none());
    }

    #[test]
    fn remove_range_spans_whole_and_partial_pages() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        let page_span = 1i64 << DEFAULT_NUMBER_PAGE_BITS;
        map.put(1, 1);
        map.put(page_span + 1, 2);
        map.put(page_span + 2, 3);
        map.put(2 * page_span + 1, 4);
        assert_eq!(map.get_size(), 4);

        assert!(map.remove_range(0, 2 * page_span));
        assert_eq!(map.get_size(), 1);
        assert!(!map.has_property(1));
        assert!(!map.has_property(page_span + 1));
        assert!(!map.has_property(page_span + 2));
        assert!(map.has_property(2 * page_span + 1));
    }

    #[test]
    fn move_range_shifts_properties_left() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(10, 100);
        map.put(12, 120);
        map.put(15, 150);

        map.move_range(10, 15, 0);

        assert!(!map.has_property(10));
        assert!(!map.has_property(12));
        assert!(!map.has_property(15));
        assert_eq!(map.get(0), Some(100));
        assert_eq!(map.get(2), Some(120));
        assert_eq!(map.get(5), Some(150));
        assert_eq!(map.get_size(), 3);
    }

    #[test]
    fn move_range_shifts_properties_right() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(0, 100);
        map.put(2, 120);
        map.put(5, 150);

        map.move_range(0, 5, 10);

        assert!(!map.has_property(0));
        assert!(!map.has_property(2));
        assert!(!map.has_property(5));
        assert_eq!(map.get(10), Some(100));
        assert_eq!(map.get(12), Some(120));
        assert_eq!(map.get(15), Some(150));
        assert_eq!(map.get_size(), 3);
    }

    #[test]
    fn property_iterator_walks_forward_and_backward() {
        let map = {
            let mut m = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
            m.put(2, 1);
            m.put(5, 1);
            m.put(9, 1);
            m
        };

        let mut it = map.get_property_iterator();
        assert!(it.has_next());
        assert_eq!(it.next(), 2);
        assert_eq!(it.next(), 5);
        assert_eq!(it.next(), 9);
        assert!(!it.has_next());
        assert_eq!(it.previous(), 9);
        assert_eq!(it.previous(), 5);

        let mut ranged = map.get_property_iterator_range(3, 9);
        assert_eq!(ranged.next(), 5);
        assert_eq!(ranged.next(), 9);
        assert!(!ranged.has_next());
    }

    #[test]
    fn save_and_restore_properties_round_trip() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(3, 30);
        map.put(7, 70);
        map.put(11, 110);

        let mut buf = Vec::new();
        map.save_properties(&mut buf, 0, 20).expect("save succeeds");

        let mut restored = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        let mut cursor = std::io::Cursor::new(buf);
        restored.restore_properties(&mut cursor).expect("restore succeeds");

        assert_eq!(restored.get_size(), 3);
        assert_eq!(restored.get(3), Some(30));
        assert_eq!(restored.get(7), Some(70));
        assert_eq!(restored.get(11), Some(110));
    }

    #[test]
    fn restore_properties_clears_existing_range_first() {
        let mut map = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        map.put(4, 40);

        let mut buf = Vec::new();
        // Empty range save: header only, no entries, terminator byte.
        let empty_source = MockValueMap::new("m", DEFAULT_NUMBER_PAGE_BITS);
        empty_source.save_properties(&mut buf, 0, 100).expect("save succeeds");

        let mut cursor = std::io::Cursor::new(buf);
        map.restore_properties(&mut cursor).expect("restore succeeds");

        assert_eq!(map.get_size(), 0);
        assert!(!map.has_property(4));
    }
}
