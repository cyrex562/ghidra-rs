//! A sparse byte array characterized by contiguous dense regions.
//!
//! Port of `ghidra.generic.util.datastruct.SemisparseByteArray`.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::generic::ulong_span::{self, Impl as Span, ULongSpan};
use crate::util::MathUtilities;

/// The size of blocks used internally to store array values.
pub const BLOCK_SIZE: usize = 0x1000;

/// A sparse byte array characterized by contiguous dense regions.
///
/// Notionally, the array is 2 to the power 64 bytes in size. Only the initialized values are
/// actually stored. Uninitialized indices are assumed to have the value 0. Naturally, this
/// implementation works best when the array is largely uninitialized. For efficient use, isolated
/// initialized values should be avoided. Rather, an entire range should be initialized at the same
/// time.
///
/// On a number line, the initialized indices of a semisparse array might be depicted:
///
/// ```text
/// -----   --------- - ------         ---
/// ```
///
/// In contrast, the same for a sparse array might be depicted:
///
/// ```text
/// -    --  -  - -    ---     --     -         -
/// ```
///
/// This implementation is well-suited for memory caches where the memory is accessed by reading
/// ranges instead of individual bytes. Because consecutive reads and writes tend to occur in a
/// common locality, caches using a semisparse array may perform well.
///
/// This implementation is also thread-safe (every operation locks an internal mutex covering both
/// the blocks and the defined-span tracking). Any thread needing exclusive access for multiple
/// reads and/or writes, e.g., to implement a compare-and-set operation, must apply additional
/// synchronization, exactly as in Java.
///
/// # Divergences from Java
///
/// * **Sharing.** Java instances are plain mutable objects; callers share one by sharing the
///   object reference and rely on `synchronized` for safety. [`SemisparseByteArray`] is `Clone`,
///   and cloning shares the same backing store (an `Arc<Mutex<Inner>>>`) rather than copying it --
///   the Rust equivalent of aliasing a Java reference. Use [`fork`](Self::fork) for an independent
///   deep copy, matching Java's `fork()`.
/// * **`defined`.** Java backs the "which offsets are initialized" tracking with a
///   `MutableULongSpanSet` (`DefaultULongSpanSet`), a general-purpose interval-set type of its
///   own. Neither `ULongSpanSet` nor `DefaultULongSpanSet` has been ported; this struct's private
///   `DefinedSpans` implements only the handful of set operations this class actually needs
///   (add, clear, contains, encloses, complement, span-containing, iteration), backed by a
///   sorted `Vec` of disjoint, non-adjacent [`Span`]s. Java's `getInitialized`/`getUninitialized`
///   return a `ULongSpanSet`; since every real caller only ever iterates the result, a `Vec<Span>`
///   stands in for it here, matching the crate's existing convention for spans returned from spot
///   queries (see [`ULongSpan`]).
/// * **`putAll`.** Java's `putAll` is `synchronized` on `this` for its entire body, while it reads
///   `from`'s fields directly without separately synchronizing on `from` -- relying only on Java
///   monitors being reentrant (so `arr.putAll(arr)` doesn't deadlock) for safety. Rust's
///   `std::sync::Mutex` is not reentrant, so holding a lock on `self` for the whole method while
///   nested calls try to relock `self` would deadlock on `arr.put_all(&arr)`. This port instead
///   takes only short-lived, per-call locks (mirroring every other method here), which avoids that
///   hazard entirely rather than reproducing it -- Java's own docs already disclaim any atomicity
///   guarantee across multiple operations, so this doesn't change the documented contract.
#[derive(Clone)]
pub struct SemisparseByteArray {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    blocks: HashMap<u64, Vec<u8>>,
    defined: DefinedSpans,
}

impl SemisparseByteArray {
    /// Mirrors `new SemisparseByteArray()`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                blocks: HashMap::new(),
                defined: DefinedSpans::new(),
            })),
        }
    }

    /// An independent deep copy of this array.
    ///
    /// Mirrors `SemisparseByteArray.fork()`.
    pub fn fork(&self) -> Self {
        let inner = self.inner.lock().unwrap();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                blocks: inner.blocks.clone(),
                defined: inner.defined.clone(),
            })),
        }
    }

    /// Clear the array.
    ///
    /// All indices will be uninitialized after this call, just as it was immediately after
    /// construction.
    ///
    /// Mirrors `SemisparseByteArray.clear()`.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.defined.clear();
        inner.blocks.clear();
    }

    /// Copy a range of data from the semisparse array into the given byte array.
    ///
    /// See [`get_data_at`](Self::get_data_at).
    ///
    /// Mirrors `SemisparseByteArray.getData(long, byte[])`.
    pub fn get_data(&self, loc: u64, data: &mut [u8]) {
        let len = data.len() as i32;
        self.get_data_at(loc, data, 0, len);
    }

    /// The live, directly-mutable backing block at `loc`, which must be block-aligned.
    ///
    /// Mirrors `SemisparseByteArray.getDirect(long)`, which returns Java's raw `byte[]` block
    /// for direct reads/writes, bypassing `defined`-span tracking entirely (so bytes written this
    /// way are not reflected by [`is_initialized`](Self::is_initialized) et al., exactly as in
    /// Java). Since Rust has no aliasable, unsynchronized array handle to hand back without
    /// `unsafe`, this returns a guard that holds the array's lock for as long as the caller
    /// derefs it (see [`DirectBlock`]) -- a stricter but still faithful way to expose the same
    /// live, mutable block.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `loc` is not block-aligned.
    pub fn get_direct(&self, loc: u64) -> DirectBlock<'_> {
        let block_num = loc / BLOCK_SIZE as u64;
        let block_offset = loc % BLOCK_SIZE as u64;
        if block_offset != 0 {
            panic!("Offset must be at block boundary");
        }
        let mut guard = self.inner.lock().unwrap();
        guard.blocks.entry(block_num).or_insert_with(|| vec![0u8; BLOCK_SIZE]);
        DirectBlock { guard, block_num }
    }

    /// Copy a range of data from the semisparse array into a portion of the given byte array.
    ///
    /// Copies `length` bytes of data from the semisparse array starting at index `loc` into
    /// `data` starting at index `offset`. All initialized portions within the requested region
    /// are copied. The uninitialized portions may be treated as zeroes or not copied at all.
    /// Typically, the destination array has been initialized to zero by the caller, such that all
    /// uninitialized portions are zero. To avoid fetching uninitialized data, use
    /// [`contiguous_available_after`](Self::contiguous_available_after) as an upper bound on the
    /// length.
    ///
    /// Mirrors `SemisparseByteArray.getData(long, byte[], int, int)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `length` is negative. Mirrors
    /// `BufferUnderflowException`: panics if the read runs past the end of the address space.
    pub fn get_data_at(&self, loc: u64, data: &mut [u8], offset: i32, length: i32) {
        if length < 0 {
            panic!("length: {length}");
        }
        let inner = self.inner.lock().unwrap();
        let length = length as u64;
        let offset = offset as u64;

        // Read in portion of first block (could be full block).
        let mut block_num = loc / BLOCK_SIZE as u64;
        let block_offset = loc % BLOCK_SIZE as u64;
        let mut amt = length.min(BLOCK_SIZE as u64 - block_offset);
        if let Some(block) = inner.blocks.get(&block_num) {
            copy_into(data, offset as usize, block, block_offset as usize, amt as usize);
        }

        // Read in each following block.
        let mut cur = amt;
        while cur < length {
            let (next, overflowed) = block_num.overflowing_add(1);
            block_num = next;
            if overflowed || block_num == 0 {
                panic!("buffer underflow: read past the end of the address space");
            }
            amt = (length - cur).min(BLOCK_SIZE as u64);
            if let Some(block) = inner.blocks.get(&block_num) {
                copy_into(data, (cur + offset) as usize, block, 0, amt as usize);
            }
            cur += amt;
        }
    }

    /// Enumerate the initialized ranges within the given range.
    ///
    /// The given range is interpreted as closed, i.e., `[a, b]`.
    ///
    /// Mirrors `SemisparseByteArray.getInitialized(long, long)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException` from constructing `ULongSpan.span(a, b)`: panics if
    /// `b < a`.
    pub fn get_initialized(&self, a: u64, b: u64) -> Vec<Span> {
        let query = ulong_span::span(a, b);
        let inner = self.inner.lock().unwrap();
        inner
            .defined
            .spans
            .iter()
            .filter(|s| s.intersects(&query))
            .map(|s| {
                let i = query.intersect(s);
                Span { min: i.min(), max: i.max() }
            })
            .collect()
    }

    /// Check if a range is completely initialized.
    ///
    /// The given range is interpreted as closed, i.e., `[a, b]`.
    ///
    /// Mirrors `SemisparseByteArray.isInitialized(long, long)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException` from constructing `ULongSpan.span(a, b)`: panics if
    /// `b < a`.
    pub fn is_initialized(&self, a: u64, b: u64) -> bool {
        let query = ulong_span::span(a, b);
        self.inner.lock().unwrap().defined.encloses(&query)
    }

    /// Check if an index is initialized.
    ///
    /// Mirrors `SemisparseByteArray.isInitialized(long)`.
    pub fn is_initialized_at(&self, a: u64) -> bool {
        self.inner.lock().unwrap().defined.contains(a)
    }

    /// Enumerate the uninitialized ranges within the given range.
    ///
    /// The given range is interpreted as closed, i.e., `[a, b]`.
    ///
    /// Mirrors `SemisparseByteArray.getUninitialized(long, long)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException` from constructing `ULongSpan.span(a, b)`: panics if
    /// `b < a`.
    pub fn get_uninitialized(&self, a: u64, b: u64) -> Vec<Span> {
        let query = ulong_span::span(a, b);
        self.inner.lock().unwrap().defined.complement(&query)
    }

    /// Initialize or modify a range of the array by copying from a given array.
    ///
    /// See [`put_data_at`](Self::put_data_at).
    ///
    /// Mirrors `SemisparseByteArray.putData(long, byte[])`.
    pub fn put_data(&self, loc: u64, data: &[u8]) {
        let len = data.len() as i32;
        self.put_data_at(loc, data, 0, len);
    }

    /// Initialize or modify a range of the array by copying a portion from a given array.
    ///
    /// Mirrors `SemisparseByteArray.putData(long, byte[], int, int)`.
    ///
    /// # Panics
    /// Mirrors `IllegalArgumentException`: panics if `length` is negative. Mirrors
    /// `BufferOverflowException`: panics if the write runs past the end of the address space.
    pub fn put_data_at(&self, loc: u64, data: &[u8], offset: i32, length: i32) {
        if length < 0 {
            panic!("length: {length}");
        }
        if length == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.defined.add(ulong_span::extent(loc, length as u64));

        let length = length as u64;
        let offset = offset as u64;

        // Write out portion of first block (could be full block).
        let mut block_num = loc / BLOCK_SIZE as u64;
        let block_offset = loc % BLOCK_SIZE as u64;
        let mut amt = length.min(BLOCK_SIZE as u64 - block_offset);
        {
            let block = inner.blocks.entry(block_num).or_insert_with(|| vec![0u8; BLOCK_SIZE]);
            copy_from(block, block_offset as usize, data, offset as usize, amt as usize);
        }

        // Write out each following block.
        let mut cur = amt;
        while cur < length {
            let (next, overflowed) = block_num.overflowing_add(1);
            block_num = next;
            if overflowed || block_num == 0 {
                panic!("buffer overflow: write past the end of the address space");
            }
            amt = (length - cur).min(BLOCK_SIZE as u64);
            let block = inner.blocks.entry(block_num).or_insert_with(|| vec![0u8; BLOCK_SIZE]);
            copy_from(block, 0, data, (cur + offset) as usize, amt as usize);
            cur += amt;
        }
    }

    /// Copy the contents of another semisparse array into this one.
    ///
    /// Mirrors `SemisparseByteArray.putAll(SemisparseByteArray)`. See the struct docs for why
    /// this port's locking is more conservative than Java's (and so does not need Java's implicit
    /// reentrant-monitor safety net).
    pub fn put_all(&self, from: &SemisparseByteArray) {
        let mut temp = vec![0u8; 4096];
        let spans: Vec<Span> = from.inner.lock().unwrap().defined.spans.clone();
        for span in spans {
            let lower = span.min;
            let length = span.length();
            let mut i: u64 = 0;
            while i < length {
                let l = MathUtilities::unsigned_min_i32_i64(temp.len() as i32, (length - i) as i64) as u64;
                from.get_data(lower.wrapping_add(i), &mut temp[..l as usize]);
                self.put_data(lower.wrapping_add(i), &temp[..l as usize]);
                i += l;
            }
        }
    }

    /// Check how many contiguous bytes are available starting at the given address.
    ///
    /// Mirrors `SemisparseByteArray.contiguousAvailableAfter(long)`.
    ///
    /// Java computes `span.max() - loc + 1` using ordinary (2's-complement-wrapping) `long`
    /// arithmetic, then treats the result as unsigned when comparing it against
    /// `Integer.MAX_VALUE`. If the containing span reaches all the way to the top of the address
    /// space (`Domain.MAX`) and `loc` is small enough that `max - loc + 1` overflows exactly back
    /// to `0` (e.g. `loc == 0` with `span.max() == u64::MAX`), Java silently reports `0` bytes
    /// available instead of `Integer.MAX_VALUE`. That overflow is faithfully reproduced here via
    /// `wrapping_sub`/`wrapping_add`, not "fixed" to compute the true (much larger) span length.
    pub fn contiguous_available_after(&self, loc: u64) -> i32 {
        let inner = self.inner.lock().unwrap();
        let Some(span) = inner.defined.span_containing(loc) else {
            return 0;
        };
        let diff = span.max.wrapping_sub(loc).wrapping_add(1);
        MathUtilities::unsigned_min_i32_i64(i32::MAX, diff as i64)
    }
}

impl Default for SemisparseByteArray {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies `amt` bytes from `src[src_off..]` into `dst[dst_off..]`.
fn copy_into(dst: &mut [u8], dst_off: usize, src: &[u8], src_off: usize, amt: usize) {
    dst[dst_off..dst_off + amt].copy_from_slice(&src[src_off..src_off + amt]);
}

/// Copies `amt` bytes from `src[src_off..]` into `dst[dst_off..]`. Same shape as
/// [`copy_into`], named separately at each call site to match the direction of the Java
/// `System.arraycopy` call it mirrors (`getData` copies *out of* a block; `putData` copies *into*
/// one).
fn copy_from(dst: &mut [u8], dst_off: usize, src: &[u8], src_off: usize, amt: usize) {
    copy_into(dst, dst_off, src, src_off, amt)
}

/// A live, directly-mutable handle to one backing block, returned by
/// [`SemisparseByteArray::get_direct`].
///
/// Holds the array's lock for its entire lifetime, so it should be dropped promptly. Derefs to
/// a `[u8]` of length [`BLOCK_SIZE`].
pub struct DirectBlock<'a> {
    guard: MutexGuard<'a, Inner>,
    block_num: u64,
}

impl<'a> Deref for DirectBlock<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.guard.blocks[&self.block_num]
    }
}

impl<'a> DerefMut for DirectBlock<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.guard.blocks.get_mut(&self.block_num).expect("block inserted by get_direct")
    }
}

/// A sorted, pairwise-disjoint, non-adjacent set of inclusive spans of defined offsets.
///
/// Internal support type for [`SemisparseByteArray`]; not a full port of Java's
/// `MutableULongSpanSet`/`DefaultULongSpanSet` (see the struct docs above for why). Kept sorted
/// by `min` so `add` can merge adjacent/overlapping runs in one pass.
#[derive(Clone, Default)]
struct DefinedSpans {
    spans: Vec<Span>,
}

impl DefinedSpans {
    fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.spans.clear();
    }

    fn contains(&self, n: u64) -> bool {
        self.spans.iter().any(|s| s.contains(n))
    }

    /// Whether the union of spans in this set fully covers `query` (no gap anywhere in it).
    fn encloses(&self, query: &Span) -> bool {
        self.complement(query).is_empty()
    }

    /// The span in this set containing `loc`, if any.
    fn span_containing(&self, loc: u64) -> Option<Span> {
        self.spans.iter().find(|s| s.contains(loc)).copied()
    }

    /// Merge `span` into this set, coalescing with any spans it overlaps or touches.
    fn add(&mut self, span: Span) {
        let mut merged_min = span.min;
        let mut merged_max = span.max;
        self.spans.retain(|s| {
            if touches_or_overlaps(merged_min, merged_max, s.min, s.max) {
                merged_min = merged_min.min(s.min);
                merged_max = merged_max.max(s.max);
                false
            } else {
                true
            }
        });
        self.spans.push(Span { min: merged_min, max: merged_max });
        self.spans.sort_unstable_by_key(|s| s.min);
    }

    /// The sub-ranges of `query` not covered by any span in this set.
    fn complement(&self, query: &Span) -> Vec<Span> {
        let (a, b) = (query.min, query.max);
        let mut result = Vec::new();
        let mut cursor = a;
        for s in &self.spans {
            if s.max < cursor {
                continue;
            }
            if s.min > b {
                break;
            }
            if s.min > cursor {
                result.push(Span { min: cursor, max: s.min - 1 });
            }
            if s.max == u64::MAX {
                return result;
            }
            cursor = cursor.max(s.max + 1);
            if cursor > b {
                return result;
            }
        }
        result.push(Span { min: cursor, max: b });
        result
    }
}

/// Whether `[a_min, a_max]` overlaps or is immediately adjacent to `[b_min, b_max]` (so the two
/// should merge into one span), without overflowing at the domain boundary.
fn touches_or_overlaps(a_min: u64, a_max: u64, b_min: u64, b_max: u64) -> bool {
    if a_max >= b_min && b_max >= a_min {
        return true;
    }
    if a_max < u64::MAX && a_max + 1 == b_min {
        return true;
    }
    if b_max < u64::MAX && b_max + 1 == a_min {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_array_is_entirely_uninitialized() {
        let arr = SemisparseByteArray::new();
        assert!(!arr.is_initialized_at(0));
        assert!(!arr.is_initialized(0, 100));
        assert_eq!(arr.get_uninitialized(0, 100), vec![Span { min: 0, max: 100 }]);
        assert!(arr.get_initialized(0, 100).is_empty());
    }

    #[test]
    fn put_data_then_get_data_round_trips_within_a_block() {
        let arr = SemisparseByteArray::new();
        arr.put_data(10, &[1, 2, 3, 4]);

        let mut out = vec![0u8; 4];
        arr.get_data(10, &mut out);
        assert_eq!(out, vec![1, 2, 3, 4]);

        assert!(arr.is_initialized(10, 13));
        assert!(!arr.is_initialized(10, 14));
        assert!(arr.is_initialized_at(10));
        assert!(!arr.is_initialized_at(14));
    }

    #[test]
    fn put_data_spans_multiple_blocks() {
        let arr = SemisparseByteArray::new();
        let loc = BLOCK_SIZE as u64 - 2;
        let data: Vec<u8> = (0..8).collect();
        arr.put_data(loc, &data);

        let mut out = vec![0u8; 8];
        arr.get_data(loc, &mut out);
        assert_eq!(out, data);
        assert!(arr.is_initialized(loc, loc + 7));
    }

    #[test]
    fn get_data_leaves_uninitialized_positions_untouched() {
        let arr = SemisparseByteArray::new();
        arr.put_data(4, &[9, 9]);

        // `put_data(4, ..)` lands inside block 0 (BLOCK_SIZE = 0x1000), allocating a
        // zero-initialized backing block (mirrors Java's `blocks.computeIfAbsent(n, () -> new
        // byte[BLOCK_SIZE])`). Reading range 0..10 is served entirely from that one existing
        // block, so bytes never explicitly `put` still come back as zero -- `get_data` copies
        // straight from the block's backing array and does not consult the separate
        // `defined`-span tracking to mask individual untouched bytes within an allocated block.
        let mut out = vec![0xffu8; 10];
        arr.get_data(0, &mut out);
        assert_eq!(out, vec![0, 0, 0, 0, 9, 9, 0, 0, 0, 0]);

        // Only bytes in a block that was never allocated at all are left untouched in the
        // destination, matching the doc contract ("uninitialized portions may be treated as
        // zeroes or not copied at all"). Block 5 (loc = 5 * BLOCK_SIZE) has never been touched.
        let mut out2 = vec![0xffu8; 4];
        arr.get_data(5 * BLOCK_SIZE as u64, &mut out2);
        assert_eq!(out2, vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn get_data_at_offset_writes_into_the_middle_of_the_destination() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2, 3]);

        let mut out = vec![0u8; 6];
        arr.get_data_at(0, &mut out, 2, 3);
        assert_eq!(out, vec![0, 0, 1, 2, 3, 0]);
    }

    #[test]
    #[should_panic(expected = "length: -1")]
    fn get_data_at_rejects_negative_length() {
        let arr = SemisparseByteArray::new();
        let mut out = vec![0u8; 4];
        arr.get_data_at(0, &mut out, 0, -1);
    }

    #[test]
    #[should_panic(expected = "length: -1")]
    fn put_data_at_rejects_negative_length() {
        let arr = SemisparseByteArray::new();
        arr.put_data_at(0, &[1, 2, 3], 0, -1);
    }

    #[test]
    fn put_data_with_zero_length_is_a_no_op() {
        let arr = SemisparseByteArray::new();
        arr.put_data_at(5, &[1, 2, 3], 0, 0);
        assert!(!arr.is_initialized_at(5));
    }

    #[test]
    fn get_initialized_clips_defined_spans_to_the_query() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &vec![1u8; 10]); // defines [0, 9]
        arr.put_data(20, &vec![1u8; 10]); // defines [20, 29]

        let initialized = arr.get_initialized(5, 25);
        assert_eq!(initialized, vec![Span { min: 5, max: 9 }, Span { min: 20, max: 25 }]);
    }

    #[test]
    fn get_uninitialized_reports_the_gaps() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &vec![1u8; 10]); // defines [0, 9]
        arr.put_data(20, &vec![1u8; 10]); // defines [20, 29]

        let gaps = arr.get_uninitialized(0, 29);
        assert_eq!(gaps, vec![Span { min: 10, max: 19 }]);
    }

    #[test]
    #[should_panic]
    fn get_initialized_panics_when_b_is_less_than_a() {
        let arr = SemisparseByteArray::new();
        arr.get_initialized(10, 5);
    }

    #[test]
    #[should_panic]
    fn is_initialized_range_panics_when_b_is_less_than_a() {
        let arr = SemisparseByteArray::new();
        arr.is_initialized(10, 5);
    }

    #[test]
    #[should_panic]
    fn get_uninitialized_panics_when_b_is_less_than_a() {
        let arr = SemisparseByteArray::new();
        arr.get_uninitialized(10, 5);
    }

    #[test]
    fn adjacent_writes_merge_into_one_defined_span() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2, 3]);
        arr.put_data(3, &[4, 5, 6]);
        assert_eq!(arr.get_uninitialized(0, 5), Vec::<Span>::new());
        assert_eq!(arr.contiguous_available_after(0), 6);
    }

    #[test]
    fn contiguous_available_after_reports_bytes_to_the_end_of_the_span() {
        let arr = SemisparseByteArray::new();
        arr.put_data(100, &vec![0u8; 50]); // defines [100, 149]
        assert_eq!(arr.contiguous_available_after(100), 50);
        assert_eq!(arr.contiguous_available_after(120), 30);
        assert_eq!(arr.contiguous_available_after(149), 1);
    }

    #[test]
    fn contiguous_available_after_is_zero_outside_any_defined_span() {
        let arr = SemisparseByteArray::new();
        arr.put_data(100, &vec![0u8; 50]);
        assert_eq!(arr.contiguous_available_after(99), 0);
        assert_eq!(arr.contiguous_available_after(150), 0);
    }

    #[test]
    fn contiguous_available_after_reproduces_the_overflow_quirk_at_the_top_of_the_address_space() {
        // A span reaching the very top of the address space, queried from offset 0: Java's
        // `span.max() - loc + 1` computes `u64::MAX - 0 + 1`, which wraps back to `0` in 64-bit
        // two's-complement arithmetic instead of the true (much larger) length -- so this
        // faithfully reports 0 bytes available rather than `i32::MAX`.
        let arr = SemisparseByteArray::new();
        {
            let mut inner = arr.inner.lock().unwrap();
            inner.defined.add(Span { min: 0, max: u64::MAX });
        }
        assert_eq!(arr.contiguous_available_after(0), 0);
    }

    #[test]
    fn get_direct_returns_a_zeroed_block_on_first_access() {
        let arr = SemisparseByteArray::new();
        let block = arr.get_direct(0);
        assert_eq!(block.len(), BLOCK_SIZE);
        assert!(block.iter().all(|&b| b == 0));
    }

    #[test]
    #[should_panic(expected = "Offset must be at block boundary")]
    fn get_direct_rejects_a_non_block_aligned_offset() {
        let arr = SemisparseByteArray::new();
        let _ = arr.get_direct(1);
    }

    #[test]
    fn get_direct_mutation_is_visible_through_get_data_but_not_marked_defined() {
        // Faithful to Java: `getDirect` returns the raw block for direct writes, which bypass
        // `defined`-span tracking entirely.
        let arr = SemisparseByteArray::new();
        {
            let mut block = arr.get_direct(0);
            block[5] = 42;
        }
        let mut out = vec![0u8; 6];
        arr.get_data(0, &mut out);
        assert_eq!(out[5], 42);
        assert!(!arr.is_initialized_at(5));
    }

    #[test]
    fn fork_produces_an_independent_copy() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2, 3]);

        let copy = arr.fork();
        copy.put_data(0, &[9, 9, 9]);

        let mut original = vec![0u8; 3];
        arr.get_data(0, &mut original);
        assert_eq!(original, vec![1, 2, 3]);

        let mut copied = vec![0u8; 3];
        copy.get_data(0, &mut copied);
        assert_eq!(copied, vec![9, 9, 9]);
    }

    #[test]
    fn clone_shares_the_same_backing_store() {
        let arr = SemisparseByteArray::new();
        let alias = arr.clone();
        alias.put_data(0, &[7, 7, 7]);

        let mut out = vec![0u8; 3];
        arr.get_data(0, &mut out);
        assert_eq!(out, vec![7, 7, 7]);
    }

    #[test]
    fn clear_resets_the_array_to_uninitialized() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2, 3]);
        arr.clear();

        assert!(!arr.is_initialized_at(0));
        // `clear()` removes the backing block entirely (mirrors Java's `blocks.clear()`), not
        // just zeroing its bytes -- so `get_data` afterward finds no block at all and copies
        // nothing (`if (block != null) { arraycopy }` else no-op, verified against
        // SemisparseByteArray.java lines 150-152), leaving the destination at whatever the
        // caller pre-filled it with.
        let mut out = vec![0xffu8; 3];
        arr.get_data(0, &mut out);
        assert_eq!(out, vec![0xff, 0xff, 0xff]);
    }

    #[test]
    fn put_all_copies_every_defined_span_from_the_source() {
        let src = SemisparseByteArray::new();
        src.put_data(0, &[1, 2, 3]);
        src.put_data(1000, &[9, 9]);

        let dst = SemisparseByteArray::new();
        dst.put_all(&src);

        let mut a = vec![0u8; 3];
        dst.get_data(0, &mut a);
        assert_eq!(a, vec![1, 2, 3]);

        let mut b = vec![0u8; 2];
        dst.get_data(1000, &mut b);
        assert_eq!(b, vec![9, 9]);

        assert_eq!(dst.get_initialized(0, 2000), src.get_initialized(0, 2000));
    }

    #[test]
    fn put_all_copying_a_span_larger_than_the_temp_buffer_still_round_trips() {
        let src = SemisparseByteArray::new();
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        src.put_data(0, &data);

        let dst = SemisparseByteArray::new();
        dst.put_all(&src);

        let mut out = vec![0u8; data.len()];
        dst.get_data(0, &mut out);
        assert_eq!(out, data);
    }

    #[test]
    fn put_all_onto_itself_does_not_deadlock_and_is_a_no_op() {
        let arr = SemisparseByteArray::new();
        arr.put_data(0, &[1, 2, 3]);
        arr.put_all(&arr.clone());

        let mut out = vec![0u8; 3];
        arr.get_data(0, &mut out);
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn default_matches_new() {
        let arr = SemisparseByteArray::default();
        assert!(!arr.is_initialized_at(0));
    }
}
