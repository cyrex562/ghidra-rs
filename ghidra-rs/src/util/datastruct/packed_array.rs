//! Shared implementation backing the `*ArrayArray` family
//! (`ByteArrayArray`, `ShortArrayArray`, `IntArrayArray`, `LongArrayArray`,
//! `FloatArrayArray`, `DoubleArrayArray`) and mirrored in spirit by
//! `StringArray`.
//!
//! Each of those Java classes is an independent, hand-duplicated copy of the
//! same "packed element buffer" data structure (a growable array of
//! variable-length primitive arrays, all sharing one contiguous backing
//! buffer that gets compacted on resize). This module factors that shared
//! implementation out once; the per-element-type wrapper structs (in
//! `byte_array_array.rs` etc.) exist only to give each Java class its own
//! named Rust type with the right public API and doc comments, matching the
//! porting convention of one Rust file per Java source file.
//!
//! This module itself is not a 1:1 port of any single Java file.
//!
//! # Faithfully-reproduced Java quirks
//!
//! - `get`'s bounds check is `index <= starts.length` (note `<=`, not `<`),
//!   an off-by-one: calling `get` with `index == starts.length` passes the
//!   check but then indexes `starts[index]` out of bounds, throwing
//!   `ArrayIndexOutOfBoundsException` in Java. We reproduce this exactly:
//!   [`PackedArrayArray::get`] panics (via a normal Rust slice-index panic)
//!   for that specific index.
//! - The per-slot length is stored as a Java `short` via `(short)value.length`.
//!   For a stored slice longer than `i16::MAX` (32767) elements, this
//!   silently wraps to a negative value. `get` reads it back sign-extended
//!   (matching Java's `int len = lengths[index];`) and then does the
//!   equivalent of `new T[len]` with a negative `len`, which in Java throws
//!   `NegativeArraySizeException`. We reproduce this with an explicit panic
//!   carrying an equivalent message.

/// Minimum backing-array capacity (number of element-array slots).
pub(crate) const MIN_SIZE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackedArrayArray<T> {
    elems: Vec<T>,
    starts: Vec<i32>,
    lengths: Vec<i16>,
    total_space_allocated: i32,
    next_free: i32,
    last_start: i32,
}

impl<T: Copy + Default> PackedArrayArray<T> {
    pub(crate) fn new() -> Self {
        Self {
            elems: vec![T::default(); 10],
            starts: vec![0; MIN_SIZE],
            lengths: vec![0; MIN_SIZE],
            total_space_allocated: 0,
            next_free: 1,
            last_start: -1,
        }
    }

    pub(crate) fn put(&mut self, index: usize, value: Option<&[T]>) {
        let Some(value) = value else {
            self.remove(index);
            return;
        };

        if index >= self.starts.len() {
            self.adjust_array_sizes(std::cmp::max(index as i64 + 1, self.starts.len() as i64 * 2));
        }
        if index as i32 > self.last_start {
            self.last_start = index as i32;
        }

        let len = value.len() as i32;
        if self.starts[index] > 0 {
            if self.lengths[index] as i32 >= len {
                self.total_space_allocated -= self.lengths[index] as i32 - len;
            } else {
                self.total_space_allocated -= self.lengths[index] as i32;
                self.starts[index] = self.alloc_space(len);
            }
        } else {
            self.starts[index] = self.alloc_space(len);
        }
        self.lengths[index] = len as i16;

        let start = self.starts[index] as usize;
        self.elems[start..start + value.len()].copy_from_slice(value);
    }

    /// Returns a copy of the element slice stored at `index`, or `None` if
    /// not initialized to another value.
    ///
    /// # Panics
    ///
    /// Faithfully reproduces two Java bugs (see module docs): panics if
    /// `index == ` the current slot-array length (the off-by-one bounds
    /// check), and panics if the stored length wrapped negative because the
    /// original slice was longer than `i16::MAX` elements.
    pub(crate) fn get(&self, index: usize) -> Option<Vec<T>> {
        if index <= self.starts.len() {
            let start = self.starts[index];
            let len = self.lengths[index] as i32;
            if start > 0 {
                assert!(
                    len >= 0,
                    "NegativeArraySizeException (Java parity): {len}"
                );
                let mut ret = vec![T::default(); len as usize];
                if len > 0 {
                    let s = start as usize;
                    let l = len as usize;
                    ret.copy_from_slice(&self.elems[s..s + l]);
                }
                return Some(ret);
            }
        }
        None
    }

    pub(crate) fn remove(&mut self, index: usize) {
        if index < self.starts.len() && self.starts[index] > 0 {
            self.total_space_allocated -= self.lengths[index] as i32;
            self.starts[index] = 0;
            if self.total_space_allocated < self.elems.len() as i32 / 4 {
                self.adjust_space(self.total_space_allocated * 2);
            }
        }

        if index as i32 == self.last_start {
            self.find_last_start();
            if self.last_start < self.starts.len() as i32 / 4 {
                self.shrink_arrays(self.last_start * 2);
            }
        }
    }

    pub(crate) fn last_non_empty_index(&self) -> i32 {
        self.last_start
    }

    fn find_last_start(&mut self) {
        let mut i = self.last_start;
        while i >= 0 {
            if self.starts[i as usize] != 0 {
                self.last_start = i;
                return;
            }
            i -= 1;
        }
        self.last_start = -1;
    }

    fn adjust_array_sizes(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.starts.resize(size, 0);
        self.lengths.resize(size, 0);
    }

    fn shrink_arrays(&mut self, capacity: i32) {
        let size = std::cmp::max(capacity, 4) as usize;
        self.starts.resize(size, 0);
        self.lengths.resize(size, 0);
    }

    fn alloc_space(&mut self, size: i32) -> i32 {
        if size > self.elems.len() as i32 - self.next_free {
            self.adjust_space(2 * (self.total_space_allocated + size));
        }
        let ret = self.next_free;
        self.next_free += size;
        self.total_space_allocated += size;
        ret
    }

    fn adjust_space(&mut self, new_size: i32) {
        let new_size = std::cmp::max(new_size, 10) as usize;
        let mut new_elems = vec![T::default(); new_size];
        let mut pos = 1i32;
        for i in 0..self.starts.len() {
            if self.starts[i] > 0 {
                let len = (self.lengths[i] as u16) as i32;
                let src = self.starts[i] as usize;
                let len_usize = len as usize;
                new_elems[pos as usize..pos as usize + len_usize]
                    .copy_from_slice(&self.elems[src..src + len_usize]);
                self.starts[i] = pos;
                pos += len;
            }
        }
        self.next_free = pos;
        self.elems = new_elems;
    }
}
