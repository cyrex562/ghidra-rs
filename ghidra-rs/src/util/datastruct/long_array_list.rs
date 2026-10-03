//! Port of `ghidra.util.datastruct.LongArrayList` (and its package-private
//! helpers `LongArrayList.LongArraySubList` and `LongArrayListIterator`).
//!
//! Java's `LongArrayList implements List<Long>, RandomAccess`, hand-rolling
//! an `ArrayList`-like structure specialized to `long`/`Long`, complete with
//! a live (mutation-propagating) `subList` view and a full `ListIterator`.
//! This crate has no pre-existing `java.util.List<T>`-shaped trait to
//! implement against (the `generic::stl` module ports a *different*,
//! unrelated C++ STL-flavored list/iterator family used by the decompiler
//! backend, not this one), so this port exposes the same surface as a set of
//! plain inherent methods instead, plus:
//!
//! - [`LongArraySubList`], a genuinely live view: it borrows its backing
//!   [`LongArrayList`] mutably (`&'a mut LongArrayList`), so mutations made
//!   through the sub-list are real mutations of the same backing storage,
//!   matching Java's live-view semantics (rather than, say, a lazily
//!   materialized copy).
//! - [`LongArrayListIterator`], a real `ListIterator` (forward/backward
//!   traversal, in-place `set`/`remove`/`add`) usable against either
//!   [`LongArrayList`] or [`LongArraySubList`] via the shared
//!   [`LongListCursorTarget`] trait, mirroring how Java's single
//!   `LongArrayListIterator` class is written against the `List<Long>`
//!   interface rather than a concrete class.
//!
//! # Faithfully-reproduced Java quirks
//!
//! - **`retainAll` returns an inverted "changed" flag** on the main list
//!   (not on the sub-list, whose `retainAll` is implemented differently and
//!   correctly). See [`LongArrayList::retain_all`] and the
//!   `retain_all_bug_returns_inverted_changed_flag` /
//!   `retain_all_correct_on_sub_list` tests below.
//! - **`ListIterator::add` never advances the cursor.** See
//!   [`LongArrayListIterator::add`] and the
//!   `list_iterator_add_bug_*` tests below.
//! - **`addAll`/`addAll(index, ...)` always return `true`**, even when the
//!   input collection is empty (i.e. nothing actually changed) -- a
//!   deviation from the documented `List` contract. See
//!   `add_all_returns_true_even_for_empty_collection` below.
//! - **`LongArraySubList.set` throws `IllegalArgumentException`** for an
//!   out-of-range index, unlike every other bounds check in the Java file
//!   (which throw `IndexOutOfBoundsException`). See
//!   [`LongArraySubList::set`].
//!
//! # A quirk *not* reproduced: identity-based `equals`/`hashCode`
//!
//! `LongArrayList implements List<Long>` directly rather than extending
//! `AbstractList`, so it inherits `Object`'s identity-based `equals`: two
//! Java `LongArrayList`s with identical contents are *not* `.equals()` to
//! each other. This port instead derives a normal structural `PartialEq`
//! (comparing contents), which is the ordinary Rust expectation for a
//! value-like collection type and is deliberately *not* a literal-behavior
//! match -- flagged here rather than silently assumed.

/// Minimum backing-array capacity used by Java's zero-arg constructor.
///
/// Preserved for parity with the original API; has no observable effect
/// since the backing storage (a `Vec`) grows on demand.
pub const MIN_SIZE: usize = 4;

/// An `ArrayList`-like structure for `i64` (Java `long`/`Long`) values.
///
/// See the module docs for the overall design and the Java quirks this port
/// faithfully reproduces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LongArrayList {
    longs: Vec<i64>,
}

impl LongArrayList {
    /// Creates a new, empty `LongArrayList`.
    pub fn new() -> Self {
        Self { longs: Vec::new() }
    }

    /// Creates a new `LongArrayList` using `arr` as its initial contents.
    pub fn from_array(arr: Vec<i64>) -> Self {
        Self { longs: arr }
    }

    /// Creates a new `LongArrayList` with a copy of `other`'s contents.
    ///
    /// Mirrors the Java copy constructor `LongArrayList(LongArrayList list)`;
    /// equivalent to `other.clone()`.
    pub fn from_list(other: &LongArrayList) -> Self {
        other.clone()
    }

    /// Appends `value` to the end of the list. Always returns `true`
    /// (mirrors both the `void add(long)` and `boolean add(Long)` Java
    /// overloads, which do the same thing; Rust has no autoboxing overload
    /// distinction).
    pub fn add(&mut self, value: i64) -> bool {
        self.longs.push(value);
        true
    }

    /// Inserts `value` at `index`, shifting subsequent elements to the right.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index > size()`.
    pub fn add_at(&mut self, index: usize, value: i64) {
        if index > self.longs.len() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for list of size {}",
                self.longs.len()
            );
        }
        self.longs.insert(index, value);
    }

    /// Removes and returns the value at `index`, shifting subsequent
    /// elements to the left.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index >= size()`.
    pub fn remove_at(&mut self, index: usize) -> i64 {
        if index >= self.longs.len() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for list of size {}",
                self.longs.len()
            );
        }
        self.longs.remove(index)
    }

    /// Returns the value at `index`.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index >= size()`.
    pub fn get(&self, index: usize) -> i64 {
        if index >= self.longs.len() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for list of size {}",
                self.longs.len()
            );
        }
        self.longs[index]
    }

    /// Returns the value at `index`. Identical to [`Self::get`]; mirrors the
    /// Java class's redundant `getLongValue(int)` (which does exactly what
    /// `get(int)` does, unboxed).
    pub fn get_long_value(&self, index: usize) -> i64 {
        self.get(index)
    }

    /// Sets the value at `index`, returning the previous value.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index >= size()`.
    pub fn set(&mut self, index: usize, value: i64) -> i64 {
        if index >= self.longs.len() {
            panic!("IndexOutOfBoundsException (Java parity): index {index} out of bounds");
        }
        let old = self.longs[index];
        self.longs[index] = value;
        old
    }

    /// Removes all values from the list.
    pub fn clear(&mut self) {
        self.longs.clear();
    }

    /// Returns the number of values in the list.
    pub fn size(&self) -> usize {
        self.longs.len()
    }

    /// Returns `true` if the list contains no values.
    pub fn is_empty(&self) -> bool {
        self.longs.is_empty()
    }

    /// Returns a copy of the list's contents. Mirrors Java's `toArray()`
    /// (returning `Long[]`) and `toArray(Long[])` (which, despite taking an
    /// array parameter, Java's version always allocates and returns a fresh
    /// array anyway) -- both collapse to this single method in Rust.
    pub fn to_array(&self) -> Vec<i64> {
        self.longs.clone()
    }

    /// Returns a copy of the list's contents as a plain `Vec<i64>`. Mirrors
    /// `toLongArray()`; identical to [`Self::to_array`] in this port since
    /// Rust has no boxed/primitive distinction.
    pub fn to_long_array(&self) -> Vec<i64> {
        self.longs.clone()
    }

    /// Returns a copy of `length` values starting at `start`. Mirrors
    /// `toLongArray(int start, int length)`.
    ///
    /// # Panics
    /// Panics if the requested range is out of bounds.
    pub fn to_long_array_range(&self, start: usize, length: usize) -> Vec<i64> {
        self.longs[start..start + length].to_vec()
    }

    /// Reverses the order of the list's elements in place.
    pub fn reverse(&mut self) {
        self.longs.reverse();
    }

    /// Removes the first occurrence of `value`, if present. Returns `true`
    /// if an element was removed.
    pub fn remove_value(&mut self, value: i64) -> bool {
        if let Some(pos) = self.longs.iter().position(|&v| v == value) {
            self.longs.remove(pos);
            true
        } else {
            false
        }
    }

    /// Returns the index of the first occurrence of `value`, or `-1` if not
    /// present.
    pub fn index_of(&self, value: i64) -> i32 {
        self.longs
            .iter()
            .position(|&v| v == value)
            .map(|p| p as i32)
            .unwrap_or(-1)
    }

    /// Returns the index of the last occurrence of `value`, or `-1` if not
    /// present.
    pub fn last_index_of(&self, value: i64) -> i32 {
        self.longs
            .iter()
            .rposition(|&v| v == value)
            .map(|p| p as i32)
            .unwrap_or(-1)
    }

    /// Returns `true` if `value` is present.
    pub fn contains(&self, value: i64) -> bool {
        self.index_of(value) >= 0
    }

    /// Returns `true` if every value in `values` is present.
    pub fn contains_all(&self, values: &[i64]) -> bool {
        values.iter().all(|&v| self.contains(v))
    }

    /// Appends every value in `values` to the end of the list. Always
    /// returns `true` -- see the module docs' "always return `true`" quirk.
    pub fn add_all(&mut self, values: &[i64]) -> bool {
        self.add_all_at(self.longs.len(), values)
    }

    /// Inserts every value in `values` starting at `index`. Always returns
    /// `true` -- see the module docs' "always return `true`" quirk.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index > size()`.
    pub fn add_all_at(&mut self, index: usize, values: &[i64]) -> bool {
        if index > self.longs.len() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for list of size {}",
                self.longs.len()
            );
        }
        self.longs.splice(index..index, values.iter().copied());
        true
    }

    /// Removes every occurrence of every value in `values`. Returns `true`
    /// if any element was removed.
    pub fn remove_all(&mut self, values: &[i64]) -> bool {
        let mut changed = false;
        for &v in values {
            while self.remove_value(v) {
                changed = true;
            }
        }
        changed
    }

    /// Keeps only the values also present in `values`, removing everything
    /// else.
    ///
    /// # Java quirk preserved
    /// `LongArrayList.retainAll`'s "did anything change" flag is computed
    /// backwards in Java (`changed = (size == newIndex)`): it returns `true`
    /// when *nothing* was removed and `false` when entries *were* removed.
    /// This port reproduces that exactly; contrast with the (correctly
    /// implemented) [`LongArraySubList::retain_all`].
    pub fn retain_all(&mut self, values: &[i64]) -> bool {
        let new_values: Vec<i64> = self.longs.iter().copied().filter(|v| values.contains(v)).collect();
        let old_size = self.longs.len();
        let new_size = new_values.len();
        self.longs = new_values;
        old_size == new_size
    }

    /// Returns an iterator over the list's values, in order. (Not part of
    /// Java's `List<Long>` surface directly -- a small ergonomic addition
    /// for idiomatic Rust iteration; see [`Self::list_iterator`] for the
    /// full mutating `ListIterator` equivalent.)
    pub fn iter(&self) -> impl Iterator<Item = i64> + '_ {
        self.longs.iter().copied()
    }

    /// Returns a [`LongArrayListIterator`] positioned before the first
    /// element. Mirrors `iterator()`/`listIterator()`.
    pub fn list_iterator(&mut self) -> LongArrayListIterator<'_, LongArrayList> {
        LongArrayListIterator::new(self, 0)
    }

    /// Returns a [`LongArrayListIterator`] positioned so that a subsequent
    /// call to `next()` would return the element at `index`. Mirrors
    /// `listIterator(int index)`.
    ///
    /// Like Java, this does **not** validate `index` at construction time --
    /// an out-of-range `index` produces an iterator that will panic lazily
    /// on first misuse (from [`LongArrayListIterator::next`]/`previous`),
    /// not immediately here.
    pub fn list_iterator_at(&mut self, index: usize) -> LongArrayListIterator<'_, LongArrayList> {
        LongArrayListIterator::new(self, index)
    }

    /// Returns a live view over `self[start_index..end_index]`. Mutations
    /// through the returned [`LongArraySubList`] are real mutations of
    /// `self`. Mirrors `subList(int, int)`.
    ///
    /// Like Java, this does not validate `start_index`/`end_index` at
    /// construction time; out-of-range use panics lazily from the affected
    /// method.
    pub fn sub_list(&mut self, start_index: usize, end_index: usize) -> LongArraySubList<'_> {
        LongArraySubList {
            backing: self,
            start_index,
            end_index,
        }
    }
}

/// Minimal operations shared by [`LongArrayList`] and [`LongArraySubList`],
/// used by [`LongArrayListIterator`] so one iterator type can drive either.
/// Mirrors how Java's `LongArrayListIterator` is written against the
/// `List<Long>` interface rather than a concrete class.
pub trait LongListCursorTarget {
    /// Current number of elements.
    fn cursor_len(&self) -> usize;
    /// Value at `index`.
    fn cursor_get(&self, index: usize) -> i64;
    /// Overwrites the value at `index`, returning the previous value.
    fn cursor_set(&mut self, index: usize, value: i64) -> i64;
    /// Inserts `value` at `index`.
    fn cursor_add(&mut self, index: usize, value: i64);
    /// Removes and returns the value at `index`.
    fn cursor_remove(&mut self, index: usize) -> i64;
}

impl LongListCursorTarget for LongArrayList {
    fn cursor_len(&self) -> usize {
        self.size()
    }
    fn cursor_get(&self, index: usize) -> i64 {
        self.get(index)
    }
    fn cursor_set(&mut self, index: usize, value: i64) -> i64 {
        self.set(index, value)
    }
    fn cursor_add(&mut self, index: usize, value: i64) {
        self.add_at(index, value);
    }
    fn cursor_remove(&mut self, index: usize) -> i64 {
        self.remove_at(index)
    }
}

/// A live view over a sub-range of a [`LongArrayList`].
///
/// Port of the Java package-private `LongArrayList.LongArraySubList`. Holds
/// a mutable borrow of its backing list, so it is a genuinely live view --
/// not a snapshot/copy -- exactly like Java's version (whose mutating
/// methods all delegate to `backingList`).
#[derive(Debug)]
pub struct LongArraySubList<'a> {
    backing: &'a mut LongArrayList,
    start_index: usize,
    end_index: usize,
}

impl<'a> LongArraySubList<'a> {
    /// Returns the number of elements in this view.
    pub fn size(&self) -> usize {
        self.end_index - self.start_index
    }

    /// Returns `true` if this view contains no elements.
    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    /// Appends `value` to the end of this view (and the backing list, at
    /// the corresponding position). Always returns `true`.
    pub fn add(&mut self, value: i64) -> bool {
        self.backing.add_at(self.end_index, value);
        self.end_index += 1;
        true
    }

    /// Inserts `value` at `index` within this view.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index > size()`.
    pub fn add_at(&mut self, index: usize, value: i64) {
        if index > self.size() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for sub-list of size {}",
                self.size()
            );
        }
        self.backing.add_at(self.start_index + index, value);
        self.end_index += 1;
    }

    /// Removes and returns the value at `index` within this view.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index >= size()`.
    pub fn remove_at(&mut self, index: usize) -> i64 {
        if index >= self.size() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for sub-list of size {}",
                self.size()
            );
        }
        self.end_index -= 1;
        self.backing.remove_at(self.start_index + index)
    }

    /// Returns the value at `index` within this view.
    ///
    /// # Panics
    /// Panics (`IndexOutOfBoundsException` parity) if `index >= size()`.
    pub fn get(&self, index: usize) -> i64 {
        if index >= self.size() {
            panic!(
                "IndexOutOfBoundsException (Java parity): Invalid index {index} for sub-list of size {}",
                self.size()
            );
        }
        self.backing.get(self.start_index + index)
    }

    /// Sets the value at `index` within this view, returning the previous
    /// value.
    ///
    /// # Panics
    ///
    /// # Java quirk preserved
    /// Panics with an `IllegalArgumentException`-parity message for an
    /// out-of-range index -- unlike every other bounds check in this file,
    /// which use `IndexOutOfBoundsException` parity. This mismatch is
    /// present in the real Java source (`LongArraySubList.set`) and is
    /// reproduced here rather than "fixed" to be consistent.
    pub fn set(&mut self, index: usize, value: i64) -> i64 {
        if index >= self.size() {
            panic!(
                "IllegalArgumentException (Java parity): index {index} out of range for sub-list of size {}",
                self.size()
            );
        }
        self.backing.set(self.start_index + index, value)
    }

    /// Removes every element in this view from the backing list.
    pub fn clear(&mut self) {
        let count = self.size();
        for _ in 0..count {
            self.backing.remove_at(self.start_index);
        }
        self.end_index = self.start_index;
    }

    /// Returns a copy of this view's contents.
    pub fn to_array(&self) -> Vec<i64> {
        (self.start_index..self.end_index).map(|i| self.backing.get(i)).collect()
    }

    /// Removes the first occurrence of `value` within this view. Returns
    /// `true` if an element was removed.
    pub fn remove_value(&mut self, value: i64) -> bool {
        for i in 0..self.size() {
            if self.backing.get(self.start_index + i) == value {
                self.remove_at(i);
                return true;
            }
        }
        false
    }

    /// Returns the index (relative to this view) of the first occurrence of
    /// `value`, or `-1` if not present.
    pub fn index_of(&self, value: i64) -> i32 {
        for i in 0..self.size() {
            if self.backing.get(self.start_index + i) == value {
                return i as i32;
            }
        }
        -1
    }

    /// Identical to [`Self::index_of`]; mirrors the Java sub-list's public
    /// `getIndex(long)` helper (present only on the sub-list, not on
    /// `LongArrayList` or the `List<Long>` interface).
    pub fn get_index(&self, value: i64) -> i32 {
        self.index_of(value)
    }

    /// Returns the index (relative to this view) of the last occurrence of
    /// `value`, or `-1` if not present.
    pub fn last_index_of(&self, value: i64) -> i32 {
        for i in (0..self.size()).rev() {
            if self.backing.get(self.start_index + i) == value {
                return i as i32;
            }
        }
        -1
    }

    /// Returns `true` if `value` is present in this view.
    pub fn contains(&self, value: i64) -> bool {
        self.index_of(value) >= 0
    }

    /// Returns `true` if every value in `values` is present in this view.
    pub fn contains_all(&self, values: &[i64]) -> bool {
        values.iter().all(|&v| self.contains(v))
    }

    /// Appends every value in `values` to the end of this view. Always
    /// returns `true`.
    pub fn add_all(&mut self, values: &[i64]) -> bool {
        self.backing.add_all_at(self.end_index, values);
        self.end_index += values.len();
        true
    }

    /// Inserts every value in `values` starting at `index` within this
    /// view. Always returns `true`.
    pub fn add_all_at(&mut self, index: usize, values: &[i64]) -> bool {
        self.backing.add_all_at(self.start_index + index, values);
        self.end_index += values.len();
        true
    }

    /// Removes every occurrence of every value in `values` from this view.
    /// Returns `true` if any element was removed.
    pub fn remove_all(&mut self, values: &[i64]) -> bool {
        let mut changed = false;
        for &v in values {
            while self.remove_value(v) {
                changed = true;
            }
        }
        changed
    }

    /// Keeps only the values also present in `values`, removing everything
    /// else from this view.
    ///
    /// Unlike [`LongArrayList::retain_all`], Java's `LongArraySubList.retainAll`
    /// is implemented correctly (via `Iterator.remove()`), and this port
    /// mirrors that: the returned flag accurately reflects whether anything
    /// changed.
    pub fn retain_all(&mut self, values: &[i64]) -> bool {
        let mut changed = false;
        let mut it = self.list_iterator_at(0);
        while it.has_next() {
            let v = it.next();
            if !values.contains(&v) {
                it.remove();
                changed = true;
            }
        }
        changed
    }

    /// Returns an iterator over this view's values, in order.
    pub fn iter(&self) -> impl Iterator<Item = i64> + '_ {
        (self.start_index..self.end_index).map(move |i| self.backing.get(i))
    }

    /// Returns a [`LongArrayListIterator`] over this view, positioned before
    /// the first element.
    pub fn list_iterator(&mut self) -> LongArrayListIterator<'_, LongArraySubList<'a>> {
        LongArrayListIterator::new(self, 0)
    }

    /// Returns a [`LongArrayListIterator`] over this view, positioned so
    /// that `next()` would return the element at `index`.
    pub fn list_iterator_at(&mut self, index: usize) -> LongArrayListIterator<'_, LongArraySubList<'a>> {
        LongArrayListIterator::new(self, index)
    }

    /// Returns a nested live view over `self[from_index..to_index]`.
    ///
    /// Mirrors Java's `LongArraySubList.subList`, which always indexes
    /// relative to the *root* backing `LongArrayList` (flattening any
    /// nesting) rather than relative to `self` -- reproduced here by
    /// reborrowing the same root `backing` reference rather than nesting
    /// `LongArraySubList`s inside each other.
    pub fn sub_list(&mut self, from_index: usize, to_index: usize) -> LongArraySubList<'_> {
        LongArraySubList {
            backing: &mut *self.backing,
            start_index: self.start_index + from_index,
            end_index: self.start_index + to_index,
        }
    }
}

impl<'a> LongListCursorTarget for LongArraySubList<'a> {
    fn cursor_len(&self) -> usize {
        self.size()
    }
    fn cursor_get(&self, index: usize) -> i64 {
        self.get(index)
    }
    fn cursor_set(&mut self, index: usize, value: i64) -> i64 {
        self.set(index, value)
    }
    fn cursor_add(&mut self, index: usize, value: i64) {
        self.add_at(index, value);
    }
    fn cursor_remove(&mut self, index: usize) -> i64 {
        self.remove_at(index)
    }
}

/// A `ListIterator<Long>` over a [`LongArrayList`] or [`LongArraySubList`].
///
/// Port of the Java package-private `LongArrayListIterator`. See the module
/// docs for the "`add` never advances the cursor" bug this faithfully
/// reproduces.
pub struct LongArrayListIterator<'a, L: LongListCursorTarget> {
    list: &'a mut L,
    next_index: usize,
    last_returned_index: Option<usize>,
}

impl<'a, L: LongListCursorTarget> LongArrayListIterator<'a, L> {
    fn new(list: &'a mut L, start_index: usize) -> Self {
        Self {
            list,
            next_index: start_index,
            last_returned_index: None,
        }
    }

    /// Returns `true` if [`Self::next`] would return an element rather than
    /// panicking.
    pub fn has_next(&self) -> bool {
        self.next_index < self.list.cursor_len()
    }

    /// Returns `true` if [`Self::previous`] would return an element rather
    /// than panicking.
    pub fn has_previous(&self) -> bool {
        self.next_index > 0
    }

    /// Returns the next element and advances the cursor.
    ///
    /// # Panics
    /// Panics (`NoSuchElementException` parity) if [`Self::has_next`] is `false`.
    pub fn next(&mut self) -> i64 {
        if !self.has_next() {
            panic!("NoSuchElementException (Java parity)");
        }
        self.last_returned_index = Some(self.next_index);
        let value = self.list.cursor_get(self.next_index);
        self.next_index += 1;
        value
    }

    /// Returns the previous element and moves the cursor backward.
    ///
    /// # Panics
    /// Panics (`NoSuchElementException` parity) if [`Self::has_previous`] is `false`.
    pub fn previous(&mut self) -> i64 {
        if !self.has_previous() {
            panic!("NoSuchElementException (Java parity)");
        }
        self.next_index -= 1;
        self.last_returned_index = Some(self.next_index);
        self.list.cursor_get(self.next_index)
    }

    /// Returns the index that a subsequent [`Self::next`] call would return.
    pub fn next_index(&self) -> i32 {
        self.next_index as i32
    }

    /// Returns the index that a subsequent [`Self::previous`] call would
    /// return (`-1` if [`Self::has_previous`] is `false`).
    pub fn previous_index(&self) -> i32 {
        self.next_index as i32 - 1
    }

    /// Removes the last element returned by [`Self::next`] or
    /// [`Self::previous`].
    ///
    /// # Panics
    /// Panics (`IllegalStateException` parity) if `next`/`previous` has not
    /// been called since the iterator was created or since the last
    /// `remove`/`add`.
    pub fn remove(&mut self) {
        let Some(last) = self.last_returned_index else {
            panic!(
                "IllegalStateException (Java parity): remove() called without a preceding \
                 next()/previous()"
            );
        };
        self.list.cursor_remove(last);
        if self.next_index > last {
            self.next_index -= 1;
        }
        self.last_returned_index = None;
    }

    /// Replaces the last element returned by [`Self::next`] or
    /// [`Self::previous`] with `value`.
    ///
    /// # Panics
    /// Panics (`IllegalStateException` parity) if `next`/`previous` has not
    /// been called since the iterator was created or since the last
    /// `remove`/`add`.
    pub fn set(&mut self, value: i64) {
        let Some(last) = self.last_returned_index else {
            panic!(
                "IllegalStateException (Java parity): set() called without a preceding \
                 next()/previous()"
            );
        };
        self.list.cursor_set(last, value);
    }

    /// Inserts `value` at the cursor position.
    ///
    /// # Java quirk preserved
    /// Faithfully reproduces a real bug in `LongArrayListIterator.add`: it
    /// inserts via `list.add(nextIndex, o)` but never advances `nextIndex`
    /// afterward. The standard `ListIterator.add` contract requires the
    /// cursor to move past the newly-inserted element (so a following
    /// `next()` skips it, and a following `previous()` returns it) -- here,
    /// because `next_index` is left unchanged, the newly-added element sits
    /// exactly at `next_index`, so a following `next()` returns *that new
    /// element* (instead of skipping past it), and a following `previous()`
    /// instead returns the element that was *before* the insertion point,
    /// skipping over the new element entirely. See
    /// `list_iterator_add_bug_next_returns_the_just_added_element` and
    /// `list_iterator_add_bug_previous_skips_the_just_added_element` below.
    pub fn add(&mut self, value: i64) {
        self.list.cursor_add(self.next_index, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let list = LongArrayList::new();
        assert!(list.is_empty());
        assert_eq!(list.size(), 0);
    }

    #[test]
    fn from_array_sets_contents() {
        let list = LongArrayList::from_array(vec![1, 2, 3]);
        assert_eq!(list.size(), 3);
        assert_eq!(list.to_array(), vec![1, 2, 3]);
    }

    #[test]
    fn from_list_copies_contents() {
        let original = LongArrayList::from_array(vec![7, 8, 9]);
        let copy = LongArrayList::from_list(&original);
        assert_eq!(copy, original);
    }

    #[test]
    fn add_appends_to_end() {
        let mut list = LongArrayList::new();
        assert!(list.add(1));
        assert!(list.add(2));
        assert_eq!(list.to_array(), vec![1, 2]);
    }

    #[test]
    fn add_at_inserts_and_shifts() {
        let mut list = LongArrayList::from_array(vec![1, 2, 4]);
        list.add_at(2, 3);
        assert_eq!(list.to_array(), vec![1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "IndexOutOfBoundsException")]
    fn add_at_past_end_panics() {
        let mut list = LongArrayList::from_array(vec![1, 2]);
        list.add_at(3, 99);
    }

    #[test]
    fn remove_at_returns_value_and_shifts() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4]);
        assert_eq!(list.remove_at(1), 2);
        assert_eq!(list.to_array(), vec![1, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "IndexOutOfBoundsException")]
    fn remove_at_out_of_bounds_panics() {
        let mut list = LongArrayList::from_array(vec![1]);
        list.remove_at(5);
    }

    #[test]
    fn get_and_get_long_value_agree() {
        let list = LongArrayList::from_array(vec![10, 20, 30]);
        assert_eq!(list.get(1), 20);
        assert_eq!(list.get_long_value(1), 20);
    }

    #[test]
    #[should_panic(expected = "IndexOutOfBoundsException")]
    fn get_out_of_bounds_panics() {
        let list = LongArrayList::from_array(vec![1]);
        list.get(5);
    }

    #[test]
    fn set_replaces_and_returns_old() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        assert_eq!(list.set(1, 99), 2);
        assert_eq!(list.to_array(), vec![1, 99, 3]);
    }

    #[test]
    #[should_panic(expected = "IndexOutOfBoundsException")]
    fn set_out_of_bounds_panics() {
        let mut list = LongArrayList::from_array(vec![1]);
        list.set(5, 99);
    }

    #[test]
    fn clear_empties_list() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        list.clear();
        assert!(list.is_empty());
    }

    #[test]
    fn to_array_and_to_long_array_match() {
        let list = LongArrayList::from_array(vec![1, 2, 3]);
        assert_eq!(list.to_array(), list.to_long_array());
    }

    #[test]
    fn to_long_array_range_returns_subrange() {
        let list = LongArrayList::from_array(vec![10, 20, 30, 40]);
        assert_eq!(list.to_long_array_range(1, 2), vec![20, 30]);
    }

    #[test]
    fn reverse_reverses_in_place() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        list.reverse();
        assert_eq!(list.to_array(), vec![3, 2, 1]);
    }

    #[test]
    fn remove_value_removes_first_occurrence() {
        let mut list = LongArrayList::from_array(vec![5, 3, 5]);
        assert!(list.remove_value(5));
        assert_eq!(list.to_array(), vec![3, 5]);
    }

    #[test]
    fn remove_value_missing_returns_false() {
        let mut list = LongArrayList::from_array(vec![1, 2]);
        assert!(!list.remove_value(99));
    }

    #[test]
    fn index_of_and_last_index_of() {
        let list = LongArrayList::from_array(vec![1, 2, 1, 3]);
        assert_eq!(list.index_of(1), 0);
        assert_eq!(list.last_index_of(1), 2);
        assert_eq!(list.index_of(99), -1);
    }

    #[test]
    fn contains_and_contains_all() {
        let list = LongArrayList::from_array(vec![1, 2, 3]);
        assert!(list.contains(2));
        assert!(!list.contains(99));
        assert!(list.contains_all(&[1, 3]));
        assert!(!list.contains_all(&[1, 99]));
    }

    #[test]
    fn add_all_appends_all_values() {
        let mut list = LongArrayList::from_array(vec![1, 2]);
        assert!(list.add_all(&[3, 4]));
        assert_eq!(list.to_array(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn add_all_returns_true_even_for_empty_collection() {
        let mut list = LongArrayList::from_array(vec![1, 2]);
        let changed = list.add_all(&[]);
        assert!(changed);
        assert_eq!(list.to_array(), vec![1, 2]);
    }

    #[test]
    fn add_all_at_inserts_at_index() {
        let mut list = LongArrayList::from_array(vec![1, 4]);
        assert!(list.add_all_at(1, &[2, 3]));
        assert_eq!(list.to_array(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn remove_all_removes_every_matching_occurrence() {
        let mut list = LongArrayList::from_array(vec![1, 2, 1, 3, 1]);
        assert!(list.remove_all(&[1]));
        assert_eq!(list.to_array(), vec![2, 3]);
    }

    #[test]
    fn remove_all_missing_returns_false() {
        let mut list = LongArrayList::from_array(vec![1, 2]);
        assert!(!list.remove_all(&[99]));
    }

    /// Faithful port of a real bug: the "changed" flag `retainAll` returns is
    /// computed backwards in Java.
    #[test]
    fn retain_all_bug_returns_inverted_changed_flag() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4]);
        let changed = list.retain_all(&[2, 4]);
        assert_eq!(list.to_array(), vec![2, 4]);
        assert!(!changed, "bug: flag is inverted when entries WERE removed");

        let mut list2 = LongArrayList::from_array(vec![5, 6]);
        let changed2 = list2.retain_all(&[5, 6, 7]);
        assert_eq!(list2.to_array(), vec![5, 6]);
        assert!(changed2, "bug: flag is inverted when nothing was removed");
    }

    #[test]
    fn retain_all_correct_on_sub_list() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4, 5]);
        let mut sub = list.sub_list(1, 4); // live view over [2, 3, 4]
        let changed = sub.retain_all(&[3]);
        assert!(changed, "sub-list's retainAll is correct, unlike the parent list's");
        assert_eq!(sub.to_array(), vec![3]);
        drop(sub);
        assert_eq!(list.to_array(), vec![1, 3, 5]);
    }

    #[test]
    fn iter_yields_values_in_order() {
        let list = LongArrayList::from_array(vec![1, 2, 3]);
        let collected: Vec<i64> = list.iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn list_iterator_next_previous_indices() {
        let mut list = LongArrayList::from_array(vec![10, 20, 30]);
        let mut it = list.list_iterator();
        assert!(it.has_next());
        assert!(!it.has_previous());
        assert_eq!(it.next_index(), 0);
        assert_eq!(it.previous_index(), -1);

        assert_eq!(it.next(), 10);
        assert_eq!(it.next(), 20);
        assert!(it.has_previous());
        assert_eq!(it.previous(), 20);
        assert_eq!(it.next(), 20);
        assert_eq!(it.next(), 30);
        assert!(!it.has_next());
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn next_past_end_panics() {
        let mut list = LongArrayList::from_array(vec![1]);
        let mut it = list.list_iterator();
        it.next();
        it.next();
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn previous_before_start_panics() {
        let mut list = LongArrayList::from_array(vec![1]);
        let mut it = list.list_iterator();
        it.previous();
    }

    #[test]
    fn list_iterator_remove() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut it = list.list_iterator();
        it.next(); // 1
        it.next(); // 2
        it.remove(); // removes 2
        assert_eq!(it.next(), 3);
        drop(it);
        assert_eq!(list.to_array(), vec![1, 3]);
    }

    #[test]
    #[should_panic(expected = "IllegalStateException")]
    fn list_iterator_remove_without_next_panics() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut it = list.list_iterator();
        it.remove();
    }

    #[test]
    fn list_iterator_set() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut it = list.list_iterator();
        it.next();
        it.set(100);
        drop(it);
        assert_eq!(list.to_array(), vec![100, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "IllegalStateException")]
    fn list_iterator_set_without_next_panics() {
        let mut list = LongArrayList::from_array(vec![1]);
        let mut it = list.list_iterator();
        it.set(5);
    }

    /// Faithful port of the `ListIterator.add` cursor-not-advanced bug (see
    /// module docs): `next()` right after `add()` returns the just-added
    /// element instead of skipping past it.
    #[test]
    fn list_iterator_add_bug_next_returns_the_just_added_element() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut it = list.list_iterator_at(1);
        it.add(99);
        assert_eq!(it.next(), 99);
        drop(it);
        assert_eq!(list.to_array(), vec![1, 99, 2, 3]);
    }

    /// Same bug, other direction: `previous()` right after `add()` skips
    /// over the just-added element entirely.
    #[test]
    fn list_iterator_add_bug_previous_skips_the_just_added_element() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut it = list.list_iterator_at(1);
        it.add(99);
        assert_eq!(it.previous(), 1);
    }

    #[test]
    fn sub_list_is_live_view_mutations_propagate() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4, 5]);
        {
            let mut sub = list.sub_list(1, 4); // [2, 3, 4]
            assert_eq!(sub.to_array(), vec![2, 3, 4]);
            sub.set(0, 99);
        }
        assert_eq!(list.to_array(), vec![1, 99, 3, 4, 5]);
    }

    #[test]
    fn sub_list_add_shifts_backing_and_updates_end_index() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        {
            let mut sub = list.sub_list(1, 2); // [2]
            sub.add(100);
            assert_eq!(sub.to_array(), vec![2, 100]);
        }
        assert_eq!(list.to_array(), vec![1, 2, 100, 3]);
    }

    #[test]
    fn sub_list_remove_updates_backing() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4]);
        {
            let mut sub = list.sub_list(1, 3); // [2, 3]
            assert_eq!(sub.remove_at(0), 2);
            assert_eq!(sub.to_array(), vec![3]);
        }
        assert_eq!(list.to_array(), vec![1, 3, 4]);
    }

    #[test]
    fn sub_list_clear_removes_only_range() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3, 4, 5]);
        {
            let mut sub = list.sub_list(1, 4); // [2, 3, 4]
            sub.clear();
            assert!(sub.is_empty());
        }
        assert_eq!(list.to_array(), vec![1, 5]);
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException")]
    fn sub_list_set_out_of_bounds_panics_with_illegal_argument() {
        let mut list = LongArrayList::from_array(vec![1, 2, 3]);
        let mut sub = list.sub_list(0, 2);
        sub.set(5, 99);
    }

    #[test]
    fn sub_list_get_index() {
        let mut list = LongArrayList::from_array(vec![10, 20, 30, 40]);
        let sub = list.sub_list(1, 3); // [20, 30]
        assert_eq!(sub.get_index(30), 1);
        assert_eq!(sub.get_index(99), -1);
    }

    #[test]
    fn sub_list_nested_sub_list_flattens_to_root_backing() {
        let mut list = LongArrayList::from_array(vec![0, 1, 2, 3, 4, 5]);
        let mut sub = list.sub_list(1, 5); // [1, 2, 3, 4]
        let mut nested = sub.sub_list(1, 3); // absolute [2, 4) => [2, 3]
        assert_eq!(nested.to_array(), vec![2, 3]);
        nested.set(0, 999);
        drop(nested);
        drop(sub);
        assert_eq!(list.to_array(), vec![0, 1, 999, 3, 4, 5]);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(LongArrayList::default(), LongArrayList::new());
    }
}
