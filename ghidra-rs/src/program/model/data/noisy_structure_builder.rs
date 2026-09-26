//! Port of `ghidra.program.model.data.NoisyStructureBuilder`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is concrete, not an interface: it carries three private fields
//! (`offsetToDataTypeMap: TreeMap<Long, DataType>`, `structDT: Structure`, `sizeOfStruct: long`)
//! that its methods read and mutate. Traits cannot store fields, so each field is instead exposed
//! as a handful of required accessor methods (no default body, mirroring the convention
//! established by [`BlockMap`](crate::program::model::pcode::block_map::BlockMap) for its private
//! `ArrayList` fields), and the real algorithm from `addDataType`/`addReference`/`computeMax`/
//! `checkForOverlap`/`getSize`/`setMinimumSize`/`iterator`/`populateOriginalStructure` is
//! reproduced faithfully as default methods built on top of those accessors -- mirroring the
//! convention established by [`LazyLoadingCachingMap`](crate::program::database::data::lazy_loading_caching_map::LazyLoadingCachingMap).
//!
//! The map is exposed via `Arc<dyn DataType>` entries rather than `Box<dyn DataType>`: Java's
//! `TreeMap` shares the exact same `DataType` reference between the map and whatever the caller
//! passed in (and hands the same shared reference back out through `iterator()`), which `Arc`'s
//! cheap, non-destructive clone models directly. A `Box`-based map would force either a deep
//! clone (not available generically on `dyn DataType`) or a destructive move on every read.
//!
//! Two static dependencies used by `addDataType` have no Rust equivalent yet:
//! - The static singleton field `DataType.DEFAULT` (used to build a "pointer to nothing" when a
//!   pointer would otherwise point back at the structure being built) is exposed as a required
//!   [`default_data_type`](NoisyStructureBuilder::default_data_type) accessor, since `DataType`
//!   itself is already ported here but no concrete singleton instance of it exists yet to hand
//!   back (mirroring the "no meaningful fallback available yet" precedent set by
//!   [`DataType::get_data_organization`](crate::program::model::data::data_type::DataType::get_data_organization)).
//! - The static helper `MetaDataType.getMostSpecificDataType(DataType, DataType)` (used to
//!   arbitrate between two datatypes occupying the same offset/length) is backed by a new minimal
//!   [`MetaDataType`](crate::program::seam_stubs::MetaDataType) placeholder trait in
//!   `seam_stubs.rs`, exposed here as a required [`meta_data_type`](NoisyStructureBuilder::meta_data_type)
//!   accessor, since the real `MetaDataType` class is not yet ported; see `STUBS.tsv`.
//!
//! Three `instanceof` downcasts (`instanceof Pointer`, `instanceof Structure`, `instanceof
//! PartialUnion`) have no general downcast available on `dyn DataType`; new `as_pointer`/
//! `as_structure`/`as_partial_union` by-reference default methods were added to
//! [`DataType`](crate::program::model::data::data_type::DataType) for this port (siblings of the
//! existing by-value `into_array`/`into_composite`/`into_array_stringable`, which cannot be used
//! here since this trait only ever holds an `Arc<dyn DataType>`, not a `Box<Self>`).
//! `instanceof Undefined`/`instanceof VoidDataType` need no such downcast since `DataType` already
//! exposes those as plain boolean flags (`is_undefined_type`/`is_void_type`).
//!
//! `dt.equals(structDT)`/`baseType.equals(structDT)` (both default `Object.equals`, i.e. Java
//! reference identity) are approximated with [`DataType::is_equivalent`] (structural comparison):
//! `Pointer::get_data_type` has no guarantee of returning the *same* `Box` each call, so `Arc`
//! pointer-identity would not model Java's reference equality here any more faithfully.
//!
//! The private `checkForOverlap` is kept private-in-spirit (a plain default method, not part of
//! the type's advertised public surface, though Rust traits cannot restrict visibility per
//! method).

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;
use crate::program::seam_stubs::MetaDataType;

/// Build a structure from a "noisy" source of field information.
///
/// Feed it field records, either via [`add_data_type`](Self::add_data_type), when we have more
/// definitive info about the size of the field, or via [`add_reference`](Self::add_reference) when
/// we have a pointer reference to the field with possibly less info about the field size.
///
/// As records come in, overlaps and conflicts in specific field data-types are resolved. In a
/// conflict, less specific data-types are replaced. After all information is collected a final
/// Structure can be built by iterating over the final field entries.
///
/// NOTE: No attempt has been made to utilize `DataType::getAlignedLength()` when considering
/// component type lengths.
///
/// Port of `ghidra.program.model.data.NoisyStructureBuilder`. See the module docs for what was
/// ported, renamed, and omitted.
pub trait NoisyStructureBuilder {
    /// Get the field entry, if any, whose offset is the greatest offset `<=` the given offset.
    /// Stands in for `offsetToDataTypeMap.floorEntry(offset)`.
    fn floor_entry(&self, offset: i64) -> Option<(i64, Arc<dyn DataType>)>;

    /// Get the field entry, if any, whose offset is the smallest offset `>` the given offset.
    /// Stands in for `offsetToDataTypeMap.higherEntry(offset)`.
    fn higher_entry(&self, offset: i64) -> Option<(i64, Arc<dyn DataType>)>;

    /// Insert (or replace) the field entry at `offset`. Stands in for
    /// `offsetToDataTypeMap.put(offset, dt)`.
    fn put_entry(&mut self, offset: i64, dt: Arc<dyn DataType>);

    /// Remove every field entry whose offset lies in `[from_offset, to_offset)`. Stands in for
    /// `offsetToDataTypeMap.subMap(fromOffset, toOffset).clear()`.
    fn clear_range(&mut self, from_offset: i64, to_offset: i64);

    /// Get a snapshot of the current field entries, ordered by ascending offset. Stands in for
    /// `offsetToDataTypeMap.entrySet()`.
    fn entries(&self) -> Vec<(i64, Arc<dyn DataType>)>;

    /// The current size of the structure in bytes (given current information). Stands in for the
    /// private `sizeOfStruct` field.
    fn size_of_struct(&self) -> i64;

    /// Set the current size of the structure in bytes. Stands in for assigning the private
    /// `sizeOfStruct` field.
    fn set_size_of_struct(&mut self, size: i64);

    /// The structure being rebuilt, if this builder was seeded via
    /// [`populate_original_structure`](Self::populate_original_structure). Stands in for the
    /// private `structDT` field, which is `null` until then.
    fn struct_data_type(&self) -> Option<Arc<dyn DataType>>;

    /// Record the structure being rebuilt. Stands in for assigning the private `structDT` field.
    fn set_struct_data_type(&mut self, dt: Arc<dyn DataType>);

    /// A "DEFAULT" datatype instance to substitute for a pointer whose pointee is the structure
    /// currently being built. Stands in for the static `DataType.DEFAULT` singleton; see the
    /// module docs.
    fn default_data_type(&self) -> Box<dyn DataType>;

    /// Decide which of two datatypes occupying the same offset/length is more specific. Stands in
    /// for the static `MetaDataType.getMostSpecificDataType` helper; see the module docs.
    fn meta_data_type(&self) -> &dyn MetaDataType;

    /// Grow [`size_of_struct`](Self::size_of_struct) so it covers `[new_off, new_off + length)`.
    ///
    /// Port of the private `computeMax(long, int)`.
    fn compute_max(&mut self, new_off: i64, length: i32) {
        let end = new_off + length as i64;
        if self.size_of_struct() < end {
            self.set_size_of_struct(end);
        }
    }

    /// Check if the given range overlaps any existing field entries. If it does return the first
    /// overlapping entry, otherwise return `None`.
    ///
    /// Port of the private `checkForOverlap(long, int)`.
    fn check_for_overlap(&self, offset: i64, size: i32) -> Option<(i64, Arc<dyn DataType>)> {
        if let Some((key, dt)) = self.floor_entry(offset) {
            let last = key + dt.get_length() as i64;
            if offset < last {
                return Some((key, dt));
            }
        }
        if let Some((key, dt)) = self.higher_entry(offset) {
            let last = offset + size as i64;
            if key < last {
                return Some((key, dt));
            }
        }
        None
    }

    /// Returns the size of the structure in bytes (given current information).
    ///
    /// Port of `getSize()`.
    fn get_size(&self) -> i64 {
        self.size_of_struct()
    }

    /// Add data-type information about a specific field.
    ///
    /// # Parameters
    /// - `offset`: offset of the field within the structure.
    /// - `dt`: the data-type of the field if known (`None` otherwise).
    ///
    /// Port of `addDataType(long, DataType)`.
    fn add_data_type(&mut self, offset: i64, dt: Option<Arc<dyn DataType>>) {
        let mut dt = match dt {
            None => {
                self.compute_max(offset, 1);
                return;
            }
            Some(dt) => dt,
        };
        if dt.is_void_type() {
            self.compute_max(offset, 1);
            return;
        }

        let pointer_base_type = dt.as_pointer().and_then(|ptr| ptr.get_data_type());
        if let Some(base_type) = pointer_base_type {
            // Be careful of taking a pointer to the structure when the structure is not fully
            // defined.
            let points_to_self = self
                .struct_data_type()
                .is_some_and(|struct_dt| base_type.is_equivalent(struct_dt.as_ref()));
            if points_to_self {
                if let Some(manager) = dt.get_data_type_manager() {
                    let default_dt = self.default_data_type();
                    let new_ptr: Box<dyn DataType> =
                        manager.get_pointer_with_size(default_dt.as_ref(), dt.get_length());
                    dt = Arc::from(new_ptr);
                }
            }
        } else if let Some(stripped) = dt.as_partial_union().map(|pu| pu.get_stripped_data_type()) {
            // The decompiler can produce the internal data-type PartialUnion, which must be
            // replaced with a suitable formal data-type within the structure being built.
            dt = Arc::from(stripped);
        }

        self.compute_max(offset, dt.get_length());
        let first_entry = self.check_for_overlap(offset, dt.get_length());
        if let Some((key, existing)) = first_entry {
            if key == offset && existing.get_length() == dt.get_length() {
                // Matching field, compare the data-types.
                if !self
                    .meta_data_type()
                    .is_more_specific(existing.as_ref(), dt.as_ref())
                {
                    return;
                }
            } else if key <= offset
                && offset + (dt.get_length() as i64) < key + (existing.get_length() as i64)
            {
                // Completely contained within preexisting entry.
                if !existing.is_undefined_type() {
                    // Don't override preexisting entry with a smaller one, unless the preexisting
                    // entry is undefined.
                    return;
                }
            } else if dt.is_undefined_type() {
                // The new field either fully or partially contains preexisting fields.
                return;
            }
            // Clear overlapping entries.
            self.clear_range(key, offset + dt.get_length() as i64);
        }
        self.put_entry(offset, dt);
    }

    /// Adds information for a field given a pointer reference. The data-type information is not
    /// used unless it is a pointer.
    ///
    /// # Parameters
    /// - `offset`: offset of the field within the structure.
    /// - `dt`: the data-type of the pointer to the field (or `None`).
    ///
    /// Port of `addReference(long, DataType)`.
    fn add_reference(&mut self, offset: i64, dt: Option<Arc<dyn DataType>>) {
        let pointee = dt.as_ref().and_then(|dt| dt.as_pointer()).and_then(|ptr| ptr.get_data_type());
        match dt.as_ref().and_then(|dt| dt.as_pointer()) {
            None => {
                self.compute_max(offset, 1);
            }
            Some(_) => match pointee {
                None => {
                    self.compute_max(offset, 1);
                }
                Some(inner) => {
                    let is_self = self
                        .struct_data_type()
                        .is_some_and(|struct_dt| inner.is_equivalent(struct_dt.as_ref()));
                    if is_self {
                        return; // Don't allow structure to contain itself.
                    }
                    if let Some(structure) = inner.as_structure() {
                        if structure.get_num_defined_components() == 0 {
                            self.compute_max(offset, 1);
                            return;
                        }
                    }
                    self.add_data_type(offset, Some(Arc::from(inner)));
                }
            },
        }
    }

    /// We may have partial information about the size of the structure. This method feeds it to
    /// the builder as a minimum size for the structure.
    ///
    /// Port of `setMinimumSize(long)`.
    fn set_minimum_size(&mut self, size: i64) {
        if size > self.size_of_struct() {
            self.set_size_of_struct(size);
        }
    }

    /// Returns the current field entries, ordered by ascending offset.
    ///
    /// Port of `iterator()`, which returns a live `Iterator<Entry<Long, DataType>>` in Java; here
    /// a snapshot `Vec` is returned instead since Rust has no direct equivalent of a lazily
    /// evaluated, borrow-checker-free `Iterator` handed back across a trait-object boundary.
    fn iterator(&self) -> Vec<(i64, Arc<dyn DataType>)> {
        self.entries()
    }

    /// Populate this builder with fields from a preexisting Structure. The builder presumes it is
    /// rebuilding this Structure so it can check for pathological containment issues.
    ///
    /// Port of `populateOriginalStructure(Structure)`.
    fn populate_original_structure(&mut self, dt: Arc<dyn Structure>) {
        for component in dt.get_defined_components() {
            self.put_entry(component.get_offset() as i64, Arc::from(component.get_data_type()));
        }
        self.set_size_of_struct(dt.get_length() as i64);
        self.set_struct_data_type(dt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ops::Bound;

    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;

    #[derive(Debug)]
    struct MockField {
        length: i32,
        is_undefined: bool,
    }

    impl DataType for MockField {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_undefined_type(&self) -> bool {
            self.is_undefined
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            std::ptr::eq(self as *const _ as *const (), dt as *const _ as *const ())
        }
    }

    struct MockMeta;
    impl MetaDataType for MockMeta {
        fn is_more_specific(&self, existing: &dyn DataType, candidate: &dyn DataType) -> bool {
            candidate.get_length() > existing.get_length()
        }
    }

    struct MockBuilder {
        map: BTreeMap<i64, Arc<dyn DataType>>,
        size: i64,
        struct_dt: Option<Arc<dyn DataType>>,
        meta: MockMeta,
    }

    impl MockBuilder {
        fn new() -> Self {
            MockBuilder {
                map: BTreeMap::new(),
                size: 0,
                struct_dt: None,
                meta: MockMeta,
            }
        }
    }

    impl NoisyStructureBuilder for MockBuilder {
        fn floor_entry(&self, offset: i64) -> Option<(i64, Arc<dyn DataType>)> {
            self.map
                .range(..=offset)
                .next_back()
                .map(|(k, v)| (*k, v.clone()))
        }

        fn higher_entry(&self, offset: i64) -> Option<(i64, Arc<dyn DataType>)> {
            self.map
                .range((Bound::Excluded(offset), Bound::Unbounded))
                .next()
                .map(|(k, v)| (*k, v.clone()))
        }

        fn put_entry(&mut self, offset: i64, dt: Arc<dyn DataType>) {
            self.map.insert(offset, dt);
        }

        fn clear_range(&mut self, from_offset: i64, to_offset: i64) {
            let keys: Vec<i64> = self.map.range(from_offset..to_offset).map(|(k, _)| *k).collect();
            for k in keys {
                self.map.remove(&k);
            }
        }

        fn entries(&self) -> Vec<(i64, Arc<dyn DataType>)> {
            self.map.iter().map(|(k, v)| (*k, v.clone())).collect()
        }

        fn size_of_struct(&self) -> i64 {
            self.size
        }

        fn set_size_of_struct(&mut self, size: i64) {
            self.size = size;
        }

        fn struct_data_type(&self) -> Option<Arc<dyn DataType>> {
            self.struct_dt.clone()
        }

        fn set_struct_data_type(&mut self, dt: Arc<dyn DataType>) {
            self.struct_dt = Some(dt);
        }

        fn default_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockField {
                length: 1,
                is_undefined: false,
            })
        }

        fn meta_data_type(&self) -> &dyn MetaDataType {
            &self.meta
        }
    }

    #[test]
    fn compute_max_and_get_size_track_the_largest_extent() {
        let mut b = MockBuilder::new();
        b.compute_max(0, 4);
        assert_eq!(b.get_size(), 4);
        b.compute_max(2, 2); // fully within [0,4) -> no growth
        assert_eq!(b.get_size(), 4);
        b.compute_max(4, 4); // extends to 8
        assert_eq!(b.get_size(), 8);
    }

    #[test]
    fn set_minimum_size_only_grows() {
        let mut b = MockBuilder::new();
        b.set_minimum_size(10);
        assert_eq!(b.get_size(), 10);
        b.set_minimum_size(4); // smaller than current -> no change
        assert_eq!(b.get_size(), 10);
    }

    #[test]
    fn add_data_type_accumulates_disjoint_fields_and_grows_size() {
        let mut b = MockBuilder::new();
        b.add_data_type(
            0,
            Some(Arc::new(MockField {
                length: 4,
                is_undefined: false,
            })),
        );
        b.add_data_type(
            4,
            Some(Arc::new(MockField {
                length: 4,
                is_undefined: false,
            })),
        );
        assert_eq!(b.get_size(), 8);
        assert_eq!(b.iterator().len(), 2);
    }

    #[test]
    fn add_data_type_rejects_less_specific_duplicate_at_same_offset() {
        let mut b = MockBuilder::new();
        let original: Arc<dyn DataType> = Arc::new(MockField {
            length: 4,
            is_undefined: false,
        });
        b.add_data_type(0, Some(original.clone()));

        // Same offset, same length -> MockMeta only prefers a strictly longer candidate, so this
        // duplicate should be rejected and the original entry retained untouched.
        b.add_data_type(
            0,
            Some(Arc::new(MockField {
                length: 4,
                is_undefined: false,
            })),
        );

        let entries = b.entries();
        assert_eq!(entries.len(), 1);
        assert!(Arc::ptr_eq(&entries[0].1, &original));
    }

    #[test]
    fn add_data_type_replaces_undefined_but_not_defined_containing_field() {
        // Case 1: an Undefined field spanning [0, 8) is replaced by a smaller, fully-contained
        // defined field.
        let mut undefined_builder = MockBuilder::new();
        undefined_builder.add_data_type(
            0,
            Some(Arc::new(MockField {
                length: 8,
                is_undefined: true,
            })),
        );
        undefined_builder.add_data_type(
            2,
            Some(Arc::new(MockField {
                length: 2,
                is_undefined: false,
            })),
        );
        let entries = undefined_builder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 2);
        assert_eq!(entries[0].1.get_length(), 2);

        // Case 2: a defined (non-Undefined) field spanning [0, 8) is NOT replaced by a smaller,
        // fully-contained field.
        let mut defined_builder = MockBuilder::new();
        defined_builder.add_data_type(
            0,
            Some(Arc::new(MockField {
                length: 8,
                is_undefined: false,
            })),
        );
        defined_builder.add_data_type(
            2,
            Some(Arc::new(MockField {
                length: 2,
                is_undefined: false,
            })),
        );
        let entries = defined_builder.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 0);
        assert_eq!(entries[0].1.get_length(), 8);
    }

    #[test]
    fn add_reference_treats_non_pointer_and_null_pointee_as_a_single_byte() {
        let mut b = MockBuilder::new();
        b.add_reference(
            0,
            Some(Arc::new(MockField {
                length: 4,
                is_undefined: false,
            })),
        );
        assert_eq!(b.get_size(), 1);
        assert!(b.entries().is_empty());

        b.add_reference(5, None);
        assert_eq!(b.get_size(), 6);
    }

    struct MockPointer {
        pointee: Option<Arc<dyn DataType>>,
    }

    impl DataType for MockPointer {
        fn get_length(&self) -> i32 {
            8
        }
    }

    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointee.as_ref().map(|_| {
                Box::new(MockField {
                    length: 4,
                    is_undefined: false,
                }) as Box<dyn DataType>
            })
        }

        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not exercised by this test")
        }

        fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockPointerField {
        pointer: MockPointer,
    }

    impl DataType for MockPointerField {
        fn get_length(&self) -> i32 {
            self.pointer.get_length()
        }
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(&self.pointer)
        }
    }

    #[test]
    fn add_reference_delegates_to_add_data_type_for_a_real_pointer() {
        let mut b = MockBuilder::new();
        let field = MockPointerField {
            pointer: MockPointer {
                pointee: Some(Arc::new(MockField {
                    length: 4,
                    is_undefined: false,
                })),
            },
        };
        b.add_reference(0, Some(Arc::new(field)));

        let entries = b.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 0);
        assert_eq!(entries[0].1.get_length(), 4);
        assert_eq!(b.get_size(), 4);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut b: Box<dyn NoisyStructureBuilder> = Box::new(MockBuilder::new());
        b.add_data_type(
            0,
            Some(Arc::new(MockField {
                length: 2,
                is_undefined: false,
            })),
        );
        assert_eq!(b.get_size(), 2);
    }
}
