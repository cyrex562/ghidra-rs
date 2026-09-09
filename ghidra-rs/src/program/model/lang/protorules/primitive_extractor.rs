//! Port of `ghidra.program.model.lang.protorules.PrimitiveExtractor`.
//!
//! Not one of the seven `protorules` classes assigned for this port, but a genuine dependency of
//! [`HomogeneousAggregate::filter`](super::homogeneous_aggregate::HomogeneousAggregate) (its Java
//! counterpart constructs a `PrimitiveExtractor` directly). Ported here, scoped `pub(crate)` to
//! this package, so that filter's logic is real rather than a stub.
//!
//! # Ownership vs. Java reference aliasing
//!
//! Java's `Primitive` wraps a shared `DataType` object reference; the same `DataType` instance
//! can appear in more than one `Primitive` (e.g. every element of an array of `int` aliases the
//! same `DataType` object). Rust's [`DataType`] has no generic clone, so this port instead
//! fetches a fresh, independently-owned `Box<dyn DataType>` for every primitive it records --
//! from `Array::get_data_type`, `DataTypeComponent::get_data_type`, or `TypeDef::get_base_data_type`,
//! all of which are `&self` methods that can be called again to mint another instance. This is
//! behavior-preserving for every read this module and [`HomogeneousAggregate`] perform on a
//! `Primitive` (metatype, aligned length, and -- per that module's own doc -- a structural
//! `is_equivalent` stand-in for Java's reference-identity comparison).

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::union::Union;
use crate::program::model::pcode::pcode_data_type_manager::{
    get_metatype, TYPE_ARRAY, TYPE_BOOL, TYPE_CODE, TYPE_FLOAT, TYPE_INT, TYPE_PTR, TYPE_PTRREL,
    TYPE_STRUCT, TYPE_UINT, TYPE_UNION, TYPE_UNKNOWN,
};

/// A single extracted primitive data-type and its offset within the containing aggregate.
///
/// Port of the nested `PrimitiveExtractor.Primitive` class.
pub(crate) struct Primitive {
    /// The primitive data-type (`Primitive.dt`).
    pub dt: Box<dyn DataType>,
    /// Offset within the container (`Primitive.offset`).
    pub offset: i32,
}

/// Port of `ghidra.program.model.lang.protorules.PrimitiveExtractor`.
pub(crate) struct PrimitiveExtractor {
    primitives: Vec<Primitive>,
    valid: bool,
    aligned: bool,
    unknown_elements: bool,
    extra_space: bool,
    union_invalid: bool,
}

impl PrimitiveExtractor {
    /// Port of the public constructor.
    ///
    /// `dt` is a borrow because this is the sole entry point reachable from
    /// [`HomogeneousAggregate::filter`](super::homogeneous_aggregate::HomogeneousAggregate),
    /// which only ever calls this with `dt` already known (via `get_metatype`) to be
    /// `TYPE_ARRAY` or `TYPE_STRUCT` -- so the top level never needs to *own* `dt` (only inspect
    /// it and recurse into independently-owned array-element/struct-component data-types); see
    /// [`extract_top`](Self::extract_top).
    pub(crate) fn new(dt: &dyn DataType, union_illegal: bool, offset: i32, max: i32) -> Self {
        let mut extractor = PrimitiveExtractor {
            primitives: Vec::new(),
            valid: true,
            aligned: true,
            unknown_elements: false,
            extra_space: false,
            union_invalid: union_illegal,
        };
        if !extractor.extract_top(dt, max, offset) {
            extractor.valid = false;
        }
        extractor
    }

    /// `true` if all primitive elements were extracted (`isValid`).
    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    /// `true` if any extracted element was unknown/undefined (`containsUnknown`).
    pub(crate) fn contains_unknown(&self) -> bool {
        self.unknown_elements
    }

    /// `true` if all extracted elements are aligned (`isAligned`).
    pub(crate) fn is_aligned(&self) -> bool {
        self.aligned
    }

    /// `true` if there is extra space in the data-type not attributable to alignment padding
    /// (`containsHoles`).
    pub(crate) fn contains_holes(&self) -> bool {
        self.extra_space
    }

    /// The number of primitives extracted (`size`).
    pub(crate) fn size(&self) -> usize {
        self.primitives.len()
    }

    /// The i-th extracted primitive and its offset (`get`).
    pub(crate) fn get(&self, i: usize) -> &Primitive {
        &self.primitives[i]
    }

    /// Top-level dispatch, operating on a borrow. Only reached once, from
    /// [`new`](Self::new); every recursive call goes through
    /// [`extract_owned`](Self::extract_owned) instead (see the module doc for why).
    fn extract_top(&mut self, dt: &dyn DataType, max: i32, offset: i32) -> bool {
        let unwrapped;
        let dt: &dyn DataType = if dt.is_typedef() {
            match dt.typedef_base_data_type() {
                Some(base) => {
                    unwrapped = base;
                    unwrapped.as_ref()
                }
                None => dt,
            }
        } else {
            dt
        };
        match get_metatype(dt) {
            TYPE_ARRAY => self.extract_array(dt, max, offset),
            TYPE_STRUCT => self.extract_struct(dt, max, offset),
            _ => false,
        }
    }

    /// Port of the private `extract(DataType, int, int)` method.
    ///
    /// Takes ownership of `dt` because, unlike [`extract_top`], this can reach the
    /// "store as `Primitive`" leaf case, which needs to move `dt` into a `Primitive`.
    fn extract_owned(&mut self, dt: Box<dyn DataType>, max: i32, offset: i32) -> bool {
        let dt: Box<dyn DataType> = if dt.is_typedef() {
            dt.typedef_base_data_type().unwrap_or(dt)
        } else {
            dt
        };
        let meta_type = get_metatype(dt.as_ref());
        match meta_type {
            TYPE_UNKNOWN | TYPE_INT | TYPE_UINT | TYPE_BOOL | TYPE_CODE | TYPE_FLOAT | TYPE_PTR
            | TYPE_PTRREL => {
                if meta_type == TYPE_UNKNOWN {
                    self.unknown_elements = true;
                }
                if self.primitives.len() as i32 >= max {
                    return false;
                }
                self.primitives.push(Primitive { dt, offset });
                true
            }
            TYPE_ARRAY => self.extract_array(dt.as_ref(), max, offset),
            TYPE_UNION => match dt.as_union() {
                Some(u) => self.handle_union(u, max, offset),
                None => false,
            },
            TYPE_STRUCT => self.extract_struct(dt.as_ref(), max, offset),
            _ => false,
        }
    }

    /// Shared `TYPE_ARRAY` handling for both [`extract_top`](Self::extract_top) and
    /// [`extract_owned`](Self::extract_owned).
    ///
    /// Port of the `case TYPE_ARRAY` arm. Java hoists a single `DataType base =
    /// ((Array) dt).getDataType()` out of the loop and reuses that one shared reference for
    /// every element (calling `base.getAlignedLength()` *after* each `extract(base, ...)`, safe
    /// there since Java never consumes `base`). This port instead re-fetches a fresh, owned
    /// element instance from `get_data_type()` on each iteration (see the module doc) and reads
    /// `get_aligned_length()` before handing that instance to
    /// [`extract_owned`](Self::extract_owned), which takes ownership of it.
    fn extract_array(&mut self, dt: &dyn DataType, max: i32, offset: i32) -> bool {
        let Some(arr) = dt.as_array() else {
            return false;
        };
        let num_els = arr.get_num_elements();
        let mut off = offset;
        for _ in 0..num_els {
            let elem = arr.get_data_type();
            let elem_len = elem.get_aligned_length();
            if !self.extract_owned(elem, max, off) {
                return false;
            }
            off += elem_len;
        }
        true
    }

    /// Shared `TYPE_STRUCT` handling for both [`extract_top`](Self::extract_top) and
    /// [`extract_owned`](Self::extract_owned).
    ///
    /// Port of the trailing structure-component loop. Java reads `compDT.getAlignedLength()`
    /// *after* `extract(compDT, ...)`, reusing the shared reference; this port hoists that read
    /// before the call to [`extract_owned`](Self::extract_owned), which takes ownership of
    /// `comp_dt` (a pure-read reordering, since `get_aligned_length` has no side effects).
    fn extract_struct(&mut self, dt: &dyn DataType, max: i32, offset: i32) -> bool {
        let Some(structure) = dt.as_structure() else {
            return false;
        };
        let is_packed = structure.is_packing_enabled();
        let components = structure.get_defined_components();
        let mut expected_off = offset;
        for component in components {
            let comp_dt = component.get_data_type();
            let cur_off = component.get_offset() + offset;
            if !is_packed {
                let align = comp_dt.get_alignment();
                if align != 0 && cur_off % align != 0 {
                    self.aligned = false;
                }
                let rem = if align != 0 { expected_off % align } else { 0 };
                if rem != 0 {
                    expected_off += align - rem;
                }
                if expected_off != cur_off {
                    self.extra_space = true;
                }
            }
            let comp_aligned_len = comp_dt.get_aligned_length();
            if !self.extract_owned(comp_dt, max, cur_off) {
                return false;
            }
            expected_off = cur_off + comp_aligned_len;
        }
        true
    }

    /// Port of `handleUnion`.
    ///
    /// Java's `handleUnion` first checks `if (unionInvalid) return false;` before doing any
    /// work; the remainder (constructing a `unionIllegal=false` sub-`PrimitiveExtractor` per
    /// union member, then computing a `commonRefinement` of their primitive lists via
    /// `checkOverlap`/`commonRefinement`, preferring integer primitives over floating-point ones
    /// at an overlapping offset) is **not** ported. This port's only caller,
    /// [`HomogeneousAggregate`](super::homogeneous_aggregate::HomogeneousAggregate), always
    /// constructs its `PrimitiveExtractor` with `union_illegal = true`
    /// (`unionInvalid` stays `true` for every extraction it triggers, transitively, since that
    /// flag is fixed at construction and never flipped), so the unported branch is genuinely
    /// unreachable from this crate's real call path -- not merely deferred.
    ///
    /// # TODO(port)
    /// If a future caller ever constructs a `PrimitiveExtractor` with `union_illegal = false`,
    /// this will conservatively fail extraction (return `false`, matching a data-type this
    /// extractor cannot classify) instead of performing Java's per-member common refinement.
    fn handle_union(&mut self, dt: &dyn Union, max: i32, offset: i32) -> bool {
        let _ = (dt, max, offset);
        if self.union_invalid {
            return false;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array::Array;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::structure::Structure;

    #[derive(Clone)]
    struct MockPrimitive {
        length: i32,
        floating_point: bool,
    }
    impl DataType for MockPrimitive {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.length
        }
        fn is_floating_point(&self) -> bool {
            self.floating_point
        }
        fn is_integer_type(&self) -> bool {
            // Reached only when `is_floating_point` is false, matching `get_metatype`'s check
            // order; makes this a proper TYPE_INT/TYPE_UINT primitive rather than falling
            // through to the TYPE_UNKNOWN default.
            !self.floating_point
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        offset: i32,
        dt_len: i32,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockPrimitive { length: self.dt_len, floating_point: false })
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockStruct {
        components: Vec<MockComponent>,
        packed: bool,
    }
    impl DataType for MockStruct {
        fn is_structure(&self) -> bool {
            true
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for MockStruct {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components.iter().cloned().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
        }
        fn is_packing_enabled(&self) -> bool {
            self.packed
        }
    }
    impl Structure for MockStruct {}

    struct MockArray {
        num_elements: i32,
        elem_len: i32,
    }
    impl DataType for MockArray {
        fn is_array(&self) -> bool {
            true
        }
        fn as_array(&self) -> Option<&dyn Array> {
            Some(self)
        }
    }
    impl Array for MockArray {
        fn get_num_elements(&self) -> i32 {
            self.num_elements
        }
        fn get_element_length(&self) -> i32 {
            self.elem_len
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockPrimitive { length: self.elem_len, floating_point: false })
        }
    }

    #[test]
    fn extracts_all_elements_of_a_primitive_array() {
        let arr = MockArray { num_elements: 4, elem_len: 4 };
        let ex = PrimitiveExtractor::new(&arr, true, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 4);
        assert_eq!(ex.get(0).offset, 0);
        assert_eq!(ex.get(1).offset, 4);
        assert_eq!(ex.get(2).offset, 8);
        assert_eq!(ex.get(3).offset, 12);
        assert!(!ex.contains_unknown());
        assert!(ex.is_aligned());
        assert!(!ex.contains_holes());
    }

    #[test]
    fn array_extraction_fails_when_exceeding_max() {
        let arr = MockArray { num_elements: 4, elem_len: 4 };
        let ex = PrimitiveExtractor::new(&arr, true, 0, 2);
        assert!(!ex.is_valid());
    }

    #[test]
    fn extracts_all_fields_of_an_unpacked_struct() {
        let s = MockStruct {
            components: vec![
                MockComponent { offset: 0, dt_len: 4 },
                MockComponent { offset: 4, dt_len: 4 },
            ],
            packed: false,
        };
        let ex = PrimitiveExtractor::new(&s, true, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 2);
        assert!(!ex.contains_holes());
    }

    #[test]
    fn detects_extra_space_between_struct_fields() {
        // A gap between field 0 (offset 0, length 4) and field 1 (offset 8) that isn't
        // explained by alignment padding.
        let s = MockStruct {
            components: vec![
                MockComponent { offset: 0, dt_len: 4 },
                MockComponent { offset: 8, dt_len: 4 },
            ],
            packed: false,
        };
        let ex = PrimitiveExtractor::new(&s, true, 0, 8);
        assert!(ex.is_valid());
        assert!(ex.contains_holes());
    }

    #[test]
    fn a_top_level_primitive_type_is_rejected() {
        // extract_top only dispatches TYPE_ARRAY/TYPE_STRUCT; anything else -- including a bare
        // primitive, which HomogeneousAggregate::filter never passes in practice since it
        // pre-checks the metatype -- fails extraction defensively.
        let p = MockPrimitive { length: 4, floating_point: false };
        let ex = PrimitiveExtractor::new(&p, true, 0, 8);
        assert!(!ex.is_valid());
    }
}
