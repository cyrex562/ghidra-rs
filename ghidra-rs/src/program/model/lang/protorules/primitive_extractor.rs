//! Port of `ghidra.program.model.lang.protorules.PrimitiveExtractor`.
//!
//! Not one of the classes originally assigned for this port, but a genuine dependency of
//! [`HomogeneousAggregate::filter`](super::homogeneous_aggregate::HomogeneousAggregate),
//! [`MultiMemberAssign`](super::multi_member_assign::MultiMemberAssign), and
//! [`MultiSlotDualAssign`](super::multi_slot_dual_assign::MultiSlotDualAssign) (each Java
//! counterpart constructs a `PrimitiveExtractor` directly). Ported here, scoped `pub(crate)` to
//! this package, so that each of those callers' logic is real rather than a stub. The union
//! common-refinement logic (`handleUnion`/`checkOverlap`/`commonRefinement`) is fully ported too
//! (see [`handle_union`](PrimitiveExtractor::handle_union), [`check_overlap`],
//! [`common_refinement`]): while it was initially dead code reachable only when a caller
//! constructs with `union_illegal = false` -- true of none of this port's first two callers --
//! `MultiSlotDualAssign` genuinely does construct that way (`new PrimitiveExtractor(dt, false, 0,
//! 1024)` in Java), so it is real, exercised logic, not speculative.
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
    fn empty(union_illegal: bool) -> Self {
        PrimitiveExtractor {
            primitives: Vec::new(),
            valid: true,
            aligned: true,
            unknown_elements: false,
            extra_space: false,
            union_invalid: union_illegal,
        }
    }

    /// Port of the public constructor, for a borrowed top-level data-type.
    ///
    /// `dt` is a borrow because every current caller --
    /// [`HomogeneousAggregate::filter`](super::homogeneous_aggregate::HomogeneousAggregate) and
    /// [`MultiMemberAssign`](super::multi_member_assign::MultiMemberAssign) -- only ever calls
    /// this with `dt` already known (via `get_metatype`) to be `TYPE_ARRAY`, `TYPE_STRUCT`, or
    /// (as of [`MultiSlotDualAssign`](super::multi_slot_dual_assign::MultiSlotDualAssign),
    /// which passes `union_illegal = false`) `TYPE_UNION` -- so the top level never needs to
    /// *own* `dt` itself (only inspect it and recurse into independently-owned
    /// array-element/struct-component/union-member data-types via
    /// [`extract_owned`](Self::extract_owned)); see [`extract_top`](Self::extract_top). A bare
    /// top-level primitive is out of scope for all of these real callers (each is only ever
    /// invoked on an aggregate data-type) and is rejected defensively; see
    /// [`new_from_owned`](Self::new_from_owned) for the owned entry point used when a leaf
    /// primitive genuinely can appear at the top (union members).
    pub(crate) fn new(dt: &dyn DataType, union_illegal: bool, offset: i32, max: i32) -> Self {
        let mut extractor = Self::empty(union_illegal);
        if !extractor.extract_top(dt, max, offset) {
            extractor.valid = false;
        }
        extractor
    }

    /// Port of the public constructor, for an owned top-level data-type.
    ///
    /// Unlike [`new`](Self::new), this dispatches through the full [`extract_owned`] logic (the
    /// direct port of Java's private `extract`), which also handles a top-level primitive
    /// leaf directly (moving `dt` into a [`Primitive`]) since ownership is available here. Used
    /// by [`handle_union`](Self::handle_union) to build a sub-extraction for each union member,
    /// mirroring Java's `handleUnion` constructing `new PrimitiveExtractor(curField.getDataType(),
    /// false, ...)` on each field's data-type (frequently itself a bare primitive, e.g. a union
    /// of `int`/`float`) -- something [`new`](Self::new)'s borrowed, array/struct/union-only
    /// dispatch cannot support.
    pub(crate) fn new_from_owned(
        dt: Box<dyn DataType>,
        union_illegal: bool,
        offset: i32,
        max: i32,
    ) -> Self {
        let mut extractor = Self::empty(union_illegal);
        if !extractor.extract_owned(dt, max, offset) {
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

    /// Consume `self`, returning the owned data-type of every extracted primitive (offsets
    /// discarded) as `Arc`-shareable values.
    ///
    /// Not part of the Java `PrimitiveExtractor` API; added so
    /// [`MultiMemberAssign`](crate::program::model::lang::protorules::multi_member_assign::MultiMemberAssign)
    /// -- the other real caller of this extractor besides
    /// [`HomogeneousAggregate`](super::homogeneous_aggregate::HomogeneousAggregate) -- can hand
    /// each primitive's data-type on to
    /// [`ParamListStandardLike::assign_address_fallback`](crate::program::seam_stubs::ParamListStandardLike::assign_address_fallback),
    /// which is `Arc`-based (see that method's doc for why). `Primitive.dt` stays a plain
    /// `Box<dyn DataType>` internally -- unaffected by, and not used by,
    /// [`HomogeneousAggregate`](super::homogeneous_aggregate::HomogeneousAggregate), which only
    /// ever borrows primitives via [`get`](Self::get) -- this method just converts each one to
    /// an `Arc` at the boundary via the standard `Box<dyn T> -> Arc<dyn T>` conversion.
    pub(crate) fn into_arc_types(self) -> Vec<std::sync::Arc<dyn DataType>> {
        self.primitives.into_iter().map(|p| std::sync::Arc::from(p.dt)).collect()
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
            TYPE_UNION => match dt.as_union() {
                Some(u) => self.handle_union(u, max, offset),
                None => false,
            },
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
    /// Form a primitive list for each field of the union, using [`new_from_owned`](Self::new_from_owned)
    /// (mirroring Java's `new PrimitiveExtractor(curField.getDataType(), false, offset +
    /// curField.getOffset(), max)`, `unionIllegal` hardcoded `false` for the member sub-extraction
    /// regardless of `self.union_invalid` -- reachable at all only because the `if
    /// (unionInvalid) return false;` guard below already filtered out the case where unions are
    /// disallowed). Then, if possible, computes a [`common_refinement`] of all the member
    /// primitive lists and appends it to `self.primitives`.
    ///
    /// Was previously unported (dead code, since this port's only two prior callers --
    /// [`HomogeneousAggregate`](super::homogeneous_aggregate::HomogeneousAggregate) and
    /// [`MultiMemberAssign`](super::multi_member_assign::MultiMemberAssign) -- always construct
    /// with `union_illegal = true`, so `self.union_invalid` was always `true` and this method
    /// always returned `false` at the guard). Now genuinely reachable:
    /// [`MultiSlotDualAssign`](super::multi_slot_dual_assign::MultiSlotDualAssign) constructs its
    /// top-level extraction with `union_illegal = false` (`new PrimitiveExtractor(dt, false, 0,
    /// 1024)` in Java), so a union-typed (or union-containing) parameter routed through that
    /// action now exercises this method for real.
    fn handle_union(&mut self, dt: &dyn Union, max: i32, offset: i32) -> bool {
        if self.union_invalid {
            return false;
        }
        let num = dt.get_num_components();
        if num == 0 {
            return false;
        }
        let Ok(first_comp) = dt.get_component(0) else {
            return false;
        };
        let first_offset = offset + first_comp.get_offset();
        let mut common =
            PrimitiveExtractor::new_from_owned(first_comp.get_data_type(), false, first_offset, max);
        if !common.is_valid() {
            return false;
        }
        for i in 1..num {
            let Ok(comp) = dt.get_component(i) else {
                return false;
            };
            let comp_offset = offset + comp.get_offset();
            let next =
                PrimitiveExtractor::new_from_owned(comp.get_data_type(), false, comp_offset, max);
            if !next.is_valid() {
                return false;
            }
            match common_refinement(std::mem::take(&mut common.primitives), next.primitives) {
                Some(refined) => common.primitives = refined,
                None => return false,
            }
        }
        if self.primitives.len() + common.primitives.len() > max as usize {
            return false;
        }
        self.primitives.append(&mut common.primitives);
        true
    }
}

/// Check that a big [`Primitive`] properly overlaps smaller Primitives.
///
/// If the big Primitive does not properly overlap the smaller Primitives starting at `*point`,
/// returns `false` (an invalid overlap). Otherwise, if the big Primitive is floating-point, adds
/// the overlapped primitives (moved out of `small`) to `res`; if not floating-point, adds the big
/// Primitive to `res` instead (integer primitives are *preferred* over floating-point primitives
/// this way). `*point` is advanced in place to the index of the next unconsumed `small` entry.
///
/// Port of the private `checkOverlap`. Java's version returns an `int` (the next index, or `-1`
/// for an invalid overlap) and operates on object references that remain valid in both the source
/// list and `res` simultaneously; this port instead takes `small` as `&mut [Option<Primitive>]`
/// so a consumed entry's `Primitive` (not `Clone`, since [`DataType`] has no generic clone) can be
/// [`Option::take`]n out and moved into `res`.
fn check_overlap(
    res: &mut Vec<Primitive>,
    small: &mut [Option<Primitive>],
    point: &mut usize,
    big: Primitive,
) -> bool {
    let end_off = big.offset + big.dt.get_aligned_length();
    // If big data-type is a float, let smaller primitives override it, otherwise keep big.
    let use_small = get_metatype(big.dt.as_ref()) == TYPE_FLOAT;
    while *point < small.len() {
        let Some(cur) = small[*point].as_ref() else {
            break;
        };
        if cur.offset >= end_off {
            break;
        }
        if cur.offset + cur.dt.get_aligned_length() > end_off {
            return false; // Improper overlap of the end of big
        }
        if use_small {
            res.push(small[*point].take().unwrap());
        }
        *point += 1;
    }
    if !use_small {
        // If big data-type was preferred, use it in the refinement.
        res.push(big);
    }
    true
}

/// Overwrite `first` with the common refinement of `first` and `second`.
///
/// Given two sets of overlapping Primitives (each already sorted by offset, as every
/// [`extract`](PrimitiveExtractor::extract_owned)ed primitive list is), finds a *common
/// refinement* of the lists. Returns `None` if there is any partial overlap of two Primitives.
/// If the same primitive data-type occurs at the same offset, it is included in the refinement;
/// otherwise an integer data-type is preferred over a floating-point one, or a bigger primitive is
/// preferred over smaller overlapping primitives (see [`check_overlap`]).
///
/// Port of the private `commonRefinement`. Takes and returns owned `Vec<Primitive>` (rather than
/// mutating `first` in place, as Java does via `ArrayList.clear`/`addAll`) since -- unlike Java's
/// shared object references -- moving a [`Primitive`] out of one list and into the merged result
/// requires actually transplanting ownership.
fn common_refinement(first: Vec<Primitive>, second: Vec<Primitive>) -> Option<Vec<Primitive>> {
    let mut first: Vec<Option<Primitive>> = first.into_iter().map(Some).collect();
    let mut second: Vec<Option<Primitive>> = second.into_iter().map(Some).collect();
    let mut first_point = 0usize;
    let mut second_point = 0usize;
    let mut common = Vec::new();
    while first_point < first.len() && second_point < second.len() {
        let first_offset = first[first_point].as_ref().unwrap().offset;
        let first_len = first[first_point].as_ref().unwrap().dt.get_aligned_length();
        let second_offset = second[second_point].as_ref().unwrap().offset;
        let second_len = second[second_point].as_ref().unwrap().dt.get_aligned_length();

        if first_offset < second_offset && first_offset + first_len <= second_offset {
            common.push(first[first_point].take().unwrap());
            first_point += 1;
            continue;
        }
        if second_offset < first_offset && second_offset + second_len <= first_offset {
            common.push(second[second_point].take().unwrap());
            second_point += 1;
            continue;
        }
        if first_len >= second_len {
            let big = first[first_point].take().unwrap();
            if !check_overlap(&mut common, &mut second, &mut second_point, big) {
                return None;
            }
            first_point += 1;
        } else {
            let big = second[second_point].take().unwrap();
            if !check_overlap(&mut common, &mut first, &mut first_point, big) {
                return None;
            }
            second_point += 1;
        }
    }
    // Add any tail primitives from either list.
    while first_point < first.len() {
        common.push(first[first_point].take().unwrap());
        first_point += 1;
    }
    while second_point < second.len() {
        common.push(second[second_point].take().unwrap());
        second_point += 1;
    }
    Some(common)
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
    fn a_top_level_primitive_type_is_rejected_via_new() {
        // extract_top's borrowed dispatch only handles TYPE_ARRAY/TYPE_STRUCT/TYPE_UNION;
        // anything else -- including a bare primitive, which HomogeneousAggregate::filter never
        // passes in practice since it pre-checks the metatype -- fails extraction defensively
        // (ownership would be required to store it as a Primitive; see new_from_owned below for
        // the owned entry point that lifts this restriction).
        let p = MockPrimitive { length: 4, floating_point: false };
        let ex = PrimitiveExtractor::new(&p, true, 0, 8);
        assert!(!ex.is_valid());
    }

    #[test]
    fn new_from_owned_extracts_a_bare_top_level_primitive() {
        let p: Box<dyn DataType> = Box::new(MockPrimitive { length: 4, floating_point: false });
        let ex = PrimitiveExtractor::new_from_owned(p, true, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 1);
        assert_eq!(ex.get(0).offset, 0);
    }

    // --- Union common-refinement (`handleUnion`/`checkOverlap`/`commonRefinement`) ---

    #[derive(Clone)]
    enum MockUnionField {
        Prim { length: i32, floating_point: bool },
        Arr { num_elements: i32, elem_len: i32 },
    }
    impl MockUnionField {
        fn to_data_type(&self) -> Box<dyn DataType> {
            match *self {
                MockUnionField::Prim { length, floating_point } => {
                    Box::new(MockPrimitive { length, floating_point })
                }
                MockUnionField::Arr { num_elements, elem_len } => {
                    Box::new(MockArray { num_elements, elem_len })
                }
            }
        }
    }

    #[derive(Clone)]
    struct MockUnionComponent {
        offset: i32,
        field: MockUnionField,
    }
    impl DataTypeComponent for MockUnionComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.field.to_data_type()
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
    }

    struct MockUnion {
        components: Vec<MockUnionComponent>,
    }
    impl DataType for MockUnion {
        fn is_union(&self) -> bool {
            true
        }
        fn as_union(&self) -> Option<&dyn crate::program::model::data::union::Union> {
            Some(self)
        }
    }
    impl Composite for MockUnion {
        fn get_num_components(&self) -> i32 {
            self.components.len() as i32
        }
        fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
            self.components
                .get(ordinal as usize)
                .cloned()
                .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
                .ok_or_else(|| "ordinal out of bounds".to_string())
        }
        fn is_packing_enabled(&self) -> bool {
            false
        }
    }
    impl crate::program::model::data::union::Union for MockUnion {
        fn clone_union(
            &self,
            _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn crate::program::model::data::union::Union> {
            unimplemented!("not exercised by these tests")
        }
        fn insert_bit_field(
            &mut self,
            _ordinal: i32,
            _base_data_type: Box<dyn DataType>,
            _bit_size: i32,
            _component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn union_is_rejected_outright_when_unions_are_disallowed() {
        let u = MockUnion {
            components: vec![MockUnionComponent {
                offset: 0,
                field: MockUnionField::Prim { length: 4, floating_point: false },
            }],
        };
        let ex = PrimitiveExtractor::new(&u, true, 0, 8);
        assert!(!ex.is_valid());
    }

    #[test]
    fn union_common_refinement_prefers_integer_over_overlapping_float() {
        // Two fields at the same offset/size, one int one float -- the docstring on the ported
        // `checkOverlap` says integer primitives are *preferred* over floating-point ones.
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: true },
                },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 1);
        assert!(!ex.get(0).dt.is_floating_point());
    }

    #[test]
    fn union_common_refinement_prefers_integer_regardless_of_field_order() {
        // Same as above but with the float field declared first, proving the preference isn't
        // just an artifact of which member happens to be "first"/"second".
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: true },
                },
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 1);
        assert!(!ex.get(0).dt.is_floating_point());
    }

    #[test]
    fn union_common_refinement_keeps_disjoint_fields_from_both_members() {
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
                MockUnionComponent {
                    offset: 4,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 2);
        assert_eq!(ex.get(0).offset, 0);
        assert_eq!(ex.get(1).offset, 4);
    }

    #[test]
    fn union_int_big_primitive_absorbs_exactly_covering_smaller_primitives() {
        // field0: one int8 at offset 0 (the "big" primitive, preferred since it's an integer).
        // field1: two int4s exactly covering the same 8 bytes.
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: false },
                },
                MockUnionComponent { offset: 0, field: MockUnionField::Arr { num_elements: 2, elem_len: 4 } },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 1);
        assert_eq!(ex.get(0).dt.get_length(), 8);
    }

    #[test]
    fn union_float_big_primitive_yields_to_exactly_covering_smaller_ints() {
        // Mirror image of the above: the big primitive is a float this time, so the smaller ints
        // that cover it are kept in the refinement instead.
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: true },
                },
                MockUnionComponent { offset: 0, field: MockUnionField::Arr { num_elements: 2, elem_len: 4 } },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 2);
        assert!(!ex.get(0).dt.is_floating_point());
        assert!(!ex.get(1).dt.is_floating_point());
    }

    #[test]
    fn union_partial_overlap_between_members_is_invalid() {
        // field0: one int8 at offset 0. field1: two int6s at offsets 0 and 6 -- the second one
        // spills past field0's 8-byte end boundary (6 + 6 = 12 > 8), an improper overlap.
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: false },
                },
                MockUnionComponent { offset: 0, field: MockUnionField::Arr { num_elements: 2, elem_len: 6 } },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(!ex.is_valid());
    }

    #[test]
    fn union_common_refinement_across_three_members_stays_the_single_big_integer() {
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: false },
                },
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: false },
                },
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 8, floating_point: false },
                },
            ],
        };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(ex.is_valid());
        assert_eq!(ex.size(), 1);
        assert_eq!(ex.get(0).dt.get_length(), 8);
    }

    #[test]
    fn union_common_refinement_fails_when_result_exceeds_max_primitives() {
        let u = MockUnion {
            components: vec![
                MockUnionComponent {
                    offset: 0,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
                MockUnionComponent {
                    offset: 4,
                    field: MockUnionField::Prim { length: 4, floating_point: false },
                },
            ],
        };
        // Refinement produces 2 disjoint primitives, exceeding a max of 1.
        let ex = PrimitiveExtractor::new(&u, false, 0, 1);
        assert!(!ex.is_valid());
    }

    #[test]
    fn union_with_no_components_is_invalid() {
        let u = MockUnion { components: Vec::new() };
        let ex = PrimitiveExtractor::new(&u, false, 0, 8);
        assert!(!ex.is_valid());
    }
}
