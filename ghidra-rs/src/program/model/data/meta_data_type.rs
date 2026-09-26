//! Port of `ghidra.program.model.data.MetaDataType`.
//!
//! The Java type is a closed `enum` with ten constants ordered from least to most "specific"
//! (`VOID, UNKNOWN, INT, UINT, BOOL, CODE, FLOAT, PTR, ARRAY, STRUCT`), consulted purely by
//! `compareTo` (ordinal order) in [`get_most_specific_data_type`]. It carries no per-variant
//! state and is never subclassed/implemented elsewhere, so -- unlike this crate's other
//! `promoted to a trait` Java-enum ports (e.g.
//! [`PointerType`](super::pointer_type::PointerType), which needed a trait because each variant
//! carries a distinct package-private `int value`) -- a plain Rust `enum` is the faithful,
//! idiomatic shape here: deriving [`Ord`] on the variants in the same declaration order
//! reproduces Java's ordinal `compareTo` exactly, with no trait indirection needed.
//!
//! `getMeta(DataType)` is ported as the free function [`get_meta`]. Its `instanceof` chain relies
//! on marker predicates already on [`DataType`] (`is_typedef`/`typedef_base_data_type`,
//! `is_default_data_type`, `is_undefined_type`, `is_integer_type`/`is_signed_integer_type`,
//! `is_boolean_type`, `is_pointer`, `is_array`, `is_structure`, `is_floating_point`,
//! `is_function_definition_type`, `as_enum`), plus two new ones grown here following this
//! crate's established convention for growing a defaulted `instanceof`-stand-in marker when
//! porting needs one that does not yet exist: [`DataType::is_array_stringable_type`] (`instanceof
//! ArrayStringable`) and [`DataType::is_string_type`] (`instanceof AbstractStringDataType`) --
//! see their own doc comments.
//!
//! `getMostSpecificDataType(DataType, DataType)` is ported as [`get_most_specific_data_type`].
//! Java's mutable `a`/`b` loop locals (reassigned to drill into a shared `Pointer`/`Array` layer
//! on a tie) are restructured here as a private recursive [`compare_specificity`] helper over
//! borrowed `Option<&dyn DataType>`: recursion naturally keeps each drilled-into `Pointer::
//! get_data_type`/`Array::get_data_type` owned `Box<dyn DataType>` alive only as long as its own
//! stack frame needs it, which sidesteps the self-referential-across-loop-iterations borrow that
//! a literal `loop` translation would require. `get_most_specific_data_type` itself then returns
//! whichever of the two *original* top-level arguments (not the drilled-into pointee/element)
//! [`compare_specificity`] found more specific, matching the Java `aCopy`/`bCopy` locals.
//!
//! The `PTR` branch does not defensively re-check `instanceof Pointer` after the typedef unwrap
//! (Java casts directly, trusting that `getMeta` already established it): this port instead
//! treats a failed [`DataType::as_pointer`] downcast as a tie (falls through to `Ordering::Equal`,
//! i.e. "return the first argument", matching Java's `break`-driven fallthrough elsewhere) rather
//! than panicking, which is strictly safer than the Java original without changing behavior for
//! any input that actually satisfies the invariant `getMeta` establishes.

use std::cmp::Ordering;

use crate::program::model::data::data_type::DataType;

/// The kind of a [`DataType`], ordered from least to most "specific".
///
/// Port of the Java `enum MetaDataType`. See the module docs for why this is a plain enum rather
/// than a trait, despite most Java-enum ports in this crate being promoted to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetaDataType {
    /// Port of `MetaDataType.VOID`: the `void` data-type.
    Void,
    /// Port of `MetaDataType.UNKNOWN`: an unknown/undefined data-type.
    Unknown,
    /// Port of `MetaDataType.INT`: signed integer.
    Int,
    /// Port of `MetaDataType.UINT`: unsigned integer.
    Uint,
    /// Port of `MetaDataType.BOOL`: boolean.
    Bool,
    /// Port of `MetaDataType.CODE`: executable code.
    Code,
    /// Port of `MetaDataType.FLOAT`: floating-point.
    Float,
    /// Port of `MetaDataType.PTR`: pointer.
    Ptr,
    /// Port of `MetaDataType.ARRAY`: array.
    Array,
    /// Port of `MetaDataType.STRUCT`: structured data-type.
    Struct,
}

/// Port of `MetaDataType.getMeta(DataType)`.
pub fn get_meta(dt: &dyn DataType) -> MetaDataType {
    let base_holder;
    let effective: &dyn DataType = if dt.is_typedef() {
        base_holder = dt.typedef_base_data_type();
        base_holder.as_deref().unwrap_or(dt)
    } else {
        dt
    };

    if effective.is_default_data_type() || effective.is_undefined_type() {
        return MetaDataType::Unknown;
    }
    if effective.is_integer_type() {
        if effective.is_boolean_type() {
            return MetaDataType::Bool;
        }
        if effective.is_signed_integer_type() {
            return MetaDataType::Int;
        }
        return MetaDataType::Uint;
    }
    if effective.is_pointer() {
        return MetaDataType::Ptr;
    }
    if effective.is_array() {
        return MetaDataType::Array;
    }
    if effective.is_structure() {
        return MetaDataType::Struct;
    }
    if effective.is_floating_point() {
        return MetaDataType::Float;
    }
    if effective.is_array_stringable_type() {
        return MetaDataType::Int;
    }
    if effective.is_function_definition_type() {
        return MetaDataType::Code;
    }
    if effective.as_enum().is_some() {
        return MetaDataType::Uint;
    }
    if effective.is_string_type() {
        return MetaDataType::Array;
    }
    MetaDataType::Struct
}

/// Recursive core of `MetaDataType.getMostSpecificDataType(DataType, DataType)`'s tie-breaking
/// loop; see the module docs for why this is recursive rather than a literal loop translation.
/// Returns whether `a` is less/equal/more specific than `b`, drilling into a shared `Pointer`/
/// `Array` layer on a [`MetaDataType`] tie exactly as the Java `for(;;)` loop does.
fn compare_specificity(a: Option<&dyn DataType>, b: Option<&dyn DataType>) -> Ordering {
    let (da, db) = match (a, b) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Less,
        (Some(_), None) => return Ordering::Greater,
        (Some(da), Some(db)) => (da, db),
    };

    let ma = get_meta(da);
    let mb = get_meta(db);
    match ma.cmp(&mb) {
        Ordering::Equal => {}
        other => return other,
    }

    if ma == MetaDataType::Ptr {
        let base_a_holder = if da.is_typedef() { da.typedef_base_data_type() } else { None };
        let eff_a = base_a_holder.as_deref().unwrap_or(da);
        let base_b_holder = if db.is_typedef() { db.typedef_base_data_type() } else { None };
        let eff_b = base_b_holder.as_deref().unwrap_or(db);

        // Java casts directly here, trusting `getMeta`'s invariant; see the module docs for why
        // a failed downcast falls through to `Equal` here instead.
        let (Some(pa), Some(pb)) = (eff_a.as_pointer(), eff_b.as_pointer()) else {
            return Ordering::Equal;
        };
        let next_a = pa.get_data_type();
        let next_b = pb.get_data_type();
        compare_specificity(next_a.as_deref(), next_b.as_deref())
    } else if ma == MetaDataType::Array {
        let base_a_holder = if da.is_typedef() { da.typedef_base_data_type() } else { None };
        let eff_a = base_a_holder.as_deref().unwrap_or(da);
        let base_b_holder = if db.is_typedef() { db.typedef_base_data_type() } else { None };
        let eff_b = base_b_holder.as_deref().unwrap_or(db);

        let (Some(arr_a), Some(arr_b)) = (eff_a.as_array(), eff_b.as_array()) else {
            return Ordering::Equal; // `break` in Java: neither drilled further, return aCopy
        };
        let next_a = arr_a.get_data_type();
        let next_b = arr_b.get_data_type();
        compare_specificity(Some(next_a.as_ref()), Some(next_b.as_ref()))
    } else {
        Ordering::Equal // `break` in Java
    }
}

/// Port of `MetaDataType.getMostSpecificDataType(DataType, DataType)`. Returns whichever of `a`/
/// `b` is more specific (see [`MetaDataType`]'s variant ordering), drilling through matching
/// `Pointer`/`Array` layers to break ties; `a` wins on an exact tie (matching the Java
/// `return aCopy;` fallthrough). Either argument may be `None`, standing in for Java `null` --
/// the other side wins outright, mirroring the loop's `if (a == null) return bCopy;`/`if (b ==
/// null) return aCopy;` checks (which also apply on later iterations, after drilling into an
/// empty pointer/array).
pub fn get_most_specific_data_type<'a>(
    a: Option<&'a dyn DataType>,
    b: Option<&'a dyn DataType>,
) -> Option<&'a dyn DataType> {
    match compare_specificity(a, b) {
        Ordering::Less => b,
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array::Array;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::pointer::Pointer;

    #[derive(Clone)]
    struct SimpleDataType {
        name: &'static str,
        length: i32,
        is_ptr: bool,
        is_arr: bool,
        is_struct: bool,
        is_float: bool,
        is_int: bool,
        is_signed: bool,
        is_undefined: bool,
    }

    impl SimpleDataType {
        fn plain(name: &'static str) -> Self {
            Self {
                name,
                length: 1,
                is_ptr: false,
                is_arr: false,
                is_struct: false,
                is_float: false,
                is_int: false,
                is_signed: false,
                is_undefined: false,
            }
        }
    }

    impl DataType for SimpleDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_pointer(&self) -> bool {
            self.is_ptr
        }
        fn is_array(&self) -> bool {
            self.is_arr
        }
        fn is_structure(&self) -> bool {
            self.is_struct
        }
        fn is_floating_point(&self) -> bool {
            self.is_float
        }
        fn is_integer_type(&self) -> bool {
            self.is_int
        }
        fn is_signed_integer_type(&self) -> bool {
            self.is_signed
        }
        fn is_undefined_type(&self) -> bool {
            self.is_undefined
        }
    }

    struct SimplePointer {
        name: &'static str,
        pointee: Option<SimpleDataType>,
    }
    impl DataType for SimplePointer {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
        fn is_pointer(&self) -> bool {
            true
        }
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for SimplePointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.pointee.clone().map(|dt| Box::new(dt) as Box<dyn DataType>)
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not exercised by these tests")
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct SimpleArray {
        name: &'static str,
        element: SimpleDataType,
    }
    impl DataType for SimpleArray {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
        fn is_array(&self) -> bool {
            true
        }
        fn as_array(&self) -> Option<&dyn Array> {
            Some(self)
        }
    }
    impl Array for SimpleArray {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.element.clone())
        }
        fn get_element_length(&self) -> i32 {
            self.element.get_length()
        }
        fn get_num_elements(&self) -> i32 {
            1
        }
    }

    #[test]
    fn meta_ordering_matches_java_ordinal_order() {
        assert!(MetaDataType::Void < MetaDataType::Unknown);
        assert!(MetaDataType::Unknown < MetaDataType::Int);
        assert!(MetaDataType::Int < MetaDataType::Uint);
        assert!(MetaDataType::Uint < MetaDataType::Bool);
        assert!(MetaDataType::Bool < MetaDataType::Code);
        assert!(MetaDataType::Code < MetaDataType::Float);
        assert!(MetaDataType::Float < MetaDataType::Ptr);
        assert!(MetaDataType::Ptr < MetaDataType::Array);
        assert!(MetaDataType::Array < MetaDataType::Struct);
    }

    #[test]
    fn get_meta_classifies_undefined_as_unknown() {
        let mut dt = SimpleDataType::plain("undefined1");
        dt.is_undefined = true;
        assert_eq!(get_meta(&dt), MetaDataType::Unknown);
    }

    #[test]
    fn get_meta_classifies_signed_and_unsigned_integers() {
        let mut signed = SimpleDataType::plain("int");
        signed.is_int = true;
        signed.is_signed = true;
        assert_eq!(get_meta(&signed), MetaDataType::Int);

        let mut unsigned = SimpleDataType::plain("uint");
        unsigned.is_int = true;
        assert_eq!(get_meta(&unsigned), MetaDataType::Uint);
    }

    #[test]
    fn get_meta_classifies_pointer_array_struct_float() {
        let mut ptr = SimpleDataType::plain("ptr");
        ptr.is_ptr = true;
        assert_eq!(get_meta(&ptr), MetaDataType::Ptr);

        let mut arr = SimpleDataType::plain("arr");
        arr.is_arr = true;
        assert_eq!(get_meta(&arr), MetaDataType::Array);

        let mut st = SimpleDataType::plain("struct");
        st.is_struct = true;
        assert_eq!(get_meta(&st), MetaDataType::Struct);

        let mut f = SimpleDataType::plain("float");
        f.is_float = true;
        assert_eq!(get_meta(&f), MetaDataType::Float);
    }

    #[test]
    fn get_meta_falls_back_to_struct_for_anything_unrecognized() {
        let dt = SimpleDataType::plain("mystery");
        assert_eq!(get_meta(&dt), MetaDataType::Struct);
    }

    #[test]
    fn most_specific_prefers_the_higher_meta_type() {
        let mut int_dt = SimpleDataType::plain("int");
        int_dt.is_int = true;
        int_dt.is_signed = true;
        let mut ptr_dt = SimpleDataType::plain("ptr");
        ptr_dt.is_ptr = true;

        let winner = get_most_specific_data_type(Some(&int_dt), Some(&ptr_dt)).unwrap();
        assert_eq!(winner.get_name(), "ptr");
        let winner2 = get_most_specific_data_type(Some(&ptr_dt), Some(&int_dt)).unwrap();
        assert_eq!(winner2.get_name(), "ptr");
    }

    #[test]
    fn most_specific_returns_the_non_null_side() {
        let mut int_dt = SimpleDataType::plain("int");
        int_dt.is_int = true;
        assert_eq!(
            get_most_specific_data_type(None, Some(&int_dt)).unwrap().get_name(),
            "int"
        );
        assert_eq!(
            get_most_specific_data_type(Some(&int_dt), None).unwrap().get_name(),
            "int"
        );
        assert!(get_most_specific_data_type(None, None).is_none());
    }

    #[test]
    fn most_specific_ties_break_toward_the_first_argument() {
        let a = SimpleDataType::plain("struct-a");
        let b = SimpleDataType::plain("struct-b");
        // Both classify as MetaDataType::Struct (the fallback) -> exact tie -> `a` wins.
        assert_eq!(get_most_specific_data_type(Some(&a), Some(&b)).unwrap().get_name(), "struct-a");
    }

    #[test]
    fn most_specific_drills_through_matching_pointer_layers() {
        let mut inner_int = SimpleDataType::plain("int");
        inner_int.is_int = true;
        inner_int.is_signed = true;
        let ptr_to_int = SimplePointer { name: "int *", pointee: Some(inner_int) };

        let mut inner_uint = SimpleDataType::plain("uint");
        inner_uint.is_int = true;
        let ptr_to_uint = SimplePointer { name: "uint *", pointee: Some(inner_uint) };

        // Both are pointers (tie at the top level); drilling in, per the Java enum's declared
        // ordinal order (INT, then UINT), UINT ranks as "more specific" than INT.
        let winner = get_most_specific_data_type(Some(&ptr_to_int), Some(&ptr_to_uint)).unwrap();
        assert_eq!(winner.get_name(), "uint *");
    }

    #[test]
    fn most_specific_drills_through_matching_array_layers() {
        let mut inner_int = SimpleDataType::plain("int");
        inner_int.is_int = true;
        inner_int.is_signed = true;
        let arr_of_int = SimpleArray { name: "int[1]", element: inner_int };

        let mut inner_uint = SimpleDataType::plain("uint");
        inner_uint.is_int = true;
        let arr_of_uint = SimpleArray { name: "uint[1]", element: inner_uint };

        // As above: UINT outranks INT in the Java enum's declared ordinal order.
        let winner = get_most_specific_data_type(Some(&arr_of_int), Some(&arr_of_uint)).unwrap();
        assert_eq!(winner.get_name(), "uint[1]");
    }
}
