//! Port of `ghidra.program.model.data.Undefined`, promoted to a trait because it was selected as
//! a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`. `BuiltIn` itself is not yet ported, so this trait extends
//! [`DataType`] + [`BuiltInDataType`] directly -- the already-ported interfaces `BuiltIn`
//! implements that `Undefined` actually relies on -- mirroring the convention established by
//! [`IntegerDataType`](crate::program::model::data::integer_data_type::IntegerDataType) and
//! [`AbstractFloatDataType`](crate::program::model::data::abstract_float_data_type). `Undefined`
//! declares no instance methods of its own in Java (it exists purely as a shared marker base for
//! the eight `UndefinedNDataType` sibling classes), so the trait body is empty. The protected
//! constructor (`Undefined(String, DataTypeManager)`, which just forwards to
//! `BuiltIn(CategoryPath.ROOT, name, dtm)`) has no Rust equivalent since traits cannot declare
//! constructors or store fields; each concrete implementor is expected to replicate it via
//! [`DataType::get_name`]/[`DataType::get_category_path`].
//!
//! The private `getUndefinedTypes()` cache and the two public factory methods built on top of it
//! (`getUndefinedDataType(int)`, `getUndefinedDataTypes()`) are omitted entirely: they build a
//! registry keyed off concrete sibling types (`Undefined1DataType` .. `Undefined8DataType`,
//! `DefaultDataType`, `ArrayDataType`) that are not yet ported and are unrelated to breaking this
//! cycle, mirroring the precedent set by `AbstractFloatDataType`'s omitted
//! `getFloatDataType`/`getFloatDataTypes` (see that module's docs) -- port them alongside those
//! concrete types instead.
//!
//! `isUndefined`/`isUndefinedArray` *are* ported faithfully, as free functions (`Undefined` itself
//! has no instance methods to attach them to). Both rely on Java `instanceof` checks that have no
//! general downcast on [`DataType`], so -- mirroring the existing `is_array`/`is_pointer`/
//! `is_structure`/`is_union`/`is_typedef` flags -- two new flag methods are added to [`DataType`]:
//! `is_default_data_type` (stands in for `instanceof DefaultDataType`; backed by a new minimal
//! [`DefaultDataType`](crate::program::seam_stubs::DefaultDataType) marker placeholder in
//! `seam_stubs.rs` since the real `DefaultDataType` is not yet ported -- see `STUBS.tsv`) and
//! `is_undefined_type` (stands in for `instanceof Undefined`; backed by this trait directly, now
//! that it exists -- implementors of [`Undefined`] are expected to override it to return `true`).
//! `instanceof Array` + `((Array) dataType).getDataType()` similarly has no downcast available, so
//! a new `into_array` default method (mirroring the existing `into_composite`/
//! `into_array_stringable`) is added to [`DataType`] as well. Both free functions take an owned
//! `Box<dyn DataType>` (rather than a borrow) since checking the array case consumes the value via
//! `into_array`, matching how `into_composite`/`into_array_stringable` are already used elsewhere
//! in this crate (e.g. `CompositeTestUtils::dump`).

use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;

/// Port of `ghidra.program.model.data.Undefined`.
///
/// Identifies an undefined data type. See the module docs for what was ported, added, and
/// omitted.
pub trait Undefined: DataType + BuiltInDataType {}

/// Determine if the specified dataType is either a `DefaultDataType`, an [`Undefined`]
/// data-type, or an Array of Undefined data-types.
///
/// Port of `Undefined.isUndefined(DataType)`.
pub fn is_undefined(data_type: Box<dyn DataType>) -> bool {
    if data_type.is_default_data_type() {
        return true;
    }
    if data_type.is_undefined_type() {
        return true;
    }
    is_undefined_array(data_type)
}

/// Determine if the specified dataType is an undefined array used to represent large undefined
/// data.
///
/// Port of `Undefined.isUndefinedArray(DataType)`.
pub fn is_undefined_array(data_type: Box<dyn DataType>) -> bool {
    match data_type.into_array() {
        Some(array) => {
            let base_type = array.get_data_type();
            base_type.is_undefined_type() || base_type.is_default_data_type()
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::array::Array;
    use crate::program::model::data::data_organization::DataOrganization;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockUndefined1;
    impl DataType for MockUndefined1 {
        fn get_length(&self) -> i32 {
            1
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }
    impl BuiltInDataType for MockUndefined1 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl Undefined for MockUndefined1 {}

    struct MockIntDataType;
    impl DataType for MockIntDataType {
        fn get_length(&self) -> i32 {
            4
        }
    }

    struct MockArrayOf {
        element_len: i32,
        make_element: fn() -> Box<dyn DataType>,
    }
    impl DataType for MockArrayOf {
        fn is_array(&self) -> bool {
            true
        }
        fn into_array(
            self: Box<Self>,
        ) -> Option<Box<dyn crate::program::model::data::array::Array>> {
            Some(self)
        }
    }
    impl Array for MockArrayOf {
        fn get_num_elements(&self) -> i32 {
            4
        }
        fn get_element_length(&self) -> i32 {
            self.element_len
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            (self.make_element)()
        }
    }

    #[test]
    fn undefined_usable_as_trait_object() {
        let u = MockUndefined1;
        let dyn_u: &dyn Undefined = &u;
        assert!(dyn_u.is_undefined_type());
        assert_eq!(dyn_u.get_length(), 1);
    }

    #[test]
    fn is_undefined_true_for_undefined_data_type() {
        assert!(is_undefined(Box::new(MockUndefined1)));
    }

    #[test]
    fn is_undefined_false_for_ordinary_data_type() {
        assert!(!is_undefined(Box::new(MockIntDataType)));
    }

    #[test]
    fn is_undefined_array_true_for_array_of_undefined_elements() {
        let arr = MockArrayOf {
            element_len: 1,
            make_element: || Box::new(MockUndefined1),
        };
        assert!(is_undefined_array(Box::new(arr)));

        let arr2 = MockArrayOf {
            element_len: 1,
            make_element: || Box::new(MockUndefined1),
        };
        assert!(is_undefined(Box::new(arr2)));
    }

    #[test]
    fn is_undefined_array_false_for_array_of_ordinary_elements() {
        let arr = MockArrayOf {
            element_len: 4,
            make_element: || Box::new(MockIntDataType),
        };
        assert!(!is_undefined_array(Box::new(arr)));
    }
}
