//! Port of `ghidra.program.model.data.DataTypeObjectComparator`.
//!
//! The Java class is a stateless `Comparator<Object>` singleton
//! (`DataTypeObjectComparator.INSTANCE`) that accepts a mix of [`DataType`]/`String` name
//! arguments, throwing `IllegalArgumentException` for anything else. Rust has no `Object`
//! equivalent; [`DataTypeOrName`] stands in for it as a two-variant enum covering exactly the
//! two cases Java actually handles (`DataType` and `String`), which makes the
//! `IllegalArgumentException` branch unreachable by construction rather than something to
//! reproduce as a runtime check.
//!
//! Mirroring [`DataTypeComparator`](super::data_type_comparator::DataTypeComparator)/
//! [`DataTypeNameComparator`](super::data_type_name_comparator::DataTypeNameComparator) -- this
//! is ported as a unit struct with an associated `compare` function returning
//! [`std::cmp::Ordering`], plus an `INSTANCE` constant mirroring the Java static field.

use std::cmp::Ordering;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_name_comparator::DataTypeNameComparator;

/// Either a [`DataType`] or a plain name string, standing in for the `Object` parameters of
/// `DataTypeObjectComparator.compare(Object, Object)`, which Java accepts as either a `DataType`
/// or a `String` name (see the module docs).
pub enum DataTypeOrName<'a> {
    /// A `DataType`, whose [`DataType::get_name`] supplies the name to compare.
    DataType(&'a dyn DataType),
    /// A plain name string, standing in for a raw `String` lookup key.
    Name(&'a str),
}

impl DataTypeOrName<'_> {
    fn name(&self) -> String {
        match self {
            DataTypeOrName::DataType(dt) => dt.get_name(),
            DataTypeOrName::Name(name) => (*name).to_string(),
        }
    }
}

/// Provides the preferred name-based comparison of data types using
/// [`DataTypeNameComparator`], allowing a mix of [`DataType`] and/or `String` names to be
/// compared.
///
/// Port of `ghidra.program.model.data.DataTypeObjectComparator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataTypeObjectComparator;

impl DataTypeObjectComparator {
    /// Mirrors the Java `public static DataTypeObjectComparator INSTANCE` singleton field.
    pub const INSTANCE: Self = Self;

    /// Port of `DataTypeObjectComparator.compare(Object, Object)`. See the module docs for why
    /// the `IllegalArgumentException` branch has no equivalent here.
    pub fn compare(o1: &DataTypeOrName, o2: &DataTypeOrName) -> Ordering {
        DataTypeNameComparator::compare(&o1.name(), &o2.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};

    struct MockDataType {
        name: String,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
    }

    #[test]
    fn two_data_types_compare_by_name() {
        let a = MockDataType { name: "aaa".to_string() };
        let b = MockDataType { name: "zzz".to_string() };
        assert_eq!(
            DataTypeObjectComparator::compare(&DataTypeOrName::DataType(&a), &DataTypeOrName::DataType(&b)),
            Ordering::Less
        );
        assert_eq!(DataTypeObjectComparator::INSTANCE, DataTypeObjectComparator);
    }

    #[test]
    fn two_names_compare_by_name() {
        assert_eq!(
            DataTypeObjectComparator::compare(&DataTypeOrName::Name("aaa"), &DataTypeOrName::Name("zzz")),
            Ordering::Less
        );
    }

    #[test]
    fn data_type_compares_against_a_name_string_key() {
        let dt = MockDataType { name: "foo".to_string() };
        assert_eq!(
            DataTypeObjectComparator::compare(&DataTypeOrName::DataType(&dt), &DataTypeOrName::Name("foo")),
            Ordering::Equal
        );
        assert_eq!(
            DataTypeObjectComparator::compare(&DataTypeOrName::Name("foo"), &DataTypeOrName::DataType(&dt)),
            Ordering::Equal
        );
    }

    #[test]
    fn name_string_key_compares_before_a_different_data_type() {
        let dt = MockDataType { name: "zzz".to_string() };
        assert_eq!(
            DataTypeObjectComparator::compare(&DataTypeOrName::Name("aaa"), &DataTypeOrName::DataType(&dt)),
            Ordering::Less
        );
    }
}
