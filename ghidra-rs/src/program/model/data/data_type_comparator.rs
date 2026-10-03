//! Port of `ghidra.program.model.data.DataTypeComparator`.
//!
//! The Java class is a stateless `Comparator<DataType>` singleton
//! (`DataTypeComparator.INSTANCE`). Mirroring
//! [`DataTypeNameComparator`](super::data_type_name_comparator::DataTypeNameComparator) -- the
//! sibling comparator this one is built on top of -- this is ported as a unit struct with an
//! associated `compare` function returning [`std::cmp::Ordering`], plus an `INSTANCE` constant
//! mirroring the Java static field.
//!
//! `compare(DataType, DataType)`'s `DataTypeManager`-nullness handling is translated exactly as
//! written, including an easy-to-miss asymmetry: when *both* data types have no
//! [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager) (`dtm1 ==
//! null && dtm2 == null`), the Java falls through its two back-to-back `if` statements to `if
//! (dtm2 == null) return 1;`, so it reports `dt1 > dt2` rather than "equal" -- not the `0` one
//! might expect. This is preserved here rather than "fixed"; see [`compare`] for the exact
//! branch-by-branch mirroring.

use std::cmp::Ordering;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_name_comparator::DataTypeNameComparator;

/// Provides the preferred named-based comparison of [`DataType`] which utilizes
/// [`DataTypeNameComparator`] for a primary [`DataType::get_name`] comparison followed by
/// sub-ordering on [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager)
/// name and [`CategoryPath`](crate::program::model::data::category_path::CategoryPath).
///
/// Port of `ghidra.program.model.data.DataTypeComparator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataTypeComparator;

impl DataTypeComparator {
    /// Mirrors the Java `public static DataTypeComparator INSTANCE` singleton field.
    pub const INSTANCE: Self = Self;

    /// Port of `DataTypeComparator.compare(DataType, DataType)`. See the module docs for the
    /// preserved `dtm1 == null && dtm2 == null` quirk.
    pub fn compare(dt1: &dyn DataType, dt2: &dyn DataType) -> Ordering {
        let name1 = dt1.get_name();
        let name2 = dt2.get_name();

        let name_compare = DataTypeNameComparator::compare(&name1, &name2);
        if name_compare != Ordering::Equal {
            return name_compare;
        }

        let dtm1 = dt1.get_data_type_manager();
        let dtm2 = dt2.get_data_type_manager();

        // Mirrors:
        //   if (dtm1 == null) { if (dtm2 != null) return -1; }
        //   if (dtm2 == null) return 1;
        // Note that when both are null, the first `if` does not return, and the second `if`
        // (dtm2 == null) does -- yielding Greater, not Equal. Preserved faithfully.
        if dtm1.is_none() && dtm2.is_some() {
            return Ordering::Less;
        }
        if dtm2.is_none() {
            return Ordering::Greater;
        }
        let dtm1 = dtm1.expect("checked above: dtm2 is Some, so this branch requires dtm1 Some");
        let dtm2 = dtm2.expect("checked above: dtm2 is Some");

        // Compare DataTypeManager names if datatypes have the same name.
        let compare = dtm1.get_name().cmp(&dtm2.get_name());
        if compare != Ordering::Equal {
            return compare;
        }

        // Compare category paths if they have the same name and DTM.
        let cat_path1 = dt1.get_category_path().get_path();
        let cat_path2 = dt2.get_category_path().get_path();
        cat_path1.cmp(&cat_path2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type_manager::DataTypeManager;

    struct MockDataType {
        name: String,
        category_path: CategoryPath,
        dtm: Option<String>,
    }

    impl MockDataType {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), category_path: ROOT.clone(), dtm: None }
        }
        fn with_dtm(name: &str, dtm_name: &str) -> Self {
            Self { name: name.to_string(), category_path: ROOT.clone(), dtm: Some(dtm_name.to_string()) }
        }
        fn with_category(name: &str, dtm_name: &str, category_path: CategoryPath) -> Self {
            Self { name: name.to_string(), category_path, dtm: Some(dtm_name.to_string()) }
        }
    }

    struct MockDataTypeManager {
        name: String,
    }
    impl DataTypeManager for MockDataTypeManager {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            self.category_path.clone()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.dtm.clone().map(|n| Box::new(MockDataTypeManager { name: n }) as Box<dyn DataTypeManager>)
        }
    }

    #[test]
    fn different_names_order_by_name() {
        let a = MockDataType::new("aaa");
        let b = MockDataType::new("zzz");
        assert_eq!(DataTypeComparator::compare(&a, &b), Ordering::Less);
        assert_eq!(DataTypeComparator::compare(&b, &a), Ordering::Greater);
        assert_eq!(DataTypeComparator::INSTANCE, DataTypeComparator);
    }

    #[test]
    fn same_name_no_manager_on_either_side_is_greater_not_equal() {
        // Preserved Java quirk: both DataTypeManagers null falls through to `return 1`.
        let a = MockDataType::new("int");
        let b = MockDataType::new("int");
        assert_eq!(DataTypeComparator::compare(&a, &b), Ordering::Greater);
    }

    #[test]
    fn same_name_dtm_present_beats_dtm_absent() {
        let with_dtm = MockDataType::with_dtm("int", "archive");
        let without_dtm = MockDataType::new("int");
        // dtm1 == null && dtm2 != null -> Less
        assert_eq!(DataTypeComparator::compare(&without_dtm, &with_dtm), Ordering::Less);
        // dtm2 == null -> Greater
        assert_eq!(DataTypeComparator::compare(&with_dtm, &without_dtm), Ordering::Greater);
    }

    #[test]
    fn same_name_orders_by_manager_name_when_both_present() {
        let a = MockDataType::with_dtm("int", "aaa-archive");
        let b = MockDataType::with_dtm("int", "zzz-archive");
        assert_eq!(DataTypeComparator::compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn same_name_and_manager_orders_by_category_path() {
        let cat_a = CategoryPath::parse("/aaa").unwrap();
        let cat_b = CategoryPath::parse("/zzz").unwrap();
        let a = MockDataType::with_category("int", "archive", cat_a);
        let b = MockDataType::with_category("int", "archive", cat_b);
        assert_eq!(DataTypeComparator::compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn identical_data_types_are_equal() {
        let a = MockDataType::with_dtm("int", "archive");
        let b = MockDataType::with_dtm("int", "archive");
        assert_eq!(DataTypeComparator::compare(&a, &b), Ordering::Equal);
    }
}
