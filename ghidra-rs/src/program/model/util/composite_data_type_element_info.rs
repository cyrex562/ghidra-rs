use crate::program::seam_stubs::DataTypeInfoLike;

/// Describes an element within an outer composite data type.
///
/// Port of `ghidra.program.model.util.CompositeDataTypeElementInfo`, which extends
/// `DataTypeInfo`; that superclass is not yet ported, so its getters live on the
/// [`DataTypeInfoLike`] supertrait (see `seam_stubs.rs`) and this trait adds only the
/// element-specific offset. This is expressed as a trait (rather than a struct) because it was
/// selected as a cycle cut-point.
pub trait CompositeDataTypeElementInfo: DataTypeInfoLike {
    /// Stands in for `CompositeDataTypeElementInfo.getDataTypeOffset()`: the offset of this
    /// element within the outer composite data type.
    fn get_data_type_offset(&self) -> i32;

    /// Port of the overridden `equals`: two elements are equal when their offset and their
    /// inherited length/alignment/handle all match. The handle (an opaque `Object` in Java) is
    /// compared by its `Display` form, matching this repo's convention for standing in for
    /// `Object.equals` on opaque identity handles.
    fn data_equals(&self, other: &dyn CompositeDataTypeElementInfo) -> bool {
        self.get_data_type_offset() == other.get_data_type_offset()
            && self.get_data_type_length() == other.get_data_type_length()
            && self.get_data_type_alignment() == other.get_data_type_alignment()
            && self.get_data_type_handle().to_string() == other.get_data_type_handle().to_string()
    }

    /// Port of the overridden `toString`, which renders as
    /// `"<handle>/<alignment>:(<offset>,<length>)"`.
    fn to_display_string(&self) -> String {
        format!(
            "{}/{}:({},{})",
            self.get_data_type_handle(),
            self.get_data_type_alignment(),
            self.get_data_type_offset(),
            self.get_data_type_length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;
    use std::sync::Arc;

    struct MockElementInfo {
        handle: Arc<dyn fmt::Display + Send + Sync>,
        length: i32,
        alignment: i32,
        offset: i32,
    }

    impl DataTypeInfoLike for MockElementInfo {
        fn get_data_type_handle(&self) -> Arc<dyn fmt::Display + Send + Sync> {
            self.handle.clone()
        }

        fn get_data_type_length(&self) -> i32 {
            self.length
        }

        fn get_data_type_alignment(&self) -> i32 {
            self.alignment
        }
    }

    impl CompositeDataTypeElementInfo for MockElementInfo {
        fn get_data_type_offset(&self) -> i32 {
            self.offset
        }
    }

    fn make(handle: &str, offset: i32, length: i32, alignment: i32) -> MockElementInfo {
        MockElementInfo {
            handle: Arc::new(handle.to_string()),
            length,
            alignment,
            offset,
        }
    }

    #[test]
    fn usable_as_trait_object_and_reports_offset() {
        let info: Box<dyn CompositeDataTypeElementInfo> = Box::new(make("myField", 4, 8, 4));
        assert_eq!(info.get_data_type_offset(), 4);
        assert_eq!(info.get_data_type_length(), 8);
        assert_eq!(info.get_data_type_alignment(), 4);
    }

    #[test]
    fn to_display_string_matches_java_format() {
        let info = make("myField", 4, 8, 2);
        assert_eq!(info.to_display_string(), "myField/2:(4,8)");
    }

    #[test]
    fn data_equals_compares_offset_and_inherited_fields() {
        let a = make("myField", 4, 8, 2);
        let b = make("myField", 4, 8, 2);
        let c = make("myField", 12, 8, 2);
        let d = make("otherField", 4, 8, 2);

        assert!(a.data_equals(&b));
        assert!(!a.data_equals(&c), "differing offset must not be equal");
        assert!(!a.data_equals(&d), "differing handle must not be equal");
    }
}
