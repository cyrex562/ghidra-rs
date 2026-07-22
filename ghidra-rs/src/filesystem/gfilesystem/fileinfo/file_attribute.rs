use crate::filesystem::seam_stubs::FileAttributeTypeLike;

/// Behavior of a `(type, type_display_string, value)` tuple, mirroring the public API of
/// `ghidra.formats.gfilesystem.fileinfo.FileAttribute<T>`.
///
/// The Java class is a concrete final value type, but it is a cycle cut-point here: it depends
/// on `FileAttributeType`, which is not yet ported. Modeling it as a trait lets callers depend
/// on this seam instead of a concrete struct while `FileAttributeType` is stubbed out (see
/// [`FileAttributeTypeLike`]).
pub trait FileAttributeLike<T> {
    /// Returns the type of this instance.
    fn attribute_type(&self) -> &dyn FileAttributeTypeLike;

    /// Returns the display name of this instance. Usually derived from the attribute type's
    /// own display name.
    fn attribute_display_name(&self) -> &str;

    /// Returns the value.
    fn attribute_value(&self) -> &T;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAttributeType(&'static str);

    impl FileAttributeTypeLike for MockAttributeType {
        fn display_name(&self) -> &str {
            self.0
        }
    }

    struct SimpleFileAttribute<T> {
        attribute_type: Box<dyn FileAttributeTypeLike>,
        attribute_display_name: String,
        attribute_value: T,
    }

    impl<T> FileAttributeLike<T> for SimpleFileAttribute<T> {
        fn attribute_type(&self) -> &dyn FileAttributeTypeLike {
            self.attribute_type.as_ref()
        }

        fn attribute_display_name(&self) -> &str {
            &self.attribute_display_name
        }

        fn attribute_value(&self) -> &T {
            &self.attribute_value
        }
    }

    #[test]
    fn accessors_return_expected_values_through_dyn_object() {
        let attr: Box<dyn FileAttributeLike<u64>> = Box::new(SimpleFileAttribute {
            attribute_type: Box::new(MockAttributeType("Size")),
            attribute_display_name: "Size".to_string(),
            attribute_value: 4096u64,
        });

        assert_eq!(attr.attribute_type().display_name(), "Size");
        assert_eq!(attr.attribute_display_name(), "Size");
        assert_eq!(*attr.attribute_value(), 4096u64);
    }

    #[test]
    fn custom_display_name_overrides_type_display_name() {
        let attr: Box<dyn FileAttributeLike<String>> = Box::new(SimpleFileAttribute {
            attribute_type: Box::new(MockAttributeType("Other attribute")),
            attribute_display_name: "My Custom Field".to_string(),
            attribute_value: "hello".to_string(),
        });

        assert_eq!(attr.attribute_type().display_name(), "Other attribute");
        assert_eq!(attr.attribute_display_name(), "My Custom Field");
        assert_eq!(attr.attribute_value(), "hello");
    }
}
