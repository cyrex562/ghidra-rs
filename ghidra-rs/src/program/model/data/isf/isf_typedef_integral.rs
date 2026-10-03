use crate::program::model::data::typedef::TypeDef;
use super::{IsfObject, AbstractIsfObject};

/// Represents an integral type definition in ISF format.
///
/// Mirrors `IsfTypedefIntegral` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds the size of the typedef (in bytes).
///
/// The `abstract_isf_object` field is marked with `#[serde(skip)]` to match the Java
/// `@Exclude` annotation on those parent fields.
#[derive(Debug, Clone)]
pub struct IsfTypedefIntegral {
    pub abstract_isf_object: AbstractIsfObject,
    pub size: Option<i32>,
}

impl IsfTypedefIntegral {
    /// Creates a new `IsfTypedefIntegral` from a `TypeDef`.
    ///
    /// Extracts metadata from the provided typedef via the parent `AbstractIsfObject`,
    /// and sets `size` to the typedef's length in bytes.
    ///
    /// Mirrors the Java constructor behavior, which calls `super(td)` and then
    /// initializes the `size` field.
    pub fn new(td: &dyn TypeDef) -> Self {
        let size = td.get_length();
        Self {
            abstract_isf_object: AbstractIsfObject::new(Some(td)),
            size: if size > 0 { Some(size) } else { None },
        }
    }
}

impl IsfObject for IsfTypedefIntegral {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    struct MockTypeDef {
        name: String,
        category_path: String,
        length: i32,
    }

    impl MockTypeDef {
        fn new(name: &str, path: &str, length: i32) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
                length,
            }
        }
    }

    impl DataType for MockTypeDef {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::parse(&self.category_path).unwrap()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    impl TypeDef for MockTypeDef {
        fn is_auto_named(&self) -> bool {
            false
        }

        fn enable_auto_naming(&mut self) {}

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(Self {
                name: self.name.clone(),
                category_path: self.category_path.clone(),
                length: self.length,
            })
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(Self {
                name: self.name.clone(),
                category_path: self.category_path.clone(),
                length: self.length,
            })
        }
    }

    #[test]
    fn new_creates_struct_from_typedef() {
        let td = MockTypeDef::new("MyTypedef", "/Category", 4);
        let isf = IsfTypedefIntegral::new(&td);
        assert_eq!(isf.size, Some(4));
    }

    #[test]
    fn size_is_some_when_length_positive() {
        let td = MockTypeDef::new("TypeA", "/Types", 8);
        let isf = IsfTypedefIntegral::new(&td);
        assert_eq!(isf.size, Some(8));
    }

    #[test]
    fn size_is_none_when_length_zero() {
        let td = MockTypeDef::new("TypeB", "/Types", 0);
        let isf = IsfTypedefIntegral::new(&td);
        assert_eq!(isf.size, None);
    }

    #[test]
    fn size_is_none_when_length_negative() {
        let td = MockTypeDef::new("TypeC", "/Types", -1);
        let isf = IsfTypedefIntegral::new(&td);
        assert_eq!(isf.size, None);
    }

    #[test]
    fn abstract_isf_object_inherits_typedef_metadata() {
        let td = MockTypeDef::new("IntegralType", "/Integral/Types", 2);
        let isf = IsfTypedefIntegral::new(&td);
        assert_eq!(isf.abstract_isf_object.name, Some("IntegralType".to_string()));
        assert_eq!(
            isf.abstract_isf_object.location,
            Some("/Integral/Types".to_string())
        );
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let td = MockTypeDef::new("Type", "/", 4);
        let isf = IsfTypedefIntegral::new(&td);
        accepts_isf_object(&isf);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let td = MockTypeDef::new("Type1", "/Path", 4);
        let isf1 = IsfTypedefIntegral::new(&td);
        let isf2 = isf1.clone();
        assert_eq!(isf1.size, isf2.size);
        assert_eq!(isf1.abstract_isf_object.name, isf2.abstract_isf_object.name);
    }

    #[test]
    fn debug_formatting() {
        let td = MockTypeDef::new("T", "/", 4);
        let isf = IsfTypedefIntegral::new(&td);
        let debug_str = format!("{:?}", isf);
        assert!(debug_str.contains("IsfTypedefIntegral"));
    }

    #[test]
    fn multiple_typedefs_have_independent_sizes() {
        let td1 = MockTypeDef::new("Type1", "/", 2);
        let td2 = MockTypeDef::new("Type2", "/", 8);

        let isf1 = IsfTypedefIntegral::new(&td1);
        let isf2 = IsfTypedefIntegral::new(&td2);

        assert_eq!(isf1.size, Some(2));
        assert_eq!(isf2.size, Some(8));
    }
}
