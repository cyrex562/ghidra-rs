use crate::util::xml::xml_parse_exception::XmlParseException;
use std::fmt;

/// Data-type class for the purpose of assigning storage.
/// Port of `ghidra.program.model.lang.StorageClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageClass {
    /// General purpose
    General,
    /// Floating-point data-types
    Float,
    /// Pointer data-types
    Ptr,
    /// Class for hidden return values
    HiddenRet,
    /// Vector data-types
    Vector,
    /// Architecture specific class 1
    Class1,
    /// Architecture specific class 2
    Class2,
    /// Architecture specific class 3
    Class3,
    /// Architecture specific class 4
    Class4,
}

impl StorageClass {
    /// Returns the numeric value for comparing storage classes.
    pub fn value(&self) -> i32 {
        match self {
            StorageClass::General => 0,
            StorageClass::Float => 1,
            StorageClass::Ptr => 2,
            StorageClass::HiddenRet => 3,
            StorageClass::Vector => 4,
            StorageClass::Class1 => 100,
            StorageClass::Class2 => 101,
            StorageClass::Class3 => 102,
            StorageClass::Class4 => 103,
        }
    }

    /// Returns the string name for marshaling.
    pub fn name(&self) -> &'static str {
        match self {
            StorageClass::General => "general",
            StorageClass::Float => "float",
            StorageClass::Ptr => "ptr",
            StorageClass::HiddenRet => "hiddenret",
            StorageClass::Vector => "vector",
            StorageClass::Class1 => "class1",
            StorageClass::Class2 => "class2",
            StorageClass::Class3 => "class3",
            StorageClass::Class4 => "class4",
        }
    }

    /// Parses a `StorageClass` from a string name.
    ///
    /// # Errors
    ///
    /// Returns `XmlParseException` if the string does not match any known storage class.
    pub(crate) fn from_str(val: &str) -> Result<StorageClass, XmlParseException> {
        match val {
            "general" => Ok(StorageClass::General),
            "float" => Ok(StorageClass::Float),
            "ptr" => Ok(StorageClass::Ptr),
            "hiddenret" => Ok(StorageClass::HiddenRet),
            "vector" => Ok(StorageClass::Vector),
            "class1" => Ok(StorageClass::Class1),
            "class2" => Ok(StorageClass::Class2),
            "class3" => Ok(StorageClass::Class3),
            "class4" => Ok(StorageClass::Class4),
            _ => Err(XmlParseException::new(format!("Unknown type class: {}", val))),
        }
    }
}

impl fmt::Display for StorageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_value() {
        assert_eq!(StorageClass::General.value(), 0);
    }

    #[test]
    fn float_value() {
        assert_eq!(StorageClass::Float.value(), 1);
    }

    #[test]
    fn ptr_value() {
        assert_eq!(StorageClass::Ptr.value(), 2);
    }

    #[test]
    fn hidden_ret_value() {
        assert_eq!(StorageClass::HiddenRet.value(), 3);
    }

    #[test]
    fn vector_value() {
        assert_eq!(StorageClass::Vector.value(), 4);
    }

    #[test]
    fn class1_value() {
        assert_eq!(StorageClass::Class1.value(), 100);
    }

    #[test]
    fn class2_value() {
        assert_eq!(StorageClass::Class2.value(), 101);
    }

    #[test]
    fn class3_value() {
        assert_eq!(StorageClass::Class3.value(), 102);
    }

    #[test]
    fn class4_value() {
        assert_eq!(StorageClass::Class4.value(), 103);
    }

    #[test]
    fn general_name() {
        assert_eq!(StorageClass::General.name(), "general");
    }

    #[test]
    fn float_name() {
        assert_eq!(StorageClass::Float.name(), "float");
    }

    #[test]
    fn ptr_name() {
        assert_eq!(StorageClass::Ptr.name(), "ptr");
    }

    #[test]
    fn hidden_ret_name() {
        assert_eq!(StorageClass::HiddenRet.name(), "hiddenret");
    }

    #[test]
    fn vector_name() {
        assert_eq!(StorageClass::Vector.name(), "vector");
    }

    #[test]
    fn class1_name() {
        assert_eq!(StorageClass::Class1.name(), "class1");
    }

    #[test]
    fn class2_name() {
        assert_eq!(StorageClass::Class2.name(), "class2");
    }

    #[test]
    fn class3_name() {
        assert_eq!(StorageClass::Class3.name(), "class3");
    }

    #[test]
    fn class4_name() {
        assert_eq!(StorageClass::Class4.name(), "class4");
    }

    #[test]
    fn general_to_string() {
        assert_eq!(StorageClass::General.to_string(), "general");
    }

    #[test]
    fn float_to_string() {
        assert_eq!(StorageClass::Float.to_string(), "float");
    }

    #[test]
    fn ptr_to_string() {
        assert_eq!(StorageClass::Ptr.to_string(), "ptr");
    }

    #[test]
    fn hidden_ret_to_string() {
        assert_eq!(StorageClass::HiddenRet.to_string(), "hiddenret");
    }

    #[test]
    fn vector_to_string() {
        assert_eq!(StorageClass::Vector.to_string(), "vector");
    }

    #[test]
    fn class1_to_string() {
        assert_eq!(StorageClass::Class1.to_string(), "class1");
    }

    #[test]
    fn class2_to_string() {
        assert_eq!(StorageClass::Class2.to_string(), "class2");
    }

    #[test]
    fn class3_to_string() {
        assert_eq!(StorageClass::Class3.to_string(), "class3");
    }

    #[test]
    fn class4_to_string() {
        assert_eq!(StorageClass::Class4.to_string(), "class4");
    }

    #[test]
    fn parse_general() {
        assert_eq!(StorageClass::from_str("general").unwrap(), StorageClass::General);
    }

    #[test]
    fn parse_float() {
        assert_eq!(StorageClass::from_str("float").unwrap(), StorageClass::Float);
    }

    #[test]
    fn parse_ptr() {
        assert_eq!(StorageClass::from_str("ptr").unwrap(), StorageClass::Ptr);
    }

    #[test]
    fn parse_hiddenret() {
        assert_eq!(StorageClass::from_str("hiddenret").unwrap(), StorageClass::HiddenRet);
    }

    #[test]
    fn parse_vector() {
        assert_eq!(StorageClass::from_str("vector").unwrap(), StorageClass::Vector);
    }

    #[test]
    fn parse_class1() {
        assert_eq!(StorageClass::from_str("class1").unwrap(), StorageClass::Class1);
    }

    #[test]
    fn parse_class2() {
        assert_eq!(StorageClass::from_str("class2").unwrap(), StorageClass::Class2);
    }

    #[test]
    fn parse_class3() {
        assert_eq!(StorageClass::from_str("class3").unwrap(), StorageClass::Class3);
    }

    #[test]
    fn parse_class4() {
        assert_eq!(StorageClass::from_str("class4").unwrap(), StorageClass::Class4);
    }

    #[test]
    fn parse_all_variants() {
        for variant in &[
            StorageClass::General,
            StorageClass::Float,
            StorageClass::Ptr,
            StorageClass::HiddenRet,
            StorageClass::Vector,
            StorageClass::Class1,
            StorageClass::Class2,
            StorageClass::Class3,
            StorageClass::Class4,
        ] {
            let name = variant.name();
            let parsed = StorageClass::from_str(name).unwrap();
            assert_eq!(parsed, *variant);
        }
    }

    #[test]
    fn parse_invalid_returns_error() {
        let result = StorageClass::from_str("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown type class"));
    }

    #[test]
    fn parse_empty_string_returns_error() {
        assert!(StorageClass::from_str("").is_err());
    }

    #[test]
    fn parse_case_sensitive() {
        assert!(StorageClass::from_str("GENERAL").is_err());
        assert!(StorageClass::from_str("Float").is_err());
    }
}
