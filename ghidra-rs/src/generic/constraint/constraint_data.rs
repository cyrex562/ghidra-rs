use std::collections::HashMap;

use crate::util::xml::xml_attribute_exception::XmlAttributeException;

/// Convenience class that converts XML attributes into typed property values.
pub struct ConstraintData {
    map: HashMap<String, String>,
}

impl ConstraintData {
    pub fn new(mappings: HashMap<String, String>) -> Self {
        Self { map: mappings }
    }

    /// Returns the string value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing.
    pub fn get_string(&self, name: &str) -> String {
        self.get_value(name, "string")
    }

    /// Returns true if the given attribute name has a value.
    pub fn has_value(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Returns the int value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing or does not contain a valid int value.
    pub fn get_int(&self, name: &str) -> i32 {
        let value = self.get_value(name, "int");
        value.parse().unwrap_or_else(|_| {
            panic!(
                "{}",
                XmlAttributeException::new(format!(
                    "Expected int value for attribute \"{}\", but was \"{}\"",
                    name, value
                ))
            )
        })
    }

    /// Returns the long value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing or does not contain a valid long value.
    pub fn get_long(&self, name: &str) -> i64 {
        let value = self.get_value(name, "long");
        value.parse().unwrap_or_else(|_| {
            panic!(
                "{}",
                XmlAttributeException::new(format!(
                    "Expected long value for attribute \"{}\", but was \"{}\"",
                    name, value
                ))
            )
        })
    }

    /// Returns the boolean value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing or does not contain a valid boolean value.
    pub fn get_boolean(&self, name: &str) -> bool {
        let value = self.get_value(name, "boolean");
        let value = value.to_lowercase();
        if value == "true" {
            return true;
        }
        if value == "false" {
            return false;
        }
        panic!(
            "{}",
            XmlAttributeException::new(format!(
                "Expected boolean value for attribute \"{}\", but was \"{}\"",
                name, value
            ))
        )
    }

    /// Returns the float value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing or does not contain a valid float value.
    pub fn get_float(&self, name: &str) -> f32 {
        let value = self.get_value(name, "float");
        value.parse().unwrap_or_else(|_| {
            panic!(
                "{}",
                XmlAttributeException::new(format!(
                    "Expected float value for attribute \"{}\", but was \"{}\"",
                    name, value
                ))
            )
        })
    }

    /// Returns the double value for the given attribute name.
    ///
    /// # Panics
    ///
    /// Panics if the attribute is missing or does not contain a valid double value.
    pub fn get_double(&self, name: &str) -> f64 {
        let value = self.get_value(name, "double");
        value.parse().unwrap_or_else(|_| {
            panic!(
                "{}",
                XmlAttributeException::new(format!(
                    "Expected double value for attribute \"{}\", but was \"{}\"",
                    name, value
                ))
            )
        })
    }

    fn get_value(&self, name: &str, type_name: &str) -> String {
        match self.map.get(name) {
            Some(value) => value.clone(),
            None => panic!(
                "{}",
                XmlAttributeException::new(format!(
                    "Missing {} value for attribute \"{}\"",
                    type_name, name
                ))
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(pairs: &[(&str, &str)]) -> ConstraintData {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        ConstraintData::new(map)
    }

    #[test]
    fn get_string_returns_value() {
        let cd = make(&[("name", "hello")]);
        assert_eq!(cd.get_string("name"), "hello");
    }

    #[test]
    #[should_panic(expected = "Missing string value for attribute \"missing\"")]
    fn get_string_panics_when_missing() {
        let cd = make(&[]);
        cd.get_string("missing");
    }

    #[test]
    fn has_value_true_and_false() {
        let cd = make(&[("name", "hello")]);
        assert!(cd.has_value("name"));
        assert!(!cd.has_value("other"));
    }

    #[test]
    fn get_int_parses_value() {
        let cd = make(&[("count", "42")]);
        assert_eq!(cd.get_int("count"), 42);
    }

    #[test]
    #[should_panic(expected = "Expected int value for attribute \"count\", but was \"nope\"")]
    fn get_int_panics_on_invalid_value() {
        let cd = make(&[("count", "nope")]);
        cd.get_int("count");
    }

    #[test]
    fn get_long_parses_value() {
        let cd = make(&[("count", "9999999999")]);
        assert_eq!(cd.get_long("count"), 9999999999i64);
    }

    #[test]
    #[should_panic(expected = "Expected long value for attribute \"count\", but was \"nope\"")]
    fn get_long_panics_on_invalid_value() {
        let cd = make(&[("count", "nope")]);
        cd.get_long("count");
    }

    #[test]
    fn get_boolean_parses_true_and_false_case_insensitive() {
        let cd = make(&[("a", "TRUE"), ("b", "False")]);
        assert!(cd.get_boolean("a"));
        assert!(!cd.get_boolean("b"));
    }

    #[test]
    #[should_panic(expected = "Expected boolean value for attribute \"flag\", but was \"maybe\"")]
    fn get_boolean_panics_on_invalid_value() {
        let cd = make(&[("flag", "maybe")]);
        cd.get_boolean("flag");
    }

    #[test]
    fn get_float_parses_value() {
        let cd = make(&[("f", "1.5")]);
        assert_eq!(cd.get_float("f"), 1.5f32);
    }

    #[test]
    #[should_panic(expected = "Expected float value for attribute \"f\", but was \"nope\"")]
    fn get_float_panics_on_invalid_value() {
        let cd = make(&[("f", "nope")]);
        cd.get_float("f");
    }

    #[test]
    fn get_double_parses_value() {
        let cd = make(&[("d", "3.14")]);
        assert_eq!(cd.get_double("d"), 3.14f64);
    }

    #[test]
    #[should_panic(expected = "Expected double value for attribute \"d\", but was \"nope\"")]
    fn get_double_panics_on_invalid_value() {
        let cd = make(&[("d", "nope")]);
        cd.get_double("d");
    }
}
