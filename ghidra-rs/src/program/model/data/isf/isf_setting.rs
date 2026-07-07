use super::IsfObject;

/// The raw value passed to [`IsfSetting::new`].
///
/// Mirrors the `Object value` parameter of the Java constructor: either a
/// string or a 64-bit integer.
pub enum IsfSettingValue {
    Str(String),
    Long(i64),
}

/// Represents an ISF setting with a name, a serialized value, and a kind
/// discriminator.
///
/// Mirrors `IsfSetting` from Ghidra's `Debugger-isf` module. The `kind` field
/// is `"string"` when the supplied value is textual, or `"long"` when it is
/// numeric, matching the Java `instanceof String` check.
#[derive(Debug, Clone)]
pub struct IsfSetting {
    pub name: String,
    pub kind: String,
    pub value: String,
}

impl IsfSetting {
    /// Creates a new `IsfSetting`.
    ///
    /// `kind` is set to `"string"` when `value` is [`IsfSettingValue::Str`],
    /// or `"long"` when it is [`IsfSettingValue::Long`].
    pub fn new(name: String, value: IsfSettingValue) -> Self {
        match value {
            IsfSettingValue::Str(s) => Self {
                name,
                kind: "string".to_string(),
                value: s,
            },
            IsfSettingValue::Long(n) => Self {
                name,
                kind: "long".to_string(),
                value: n.to_string(),
            },
        }
    }
}

impl IsfObject for IsfSetting {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_value_sets_kind_to_string() {
        let s = IsfSetting::new("arch".to_string(), IsfSettingValue::Str("x86_64".to_string()));
        assert_eq!(s.kind, "string");
        assert_eq!(s.value, "x86_64");
        assert_eq!(s.name, "arch");
    }

    #[test]
    fn long_value_sets_kind_to_long() {
        let s = IsfSetting::new("version".to_string(), IsfSettingValue::Long(42));
        assert_eq!(s.kind, "long");
        assert_eq!(s.value, "42");
        assert_eq!(s.name, "version");
    }

    #[test]
    fn negative_long_serialized_correctly() {
        let s = IsfSetting::new("offset".to_string(), IsfSettingValue::Long(-1));
        assert_eq!(s.kind, "long");
        assert_eq!(s.value, "-1");
    }

    #[test]
    fn zero_long_serialized_correctly() {
        let s = IsfSetting::new("base".to_string(), IsfSettingValue::Long(0));
        assert_eq!(s.kind, "long");
        assert_eq!(s.value, "0");
    }

    #[test]
    fn empty_string_value() {
        let s = IsfSetting::new("label".to_string(), IsfSettingValue::Str(String::new()));
        assert_eq!(s.kind, "string");
        assert_eq!(s.value, "");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let s = IsfSetting::new("x".to_string(), IsfSettingValue::Long(1));
        accepts_isf_object(&s);
    }
}
