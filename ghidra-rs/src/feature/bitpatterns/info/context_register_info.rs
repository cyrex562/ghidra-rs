/// XML element name used when serialising this type.
pub const XML_ELEMENT_NAME: &str = "ContextRegisterInfo";

/// The value a specific context register assumes within a function body.
///
/// Mirrors `ghidra.bitpatterns.info.ContextRegisterInfo`.
/// Java's `BigInteger` is represented as `i128`, consistent with the rest of
/// the `bitpatterns::info` module. The `value` field is `Option<i128>` to
/// match Java's nullable `BigInteger`.
#[derive(Debug, Clone, Default)]
pub struct ContextRegisterInfo {
    context_register: String,
    value: Option<i128>,
}

impl ContextRegisterInfo {
    /// Creates an empty `ContextRegisterInfo` (mirrors the default constructor).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a `ContextRegisterInfo` for the named context register.
    pub fn with_register(context_register: impl Into<String>) -> Self {
        Self {
            context_register: context_register.into(),
            value: None,
        }
    }

    /// Returns the context register name.
    pub fn get_context_register(&self) -> &str {
        &self.context_register
    }

    /// Sets the context register name.
    pub fn set_context_register(&mut self, context_register: impl Into<String>) {
        self.context_register = context_register.into();
    }

    /// Returns the value associated with this register, if any.
    pub fn get_value(&self) -> Option<i128> {
        self.value
    }

    /// Sets the value associated with this register.
    pub fn set_value(&mut self, value: Option<i128>) {
        self.value = value;
    }
}

impl std::fmt::Display for ContextRegisterInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {:?}", self.context_register, self.value)
    }
}

impl PartialEq for ContextRegisterInfo {
    fn eq(&self, other: &Self) -> bool {
        self.context_register == other.context_register && self.value == other.value
    }
}

impl Eq for ContextRegisterInfo {}

impl std::hash::Hash for ContextRegisterInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.context_register.hash(state);
        self.value.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equals_same_register_no_value() {
        let info1 = ContextRegisterInfo::with_register("contextRegister1");
        let info2 = ContextRegisterInfo::with_register("contextRegister1");
        assert_eq!(info1, info1);
        assert_eq!(info1, info2);
        assert_eq!(info2, info1);
    }

    #[test]
    fn test_not_equals_different_register_no_value() {
        let info1 = ContextRegisterInfo::with_register("contextRegister1");
        let info3 = ContextRegisterInfo::with_register("contextRegister2");
        assert_ne!(info1, info3);
        assert_ne!(info3, info1);
    }

    #[test]
    fn test_equals_same_register_same_value() {
        let mut info1 = ContextRegisterInfo::with_register("contextRegister1");
        let mut info2 = ContextRegisterInfo::with_register("contextRegister1");
        info1.set_value(Some(1));
        info2.set_value(Some(1));
        assert_eq!(info1, info1);
        assert_eq!(info1, info2);
        assert_eq!(info2, info1);
    }

    #[test]
    fn test_not_equals_same_register_different_value() {
        let mut info1 = ContextRegisterInfo::with_register("contextRegister1");
        let mut info3 = ContextRegisterInfo::with_register("contextRegister2");
        info1.set_value(Some(1));
        info3.set_value(Some(3));
        assert_ne!(info1, info3);
        assert_ne!(info3, info1);
    }

    #[test]
    fn test_not_equals_null_vs_set_value() {
        let info1 = ContextRegisterInfo::with_register("reg");
        let mut info2 = ContextRegisterInfo::with_register("reg");
        info2.set_value(Some(1));
        assert_ne!(info1, info2);
        assert_ne!(info2, info1);
    }

    #[test]
    fn test_getters_setters() {
        let mut info = ContextRegisterInfo::new();
        info.set_context_register("myReg");
        info.set_value(Some(42));
        assert_eq!(info.get_context_register(), "myReg");
        assert_eq!(info.get_value(), Some(42));
    }

    #[test]
    fn test_with_register_constructor() {
        let info = ContextRegisterInfo::with_register("TMode");
        assert_eq!(info.get_context_register(), "TMode");
        assert_eq!(info.get_value(), None);
    }

    #[test]
    fn test_display() {
        let mut info = ContextRegisterInfo::with_register("TMode");
        info.set_value(Some(1));
        let s = info.to_string();
        assert!(s.contains("TMode"));
        assert!(s.contains("1"));
    }

    #[test]
    fn test_hash_consistent_with_eq() {
        use std::collections::HashSet;
        let mut info1 = ContextRegisterInfo::with_register("R1");
        info1.set_value(Some(5));
        let mut info2 = ContextRegisterInfo::with_register("R1");
        info2.set_value(Some(5));
        assert_eq!(info1, info2);
        let mut set = HashSet::new();
        set.insert(info1);
        assert!(set.contains(&info2));
    }

    #[test]
    fn test_xml_element_name_constant() {
        assert_eq!(XML_ELEMENT_NAME, "ContextRegisterInfo");
    }
}
