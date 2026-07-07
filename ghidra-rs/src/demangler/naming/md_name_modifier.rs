/// Provides a name modifier string for use within a Microsoft mangled name.
///
/// Port of `mdemangler.naming.MDNameModifier`.
pub trait MdNameModifier {
    /// Returns the modifier string for the name.
    fn get_modifier(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestModifier(&'static str);

    impl MdNameModifier for TestModifier {
        fn get_modifier(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn get_modifier_returns_expected_string() {
        let m = TestModifier("__cdecl");
        assert_eq!(m.get_modifier(), "__cdecl");
    }

    #[test]
    fn get_modifier_empty_string() {
        let m = TestModifier("");
        assert_eq!(m.get_modifier(), "");
    }

    #[test]
    fn trait_object_is_usable() {
        let m: &dyn MdNameModifier = &TestModifier("volatile");
        assert_eq!(m.get_modifier(), "volatile");
    }
}
