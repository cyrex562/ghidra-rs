/// Trait for types that can produce a display string suitable for user consumption.
///
/// Corresponds to `docking.widgets.table.DisplayStringProvider` in the Java source.
/// Used by the table filtering mechanism to transform cell data into filterable strings.
pub trait DisplayStringProvider {
    /// Returns a display string suitable for user consumption.
    fn display_string(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleLabel(String);

    impl DisplayStringProvider for SimpleLabel {
        fn display_string(&self) -> String {
            self.0.clone()
        }
    }

    #[test]
    fn returns_expected_string() {
        let label = SimpleLabel("hello world".to_string());
        assert_eq!(label.display_string(), "hello world");
    }

    #[test]
    fn empty_string_is_valid() {
        let label = SimpleLabel(String::new());
        assert_eq!(label.display_string(), "");
    }

    #[test]
    fn trait_object_usable() {
        let label: Box<dyn DisplayStringProvider> = Box::new(SimpleLabel("boxed".to_string()));
        assert_eq!(label.display_string(), "boxed");
    }
}
