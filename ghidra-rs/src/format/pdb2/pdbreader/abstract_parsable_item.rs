/// Base trait for PDB record items that can be parsed and rendered as strings.
///
/// Implementors override [`emit`](AbstractParsableItem::emit) to customise the string
/// representation. The blanket [`to_display_string`](AbstractParsableItem::to_display_string)
/// builds on `emit` and corresponds to Java's `toString()`.
pub trait AbstractParsableItem {
    /// Appends a string representation of this item to `builder`.
    ///
    /// The default implementation appends the simple (unqualified) Rust type name, mirroring
    /// Java's `getClass().getSimpleName()`.
    fn emit(&self, builder: &mut String) {
        let full = std::any::type_name::<Self>();
        let simple = full.rsplit("::").next().unwrap_or(full);
        builder.push_str(simple);
    }

    /// Returns the string representation of this item by delegating to [`emit`](Self::emit).
    fn to_display_string(&self) -> String {
        let mut s = String::new();
        self.emit(&mut s);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DefaultItem;
    impl AbstractParsableItem for DefaultItem {}

    struct CustomItem;
    impl AbstractParsableItem for CustomItem {
        fn emit(&self, builder: &mut String) {
            builder.push_str("custom-output");
        }
    }

    struct AppendingItem;
    impl AbstractParsableItem for AppendingItem {
        fn emit(&self, builder: &mut String) {
            builder.push_str("part1");
            builder.push(' ');
            builder.push_str("part2");
        }
    }

    #[test]
    fn default_emit_uses_type_simple_name() {
        let item = DefaultItem;
        let mut s = String::new();
        item.emit(&mut s);
        assert_eq!(s, "DefaultItem");
    }

    #[test]
    fn default_to_display_string_matches_emit() {
        let item = DefaultItem;
        assert_eq!(item.to_display_string(), "DefaultItem");
    }

    #[test]
    fn custom_emit_overrides_default() {
        let item = CustomItem;
        let mut s = String::new();
        item.emit(&mut s);
        assert_eq!(s, "custom-output");
    }

    #[test]
    fn to_display_string_uses_overridden_emit() {
        let item = CustomItem;
        assert_eq!(item.to_display_string(), "custom-output");
    }

    #[test]
    fn emit_appends_to_existing_content() {
        let item = CustomItem;
        let mut s = String::from("prefix:");
        item.emit(&mut s);
        assert_eq!(s, "prefix:custom-output");
    }

    #[test]
    fn multi_part_emit_produces_correct_string() {
        let item = AppendingItem;
        assert_eq!(item.to_display_string(), "part1 part2");
    }
}
