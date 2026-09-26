use std::collections::BTreeMap;

use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_internal;
use crate::util::msg::Msg;

/// Port of `ghidra.program.model.data.CompositeTestUtils`.
///
/// The Java class is a static-method-only utility (private constructor) rather than a formal
/// interface, so it is ported as free functions instead of a trait.
///
/// The Java `assertExpectedComposite`/`dump` overloads accept a plain `DataType` and assert/check
/// `instanceof Composite` at runtime, falling back to an empty dump for non-composites. Since a
/// Rust caller of these test helpers already has a value that implements
/// [`Composite`](Composite), that runtime check is expressed here as the static
/// `composite: &dyn Composite` parameter type instead. The `instanceof Composite` check on a
/// component's *nested* data type in [`collect_composites`] has no such static alternative (the
/// component's data type is any [`DataType`](crate::program::model::data::data_type::DataType)),
/// so it uses [`DataType::into_composite`](crate::program::model::data::data_type::DataType::into_composite).
///
/// The Java `Object test` parameter (typically the JUnit `TestCase` instance, used only for
/// `Msg.error` reporting) is ported as `&str`, matching
/// [`Msg::error`](crate::util::msg::Msg::error)'s `originator` parameter.
///
/// Compare dump of composite with the expected one.
///
/// # Panics
/// Panics (mirroring JUnit's `fail`) if the dump of `composite` does not match `expected_dump`.
pub fn assert_expected_composite(test: &str, expected_dump: &str, composite: &dyn Composite) {
    assert_expected_composite_recursive(test, expected_dump, composite, false);
}

/// Compare dump of composite with the expected one.
///
/// `recursive`: if true all child composites will be included in the dump.
///
/// # Panics
/// Panics (mirroring JUnit's `fail`) if the dump of `composite` does not match `expected_dump`.
pub fn assert_expected_composite_recursive(
    test: &str,
    expected_dump: &str,
    composite: &dyn Composite,
    recursive: bool,
) {
    let result = dump(composite, recursive);
    let result: Vec<char> = result.trim().chars().collect();
    let expected_dump: Vec<char> = expected_dump.trim().chars().collect();
    let len = expected_dump.len();
    let mut expected_line = 1;
    let mut expected_col = 0;
    let mut mismatch = false;

    for index in 0..len {
        expected_col += 1;
        let expected_char = expected_dump[index];
        if expected_char == '\n' {
            expected_line += 1;
            expected_col = 0;
        }
        let result_char = result.get(index).copied().unwrap_or('\0');
        if result_char != expected_char {
            Msg::error(
                test,
                &format!("Expected and result differ: expected line {expected_line}, column {expected_col}"),
            );
            mismatch = true;
            break;
        }
    }

    mismatch |= len != result.len();

    if mismatch {
        let expected_dump: String = expected_dump.into_iter().collect();
        let result: String = result.into_iter().collect();
        Msg::error(test, &format!("Expected composite:\n{expected_dump}"));
        Msg::error(test, &format!("Result composite:\n{result}"));
        panic!("Composite mismatch (see log)");
    }
}

/// Dump composite details for examination or test comparison.
///
/// `recursive`: if true all child composites will also be dumped recursively.
pub fn dump(composite: &dyn Composite, recursive: bool) -> String {
    let mut buf = composite_internal::to_string(composite);

    if recursive {
        let mut other_composites: BTreeMap<String, Box<dyn Composite>> = BTreeMap::new();
        collect_composites(composite, &mut other_composites);
        for child in other_composites.values() {
            buf.push_str(&composite_internal::to_string(child.as_ref()));
        }
    }
    buf
}

/// Collects, keyed and sorted by path name, every composite reachable transitively through
/// `composite`'s defined components' data types. Stands in for the Java `TreeSet<Composite>`
/// ordered by `Composite.getPathName()`.
fn collect_composites(composite: &dyn Composite, collection: &mut BTreeMap<String, Box<dyn Composite>>) {
    for c in composite.get_defined_components() {
        if let Some(child_composite) = c.get_data_type().into_composite() {
            collect_composites(child_composite.as_ref(), collection);
            collection
                .entry(child_composite.get_path_name())
                .or_insert(child_composite);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::packing_type::PackingType;

    struct PlainDataType;
    impl DataType for PlainDataType {}

    struct Leaf {
        path_name: String,
        display_name: String,
    }

    impl DataType for Leaf {
        fn get_path_name(&self) -> String {
            self.path_name.clone()
        }
        fn get_display_name(&self) -> String {
            self.display_name.clone()
        }
        fn is_structure(&self) -> bool {
            true
        }
        fn into_composite(self: Box<Self>) -> Option<Box<dyn Composite>> {
            Some(self)
        }
    }
    impl Composite for Leaf {}

    struct Outer {
        components: Vec<(&'static str, Option<&'static str>)>,
    }

    impl DataType for Outer {
        fn get_path_name(&self) -> String {
            "/Outer".to_string()
        }
        fn get_display_name(&self) -> String {
            "Outer".to_string()
        }
        fn is_structure(&self) -> bool {
            true
        }
    }

    impl Composite for Outer {
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .enumerate()
                .map(|(i, (name, child_path))| -> Box<dyn DataTypeComponent> {
                    Box::new(NamedComponent {
                        offset: i as i32 * 4,
                        field_name: name.to_string(),
                        child_path: child_path.map(|s| s.to_string()),
                    })
                })
                .collect()
        }

        fn get_packing_type(&self) -> PackingType {
            PackingType::Disabled
        }
    }

    struct NamedComponent {
        offset: i32,
        field_name: String,
        child_path: Option<String>,
    }

    impl DataTypeComponent for NamedComponent {
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn get_data_type_name(&self) -> String {
            self.field_name.clone()
        }
        fn get_field_name(&self) -> Option<String> {
            Some(self.field_name.clone())
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            match &self.child_path {
                Some(path) => Box::new(Leaf {
                    path_name: path.clone(),
                    // Display name excludes the category path (as in real Ghidra), so the
                    // full path string appears exactly once per composite dump.
                    display_name: path.trim_start_matches('/').to_string(),
                }),
                None => Box::new(PlainDataType),
            }
        }
    }

    #[test]
    fn dump_non_recursive_matches_composite_internal_to_string() {
        let outer = Outer { components: vec![("a", None)] };
        assert_eq!(dump(&outer, false), composite_internal::to_string(&outer));
    }

    #[test]
    fn dump_recursive_appends_sorted_unique_child_composites() {
        let outer = Outer {
            components: vec![
                ("a", Some("/Zeta")),
                ("b", Some("/Alpha")),
                ("c", Some("/Alpha")),
            ],
        };
        let result = dump(&outer, true);
        let alpha_index = result.find("/Alpha").unwrap();
        let zeta_index = result.find("/Zeta").unwrap();
        assert!(alpha_index < zeta_index);
        assert_eq!(result.matches("/Alpha").count(), 1);
    }

    #[test]
    fn assert_expected_composite_passes_on_match() {
        let outer = Outer { components: vec![] };
        let expected = dump(&outer, false);
        assert_expected_composite("test", &expected, &outer);
    }

    #[test]
    #[should_panic(expected = "Composite mismatch")]
    fn assert_expected_composite_panics_on_mismatch() {
        let outer = Outer { components: vec![] };
        assert_expected_composite("test", "totally different", &outer);
    }

    #[test]
    #[should_panic(expected = "Composite mismatch")]
    fn assert_expected_composite_panics_on_length_mismatch() {
        let outer = Outer { components: vec![] };
        let expected = dump(&outer, false);
        // Both sides are trimmed inside assert_expected_composite, so a mismatch must come
        // from dropping a non-whitespace char (not just the trailing newline).
        let trimmed = expected.trim_end();
        let truncated = &trimmed[..trimmed.len() - 1];
        assert_expected_composite("test", truncated, &outer);
    }
}
