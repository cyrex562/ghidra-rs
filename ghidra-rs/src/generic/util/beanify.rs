use serde_json::Value;

/// Converts a Java-style getter method name to a bean property name.
///
/// `"getFoo"` → `Some("foo")`, `"isBar"` → `Some("bar")`, anything else → `None`.
/// Mirrors the private `Beanify.fix` helper from `generic.util.Beanify`.
pub fn fix(name: &str) -> Option<String> {
    if name.starts_with("get") && name.len() > 3 {
        Some(lowercase_first(&name[3..]))
    } else if name.starts_with("is") && name.len() > 2 {
        Some(lowercase_first(&name[2..]))
    } else {
        None
    }
}

fn lowercase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
    }
}

/// Trait for types that can expose their observable state as an ordered property map.
///
/// Mirrors `generic.util.Beanify` from Ghidra. The Java original uses runtime
/// reflection to discover public getter methods (`getXxx`, `isXxx`) and public
/// fields on any object. In Rust there is no runtime reflection, so types implement
/// this trait explicitly. The return type is `Vec<(String, Value)>` rather than
/// `LinkedHashMap` to preserve insertion order without an external crate dependency.
///
/// Implementors should list properties in the same order the Java code would
/// discover them: getter-derived entries first, then field-derived entries.
pub trait Beanify {
    /// Returns an ordered list of `(property_name, JSON value)` pairs representing
    /// the object's public state.
    fn beanify(&self) -> Vec<(String, Value)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_get_prefix() {
        assert_eq!(fix("getFoo"), Some("foo".to_string()));
    }

    #[test]
    fn fix_is_prefix() {
        assert_eq!(fix("isBar"), Some("bar".to_string()));
    }

    #[test]
    fn fix_get_alone_returns_none() {
        assert_eq!(fix("get"), None);
    }

    #[test]
    fn fix_is_alone_returns_none() {
        assert_eq!(fix("is"), None);
    }

    #[test]
    fn fix_unrecognized_prefix_returns_none() {
        assert_eq!(fix("name"), None);
        assert_eq!(fix("setFoo"), None);
        assert_eq!(fix(""), None);
    }

    #[test]
    fn fix_preserves_camel_case_remainder() {
        assert_eq!(fix("getMaxValue"), Some("maxValue".to_string()));
        assert_eq!(fix("isEnabled"), Some("enabled".to_string()));
    }

    #[test]
    fn fix_lowercases_only_first_char() {
        // Java: name.substring(3,4).toLowerCase() + name.substring(4)
        // "getURL" → "u" + "RL" → "uRL"
        assert_eq!(fix("getURL"), Some("uRL".to_string()));
    }

    #[test]
    fn fix_single_char_after_prefix() {
        assert_eq!(fix("getX"), Some("x".to_string()));
        assert_eq!(fix("isA"), Some("a".to_string()));
    }

    #[test]
    fn beanify_trait_collects_properties_in_order() {
        struct TestBean {
            label: String,
            active: bool,
        }

        impl Beanify for TestBean {
            fn beanify(&self) -> Vec<(String, Value)> {
                vec![
                    ("label".to_string(), Value::String(self.label.clone())),
                    ("active".to_string(), Value::Bool(self.active)),
                ]
            }
        }

        let bean = TestBean { label: "hello".to_string(), active: true };
        let props = bean.beanify();
        assert_eq!(props.len(), 2);
        assert_eq!(props[0], ("label".to_string(), Value::String("hello".to_string())));
        assert_eq!(props[1], ("active".to_string(), Value::Bool(true)));
    }

    #[test]
    fn beanify_trait_empty_impl() {
        struct EmptyBean;

        impl Beanify for EmptyBean {
            fn beanify(&self) -> Vec<(String, Value)> {
                vec![]
            }
        }

        assert!(EmptyBean.beanify().is_empty());
    }

    #[test]
    fn beanify_trait_numeric_values() {
        struct Counter {
            count: u64,
        }

        impl Beanify for Counter {
            fn beanify(&self) -> Vec<(String, Value)> {
                vec![("count".to_string(), Value::Number(self.count.into()))]
            }
        }

        let c = Counter { count: 42 };
        let props = c.beanify();
        assert_eq!(props[0].1, Value::Number(42u64.into()));
    }
}
