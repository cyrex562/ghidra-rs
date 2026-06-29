use serde::Serialize;
use serde_json::{Map, Value};

/// Token type identifiers used by the JSMN JSON parser.
///
/// Mirrors `generic.json.JSONType` from Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonType {
    /// A primitive value: number, boolean, or null.
    JsmnPrimitive,
    /// A JSON object (`{...}`).
    JsmnObject,
    /// A JSON array (`[...]`).
    JsmnArray,
    /// A JSON string.
    JsmnString,
}

/// Error codes returned by the JSMN JSON parser.
///
/// Mirrors `generic.json.JSONError` from Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonError {
    /// Parsing succeeded.
    JsmnSuccess,
    /// Not enough tokens were provided.
    JsmnErrorNomem,
    /// Invalid character inside JSON string.
    JsmnErrorInval,
    /// The string is not a full JSON packet, more bytes expected.
    JsmnErrorPart,
}

/// Utility for formatting serializable values as JSON strings.
///
/// Mirrors `generic.json.Json` from Ghidra. In Java this class used reflection via
/// Apache Commons Lang `ReflectionToStringBuilder`; the Rust equivalent requires types
/// to implement [`serde::Serialize`].
pub struct Json;

impl Json {
    /// Formats `obj` as a pretty-printed JSON string (with newlines and indentation).
    ///
    /// Mirrors `Json.toString(Object)` from Ghidra.
    pub fn to_string<T: Serialize>(obj: &T) -> String {
        serde_json::to_string_pretty(obj).unwrap_or_else(|_| "{}".to_string())
    }

    /// Formats `obj` as a compact single-line JSON string.
    ///
    /// Mirrors `Json.toStringFlat(Object)` from Ghidra.
    pub fn to_string_flat<T: Serialize>(obj: &T) -> String {
        serde_json::to_string(obj).unwrap_or_else(|_| "{}".to_string())
    }

    /// Formats only the specified fields of `obj` as a pretty-printed JSON string.
    ///
    /// Fields are emitted in the order given by `include_fields`, mirroring the
    /// `InclusiveReflectionToStringBuilder` ordering from the Java source. If
    /// `include_fields` is empty, the full serialized object is returned.
    ///
    /// Mirrors `Json.toString(Object, String...)` from Ghidra.
    pub fn to_string_include<T: Serialize>(obj: &T, include_fields: &[&str]) -> String {
        let value = match serde_json::to_value(obj) {
            Ok(v) => v,
            Err(_) => return "{}".to_string(),
        };

        let Value::Object(map) = value else {
            return serde_json::to_string_pretty(obj).unwrap_or_else(|_| "{}".to_string());
        };

        if include_fields.is_empty() {
            return serde_json::to_string_pretty(&Value::Object(map))
                .unwrap_or_else(|_| "{}".to_string());
        }

        let pairs: Vec<(String, Value)> = include_fields
            .iter()
            .filter_map(|&name| map.get(name).map(|v| (name.to_string(), v.clone())))
            .collect();

        format_ordered(pairs)
    }

    /// Formats all fields of `obj` except those named in `exclude_fields`,
    /// as a pretty-printed JSON string.
    ///
    /// Mirrors `Json.toStringExclude(Object, String...)` from Ghidra.
    pub fn to_string_exclude<T: Serialize>(obj: &T, exclude_fields: &[&str]) -> String {
        let value = match serde_json::to_value(obj) {
            Ok(v) => v,
            Err(_) => return "{}".to_string(),
        };

        let Value::Object(map) = value else {
            return serde_json::to_string_pretty(obj).unwrap_or_else(|_| "{}".to_string());
        };

        let filtered: Map<String, Value> = map
            .into_iter()
            .filter(|(k, _)| !exclude_fields.contains(&k.as_str()))
            .collect();

        serde_json::to_string_pretty(&Value::Object(filtered))
            .unwrap_or_else(|_| "{}".to_string())
    }
}

/// Builds a pretty-printed JSON object string from `pairs`, preserving their insertion order.
fn format_ordered(pairs: Vec<(String, Value)>) -> String {
    if pairs.is_empty() {
        return "{}".to_string();
    }
    let last = pairs.len().saturating_sub(1);
    let mut out = String::from("{\n");
    for (i, (key, val)) in pairs.into_iter().enumerate() {
        let key_json = serde_json::to_string(&Value::String(key)).unwrap_or_default();
        let val_pretty =
            serde_json::to_string_pretty(&val).unwrap_or_else(|_| "null".to_string());
        let val_indented = indent_continuation(&val_pretty, "  ");
        let comma = if i < last { "," } else { "" };
        out.push_str(&format!("  {}: {}{}\n", key_json, val_indented, comma));
    }
    out.push('}');
    out
}

/// Adds `prefix` to every line of `s` after the first.
fn indent_continuation(s: &str, prefix: &str) -> String {
    let mut lines = s.lines();
    match lines.next() {
        None => String::new(),
        Some(first) => {
            let rest: Vec<String> = lines.map(|l| format!("{}{}", prefix, l)).collect();
            if rest.is_empty() {
                first.to_string()
            } else {
                format!("{}\n{}", first, rest.join("\n"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_type_variants_are_distinct() {
        assert_ne!(JsonType::JsmnPrimitive, JsonType::JsmnObject);
        assert_ne!(JsonType::JsmnObject, JsonType::JsmnArray);
        assert_ne!(JsonType::JsmnArray, JsonType::JsmnString);
    }

    #[test]
    fn test_json_type_copy_and_clone() {
        let t = JsonType::JsmnString;
        let c = t;
        assert_eq!(t, c);
        assert_eq!(t.clone(), c);
    }

    #[test]
    fn test_json_type_debug_format() {
        assert_eq!(format!("{:?}", JsonType::JsmnPrimitive), "JsmnPrimitive");
        assert_eq!(format!("{:?}", JsonType::JsmnObject), "JsmnObject");
        assert_eq!(format!("{:?}", JsonType::JsmnArray), "JsmnArray");
        assert_eq!(format!("{:?}", JsonType::JsmnString), "JsmnString");
    }

    #[test]
    fn test_json_type_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(JsonType::JsmnPrimitive);
        set.insert(JsonType::JsmnArray);
        assert!(set.contains(&JsonType::JsmnPrimitive));
        assert!(!set.contains(&JsonType::JsmnObject));
    }

    #[test]
    fn test_variants_are_distinct() {
        assert_ne!(JsonError::JsmnSuccess, JsonError::JsmnErrorNomem);
        assert_ne!(JsonError::JsmnErrorNomem, JsonError::JsmnErrorInval);
        assert_ne!(JsonError::JsmnErrorInval, JsonError::JsmnErrorPart);
    }

    #[test]
    fn test_copy_and_clone() {
        let e = JsonError::JsmnErrorInval;
        let c = e;
        assert_eq!(e, c);
        assert_eq!(e.clone(), c);
    }

    #[test]
    fn test_debug_format() {
        assert_eq!(format!("{:?}", JsonError::JsmnSuccess), "JsmnSuccess");
        assert_eq!(format!("{:?}", JsonError::JsmnErrorNomem), "JsmnErrorNomem");
        assert_eq!(format!("{:?}", JsonError::JsmnErrorInval), "JsmnErrorInval");
        assert_eq!(format!("{:?}", JsonError::JsmnErrorPart), "JsmnErrorPart");
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(JsonError::JsmnSuccess);
        set.insert(JsonError::JsmnErrorPart);
        assert!(set.contains(&JsonError::JsmnSuccess));
        assert!(!set.contains(&JsonError::JsmnErrorNomem));
    }

    // --- Json utility tests ---

    #[derive(serde::Serialize)]
    struct Sample {
        x: i32,
        y: i32,
        label: String,
    }

    #[derive(serde::Serialize)]
    struct Nested {
        name: String,
        inner: Sample,
    }

    #[test]
    fn json_to_string_produces_multiline_output() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string(&s);
        assert!(out.contains('\n'), "pretty output should contain newlines");
        assert!(out.contains("\"x\""));
        assert!(out.contains("\"y\""));
        assert!(out.contains("\"label\""));
    }

    #[test]
    fn json_to_string_flat_has_no_newlines() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_flat(&s);
        assert!(!out.contains('\n'), "flat output must not contain newlines");
        assert!(out.contains("\"x\""));
        assert!(out.contains("\"y\""));
        assert!(out.contains("\"label\""));
    }

    #[test]
    fn json_to_string_include_filters_to_named_fields() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_include(&s, &["x", "label"]);
        assert!(out.contains("\"x\""), "x should be present");
        assert!(out.contains("\"label\""), "label should be present");
        assert!(!out.contains("\"y\""), "y should be absent");
    }

    #[test]
    fn json_to_string_include_preserves_specified_order() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_include(&s, &["label", "x"]);
        let label_pos = out.find("\"label\"").unwrap();
        let x_pos = out.find("\"x\"").unwrap();
        assert!(label_pos < x_pos, "label should appear before x");
    }

    #[test]
    fn json_to_string_include_empty_returns_all_fields() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_include(&s, &[]);
        assert!(out.contains("\"x\""));
        assert!(out.contains("\"y\""));
        assert!(out.contains("\"label\""));
    }

    #[test]
    fn json_to_string_include_unknown_field_is_silently_skipped() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_include(&s, &["x", "missing"]);
        assert!(out.contains("\"x\""));
        assert!(!out.contains("\"missing\""));
    }

    #[test]
    fn json_to_string_exclude_omits_named_fields() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_exclude(&s, &["y"]);
        assert!(out.contains("\"x\""), "x should be present");
        assert!(!out.contains("\"y\""), "y should be absent");
        assert!(out.contains("\"label\""), "label should be present");
    }

    #[test]
    fn json_to_string_exclude_empty_list_returns_all_fields() {
        let s = Sample { x: 1, y: 2, label: "pt".to_string() };
        let out = Json::to_string_exclude(&s, &[]);
        assert!(out.contains("\"x\""));
        assert!(out.contains("\"y\""));
        assert!(out.contains("\"label\""));
    }

    #[test]
    fn json_to_string_flat_and_pretty_contain_same_values() {
        let s = Sample { x: 42, y: 99, label: "test".to_string() };
        let flat = Json::to_string_flat(&s);
        let pretty = Json::to_string(&s);
        assert!(flat.contains("42") && pretty.contains("42"));
        assert!(flat.contains("99") && pretty.contains("99"));
        assert!(flat.contains("\"test\"") && pretty.contains("\"test\""));
    }

    #[test]
    fn json_to_string_include_handles_nested_value() {
        let n = Nested {
            name: "outer".to_string(),
            inner: Sample { x: 3, y: 4, label: "inner".to_string() },
        };
        let out = Json::to_string_include(&n, &["name", "inner"]);
        assert!(out.contains("\"name\""));
        assert!(out.contains("\"inner\""));
        assert!(out.contains("\"outer\""));
    }
}
