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

/// A JSON token with its type and position metadata.
///
/// Mirrors `generic.json.JSONToken` from Ghidra. Represents a single token
/// in a JSON parse stream, recording its type, start/end positions in the
/// source string, and optionally a size count (useful for container tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonToken {
    /// The token type (object, array, string, primitive).
    pub token_type: JsonType,
    /// Start position in the JSON source string.
    pub start: i32,
    /// End position in the JSON source string.
    pub end: i32,
    /// Size count (typically 0 initially, incremented for container tokens).
    pub size: i32,
}

impl JsonToken {
    /// Creates a new JSON token with the given type and position bounds.
    ///
    /// The size is initialized to 0, mirroring the Java constructor.
    pub fn new(token_type: JsonType, start: i32, end: i32) -> Self {
        Self {
            token_type,
            start,
            end,
            size: 0,
        }
    }

    /// Sets the token type.
    pub fn set_token_type(&mut self, token_type: JsonType) {
        self.token_type = token_type;
    }

    /// Returns the token type.
    pub fn token_type(&self) -> JsonType {
        self.token_type
    }

    /// Sets the start position.
    pub fn set_start(&mut self, start: i32) {
        self.start = start;
    }

    /// Returns the start position.
    pub fn get_start(&self) -> i32 {
        self.start
    }

    /// Sets the end position.
    pub fn set_end(&mut self, end: i32) {
        self.end = end;
    }

    /// Returns the end position.
    pub fn get_end(&self) -> i32 {
        self.end
    }

    /// Sets the size.
    pub fn set_size(&mut self, size: i32) {
        self.size = size;
    }

    /// Returns the size.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Increments the size by 1.
    pub fn inc_size(&mut self) {
        self.size += 1;
    }
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

    // --- JsonToken tests ---

    #[test]
    fn json_token_new_initializes_fields() {
        let token = JsonToken::new(JsonType::JsmnString, 5, 10);
        assert_eq!(token.token_type, JsonType::JsmnString);
        assert_eq!(token.start, 5);
        assert_eq!(token.end, 10);
        assert_eq!(token.size, 0);
    }

    #[test]
    fn json_token_set_and_get_type() {
        let mut token = JsonToken::new(JsonType::JsmnString, 0, 5);
        assert_eq!(token.token_type(), JsonType::JsmnString);
        token.set_token_type(JsonType::JsmnObject);
        assert_eq!(token.token_type(), JsonType::JsmnObject);
    }

    #[test]
    fn json_token_set_and_get_start() {
        let mut token = JsonToken::new(JsonType::JsmnArray, 0, 5);
        assert_eq!(token.get_start(), 0);
        token.set_start(100);
        assert_eq!(token.get_start(), 100);
    }

    #[test]
    fn json_token_set_and_get_end() {
        let mut token = JsonToken::new(JsonType::JsmnArray, 0, 5);
        assert_eq!(token.get_end(), 5);
        token.set_end(200);
        assert_eq!(token.get_end(), 200);
    }

    #[test]
    fn json_token_set_and_get_size() {
        let mut token = JsonToken::new(JsonType::JsmnObject, 0, 5);
        assert_eq!(token.get_size(), 0);
        token.set_size(42);
        assert_eq!(token.get_size(), 42);
    }

    #[test]
    fn json_token_inc_size_increments_by_one() {
        let mut token = JsonToken::new(JsonType::JsmnArray, 0, 10);
        assert_eq!(token.get_size(), 0);
        token.inc_size();
        assert_eq!(token.get_size(), 1);
        token.inc_size();
        assert_eq!(token.get_size(), 2);
    }

    #[test]
    fn json_token_inc_size_multiple_times() {
        let mut token = JsonToken::new(JsonType::JsmnObject, 0, 100);
        for _ in 0..5 {
            token.inc_size();
        }
        assert_eq!(token.get_size(), 5);
    }

    #[test]
    fn json_token_copy_and_clone() {
        let token1 = JsonToken::new(JsonType::JsmnString, 10, 20);
        let token2 = token1;
        assert_eq!(token1, token2);
        let token3 = token1.clone();
        assert_eq!(token1, token3);
    }

    #[test]
    fn json_token_equality() {
        let token1 = JsonToken::new(JsonType::JsmnArray, 5, 15);
        let token2 = JsonToken::new(JsonType::JsmnArray, 5, 15);
        let token3 = JsonToken::new(JsonType::JsmnObject, 5, 15);
        assert_eq!(token1, token2);
        assert_ne!(token1, token3);
    }

    #[test]
    fn json_token_different_positions_not_equal() {
        let token1 = JsonToken::new(JsonType::JsmnString, 0, 5);
        let token2 = JsonToken::new(JsonType::JsmnString, 0, 6);
        assert_ne!(token1, token2);
    }

    #[test]
    fn json_token_debug_format() {
        let token = JsonToken::new(JsonType::JsmnPrimitive, 25, 30);
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("JsonToken"));
        assert!(debug_str.contains("JsmnPrimitive"));
    }

    #[test]
    fn json_token_matches_java_constructor_behavior() {
        let mut token = JsonToken::new(JsonType::JsmnObject, 0, 100);
        assert_eq!(token.token_type, JsonType::JsmnObject);
        assert_eq!(token.start, 0);
        assert_eq!(token.end, 100);
        assert_eq!(token.size, 0);

        token.inc_size();
        token.inc_size();
        assert_eq!(token.size, 2);
    }
}
