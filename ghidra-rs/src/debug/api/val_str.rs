use std::collections::HashMap;
use std::fmt;

/// A value paired with its string representation.
///
/// Mirrors `ghidra.debug.api.ValStr<T>`. The `val` field holds the typed value and
/// `str` holds the human-readable string form, which may differ from `val.to_string()`
/// after a [`cast`] that changes the type without altering the string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValStr<T> {
    pub val: T,
    pub str: String,
}

/// Decodes a raw string into a typed value, optionally preserving the original string.
///
/// Mirrors `ghidra.debug.api.ValStr.Decoder<T>`.
pub trait Decoder {
    type Output;

    fn decode(&self, string: &str) -> Self::Output;

    fn decode_val_str(&self, string: &str) -> ValStr<Self::Output> {
        ValStr::new(self.decode(string), string.to_owned())
    }
}

impl<T> ValStr<T> {
    pub fn new(val: T, str: String) -> Self {
        ValStr { val, str }
    }

    pub fn val(&self) -> &T {
        &self.val
    }

    pub fn str_ref(&self) -> &str {
        &self.str
    }
}

impl ValStr<String> {
    /// Creates a `ValStr<String>` where the value and its string form are identical.
    ///
    /// Mirrors `ValStr.str(String value)`.
    pub fn from_string(value: String) -> Self {
        ValStr { val: value.clone(), str: value }
    }
}

impl<T: fmt::Display> ValStr<T> {
    /// Creates a `ValStr<T>` using the `Display` impl to derive the string form.
    ///
    /// Mirrors `ValStr.from(T value)` for non-null values.
    pub fn from_val(val: T) -> Self {
        let s = val.to_string();
        ValStr { val, str: s }
    }

    /// Returns the string representation of `val`.
    ///
    /// Mirrors the instance `normStr()` method.
    pub fn norm_str(&self) -> &str {
        &self.str
    }
}

/// Returns the `norm_str` of `val`, or `""` if `val` is `None`.
///
/// Mirrors the static `ValStr.normStr(ValStr<?> val)` overload that handles Java null.
pub fn norm_str_of<T: fmt::Display>(val: Option<&ValStr<T>>) -> &str {
    val.map(|v| v.norm_str()).unwrap_or("")
}

/// Converts a plain `HashMap<String, V>` into a `HashMap<String, ValStr<V>>`.
///
/// Mirrors `ValStr.fromPlainMap(Map<String, ?> map)`.
pub fn from_plain_map<V: fmt::Display>(map: HashMap<String, V>) -> HashMap<String, ValStr<V>> {
    map.into_iter()
        .map(|(k, v)| {
            let s = v.to_string();
            (k, ValStr { val: v, str: s })
        })
        .collect()
}

/// Extracts the `val` field from each entry in a `HashMap<String, ValStr<V>>`.
///
/// Mirrors `ValStr.toPlainMap(Map<String, ValStr<?>> map)`.
pub fn to_plain_map<V>(map: HashMap<String, ValStr<V>>) -> HashMap<String, V> {
    map.into_iter().map(|(k, v)| (k, v.val)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_val_and_str_identical() {
        let vs = ValStr::from_string("hello".to_owned());
        assert_eq!(vs.val, "hello");
        assert_eq!(vs.str, "hello");
    }

    #[test]
    fn from_val_uses_display() {
        let vs = ValStr::from_val(42u32);
        assert_eq!(vs.val, 42u32);
        assert_eq!(vs.str, "42");
    }

    #[test]
    fn new_allows_divergent_val_and_str() {
        let vs: ValStr<u32> = ValStr::new(7, "seven".to_owned());
        assert_eq!(vs.val, 7);
        assert_eq!(vs.str, "seven");
    }

    #[test]
    fn norm_str_returns_str_field() {
        let vs = ValStr::from_val(99u32);
        assert_eq!(vs.norm_str(), "99");
    }

    #[test]
    fn norm_str_of_none_returns_empty() {
        let none: Option<&ValStr<u32>> = None;
        assert_eq!(norm_str_of(none), "");
    }

    #[test]
    fn norm_str_of_some_delegates() {
        let vs = ValStr::from_val(5u32);
        assert_eq!(norm_str_of(Some(&vs)), "5");
    }

    #[test]
    fn from_plain_map_wraps_values() {
        let mut m = HashMap::new();
        m.insert("a".to_owned(), 1u32);
        m.insert("b".to_owned(), 2u32);
        let wrapped = from_plain_map(m);
        assert_eq!(wrapped["a"].val, 1);
        assert_eq!(wrapped["a"].str, "1");
        assert_eq!(wrapped["b"].val, 2);
        assert_eq!(wrapped["b"].str, "2");
    }

    #[test]
    fn to_plain_map_extracts_values() {
        let mut m = HashMap::new();
        m.insert("x".to_owned(), ValStr::from_val(10u32));
        let plain = to_plain_map(m);
        assert_eq!(plain["x"], 10u32);
    }

    struct DoubleDecoder;
    impl Decoder for DoubleDecoder {
        type Output = f64;
        fn decode(&self, s: &str) -> f64 {
            s.parse().unwrap()
        }
    }

    #[test]
    fn decoder_decode_val_str_preserves_raw_string() {
        let d = DoubleDecoder;
        let vs = d.decode_val_str("3.14");
        assert!((vs.val - 3.14).abs() < 1e-9);
        assert_eq!(vs.str, "3.14");
    }

    #[test]
    fn val_str_clone_and_eq() {
        let vs = ValStr::from_val(1u32);
        assert_eq!(vs.clone(), vs);
    }
}
