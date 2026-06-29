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

#[cfg(test)]
mod tests {
    use super::*;

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
}
