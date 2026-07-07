use std::io;

/// Parses an EXPORTS line from a `.def` file.
///
/// See <https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170>
#[derive(Debug)]
pub struct DefExportLine {
    name: String,
    internal_name: Option<String>,
    other_module_name: Option<String>,
    other_module_exported_name: Option<String>,
    other_module_ordinal: Option<i32>,
    ordinal: Option<i32>,
    is_no_name: bool,
    is_private: bool,
    is_data: bool,
}

fn parse_int(s: &str) -> io::Result<i32> {
    s.parse::<i32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

impl DefExportLine {
    /// Parses the given export line into a new [`DefExportLine`].
    pub fn new(export_line: &str) -> io::Result<Self> {
        let mut tokens = export_line.split_whitespace();

        let first = tokens
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Line is empty"))?;

        let mut line = DefExportLine {
            name: String::new(),
            internal_name: None,
            other_module_name: None,
            other_module_exported_name: None,
            other_module_ordinal: None,
            ordinal: None,
            is_no_name: false,
            is_private: false,
            is_data: false,
        };

        // First token: "name", "name=internal", "name=module.export", or "name=module.#ordinal"
        let equals_parts: Vec<&str> = first.splitn(2, '=').collect();
        line.name = equals_parts[0].to_string();
        if equals_parts.len() > 1 {
            let rhs = equals_parts[1];
            let dot_parts: Vec<&str> = rhs.splitn(2, '.').collect();
            if dot_parts.len() == 1 {
                line.internal_name = Some(rhs.to_string());
            } else {
                line.other_module_name = Some(dot_parts[0].to_string());
                if dot_parts[1].starts_with('#') {
                    line.other_module_ordinal = Some(parse_int(&dot_parts[1][1..])?);
                } else {
                    line.other_module_exported_name = Some(dot_parts[1].to_string());
                }
            }
        }

        // Remaining tokens: optional "@ordinal", NONAME, PRIVATE, DATA
        while let Some(token) = tokens.next() {
            if line.ordinal.is_none() && token.starts_with('@') {
                if token == "@" {
                    if let Some(next) = tokens.next() {
                        line.ordinal = Some(parse_int(next)?);
                    }
                } else {
                    line.ordinal = Some(parse_int(&token[1..])?);
                }
            } else {
                match token {
                    "NONAME" => line.is_no_name = true,
                    "PRIVATE" => line.is_private = true,
                    "DATA" => line.is_data = true,
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid type: {other}"),
                        ))
                    }
                }
            }
        }

        Ok(line)
    }

    /// Returns the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the internal name, or `None` if there is no internal name.
    pub fn internal_name(&self) -> Option<&str> {
        self.internal_name.as_deref()
    }

    /// Returns the other module name, or `None` if there is no other module.
    pub fn other_module_name(&self) -> Option<&str> {
        self.other_module_name.as_deref()
    }

    /// Returns the other module exported name, or `None` if there is no other module exported name.
    pub fn other_module_exported_name(&self) -> Option<&str> {
        self.other_module_exported_name.as_deref()
    }

    /// Returns the other module ordinal, or `None` if there is no other module ordinal.
    pub fn other_module_ordinal(&self) -> Option<i32> {
        self.other_module_ordinal
    }

    /// Returns the ordinal value, or `None` if there is no ordinal.
    pub fn ordinal(&self) -> Option<i32> {
        self.ordinal
    }

    /// Returns `true` if the export has no name.
    pub fn is_no_name(&self) -> bool {
        self.is_no_name
    }

    /// Returns `true` if the export is private.
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Returns `true` if the export is data.
    pub fn is_data(&self) -> bool {
        self.is_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_name() {
        let d = DefExportLine::new("MyFunc").unwrap();
        assert_eq!(d.name(), "MyFunc");
        assert!(d.internal_name().is_none());
        assert!(d.other_module_name().is_none());
        assert!(d.ordinal().is_none());
        assert!(!d.is_no_name());
        assert!(!d.is_private());
        assert!(!d.is_data());
    }

    #[test]
    fn name_with_internal_name() {
        let d = DefExportLine::new("Foo=Bar").unwrap();
        assert_eq!(d.name(), "Foo");
        assert_eq!(d.internal_name(), Some("Bar"));
        assert!(d.other_module_name().is_none());
    }

    #[test]
    fn name_with_forwarded_export() {
        let d = DefExportLine::new("Foo=other.Bar").unwrap();
        assert_eq!(d.name(), "Foo");
        assert!(d.internal_name().is_none());
        assert_eq!(d.other_module_name(), Some("other"));
        assert_eq!(d.other_module_exported_name(), Some("Bar"));
        assert!(d.other_module_ordinal().is_none());
    }

    #[test]
    fn name_with_forwarded_ordinal() {
        let d = DefExportLine::new("Foo=other.#42").unwrap();
        assert_eq!(d.name(), "Foo");
        assert_eq!(d.other_module_name(), Some("other"));
        assert!(d.other_module_exported_name().is_none());
        assert_eq!(d.other_module_ordinal(), Some(42));
    }

    #[test]
    fn ordinal_attached() {
        let d = DefExportLine::new("MyFunc @10").unwrap();
        assert_eq!(d.name(), "MyFunc");
        assert_eq!(d.ordinal(), Some(10));
    }

    #[test]
    fn ordinal_separated() {
        let d = DefExportLine::new("MyFunc @ 10").unwrap();
        assert_eq!(d.name(), "MyFunc");
        assert_eq!(d.ordinal(), Some(10));
    }

    #[test]
    fn flag_noname() {
        let d = DefExportLine::new("MyFunc @5 NONAME").unwrap();
        assert!(d.is_no_name());
        assert!(!d.is_private());
        assert!(!d.is_data());
    }

    #[test]
    fn flag_private() {
        let d = DefExportLine::new("MyFunc PRIVATE").unwrap();
        assert!(!d.is_no_name());
        assert!(d.is_private());
        assert!(!d.is_data());
    }

    #[test]
    fn flag_data() {
        let d = DefExportLine::new("MyFunc DATA").unwrap();
        assert!(!d.is_no_name());
        assert!(!d.is_private());
        assert!(d.is_data());
    }

    #[test]
    fn all_flags_and_ordinal() {
        let d = DefExportLine::new("MyFunc @7 NONAME PRIVATE DATA").unwrap();
        assert_eq!(d.ordinal(), Some(7));
        assert!(d.is_no_name());
        assert!(d.is_private());
        assert!(d.is_data());
    }

    #[test]
    fn empty_line_errors() {
        assert!(DefExportLine::new("").is_err());
        assert!(DefExportLine::new("   ").is_err());
    }

    #[test]
    fn invalid_type_errors() {
        let err = DefExportLine::new("MyFunc UNKNOWN").unwrap_err();
        assert!(err.to_string().contains("Invalid type: UNKNOWN"));
    }

    #[test]
    fn invalid_ordinal_errors() {
        assert!(DefExportLine::new("MyFunc @notanumber").is_err());
    }

    #[test]
    fn invalid_forwarded_ordinal_errors() {
        assert!(DefExportLine::new("Foo=other.#notanumber").is_err());
    }

    // --- Tests ported from DefExportLineTest.java ---

    #[test]
    fn test_export_line_name_only() {
        let export = DefExportLine::new("func").unwrap();
        assert_eq!(export.name(), "func");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_internal_name() {
        let export = DefExportLine::new("func2=func1").unwrap();
        assert_eq!(export.name(), "func2");
        assert_eq!(export.internal_name(), Some("func1"));
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_other_module_exported_name() {
        let export = DefExportLine::new("func2=other_module.func1").unwrap();
        assert_eq!(export.name(), "func2");
        assert!(export.internal_name().is_none());
        assert_eq!(export.other_module_name(), Some("other_module"));
        assert_eq!(export.other_module_exported_name(), Some("func1"));
        assert!(export.other_module_ordinal().is_none());
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_other_module_ordinal() {
        let export = DefExportLine::new("func2=other_module.#42").unwrap();
        assert_eq!(export.name(), "func2");
        assert!(export.internal_name().is_none());
        assert_eq!(export.other_module_name(), Some("other_module"));
        assert!(export.other_module_exported_name().is_none());
        assert_eq!(export.other_module_ordinal(), Some(42));
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_ordinal() {
        let export = DefExportLine::new("func @1").unwrap();
        assert_eq!(export.name(), "func");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert_eq!(export.ordinal(), Some(1));
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_ordinal_spaces() {
        let export = DefExportLine::new("func @     1").unwrap();
        assert_eq!(export.name(), "func");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert_eq!(export.ordinal(), Some(1));
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_ordinal_no_name() {
        let export = DefExportLine::new("func @1 NONAME").unwrap();
        assert_eq!(export.name(), "func");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert_eq!(export.ordinal(), Some(1));
        assert!(export.is_no_name());
        assert!(!export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_data() {
        let export = DefExportLine::new("exported_global DATA").unwrap();
        assert_eq!(export.name(), "exported_global");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(!export.is_private());
        assert!(export.is_data());
    }

    #[test]
    fn test_export_line_private() {
        let export = DefExportLine::new("func PRIVATE").unwrap();
        assert_eq!(export.name(), "func");
        assert!(export.internal_name().is_none());
        assert!(export.other_module_name().is_none());
        assert!(export.other_module_exported_name().is_none());
        assert!(export.other_module_ordinal().is_none());
        assert!(export.ordinal().is_none());
        assert!(!export.is_no_name());
        assert!(export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_all() {
        let export = DefExportLine::new("func2=other_module.#42 @ 1 NONAME PRIVATE").unwrap();
        assert_eq!(export.name(), "func2");
        assert!(export.internal_name().is_none());
        assert_eq!(export.other_module_name(), Some("other_module"));
        assert!(export.other_module_exported_name().is_none());
        assert_eq!(export.other_module_ordinal(), Some(42));
        assert_eq!(export.ordinal(), Some(1));
        assert!(export.is_no_name());
        assert!(export.is_private());
        assert!(!export.is_data());
    }

    #[test]
    fn test_export_line_with_no_name() {
        assert!(DefExportLine::new("   ").is_err());
    }

    #[test]
    fn test_export_line_with_invalid_ordinal() {
        assert!(DefExportLine::new("func @ff").is_err());
    }

    #[test]
    fn test_export_line_with_invalid_type() {
        assert!(DefExportLine::new("func @ 1 INVALID_TYPE").is_err());
    }
}
