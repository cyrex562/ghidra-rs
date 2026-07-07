/// Processor symbol type variants used in relax grammar specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessorSymbolType {
    Code,
    CodePtr,
}

impl ProcessorSymbolType {
    /// Returns the `ProcessorSymbolType` for the given string (case-insensitive),
    /// or `None` if `s` is `None`. Returns an `Err` for unrecognized values.
    ///
    /// Mirrors `ProcessorSymbolType.getType(String)` from Java.
    pub fn get_type(s: Option<&str>) -> Result<Option<Self>, String> {
        let s = match s {
            None => return Ok(None),
            Some(v) => v,
        };
        match s.to_lowercase().as_str() {
            "code" => Ok(Some(Self::Code)),
            "code_ptr" => Ok(Some(Self::CodePtr)),
            _ => Err(format!("unsupported symbol type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_returns_none() {
        assert_eq!(ProcessorSymbolType::get_type(None).unwrap(), None);
    }

    #[test]
    fn code_lowercase() {
        assert_eq!(
            ProcessorSymbolType::get_type(Some("code")).unwrap(),
            Some(ProcessorSymbolType::Code)
        );
    }

    #[test]
    fn code_uppercase() {
        assert_eq!(
            ProcessorSymbolType::get_type(Some("CODE")).unwrap(),
            Some(ProcessorSymbolType::Code)
        );
    }

    #[test]
    fn code_mixed_case() {
        assert_eq!(
            ProcessorSymbolType::get_type(Some("Code")).unwrap(),
            Some(ProcessorSymbolType::Code)
        );
    }

    #[test]
    fn code_ptr_lowercase() {
        assert_eq!(
            ProcessorSymbolType::get_type(Some("code_ptr")).unwrap(),
            Some(ProcessorSymbolType::CodePtr)
        );
    }

    #[test]
    fn code_ptr_uppercase() {
        assert_eq!(
            ProcessorSymbolType::get_type(Some("CODE_PTR")).unwrap(),
            Some(ProcessorSymbolType::CodePtr)
        );
    }

    #[test]
    fn unsupported_type_returns_err() {
        let result = ProcessorSymbolType::get_type(Some("data"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported symbol type: data"));
    }

    #[test]
    fn empty_string_returns_err() {
        assert!(ProcessorSymbolType::get_type(Some("")).is_err());
    }
}
