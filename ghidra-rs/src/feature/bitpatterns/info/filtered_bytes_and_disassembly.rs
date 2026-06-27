/// Container pairing filtered byte strings with their disassembly lines.
///
/// Mirrors `ghidra.bitpatterns.info.FilteredBytesAndDisassembly`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredBytesAndDisassembly {
    filtered_bytes: Vec<String>,
    disassembly: Vec<String>,
}

impl FilteredBytesAndDisassembly {
    pub fn new(filtered_bytes: Vec<String>, disassembly: Vec<String>) -> Self {
        Self {
            filtered_bytes,
            disassembly,
        }
    }

    pub fn filtered_bytes(&self) -> &[String] {
        &self.filtered_bytes
    }

    pub fn disassembly(&self) -> &[String] {
        &self.disassembly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getters() {
        let bytes = vec!["aa".to_string(), "bb".to_string()];
        let disasm = vec!["NOP".to_string(), "RET".to_string()];
        let fbd = FilteredBytesAndDisassembly::new(bytes.clone(), disasm.clone());
        assert_eq!(fbd.filtered_bytes(), bytes.as_slice());
        assert_eq!(fbd.disassembly(), disasm.as_slice());
    }

    #[test]
    fn test_equality() {
        let a = FilteredBytesAndDisassembly::new(
            vec!["cc".to_string()],
            vec!["MOV".to_string()],
        );
        let b = FilteredBytesAndDisassembly::new(
            vec!["cc".to_string()],
            vec!["MOV".to_string()],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_different_bytes() {
        let a = FilteredBytesAndDisassembly::new(
            vec!["aa".to_string()],
            vec!["NOP".to_string()],
        );
        let b = FilteredBytesAndDisassembly::new(
            vec!["bb".to_string()],
            vec!["NOP".to_string()],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_different_disassembly() {
        let a = FilteredBytesAndDisassembly::new(
            vec!["aa".to_string()],
            vec!["NOP".to_string()],
        );
        let b = FilteredBytesAndDisassembly::new(
            vec!["aa".to_string()],
            vec!["CALL".to_string()],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_vecs() {
        let fbd = FilteredBytesAndDisassembly::new(vec![], vec![]);
        assert!(fbd.filtered_bytes().is_empty());
        assert!(fbd.disassembly().is_empty());
    }
}
