use std::fmt;

/// Identifies the role a taint rule plays in a taint analysis result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintRule {
    Unknown,
    Source,
    Sink,
    Gate,
    Insn,
    Vertex,
    Path,
}

impl TaintRule {
    /// Maps a SARIF rule ID to a `TaintRule` variant based on the embedded code token.
    pub fn from_rule_id(rule_id: &str) -> Self {
        if rule_id.contains("C0003") {
            Self::Source
        } else if rule_id.contains("C0001") {
            Self::Path
        } else if rule_id.contains("C0004") {
            Self::Sink
        } else if rule_id.contains("C0002") {
            Self::Insn
        } else if rule_id.contains("C0005") {
            Self::Vertex
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for TaintRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "UNKNOWN",
            Self::Source => "Source",
            Self::Sink => "Sink",
            Self::Gate => "Gate",
            Self::Insn => "Instruction",
            Self::Vertex => "Vertex",
            Self::Path => "Path",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_rule_id_source() {
        assert_eq!(TaintRule::from_rule_id("C0003-something"), TaintRule::Source);
    }

    #[test]
    fn test_from_rule_id_path() {
        assert_eq!(TaintRule::from_rule_id("rule-C0001"), TaintRule::Path);
    }

    #[test]
    fn test_from_rule_id_sink() {
        assert_eq!(TaintRule::from_rule_id("C0004"), TaintRule::Sink);
    }

    #[test]
    fn test_from_rule_id_insn() {
        assert_eq!(TaintRule::from_rule_id("taint-C0002-rule"), TaintRule::Insn);
    }

    #[test]
    fn test_from_rule_id_vertex() {
        assert_eq!(TaintRule::from_rule_id("C0005xyz"), TaintRule::Vertex);
    }

    #[test]
    fn test_from_rule_id_unknown() {
        assert_eq!(TaintRule::from_rule_id("C9999"), TaintRule::Unknown);
        assert_eq!(TaintRule::from_rule_id(""), TaintRule::Unknown);
    }

    #[test]
    fn test_display() {
        assert_eq!(TaintRule::Unknown.to_string(), "UNKNOWN");
        assert_eq!(TaintRule::Source.to_string(), "Source");
        assert_eq!(TaintRule::Sink.to_string(), "Sink");
        assert_eq!(TaintRule::Gate.to_string(), "Gate");
        assert_eq!(TaintRule::Insn.to_string(), "Instruction");
        assert_eq!(TaintRule::Vertex.to_string(), "Vertex");
        assert_eq!(TaintRule::Path.to_string(), "Path");
    }

    #[test]
    fn test_clone_and_copy() {
        let r = TaintRule::Source;
        let r2 = r;
        assert_eq!(r, r2);
        let r3 = r.clone();
        assert_eq!(r, r3);
    }

    #[test]
    fn test_from_rule_id_priority_source_over_path() {
        // C0003 appears before C0001 check, so C0003 wins even if C0001 also present
        assert_eq!(TaintRule::from_rule_id("C0003-C0001"), TaintRule::Source);
    }
}
