use std::collections::HashSet;
use std::fmt;

use once_cell::sync::Lazy;

/// The kind of breakpoint, identifying the sort of access that would trap execution.
///
/// Encoding in a trace database depends on this enum's flag characters, so the variant order
/// and flags must not change without a database migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceBreakpointKind {
    Read,
    Write,
    HwExecute,
    SwExecute,
}

impl TraceBreakpointKind {
    /// All variants in declaration order (matches Java's `VALUES`).
    pub const VALUES: &'static [Self] = &[Self::Read, Self::Write, Self::HwExecute, Self::SwExecute];

    /// Number of variants.
    pub const COUNT: usize = Self::VALUES.len();

    /// The single-character flag used in encoded representations.
    pub fn flag(self) -> char {
        match self {
            Self::Read => 'R',
            Self::Write => 'W',
            Self::HwExecute => 'X',
            Self::SwExecute => 'x',
        }
    }

    /// The canonical name used in the comma-separated legacy encoding.
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::HwExecute => "HW_EXECUTE",
            Self::SwExecute => "SW_EXECUTE",
        }
    }
}

/// A set of [`TraceBreakpointKind`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceBreakpointKindSet(HashSet<TraceBreakpointKind>);

impl TraceBreakpointKindSet {
    /// Creates an empty set.
    pub fn empty() -> Self {
        Self(HashSet::new())
    }

    /// Creates a set from the given kinds.
    pub fn of(kinds: &[TraceBreakpointKind]) -> Self {
        Self(kinds.iter().copied().collect())
    }

    /// Creates a set by copying from any iterator of kinds.
    pub fn copy_of(kinds: impl IntoIterator<Item = TraceBreakpointKind>) -> Self {
        Self(kinds.into_iter().collect())
    }

    pub fn contains(&self, kind: TraceBreakpointKind) -> bool {
        self.0.contains(&kind)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = TraceBreakpointKind> + '_ {
        self.0.iter().copied()
    }

    /// Encode a set of kinds as a flag string in enum declaration order.
    ///
    /// For example, `{Read, Write}` encodes as `"RW"`.
    pub fn encode(col: &HashSet<TraceBreakpointKind>) -> String {
        let mut s = String::new();
        for k in TraceBreakpointKind::VALUES {
            if col.contains(k) {
                s.push(k.flag());
            }
        }
        s
    }

    /// Decode a string of flags or comma-separated names to a set of kinds.
    ///
    /// When the encoded string is fewer than 4 characters it is treated as a sequence of flag
    /// characters (`R`, `W`, `X`, `x`). When it is 4 or more characters it is treated as a
    /// comma-separated list of kind names (case-insensitive). `strict` controls whether
    /// unrecognised names cause an error in the name-encoding path.
    pub fn decode(encoded: &str, strict: bool) -> Result<Self, String> {
        let simple: Option<Self> = match encoded {
            "" => Some(Self::empty()),
            "x" | "SW_EXECUTE" => Some(CommonSet::Swx.kinds().clone()),
            "X" | "HW_EXECUTE" => Some(CommonSet::Hwx.kinds().clone()),
            "R" | "READ" => Some(CommonSet::Read.kinds().clone()),
            "W" | "WRITE" => Some(CommonSet::Write.kinds().clone()),
            "RW" | "READ,WRITE" | "WRITE,READ" => Some(CommonSet::Access.kinds().clone()),
            _ => None,
        };
        if let Some(s) = simple {
            return Ok(s);
        }

        let mut result = HashSet::new();
        if encoded.len() < 4 {
            for k in TraceBreakpointKind::VALUES {
                if encoded.contains(k.flag()) {
                    result.insert(*k);
                }
            }
        } else {
            let mut names: HashSet<String> = encoded
                .to_uppercase()
                .split(',')
                .map(str::to_owned)
                .collect();
            for k in TraceBreakpointKind::VALUES {
                if names.remove(k.name()) {
                    result.insert(*k);
                }
            }
            if strict && !names.is_empty() {
                return Err(format!("{:?}", names));
            }
        }
        Ok(Self(result))
    }
}

impl fmt::Display for TraceBreakpointKindSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::encode(&self.0))
    }
}

static SWX_KINDS: Lazy<TraceBreakpointKindSet> =
    Lazy::new(|| TraceBreakpointKindSet::of(&[TraceBreakpointKind::SwExecute]));
static HWX_KINDS: Lazy<TraceBreakpointKindSet> =
    Lazy::new(|| TraceBreakpointKindSet::of(&[TraceBreakpointKind::HwExecute]));
static READ_KINDS: Lazy<TraceBreakpointKindSet> =
    Lazy::new(|| TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read]));
static WRITE_KINDS: Lazy<TraceBreakpointKindSet> =
    Lazy::new(|| TraceBreakpointKindSet::of(&[TraceBreakpointKind::Write]));
static ACCESS_KINDS: Lazy<TraceBreakpointKindSet> = Lazy::new(|| {
    TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read, TraceBreakpointKind::Write])
});

/// Common predefined sets of [`TraceBreakpointKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommonSet {
    Swx,
    Hwx,
    Read,
    Write,
    Access,
}

impl CommonSet {
    pub const VALUES: &'static [Self] =
        &[Self::Swx, Self::Hwx, Self::Read, Self::Write, Self::Access];

    /// Human-readable display label.
    pub fn display(self) -> &'static str {
        match self {
            Self::Swx => "Execute (sw)",
            Self::Hwx => "Execute (hw)",
            Self::Read => "Read (hw)",
            Self::Write => "Write (hw)",
            Self::Access => "Access (hw)",
        }
    }

    /// The predefined set of kinds for this common group.
    pub fn kinds(self) -> &'static TraceBreakpointKindSet {
        match self {
            Self::Swx => &SWX_KINDS,
            Self::Hwx => &HWX_KINDS,
            Self::Read => &READ_KINDS,
            Self::Write => &WRITE_KINDS,
            Self::Access => &ACCESS_KINDS,
        }
    }
}

impl fmt::Display for CommonSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_flags() {
        assert_eq!(TraceBreakpointKind::Read.flag(), 'R');
        assert_eq!(TraceBreakpointKind::Write.flag(), 'W');
        assert_eq!(TraceBreakpointKind::HwExecute.flag(), 'X');
        assert_eq!(TraceBreakpointKind::SwExecute.flag(), 'x');
    }

    #[test]
    fn kind_names() {
        assert_eq!(TraceBreakpointKind::Read.name(), "READ");
        assert_eq!(TraceBreakpointKind::Write.name(), "WRITE");
        assert_eq!(TraceBreakpointKind::HwExecute.name(), "HW_EXECUTE");
        assert_eq!(TraceBreakpointKind::SwExecute.name(), "SW_EXECUTE");
    }

    #[test]
    fn count_and_values() {
        assert_eq!(TraceBreakpointKind::COUNT, 4);
        assert_eq!(TraceBreakpointKind::VALUES.len(), 4);
        assert_eq!(TraceBreakpointKind::VALUES[0], TraceBreakpointKind::Read);
        assert_eq!(TraceBreakpointKind::VALUES[3], TraceBreakpointKind::SwExecute);
    }

    #[test]
    fn set_empty() {
        let s = TraceBreakpointKindSet::empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.contains(TraceBreakpointKind::Read));
    }

    #[test]
    fn set_of() {
        let s = TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read, TraceBreakpointKind::Write]);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 2);
        assert!(s.contains(TraceBreakpointKind::Read));
        assert!(s.contains(TraceBreakpointKind::Write));
        assert!(!s.contains(TraceBreakpointKind::HwExecute));
    }

    #[test]
    fn set_copy_of() {
        let v = vec![TraceBreakpointKind::SwExecute];
        let s = TraceBreakpointKindSet::copy_of(v);
        assert!(s.contains(TraceBreakpointKind::SwExecute));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn encode_empty() {
        let s = TraceBreakpointKindSet::empty();
        assert_eq!(s.to_string(), "");
    }

    #[test]
    fn encode_single_kinds() {
        assert_eq!(
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read]).to_string(),
            "R"
        );
        assert_eq!(
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Write]).to_string(),
            "W"
        );
        assert_eq!(
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::HwExecute]).to_string(),
            "X"
        );
        assert_eq!(
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::SwExecute]).to_string(),
            "x"
        );
    }

    #[test]
    fn encode_respects_declaration_order() {
        let s = TraceBreakpointKindSet::of(&[
            TraceBreakpointKind::SwExecute,
            TraceBreakpointKind::Read,
        ]);
        assert_eq!(s.to_string(), "Rx");
    }

    #[test]
    fn encode_all() {
        let s = TraceBreakpointKindSet::of(&[
            TraceBreakpointKind::Read,
            TraceBreakpointKind::Write,
            TraceBreakpointKind::HwExecute,
            TraceBreakpointKind::SwExecute,
        ]);
        assert_eq!(s.to_string(), "RWXx");
    }

    #[test]
    fn decode_empty_string() {
        let s = TraceBreakpointKindSet::decode("", false).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn decode_single_flags() {
        assert_eq!(
            TraceBreakpointKindSet::decode("R", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("W", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Write])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("X", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::HwExecute])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("x", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::SwExecute])
        );
    }

    #[test]
    fn decode_flag_combination_short() {
        let s = TraceBreakpointKindSet::decode("RW", false).unwrap();
        assert!(s.contains(TraceBreakpointKind::Read));
        assert!(s.contains(TraceBreakpointKind::Write));
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn decode_single_names() {
        assert_eq!(
            TraceBreakpointKindSet::decode("READ", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("WRITE", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::Write])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("HW_EXECUTE", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::HwExecute])
        );
        assert_eq!(
            TraceBreakpointKindSet::decode("SW_EXECUTE", false).unwrap(),
            TraceBreakpointKindSet::of(&[TraceBreakpointKind::SwExecute])
        );
    }

    #[test]
    fn decode_comma_names() {
        let s = TraceBreakpointKindSet::decode("READ,WRITE", false).unwrap();
        assert!(s.contains(TraceBreakpointKind::Read));
        assert!(s.contains(TraceBreakpointKind::Write));
        assert_eq!(s.len(), 2);

        let s2 = TraceBreakpointKindSet::decode("WRITE,READ", false).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn decode_strict_rejects_unknown_names() {
        assert!(TraceBreakpointKindSet::decode("READ,BOGUS", true).is_err());
    }

    #[test]
    fn decode_lenient_ignores_unknown_names() {
        let s = TraceBreakpointKindSet::decode("READ,BOGUS", false).unwrap();
        assert!(s.contains(TraceBreakpointKind::Read));
    }

    #[test]
    fn decode_case_insensitive_names() {
        let s = TraceBreakpointKindSet::decode("read,write", false).unwrap();
        assert!(s.contains(TraceBreakpointKind::Read));
        assert!(s.contains(TraceBreakpointKind::Write));
    }

    #[test]
    fn common_set_display() {
        assert_eq!(CommonSet::Swx.to_string(), "Execute (sw)");
        assert_eq!(CommonSet::Hwx.to_string(), "Execute (hw)");
        assert_eq!(CommonSet::Read.to_string(), "Read (hw)");
        assert_eq!(CommonSet::Write.to_string(), "Write (hw)");
        assert_eq!(CommonSet::Access.to_string(), "Access (hw)");
    }

    #[test]
    fn common_set_kinds() {
        assert!(CommonSet::Swx.kinds().contains(TraceBreakpointKind::SwExecute));
        assert!(!CommonSet::Swx.kinds().contains(TraceBreakpointKind::HwExecute));

        assert!(CommonSet::Access.kinds().contains(TraceBreakpointKind::Read));
        assert!(CommonSet::Access.kinds().contains(TraceBreakpointKind::Write));
        assert_eq!(CommonSet::Access.kinds().len(), 2);
    }

    #[test]
    fn common_set_values_count() {
        assert_eq!(CommonSet::VALUES.len(), 5);
    }

    #[test]
    fn set_iter() {
        let s = TraceBreakpointKindSet::of(&[TraceBreakpointKind::Read, TraceBreakpointKind::HwExecute]);
        let collected: HashSet<_> = s.iter().collect();
        assert!(collected.contains(&TraceBreakpointKind::Read));
        assert!(collected.contains(&TraceBreakpointKind::HwExecute));
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn decode_encode_roundtrip() {
        // The flag encoding deliberately cannot represent all 4 flags at once (see the
        // Java `decode` note: a 4+ character string is treated as comma-separated names,
        // not flags), so round-trip is only defined for up to 3 flags.
        let original = "RWX";
        let set = TraceBreakpointKindSet::decode(original, false).unwrap();
        assert_eq!(set.to_string(), original);
    }
}
