/// The memory state of a byte range in a trace snapshot.
///
/// Mirrors `ghidra.trace.model.memory.TraceMemoryState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryState {
    /// The value was not observed at the snapshot.
    Unknown,
    /// The value was observed at the snapshot.
    Known,
    /// The value could not be observed at the snapshot.
    Error,
}

impl TraceMemoryState {
    /// The state implied when no explicit state is stored (i.e. the `null`-equivalent).
    ///
    /// Matches Java's `IMPLIED_BY_NULL` — the first variant whose `implied_by_null()` is `true`,
    /// which is [`TraceMemoryState::Unknown`].
    pub const IMPLIED_BY_NULL: Self = Self::Unknown;

    /// Returns `s`, or [`Self::IMPLIED_BY_NULL`] when `s` is `None`.
    ///
    /// Mirrors Java's `orImplied(TraceMemoryState s)`.
    pub fn or_implied(s: Option<Self>) -> Self {
        s.unwrap_or(Self::IMPLIED_BY_NULL)
    }

    /// Whether this state is implied by the absence of an explicit entry (`null` in Java).
    ///
    /// Only [`TraceMemoryState::Unknown`] returns `true`.
    pub fn implied_by_null(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Whether this state causes range reads to be truncated at the boundary.
    ///
    /// Only [`TraceMemoryState::Known`] returns `true`.
    pub fn truncates(self) -> bool {
        matches!(self, Self::Known)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implied_by_null_is_unknown() {
        assert_eq!(TraceMemoryState::IMPLIED_BY_NULL, TraceMemoryState::Unknown);
    }

    #[test]
    fn implied_by_null_predicate() {
        assert!(TraceMemoryState::Unknown.implied_by_null());
        assert!(!TraceMemoryState::Known.implied_by_null());
        assert!(!TraceMemoryState::Error.implied_by_null());
    }

    #[test]
    fn truncates_predicate() {
        assert!(!TraceMemoryState::Unknown.truncates());
        assert!(TraceMemoryState::Known.truncates());
        assert!(!TraceMemoryState::Error.truncates());
    }

    #[test]
    fn or_implied_returns_value_when_some() {
        assert_eq!(
            TraceMemoryState::or_implied(Some(TraceMemoryState::Known)),
            TraceMemoryState::Known
        );
        assert_eq!(
            TraceMemoryState::or_implied(Some(TraceMemoryState::Error)),
            TraceMemoryState::Error
        );
    }

    #[test]
    fn or_implied_returns_implied_by_null_when_none() {
        assert_eq!(
            TraceMemoryState::or_implied(None),
            TraceMemoryState::IMPLIED_BY_NULL
        );
    }

    #[test]
    fn only_one_variant_implied_by_null() {
        let implied: Vec<_> = [
            TraceMemoryState::Unknown,
            TraceMemoryState::Known,
            TraceMemoryState::Error,
        ]
        .iter()
        .filter(|s| s.implied_by_null())
        .collect();
        assert_eq!(implied.len(), 1);
        assert_eq!(*implied[0], TraceMemoryState::Unknown);
    }
}
