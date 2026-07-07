/// A pairing of a trace with a lifespan, representing a scoped time range within a trace.
///
/// Java source: `ghidra.trace.model.TraceSpan`.
///
/// In the original, `TraceSpan` is an interface requiring implementors to supply the owning
/// `Trace` and the `Lifespan` (a closed range of snapshot keys). Because both of those types
/// are themselves large Java interfaces, we capture them as associated types so that concrete
/// Rust implementations can supply the appropriate types once those are ported.
pub trait TraceSpan: Ord {
    /// The trace this span belongs to.
    type Trace;
    /// The closed range of snapshot keys that describes this span's lifetime.
    type Lifespan;

    /// Returns the trace this span belongs to.
    fn get_trace(&self) -> &Self::Trace;

    /// Returns the lifespan (snapshot-key range) of this span.
    fn get_span(&self) -> &Self::Lifespan;
}

#[cfg(test)]
mod tests {
    use super::TraceSpan;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockTrace {
        id: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct MockSpan {
        trace: MockTrace,
        span: MockLifespan,
    }

    impl PartialOrd for MockSpan {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for MockSpan {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.span.cmp(&other.span)
        }
    }

    impl TraceSpan for MockSpan {
        type Trace = MockTrace;
        type Lifespan = MockLifespan;

        fn get_trace(&self) -> &Self::Trace {
            &self.trace
        }

        fn get_span(&self) -> &Self::Lifespan {
            &self.span
        }
    }

    fn make_span(trace_id: u64, min: i64, max: i64) -> MockSpan {
        MockSpan {
            trace: MockTrace { id: trace_id },
            span: MockLifespan { min, max },
        }
    }

    #[test]
    fn get_trace_returns_owning_trace() {
        let s = make_span(42, 0, 100);
        assert_eq!(s.get_trace().id, 42);
    }

    #[test]
    fn get_span_returns_lifespan() {
        let s = make_span(1, 10, 20);
        assert_eq!(s.get_span().min, 10);
        assert_eq!(s.get_span().max, 20);
    }

    #[test]
    fn ordering_by_lifespan() {
        let a = make_span(1, 0, 50);
        let b = make_span(1, 0, 100);
        let c = make_span(1, 0, 50);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, c);
    }

    #[test]
    fn comparable_to_self() {
        let s = make_span(7, 5, 15);
        assert_eq!(s.cmp(&s), std::cmp::Ordering::Equal);
    }
}
