use crate::trace::model::trace::Trace;

/// A view of a trace at a specific snapshot.
///
/// Represents a read-only view of trace data at a particular point in time (snapshot).
///
/// Port of `ghidra.trace.model.program.SnapSpecificTraceView`.
pub trait SnapSpecificTraceView {
    /// Returns the trace this view presents.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Returns the snapshot this view presents.
    fn get_snap(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::SnapSpecificTraceView;
    use crate::trace::model::trace::Trace;

    #[derive(Debug, Clone)]
    struct MockTrace {
        id: String,
    }

    #[derive(Debug)]
    struct MockSnapView {
        trace: MockTrace,
        snap: i64,
    }

    impl SnapSpecificTraceView for MockSnapView {
        fn get_trace(&self) -> Box<dyn Trace> {
            // This would normally return a proper implementation, but for testing
            // we use a mock that satisfies the interface requirement
            unimplemented!("Mock trace implementation")
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    #[test]
    fn get_snap_returns_correct_snapshot() {
        let view = MockSnapView {
            trace: MockTrace {
                id: "test_trace".to_string(),
            },
            snap: 42,
        };
        assert_eq!(view.get_snap(), 42);
    }

    #[test]
    fn get_snap_returns_zero() {
        let view = MockSnapView {
            trace: MockTrace {
                id: "test_trace".to_string(),
            },
            snap: 0,
        };
        assert_eq!(view.get_snap(), 0);
    }

    #[test]
    fn get_snap_returns_negative_value() {
        let view = MockSnapView {
            trace: MockTrace {
                id: "test_trace".to_string(),
            },
            snap: -1,
        };
        assert_eq!(view.get_snap(), -1);
    }

    #[test]
    fn get_snap_returns_large_value() {
        let view = MockSnapView {
            trace: MockTrace {
                id: "test_trace".to_string(),
            },
            snap: i64::MAX,
        };
        assert_eq!(view.get_snap(), i64::MAX);
    }
}
