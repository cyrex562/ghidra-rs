use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::symbol::trace_symbol::TraceSymbol;

/// A trace symbol having a lifespan.
///
/// Port of `ghidra.trace.model.symbol.TraceSymbolWithLifespan`.
///
/// It was selected as a dependency-cycle cut-point.
pub trait TraceSymbolWithLifespan: TraceSymbol {
    /// Get the lifespan of the symbol.
    fn get_lifespan(&self) -> Box<dyn Lifespan>;

    /// Get the minimum snapshot key in the lifespan.
    fn get_start_snap(&self) -> i64;

    /// Set the maximum snapshot key in the lifespan.
    fn set_end_snap(&mut self, snap: i64);

    /// Get the maximum snapshot key in the lifespan.
    fn get_end_snap(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{SourceType, Symbol, SymbolType};
    use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    struct MockSymbolWithLifespan {
        id: i64,
        start: i64,
        end: AtomicI64,
    }

    impl Symbol for MockSymbolWithLifespan {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_name(&self) -> &str {
            "mock_symbol_with_lifespan"
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl TraceSymbol for MockSymbolWithLifespan {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }

        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }

        fn get_references_with_monitor(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }

        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }

        fn set_pinned(&mut self, _pinned: bool) {}

        fn is_pinned(&self) -> bool {
            false
        }
    }

    impl TraceSymbolWithLifespan for MockSymbolWithLifespan {
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.start,
                max: self.end.load(Ordering::SeqCst),
            })
        }

        fn get_start_snap(&self) -> i64 {
            self.start
        }

        fn set_end_snap(&mut self, snap: i64) {
            self.end.store(snap, Ordering::SeqCst);
        }

        fn get_end_snap(&self) -> i64 {
            self.end.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe_and_reports_lifespan() {
        let mut sym = MockSymbolWithLifespan {
            id: 1,
            start: 10,
            end: AtomicI64::new(20),
        };

        assert_eq!(sym.get_start_snap(), 10);
        assert_eq!(sym.get_end_snap(), 20);

        sym.set_end_snap(30);
        assert_eq!(sym.get_end_snap(), 30);

        let boxed: Box<dyn TraceSymbolWithLifespan> = Box::new(sym);
        let span = boxed.get_lifespan();
        assert_eq!(span.lmin(), 10);
        assert_eq!(span.lmax(), 30);
        assert!(span.contains(15));
        assert!(!span.contains(31));
    }
}
