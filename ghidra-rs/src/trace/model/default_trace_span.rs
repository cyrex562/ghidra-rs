use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_span::TraceSpan;

/// A concrete pairing of a trace and a lifespan.
///
/// NOTE: This is used to mark (trace, snap) regardless of whether that snapshot is actually in
/// the database.... Cannot just use `TraceSnapshot` here.
///
/// Java source: `ghidra.trace.model.DefaultTraceSpan`.
///
/// The `trace` field is held by [`Arc`] rather than by value, since equality (and the Java
/// original's `this.trace != that.trace` check) is based on shared identity of the referenced
/// trace, not its contents.
pub struct DefaultTraceSpan {
    trace: Arc<dyn Trace>,
    span: Box<dyn Lifespan>,
}

impl DefaultTraceSpan {
    /// Creates a new span pairing `trace` with `span`.
    pub fn new(trace: Arc<dyn Trace>, span: Box<dyn Lifespan>) -> Self {
        Self { trace, span }
    }
}

impl TraceSpan for DefaultTraceSpan {
    type Trace = Arc<dyn Trace>;
    type Lifespan = Box<dyn Lifespan>;

    fn get_trace(&self) -> &Self::Trace {
        &self.trace
    }

    fn get_span(&self) -> &Self::Lifespan {
        &self.span
    }
}

impl fmt::Display for DefaultTraceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TraceSnap<{}: [{}, {}]>",
            self.trace.get_name(),
            self.span.lmin(),
            self.span.lmax()
        )
    }
}

impl PartialEq for DefaultTraceSpan {
    fn eq(&self, other: &Self) -> bool {
        if !Arc::ptr_eq(&self.trace, &other.trace) {
            return false;
        }
        self.span.compare_to(other.span.as_ref()) == Ordering::Equal
    }
}

impl Eq for DefaultTraceSpan {}

impl Hash for DefaultTraceSpan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.trace) as *const ()).hash(state);
        self.span.lmin().hash(state);
        self.span.lmax().hash(state);
    }
}

impl PartialOrd for DefaultTraceSpan {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DefaultTraceSpan {
    fn cmp(&self, other: &Self) -> Ordering {
        if std::ptr::eq(self, other) {
            return Ordering::Equal;
        }
        self.trace
            .get_name()
            .cmp(&other.trace.get_name())
            .then_with(|| self.span.compare_to(other.span.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_object::DomainObject;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceBreakpointManager, TraceCodeManager, TraceEquateManager, TraceMemoryManager,
        TraceModuleManager, TraceObjectManager, TracePlatformManager, TraceProgramView,
        TraceReferenceManager, TraceRegisterContextManager, TraceStackManager,
        TraceStaticMappingManager, TraceSymbolManager, TraceThreadManager, TraceTimeManager,
        TraceTimeViewport, TraceVariableSnapProgramView,
    };
    use std::collections::hash_map::DefaultHasher;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    struct MockTrace {
        name: String,
    }

    impl DomainObject for MockTrace {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn crate::program::model::data::data_type_manager::DataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by these tests")
        }

        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by these tests")
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by these tests")
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn hash_of<T: Hash>(v: &T) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    fn make_trace(name: &str) -> Arc<dyn Trace> {
        Arc::new(MockTrace {
            name: name.to_string(),
        })
    }

    fn make_span(min: i64, max: i64) -> Box<dyn Lifespan> {
        Box::new(MockLifespan { min, max })
    }

    #[test]
    fn get_trace_and_get_span_return_constructor_values() {
        let trace = make_trace("t1");
        let span = DefaultTraceSpan::new(trace.clone(), make_span(0, 10));
        assert!(Arc::ptr_eq(span.get_trace(), &trace));
        assert_eq!(span.get_span().lmin(), 0);
        assert_eq!(span.get_span().lmax(), 10);
    }

    #[test]
    fn equal_when_same_trace_and_equal_span() {
        let trace = make_trace("t1");
        let a = DefaultTraceSpan::new(trace.clone(), make_span(0, 10));
        let b = DefaultTraceSpan::new(trace, make_span(0, 10));
        assert_eq!(a, b);
    }

    #[test]
    fn not_equal_when_different_trace_reference() {
        let a = DefaultTraceSpan::new(make_trace("t1"), make_span(0, 10));
        let b = DefaultTraceSpan::new(make_trace("t1"), make_span(0, 10));
        assert_ne!(a, b);
    }

    #[test]
    fn not_equal_when_different_span() {
        let trace = make_trace("t1");
        let a = DefaultTraceSpan::new(trace.clone(), make_span(0, 10));
        let b = DefaultTraceSpan::new(trace, make_span(0, 20));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_matches_for_equal_spans() {
        let trace = make_trace("t1");
        let a = DefaultTraceSpan::new(trace.clone(), make_span(0, 10));
        let b = DefaultTraceSpan::new(trace, make_span(0, 10));
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn ordering_by_trace_name_first() {
        let a = DefaultTraceSpan::new(make_trace("a"), make_span(0, 100));
        let b = DefaultTraceSpan::new(make_trace("b"), make_span(0, 0));
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn ordering_by_span_when_trace_names_equal() {
        let a = DefaultTraceSpan::new(make_trace("t1"), make_span(0, 10));
        let b = DefaultTraceSpan::new(make_trace("t1"), make_span(0, 20));
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn comparable_to_self() {
        let s = DefaultTraceSpan::new(make_trace("t1"), make_span(5, 15));
        assert_eq!(s.cmp(&s), Ordering::Equal);
    }

    #[test]
    fn display_includes_trace_name_and_span_bounds() {
        let s = DefaultTraceSpan::new(make_trace("t1"), make_span(0, 10));
        assert_eq!(s.to_string(), "TraceSnap<t1: [0, 10]>");
    }
}
