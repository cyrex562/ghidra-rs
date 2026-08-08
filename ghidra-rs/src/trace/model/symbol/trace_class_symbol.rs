use crate::program::model::listing::ghidra_class::GhidraClass;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;

/// A trace class symbol.
///
/// Port of `ghidra.trace.model.symbol.TraceClassSymbol`.
///
/// It was selected as a dependency-cycle cut-point. The Java interface `extends
/// TraceNamespaceSymbol, GhidraClass` and adds nothing of its own; both supertraits already
/// require [`Namespace`](crate::program::model::symbol::Namespace), so no diamond conflict
/// arises from combining them here.
pub trait TraceClassSymbol: TraceNamespaceSymbol + GhidraClass {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{
        Namespace, NamespaceType, SourceType, Symbol, SymbolType,
    };
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::TraceThread;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    struct MockClassSymbol {
        id: i64,
        name: String,
    }

    impl Symbol for MockClassSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Class
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
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

    impl Namespace for MockClassSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled; see TraceNamespaceSymbol trait docs")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl GhidraClass for MockClassSymbol {}

    impl TraceSymbol for MockClassSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }

        fn get_parent_trace_namespace(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }

        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
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

    impl TraceNamespaceSymbol for MockClassSymbol {
        fn get_parent_trace_namespace_symbol(&self) -> Option<Arc<dyn TraceNamespaceSymbol>> {
            None
        }

        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }

        fn get_path(&self) -> Vec<String> {
            vec![self.name.clone()]
        }
    }

    impl TraceClassSymbol for MockClassSymbol {}

    #[test]
    fn trait_object_usage_is_object_safe_and_reports_class_type() {
        let sym: Box<dyn TraceClassSymbol> = Box::new(MockClassSymbol {
            id: 42,
            name: "MyClass".to_string(),
        });

        assert_eq!(GhidraClass::get_type(sym.as_ref()), NamespaceType::Class);
        assert_eq!(Namespace::get_name(sym.as_ref()), "MyClass".to_string());
        assert_eq!(sym.get_path(), vec!["MyClass".to_string()]);
        assert!(sym.get_children().is_empty());
    }
}
