//! Port of `ghidra.features.bsim.query.protocol.PreFilter`.

use crate::feature::bsim::query::description::FunctionDescription;
use crate::program::model::listing::program::Program;

/// A predicate over `(Program, FunctionDescription)`, standing in for Java's
/// `BiPredicate<Program, FunctionDescription>`.
pub type PreFilterPredicate = Box<dyn Fn(&dyn Program, &FunctionDescription) -> bool + Send + Sync>;

/// A collection of pre-filters used to restrict which functions a BSim query considers.
///
/// Port of `ghidra.features.bsim.query.protocol.PreFilter`.
///
/// Java combines the registered predicates lazily via `Stream.reduce`: `getAndReducedPredicate`
/// folds with `(x, y) -> true` as the identity and `BiPredicate::and` as the accumulator, and
/// `getOrReducedPredicate` folds with `(x, y) -> false` and `BiPredicate::or`. Folding AND with
/// an always-true identity (or OR with an always-false identity) leaves the combined truth value
/// unchanged for every registered filter, and reduces to that identity itself when the filter
/// list is empty -- exactly the semantics of [`Iterator::all`] and [`Iterator::any`] respectively
/// (both of which likewise default to `true`/`false` on an empty iterator), so those are used
/// here instead of building up a literal `BiPredicate` chain.
#[derive(Default)]
pub struct PreFilter {
    pre_filters: Vec<PreFilterPredicate>,
}

impl PreFilter {
    /// Mirrors `PreFilter()`.
    pub fn new() -> Self {
        Self { pre_filters: Vec::new() }
    }

    /// Mirrors `addPredicate(BiPredicate<Program, FunctionDescription>)`.
    pub fn add_predicate(&mut self, predicate: PreFilterPredicate) {
        self.pre_filters.push(predicate);
    }

    /// Mirrors `getAndReducedPredicate()`: a predicate that is `true` only when every registered
    /// filter is `true` (vacuously `true` when no filters are registered).
    pub fn get_and_reduced_predicate(&self) -> impl Fn(&dyn Program, &FunctionDescription) -> bool + '_ {
        move |program, function| self.pre_filters.iter().all(|f| f(program, function))
    }

    /// Mirrors `getOrReducedPredicate()`: a predicate that is `true` when any registered filter
    /// is `true` (vacuously `false` when no filters are registered).
    pub fn get_or_reduced_predicate(&self) -> impl Fn(&dyn Program, &FunctionDescription) -> bool + '_ {
        move |program, function| self.pre_filters.iter().any(|f| f(program, function))
    }

    /// Mirrors `clearFilters()`.
    pub fn clear_filters(&mut self) {
        self.pre_filters.clear();
    }

    /// The number of registered filters. Java has no direct equivalent; useful here for
    /// asserting [`clear_filters`](Self::clear_filters) actually emptied the list.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.pre_filters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::ExecutableRecord;
    use crate::framework::model::DomainObject;
    use std::sync::Arc;

    /// A minimal `Program` for exercising [`PreFilter`]'s predicates, which never actually call
    /// through to `program` in these tests. `DomainObject` and every `Program` method beyond the
    /// two Java declares abstract (`getName`/`getLanguageID`) have crate-provided defaults.
    struct FakeProgram;
    impl DomainObject for FakeProgram {}
    impl Program for FakeProgram {
        fn get_name(&self) -> String {
            "fake".to_string()
        }
        fn get_language_id(&self) -> String {
            "fake:LE:32:default".to_string()
        }
    }

    fn function(name: &str, address: i64) -> FunctionDescription {
        let exerec = Arc::new(ExecutableRecord::new("aa", "a.exe", "x86:LE:32:default", "gcc"));
        FunctionDescription::new(exerec, name, address)
    }

    #[test]
    fn and_reduced_predicate_is_true_when_no_filters_registered() {
        let pre_filter = PreFilter::new();
        let predicate = pre_filter.get_and_reduced_predicate();
        let function = function("foo", 0x1000);

        assert!(predicate(&FakeProgram, &function));
    }

    #[test]
    fn or_reduced_predicate_is_false_when_no_filters_registered() {
        let pre_filter = PreFilter::new();
        let predicate = pre_filter.get_or_reduced_predicate();
        let function = function("foo", 0x1000);

        assert!(!predicate(&FakeProgram, &function));
    }

    #[test]
    fn and_reduced_predicate_requires_every_filter_to_pass() {
        let mut pre_filter = PreFilter::new();
        pre_filter.add_predicate(Box::new(|_p, f| f.get_function_name().starts_with('f')));
        pre_filter.add_predicate(Box::new(|_p, f| f.get_address() > 0x500));

        let predicate = pre_filter.get_and_reduced_predicate();
        let matches_both = function("foo", 0x1000);
        let matches_only_name = function("foo", 0x100);
        let matches_only_address = function("bar", 0x1000);

        assert!(predicate(&FakeProgram, &matches_both));
        assert!(!predicate(&FakeProgram, &matches_only_name));
        assert!(!predicate(&FakeProgram, &matches_only_address));
    }

    #[test]
    fn or_reduced_predicate_passes_if_any_filter_passes() {
        let mut pre_filter = PreFilter::new();
        pre_filter.add_predicate(Box::new(|_p, f| f.get_function_name().starts_with('f')));
        pre_filter.add_predicate(Box::new(|_p, f| f.get_address() > 0x500));

        let predicate = pre_filter.get_or_reduced_predicate();
        let matches_only_address = function("bar", 0x1000);
        let matches_neither = function("bar", 0x100);

        assert!(predicate(&FakeProgram, &matches_only_address));
        assert!(!predicate(&FakeProgram, &matches_neither));
    }

    #[test]
    fn clear_filters_empties_the_list() {
        let mut pre_filter = PreFilter::new();
        pre_filter.add_predicate(Box::new(|_p, _f| true));
        pre_filter.add_predicate(Box::new(|_p, _f| false));
        assert_eq!(pre_filter.len(), 2);

        pre_filter.clear_filters();
        assert_eq!(pre_filter.len(), 0);
        // an empty AND-reduced predicate is vacuously true again after clearing
        assert!(pre_filter.get_and_reduced_predicate()(&FakeProgram, &function("foo", 0)));
    }
}
