//! Port of `ghidra.trace.model.target.path.PathMatcher`.

use std::collections::HashSet;

use super::path_pattern::Align;
use super::{KeyPath, PathFilter, PathPattern};

/// Minimal capability for combining anything pattern-bearing into a [`PathMatcher`], standing in
/// for Java's `PathFilter` interface where `PathMatcher.any`/`PathMatcher.or` accept it
/// polymorphically (`Collection<PathFilter>`, `PathFilter...`, or a single `PathFilter`).
///
/// This crate's existing [`PathFilter`] trait (see its docs) is deliberately kept minimal --
/// just enough for `KeyPath::stream_matching_ancestry` -- rather than growing it into the full
/// Java interface (`or`, `getPatterns`, `isNone`, `applyKeys`, ... -- more than a dozen members).
/// `HasPatterns` is a second, narrower trait covering only what `PathMatcher::any_of_filters`/
/// [`PathMatcher::or`] need: a filter's underlying set of [`PathPattern`]s.
pub trait HasPatterns {
    /// Port of `PathFilter.getPatterns()`.
    fn patterns(&self) -> HashSet<PathPattern>;
}

impl HasPatterns for PathPattern {
    /// Port of `PathPattern.getPatterns()`: `Set.of(this)`.
    fn patterns(&self) -> HashSet<PathPattern> {
        let mut set = HashSet::new();
        set.insert(self.clone());
        set
    }
}

impl HasPatterns for PathMatcher {
    fn patterns(&self) -> HashSet<PathPattern> {
        self.patterns.clone()
    }
}

/// A [`PathFilter`]-like object that is the union of zero or more [`PathPattern`]s: it matches a
/// path if *any* contained pattern matches.
///
/// # Differences from Java
///
/// Java's `PathMatcher implements PathFilter`, so it exposes the entire ~15-member `PathFilter`
/// interface polymorphically. This port exposes the same operations as plain inherent methods
/// (per this crate's "composition over inheritance" convention) rather than implementing this
/// crate's minimal [`PathFilter`] trait's three members and bolting the rest on separately --
/// [`PathMatcher::matches`] and [`PathMatcher::ancestor_matches`] are inherent methods with the
/// same names/signatures as the trait's, so `PathMatcher` can still be used wherever a bare
/// `matches`/`ancestor_matches` call is needed, without forcing every other Java `PathFilter`
/// member through a trait no other implementor (besides [`PathPattern`]) would need in full.
///
/// Java's three-argument-shape overloaded `any` factory (`any(Stream<PathPattern>)`,
/// `any(Collection<PathFilter>)`, `any(PathFilter...)`) collapses to two Rust functions:
/// [`PathMatcher::any_of_patterns`] (from an iterator of [`PathPattern`], covering the `Stream`
/// overload) and [`PathMatcher::any_of_filters`] (from an iterator of `&dyn HasPatterns`,
/// covering both the `Collection` and varargs overloads, since Rust does not distinguish
/// overloads by argument-count the way Java does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatcher {
    patterns: HashSet<PathPattern>,
}

impl PathMatcher {
    /// Port of the package-private constructor `PathMatcher(Set<PathPattern>)`. Kept
    /// crate-private, matching Java's package-private visibility: external callers are expected
    /// to go through [`PathMatcher::any_of_patterns`]/[`PathMatcher::any_of_filters`].
    pub(crate) fn from_patterns(patterns: HashSet<PathPattern>) -> Self {
        PathMatcher { patterns }
    }

    /// Port of `PathMatcher.any(Stream<PathPattern>)`.
    pub fn any_of_patterns(patterns: impl Iterator<Item = PathPattern>) -> Self {
        PathMatcher::from_patterns(patterns.collect())
    }

    /// Port of `PathMatcher.any(Collection<PathFilter>)` and `PathMatcher.any(PathFilter...)`.
    ///
    /// See this struct's docs for why both Java overloads map to one Rust function.
    pub fn any_of_filters<'a>(filters: impl IntoIterator<Item = &'a dyn HasPatterns>) -> Self {
        let mut patterns = HashSet::new();
        for f in filters {
            patterns.extend(f.patterns());
        }
        PathMatcher::from_patterns(patterns)
    }

    /// Port of `PathMatcher.or(PathFilter)`.
    pub fn or(&self, that: &dyn HasPatterns) -> PathMatcher {
        let mut patterns = self.patterns.clone();
        patterns.extend(that.patterns());
        PathMatcher::from_patterns(patterns)
    }

    /// Port of the private helper `PathMatcher.anyPattern(Predicate<PathPattern>)`.
    ///
    /// > TODO: We could probably do a lot better, esp. for many patterns, by using a trie.
    fn any_pattern(&self, pred: impl Fn(&PathPattern) -> bool) -> bool {
        self.patterns.iter().any(pred)
    }

    /// Port of `PathMatcher.matches(KeyPath)`.
    pub fn matches(&self, path: &KeyPath) -> bool {
        self.any_pattern(|p| p.matches(path))
    }

    /// Port of `PathMatcher.successorCouldMatch(KeyPath, boolean)`.
    pub fn successor_could_match(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.successor_could_match(path, strict))
    }

    /// Port of `PathMatcher.ancestorMatches(KeyPath, boolean)`.
    pub fn ancestor_matches(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.ancestor_matches(path, strict))
    }

    /// Port of `PathMatcher.ancestorCouldMatchRight(KeyPath, boolean)`.
    pub fn ancestor_could_match_right(&self, path: &KeyPath, strict: bool) -> bool {
        self.any_pattern(|p| p.ancestor_could_match_right(path, strict))
    }

    /// Port of `PathMatcher.getSingletonPath()`.
    pub fn get_singleton_path(&self) -> Option<KeyPath> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next().and_then(|p| p.get_singleton_path())
    }

    /// Port of `PathMatcher.getSingletonPattern()`.
    pub fn get_singleton_pattern(&self) -> Option<&PathPattern> {
        if self.patterns.len() != 1 {
            return None;
        }
        self.patterns.iter().next()
    }

    /// Port of `PathMatcher.getPatterns()`.
    pub fn get_patterns(&self) -> &HashSet<PathPattern> {
        &self.patterns
    }

    /// Port of the protected helper `PathMatcher.coalesceWilds(Set<String>)`.
    ///
    /// When `result` contains the name-wildcard `""`, every concrete (non-index) key is dropped
    /// in favor of it -- a specific name is redundant once "any name" is already accepted.
    /// Symmetrically, when `result` contains the index-wildcard `"[]"`, every concrete index key
    /// is dropped in favor of it. The two reductions are independent (each block only inspects,
    /// and only removes keys of, its own shape), so when *both* wildcard forms are present at
    /// once, both survive together and every concrete key of either shape is eliminated -- see
    /// [`coalesce_wilds_drops_concrete_keys_once_both_wildcards_present`].
    fn coalesce_wilds(result: &mut HashSet<String>) {
        if result.contains("") {
            result.retain(|k| !KeyPath::is_name(k));
            result.insert(String::new());
        }
        if result.contains("[]") {
            result.retain(|k| !KeyPath::is_index(k));
            result.insert("[]".to_string());
        }
    }

    /// Port of `PathMatcher.getNextKeys(KeyPath)`.
    pub fn get_next_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_keys(path));
        }
        Self::coalesce_wilds(&mut result);
        result
    }

    /// Port of `PathMatcher.getNextNames(KeyPath)`.
    ///
    /// Short-circuits (returns the wildcard singleton `{""}`) as soon as any contributing
    /// pattern's names include the wildcard `""`, without consulting the remaining patterns --
    /// matching Java's early `return WILD_SINGLETON` inside the accumulation loop.
    pub fn get_next_names(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_names(path));
            if result.contains("") {
                return Self::wild_singleton();
            }
        }
        result
    }

    /// Port of `PathMatcher.getNextIndices(KeyPath)`. See [`PathMatcher::get_next_names`] for the
    /// early-return behavior this mirrors.
    pub fn get_next_indices(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(pattern.get_next_indices(path));
            if result.contains("") {
                return Self::wild_singleton();
            }
        }
        result
    }

    /// Port of `PathMatcher.getPrevKeys(KeyPath)`.
    pub fn get_prev_keys(&self, path: &KeyPath) -> HashSet<String> {
        let mut result = HashSet::new();
        for pattern in &self.patterns {
            result.extend(PathFilter::get_prev_keys(pattern, path));
        }
        Self::coalesce_wilds(&mut result);
        result
    }

    /// Port of `PathMatcher.WILD_SINGLETON` (`Set.of("")`), materialized on demand rather than
    /// as a shared static since it is cheap to build and callers only ever read it.
    fn wild_singleton() -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert(String::new());
        set
    }

    /// Port of `PathMatcher.isNone()`.
    pub fn is_none(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Port of `PathMatcher.applyKeys(Align, List<String>)`.
    pub fn apply_keys(&self, align: Align, indices: &[String]) -> PathMatcher {
        let patterns = self.patterns.iter().map(|p| p.apply_keys(align, indices)).collect();
        PathMatcher::from_patterns(patterns)
    }

    /// Port of `PathMatcher.removeRight(int)`.
    pub fn remove_right(&self, count: usize) -> PathMatcher {
        let mut patterns = HashSet::new();
        for pat in &self.patterns {
            pat.do_remove_right(count, &mut patterns);
        }
        PathMatcher::from_patterns(patterns)
    }
}

impl std::fmt::Display for PathMatcher {
    /// Port of `PathMatcher.toString()`.
    ///
    /// Java joins `patterns` (a `Set`, so iteration order is unspecified) with `StringUtils
    /// .join(patterns, "\n  ")`; this joins this crate's `HashSet` the same way, so the exact
    /// output is only deterministic for zero or one contained pattern (see this struct's tests).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined =
            self.patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("\n  ");
        write!(f, "<PathMatcher\n  {}\n>", joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> PathPattern {
        PathPattern::parse(s).unwrap()
    }

    fn matcher(pats: &[&str]) -> PathMatcher {
        PathMatcher::any_of_patterns(pats.iter().map(|s| pat(s)))
    }

    /// A single-key pattern built directly from a key string, bypassing `PathPattern::parse`.
    /// Needed for the bare name-wildcard key `""`: `KeyPath::parse("")` yields the *empty* (root)
    /// path, not a one-key path containing `""`, so `pat("")` can't express "a pattern whose one
    /// key is the wildcard name".
    fn single_key(key: &str) -> PathPattern {
        PathPattern::new(KeyPath::of(&[key]))
    }

    #[test]
    fn any_of_patterns_collects_all() {
        let m = matcher(&["Processes[0]", "Processes[1]"]);
        assert_eq!(m.get_patterns().len(), 2);
    }

    #[test]
    fn any_of_filters_flattens_patterns_from_matchers_and_patterns() {
        let inner = matcher(&["A", "B"]);
        let p = pat("C");
        let combined = PathMatcher::any_of_filters([&inner as &dyn HasPatterns, &p as &dyn HasPatterns]);
        assert_eq!(
            combined.get_patterns().clone(),
            HashSet::from([pat("A"), pat("B"), pat("C")])
        );
    }

    #[test]
    fn or_unions_patterns() {
        let a = matcher(&["A"]);
        let b = matcher(&["B"]);
        let unioned = a.or(&b);
        assert_eq!(unioned.get_patterns().clone(), HashSet::from([pat("A"), pat("B")]));
        // `a`/`b` are unmodified (Java: "This object is unmodified, and the result is returned").
        assert_eq!(a.get_patterns().len(), 1);
        assert_eq!(b.get_patterns().len(), 1);
    }

    #[test]
    fn matches_true_if_any_pattern_matches() {
        let m = matcher(&["Processes[0]", "Processes[1]"]);
        assert!(m.matches(&KeyPath::parse("Processes[1]").unwrap()));
        assert!(!m.matches(&KeyPath::parse("Processes[2]").unwrap()));
    }

    #[test]
    fn matches_false_for_empty_matcher() {
        let m = PathMatcher::any_of_patterns(std::iter::empty());
        assert!(!m.matches(&KeyPath::root()));
        assert!(m.is_none());
    }

    #[test]
    fn successor_could_match_true_if_any_pattern_could_match() {
        let m = matcher(&["Processes[0].Threads", "Other"]);
        assert!(m.successor_could_match(&KeyPath::parse("Processes[0]").unwrap(), false));
        assert!(!m.successor_could_match(&KeyPath::parse("Nope").unwrap(), false));
    }

    #[test]
    fn ancestor_matches_true_if_any_pattern_matches_ancestor() {
        let m = matcher(&["Processes[0]"]);
        assert!(m.ancestor_matches(&KeyPath::parse("Processes[0].Threads").unwrap(), false));
        assert!(!m.ancestor_matches(&KeyPath::parse("Processes[1].Threads").unwrap(), false));
    }

    #[test]
    fn ancestor_could_match_right_true_if_any_pattern_could_match() {
        let m = matcher(&["Processes[0].Threads"]);
        assert!(m.ancestor_could_match_right(&KeyPath::parse("Threads").unwrap(), false));
        assert!(!m.ancestor_could_match_right(&KeyPath::parse("Other").unwrap(), false));
    }

    #[test]
    fn get_singleton_path_none_when_multiple_patterns() {
        let m = matcher(&["A", "B"]);
        assert_eq!(m.get_singleton_path(), None);
    }

    #[test]
    fn get_singleton_path_none_when_single_pattern_has_wildcard() {
        let m = matcher(&["Processes[]"]);
        assert_eq!(m.get_singleton_path(), None);
    }

    #[test]
    fn get_singleton_path_some_when_single_concrete_pattern() {
        let m = matcher(&["Processes[0]"]);
        assert_eq!(m.get_singleton_path(), Some(KeyPath::parse("Processes[0]").unwrap()));
    }

    #[test]
    fn get_singleton_pattern_matches_java_semantics() {
        assert_eq!(matcher(&["A", "B"]).get_singleton_pattern(), None);
        assert_eq!(matcher(&["A"]).get_singleton_pattern(), Some(&pat("A")));
    }

    #[test]
    fn get_next_keys_unions_across_patterns() {
        let m = matcher(&["Processes[0].Threads", "Processes[1].Threads"]);
        assert_eq!(
            m.get_next_keys(&KeyPath::root()),
            HashSet::from(["Processes".to_string()])
        );
        assert_eq!(
            m.get_next_keys(&KeyPath::parse("Processes").unwrap()),
            HashSet::from(["[0]".to_string(), "[1]".to_string()])
        );
    }

    #[test]
    fn get_next_names_short_circuits_on_wildcard() {
        // One pattern's next key is a concrete name, the other's is the name-wildcard "": the
        // union must collapse to the wildcard singleton, not {"A", ""}.
        let m = PathMatcher::any_of_patterns([pat("A"), single_key("")].into_iter());
        assert_eq!(m.get_next_names(&KeyPath::root()), HashSet::from([String::new()]));
    }

    #[test]
    fn get_next_indices_short_circuits_on_wildcard() {
        let m = matcher(&["[0]", "[]"]);
        assert_eq!(m.get_next_indices(&KeyPath::root()), HashSet::from([String::new()]));
    }

    #[test]
    fn get_prev_keys_unions_across_patterns() {
        let m = matcher(&["Processes[0].Threads", "Processes[1].Threads"]);
        assert_eq!(
            m.get_prev_keys(&KeyPath::root()),
            HashSet::from(["Threads".to_string()])
        );
    }

    /// See [`PathMatcher::coalesce_wilds`]'s doc comment: once both wildcard forms are present,
    /// concrete keys of either shape are dropped, but the two wildcard markers themselves both
    /// survive (the reductions don't interfere with each other).
    #[test]
    fn coalesce_wilds_drops_concrete_keys_once_both_wildcards_present() {
        // Four single-key patterns whose getNextKeys, for the root path, contribute "Foo" (a
        // concrete name), "[3]" (a concrete index), "" (the name wildcard), and "[]" (the index
        // wildcard).
        let m = PathMatcher::any_of_patterns(
            [pat("Foo"), pat("[3]"), single_key(""), pat("[]")].into_iter(),
        );
        assert_eq!(
            m.get_next_keys(&KeyPath::root()),
            HashSet::from(["".to_string(), "[]".to_string()])
        );
    }

    #[test]
    fn is_none_true_only_for_empty_matcher() {
        assert!(PathMatcher::any_of_patterns(std::iter::empty()).is_none());
        assert!(!matcher(&["A"]).is_none());
    }

    #[test]
    fn apply_keys_substitutes_each_pattern() {
        let m = matcher(&["Processes[]", "Threads[]"]);
        let applied = m.apply_keys(Align::Left, &["7".to_string()]);
        assert_eq!(
            applied.get_patterns().clone(),
            HashSet::from([pat("Processes[7]"), pat("Threads[7]")])
        );
    }

    #[test]
    fn remove_right_drops_trailing_keys_from_each_pattern() {
        let m = matcher(&["Processes[0].Threads", "Processes[1].Threads"]);
        let removed = m.remove_right(1);
        assert_eq!(
            removed.get_patterns().clone(),
            HashSet::from([pat("Processes[0]"), pat("Processes[1]")])
        );
    }

    #[test]
    fn remove_right_beyond_pattern_length_drops_that_pattern() {
        let m = matcher(&["A"]);
        let removed = m.remove_right(5);
        assert!(removed.is_none());
    }

    #[test]
    fn display_single_pattern_matches_java_format() {
        let m = matcher(&["Processes[0]"]);
        assert_eq!(m.to_string(), "<PathMatcher\n  <PathPattern Processes[0]>\n>");
    }

    #[test]
    fn display_empty_matcher() {
        let m = PathMatcher::any_of_patterns(std::iter::empty());
        assert_eq!(m.to_string(), "<PathMatcher\n  \n>");
    }

    #[test]
    fn equality_ignores_pattern_insertion_order() {
        let a = matcher(&["A", "B"]);
        let b = matcher(&["B", "A"]);
        assert_eq!(a, b);
    }
}
