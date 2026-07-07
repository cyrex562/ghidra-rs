/// A model to generate the suggested completions, given a viable prefix.
///
/// Corresponds to `docking.widgets.autocomplete.AutocompletionModel`.
pub trait AutocompletionModel<T> {
    /// Compute a collection of possible completions to the given text (prefix).
    ///
    /// `text` is the prefix — the text to the left of the user's caret. Returns a
    /// (possibly empty) list of suggested completions.
    ///
    /// There is no requirement that the returned items actually start with the given
    /// prefix; however, by default, the displayed text for the suggested item is
    /// inserted at the caret, without changing the surrounding text.
    fn compute_completions(&self, text: &str) -> Vec<T>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PrefixModel {
        candidates: Vec<String>,
    }

    impl AutocompletionModel<String> for PrefixModel {
        fn compute_completions(&self, text: &str) -> Vec<String> {
            self.candidates
                .iter()
                .filter(|s| s.starts_with(text))
                .cloned()
                .collect()
        }
    }

    #[test]
    fn returns_matching_completions() {
        let model = PrefixModel {
            candidates: vec!["foo".to_string(), "foobar".to_string(), "baz".to_string()],
        };
        let results = model.compute_completions("foo");
        assert_eq!(results, vec!["foo", "foobar"]);
    }

    #[test]
    fn returns_empty_when_no_match() {
        let model = PrefixModel {
            candidates: vec!["alpha".to_string(), "beta".to_string()],
        };
        let results = model.compute_completions("xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn empty_prefix_returns_all_candidates() {
        let model = PrefixModel {
            candidates: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        let results = model.compute_completions("");
        assert_eq!(results, vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_candidate_list_returns_empty() {
        let model = PrefixModel { candidates: vec![] };
        let results = model.compute_completions("any");
        assert!(results.is_empty());
    }
}
