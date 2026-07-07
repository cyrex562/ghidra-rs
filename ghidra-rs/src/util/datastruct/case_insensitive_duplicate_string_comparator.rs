/// Comparator for sorting strings case-insensitively, with case-insensitive
/// duplicates sub-sorted by reverse case so that lower-case sorts before upper-case.
///
/// Example: "abc", "bob", "Bob", "zzz" always sort in that order. In a normal
/// case-insensitive sort the relative order of "bob" and "Bob" would be arbitrary.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaseInsensitiveDuplicateStringComparator;

impl CaseInsensitiveDuplicateStringComparator {
    /// Compares two strings case-insensitively, breaking ties with a reverse
    /// case-sensitive comparison so that lower-case sorts first.
    pub fn compare(name1: &str, name2: &str) -> std::cmp::Ordering {
        let result = name1.to_lowercase().cmp(&name2.to_lowercase());
        if result == std::cmp::Ordering::Equal {
            // Reverse case-sensitive order so lower-case comes before upper-case.
            name2.cmp(name1)
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn different_words_sort_case_insensitively() {
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("abc", "zzz"),
            Ordering::Less
        );
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("zzz", "abc"),
            Ordering::Greater
        );
    }

    #[test]
    fn identical_strings_are_equal() {
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("abc", "abc"),
            Ordering::Equal
        );
    }

    #[test]
    fn lowercase_before_uppercase_when_case_insensitive_equal() {
        // "bob" and "Bob" are equal ignoring case; lowercase must sort first.
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("bob", "Bob"),
            Ordering::Less
        );
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("Bob", "bob"),
            Ordering::Greater
        );
    }

    #[test]
    fn sort_matches_javadoc_example() {
        // Java doc: "abc", "bob", "Bob", "zzz" always sort in that order.
        let mut words = vec!["zzz", "Bob", "abc", "bob"];
        words.sort_by(|a, b| CaseInsensitiveDuplicateStringComparator::compare(a, b));
        assert_eq!(words, vec!["abc", "bob", "Bob", "zzz"]);
    }

    #[test]
    fn all_uppercase_before_all_lowercase_within_same_word() {
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("ABC", "abc"),
            Ordering::Greater
        );
    }

    #[test]
    fn empty_string_sorts_before_nonempty() {
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("", "a"),
            Ordering::Less
        );
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("a", ""),
            Ordering::Greater
        );
    }

    #[test]
    fn two_empty_strings_are_equal() {
        assert_eq!(
            CaseInsensitiveDuplicateStringComparator::compare("", ""),
            Ordering::Equal
        );
    }
}
