//! Rust port of `ghidra.app.plugin.core.strings.StringTrigramIterator`.

use std::str::Chars;

use super::trigram::Trigram;

/// Splits a string into [`Trigram`]s, including a start-of-string and an end-of-string
/// trigram (code point `0` stands for the position before the first / after the last char).
///
/// For `"abc"` this yields `[0,a,b]`, `[a,b,c]`, `[b,c,0]`. Strings with fewer than 3 code
/// points yield nothing.
///
/// Mirrors the Java `Iterator<Trigram>`; per the shape rules it is a Rust [`Iterator`] rather
/// than a `hasNext`/`next` pair. Java walks UTF-16 indices with `codePointAt`; iterating
/// [`char`]s visits the same code points.
pub struct StringTrigramIterator<'a> {
    /// Remaining code points, or `None` once exhausted (or if the string was too short).
    chars: Option<Chars<'a>>,
    prev_code_points: [i32; 2],
}

impl<'a> StringTrigramIterator<'a> {
    /// Creates an iterator over the trigrams of `s`.
    ///
    /// Mirrors `StringTrigramIterator(String)`, including discarding the leading
    /// `[0, 0, first char]` trigram.
    pub fn new(s: &'a str) -> StringTrigramIterator<'a> {
        // throw away string if length is less than 3
        let chars = (s.chars().count() >= 3).then(|| s.chars());
        let mut it = StringTrigramIterator { chars, prev_code_points: [0, 0] };
        it.next(); // throw away first value which will be "\0, \0, first char"
        it
    }
}

impl Iterator for StringTrigramIterator<'_> {
    type Item = Trigram;

    fn next(&mut self) -> Option<Trigram> {
        let chars = self.chars.as_mut()?;
        let code_point = match chars.next() {
            Some(c) => c as i32,
            None => {
                // the end-of-string position is emitted once, then the iterator is exhausted
                self.chars = None;
                0
            }
        };
        let result = Trigram::of(self.prev_code_points[0], self.prev_code_points[1], code_point);
        self.prev_code_points = [self.prev_code_points[1], code_point];
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tri(s: &str) -> Vec<Trigram> {
        StringTrigramIterator::new(s).collect()
    }

    fn cp(c: char) -> i32 {
        c as i32
    }

    #[test]
    fn three_char_string_yields_start_middle_end() {
        assert_eq!(
            tri("abc"),
            vec![
                Trigram::of(0, cp('a'), cp('b')),
                Trigram::of(cp('a'), cp('b'), cp('c')),
                Trigram::of(cp('b'), cp('c'), 0),
            ]
        );
    }

    #[test]
    fn short_strings_yield_nothing() {
        assert!(tri("").is_empty());
        assert!(tri("a").is_empty());
        assert!(tri("ab").is_empty());
        // counts code points, not UTF-16 units: two supplementary chars are still too short
        assert!(tri("\u{1F600}\u{1F601}").is_empty());
    }

    #[test]
    fn count_is_length_plus_one_minus_one() {
        // n code points -> n trigrams (n+1 positions incl. end, minus the discarded first)
        assert_eq!(tri("hello").len(), 5);
        assert_eq!(tri("hello").last().unwrap().to_string(), "lo[NUL]");
    }

    #[test]
    fn supplementary_code_points_are_single_positions() {
        let t = tri("a\u{1F600}b");
        assert_eq!(
            t,
            vec![
                Trigram::of(0, cp('a'), 0x1F600),
                Trigram::of(cp('a'), 0x1F600, cp('b')),
                Trigram::of(0x1F600, cp('b'), 0),
            ]
        );
    }

    #[test]
    fn trigram_iterate_is_the_same_iterator() {
        assert_eq!(Trigram::iterate("xyz").collect::<Vec<_>>(), tri("xyz"));
    }

    #[test]
    fn exhausted_iterator_stays_exhausted() {
        let mut it = StringTrigramIterator::new("abc");
        assert_eq!(it.by_ref().count(), 3);
        assert_eq!(it.next(), None);
    }
}
