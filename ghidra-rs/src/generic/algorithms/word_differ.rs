use std::collections::BTreeMap;

use super::string_reducing_lcs::StringReducingLcs;
use crate::util::task::DummyMonitor;

/// A piece of a diffed word: either unchanged ("same") text or a differing span, each
/// carrying its character offset into the "new" word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    Same { text: String, index: usize },
    Different { text: String, index: usize },
}

impl WordPart {
    pub fn text(&self) -> &str {
        match self {
            Self::Same { text, .. } | Self::Different { text, .. } => text,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::Same { index, .. } | Self::Different { index, .. } => *index,
        }
    }

    pub fn length(&self) -> usize {
        self.text().chars().count()
    }
}

/// Finds differences between two words (any two strings). The results are available via
/// [`WordDiffer::get_parts`].
pub struct WordDiffer {
    parts: Vec<WordPart>,
}

impl WordDiffer {
    /// Diffs the text between the old and new word. The new word is the current version of
    /// the two strings, the old word is the previous version.
    pub fn new(old_word: &str, new_word: &str) -> Self {
        let new_chars: Vec<char> = new_word.chars().collect();

        let lcs = match Self::get_lcs(new_word, old_word) {
            Some(lcs) => lcs,
            None => return Self { parts: Vec::new() },
        };

        let words_by_offset = Self::build_word_offsets(&new_chars, &lcs);
        let parts = Self::create_word_parts(&new_chars, &words_by_offset);
        Self { parts }
    }

    /// Returns the "new word" broken into parts, with each part being the same text or
    /// different text; empty if the LCS could not be created.
    pub fn get_parts(&self) -> &[WordPart] {
        &self.parts
    }

    /// The same as [`Self::get_parts`] except that this method merges differences that are
    /// separated only by `max_size` or fewer characters, collapsing them into a single
    /// differing part. Only differing parts (raw or merged) are returned.
    pub fn get_merged_parts(&self, max_size: usize) -> Vec<WordPart> {
        let mut new_parts: Vec<WordPart> = Vec::new();
        let mut i = 0;
        while i < self.parts.len() {
            let part = &self.parts[i];
            if matches!(part, WordPart::Different { .. }) {
                new_parts.push(part.clone());
                i += 1;
                continue;
            }

            if part.length() > max_size {
                i += 1;
                continue;
            }

            let next_part = self.parts.get(i + 1);
            let merged = match (new_parts.last(), next_part) {
                (
                    Some(WordPart::Different {
                        text: prev_text,
                        index: prev_index,
                    }),
                    Some(WordPart::Different { text: next_text, .. }),
                ) => Some(WordPart::Different {
                    text: format!("{}{}{}", prev_text, part.text(), next_text),
                    index: *prev_index,
                }),
                _ => None,
            };

            match merged {
                Some(merged_part) => {
                    new_parts.pop();
                    new_parts.push(merged_part);
                    i += 2;
                }
                None => {
                    i += 1;
                }
            }
        }
        new_parts
    }

    fn get_lcs(new_word: &str, old_word: &str) -> Option<Vec<char>> {
        let lcs = StringReducingLcs::new(new_word.to_string(), old_word.to_string());
        let lcs_string = lcs.get_lcs(&DummyMonitor).ok()?;
        if lcs_string.chars().count() < 3 {
            return None;
        }
        Some(lcs_string.chars().collect())
    }

    /// Turns the LCS match into one or more words that do not match. This uses the common
    /// characters to build a mapping of the different words and their offsets into the new
    /// word originally passed to the differ.
    fn build_word_offsets(new_word: &[char], lcs: &[char]) -> BTreeMap<usize, String> {
        let mut words_by_offset = BTreeMap::new();

        let mut buffy = String::new();
        let mut word_index = 0usize;
        for &c in lcs {
            while word_index < new_word.len() {
                let word_char = new_word[word_index];
                if word_char == c {
                    let offset = word_index - buffy.chars().count();
                    Self::save_word(&mut buffy, offset, &mut words_by_offset);
                    word_index += 1;
                    break;
                }
                buffy.push(word_char);
                word_index += 1;
            }
        }

        let offset = word_index - buffy.chars().count();
        Self::save_word(&mut buffy, offset, &mut words_by_offset);

        if word_index < new_word.len() {
            buffy.extend(new_word[word_index..].iter());
            Self::save_word(&mut buffy, word_index, &mut words_by_offset);
        }

        words_by_offset
    }

    fn save_word(
        buffy: &mut String,
        char_position: usize,
        word_indices: &mut BTreeMap<usize, String>,
    ) {
        if !buffy.is_empty() {
            word_indices.insert(char_position, std::mem::take(buffy));
        }
    }

    fn create_word_parts(
        new_word: &[char],
        word_indices: &BTreeMap<usize, String>,
    ) -> Vec<WordPart> {
        let mut results = Vec::new();
        let mut last_written_index = 0usize;

        for (&index, word) in word_indices {
            if last_written_index < index {
                let text: String = new_word[last_written_index..index].iter().collect();
                results.push(WordPart::Same {
                    text,
                    index: last_written_index,
                });
            }

            results.push(WordPart::Different {
                text: word.clone(),
                index,
            });
            last_written_index = index + word.chars().count();
        }

        if last_written_index < new_word.len() {
            let text: String = new_word[last_written_index..].iter().collect();
            results.push(WordPart::Same {
                text,
                index: last_written_index,
            });
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_words_produce_a_single_same_part() {
        let differ = WordDiffer::new("Ghidra", "Ghidra");
        assert_eq!(
            differ.get_parts(),
            &[WordPart::Same {
                text: "Ghidra".to_string(),
                index: 0
            }]
        );
    }

    #[test]
    fn test_appended_suffix_is_a_trailing_different_part() {
        let differ = WordDiffer::new("Ghidra", "Ghidra-rs");
        assert_eq!(
            differ.get_parts(),
            &[
                WordPart::Same {
                    text: "Ghidra".to_string(),
                    index: 0
                },
                WordPart::Different {
                    text: "-rs".to_string(),
                    index: 6
                },
            ]
        );
    }

    #[test]
    fn test_lcs_too_short_yields_no_parts() {
        let differ = WordDiffer::new("xy", "ab");
        assert!(differ.get_parts().is_empty());
    }

    #[test]
    fn test_two_inserted_characters_produce_two_different_parts() {
        let differ = WordDiffer::new("abcdefghi", "abcXdefYghi");
        assert_eq!(
            differ.get_parts(),
            &[
                WordPart::Same {
                    text: "abc".to_string(),
                    index: 0
                },
                WordPart::Different {
                    text: "X".to_string(),
                    index: 3
                },
                WordPart::Same {
                    text: "def".to_string(),
                    index: 4
                },
                WordPart::Different {
                    text: "Y".to_string(),
                    index: 7
                },
                WordPart::Same {
                    text: "ghi".to_string(),
                    index: 8
                },
            ]
        );
    }

    #[test]
    fn test_get_merged_parts_combines_diffs_separated_by_a_short_gap() {
        let differ = WordDiffer::new("abcdefghi", "abcXdefYghi");
        let merged = differ.get_merged_parts(3);
        assert_eq!(
            merged,
            vec![WordPart::Different {
                text: "XdefY".to_string(),
                index: 3
            }]
        );
    }
}
