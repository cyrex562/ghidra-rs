/// Represents a word from console input with its position information.
///
/// Contains the text of the word and its start and end positions in the original input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleWord {
    word: String,
    start_position: usize,
    end_position: usize,
}

impl ConsoleWord {
    /// Creates a new ConsoleWord.
    ///
    /// # Arguments
    /// * `word` - The text of the word
    /// * `start_position` - The starting position in the input
    /// * `end_position` - The ending position in the input
    pub fn new(word: String, start_position: usize, end_position: usize) -> Self {
        Self {
            word,
            start_position,
            end_position,
        }
    }

    /// Returns the text of this word.
    pub fn word(&self) -> &str {
        &self.word
    }

    /// Returns the starting position of this word in the input.
    pub fn start_position(&self) -> usize {
        self.start_position
    }

    /// Returns the ending position of this word in the input.
    pub fn end_position(&self) -> usize {
        self.end_position
    }

    /// Returns a new ConsoleWord with special characters removed from the start and end.
    ///
    /// Special characters are: `]`, `[`, `,`, `.`
    pub fn get_word_without_special_characters(&self) -> ConsoleWord {
        let mut chars: Vec<char> = self.word.chars().collect();
        let mut new_end_position = self.end_position;
        let mut new_start_position = self.start_position;

        // Trim the back
        while !chars.is_empty() && Self::is_special_char(chars[chars.len() - 1]) {
            chars.pop();
            new_end_position -= 1;
        }

        // Trim the front
        while !chars.is_empty() && Self::is_special_char(chars[0]) {
            chars.remove(0);
            new_start_position += 1;
        }

        let trimmed_word = chars.iter().collect::<String>();
        ConsoleWord::new(trimmed_word, new_start_position, new_end_position)
    }

    /// Checks if a character is a special character that should be trimmed.
    fn is_special_char(c: char) -> bool {
        c == ']' || c == '[' || c == ',' || c == '.'
    }
}

impl std::fmt::Display for ConsoleWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({},{})",
            self.word, self.start_position, self.end_position
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let word = ConsoleWord::new("hello".to_string(), 0, 5);
        assert_eq!(word.word(), "hello");
        assert_eq!(word.start_position(), 0);
        assert_eq!(word.end_position(), 5);
    }

    #[test]
    fn test_display() {
        let word = ConsoleWord::new("hello".to_string(), 0, 5);
        assert_eq!(word.to_string(), "hello(0,5)");
    }

    #[test]
    fn test_get_word_without_special_characters_no_special() {
        let word = ConsoleWord::new("hello".to_string(), 0, 5);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 0);
        assert_eq!(trimmed.end_position(), 5);
    }

    #[test]
    fn test_get_word_without_special_characters_trailing() {
        let word = ConsoleWord::new("hello.".to_string(), 0, 6);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 0);
        assert_eq!(trimmed.end_position(), 5);
    }

    #[test]
    fn test_get_word_without_special_characters_leading() {
        let word = ConsoleWord::new("[hello".to_string(), 0, 6);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 1);
        assert_eq!(trimmed.end_position(), 6);
    }

    #[test]
    fn test_get_word_without_special_characters_both_sides() {
        let word = ConsoleWord::new("[hello]".to_string(), 0, 7);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 1);
        assert_eq!(trimmed.end_position(), 6);
    }

    #[test]
    fn test_get_word_without_special_characters_multiple_trailing() {
        let word = ConsoleWord::new("hello,,.".to_string(), 0, 8);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 0);
        assert_eq!(trimmed.end_position(), 5);
    }

    #[test]
    fn test_get_word_without_special_characters_multiple_leading() {
        let word = ConsoleWord::new(".,[hello".to_string(), 0, 8);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hello");
        assert_eq!(trimmed.start_position(), 3);
        assert_eq!(trimmed.end_position(), 8);
    }

    #[test]
    fn test_get_word_without_special_characters_only_special() {
        let word = ConsoleWord::new(".,[".to_string(), 0, 3);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "");
        assert_eq!(trimmed.start_position(), 3);
        assert_eq!(trimmed.end_position(), 3);
    }

    #[test]
    fn test_get_word_without_special_characters_middle_special_preserved() {
        let word = ConsoleWord::new("[hel.lo]".to_string(), 0, 8);
        let trimmed = word.get_word_without_special_characters();
        assert_eq!(trimmed.word(), "hel.lo");
        assert_eq!(trimmed.start_position(), 1);
        assert_eq!(trimmed.end_position(), 7);
    }

    #[test]
    fn test_equality() {
        let word1 = ConsoleWord::new("hello".to_string(), 0, 5);
        let word2 = ConsoleWord::new("hello".to_string(), 0, 5);
        assert_eq!(word1, word2);
    }

    #[test]
    fn test_inequality_word() {
        let word1 = ConsoleWord::new("hello".to_string(), 0, 5);
        let word2 = ConsoleWord::new("world".to_string(), 0, 5);
        assert_ne!(word1, word2);
    }

    #[test]
    fn test_inequality_start_position() {
        let word1 = ConsoleWord::new("hello".to_string(), 0, 5);
        let word2 = ConsoleWord::new("hello".to_string(), 1, 5);
        assert_ne!(word1, word2);
    }

    #[test]
    fn test_clone() {
        let word1 = ConsoleWord::new("hello".to_string(), 0, 5);
        let word2 = word1.clone();
        assert_eq!(word1, word2);
    }
}
