use super::lcs::get_reducing_lcs;
use crate::util::task::DummyMonitor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    Same { text: String, index: usize },
    Different { text: String, index: usize },
}

impl WordPart {
    pub fn text(&self) -> &str {
        match self {
            Self::Same { text, .. } => text,
            Self::Different { text, .. } => text,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::Same { index, .. } => *index,
            Self::Different { index, .. } => *index,
        }
    }

    pub fn length(&self) -> usize {
        self.text().len()
    }
}

pub struct WordDiffer {
    parts: Vec<WordPart>,
}

impl WordDiffer {
    pub fn new(old_word: &str, new_word: &str) -> Self {
        let x: Vec<char> = new_word.chars().collect();
        let y: Vec<char> = old_word.chars().collect();

        let monitor = DummyMonitor;
        let lcs = match get_reducing_lcs(&x, &y, &monitor) {
            Ok(lcs) if lcs.len() >= 3 => lcs,
            _ => return Self { parts: Vec::new() },
        };

        let mut parts = Vec::new();
        let mut word_index = 0;
        let mut last_written_index = 0;
        let mut diff_buffer = String::new();

        for &c in &lcs {
            while word_index < x.len() {
                let word_char = x[word_index];
                if word_char == c {
                    if !diff_buffer.is_empty() {
                        let offset = word_index - diff_buffer.chars().count();
                        if last_written_index < offset {
                            parts.push(WordPart::Same {
                                text: x[last_written_index..offset].iter().collect(),
                                index: last_written_index,
                            });
                        }
                        parts.push(WordPart::Different {
                            text: diff_buffer.clone(),
                            index: offset,
                        });
                        last_written_index = word_index;
                        diff_buffer.clear();
                    }
                    word_index += 1;
                    break;
                }
                diff_buffer.push(word_char);
                word_index += 1;
            }
        }

        if !diff_buffer.is_empty() {
            let offset = word_index - diff_buffer.chars().count();
            if last_written_index < offset {
                parts.push(WordPart::Same {
                    text: x[last_written_index..offset].iter().collect(),
                    index: last_written_index,
                });
            }
            parts.push(WordPart::Different {
                text: diff_buffer.clone(),
                index: offset,
            });
            last_written_index = word_index;
        }

        if last_written_index < x.len() {
            parts.push(WordPart::Same {
                text: x[last_written_index..].iter().collect(),
                index: last_written_index,
            });
        }

        Self { parts }
    }

    pub fn get_parts(&self) -> &[WordPart] {
        &self.parts
    }

    pub fn get_merged_parts(&self, max_size: usize) -> Vec<WordPart> {
        let mut new_parts = Vec::new();
        let mut i = 0;

        while i < self.parts.len() {
            let part = &self.parts[i];

            match part {
                WordPart::Different { .. } => {
                    new_parts.push(part.clone());
                }
                WordPart::Same { text, .. } if text.len() <= max_size => {
                    if let Some(WordPart::Different {
                        text: prev_text,
                        index: _prev_index,
                    }) = new_parts.last_mut()
                    {
                        if i + 1 < self.parts.len() {
                            if let WordPart::Different {
                                text: next_text, ..
                            } = &self.parts[i + 1]
                            {
                                let merged_text = format!("{}{}{}", prev_text, text, next_text);
                                *prev_text = merged_text;
                                i += 1;
                            } else {
                                new_parts.push(part.clone());
                            }
                        } else {
                            new_parts.push(part.clone());
                        }
                    } else {
                        new_parts.push(part.clone());
                    }
                }
                _ => {
                    new_parts.push(part.clone());
                }
            }
            i += 1;
        }
        new_parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_differ() {
        let differ = WordDiffer::new("Ghidra", "Ghidra-rs");
        let parts = differ.get_parts();
        assert!(!parts.is_empty());
    }
}
