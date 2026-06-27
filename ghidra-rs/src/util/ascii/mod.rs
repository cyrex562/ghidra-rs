pub mod ascii_char_set_recognizer;

pub use ascii_char_set_recognizer::AsciiCharSetRecognizer;

/// Trait mirroring `ghidra.util.ascii.CharSetRecognizer`.
pub trait CharSetRecognizer {
    fn contains(&self, c: i32) -> bool;
}
