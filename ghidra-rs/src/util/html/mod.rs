pub mod html_line_splitter;
pub mod preserving_whitespace_handler;
pub mod whitespace_handler;

pub use html_line_splitter::{split, split_with_spacing, MAX_WORD_LENGTH};
pub use preserving_whitespace_handler::PreservingWhitespaceHandler;
pub use whitespace_handler::WhitespaceHandler;
