//! Port of the `ghidra.markdown` Java package.
//!
//! Provides conversion of Markdown (CommonMark) text and files into complete
//! HTML documents.

pub mod markdown_to_html;

pub use markdown_to_html::MarkdownToHtml;
