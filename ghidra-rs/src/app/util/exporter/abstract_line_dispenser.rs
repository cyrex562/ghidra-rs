//! Abstract line dispenser for exporters.

use crate::program::model::address::Address;

/// Trait for generating lines of output, optionally formatted as HTML.
///
/// Mirrors `ghidra.app.util.exporter.AbstractLineDispenser`.
pub trait AbstractLineDispenser {
    /// Returns whether more lines are available.
    fn has_more_lines(&self) -> bool;

    /// Returns the next line of output.
    fn get_next_line(&self) -> String;

    /// Releases any resources held by this dispenser.
    fn dispose(&mut self);

    /// Returns whether the output should be formatted as HTML.
    fn is_html(&self) -> bool;

    /// Returns the width limit for output lines.
    fn width(&self) -> usize;

    /// Returns the fill amount used for padding.
    fn fill_amount(&self) -> usize;

    /// Returns the prefix used for lines.
    fn prefix(&self) -> Option<&str>;

    /// Returns the current line index.
    fn index(&self) -> usize;
}

/// Generates a unique string representation of an address.
///
/// Mirrors `AbstractLineDispenser.getUniqueAddressString(Address)`.
pub fn get_unique_address_string(addr: &Address) -> String {
    addr.to_string()
}

/// Generates a string of spaces with the specified length.
///
/// Mirrors `AbstractLineDispenser.getFill(int)`.
pub fn get_fill(amt: usize) -> String {
    " ".repeat(amt)
}

/// Clips or pads a string to fit within a specified width.
///
/// Uses left justification and pads shorter strings if necessary.
///
/// Mirrors `AbstractLineDispenser.clip(String, int)`.
pub fn clip(s: &str, width: usize) -> String {
    clip_with_options(s, width, true, true)
}

/// Clips or pads a string to fit within a specified width with options.
///
/// # Arguments
///
/// * `s` - The string to clip or pad.
/// * `width` - The target width. Returns empty string if negative (treated as 0 in Rust).
/// * `pad_if_shorter` - If true, pads shorter strings to the target width.
/// * `left_justify` - If true, uses left justification; otherwise right justification.
///
/// If the string is shorter than the width, it is padded with spaces (if `pad_if_shorter` is true).
/// If the string is longer than the width, it is truncated with "..." appended (if width >= 3).
/// For width < 3, returns "." (width=1), ".." (width=2), or "" (width=0).
///
/// Mirrors `AbstractLineDispenser.clip(String, int, boolean, boolean)`.
pub fn clip_with_options(s: &str, width: usize, pad_if_shorter: bool, left_justify: bool) -> String {
    if width == 0 {
        return String::new();
    }

    let s_len = s.len();

    if s_len <= width {
        if left_justify {
            if pad_if_shorter {
                format!("{}{}", s, get_fill(width - s_len))
            } else {
                s.to_string()
            }
        } else {
            if pad_if_shorter {
                format!("{}{}", get_fill(width - s_len), s)
            } else {
                s.to_string()
            }
        }
    } else {
        match width {
            1 => ".".to_string(),
            2 => "..".to_string(),
            3 => "...".to_string(),
            _ => format!("{}...", &s[..width - 3]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[test]
    fn test_get_fill() {
        assert_eq!(get_fill(0), "");
        assert_eq!(get_fill(1), " ");
        assert_eq!(get_fill(5), "     ");
        assert_eq!(get_fill(10), "          ");
    }

    #[test]
    fn test_clip_exact_width() {
        assert_eq!(clip("hello", 5), "hello");
    }

    #[test]
    fn test_clip_shorter_string_left_justify() {
        assert_eq!(clip("hi", 5), "hi   ");
    }

    #[test]
    fn test_clip_shorter_string_right_justify() {
        assert_eq!(clip_with_options("hi", 5, true, false), "   hi");
    }

    #[test]
    fn test_clip_shorter_string_no_padding() {
        assert_eq!(clip_with_options("hi", 5, false, true), "hi");
    }

    #[test]
    fn test_clip_longer_string_width_3() {
        assert_eq!(clip("hello world", 3), "...");
    }

    #[test]
    fn test_clip_longer_string_width_4() {
        assert_eq!(clip("hello world", 4), "h...");
    }

    #[test]
    fn test_clip_longer_string_width_5() {
        assert_eq!(clip("hello world", 5), "he...");
    }

    #[test]
    fn test_clip_width_0() {
        assert_eq!(clip("hello", 0), "");
    }

    #[test]
    fn test_clip_width_1() {
        assert_eq!(clip("hello", 1), ".");
    }

    #[test]
    fn test_clip_width_2() {
        assert_eq!(clip("hello", 2), "..");
    }

    #[test]
    fn test_clip_empty_string_with_width() {
        assert_eq!(clip("", 5), "     ");
    }

    #[test]
    fn test_clip_empty_string_no_padding() {
        assert_eq!(clip_with_options("", 5, false, true), "");
    }

    #[test]
    fn test_get_unique_address_string() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x1000);
        let addr_str = get_unique_address_string(&addr);
        assert!(addr_str.contains("ram"));
        assert!(addr_str.contains("1000"));
    }

    #[test]
    fn test_clip_with_special_chars() {
        assert_eq!(clip("hello\nworld", 5), "hello");
        assert_eq!(clip("a\tb\tc", 3), "...");
    }

    #[test]
    fn test_clip_unicode() {
        assert_eq!(clip("hello", 7), "hello  ");
    }

    #[test]
    fn test_clip_right_justify_longer() {
        assert_eq!(
            clip_with_options("hello world", 7, true, false),
            "he....."
        );
    }

    #[test]
    fn test_clip_with_options_comprehensive() {
        assert_eq!(clip_with_options("test", 6, true, true), "test  ");
        assert_eq!(clip_with_options("test", 6, false, true), "test");
        assert_eq!(clip_with_options("test", 6, true, false), "  test");
        assert_eq!(clip_with_options("test", 6, false, false), "test");
    }
}
