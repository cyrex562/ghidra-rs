//! Renderer-supplied font measurements (spec §5): the listing is monospace,
//! so a per-style character advance plus vertical metrics is exact.

/// Measurements of the listing font, supplied by the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FontMetrics {
    /// Advance width of one character in the plain style, in pixels.
    pub char_width: i32,
    /// Advance width in the bold style.
    pub bold_char_width: i32,
    /// Pixels above the baseline.
    pub ascent: i32,
    /// Pixels below the baseline.
    pub descent: i32,
    /// Extra line spacing.
    pub leading: i32,
}

impl FontMetrics {
    /// A monospace font with `char_width` for both styles.
    pub const fn monospace(char_width: i32, ascent: i32, descent: i32) -> Self {
        Self { char_width, bold_char_width: char_width, ascent, descent, leading: 0 }
    }

    /// Line height (ascent + descent + leading).
    pub fn line_height(&self) -> i32 {
        self.ascent + self.descent + self.leading
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_height_sums_parts() {
        let m = FontMetrics { char_width: 7, bold_char_width: 8, ascent: 11, descent: 3, leading: 1 };
        assert_eq!(m.line_height(), 15);
        assert_eq!(FontMetrics::monospace(7, 11, 3).bold_char_width, 7);
    }
}
