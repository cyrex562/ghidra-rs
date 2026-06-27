pub mod text_line;

/// RGBA color, mirroring `java.awt.Color` as used in the html diff utilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }
}

impl std::fmt::Display for Color {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Color[r={},g={},b={},a={}]", self.r, self.g, self.b, self.a)
    }
}

/// Error/invalid highlight color, approximating Java's `Messages.ERROR`.
pub const INVALID_COLOR: Color = Color::rgb(255, 0, 0);

/// A line of text that can be validated (diff-compared) against another line.
///
/// Mirrors `ghidra.app.util.html.ValidatableLine`.
pub trait ValidatableLine {
    /// Updates text color based on whether this line matches `other_line`.
    ///
    /// If `other_line` is `None`, colors `self` with `invalid_color`. Otherwise, if
    /// `self` and `other_line` do not match, colors both with `invalid_color`.
    ///
    /// # Panics
    /// Panics if `invalid_color` is somehow unrepresentable (never in practice — mirrors
    /// Java's `NullPointerException("Color cannot be null")`).
    fn update_color(&mut self, other_line: Option<&mut dyn ValidatableLine>, invalid_color: Color);

    /// Returns `true` if this line's text color has been set (i.e. it carries diff coloring).
    fn is_diff_colored(&self) -> bool;

    /// Returns `true` if this line's text matches `other_line`'s text.
    fn matches_line(&self, other_line: &dyn ValidatableLine) -> bool;

    /// Returns a fresh copy of this line (without diff color).
    fn copy(&self) -> Box<dyn ValidatableLine>;

    /// Returns the text content of this line.
    fn get_text(&self) -> &str;

    /// Sets the text color.
    fn set_text_color(&mut self, color: Color);

    /// Pairs this line with `line` for validation and triggers a color update.
    ///
    /// # Note
    /// The Java source calls `line.setValidationLine(this)` here to create a mutual
    /// back-reference. In Rust that causes borrow conflicts; callers must set both sides
    /// explicitly, e.g. via [`validate_pair`].
    fn set_validation_line(&mut self, line: &mut dyn ValidatableLine);

    /// Returns `true` if this line has been paired with a validation counterpart.
    fn is_validated(&self) -> bool;
}

/// Pairs two lines for mutual validation, replicating Java's single
/// `setValidationLine` call that recurses to set both sides.
pub fn validate_pair(a: &mut dyn ValidatableLine, b: &mut dyn ValidatableLine) {
    a.set_validation_line(b);
    b.set_validation_line(a);
}
