/// A color with RGBA components.
/// Represents the functionality of java.awt.Color for entropy visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

impl Color {
    /// Creates a new color from RGBA components.
    ///
    /// # Arguments
    ///
    /// * `r` - Red component (0-255)
    /// * `g` - Green component (0-255)
    /// * `b` - Blue component (0-255)
    /// * `a` - Alpha component (0-255, where 255 is fully opaque)
    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Color { r, g, b, a }
    }

    /// Creates a new color from RGB components with full opacity.
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Color { r, g, b, a: 255 }
    }

    /// Returns the red component.
    pub fn get_red(&self) -> u8 {
        self.r
    }

    /// Returns the green component.
    pub fn get_green(&self) -> u8 {
        self.g
    }

    /// Returns the blue component.
    pub fn get_blue(&self) -> u8 {
        self.b
    }

    /// Returns the alpha (opacity) component.
    pub fn get_alpha(&self) -> u8 {
        self.a
    }

    /// Converts to a 32-bit ARGB color value.
    pub fn to_argb(&self) -> u32 {
        ((self.a as u32) << 24)
            | ((self.r as u32) << 16)
            | ((self.g as u32) << 8)
            | (self.b as u32)
    }

    /// Creates a Color from a 32-bit ARGB color value.
    pub fn from_argb(argb: u32) -> Self {
        Color {
            a: ((argb >> 24) & 0xFF) as u8,
            r: ((argb >> 16) & 0xFF) as u8,
            g: ((argb >> 8) & 0xFF) as u8,
            b: (argb & 0xFF) as u8,
        }
    }
}

/// Entropy information for the Entropy color legend panel.
/// A KnotRecord records a "known" entropy range for a specific type of data in a program.
/// For example, if you compute the entropy for a range of bytes containing ASCII characters,
/// you will get an entropy score close to 4.7.
#[derive(Debug, Clone, PartialEq)]
pub struct KnotRecord {
    pub name: String,
    pub color: Color,
    pub start: i32,
    pub end: i32,
    pub point: i32,
}

impl KnotRecord {
    /// Constructor
    ///
    /// # Arguments
    ///
    /// * `name` - A name for what this range represents (e.g., ASCII, X86 code)
    /// * `color` - The color to associate with this type
    /// * `start` - The minimum entropy for this range
    /// * `end` - The maximum entropy for this range
    /// * `point` - The x coordinate in the legend for this knot
    pub fn new<S: Into<String>>(name: S, color: Color, start: i32, end: i32, point: i32) -> Self {
        KnotRecord { name: name.into(), color, start, end, point }
    }

    /// Returns the name of this knot record.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Checks if an entropy value is contained within this knot's range.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy value to check
    ///
    /// # Returns
    ///
    /// True if the entropy value is between start and end (inclusive), false otherwise.
    pub fn contains(&self, entropy: i32) -> bool {
        entropy >= self.start && entropy <= self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_creation_rgba() {
        let color = Color::new(255, 128, 64, 200);
        assert_eq!(color.get_red(), 255);
        assert_eq!(color.get_green(), 128);
        assert_eq!(color.get_blue(), 64);
        assert_eq!(color.get_alpha(), 200);
    }

    #[test]
    fn test_color_creation_rgb() {
        let color = Color::rgb(100, 150, 200);
        assert_eq!(color.get_red(), 100);
        assert_eq!(color.get_green(), 150);
        assert_eq!(color.get_blue(), 200);
        assert_eq!(color.get_alpha(), 255);
    }

    #[test]
    fn test_color_to_argb() {
        let color = Color::new(255, 128, 64, 200);
        let argb = color.to_argb();
        // Java Color.getRGB() packs as 0xAARRGGBB: a=200(0xC8) r=255(0xFF) g=128(0x80) b=64(0x40)
        assert_eq!(argb, 0xC8FF8040);
    }

    #[test]
    fn test_color_from_argb() {
        let argb = 0xC8FF4040u32;
        let color = Color::from_argb(argb);
        assert_eq!(color.get_red(), 255);
        assert_eq!(color.get_green(), 64);
        assert_eq!(color.get_blue(), 64);
        assert_eq!(color.get_alpha(), 200);
    }

    #[test]
    fn test_color_argb_roundtrip() {
        let original = Color::new(50, 100, 150, 230);
        let argb = original.to_argb();
        let restored = Color::from_argb(argb);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_color_clone_and_copy() {
        let color = Color::rgb(255, 0, 0);
        let cloned = color;
        assert_eq!(color, cloned);
    }

    #[test]
    fn test_knot_record_creation() {
        let color = Color::rgb(255, 0, 0);
        let record = KnotRecord::new("ASCII", color, 0, 100, 50);
        assert_eq!(record.get_name(), "ASCII");
        assert_eq!(record.color, color);
        assert_eq!(record.start, 0);
        assert_eq!(record.end, 100);
        assert_eq!(record.point, 50);
    }

    #[test]
    fn test_knot_record_creation_with_owned_string() {
        let color = Color::rgb(0, 255, 0);
        let record = KnotRecord::new("X86 Code".to_string(), color, 50, 200, 125);
        assert_eq!(record.get_name(), "X86 Code");
        assert_eq!(record.color, color);
        assert_eq!(record.start, 50);
        assert_eq!(record.end, 200);
        assert_eq!(record.point, 125);
    }

    #[test]
    fn test_knot_record_contains() {
        let color = Color::rgb(100, 100, 255);
        let record = KnotRecord::new("Test", color, 10, 50, 30);

        assert!(!record.contains(9));
        assert!(record.contains(10));
        assert!(record.contains(30));
        assert!(record.contains(50));
        assert!(!record.contains(51));
    }

    #[test]
    fn test_knot_record_contains_single_value() {
        let color = Color::rgb(200, 200, 200);
        let record = KnotRecord::new("Single", color, 42, 42, 42);

        assert!(!record.contains(41));
        assert!(record.contains(42));
        assert!(!record.contains(43));
    }

    #[test]
    fn test_knot_record_clone() {
        let color = Color::rgb(255, 128, 64);
        let record = KnotRecord::new("Original", color, 5, 95, 50);
        let cloned = record.clone();

        assert_eq!(record, cloned);
        assert_eq!(cloned.get_name(), "Original");
        assert!(cloned.contains(50));
    }

    #[test]
    fn test_knot_record_with_negative_values() {
        let color = Color::rgb(0, 0, 0);
        let record = KnotRecord::new("Negative", color, -100, -50, -75);

        assert!(!record.contains(-101));
        assert!(record.contains(-100));
        assert!(record.contains(-75));
        assert!(record.contains(-50));
        assert!(!record.contains(-49));
    }
}
