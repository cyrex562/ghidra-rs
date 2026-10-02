//! Toolkit-neutral `java.awt.Color` value.

/// A port of the `java.awt.Color` value: sRGB components plus alpha, stored as
/// Java's packed ARGB. Only the value semantics are ported; painting belongs to
/// the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    argb: u32,
}

impl Color {
    /// `java.awt.Color.WHITE`
    pub const WHITE: Color = Color::from_rgb(255, 255, 255);
    /// `java.awt.Color.BLACK`
    pub const BLACK: Color = Color::from_rgb(0, 0, 0);
    /// `java.awt.Color.RED`
    pub const RED: Color = Color::from_rgb(255, 0, 0);
    /// `java.awt.Color.GREEN`
    pub const GREEN: Color = Color::from_rgb(0, 255, 0);
    /// `java.awt.Color.BLUE`
    pub const BLUE: Color = Color::from_rgb(0, 0, 255);

    /// Opaque color from components (`new Color(r, g, b)`).
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self::from_rgba(r, g, b, 255)
    }

    /// Color with alpha (`new Color(r, g, b, a)`).
    pub const fn from_rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self {
            argb: (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32,
        }
    }

    /// `new Color(int rgb)`: the top byte is ignored and alpha is 255.
    pub const fn from_rgb_int(rgb: i32) -> Self {
        Self {
            argb: 0xFF00_0000 | (rgb as u32 & 0x00FF_FFFF),
        }
    }

    /// `new Color(int argb, true)`: alpha taken from the top byte.
    pub const fn from_argb_int(argb: i32) -> Self {
        Self { argb: argb as u32 }
    }

    /// `getRGB()`: packed ARGB as Java's signed int.
    pub const fn get_rgb(self) -> i32 {
        self.argb as i32
    }

    /// `getRed()`
    pub const fn red(self) -> u8 {
        (self.argb >> 16) as u8
    }

    /// `getGreen()`
    pub const fn green(self) -> u8 {
        (self.argb >> 8) as u8
    }

    /// `getBlue()`
    pub const fn blue(self) -> u8 {
        self.argb as u8
    }

    /// `getAlpha()`
    pub const fn alpha(self) -> u8 {
        (self.argb >> 24) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_constants_pack_as_java_get_rgb() {
        // java.awt.Color.RED.getRGB() == 0xFFFF0000 (as a signed int: -65536)
        assert_eq!(Color::RED.get_rgb(), 0xFFFF_0000_u32 as i32);
        assert_eq!(Color::GREEN.get_rgb(), 0xFF00_FF00_u32 as i32);
        assert_eq!(Color::BLUE.get_rgb(), 0xFF00_00FF_u32 as i32);
        assert_eq!(Color::WHITE.get_rgb(), -1);
        assert_eq!(Color::BLACK.get_rgb(), 0xFF00_0000_u32 as i32);
    }

    #[test]
    fn rgb_int_constructor_forces_opaque_alpha() {
        // new Color(0x12345678) ignores the top byte and sets alpha to 255.
        let c = Color::from_rgb_int(0x1234_5678);
        assert_eq!(c.get_rgb(), 0xFF34_5678_u32 as i32);
        assert_eq!((c.alpha(), c.red(), c.green(), c.blue()), (255, 0x34, 0x56, 0x78));
    }

    #[test]
    fn argb_int_constructor_keeps_alpha() {
        let c = Color::from_argb_int(0x8011_2233_u32 as i32);
        assert_eq!((c.alpha(), c.red(), c.green(), c.blue()), (0x80, 0x11, 0x22, 0x33));
        assert_eq!(c.get_rgb(), 0x8011_2233_u32 as i32);
    }

    #[test]
    fn rgba_components_round_trip() {
        let c = Color::from_rgba(1, 2, 3, 4);
        assert_eq!((c.red(), c.green(), c.blue(), c.alpha()), (1, 2, 3, 4));
        assert_eq!(Color::from_rgb(9, 8, 7).alpha(), 255);
    }
}
