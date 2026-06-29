/// Pixel format for Ghidra image buffers.
///
/// Mirrors `ghidra.file.image.GImageFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GImageFormat {
    /// 32-bit RGBA: red, green, blue, alpha (4 bytes per pixel).
    RgbAlpha4Byte,
    /// 16-bit gray + alpha: luminance and alpha (2 bytes per pixel).
    GrayAlpha2Byte,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(GImageFormat::RgbAlpha4Byte, GImageFormat::GrayAlpha2Byte);
    }

    #[test]
    fn variants_are_copy() {
        let a = GImageFormat::RgbAlpha4Byte;
        let _b = a;
        let _c = a;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", GImageFormat::RgbAlpha4Byte), "RgbAlpha4Byte");
        assert_eq!(format!("{:?}", GImageFormat::GrayAlpha2Byte), "GrayAlpha2Byte");
    }

    #[test]
    fn variants_match_exhaustively() {
        for fmt in [GImageFormat::RgbAlpha4Byte, GImageFormat::GrayAlpha2Byte] {
            match fmt {
                GImageFormat::RgbAlpha4Byte => {}
                GImageFormat::GrayAlpha2Byte => {}
            }
        }
    }
}
