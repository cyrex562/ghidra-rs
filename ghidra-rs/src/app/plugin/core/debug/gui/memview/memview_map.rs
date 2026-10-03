/// Maps between a linear address/element space and a pixel coordinate space.
///
/// Ported from `ghidra.app.plugin.core.debug.gui.memview.MemviewMap`.
pub struct MemviewMap {
    max: i64,
    #[allow(dead_code)]
    sz: i64,
    elements_per_pixel: f64,
    multiplier: f64,
}

impl MemviewMap {
    /// Creates a new mapping between `elems` elements and `pixels` pixels.
    pub fn new(elems: i64, pixels: i64) -> Self {
        let elements_per_pixel = if pixels == 0 {
            0.0
        } else {
            elems as f64 / pixels as f64
        };
        Self {
            max: elems,
            sz: elems,
            elements_per_pixel,
            multiplier: 1.0,
        }
    }

    /// Sets the zoom multiplier used when converting between offsets and pixels.
    pub fn create_mapping(&mut self, mult: f64) {
        self.multiplier = mult;
    }

    /// Returns the element offset that corresponds to `pixel`.
    pub fn get_offset(&self, pixel: i32) -> i64 {
        (pixel as f64 * self.elements_per_pixel / self.multiplier).round() as i64
    }

    /// Returns the pixel that corresponds to `offset`.
    ///
    /// Negative offsets are clamped to `max`.
    pub fn get_pixel(&self, offset: i64) -> i32 {
        let o = if offset < 0 { self.max } else { offset };
        (o as f64 * self.multiplier / self.elements_per_pixel).round() as i32
    }

    /// Returns the total pixel extent of the mapped range.
    pub fn get_size(&self) -> i32 {
        self.get_pixel(self.max)
    }

    /// Returns the current zoom multiplier.
    pub fn get_multiplier(&self) -> f64 {
        self.multiplier
    }

    /// Returns the original elements-per-pixel ratio (at multiplier = 1.0).
    pub fn get_original_elem_per_pixel(&self) -> f64 {
        self.elements_per_pixel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_mapping() {
        let m = MemviewMap::new(1000, 100);
        assert_eq!(m.get_original_elem_per_pixel(), 10.0);
        assert_eq!(m.get_multiplier(), 1.0);
    }

    #[test]
    fn test_get_offset() {
        let m = MemviewMap::new(1000, 100);
        // pixel 10 → offset 100
        assert_eq!(m.get_offset(10), 100);
        // pixel 0 → offset 0
        assert_eq!(m.get_offset(0), 0);
        // pixel 50 → offset 500
        assert_eq!(m.get_offset(50), 500);
    }

    #[test]
    fn test_get_pixel() {
        let m = MemviewMap::new(1000, 100);
        assert_eq!(m.get_pixel(100), 10);
        assert_eq!(m.get_pixel(0), 0);
        assert_eq!(m.get_pixel(500), 50);
    }

    #[test]
    fn test_negative_offset_clamps_to_max() {
        let m = MemviewMap::new(1000, 100);
        // negative offset should map as if offset == max (1000)
        assert_eq!(m.get_pixel(-1), m.get_pixel(1000));
    }

    #[test]
    fn test_get_size() {
        let m = MemviewMap::new(1000, 100);
        // get_size() == get_pixel(max) == 100
        assert_eq!(m.get_size(), 100);
    }

    #[test]
    fn test_create_mapping_multiplier() {
        let mut m = MemviewMap::new(1000, 100);
        m.create_mapping(2.0);
        assert_eq!(m.get_multiplier(), 2.0);
        // With multiplier=2, get_pixel doubles: offset 100 → pixel 20
        assert_eq!(m.get_pixel(100), 20);
        // With multiplier=2, get_offset halves: pixel 10 → offset 50
        assert_eq!(m.get_offset(10), 50);
    }

    #[test]
    fn test_zero_pixels_no_panic() {
        let m = MemviewMap::new(1000, 0);
        // elements_per_pixel is 0; Java returns 0 for NaN/Infinity casts
        assert_eq!(m.get_offset(10), 0);
        // get_pixel with zero elements_per_pixel: division by 0.0 → Inf → saturates to i32::MAX
        // (matches Java behavior where (int)Math.round(Infinity) yields Integer.MAX_VALUE)
        let px = m.get_pixel(100);
        // Just verify it doesn't panic; value is saturated
        let _ = px;
    }

    #[test]
    fn test_roundtrip() {
        let m = MemviewMap::new(2000, 200);
        // offset → pixel → offset should be stable for clean multiples
        let offset = 400i64;
        let pixel = m.get_pixel(offset);
        let recovered = m.get_offset(pixel);
        assert_eq!(recovered, offset);
    }
}
