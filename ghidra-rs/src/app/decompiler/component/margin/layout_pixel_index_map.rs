//! Mapping between pixel coordinates and layout indexes in the decompiler panel.
//!
//! Mirrors `ghidra.app.decompiler.component.margin.LayoutPixelIndexMap`.

/// A mapping from pixel coordinate to layout index.
///
/// At the moment, the only implementation provides a map from vertical position to layout.
/// While this does not have to be the case, the documentation presumes the y coordinate.
///
/// Layout indexes are Java `BigInteger`s; like the rest of the field-panel port (e.g.
/// `ViewerPosition::index`) they are represented as `i128`.
pub trait LayoutPixelIndexMap {
    /// Gets the top of the layout with the given index.
    ///
    /// Returns the minimum y coordinate of any pixel occupied by the layout having the given
    /// index, relative to the main panel's viewport. This accounts for scrolling and non-uniform
    /// height among the layouts.
    fn get_pixel(&self, index: i128) -> i32;

    /// Gets the index of the layout occupying the line of pixels at vertical position `pixel`,
    /// relative to the main panel's viewport. This accounts for scrolling and non-uniform height
    /// among the layouts.
    ///
    /// Clients should avoid frequent calls to this method; it should only be necessary to call it
    /// once or twice per repaint.
    fn get_index(&self, pixel: i32) -> i128;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double following Java's `VerticalLayoutPixelIndexMap` algorithm: layouts starting at
    /// index `base`, with the given top y positions.
    struct VerticalMap {
        base: i128,
        y_positions: Vec<i32>,
    }

    impl LayoutPixelIndexMap for VerticalMap {
        fn get_pixel(&self, index: i128) -> i32 {
            self.y_positions[usize::try_from(index - self.base).unwrap()]
        }

        fn get_index(&self, pixel: i32) -> i128 {
            let off = match self.y_positions.binary_search(&pixel) {
                Ok(i) => i as i128,
                Err(insertion_point) => insertion_point as i128 - 1,
            };
            self.base + off
        }
    }

    fn map() -> VerticalMap {
        VerticalMap { base: 10, y_positions: vec![-5, 12, 30, 31] }
    }

    #[test]
    fn get_pixel_maps_index_to_layout_top() {
        let m = map();
        assert_eq!(m.get_pixel(10), -5);
        assert_eq!(m.get_pixel(12), 30);
    }

    #[test]
    fn get_index_maps_pixel_to_containing_layout() {
        let m = map();
        assert_eq!(m.get_index(-5), 10); // exact top
        assert_eq!(m.get_index(0), 10); // inside first layout
        assert_eq!(m.get_index(29), 11);
        assert_eq!(m.get_index(31), 13);
        assert_eq!(m.get_index(1000), 13);
        // above the first layout: Java yields base - 1
        assert_eq!(m.get_index(-6), 9);
    }

    #[test]
    fn usable_as_trait_object() {
        let m: &dyn LayoutPixelIndexMap = &map();
        assert_eq!(m.get_pixel(m.get_index(12)), 12);
    }
}
