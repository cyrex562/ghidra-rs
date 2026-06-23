use std::collections::HashMap;

/// A proportional weight for use with [`ProportionalHorizontalLayout`].
///
/// Port of `ghidra.util.layout.ProportionalHorizontalLayout.Proportion`.
#[derive(Debug, Clone, Copy)]
pub struct Proportion(pub f64);

/// Width and height in pixels.
///
/// Equivalent to `java.awt.Dimension`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Size {
    pub width: i32,
    pub height: i32,
}

/// Axis-aligned rectangle in pixel coordinates.
///
/// Equivalent to `java.awt.Rectangle`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Layout manager that distributes horizontal space proportionally among child components.
///
/// Port of `ghidra.util.layout.ProportionalHorizontalLayout`.
///
/// Unlike the Java version, which holds AWT `Component` references, this implementation
/// uses stable `u64` keys. Callers supply preferred/minimum sizes when querying size metrics,
/// and receive back per-key [`Rect`] values from [`layout_container`][Self::layout_container].
#[derive(Debug, Default)]
pub struct ProportionalHorizontalLayout {
    order: Vec<u64>,
    weights: HashMap<u64, f64>,
    next_id: u64,
}

impl ProportionalHorizontalLayout {
    /// Creates a new empty layout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a component with the given proportional weight and returns a stable key.
    ///
    /// Port of `addLayoutComponent(Component, Object)`.
    pub fn add_component(&mut self, proportion: Proportion) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.order.push(id);
        self.weights.insert(id, proportion.0);
        id
    }

    /// Removes the component identified by `key`.
    ///
    /// Port of `removeLayoutComponent(Component)`.
    pub fn remove_component(&mut self, key: u64) {
        self.order.retain(|&k| k != key);
        self.weights.remove(&key);
    }

    fn total_weight(&self) -> f64 {
        self.order.iter().map(|k| self.weights[k]).sum()
    }

    fn compute_size<F>(&self, size_fn: F) -> Size
    where
        F: Fn(u64) -> Option<Size>,
    {
        let total_p = self.total_weight();
        let mut result = Size::default();
        for &id in &self.order {
            let w = self.weights[&id];
            let fraction = if total_p == 0.0 { 0.0 } else { w / total_p };
            if fraction == 0.0 {
                continue;
            }
            if let Some(size) = size_fn(id) {
                let needed_width = (size.width as f64 / fraction).ceil() as i32;
                result.width = result.width.max(needed_width);
                result.height = result.height.max(size.height);
            }
        }
        result
    }

    /// Computes the preferred container size so every child can fit at its preferred size.
    ///
    /// `preferred_sizes` maps component keys to their preferred [`Size`].
    ///
    /// Port of `preferredLayoutSize(Container)`.
    pub fn preferred_layout_size(&self, preferred_sizes: &HashMap<u64, Size>) -> Size {
        self.compute_size(|id| preferred_sizes.get(&id).copied())
    }

    /// Computes the minimum container size so every child can fit at its minimum size.
    ///
    /// `minimum_sizes` maps component keys to their minimum [`Size`].
    ///
    /// Port of `minimumLayoutSize(Container)`.
    pub fn minimum_layout_size(&self, minimum_sizes: &HashMap<u64, Size>) -> Size {
        self.compute_size(|id| minimum_sizes.get(&id).copied())
    }

    /// Returns the maximum layout size (unbounded in both dimensions).
    ///
    /// Port of `maximumLayoutSize(Container)`.
    pub fn maximum_layout_size() -> Size {
        Size { width: i32::MAX, height: i32::MAX }
    }

    /// Returns the horizontal alignment for this layout (0.5 = centered).
    ///
    /// Port of `getLayoutAlignmentX(Container)`.
    pub fn layout_alignment_x() -> f32 {
        0.5
    }

    /// Returns the vertical alignment for this layout (0.5 = centered).
    ///
    /// Port of `getLayoutAlignmentY(Container)`.
    pub fn layout_alignment_y() -> f32 {
        0.5
    }

    /// Computes the bounding rectangle for each component within a container of `container` size.
    ///
    /// Returns `(key, rect)` pairs in component insertion order. Uses a cumulative-division
    /// algorithm matching the Java source to avoid integer-rounding drift across components.
    ///
    /// Port of `layoutContainer(Container)`.
    pub fn layout_container(&self, container: Size) -> Vec<(u64, Rect)> {
        let total_weight = self.total_weight();
        let mut running = 0.0f64;
        let mut cur_x: i32 = 0;
        let mut result = Vec::with_capacity(self.order.len());
        for &id in &self.order {
            let w = self.weights[&id];
            running += w;
            let new_x = (container.width as f64 * running / total_weight) as i32;
            result.push((id, Rect {
                x: cur_x,
                y: 0,
                width: new_x - cur_x,
                height: container.height,
            }));
            cur_x = new_x;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_weights_divide_space() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(1.0));
        let b = layout.add_component(Proportion(1.0));
        let rects = layout.layout_container(Size { width: 100, height: 50 });
        assert_eq!(rects.len(), 2);
        assert_eq!(rects[0].0, a);
        assert_eq!(rects[0].1, Rect { x: 0, y: 0, width: 50, height: 50 });
        assert_eq!(rects[1].0, b);
        assert_eq!(rects[1].1, Rect { x: 50, y: 0, width: 50, height: 50 });
    }

    #[test]
    fn test_unequal_weights() {
        let mut layout = ProportionalHorizontalLayout::new();
        let _a = layout.add_component(Proportion(1.0));
        let _b = layout.add_component(Proportion(2.0));
        let _c = layout.add_component(Proportion(1.0));
        let rects = layout.layout_container(Size { width: 120, height: 40 });
        // total=4; a=30, b=60, c=30
        assert_eq!(rects[0].1, Rect { x: 0, y: 0, width: 30, height: 40 });
        assert_eq!(rects[1].1, Rect { x: 30, y: 0, width: 60, height: 40 });
        assert_eq!(rects[2].1, Rect { x: 90, y: 0, width: 30, height: 40 });
    }

    #[test]
    fn test_rects_fill_container_with_non_divisible_width() {
        // Three equal weights, width not divisible by 3.
        let mut layout = ProportionalHorizontalLayout::new();
        layout.add_component(Proportion(1.0));
        layout.add_component(Proportion(1.0));
        layout.add_component(Proportion(1.0));
        let rects = layout.layout_container(Size { width: 100, height: 10 });
        let last = rects.last().unwrap().1;
        // cumulative algorithm: new_x at end = (int)(100 * 3/3) = 100
        assert_eq!(last.x + last.width, 100);
    }

    #[test]
    fn test_preferred_layout_size() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(1.0));
        let b = layout.add_component(Proportion(1.0));
        let mut sizes = HashMap::new();
        sizes.insert(a, Size { width: 100, height: 50 });
        sizes.insert(b, Size { width: 80, height: 60 });
        let size = layout.preferred_layout_size(&sizes);
        // Each has fraction 0.5; needed = ceil(w/0.5)
        // a: ceil(200) = 200, b: ceil(160) = 160 → width=200, height=max(50,60)=60
        assert_eq!(size, Size { width: 200, height: 60 });
    }

    #[test]
    fn test_minimum_layout_size() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(2.0));
        let b = layout.add_component(Proportion(1.0));
        let mut sizes = HashMap::new();
        sizes.insert(a, Size { width: 60, height: 30 });
        sizes.insert(b, Size { width: 30, height: 20 });
        let size = layout.minimum_layout_size(&sizes);
        // total=3; a fraction=2/3, b fraction=1/3
        // a: ceil(60/(2/3)) = ceil(90) = 90; b: ceil(30/(1/3)) = ceil(90) = 90
        // width=90, height=max(30,20)=30
        assert_eq!(size, Size { width: 90, height: 30 });
    }

    #[test]
    fn test_zero_weight_skipped_in_preferred_size() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(0.0));
        let b = layout.add_component(Proportion(1.0));
        let mut sizes = HashMap::new();
        sizes.insert(a, Size { width: 100, height: 50 });
        sizes.insert(b, Size { width: 80, height: 30 });
        let size = layout.preferred_layout_size(&sizes);
        // a has fraction 0 → skipped; b has fraction 1.0 → ceil(80/1)=80
        assert_eq!(size, Size { width: 80, height: 30 });
    }

    #[test]
    fn test_remove_component() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(1.0));
        let b = layout.add_component(Proportion(1.0));
        layout.remove_component(a);
        let rects = layout.layout_container(Size { width: 100, height: 50 });
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0].0, b);
        assert_eq!(rects[0].1, Rect { x: 0, y: 0, width: 100, height: 50 });
    }

    #[test]
    fn test_remove_middle_component() {
        let mut layout = ProportionalHorizontalLayout::new();
        let a = layout.add_component(Proportion(1.0));
        let b = layout.add_component(Proportion(1.0));
        let c = layout.add_component(Proportion(1.0));
        layout.remove_component(b);
        let rects = layout.layout_container(Size { width: 100, height: 20 });
        assert_eq!(rects.len(), 2);
        assert_eq!(rects[0].0, a);
        assert_eq!(rects[1].0, c);
        // two equal weights → each gets 50 px
        assert_eq!(rects[0].1, Rect { x: 0, y: 0, width: 50, height: 20 });
        assert_eq!(rects[1].1, Rect { x: 50, y: 0, width: 50, height: 20 });
    }

    #[test]
    fn test_maximum_layout_size() {
        let s = ProportionalHorizontalLayout::maximum_layout_size();
        assert_eq!(s.width, i32::MAX);
        assert_eq!(s.height, i32::MAX);
    }

    #[test]
    fn test_alignment_constants() {
        assert_eq!(ProportionalHorizontalLayout::layout_alignment_x(), 0.5);
        assert_eq!(ProportionalHorizontalLayout::layout_alignment_y(), 0.5);
    }

    #[test]
    fn test_empty_layout() {
        let layout = ProportionalHorizontalLayout::new();
        let rects = layout.layout_container(Size { width: 100, height: 50 });
        assert!(rects.is_empty());
    }

    #[test]
    fn test_insertion_order_preserved() {
        let mut layout = ProportionalHorizontalLayout::new();
        let ids: Vec<u64> = (0..5).map(|_| layout.add_component(Proportion(1.0))).collect();
        let rects = layout.layout_container(Size { width: 500, height: 10 });
        for (i, &id) in ids.iter().enumerate() {
            assert_eq!(rects[i].0, id);
        }
    }
}
