//! Listing scroll policy (Java `IndexedScrollPane` + its view-to-index
//! mappers): the clamp that keeps the last page full, the scrollbar mapping,
//! and keeping the cursor on screen. Pure u128 math so the renderer never
//! does index arithmetic (spec §5).

/// Scrollbar resolution used once a listing has more top positions than an
/// int scrollbar can address one-to-one (Java's `PreMappedViewToIndexMapper`
/// fallback).
pub const SCROLL_RANGE: u32 = 1_000_000;

/// Scroll geometry of a listing with `count` rows and a viewport of
/// `page_rows` whole rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollModel {
    count: u128,
    page_rows: u128,
}

impl ScrollModel {
    /// `page_rows` below 1 is treated as 1.
    pub fn new(count: u128, page_rows: u32) -> Self {
        Self { count, page_rows: u128::from(page_rows.max(1)) }
    }

    /// The largest top index that still fills the viewport (the last page is
    /// full, as Java never scrolls past view height minus viewport height).
    pub fn max_top(&self) -> u128 {
        self.count.saturating_sub(self.page_rows)
    }

    /// `top` limited to `0..=max_top`.
    pub fn clamp(&self, top: u128) -> u128 {
        top.min(self.max_top())
    }

    /// `top` moved by `delta` rows, clamped at both ends.
    pub fn scroll(&self, top: u128, delta: i64) -> u128 {
        let moved = if delta < 0 {
            top.saturating_sub(u128::from(delta.unsigned_abs()))
        } else {
            top.saturating_add(delta as u128)
        };
        self.clamp(moved)
    }

    /// Whether scrollbar values map one-to-one onto top indices.
    pub fn is_exact(&self) -> bool {
        self.max_top() <= u128::from(SCROLL_RANGE)
    }

    /// Scrollbar maximum (minimum is 0).
    pub fn range_max(&self) -> i32 {
        if self.is_exact() { self.max_top() as i32 } else { SCROLL_RANGE as i32 }
    }

    /// Scrollbar page step: one viewport of rows in exact mode, its share of
    /// the range (at least 1) otherwise.
    pub fn page_step(&self) -> i32 {
        if self.is_exact() {
            self.page_rows.min(u128::from(SCROLL_RANGE)) as i32
        } else {
            (self.page_rows * u128::from(SCROLL_RANGE) / self.max_top()).max(1) as i32
        }
    }

    /// Top index for scrollbar `value` (clamped to the range).
    pub fn top_for_value(&self, value: i32) -> u128 {
        let v = u128::from(value.max(0) as u32).min(self.range_max() as u128);
        if self.is_exact() { v } else { self.max_top() * v / u128::from(SCROLL_RANGE) }
    }

    /// Scrollbar value for `top`.
    pub fn value_for_top(&self, top: u128) -> i32 {
        let t = self.clamp(top);
        if self.is_exact() { t as i32 } else { (t * u128::from(SCROLL_RANGE) / self.max_top()) as i32 }
    }

    /// The top that keeps `cursor` on screen: unchanged when the cursor row
    /// is visible, else the cursor at the top edge (moved up) or bottom edge
    /// (moved down).
    pub fn ensure_visible(&self, top: u128, cursor: u128) -> u128 {
        if cursor < top {
            self.clamp(cursor)
        } else if cursor - top >= self.page_rows {
            self.clamp(cursor + 1 - self.page_rows)
        } else {
            self.clamp(top)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUGE: u128 = 1u128 << 64;

    #[test]
    fn the_last_page_stays_full() {
        let m = ScrollModel::new(18, 5);
        assert_eq!(m.max_top(), 13);
        assert_eq!(m.scroll(10, 100), 13);
        assert_eq!(m.scroll(2, -5), 0);
        assert_eq!(m.scroll(0, i64::MIN), 0);
        assert_eq!(m.clamp(17), 13);
    }

    #[test]
    fn a_page_taller_than_the_listing_never_scrolls() {
        let m = ScrollModel::new(3, 40);
        assert_eq!(m.max_top(), 0);
        assert_eq!(m.scroll(0, 5), 0);
        assert_eq!(m.range_max(), 0);
        let empty = ScrollModel::new(0, 0);
        assert_eq!((empty.max_top(), empty.range_max(), empty.top_for_value(7), empty.value_for_top(9)), (0, 0, 0, 0));
    }

    #[test]
    fn small_listings_map_scrollbar_values_exactly() {
        let m = ScrollModel::new(18, 5);
        assert!(m.is_exact());
        assert_eq!(m.range_max(), 13);
        assert_eq!(m.page_step(), 5);
        assert_eq!(m.top_for_value(1), 1); // the arrow button moves one row
        assert_eq!(m.value_for_top(7), 7);
        assert_eq!(m.top_for_value(99), 13);
        assert_eq!(m.top_for_value(-3), 0);
    }

    #[test]
    fn huge_listings_map_a_fraction_without_overflow() {
        let m = ScrollModel::new(HUGE, 40);
        assert!(!m.is_exact());
        assert_eq!(m.range_max(), SCROLL_RANGE as i32);
        assert_eq!(m.top_for_value(0), 0);
        assert_eq!(m.top_for_value(SCROLL_RANGE as i32), m.max_top());
        assert_eq!(m.top_for_value(SCROLL_RANGE as i32 / 2), m.max_top() / 2);
        assert_eq!(m.value_for_top(m.max_top()), SCROLL_RANGE as i32);
        assert_eq!(m.value_for_top(u128::MAX), SCROLL_RANGE as i32);
        assert_eq!(m.page_step(), 1);
    }

    #[test]
    fn ensure_visible_is_exact_near_two_to_the_64() {
        let m = ScrollModel::new(HUGE, 40);
        let top = 1u128 << 63;
        assert_eq!(m.ensure_visible(top, top - 1), top - 1); // Up off the top edge
        assert_eq!(m.ensure_visible(top, top + 39), top); // last visible row
        assert_eq!(m.ensure_visible(top, top + 40), top + 1); // Down off the bottom edge
    }

    #[test]
    fn ensure_visible_keeps_the_last_page_full() {
        let m = ScrollModel::new(18, 5);
        assert_eq!(m.ensure_visible(0, 17), 13);
        assert_eq!(m.ensure_visible(15, 16), 13);
    }
}
