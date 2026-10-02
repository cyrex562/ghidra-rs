//! Listing view state and navigation (spec §5 M1 scope): top row, cursor,
//! selection, the middle-mouse text highlight and back/forward history all
//! live here, so the renderer only sends intents and paints frames.

use std::sync::{Arc, Mutex, MutexGuard};

use ghidra_rs::app::plugin::core::navigation::history_list::{HistoryList, MAX_HISTORY_SIZE};

use crate::listing::{CursorPos, FieldRow, FontMetrics, ListingViewModel, Move};
use crate::listing_scroll::ScrollModel;
use crate::listing_selection::IndexSelection;

/// Pointer travel (px) before a press becomes a drag (Java `FieldPanel`).
const DRAG_THRESHOLD: i32 = 3;

/// Shared handle: the session's view-model registry and the listing's
/// actions both hold one. Lock order: session, then controller.
pub type ListingHandle = Arc<Mutex<ListingController>>;

/// Locks a listing, recovering from poison: a panic in one renderer call
/// (caught by the bridge's guard) must not blank the listing for the rest of
/// the session (spec §3: errors, not a dead UI).
pub fn lock(handle: &ListingHandle) -> MutexGuard<'_, ListingController> {
    handle.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One painted row with its decorations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRow {
    /// The laid-out row.
    pub row: FieldRow,
    /// Whether the row is selected.
    pub selected: bool,
    /// Cursor bar x, when the cursor is on this row.
    pub cursor_x: Option<i32>,
    /// Highlighted spans `(x, width)`.
    pub highlights: Vec<(i32, i32)>,
}

/// Everything the renderer paints for one viewport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingFrame {
    /// First row index.
    pub top: u128,
    /// Visible rows.
    pub rows: Vec<FrameRow>,
    /// Scrollbar maximum.
    pub scroll_max: i32,
    /// Scrollbar page step.
    pub scroll_page: i32,
    /// Scrollbar value.
    pub scroll_value: i32,
    /// Cursor location for the status bar (the cursor row's address).
    pub location: String,
}

/// History entries compare by row (Java `LocationMemento` compares the
/// program location; for undefined bytes that is the address).
#[derive(Debug, Clone, Copy)]
struct Memento(CursorPos);

impl PartialEq for Memento {
    fn eq(&self, other: &Self) -> bool {
        self.0.index == other.0.index
    }
}

/// Listing view state over a [`ListingViewModel`].
pub struct ListingController {
    model: Box<dyn ListingViewModel>,
    metrics: FontMetrics,
    viewport_px: i32,
    top: u128,
    cursor: Option<CursorPos>,
    anchor: Option<u128>,
    selection: IndexSelection,
    highlight: Option<String>,
    history: HistoryList<Memento>,
    /// Where the left button went down, until a key moves the cursor.
    press: Option<(i32, i32)>,
    /// The press has moved past the jitter threshold.
    dragging: bool,
}

impl ListingController {
    /// A controller over `model`, scrolled to the top, no cursor.
    pub fn new(model: Box<dyn ListingViewModel>) -> Self {
        Self {
            model,
            metrics: FontMetrics::monospace(7, 11, 3),
            viewport_px: 0,
            top: 0,
            cursor: None,
            anchor: None,
            selection: IndexSelection::default(),
            highlight: None,
            history: HistoryList::new(MAX_HISTORY_SIZE),
            press: None,
            dragging: false,
        }
    }

    /// [`Self::new`] behind a shared handle.
    pub fn handle(model: Box<dyn ListingViewModel>) -> ListingHandle {
        Arc::new(Mutex::new(Self::new(model)))
    }

    /// Gives the view-model back.
    pub fn into_model(self) -> Box<dyn ListingViewModel> {
        self.model
    }

    /// The view-model.
    pub fn model(&self) -> &dyn ListingViewModel {
        self.model.as_ref()
    }

    /// New renderer font metrics; the top row stays put.
    pub fn set_metrics(&mut self, metrics: FontMetrics) {
        self.metrics = metrics;
        self.model.set_metrics(metrics);
        self.top = self.scroll().clamp(self.top);
    }

    /// New viewport height; the top is re-clamped so the last page stays full.
    pub fn set_viewport(&mut self, px: i32) {
        self.viewport_px = px.max(0);
        self.top = self.scroll().clamp(self.top);
    }

    /// First visible row.
    pub fn top(&self) -> u128 {
        self.top
    }

    /// The cursor, once placed.
    pub fn cursor(&self) -> Option<CursorPos> {
        self.cursor
    }

    /// The selection.
    pub fn selection(&self) -> &IndexSelection {
        &self.selection
    }

    /// The highlighted text, if any.
    pub fn highlight(&self) -> Option<&str> {
        self.highlight.as_deref()
    }

    /// Moves the cursor; `extend` grows the selection from its anchor
    /// (shift+key), otherwise the selection is cleared.
    pub fn key(&mut self, mv: Move, extend: bool) {
        self.press = None;
        let current = self.cursor.unwrap_or(CursorPos { index: self.top, field: 0, col: 0 });
        let next = self.model.move_cursor(current, mv, self.page_rows());
        self.place(next, extend, current.index);
        self.top = self.scroll().ensure_visible(self.top, next.index);
    }

    /// Places the cursor at a click; `extend` selects from the anchor.
    pub fn click(&mut self, x: i32, y: i32, extend: bool) {
        let Some(hit) = self.hit(x, y) else { return };
        let from = self.cursor.map_or(hit.index, |c| c.index);
        self.place(hit, extend, from);
        self.press = Some((x, y));
        self.dragging = false;
    }

    /// Left-button drag to (`x`, `y`): selects from the press position; past
    /// the top or bottom edge the view scrolls a row toward the pointer and
    /// the selection follows the edge row (Java `FieldPanel` drag auto-scroll).
    pub fn drag(&mut self, x: i32, y: i32) {
        let Some((px, py)) = self.press else { return };
        if !self.dragging {
            // Java FieldPanel ignores drags within 3px of the press.
            if (x - px).abs() <= DRAG_THRESHOLD && (y - py).abs() <= DRAG_THRESHOLD {
                return;
            }
            self.dragging = true;
        }
        let line = self.metrics.line_height().max(1);
        let y = if y < 0 {
            self.wheel(-i64::from(1 + (-y) / line));
            0
        } else if y >= self.viewport_px {
            self.wheel(i64::from(1 + (y - self.viewport_px) / line));
            (self.viewport_px - 1).max(0)
        } else {
            y
        };
        // Below the last row (short listing, partial page): its last row.
        let hit = self.hit(x, y).or_else(|| {
            let last = self.model.rows(self.top, self.viewport_px).pop()?;
            self.model.hit_test(last.index, x)
        });
        let Some(hit) = hit else { return };
        let from = self.cursor.map_or(hit.index, |c| c.index);
        self.place(hit, true, from);
        if self.anchor == Some(hit.index) {
            self.selection.clear(); // a drag back to its start selects nothing
        }
    }

    /// Middle click: cursor there, then highlight the word under it (Java
    /// `ListingMiddleMouseHighlightProvider`); the same word again clears.
    pub fn middle_click(&mut self, x: i32, y: i32) {
        let Some(hit) = self.hit(x, y) else { return };
        self.place(hit, false, hit.index);
        let word = self.model.field_text(hit).and_then(|t| find_word(&t, hit.col));
        self.highlight = if word.is_some() && word == self.highlight { None } else { word };
    }

    /// Scrolls by `rows` (wheel).
    pub fn wheel(&mut self, rows: i64) {
        self.top = self.scroll().scroll(self.top, rows);
    }

    /// Scrollbar moved to `value`.
    pub fn set_scroll_value(&mut self, value: i32) {
        self.top = self.scroll().top_for_value(value);
    }

    /// Goes to `address`, recording history (from, then to) and centering the
    /// target when it is off screen. Unlisted addresses change nothing.
    pub fn goto_address(&mut self, address: u64) -> Result<(), String> {
        let index = self.model.goto(address).ok_or_else(|| format!("Address not found: {address:x}"))?;
        // Java's navigatable always has a location: before any click or key
        // that is the top row, so the first goto is still undoable.
        if let Some(c) = self.location() {
            self.history.add(Memento(c));
        }
        let target = CursorPos { index, field: 0, col: 0 };
        self.history.add(Memento(target));
        self.navigate(target);
        Ok(())
    }

    /// Previous location (Java `NavigationHistoryPlugin.previous`).
    pub fn back(&mut self) -> bool {
        if !self.history.has_previous() {
            return false;
        }
        if !self.history.has_next() {
            if let Some(c) = self.location() {
                self.history.add(Memento(c));
            }
        }
        match self.history.previous() {
            Some(Memento(c)) => {
                self.navigate(c);
                true
            }
            None => false,
        }
    }

    /// Next location.
    pub fn forward(&mut self) -> bool {
        match self.history.next() {
            Some(Memento(c)) => {
                self.navigate(c);
                true
            }
            None => false,
        }
    }

    /// Whether `back` would move.
    pub fn can_go_back(&self) -> bool {
        self.history.has_previous()
    }

    /// Whether `forward` would move.
    pub fn can_go_forward(&self) -> bool {
        self.history.has_next()
    }

    /// The current location: the cursor, else the top row (none when empty).
    fn location(&self) -> Option<CursorPos> {
        self.cursor.or_else(|| (self.model.index_count() > 0).then_some(CursorPos { index: self.top, field: 0, col: 0 }))
    }

    /// Rows that fit entirely in the viewport (at least 1).
    fn page_rows(&self) -> u32 {
        (self.viewport_px / self.metrics.line_height().max(1)).max(1) as u32
    }

    fn scroll(&self) -> ScrollModel {
        ScrollModel::new(self.model.index_count(), self.page_rows())
    }

    /// The cursor position under a viewport pixel, if a row is there.
    fn hit(&self, x: i32, y: i32) -> Option<CursorPos> {
        let row = self.model.rows(self.top, self.viewport_px.max(y + 1)).into_iter().find(|r| r.y <= y && y < r.y + r.height)?;
        self.model.hit_test(row.index, x)
    }

    /// Moves the cursor to `c`; `extend` selects from the anchor (set to
    /// `from` when none), otherwise clears the selection.
    fn place(&mut self, c: CursorPos, extend: bool, from: u128) {
        if extend {
            let anchor = *self.anchor.get_or_insert(from);
            self.selection.set_range(anchor, c.index);
        } else {
            self.anchor = None;
            self.selection.clear();
        }
        self.cursor = Some(c);
    }

    /// Cursor to `c`, centering it when off screen (Java
    /// `ListingPanel.goTo(loc, centerWhenNotVisible = true)`); keeps the selection.
    fn navigate(&mut self, c: CursorPos) {
        self.cursor = Some(c);
        self.anchor = None;
        let page = u128::from(self.page_rows());
        if c.index < self.top || c.index - self.top >= page {
            self.top = self.scroll().clamp(c.index.saturating_sub(page / 2));
        }
    }

    /// Spans of every literal occurrence of `word` in `row`'s runs.
    fn highlight_spans(&self, row: &FieldRow, word: &str) -> Vec<(i32, i32)> {
        let mut out = Vec::new();
        for run in &row.runs {
            let cw = if run.bold { self.metrics.bold_char_width } else { self.metrics.char_width };
            for (byte_at, m) in run.text.match_indices(word) {
                let col = run.text[..byte_at].chars().count() as i32;
                out.push((run.x + col * cw, m.chars().count() as i32 * cw));
            }
        }
        out
    }

    /// The frame for the current viewport.
    pub fn frame(&self) -> ListingFrame {
        let scroll = self.scroll();
        let rows = self
            .model
            .rows(self.top, self.viewport_px)
            .into_iter()
            .map(|row| {
                let cursor_x = self.cursor.filter(|c| c.index == row.index).and_then(|c| self.model.cursor_x(c));
                let highlights = self.highlight.as_deref().map_or_else(Vec::new, |w| self.highlight_spans(&row, w));
                FrameRow { selected: self.selection.contains(row.index), cursor_x, highlights, row }
            })
            .collect();
        ListingFrame {
            top: self.top,
            rows,
            scroll_max: scroll.range_max(),
            scroll_page: scroll.page_step(),
            scroll_value: scroll.value_for_top(self.top),
            location: self.cursor.map(|c| self.model.address_text(c.index)).unwrap_or_default(),
        }
    }
}

/// Parses a Go To address: hex with an optional `0x` prefix or `h` suffix.
pub fn parse_address(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let digits = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_suffix('h'))
        .or_else(|| t.strip_suffix('H'))
        .unwrap_or(t);
    u64::from_str_radix(digits, 16).map_err(|_| format!("Invalid address: {t}"))
}

/// Java `StringUtilities.findWord(text, pos, UNDERSCORE_AND_PERIOD_OK)`: the
/// run of letters, digits, `_` and `.` around char `pos`.
fn find_word(text: &str, pos: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let is_word = |c: char| c.is_alphanumeric() || c == '_' || c == '.';
    let pos = pos.min(chars.len().checked_sub(1)?);
    if !is_word(chars[pos]) {
        return None;
    }
    let start = (0..pos).rev().take_while(|&i| is_word(chars[i])).last().unwrap_or(pos);
    let end = (pos..chars.len()).take_while(|&i| is_word(chars[i])).last().unwrap_or(pos);
    Some(chars[start..=end].iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{MemoryBlockSnapshot, MemoryListing};

    const H: i32 = 14; // monospace(7, 11, 3) line height

    /// Rows 0..=3 are 0x401000..0x401003, row 4 is 0x402000 (gap between).
    fn controller(viewport_rows: i32) -> ListingController {
        let mut c = ListingController::new(Box::new(MemoryListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x401000, vec![0x55, 0x48, 0x89, 0x55]),
                MemoryBlockSnapshot::initialized(0x402000, vec![0xc3]),
            ],
        )));
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(viewport_rows * H);
        c
    }

    fn at(c: &ListingController) -> u128 {
        c.cursor().expect("cursor").index
    }

    #[test]
    fn parse_address_accepts_ghidra_hex_forms() {
        assert_eq!(parse_address("0x402000"), Ok(0x402000));
        assert_eq!(parse_address(" 402000 "), Ok(0x402000));
        assert_eq!(parse_address("402000h"), Ok(0x402000));
        assert_eq!(parse_address("0X40200A"), Ok(0x40200a));
        assert_eq!(parse_address("zz"), Err("Invalid address: zz".to_string()));
        assert!(parse_address("").is_err());
        assert!(parse_address("1ffffffffffffffff").is_err());
    }

    #[test]
    fn find_word_takes_identifier_runs() {
        assert_eq!(find_word("mov eax,dword ptr [rbp + local_8]", 30).as_deref(), Some("local_8"));
        assert_eq!(find_word("55h", 9).as_deref(), Some("55h"));
        assert_eq!(find_word("??", 0), None);
        assert_eq!(find_word("", 0), None);
    }

    #[test]
    fn back_after_goto_returns_and_forward_reenters() {
        let mut c = controller(3);
        c.key(Move::Down, false);
        assert_eq!(at(&c), 1);
        c.goto_address(0x402000).unwrap();
        assert_eq!(at(&c), 4);
        assert!(c.back());
        assert_eq!(at(&c), 1);
        assert!(c.forward());
        assert_eq!(at(&c), 4);
        assert!(!c.can_go_forward());
    }

    #[test]
    fn back_after_a_first_goto_returns_to_the_initial_location() {
        let mut c = controller(3);
        c.goto_address(0x402000).unwrap(); // no click or key first
        assert!(c.can_go_back());
        assert!(c.back());
        assert_eq!(at(&c), 0);
        assert_eq!(c.top(), 0);
    }

    #[test]
    fn a_poisoned_listing_lock_still_serves_the_listing() {
        let h = ListingController::handle(controller(3).into_model());
        let h2 = h.clone();
        let _ = std::thread::spawn(move || {
            let _guard = h2.lock().unwrap();
            panic!("model bug while locked");
        })
        .join();
        assert!(h.is_poisoned());
        lock(&h).key(Move::Down, false);
        assert_eq!(lock(&h).cursor().map(|c| c.index), Some(1));
    }

    #[test]
    fn goto_off_screen_centers_and_keeps_the_last_page_full() {
        let mut c = controller(3);
        c.goto_address(0x402000).unwrap();
        assert_eq!(c.top(), 2); // max top for 5 rows in 3
        let f = c.frame();
        assert_eq!(f.location, "00402000");
        assert!(f.rows.iter().any(|r| r.row.index == 4 && r.cursor_x == Some(0)));
    }

    #[test]
    fn history_survives_many_gotos() {
        let mut c = controller(3);
        for i in 0..40u64 {
            c.goto_address(if i % 2 == 0 { 0x401000 + (i % 4) } else { 0x402000 }).unwrap();
        }
        let mut steps = 0;
        while c.back() {
            steps += 1;
        }
        assert!(steps < MAX_HISTORY_SIZE, "{steps}");
        assert!(c.cursor().is_some());
    }

    #[test]
    fn a_bad_goto_changes_nothing() {
        let mut c = controller(3);
        c.key(Move::Down, false);
        let before = (c.top(), c.cursor());
        assert!(c.goto_address(0x401800).unwrap_err().contains("401800"));
        assert_eq!((c.top(), c.cursor()), before);
        assert!(!c.can_go_back());
    }

    #[test]
    fn shift_keys_select_across_the_gap_and_plain_keys_clear() {
        let mut c = controller(5);
        c.key(Move::Down, true);
        c.key(Move::Down, true);
        assert_eq!(c.selection().ranges(), &[(0, 2)]);
        c.key(Move::End, true);
        assert_eq!(c.selection().ranges(), &[(0, 4)]);
        assert!(c.frame().rows.iter().all(|r| r.selected));
        c.key(Move::Home, true);
        assert_eq!(c.selection().ranges(), &[(0, 0)]);
        c.key(Move::Down, false);
        assert!(c.selection().is_empty());
    }

    #[test]
    fn shift_click_selects_from_the_cursor() {
        let mut c = controller(5);
        c.click(0, H + 1, false); // row 1
        c.click(0, 3 * H + 1, true); // row 3
        assert_eq!(c.selection().ranges(), &[(1, 3)]);
        assert_eq!(at(&c), 3);
        c.click(0, 100 * H, false); // below the last row: ignored
        assert_eq!(at(&c), 3);
    }

    #[test]
    fn dragging_selects_past_a_jitter_threshold_and_autoscrolls_by_distance() {
        let mut c = controller(3); // rows 0..=4, three visible (42px)
        c.click(0, 1, false); // press on row 0
        c.drag(2, 3); // within 3px: still a click
        assert!(c.selection().is_empty());
        c.drag(0, 2 * H + 1); // row 2
        assert_eq!(c.selection().ranges(), &[(0, 2)]);
        c.drag(0, 1); // back on the anchor row: nothing selected
        assert!(c.selection().is_empty());
        c.drag(0, 10 * H); // 7 rows below the edge: scroll toward the pointer
        assert_eq!(c.top(), 2);
        assert_eq!(c.selection().ranges(), &[(0, 4)]);
        c.drag(0, -5); // just above: one row up, select to the top row
        assert_eq!(c.top(), 1);
        assert_eq!(c.selection().ranges(), &[(0, 1)]);
    }

    #[test]
    fn dragging_below_a_short_listing_selects_to_its_last_row() {
        let mut c = controller(10); // all five rows fit
        c.click(0, 1, false);
        c.drag(0, 8 * H); // empty area below the data
        assert_eq!(c.top(), 0);
        assert_eq!(c.selection().ranges(), &[(0, 4)]);
    }

    #[test]
    fn a_drag_without_a_press_does_nothing() {
        let mut c = controller(3);
        c.key(Move::Down, false);
        c.drag(0, 2 * H + 1);
        assert!(c.selection().is_empty());
    }

    #[test]
    fn middle_click_highlights_the_word_everywhere_and_again_clears() {
        let mut c = controller(5);
        let bytes_x = 10 * 7 + 1; // inside the bytes field of row 0 ("55")
        c.middle_click(bytes_x, 1);
        assert_eq!(c.highlight(), Some("55"));
        let f = c.frame();
        // row 0: "55" bytes + "55h" operand prefix; row 3: same; others none
        assert_eq!(f.rows[0].highlights.len(), 2);
        assert_eq!(f.rows[0].highlights[0], (10 * 7, 14));
        assert_eq!(f.rows[3].highlights.len(), 2);
        assert!(f.rows[1].highlights.is_empty());
        c.middle_click(bytes_x, 1);
        assert_eq!(c.highlight(), None);
    }

    #[test]
    fn wheel_and_scrollbar_clamp_and_metrics_keep_top() {
        let mut c = controller(2);
        c.wheel(100);
        assert_eq!(c.top(), 3);
        c.wheel(-1);
        assert_eq!(c.top(), 2);
        c.set_scroll_value(1);
        assert_eq!(c.top(), 1);
        assert_eq!(c.frame().scroll_value, 1);
        c.set_metrics(FontMetrics::monospace(9, 13, 4));
        assert_eq!(c.top(), 1);
        assert_eq!(c.frame().rows[0].row.runs[1].x, 10 * 9);
    }

    /// Spec §5/§7: every UI-path call inside 8 ms on a 1M-unit listing
    /// (40 ms in unoptimized debug builds). Covers the controller paths the
    /// renderer drives per keystroke/scroll: an intent plus a full frame with
    /// selection and highlight decorations.
    #[test]
    fn frames_and_intents_stay_inside_the_ui_budget_on_a_million_rows() {
        let mut c = ListingController::new(Box::new(MemoryListing::new(
            32,
            vec![MemoryBlockSnapshot::initialized(0x1000_0000, (0..1u32 << 20).map(|i| i as u8).collect())],
        )));
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(1200);
        c.middle_click(10 * 7 + 1, 1); // highlight on, decorations in every frame
        let budget = if cfg!(debug_assertions) { 40 } else { 8 };
        let max = c.frame().scroll_max;
        for i in 0..100i32 {
            let t = std::time::Instant::now();
            c.set_scroll_value((i * 7919) % (max + 1));
            c.key(Move::Down, i % 2 == 0);
            let f = c.frame();
            assert!(!f.rows.is_empty());
            assert!(t.elapsed().as_millis() < budget, "intent+frame took {:?}", t.elapsed());
        }
        let t = std::time::Instant::now();
        c.goto_address(0x1000_0000 + 900_000).unwrap();
        let _ = c.frame();
        assert!(t.elapsed().as_millis() < budget, "goto+frame took {:?}", t.elapsed());
    }
}