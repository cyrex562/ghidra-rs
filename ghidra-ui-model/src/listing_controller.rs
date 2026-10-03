//! Listing view state and navigation (spec §5 M1 scope): top row, cursor,
//! selection, the middle-mouse text highlight and back/forward history all
//! live here, so the renderer only sends intents and paints frames.

use std::sync::{Arc, Mutex, MutexGuard};

use ghidra_rs::app::plugin::core::navigation::history_list::{HistoryList, MAX_HISTORY_SIZE};

use crate::listing::{CursorPos, FieldRow, FontMetrics, ListingViewModel, Move};
use crate::listing_scroll::ScrollModel;
use crate::listing_selection::IndexSelection;

/// Most rows Edit > Copy will lay out at once.
pub const MAX_COPY_ROWS: u128 = 100_000;

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

/// A history entry: the row, plus its address for after the model changes
/// (Java `LocationMemento` holds a program location). Entries of one model
/// compare by row, across models by address.
#[derive(Debug, Clone, Copy)]
struct Memento {
    pos: CursorPos,
    address: Option<u64>,
    epoch: u64,
}

impl PartialEq for Memento {
    fn eq(&self, other: &Self) -> bool {
        if self.epoch == other.epoch {
            self.pos.index == other.pos.index
        } else {
            self.address.is_some() && self.address == other.address
        }
    }
}

/// The first and last row of the code unit holding `address` (its label and
/// header rows, then the unit), if listed.
fn rows_at(m: &dyn ListingViewModel, address: u64) -> Option<(u128, u128)> {
    let first = m.goto(address)?;
    let unit = m.address_of(first);
    let mut last = first;
    while last + 1 < m.index_count() && m.address_of(last + 1) == unit {
        last += 1;
    }
    Some((first, last))
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
    /// Bumped by [`Self::replace_model`]; older history resolves by address.
    epoch: u64,
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
            epoch: 0,
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

    /// Double click (Java `OperandFieldMouseHandler`): the cursor goes there,
    /// then to the operand's referenced address if it has one, with history.
    /// Returns whether it navigated.
    pub fn activate(&mut self, x: i32, y: i32) -> bool {
        self.click(x, y, false);
        let Some(target) = self.cursor.and_then(|c| self.model.reference_target(c)) else { return false };
        self.goto_address(target).is_ok()
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
            self.history.add(self.memento(c));
        }
        let target = CursorPos { index, field: 0, col: 0 };
        self.history.add(self.memento(target));
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
                self.history.add(self.memento(c));
            }
        }
        match self.history.previous().and_then(|m| self.resolve(m)) {
            Some(c) => {
                self.navigate(c);
                true
            }
            None => false,
        }
    }

    /// Next location.
    pub fn forward(&mut self) -> bool {
        match self.history.next().and_then(|m| self.resolve(m)) {
            Some(c) => {
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

    /// Swaps in a new view-model of the same program (after an edit), keeping
    /// the top row, cursor, selection and history by address: each lands on
    /// the first row at its address (a selection's end on the last), so an
    /// address now inside a code unit lands on that unit.
    pub fn replace_model(&mut self, mut model: Box<dyn ListingViewModel>) {
        model.set_metrics(self.metrics);
        let old = std::mem::replace(&mut self.model, model);
        let new = self.model.as_ref();
        // Rows keep their place counted from the end of their address's rows
        // (the code unit row is last, labels and headers above it).
        let row = |i: u128| {
            let a = old.address_of(i)?;
            let (_, old_last) = rows_at(old.as_ref(), a)?;
            let (first, last) = rows_at(new, a)?;
            Some(last.saturating_sub(old_last.saturating_sub(i)).max(first))
        };
        let first = |m: &dyn ListingViewModel, i: u128| old.address_of(i).and_then(|a| m.goto(a));
        let top = row(self.top).unwrap_or(0);
        self.cursor = self.cursor.and_then(|c| row(c.index)).map(|index| CursorPos { index, field: 0, col: 0 });
        self.anchor = self.anchor.and_then(row);
        let ranges: Vec<(u128, u128)> = self
            .selection
            .ranges()
            .iter()
            .filter_map(|&(a, b)| {
                let start = first(self.model.as_ref(), a)?;
                let (_, end) = rows_at(self.model.as_ref(), old.address_of(b)?)?;
                Some((start, end.max(start)))
            })
            .collect();
        self.selection.clear();
        for (a, b) in ranges {
            self.selection.add_range(a, b);
        }
        self.top = self.scroll().clamp(top);
        self.press = None;
        self.dragging = false;
        self.epoch += 1;
    }

    fn memento(&self, pos: CursorPos) -> Memento {
        Memento { pos, address: self.model.address_of(pos.index), epoch: self.epoch }
    }

    /// A history entry's row in the current model.
    fn resolve(&self, m: Memento) -> Option<CursorPos> {
        if m.epoch == self.epoch {
            return Some(m.pos);
        }
        let index = self.model.goto(m.address?)?;
        Some(CursorPos { index, field: 0, col: 0 })
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

    /// Edit > Copy (Java `CodeBrowserClipboardProvider.copy`): the selected
    /// rows laid out as text (`copyCode` + `TextLayoutGraphics`), else the
    /// cursor field's text (`copyFromCurrentLocation`); `None` with neither.
    pub fn copy_text(&self) -> Result<Option<String>, String> {
        if self.selection.is_empty() {
            return Ok(self.cursor.and_then(|c| self.model.field_text(c)));
        }
        let rows = self.selection.row_count();
        if rows > MAX_COPY_ROWS {
            return Err(format!("Selection too large to copy: {rows} rows (limit {MAX_COPY_ROWS})"));
        }
        let mut out = String::new();
        for &(lo, hi) in self.selection.ranges() {
            let mut index = lo;
            while index <= hi {
                let viewport = (self.metrics.line_height().max(1)) * 64;
                let chunk = self.model.rows(index, viewport);
                if chunk.is_empty() {
                    break;
                }
                for row in chunk.iter().take_while(|r| r.index <= hi) {
                    self.layout_row_text(row, &mut out);
                    index = row.index + 1;
                }
                if chunk.last().is_some_and(|r| r.index >= hi) {
                    break;
                }
            }
        }
        Ok(Some(out))
    }

    /// Java `TextLayoutGraphics.flush` for one row: runs in x order, gaps
    /// filled with round(gap / space width) spaces (at least one), then '\n'.
    fn layout_row_text(&self, row: &FieldRow, out: &mut String) {
        let mut runs: Vec<&crate::listing::PositionedRun> = row.runs.iter().collect();
        runs.sort_by_key(|r| r.x);
        let mut current_x = 0;
        for run in runs {
            let cw = if run.bold { self.metrics.bold_char_width } else { self.metrics.char_width }.max(1);
            let gap = run.x - current_x;
            let mut fill = ((gap as f32) / (cw as f32)).round() as i32;
            if fill == 0 && run.x > current_x {
                fill = 1;
            }
            out.extend(std::iter::repeat_n(' ', fill.max(0) as usize));
            out.push_str(&run.text);
            current_x = run.x + run.text.chars().count() as i32 * cw;
        }
        out.push('\n');
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

    /// The same memory as [`controller`] with a label and a 3-byte
    /// instruction at 0x401000: rows label, insn, 0x401003, 0x402000.
    fn disassembled() -> Box<dyn ListingViewModel> {
        use crate::code_unit_listing::{CodeUnitListing, InstructionSnapshot, LabelSnapshot};
        Box::new(CodeUnitListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x401000, vec![0x55, 0x48, 0x89, 0x55]),
                MemoryBlockSnapshot::initialized(0x402000, vec![0xc3]),
            ],
            vec![InstructionSnapshot { start: 0x401000, len: 3, mnemonic: "PUSH".into(), operands: String::new(), references: vec![] }],
            vec![LabelSnapshot { address: 0x401000, name: "f".into(), primary: true, id: 0 }],
        ))
    }

    #[test]
    fn rows_know_their_addresses() {
        let c = controller(10);
        assert_eq!(c.model().address_of(1), Some(0x401001));
        assert_eq!(c.model().address_of(4), Some(0x402000));
        assert_eq!(c.model().address_of(5), None);
        let d = disassembled();
        assert_eq!((d.address_of(0), d.address_of(1), d.address_of(2)), (Some(0x401000), Some(0x401000), Some(0x401003)));
    }

    #[test]
    fn replacing_the_model_keeps_cursor_and_selection_by_address() {
        let mut c = controller(10);
        c.click(1, H + 1, false); // row 1 = 0x401001
        c.key(Move::Down, true); // select 0x401001..0x401002, cursor 0x401002
        assert_eq!(at(&c), 2);
        c.replace_model(disassembled());
        // both bytes are inside the new instruction (row 1)
        assert_eq!(at(&c), 1);
        assert_eq!(c.model().address_of(at(&c)), Some(0x401000));
        assert!(c.selection().contains(1) && !c.selection().is_empty());
        assert!(!c.selection().contains(2));
    }

    #[test]
    fn history_from_before_a_model_change_resolves_by_address() {
        let mut c = controller(10);
        c.click(1, 3 * H + 1, false); // 0x401003
        c.goto_address(0x402000).unwrap();
        c.replace_model(disassembled());
        assert_eq!(c.model().address_of(at(&c)), Some(0x402000));
        assert!(c.back());
        assert_eq!(c.model().address_of(at(&c)), Some(0x401003));
        assert_eq!(at(&c), 2);
        assert!(c.forward());
        assert_eq!(at(&c), 3);
    }

    /// [`disassembled`] after Clear Code Bytes: label f, then one row per byte.
    fn cleared() -> Box<dyn ListingViewModel> {
        use crate::code_unit_listing::{CodeUnitListing, LabelSnapshot};
        Box::new(CodeUnitListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x401000, vec![0x55, 0x48, 0x89, 0x55]),
                MemoryBlockSnapshot::initialized(0x402000, vec![0xc3]),
            ],
            vec![],
            vec![LabelSnapshot { address: 0x401000, name: "f".into(), primary: true, id: 0 }],
        ))
    }

    #[test]
    fn a_cursor_on_the_code_unit_row_stays_on_it_not_on_its_label() {
        let mut c = ListingController::new(disassembled());
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(10 * H);
        c.click(1, H + 1, false); // the instruction row, under label f
        c.replace_model(cleared());
        assert_eq!(at(&c), 1, "the byte row at 0x401000, not the label");
        c.click(1, 1, false); // on the label
        c.replace_model(disassembled());
        assert_eq!(at(&c), 0, "a label row stays the label row");
    }

    #[test]
    fn the_selection_anchor_keeps_its_row_kind_too() {
        let mut c = ListingController::new(disassembled());
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(10 * H);
        c.click(1, H + 1, false); // anchor: the instruction row
        c.key(Move::Down, true);
        c.replace_model(disassembled());
        c.key(Move::Down, true);
        assert!(!c.selection().contains(0), "the label above the anchor is not pulled in");
        assert!(c.selection().contains(1));
    }

    #[test]
    fn activating_an_operand_with_a_reference_follows_it_with_history() {
        use crate::code_unit_listing::{CodeUnitListing, InstructionSnapshot, OperandRef};
        let mut c = ListingController::new(Box::new(CodeUnitListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x401000, vec![0xe8, 0, 0x10, 0, 0]),
                MemoryBlockSnapshot::initialized(0x402000, vec![0xc3]),
            ],
            vec![InstructionSnapshot {
                start: 0x401000,
                len: 5,
                mnemonic: "CALL".into(),
                operands: "0x402000".into(),
                references: vec![OperandRef { op_index: 0, to: 0x402000 }],
            }],
            vec![],
        )));
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(10 * H);
        let operand_x = c.model().cursor_x(CursorPos { index: 0, field: 3, col: 2 }).unwrap();
        let mnemonic_x = c.model().cursor_x(CursorPos { index: 0, field: 2, col: 1 }).unwrap();
        assert!(!c.activate(mnemonic_x, 1), "the mnemonic only places the cursor");
        assert_eq!(c.cursor().unwrap().field, 2);
        assert!(c.activate(operand_x, 1));
        assert_eq!(c.model().address_of(at(&c)), Some(0x402000));
        assert!(c.back());
        assert_eq!(at(&c), 0);
    }

    #[test]
    fn replacing_with_an_empty_model_drops_the_cursor() {
        let mut c = controller(10);
        c.click(1, 1, false);
        c.replace_model(Box::new(MemoryListing::new(32, vec![])));
        assert!(c.cursor().is_none());
        assert!(c.selection().is_empty());
        assert_eq!(c.top(), 0);
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
    fn copy_lays_out_selected_rows_like_ghidras_text_layout() {
        let mut c = controller(5);
        c.click(0, 3 * H + 1, false); // row 3
        c.key(Move::Down, true); // select rows 3..=4 (across the block gap)
        let text = c.copy_text().unwrap().unwrap();
        // address (10 chars wide), bytes (12), mnemonic (8), operand: runs padded by
        // round((x - end)/char width) spaces, one line per row, each ending in '\n'
        assert_eq!(text, "00401003  55          ??      55h\n00402000  c3          ??      C3h\n");
    }

    #[test]
    fn copy_without_a_selection_takes_the_cursor_field() {
        let mut c = controller(5);
        assert_eq!(c.copy_text().unwrap(), None);
        c.click(10 * 7 + 1, 1, false); // bytes field of row 0
        assert_eq!(c.copy_text().unwrap().as_deref(), Some("55"));
    }

    #[test]
    fn copying_a_huge_selection_is_refused() {
        let mut c = ListingController::new(Box::new(MemoryListing::new(32, vec![MemoryBlockSnapshot::initialized(0, vec![0; 300_000])])));
        c.set_metrics(FontMetrics::monospace(7, 11, 3));
        c.set_viewport(10 * H);
        c.key(Move::End, true);
        assert!(c.copy_text().unwrap_err().contains("300000"));
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