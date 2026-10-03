//! The listing view-model contract (spec §5) and `MemoryListing`, which
//! renders every byte of a memory snapshot as Ghidra shows undefined data:
//! `address  bytes  ??  NNh`. Layout math happens here, from the renderer's
//! font metrics; the renderer paints the positioned runs.

pub use ghidra_rs::docking::widgets::fieldpanel::field::FontMetrics;
use ghidra_rs::docking::widgets::fieldpanel::field::{ClippingTextField, FieldElement, TextStyle};
use ghidra_rs::docking::widgets::fieldpanel::Layout;
use ghidra_rs::program::model::mem::memory::{Memory, MemoryBlockHandle};

/// A run of text placed at an x position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionedRun {
    /// Left edge in pixels.
    pub x: i32,
    /// Shown text.
    pub text: String,
    /// Theme color id.
    pub color_id: Option<String>,
    /// Bold.
    pub bold: bool,
}

/// One laid-out listing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRow {
    /// Row index.
    pub index: u128,
    /// Top of the row relative to the viewport top.
    pub y: i32,
    /// Row height.
    pub height: i32,
    /// Positioned runs, one per field.
    pub runs: Vec<PositionedRun>,
}

/// Cursor position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPos {
    /// Row index.
    pub index: u128,
    /// Field within the row.
    pub field: usize,
    /// Column within the field.
    pub col: usize,
}

/// Cursor movements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Move {
    /// Previous row.
    Up,
    /// Next row.
    Down,
    /// Previous column (wraps to the previous field).
    Left,
    /// Next column (wraps to the next field).
    Right,
    /// Up a page.
    PageUp,
    /// Down a page.
    PageDown,
    /// First row.
    Home,
    /// Last row.
    End,
}

/// The listing view-model the renderer drives.
pub trait ListingViewModel: Send {
    /// Sets the renderer's font metrics (re-layout).
    fn set_metrics(&mut self, metrics: FontMetrics);
    /// Number of rows.
    fn index_count(&self) -> u128;
    /// Rows from `top` filling `viewport_px` (a partial last row included).
    fn rows(&self, top: u128, viewport_px: i32) -> Vec<FieldRow>;
    /// Cursor position for pixel `x` on row `index`.
    fn hit_test(&self, index: u128, x: i32) -> Option<CursorPos>;
    /// Moves the cursor; `page_rows` sizes PageUp/PageDown.
    fn move_cursor(&self, cursor: CursorPos, mv: Move, page_rows: u32) -> CursorPos;
    /// Row index of an address, if listed.
    fn goto(&self, address: u64) -> Option<u128>;
    /// The address of a row as text.
    fn address_text(&self, index: u128) -> String;
    /// The address of a row (a label row: its code unit's), if listed.
    fn address_of(&self, index: u128) -> Option<u64>;
    /// Pixel x of the cursor's column, if the cursor is on a listed row.
    fn cursor_x(&self, cursor: CursorPos) -> Option<i32>;
    /// Full text of the cursor's field.
    fn field_text(&self, cursor: CursorPos) -> Option<String>;
}

/// One memory block (an immutable snapshot): its bytes, or only its length
/// when the block is uninitialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlockSnapshot {
    /// First address.
    pub start: u64,
    bytes: Vec<u8>,
    len: u64,
}

impl MemoryBlockSnapshot {
    /// An initialized block holding `bytes`.
    pub fn initialized(start: u64, bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        Self { start, bytes, len }
    }

    /// An initialized block of `len` bytes of which only the leading `bytes`
    /// could be read; the rest shows as `??`.
    pub fn partial(start: u64, mut bytes: Vec<u8>, len: u64) -> Self {
        bytes.truncate(usize::try_from(len).unwrap_or(usize::MAX));
        Self { start, bytes, len }
    }

    /// An uninitialized block of `len` bytes (shown as `??`).
    pub fn uninitialized(start: u64, len: u64) -> Self {
        Self { start, bytes: Vec::new(), len }
    }

    /// Length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the block has no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The byte at `offset`; `None` when uninitialized or out of range.
    pub fn byte(&self, offset: u64) -> Option<u8> {
        usize::try_from(offset).ok().and_then(|o| self.bytes.get(o).copied())
    }
}

/// Snapshots a program memory's blocks for [`MemoryListing`]: the address
/// size in bits and every non-overlay block, initialized bytes copied.
pub fn snapshot_memory(memory: &dyn Memory) -> (u32, Vec<MemoryBlockSnapshot>) {
    snapshot_blocks(&memory.get_block_handles())
}

/// Bytes copied per initialized block at most; larger blocks render as `??`
/// until the listing reads lazily.
pub const MAX_SNAPSHOT_BYTES: u64 = 256 << 20;

/// [`snapshot_memory`] over block handles: only loaded-memory blocks (the
/// listing has one address column, no space qualifier); bytes that cannot be
/// read render as `??` without shrinking the block.
pub fn snapshot_blocks(handles: &[MemoryBlockHandle]) -> (u32, Vec<MemoryBlockSnapshot>) {
    let mut bits = None;
    let mut blocks = Vec::with_capacity(handles.len());
    for h in handles {
        let Ok(b) = h.read() else { continue };
        let start = b.get_start();
        if !start.space().is_loaded_memory_space() {
            continue;
        }
        bits.get_or_insert(start.space().size().max(1) as u32);
        let offset = start.offset() as u64;
        let size = b.get_size();
        if !b.is_initialized() {
            blocks.push(MemoryBlockSnapshot::uninitialized(offset, size));
            continue;
        }
        // UI paths read snapshots (spec §3): copy once, bounded, and never
        // abort on allocation failure.
        let mut bytes = Vec::new();
        let copy = (size <= MAX_SNAPSHOT_BYTES)
            .then(|| usize::try_from(size).ok())
            .flatten()
            .filter(|&n| bytes.try_reserve_exact(n).is_ok());
        if let Some(n) = copy {
            bytes.resize(n, 0);
            let read = b.get_bytes(&start, &mut bytes);
            bytes.truncate(read);
        }
        blocks.push(MemoryBlockSnapshot::partial(offset, bytes, size));
    }
    (bits.unwrap_or(32), blocks)
}

/// Every byte of a memory snapshot as an undefined-data row.
pub struct MemoryListing {
    addr_digits: usize,
    blocks: Vec<MemoryBlockSnapshot>,
    starts: Vec<u128>,
    count: u128,
    metrics: FontMetrics,
}

/// Field widths in characters: address, bytes, mnemonic, operand.
const FIELD_CHARS: [i32; 4] = [0 /* address: digits + 2 */, 12, 8, 16];

impl MemoryListing {
    /// A listing over `blocks` (sorted by start) in a space of `address_bits`.
    pub fn new(address_bits: u32, mut blocks: Vec<MemoryBlockSnapshot>) -> Self {
        blocks.sort_by_key(|b| b.start);
        let mut starts = Vec::with_capacity(blocks.len());
        let mut count: u128 = 0;
        for b in &blocks {
            starts.push(count);
            count += u128::from(b.len());
        }
        let addr_digits = (address_bits as usize).div_ceil(4).max(1);
        Self { addr_digits, blocks, starts, count, metrics: FontMetrics::monospace(7, 11, 3) }
    }

    /// Address and byte (`None` = uninitialized) of row `index`.
    fn locate(&self, index: u128) -> Option<(u64, Option<u8>)> {
        if index >= self.count {
            return None;
        }
        let i = self.starts.partition_point(|&s| s <= index) - 1;
        let off = (index - self.starts[i]) as u64;
        let b = &self.blocks[i];
        Some((b.start.wrapping_add(off), b.byte(off)))
    }

    fn field_xs(&self) -> [(i32, i32); 4] {
        let cw = self.metrics.char_width;
        let mut x = 0;
        let mut out = [(0, 0); 4];
        for (i, chars) in FIELD_CHARS.iter().enumerate() {
            let w = if i == 0 { (self.addr_digits as i32 + 2) * cw } else { chars * cw };
            out[i] = (x, w);
            x += w;
        }
        out
    }

    fn layout(&self, index: u128) -> Option<Layout> {
        let (addr, byte) = self.locate(index)?;
        let texts = [
            format!("{:0width$x}", addr, width = self.addr_digits),
            byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02x}")),
            "??".to_owned(),
            byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}h")),
        ];
        let fields = self
            .field_xs()
            .iter()
            .zip(texts)
            .map(|((x, w), t)| ClippingTextField::new(*x, *w, FieldElement::new(t, None, TextStyle::Plain), &self.metrics))
            .collect();
        Some(Layout::new(fields, &self.metrics))
    }
}

impl ListingViewModel for MemoryListing {
    fn set_metrics(&mut self, metrics: FontMetrics) {
        self.metrics = metrics;
    }

    fn index_count(&self) -> u128 {
        self.count
    }

    fn rows(&self, top: u128, viewport_px: i32) -> Vec<FieldRow> {
        let h = self.metrics.line_height().max(1);
        if viewport_px <= 0 || top >= self.count {
            return Vec::new();
        }
        let n = ((viewport_px + h - 1) / h) as u128;
        let end = (top + n).min(self.count);
        (top..end)
            .enumerate()
            .filter_map(|(i, index)| {
                let layout = self.layout(index)?;
                Some(FieldRow {
                    index,
                    y: i as i32 * h,
                    height: layout.height(),
                    runs: layout
                        .fields()
                        .iter()
                        .map(|f| PositionedRun {
                            x: f.start_x(),
                            text: f.visible_text().to_owned(),
                            color_id: f.visible_element().color_id().map(str::to_owned),
                            bold: f.visible_element().style() == TextStyle::Bold,
                        })
                        .collect(),
                })
            })
            .collect()
    }

    fn hit_test(&self, index: u128, x: i32) -> Option<CursorPos> {
        let loc = self.layout(index)?.try_cursor_location(index, x)?;
        Some(CursorPos { index, field: loc.field, col: loc.col })
    }

    fn move_cursor(&self, c: CursorPos, mv: Move, page_rows: u32) -> CursorPos {
        if self.count == 0 {
            return c;
        }
        let last = self.count - 1;
        let clamp_col = |index: u128, field: usize, col: usize| -> CursorPos {
            // The previous row's field may not exist on this one (U2b rows
            // differ in field count): clamp to the last field.
            let Some(l) = self.layout(index) else { return CursorPos { index, field: 0, col: 0 } };
            let field = field.min(l.fields().len().saturating_sub(1));
            let cols = l.fields().get(field).map_or(1, |f| f.num_cols());
            CursorPos { index, field, col: col.min(cols - 1) }
        };
        let page = page_rows.max(1) as u128;
        match mv {
            Move::Up => clamp_col(c.index.saturating_sub(1), c.field, c.col),
            Move::Down => clamp_col((c.index + 1).min(last), c.field, c.col),
            Move::PageUp => clamp_col(c.index.saturating_sub(page), c.field, c.col),
            Move::PageDown => clamp_col((c.index + page).min(last), c.field, c.col),
            Move::Home => clamp_col(0, c.field, c.col),
            Move::End => clamp_col(last, c.field, c.col),
            Move::Right => {
                let c = clamp_col(c.index, c.field, c.col);
                let Some(l) = self.layout(c.index) else { return c };
                if c.col + 1 < l.fields()[c.field].num_cols() {
                    CursorPos { col: c.col + 1, ..c }
                } else if c.field + 1 < l.fields().len() {
                    CursorPos { field: c.field + 1, col: 0, ..c }
                } else {
                    c
                }
            }
            Move::Left => {
                let c = clamp_col(c.index, c.field, c.col);
                if c.col > 0 {
                    CursorPos { col: c.col - 1, ..c }
                } else if c.field > 0 {
                    let cols = self.layout(c.index).map(|l| l.fields()[c.field - 1].num_cols()).unwrap_or(1);
                    CursorPos { field: c.field - 1, col: cols - 1, ..c }
                } else {
                    c
                }
            }
        }
    }

    fn goto(&self, address: u64) -> Option<u128> {
        self.blocks.iter().enumerate().find_map(|(i, b)| {
            let off = address.checked_sub(b.start)?;
            (off < b.len()).then(|| self.starts[i] + u128::from(off))
        })
    }

    fn address_text(&self, index: u128) -> String {
        self.locate(index).map(|(a, _)| format!("{:0width$x}", a, width = self.addr_digits)).unwrap_or_default()
    }

    fn address_of(&self, index: u128) -> Option<u64> {
        self.locate(index).map(|(a, _)| a)
    }

    fn cursor_x(&self, c: CursorPos) -> Option<i32> {
        Some(self.layout(c.index)?.fields().get(c.field)?.x(c.col))
    }

    fn field_text(&self, c: CursorPos) -> Option<String> {
        Some(self.layout(c.index)?.fields().get(c.field)?.text().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> FontMetrics {
        FontMetrics::monospace(7, 11, 3)
    }
    fn listing() -> MemoryListing {
        let mut l = MemoryListing::new(
            32,
            vec![MemoryBlockSnapshot::initialized(0x401000, vec![0x55, 0x48, 0x89, 0xe5]), MemoryBlockSnapshot::initialized(0x402000, vec![0xc3])],
        );
        l.set_metrics(metrics());
        l
    }
    fn texts(r: &FieldRow) -> Vec<String> {
        r.runs.iter().map(|x| x.text.clone()).collect()
    }

    #[test]
    fn undefined_bytes_render_like_ghidra() {
        let l = listing();
        assert_eq!(l.index_count(), 5);
        let rows = l.rows(0, 1000);
        assert_eq!(rows.len(), 5);
        assert_eq!(texts(&rows[0]), vec!["00401000", "55", "??", "55h"]);
        assert_eq!(texts(&rows[3]), vec!["00401003", "e5", "??", "E5h"]);
        assert_eq!(texts(&rows[4]), vec!["00402000", "c3", "??", "C3h"]); // gap skipped
        assert!(rows.windows(2).all(|w| w[1].y == w[0].y + w[0].height));
    }

    #[test]
    fn a_cursor_field_past_the_row_is_clamped_not_a_panic() {
        let l = listing();
        let c = CursorPos { index: 0, field: 9, col: 9 };
        assert_eq!(l.move_cursor(c, Move::Down, 1), CursorPos { index: 1, field: 3, col: 3 });
        assert_eq!(l.move_cursor(c, Move::Left, 1), CursorPos { index: 0, field: 3, col: 2 });
        assert_eq!(l.cursor_x(c), None);
        assert_eq!(l.field_text(CursorPos { index: 4, field: 1, col: 0 }).as_deref(), Some("c3"));
    }

    #[test]
    fn uninitialized_bytes_show_question_marks() {
        let mut l = MemoryListing::new(
            32,
            vec![MemoryBlockSnapshot::initialized(0x1000, vec![0x90]), MemoryBlockSnapshot::uninitialized(0x2000, 3)],
        );
        l.set_metrics(metrics());
        assert_eq!(l.index_count(), 4);
        let rows = l.rows(0, 1000);
        assert_eq!(texts(&rows[0]), vec!["00001000", "90", "??", "90h"]);
        assert_eq!(texts(&rows[3]), vec!["00002002", "??", "??", "??"]);
        assert_eq!(l.goto(0x2002), Some(3));
        assert_eq!(l.goto(0x2003), None);
    }

    #[test]
    fn a_memory_map_db_snapshots_into_listing_rows() {
        use ghidra_rs::framework::data::OpenMode;
        use ghidra_rs::framework::db::DBHandle;
        use ghidra_rs::program::database::map::AddressMapDB;
        use ghidra_rs::program::database::mem::memory_map_db::MemoryMapDB;
        use ghidra_rs::program::model::address::{Address, AddressSpace, AddressSpaceType, DefaultAddressFactory};
        use ghidra_rs::util::task::DummyMonitor;
        use std::sync::{Arc, RwLock};

        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![ram.clone()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let map = MemoryMapDB::new(handle, addr_map, OpenMode::Create, false, &DummyMonitor).unwrap();
        {
            let mut m = map.write().unwrap();
            let mut text: &[u8] = &[0x55, 0xc3];
            m.create_initialized_block(".text", &Address::new(ram.clone(), 0x401000), Some(&mut text), 2, None, false).unwrap();
            m.create_uninitialized_block(".bss", &Address::new(ram.clone(), 0x404000), 2, false).unwrap();
        }
        let (bits, blocks) = snapshot_memory(&*map.read().unwrap());
        assert_eq!(bits, 32);
        let mut l = MemoryListing::new(bits, blocks);
        l.set_metrics(metrics());
        let rows: Vec<Vec<String>> = l.rows(0, 1000).iter().map(texts).collect();
        assert_eq!(
            rows,
            vec![
                vec!["00401000", "55", "??", "55h"],
                vec!["00401001", "c3", "??", "C3h"],
                vec!["00404000", "??", "??", "??"],
                vec!["00404001", "??", "??", "??"],
            ]
        );
    }

    mod fake {
        use ghidra_rs::program::model::address::{Address, AddressSpace, AddressSpaceType};
        use ghidra_rs::program::model::mem::memory::MemoryBlockHandle;
        use ghidra_rs::program::model::mem::memory_block::MemoryBlock;
        use ghidra_rs::program::model::mem::MemoryAccessException;
        use std::sync::{Arc, RwLock};

        pub struct Block {
            pub start: Address,
            pub size: u64,
            pub initialized: bool,
            pub readable: usize,
        }

        impl MemoryBlock for Block {
            fn get_name(&self) -> &str {
                "b"
            }
            fn get_start(&self) -> Address {
                self.start.clone()
            }
            fn get_end(&self) -> Address {
                self.start.clone()
            }
            fn get_size(&self) -> u64 {
                self.size
            }
            fn is_initialized(&self) -> bool {
                self.initialized
            }
            fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
                Ok(0xab)
            }
            fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
                let n = self.readable.min(dest.len());
                dest[..n].fill(0xab);
                n
            }
            fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
                Ok(())
            }
        }

        pub fn ram(offset: i64) -> Address {
            Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0), offset)
        }

        pub fn other(offset: i64) -> Address {
            Address::new(AddressSpace::other_space().clone(), offset)
        }

        pub fn handle(start: Address, size: u64, initialized: bool, readable: usize) -> MemoryBlockHandle {
            Arc::new(RwLock::new(Block { start, size, initialized, readable }))
        }
    }

    #[test]
    fn a_short_read_keeps_the_block_length_and_shows_question_marks() {
        let (bits, blocks) = snapshot_blocks(&[fake::handle(fake::ram(0x1000), 4, true, 2)]);
        let mut l = MemoryListing::new(bits, blocks);
        l.set_metrics(metrics());
        let rows: Vec<Vec<String>> = l.rows(0, 1000).iter().map(texts).collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1], vec!["00001001", "ab", "??", "ABh"]);
        assert_eq!(rows[2], vec!["00001002", "??", "??", "??"]);
        assert_eq!(l.goto(0x1003), Some(3));
    }

    #[test]
    fn non_loaded_spaces_are_left_out_and_do_not_widen_addresses() {
        let (bits, blocks) =
            snapshot_blocks(&[fake::handle(fake::ram(0x1000), 1, true, 1), fake::handle(fake::other(0x1000), 8, true, 8)]);
        assert_eq!(bits, 32);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 1);
    }

    #[test]
    fn a_huge_block_is_not_copied() {
        let size = 1u64 << 40;
        let (_, blocks) = snapshot_blocks(&[fake::handle(fake::ram(0), size, true, 0)]);
        assert_eq!(blocks[0].len(), size);
        assert_eq!(blocks[0].byte(0), None);
    }

    #[test]
    fn rows_clamp_at_both_ends() {
        let l = listing();
        assert_eq!(l.rows(3, 1000).len(), 2);
        assert!(l.rows(99, 1000).is_empty());
        assert_eq!(l.rows(0, 15).len(), 2); // partial second row is included
        assert!(l.rows(0, 0).is_empty());
    }

    #[test]
    fn goto_and_address_text() {
        let l = listing();
        assert_eq!(l.goto(0x402000), Some(4));
        assert_eq!(l.goto(0x401800), None); // gap
        assert_eq!(l.address_text(1), "00401001");
    }

    #[test]
    fn hit_test_and_cursor_moves() {
        let l = listing();
        let c = l.hit_test(1, 0).unwrap();
        assert_eq!((c.index, c.field, c.col), (1, 0, 0));
        assert_eq!(l.move_cursor(c, Move::Down, 10).index, 2);
        assert_eq!(l.move_cursor(CursorPos { index: 4, field: 0, col: 0 }, Move::Down, 10).index, 4); // clamp
        assert_eq!(l.move_cursor(c, Move::Up, 10).index, 0);
        assert_eq!(l.move_cursor(c, Move::Right, 10).col, 1);
        assert_eq!(l.move_cursor(CursorPos { index: 0, field: 0, col: 8 }, Move::Right, 10).field, 1); // wrap to next field
        assert_eq!(l.move_cursor(c, Move::End, 10).index, 4);
        assert_eq!(l.move_cursor(c, Move::PageDown, 2).index, 3);
    }

    #[test]
    fn metric_changes_relayout_without_moving_indices() {
        let mut l = listing();
        let before = l.rows(2, 1000)[0].index;
        l.set_metrics(FontMetrics::monospace(9, 13, 4));
        let after = l.rows(2, 1000);
        assert_eq!(after[0].index, before);
        assert_eq!(after[0].height, 17);
        assert!(after[0].runs[1].x > 0);
    }

    #[test]
    fn rows_stay_fast_on_a_megabyte_block() {
        let mut l = MemoryListing::new(32, vec![MemoryBlockSnapshot::initialized(0x1000_0000, vec![0x90; 1 << 20])]);
        l.set_metrics(metrics());
        let budget = if cfg!(debug_assertions) { 40 } else { 8 };
        for i in 0..100u128 {
            let top = (i * 7919) % l.index_count();
            let t = std::time::Instant::now();
            let rows = l.rows(top, 1200);
            assert!(!rows.is_empty());
            assert!(t.elapsed().as_millis() < budget, "rows() took {:?}", t.elapsed());
        }
    }
}
