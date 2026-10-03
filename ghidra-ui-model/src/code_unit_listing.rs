//! A listing over code units and labels (the step between the byte-per-row
//! [`MemoryListing`](crate::listing::MemoryListing) and U2b's FieldFactory
//! port): an instruction is one row spanning its bytes, undefined bytes stay
//! one row each (`??`), and each label gets its own row above the code unit
//! at its address, as Ghidra's Label field sits above the code unit.

use ghidra_rs::docking::widgets::fieldpanel::field::{ClippingTextField, FieldElement, TextStyle};
use ghidra_rs::docking::widgets::fieldpanel::Layout;

use crate::listing::{CursorPos, FieldRow, FontMetrics, ListingViewModel, MemoryBlockSnapshot, Move};

/// A decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionSnapshot {
    /// First address.
    pub start: u64,
    /// Length in bytes.
    pub len: u32,
    /// Mnemonic as the listing shows it.
    pub mnemonic: String,
    /// Operands, comma separated, as the listing shows them.
    pub operands: String,
    /// Each operand's primary memory reference.
    pub references: Vec<OperandRef>,
}

/// An operand's primary memory reference (Java `getPrimaryReferenceFrom`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperandRef {
    /// The operand (0-based).
    pub op_index: i32,
    /// The referenced address.
    pub to: u64,
}

/// A label at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelSnapshot {
    /// Address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// The address's primary symbol (shown first).
    pub primary: bool,
    /// The symbol's id (0 when it has none, as in fixtures).
    pub id: i64,
}

/// What a memory block's start header shows (Java `MemoryBlockStartFieldFactory`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block's first address.
    pub start: u64,
    /// Name plus a type suffix for non-default blocks (" (Bit Mapped)", ...).
    pub name: String,
    /// The block comment ("" for none).
    pub comment: String,
    /// The address space name ("ram").
    pub space: String,
}

/// Code units and labels over memory.
pub struct CodeUnitListing {
    addr_digits: usize,
    blocks: Vec<MemoryBlockSnapshot>,
    segments: Vec<Segment>,
    count: u128,
    metrics: FontMetrics,
}

#[derive(Debug, Clone)]
enum SegKind {
    /// A label row: the symbol's name and id.
    Label { name: String, id: i64 },
    /// A block-start `//` header line.
    Header(String),
    Instruction { len: u64, mnemonic: String, operands: String, references: Vec<OperandRef> },
    /// `rows` undefined bytes from `address`.
    Undefined,
}

#[derive(Debug, Clone)]
struct Segment {
    first_row: u128,
    rows: u128,
    address: u64,
    block: usize,
    kind: SegKind,
}

impl Segment {
    /// End of the address span this segment covers (a label covers none).
    fn end(&self) -> u64 {
        match &self.kind {
            SegKind::Label { .. } | SegKind::Header(_) => self.address,
            SegKind::Instruction { len, .. } => self.address + len,
            SegKind::Undefined => self.address + self.rows as u64,
        }
    }
}

/// Field widths in characters after the address: bytes, mnemonic, operands.
const FIELD_CHARS: [i32; 3] = [12, 8, 40];

impl CodeUnitListing {
    /// A listing over `blocks` with `instructions` decoded and `labels` placed.
    /// Overlapping instructions after the first are skipped, instructions are
    /// clamped to their block, and labels outside memory are dropped.
    pub fn new(
        address_bits: u32,
        blocks: Vec<MemoryBlockSnapshot>,
        instructions: Vec<InstructionSnapshot>,
        labels: Vec<LabelSnapshot>,
    ) -> Self {
        Self::with_headers(address_bits, blocks, instructions, labels, Vec::new())
    }

    /// [`Self::new`] plus the `//` header Ghidra draws at each block's start.
    pub fn with_headers(
        address_bits: u32,
        mut blocks: Vec<MemoryBlockSnapshot>,
        mut instructions: Vec<InstructionSnapshot>,
        mut labels: Vec<LabelSnapshot>,
        headers: Vec<BlockHeader>,
    ) -> Self {
        let addr_digits = (address_bits as usize).div_ceil(4).max(1);
        blocks.sort_by_key(|b| b.start);
        instructions.sort_by_key(|i| i.start);
        // LabelFieldSymbolLoader: non-primaries first, the primary last
        labels.sort_by(|a, b| a.address.cmp(&b.address).then(a.primary.cmp(&b.primary)).then(a.name.cmp(&b.name)));
        let mut segments = Vec::new();
        let mut next_row: u128 = 0;
        let mut push = |segments: &mut Vec<Segment>, rows: u128, address: u64, block: usize, kind: SegKind| {
            segments.push(Segment { first_row: next_row, rows, address, block, kind });
            next_row += rows;
        };
        let (mut ii, mut li) = (0usize, 0usize);
        for (bi, b) in blocks.iter().enumerate() {
            let (start, end) = (b.start, b.start.saturating_add(b.len()));
            while ii < instructions.len() && instructions[ii].start < start {
                ii += 1;
            }
            while li < labels.len() && labels[li].address < start {
                li += 1;
            }
            if let Some(h) = headers.iter().find(|h| h.start == start && b.len() > 0) {
                // MemoryBlockStartFieldFactory.createBlockStartText
                let last = start + b.len() - 1;
                let range = format!("{0}:{1:02$x}-{0}:{3:02$x}", h.space, start, addr_digits, last);
                let mut lines = vec!["//".to_owned(), format!("// {}", h.name)];
                if !h.comment.is_empty() {
                    lines.push(format!("// {}", h.comment));
                }
                lines.push(format!("// {range}"));
                lines.push("//".to_owned());
                for line in lines {
                    push(&mut segments, 1, start, bi, SegKind::Header(line));
                }
            }
            let mut cursor = start;
            loop {
                while ii < instructions.len() && instructions[ii].start < cursor {
                    ii += 1; // overlaps the previous instruction
                }
                let next_insn = instructions.get(ii).map(|i| i.start).filter(|&a| a < end);
                let next_label = labels.get(li).map(|l| l.address).filter(|&a| a < end);
                let p = match (next_insn, next_label) {
                    (Some(a), Some(b)) => a.min(b),
                    (Some(a), None) | (None, Some(a)) => a,
                    (None, None) => end,
                };
                if p > cursor {
                    push(&mut segments, u128::from(p - cursor), cursor, bi, SegKind::Undefined);
                    cursor = p;
                }
                if p >= end {
                    break;
                }
                let at = li;
                while li < labels.len() && labels[li].address == p {
                    li += 1;
                }
                let len = (next_insn == Some(p)).then(|| u64::from(instructions[ii].len.max(1)).min(end - p));
                // offcut labels inside the instruction first (Symbols lists
                // offcuts before the code unit's own symbols)
                let unit_end = p + len.unwrap_or(0);
                while li < labels.len() && labels[li].address < unit_end {
                    push(&mut segments, 1, p, bi, SegKind::Label { name: labels[li].name.clone(), id: labels[li].id });
                    li += 1;
                }
                for l in labels[at..].iter().take_while(|l| l.address == p) {
                    push(&mut segments, 1, p, bi, SegKind::Label { name: l.name.clone(), id: l.id });
                }
                if let Some(len) = len {
                    let insn = &instructions[ii];
                    let kind = SegKind::Instruction {
                        len,
                        mnemonic: insn.mnemonic.clone(),
                        operands: insn.operands.clone(),
                        references: insn.references.clone(),
                    };
                    push(&mut segments, 1, p, bi, kind);
                    cursor = p + len;
                    ii += 1;
                }
            }
        }
        Self { addr_digits, blocks, segments, count: next_row, metrics: FontMetrics::monospace(7, 11, 3) }
    }

    fn segment(&self, index: u128) -> Option<&Segment> {
        if index >= self.count {
            return None;
        }
        let i = self.segments.partition_point(|s| s.first_row <= index).checked_sub(1)?;
        self.segments.get(i)
    }

    /// The address a row shows.
    fn row_address(&self, index: u128) -> Option<u64> {
        let s = self.segment(index)?;
        Some(match s.kind {
            SegKind::Undefined => s.address + (index - s.first_row) as u64,
            _ => s.address,
        })
    }

    fn field_xs(&self) -> [(i32, i32); 4] {
        let cw = self.metrics.char_width;
        let mut x = 0;
        let mut out = [(0, 0); 4];
        let widths = [(self.addr_digits as i32 + 2) * cw, FIELD_CHARS[0] * cw, FIELD_CHARS[1] * cw, FIELD_CHARS[2] * cw];
        for (i, w) in widths.into_iter().enumerate() {
            out[i] = (x, w);
            x += w;
        }
        out
    }

    fn field(&self, x: i32, w: i32, text: String) -> ClippingTextField {
        ClippingTextField::new(x, w, FieldElement::new(text, None, TextStyle::Plain), &self.metrics)
    }

    fn layout(&self, index: u128) -> Option<Layout> {
        let s = self.segment(index)?;
        let xs = self.field_xs();
        let block = &self.blocks[s.block];
        let fields = match &s.kind {
            SegKind::Label { name, .. } | SegKind::Header(name) => {
                let width = xs[1].1 + xs[2].1 + xs[3].1;
                vec![self.field(xs[1].0, width, name.clone())]
            }
            SegKind::Instruction { len, mnemonic, operands, .. } => {
                let off = s.address - block.start;
                let bytes: Vec<String> = (0..*len).map(|k| block.byte(off + k).map_or_else(|| "??".to_owned(), |b| format!("{b:02x}"))).collect();
                let texts = [self.address_string(s.address), bytes.join(" "), mnemonic.clone(), operands.clone()];
                xs.iter().zip(texts).map(|((x, w), t)| self.field(*x, *w, t)).collect()
            }
            SegKind::Undefined => {
                let address = s.address + (index - s.first_row) as u64;
                let byte = block.byte(address - block.start);
                let texts = [
                    self.address_string(address),
                    byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02x}")),
                    "??".to_owned(),
                    byte.map_or_else(|| "??".to_owned(), |b| format!("{b:02X}h")),
                ];
                xs.iter().zip(texts).map(|((x, w), t)| self.field(*x, *w, t)).collect()
            }
        };
        Some(Layout::new(fields, &self.metrics))
    }

    fn address_string(&self, address: u64) -> String {
        format!("{:0width$x}", address, width = self.addr_digits)
    }
}

/// The operand (0-based) holding column `col` of an operand field's text:
/// operands are separated by commas outside `[]`/`()`; a column past the end
/// belongs to the last operand.
pub fn operand_index_at(text: &str, col: usize) -> i32 {
    let mut depth = 0i32;
    let mut index = 0;
    for ch in text.chars().take(col) {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth <= 0 => index += 1,
            _ => {}
        }
    }
    index
}

impl ListingViewModel for CodeUnitListing {
    fn label_at(&self, index: u128) -> Option<(i64, String)> {
        match &self.segment(index)?.kind {
            SegKind::Label { name, id } => Some((*id, name.clone())),
            _ => None,
        }
    }
    fn reference_target(&self, c: CursorPos) -> Option<u64> {
        const OPERANDS: usize = 3;
        let s = self.segment(c.index)?;
        let SegKind::Instruction { operands, references, .. } = &s.kind else { return None };
        if c.field != OPERANDS {
            return None;
        }
        let op = operand_index_at(operands, c.col);
        references.iter().find(|r| r.op_index == op).map(|r| r.to)
    }
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
        let end = top.saturating_add(n).min(self.count);
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
                        .map(|f| crate::listing::PositionedRun {
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
            let Some(l) = self.layout(index) else { return CursorPos { index, field: 0, col: 0 } };
            let field = field.min(l.fields().len().saturating_sub(1));
            let cols = l.fields().get(field).map_or(1, |f| f.num_cols());
            CursorPos { index, field, col: col.min(cols - 1) }
        };
        let page = u128::from(page_rows.max(1));
        match mv {
            Move::Up => clamp_col(c.index.saturating_sub(1), c.field, c.col),
            Move::Down => clamp_col((c.index + 1).min(last), c.field, c.col),
            Move::PageUp => clamp_col(c.index.saturating_sub(page), c.field, c.col),
            Move::PageDown => clamp_col(c.index.saturating_add(page).min(last), c.field, c.col),
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
                    let cols = self.layout(c.index).and_then(|l| l.fields().get(c.field - 1).map(|f| f.num_cols())).unwrap_or(1);
                    CursorPos { field: c.field - 1, col: cols - 1, ..c }
                } else {
                    c
                }
            }
        }
    }
    fn goto(&self, address: u64) -> Option<u128> {
        // the first segment at `address` (its label rows first), or the one covering it
        let i = self.segments.partition_point(|s| s.end() <= address && s.address != address);
        let s = self.segments.get(i)?;
        if s.address == address {
            return Some(s.first_row);
        }
        (s.address < address && address < s.end()).then(|| match s.kind {
            SegKind::Undefined => s.first_row + u128::from(address - s.address),
            _ => s.first_row,
        })
    }
    fn address_text(&self, index: u128) -> String {
        self.row_address(index).map(|a| self.address_string(a)).unwrap_or_default()
    }
    fn address_of(&self, index: u128) -> Option<u64> {
        self.row_address(index)
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
    use crate::listing::MemoryListing;

    fn metrics() -> FontMetrics {
        FontMetrics::monospace(7, 11, 3)
    }

    fn texts(rows: &[FieldRow]) -> Vec<Vec<String>> {
        rows.iter().map(|r| r.runs.iter().map(|x| x.text.clone()).collect()).collect()
    }

    fn insn(start: u64, len: u32, mnemonic: &str, operands: &str) -> InstructionSnapshot {
        InstructionSnapshot { start, len, mnemonic: mnemonic.into(), operands: operands.into(), references: vec![] }
    }

    fn label(address: u64, name: &str, primary: bool) -> LabelSnapshot {
        LabelSnapshot { address, name: name.into(), primary, id: 0 }
    }

    fn listing(instructions: Vec<InstructionSnapshot>, labels: Vec<LabelSnapshot>) -> CodeUnitListing {
        let mut l = CodeUnitListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x1000, vec![0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x90]),
                MemoryBlockSnapshot::uninitialized(0x2000, 2),
            ],
            instructions,
            labels,
        );
        l.set_metrics(metrics());
        l
    }

    #[test]
    fn with_no_code_units_it_reads_exactly_like_memory_listing() {
        let l = listing(vec![], vec![]);
        let mut m = MemoryListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x1000, vec![0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x90]),
                MemoryBlockSnapshot::uninitialized(0x2000, 2),
            ],
        );
        m.set_metrics(metrics());
        assert_eq!(l.index_count(), m.index_count());
        assert_eq!(texts(&l.rows(0, 1000)), texts(&m.rows(0, 1000)));
        assert_eq!(l.goto(0x2001), m.goto(0x2001));
    }

    #[test]
    fn an_instruction_is_one_row_spanning_its_bytes() {
        let l = listing(vec![insn(0x1000, 4, "ENDBR64", ""), insn(0x1004, 2, "XOR", "EBP,EBP")], vec![]);
        assert_eq!(l.index_count(), 5); // 2 instructions + 0x1006 + 2 uninitialized
        assert_eq!(
            texts(&l.rows(0, 1000))[..3],
            [
                vec!["00001000", "f3 0f 1e fa", "ENDBR64", ""].iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                vec!["00001004", "31 ed", "XOR", "EBP,EBP"].iter().map(|s| s.to_string()).collect(),
                vec!["00001006", "90", "??", "90h"].iter().map(|s| s.to_string()).collect(),
            ]
        );
    }

    #[test]
    fn labels_get_their_own_rows_above_the_unit_primary_last() {
        // LabelFieldSymbolLoader: non-primaries first, the primary last (just
        // above the code unit)
        let l = listing(
            vec![insn(0x1000, 4, "ENDBR64", "")],
            vec![label(0x1000, "entry", false), label(0x1000, "_start", true), label(0x1006, "tail", true)],
        );
        let rows = texts(&l.rows(0, 1000));
        assert_eq!(rows[0], vec!["entry"]);
        assert_eq!(rows[1], vec!["_start"]);
        assert_eq!(rows[2][2], "ENDBR64");
        assert_eq!(rows[3][0], "00001004"); // undefined bytes 0x1004..
        assert_eq!(rows[5], vec!["tail"]);
        assert_eq!(rows[6][0], "00001006");
        assert_eq!(l.address_text(0), "00001000");
        assert_eq!(l.address_text(5), "00001006");
    }

    #[test]
    fn offcut_labels_sit_above_the_labels_at_the_unit_start() {
        let l = listing(
            vec![insn(0x1000, 4, "MOV", "")],
            vec![label(0x1000, "fn", true), label(0x1002, "mid", true)],
        );
        let rows = texts(&l.rows(0, 1000));
        assert_eq!(rows[0], vec!["mid"]);
        assert_eq!(rows[1], vec!["fn"]);
        assert_eq!(rows[2][2], "MOV");
    }

    #[test]
    fn operand_columns_split_at_top_level_commas() {
        let text = "RAX,qword ptr [RBX + RCX*0x8 + 0x10]";
        assert_eq!(operand_index_at(text, 0), 0);
        assert_eq!(operand_index_at(text, 2), 0);
        assert_eq!(operand_index_at(text, 3), 0, "the comma ends operand 0");
        assert_eq!(operand_index_at(text, 4), 1);
        assert_eq!(operand_index_at(text, 99), 1, "past the end: the last operand");
        assert_eq!(operand_index_at("qword ptr [RIP + 0x2fe2]", 12), 0);
        assert_eq!(operand_index_at("dword ptr [RAX + RAX*0x1],EAX", 26), 1);
    }

    #[test]
    fn an_operands_reference_is_its_target() {
        let mut call = insn(0x1000, 4, "CALL", "RAX,qword ptr [0x2000]");
        call.references = vec![OperandRef { op_index: 1, to: 0x2000 }];
        let l = listing(vec![call], vec![label(0x1000, "f", true)]);
        let at = |field, col| l.reference_target(CursorPos { index: 1, field, col });
        assert_eq!(at(3, 6), Some(0x2000));
        assert_eq!(at(3, 0), None, "operand 0 (RAX) has no reference");
        assert_eq!(at(2, 0), None, "the mnemonic");
        assert_eq!(l.reference_target(CursorPos { index: 0, field: 0, col: 0 }), None, "the label row");
    }

    #[test]
    fn label_rows_know_their_symbol_and_headers_are_not_labels() {
        let mut f = label(0x1000, "f", true);
        f.id = 7;
        let mut mid = label(0x1002, "mid", true);
        mid.id = 9;
        let mut l = CodeUnitListing::with_headers(
            32,
            vec![MemoryBlockSnapshot::initialized(0x1000, vec![0x90; 8])],
            vec![insn(0x1000, 4, "NOP4", "")],
            vec![f, mid],
            vec![BlockHeader { start: 0x1000, name: ".text".into(), comment: String::new(), space: "ram".into() }],
        );
        l.set_metrics(FontMetrics::monospace(7, 11, 3));
        // 4 header rows, offcut "mid", "f", the instruction
        assert_eq!(l.label_at(0), None, "a header row");
        assert_eq!(l.label_at(4), Some((9, "mid".to_string())), "the offcut label keeps its own symbol");
        assert_eq!(l.label_at(5), Some((7, "f".to_string())));
        assert_eq!(l.label_at(6), None, "the instruction row");
    }

    #[test]
    fn a_long_operand_is_reachable_by_the_cursor() {
        let mut l = listing(vec![insn(0x1000, 6, "CALL", "qword ptr [DAT_00bc06b8]")], vec![]);
        l.set_metrics(FontMetrics::monospace(7, 11, 3));
        let x = l.cursor_x(CursorPos { index: 0, field: 3, col: 0 }).unwrap() + 22 * 7 + 1;
        assert_eq!(l.hit_test(0, x).map(|c| (c.field, c.col)), Some((3, 22)), "column 22 of the operands is visible");
    }

    #[test]
    fn goto_lands_on_the_first_row_at_an_address() {
        let l = listing(vec![insn(0x1000, 4, "ENDBR64", "")], vec![label(0x1000, "_start", true)]);
        assert_eq!(l.goto(0x1000), Some(0)); // the label row
        assert_eq!(l.goto(0x1002), Some(1)); // inside the instruction: its row
        assert_eq!(l.goto(0x1004), Some(2));
        assert_eq!(l.goto(0x2001), Some(l.index_count() - 1));
        assert_eq!(l.goto(0x1800), None); // gap
        assert_eq!(l.address_text(1), "00001000");
    }

    #[test]
    fn bad_snapshots_are_clamped_not_panics() {
        // overlaps the next, and runs past the block end; a label off memory
        let l = listing(vec![insn(0x1005, 9, "BIG", ""), insn(0x1006, 1, "NOP", "")], vec![label(0x9999, "nowhere", true)]);
        let rows = texts(&l.rows(0, 1000));
        let big = rows.iter().find(|r| r.get(2).map(String::as_str) == Some("BIG")).expect("BIG row");
        assert_eq!(big[1], "ed 90"); // clamped to the block
        assert!(rows.iter().all(|r| r.get(2).map(String::as_str) != Some("NOP")), "overlapped instruction skipped");
        assert!(rows.iter().all(|r| r[0] != "nowhere"));
    }

    #[test]
    fn a_block_start_gets_ghidras_comment_header_before_its_labels() {
        let mut l = CodeUnitListing::with_headers(
            32,
            vec![MemoryBlockSnapshot::initialized(0x1000, vec![0x90, 0x90]), MemoryBlockSnapshot::uninitialized(0x2000, 1)],
            vec![],
            vec![label(0x1000, "_start", true)],
            vec![
                BlockHeader { start: 0x1000, name: ".text".into(), comment: "SHT_PROGBITS [0x1000 - 0x1001]".into(), space: "ram".into() },
                BlockHeader { start: 0x2000, name: ".bss".into(), comment: String::new(), space: "ram".into() },
            ],
        );
        l.set_metrics(metrics());
        let rows = texts(&l.rows(0, 1000));
        let first: Vec<&str> = rows.iter().take(6).map(|r| r[0].as_str()).collect();
        assert_eq!(first, vec!["//", "// .text", "// SHT_PROGBITS [0x1000 - 0x1001]", "// ram:00001000-ram:00001001", "//", "_start"]);
        let bss = rows.iter().position(|r| r[0] == "// .bss").unwrap();
        assert_eq!(rows[bss + 1][0], "// ram:00002000-ram:00002000", "no comment line when empty");
        assert_eq!(l.goto(0x1000), Some(0), "goto lands on the header");
        assert_eq!(l.address_text(1), "00001000");
    }

    #[test]
    fn the_cursor_moves_across_label_rows() {
        let l = listing(vec![insn(0x1000, 4, "ENDBR64", "")], vec![label(0x1000, "_start", true)]);
        let at_label = l.hit_test(0, 200).unwrap();
        assert_eq!(at_label.field, 0);
        let down = l.move_cursor(CursorPos { index: 0, field: 3, col: 9 }, Move::Down, 1);
        assert_eq!(down.index, 1);
        let up = l.move_cursor(CursorPos { index: 1, field: 3, col: 0 }, Move::Up, 1);
        assert_eq!((up.index, up.field), (0, 0), "field clamped to the label row's only field");
        assert_eq!(l.field_text(CursorPos { index: 0, field: 0, col: 0 }).as_deref(), Some("_start"));
    }

    #[test]
    fn rows_stay_fast_over_a_million_rows() {
        let bytes = vec![0x90u8; 1 << 20];
        let instructions: Vec<_> = (0..100_000u64).map(|i| insn(0x1000_0000 + i * 8, 4, "NOP4", "")).collect();
        let labels: Vec<_> = (0..10_000u64).map(|i| label(0x1000_0000 + i * 64, &format!("L{i}"), true)).collect();
        let mut l = CodeUnitListing::new(32, vec![MemoryBlockSnapshot::initialized(0x1000_0000, bytes)], instructions, labels);
        l.set_metrics(metrics());
        let budget = if cfg!(debug_assertions) { 40 } else { 8 };
        for i in 0..100u128 {
            let top = (i * 7919) % l.index_count();
            let t = std::time::Instant::now();
            assert!(!l.rows(top, 1200).is_empty());
            let _ = l.goto(0x1000_0000 + (i as u64 * 9973) % (1 << 20));
            assert!(t.elapsed().as_millis() < budget, "{:?}", t.elapsed());
        }
    }
}
