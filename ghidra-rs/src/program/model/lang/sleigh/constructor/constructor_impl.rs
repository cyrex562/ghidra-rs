//! Port of `ghidra.app.plugin.processors.sleigh.Constructor`.

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::program::model::lang::sleigh::constructor::ContextChange;
use crate::program::model::lang::sleigh::symbol::{
    OperandSymbol, PrintListItem, SleighSymbol, SymbolTable,
};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::walker::{ParserWalker, SleighError};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_FIRST, ATTRIB_ID, ATTRIB_LENGTH, ATTRIB_LINE, ATTRIB_PARENT,
    ATTRIB_PIECE, ATTRIB_SOURCE, ELEM_COMMIT, ELEM_CONSTRUCTOR, ELEM_CONTEXT_OP, ELEM_OPER,
    ELEM_OPPRINT, ELEM_PRINT,
};

/// One constructor of a sleigh subtable: its operands, display pieces, context changes and
/// p-code templates.
///
/// Port of `ghidra.app.plugin.processors.sleigh.Constructor`. Operands are held as the ids of
/// their [`OperandSymbol`]s (Java holds the symbol objects), resolved through the language's
/// [`SymbolTable`] -- a constructor is decoded while the symbol table is still being filled in.
pub struct Constructor {
    /// Id of the subtable this constructor belongs to (Java's `parent.getId()`).
    pub parent_id: i32,
    /// Unique id of the constructor within its subtable (`id`).
    pub id: i32,
    /// Index of the first whitespace piece in `print_pieces` (`firstwhitespace`).
    pub first_whitespace: i32,
    /// Minimum length taken up by the constructor (`minimumlength`).
    pub minimum_length: i32,
    /// Line number of the constructor in the original specification (`lineno`).
    pub lineno: i32,
    /// Ids of the operand symbols, in operand order (`operands`).
    pub operands: Vec<i32>,
    /// Display pieces (`printpiece`): literal text, or `"\n"` + (`'A'` + operand index).
    pub print_pieces: Vec<String>,
    /// Context changes applied when the constructor matches (`context`).
    pub context: Vec<ContextChange>,
    /// The main p-code template section (`templ`).
    pub templ: Option<ConstructTpl>,
    /// Other named p-code template sections (`namedtempl`).
    pub named_templ: Vec<Option<ConstructTpl>>,
    /// Operand whose constructor supplies this one's display, or -1 (`flowthruindex`).
    pub flowthru_index: i32,
}

impl Default for Constructor {
    fn default() -> Self {
        Self::new()
    }
}

impl Constructor {
    /// Port of `Constructor()`.
    pub fn new() -> Self {
        Self {
            parent_id: 0,
            id: 0,
            first_whitespace: -1,
            minimum_length: 0,
            lineno: 0,
            operands: Vec::new(),
            print_pieces: Vec::new(),
            context: Vec::new(),
            templ: None,
            named_templ: Vec::new(),
            flowthru_index: -1,
        }
    }

    /// Port of `getFlowthruIndex()`.
    pub fn get_flowthru_index(&self) -> i32 {
        self.flowthru_index
    }

    /// Port of `getMinimumLength()`.
    pub fn get_minimum_length(&self) -> i32 {
        self.minimum_length
    }

    /// Port of `getId()`.
    pub fn get_id(&self) -> i32 {
        self.id
    }

    /// Port of `getLineno()`.
    pub fn get_lineno(&self) -> i32 {
        self.lineno
    }

    /// Port of `getNumOperands()`.
    pub fn get_num_operands(&self) -> usize {
        self.operands.len()
    }

    /// Port of `getOperand(int)`, resolved through `table`.
    pub fn get_operand<'t>(&self, table: &'t SymbolTable, i: usize) -> Option<&'t OperandSymbol> {
        table.find_operand(*self.operands.get(i)?)
    }

    /// Port of `getTempl()`.
    pub fn get_templ(&self) -> Option<&ConstructTpl> {
        self.templ.as_ref()
    }

    /// Port of `getNamedTempl(int)`.
    pub fn get_named_templ(&self, secnum: i32) -> Option<&ConstructTpl> {
        if secnum < 0 {
            return None;
        }
        self.named_templ.get(secnum as usize)?.as_ref()
    }

    /// Port of `getPrintPieces()`.
    pub fn get_print_pieces(&self) -> &[String] {
        &self.print_pieces
    }

    /// Port of `getContextChanges()`.
    pub fn get_context_changes(&self) -> &[ContextChange] {
        &self.context
    }

    /// The operand index an operand print piece (`"\n"` + letter) refers to.
    fn piece_operand(piece: &str) -> Option<usize> {
        let bytes = piece.as_bytes();
        if bytes.first() == Some(&b'\n') && bytes.len() >= 2 {
            Some((bytes[1] - b'A') as usize)
        } else {
            None
        }
    }

    fn operand_for_walker<'t>(
        &self,
        walker: &ParserWalker<'t>,
        index: usize,
    ) -> Result<&'t OperandSymbol, SleighError> {
        walker
            .symbol_table()
            .and_then(|t| self.get_operand(t, index))
            .ok_or_else(|| {
                SleighException::with_message(format!(
                    "operand {index} of constructor line {} is not an operand symbol",
                    self.lineno
                ))
                .into()
            })
    }

    fn print_pieces_range(
        &self,
        walker: &mut ParserWalker<'_>,
        range: std::ops::Range<usize>,
    ) -> Result<String, SleighError> {
        let mut res = String::new();
        let pieces = self.print_pieces.get(range).unwrap_or_default();
        for piece in pieces {
            if piece.is_empty() {
                continue;
            }
            match Self::piece_operand(piece) {
                Some(index) => res += &self.operand_for_walker(walker, index)?.print(walker)?,
                None => res += piece,
            }
        }
        Ok(res)
    }

    /// Port of `print(ParserWalker)`: the full display of this constructor at the walker's
    /// position.
    pub fn print(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        self.print_pieces_range(walker, 0..self.print_pieces.len())
    }

    /// Port of `printSeparator(int)`: the characters to the left of operand
    /// `separator_index`, ignoring the mnemonic, or `None` if there are none. (Java caches the
    /// answers; they are recomputed here.)
    pub fn print_separator(&self, separator_index: i32) -> Option<String> {
        if separator_index < 0 || separator_index as usize > self.operands.len() {
            return None;
        }
        let pieces = &self.print_pieces;
        // skip mnemonic and set cur_pos to first print-piece associated with operand 0
        let mut cur_pos = 0;
        while cur_pos < pieces.len() && (pieces[cur_pos].is_empty() || !pieces[cur_pos].starts_with(' '))
        {
            cur_pos += 1;
        }
        cur_pos += 1;

        let mut op_index = 0;
        let mut buf = String::new();
        let mut i = cur_pos;
        while i < pieces.len() && op_index <= separator_index {
            let piece = &pieces[i];
            if !piece.is_empty() {
                if piece.starts_with('\n') {
                    if op_index == separator_index {
                        break;
                    }
                    op_index += 1;
                } else if op_index == separator_index {
                    buf.push_str(piece);
                }
            }
            i += 1;
        }
        let separator = collapse_comma_whitespace(&buf);
        if separator.is_empty() {
            None
        } else {
            Some(separator)
        }
    }

    /// Port of `printList(ParserWalker, ArrayList<Object>)`: the characters and handles making
    /// up this constructor's display. A single handle exported through a constant operand is
    /// "fixed" into an address, as in Java (which adjusts the parser context's own handle; the
    /// adjusted handle is written back here).
    pub fn print_list(
        &self,
        walker: &mut ParserWalker<'_>,
        list: &mut Vec<PrintListItem>,
    ) -> Result<(), SleighError> {
        let mut op_symbol_cnt = 0;
        let mut last_handle: Option<usize> = None; // position in `list`
        let mut last_handle_index = -1;

        for piece in &self.print_pieces {
            let prev_size = list.len();
            if piece.is_empty() {
                continue;
            }
            match Self::piece_operand(piece) {
                Some(index) => {
                    self.operand_for_walker(walker, index)?
                        .print_list(walker, list)?;
                    if prev_size != list.len() {
                        op_symbol_cnt += 1;
                        if op_symbol_cnt == 1 {
                            // Identify sole handle which can be fixed
                            for (n, item) in list.iter().enumerate().skip(prev_size) {
                                if !matches!(item, PrintListItem::Handle { .. }) {
                                    continue;
                                }
                                if last_handle.is_some() {
                                    // can't fix multiple handles
                                    last_handle = None;
                                    break;
                                }
                                last_handle = Some(n);
                                last_handle_index = index as i32;
                            }
                        }
                    }
                }
                None => list.extend(piece.chars().map(PrintListItem::Char)),
            }
        }

        // Fix constant operand exported as address
        if op_symbol_cnt == 1 {
            if let Some(pos) = last_handle {
                if let (Some(res), PrintListItem::Handle { key, handle }) =
                    (self.templ.as_ref().and_then(|t| t.result.as_ref()), &mut list[pos])
                {
                    if handle.fixable {
                        // Pop up handle to containing operand
                        res.fix_print_piece(handle, walker, last_handle_index)?;
                        walker.get_parser_context().set_fixed_handle(*key, handle.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether operand `index` is defined by a subtable.
    fn operand_is_subtable(&self, walker: &ParserWalker<'_>, index: usize) -> bool {
        let Some(table) = walker.symbol_table() else {
            return false;
        };
        matches!(
            self.get_operand(table, index)
                .and_then(|op| op.get_defining_symbol(table)),
            Some(SleighSymbol::Subtable(_))
        )
    }

    /// Port of `printMnemonic(ParserWalker)`.
    pub fn print_mnemonic(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        if self.flowthru_index != -1 && self.operand_is_subtable(walker, self.flowthru_index as usize)
        {
            walker.push_operand(self.flowthru_index as usize);
            let res = match walker.get_constructor() {
                Some(ct) => ct.print_mnemonic(walker),
                None => Err(SleighException::with_message("unresolved subtable operand").into()),
            };
            walker.pop_operand();
            return res;
        }
        let endind = if self.first_whitespace == -1 {
            self.print_pieces.len()
        } else {
            self.first_whitespace as usize
        };
        self.print_pieces_range(walker, 0..endind)
    }

    /// Port of `printBody(ParserWalker)`.
    pub fn print_body(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        if self.flowthru_index != -1 && self.operand_is_subtable(walker, self.flowthru_index as usize)
        {
            walker.push_operand(self.flowthru_index as usize);
            let res = match walker.get_constructor() {
                Some(ct) => ct.print_body(walker),
                None => Err(SleighException::with_message("unresolved subtable operand").into()),
            };
            walker.pop_operand();
            return res;
        }
        if self.first_whitespace == -1 {
            return Ok(String::new()); // Nothing to print
        }
        self.print_pieces_range(walker, (self.first_whitespace as usize + 1)..self.print_pieces.len())
    }

    /// Apply any operations on context for this constructor. Port of
    /// `applyContext(ParserWalker, SleighDebugLogger)`.
    ///
    /// # Errors
    /// A [`SleighError`] if a context expression cannot be evaluated.
    pub fn apply_context(&self, walker: &ParserWalker<'_>) -> Result<(), SleighError> {
        for change in &self.context {
            change.apply(walker)?;
        }
        Ok(())
    }

    /// The indices of the operands in the order they are printed (after the first white
    /// space). Port of `getOpsPrintOrder()`.
    pub fn get_ops_print_order(&self) -> Vec<i32> {
        if self.first_whitespace == -1 {
            return Vec::new();
        }
        self.print_pieces
            .get((self.first_whitespace as usize + 1)..)
            .unwrap_or_default()
            .iter()
            .filter_map(|p| Self::piece_operand(p))
            .map(|i| i as i32)
            .collect()
    }

    /// Port of `hashCode()`.
    pub fn java_hash_code(&self) -> i32 {
        self.parent_id.wrapping_mul(31).wrapping_add(self.id)
    }

    /// Port of `toString()`.
    pub fn to_display_string(&self) -> String {
        format!("line{}(id{}.{})", self.lineno, self.parent_id, self.id)
    }

    /// Port of `decode(Decoder, SleighLanguage)`. Operand references are recorded as symbol
    /// ids; the source-file name (`sourceFile`) is not kept, since the `.sla` source-file index
    /// is not decoded.
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_CONSTRUCTOR)?;

        self.parent_id = decoder.read_unsigned_integer_with_id(ATTRIB_PARENT)? as i32;
        self.first_whitespace = decoder.read_signed_integer_with_id(ATTRIB_FIRST)? as i32;
        self.minimum_length = decoder.read_signed_integer_with_id(ATTRIB_LENGTH)? as i32;
        let _src_line = decoder.read_signed_integer_with_id(ATTRIB_SOURCE)? as i32;
        self.lineno = decoder.read_signed_integer_with_id(ATTRIB_LINE)? as i32;

        self.operands.clear();
        self.print_pieces.clear();
        self.context.clear();
        self.templ = None;
        self.named_templ.clear();

        while decoder.peek_element()? != 0 {
            let subel = decoder.peek_element()?;
            if subel == ELEM_OPER.id {
                let subel_open = decoder.open_element()?;
                let my_id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
                self.operands.push(my_id);
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_PRINT.id {
                let subel_open = decoder.open_element()?;
                self.print_pieces
                    .push(decoder.read_string_with_id(ATTRIB_PIECE)?);
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_OPPRINT.id {
                let subel_open = decoder.open_element()?;
                let my_id = decoder.read_signed_integer_with_id(ATTRIB_ID)? as i32;
                let mut operstring = String::from("\n");
                operstring.push((b'A' + my_id as u8) as char);
                self.print_pieces.push(operstring);
                decoder.close_element_skipping(subel_open)?;
            } else if subel == ELEM_CONTEXT_OP.id {
                let mut c_op = super::ContextOp::new();
                c_op.decode(decoder, sleigh)?;
                self.context.push(ContextChange::Op(c_op));
            } else if subel == ELEM_COMMIT.id {
                let mut c_commit = super::ContextCommit::new();
                c_commit.decode(decoder, sleigh)?;
                self.context.push(ContextChange::Commit(c_commit));
            } else {
                let mut curtempl = ConstructTpl::new();
                let section_id = curtempl.decode(decoder)?;
                if section_id < 0 {
                    if self.templ.is_some() {
                        return Err(DecoderError::Generic(
                            "Duplicate main template section".to_string(),
                        ));
                    }
                    self.templ = Some(curtempl);
                } else {
                    let sid = section_id as usize;
                    if self.named_templ.len() <= sid {
                        self.named_templ.resize(sid + 1, None);
                    }
                    if self.named_templ[sid].is_some() {
                        return Err(DecoderError::Generic(
                            "Duplicate named template section".to_string(),
                        ));
                    }
                    self.named_templ[sid] = Some(curtempl);
                }
            }
        }

        if self.print_pieces.len() == 1
            && self.print_pieces[0].len() >= 2
            && self.print_pieces[0].starts_with('\n')
        {
            self.flowthru_index = (self.print_pieces[0].as_bytes()[1] - b'A') as i32;
        } else {
            self.flowthru_index = -1;
        }

        decoder.close_element(el)?;
        Ok(())
    }
}

/// Java's `separator.replaceAll(",\\s+", ",")`: drops the whitespace following each comma.
fn collapse_comma_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == ',' {
            while chars.peek().is_some_and(|n| n.is_ascii_whitespace() || *n == '\x0b') {
                chars.next();
            }
        }
    }
    out
}

impl std::fmt::Debug for Constructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_pieces(first_whitespace: i32, pieces: &[&str], operands: usize) -> Constructor {
        let mut ct = Constructor::new();
        ct.first_whitespace = first_whitespace;
        ct.print_pieces = pieces.iter().map(|s| s.to_string()).collect();
        ct.operands = (0..operands as i32).collect();
        ct
    }

    #[test]
    fn ops_print_order_follows_the_display_after_the_mnemonic() {
        // "mov" " " B "," A  -> operand 1 printed first, then operand 0
        let ct = with_pieces(1, &["mov", " ", "\nB", ",", "\nA"], 2);
        assert_eq!(ct.get_ops_print_order(), vec![1, 0]);
        assert!(with_pieces(-1, &["nop"], 0).get_ops_print_order().is_empty());
    }

    #[test]
    fn print_separator_collects_text_between_operands() {
        let ct = with_pieces(1, &["mov", " ", "\nA", ", ", "\nB", "]"], 2);
        assert_eq!(ct.print_separator(0), None);
        // ",\s+" collapses to ","
        assert_eq!(ct.print_separator(1).as_deref(), Some(","));
        assert_eq!(ct.print_separator(2).as_deref(), Some("]"));
        assert_eq!(ct.print_separator(3), None);
        assert_eq!(ct.print_separator(-1), None);
    }

    #[test]
    fn collapse_comma_whitespace_matches_java_regex() {
        assert_eq!(collapse_comma_whitespace(",  x, y,z"), ",x,y,z");
        assert_eq!(collapse_comma_whitespace("a ,b"), "a ,b");
    }

    #[test]
    fn named_templates_are_looked_up_by_section() {
        let mut ct = Constructor::new();
        ct.named_templ = vec![None, Some(ConstructTpl::new())];
        assert!(ct.get_named_templ(0).is_none());
        assert!(ct.get_named_templ(1).is_some());
        assert!(ct.get_named_templ(2).is_none());
        assert!(ct.get_named_templ(-1).is_none());
    }

    #[test]
    fn hash_and_display_follow_java() {
        let mut ct = Constructor::new();
        ct.parent_id = 3;
        ct.id = 2;
        ct.lineno = 17;
        assert_eq!(ct.java_hash_code(), 95);
        assert_eq!(ct.to_display_string(), "line17(id3.2)");
    }
}
