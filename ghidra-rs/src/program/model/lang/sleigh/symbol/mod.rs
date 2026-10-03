//! Port of the `ghidra.app.plugin.processors.sleigh.symbol` package: the sleigh symbol table
//! decoded from a `.sla` file and the run-time behaviour of its symbols.
//!
//! # Shape
//! Java's hierarchy (`Symbol` <- `TripleSymbol` <- `FamilySymbol`/`SpecificSymbol`/... <- the
//! concrete kinds) is a closed set decoded from one file format, so it is the enum
//! [`SleighSymbol`] with one variant per concrete Java class; the abstract `TripleSymbol` API
//! (`resolve`, `getFixedHandle`, `print`, `printList`, `getPatternExpression`) is realized as
//! methods on the enum. Symbols refer to one another by id (an operand's defining symbol, a
//! varnode list's entries, a context symbol's varnode, a constructor's operands), resolved
//! through the [`SymbolTable`]; this is also what lets a symbol's body refer to a symbol whose
//! body has not been decoded yet, which Java handles by pre-creating every symbol object.

use super::constructor::Constructor;
use super::decision::DecisionNode;
use super::expression::PatternExpression;
use super::walker::{ParserWalker, SleighError};
use super::{FixedHandle, SleighLanguage};
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::ids::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Common header fields shared by every symbol in the sleigh symbol table.
///
/// Port of the abstract base class `ghidra.app.plugin.processors.sleigh.symbol.Symbol`. Java's
/// `Symbol` is `abstract`, carrying the `name`/`id`/`scopeid` fields and the concrete
/// `decodeHeader(Decoder)` method, and leaving `decode(Decoder, SleighLanguage)` abstract for
/// each of its seven direct subclasses (`UseropSymbol`, `VarnodeSymbol`, `ValueSymbol`,
/// `SubtableSymbol`, `OperandSymbol`, `TripleSymbol`, and others) to implement.
///
/// Rather than a trait-based hierarchy, this crate's sleigh symbol family already used
/// composition + enum dispatch before this class was ported: each concrete symbol struct
/// (e.g. [`UseropSymbol`], [`VarnodeSymbol`]) embeds a `header: SymbolHeader` field instead of
/// inheriting from a `Symbol` base, and the abstract `decode` method is realized as the
/// [`SleighSymbol::decode`] dispatch over the [`SleighSymbol`] enum instead of dynamic dispatch.
/// `SymbolHeader::decode` is the direct port of `Symbol.decodeHeader(Decoder)`.
#[derive(Clone, Debug)]
pub struct SymbolHeader {
    pub name: String,
    pub id: i32,
    pub scope_id: i32,
}

impl SymbolHeader {
    /// Decodes the header shared by every symbol kind: name, unique id, and containing scope id.
    ///
    /// Mirrors `Symbol.decodeHeader(Decoder)`.
    pub fn decode(decoder: &dyn Decoder) -> Result<(Self, i32), DecoderError> {
        let el = decoder.open_element()?;
        let name = decoder.read_string_with_id(ATTRIB_NAME)?;
        let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
        let scope_id = decoder.read_unsigned_integer_with_id(ATTRIB_SCOPE)? as i32;
        decoder.close_element(el)?;
        Ok((Self { name, id, scope_id }, el))
    }

    /// Returns the symbol's name.
    ///
    /// Mirrors `Symbol.getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol's unique id (unique across all symbols).
    ///
    /// Mirrors `Symbol.getId()`.
    pub fn get_id(&self) -> i32 {
        self.id
    }

    /// Returns the id of the scope this symbol is in.
    ///
    /// Mirrors `Symbol.getScopeId()`.
    pub fn get_scope_id(&self) -> i32 {
        self.scope_id
    }
}

/// An item of an operand's representation list: Java's `printList` fills an
/// `ArrayList<Object>` with `Character`s and `FixedHandle`s.
#[derive(Clone, Debug, PartialEq)]
pub enum PrintListItem {
    /// A literal character of the operand's text.
    Char(char),
    /// A handle to be rendered as a register, scalar or address. `key` is the tree node the
    /// handle belongs to, so an in-place adjustment (Java mutates the handle object it put in
    /// the list, which is the parser context's own handle) can be written back.
    Handle {
        /// Handle-map key of the node the handle belongs to.
        key: usize,
        /// The handle.
        handle: FixedHandle,
    },
}

/// Formats a value the way the Java symbols print one: `0x` + hex, or `-0x` + hex of the
/// negation for a negative value.
pub fn format_hex_value(val: i64) -> String {
    if val >= 0 {
        format!("0x{val:x}")
    } else {
        format!("-0x{:x}", val.wrapping_neg() as u64)
    }
}

/// A user-defined pcode operation (`PcodeOp`).
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol`. This is implemented as a
/// name and a unique id which is passed as the first parameter to a `PcodeOp` with the opcode
/// `CALLOTHER`. Java's `UseropSymbol extends Symbol`; here the base fields live in the
/// [`SymbolHeader`] `header` field per this module's composition convention.
///
/// Java's `decode` has a commented-out `decoder.openElement(ELEM_USEROP)` -- the element is
/// actually opened by the caller ([`SymbolTable::decode`]'s dispatch loop) before `decode` is
/// invoked, so this only reads the `index` attribute and closes the element.
pub struct UseropSymbol {
    pub header: SymbolHeader,
    pub index: i32,
}

impl UseropSymbol {
    /// Returns the unique id for this userop.
    ///
    /// Mirrors `UseropSymbol.getIndex()`.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Mirrors `UseropSymbol.decode(Decoder, SleighLanguage)`.
    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        self.index = decoder.read_signed_integer_with_id(ATTRIB_INDEX)? as i32;
        decoder.close_element(ELEM_USEROP.id)?;
        Ok(())
    }
}

/// A symbol naming a fixed varnode (a register, a memory location, ...).
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.VarnodeSymbol`; `space`/`offset`/`size`
/// are Java's `fix` (`VarnodeData`).
pub struct VarnodeSymbol {
    pub header: SymbolHeader,
    pub space: Option<Arc<AddressSpace>>,
    pub offset: u64,
    pub size: i32,
}

impl VarnodeSymbol {
    /// Mirrors `VarnodeSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        self.space = Some(decoder.read_space_with_id(ATTRIB_SPACE)?);
        self.offset = decoder.read_unsigned_integer_with_id(ATTRIB_OFF)?;
        self.size = decoder.read_signed_integer_with_id(ATTRIB_SIZE)? as i32;
        decoder.close_element(ELEM_VARNODE_SYM.id)?;
        Ok(())
    }

    /// Port of `VarnodeSymbol.getFixedHandle(FixedHandle, ParserWalker)`.
    fn fill_handle(&self, hand: &mut FixedHandle) {
        hand.space = self.space.clone();
        hand.offset_space = None; // Not a dynamic variable
        hand.offset_offset = self.offset as i64;
        hand.size = self.size;
    }
}

/// A symbol whose value is a pattern value (a token or context field, ...).
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.ValueSymbol`.
pub struct ValueSymbol {
    pub header: SymbolHeader,
    pub patval: Option<PatternExpression>,
}

impl ValueSymbol {
    /// Mirrors `ValueSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        decoder.close_element_skipping(ELEM_VALUE_SYM.id)?;
        Ok(())
    }
}

/// A value symbol whose pattern value indexes a table of attached values.
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.ValueMapSymbol`.
pub struct ValueMapSymbol {
    pub header: SymbolHeader,
    pub patval: Option<PatternExpression>,
    /// Map from natural encoding to attached values (`valuetable`); `0xBADBEEF` marks a hole.
    pub valuetable: Vec<i64>,
    /// True if every value the pattern can produce has an entry (`tableisfilled`).
    pub tableisfilled: bool,
}

/// The value `ValueMapSymbol` uses to mark a hole in its table.
const BAD_VALUE: i64 = 0xBADBEEF;

impl ValueMapSymbol {
    /// Port of `ValueMapSymbol.getMap()`.
    pub fn get_map(&self) -> &[i64] {
        &self.valuetable
    }

    /// Mirrors `ValueMapSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        self.valuetable.clear();
        while decoder.peek_element()? == ELEM_VALUETAB.id {
            decoder.open_element()?;
            self.valuetable
                .push(decoder.read_signed_integer_with_id(ATTRIB_VAL)?);
            decoder.close_element(ELEM_VALUETAB.id)?;
        }
        self.tableisfilled = table_is_filled(&self.patval, self.valuetable.len())
            && !self.valuetable.contains(&BAD_VALUE);
        decoder.close_element(ELEM_VALUEMAP_SYM.id)?;
        Ok(())
    }
}

/// A value symbol whose pattern value indexes a table of names.
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.NameSymbol`.
pub struct NameSymbol {
    pub header: SymbolHeader,
    pub patval: Option<PatternExpression>,
    /// The table of strings (`nametable`); `None` marks a hole.
    pub nametable: Vec<Option<String>>,
    /// True if every value the pattern can produce has an entry (`tableisfilled`).
    pub tableisfilled: bool,
}

impl NameSymbol {
    /// Port of `NameSymbol.getNameTable()`.
    pub fn get_name_table(&self) -> &[Option<String>] {
        &self.nametable
    }

    /// Mirrors `NameSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        self.nametable.clear();
        while decoder.peek_element()? == ELEM_NAMETAB.id {
            decoder.open_element()?;
            let attrib = decoder.get_next_attribute_id()?;
            if attrib == ATTRIB_NAME.id {
                self.nametable.push(Some(decoder.read_string()?));
            } else {
                self.nametable.push(None);
            }
            decoder.close_element(ELEM_NAMETAB.id)?;
        }
        self.tableisfilled = table_is_filled(&self.patval, self.nametable.len())
            && self.nametable.iter().all(Option::is_some);
        decoder.close_element(ELEM_NAME_SYM.id)?;
        Ok(())
    }
}

/// The range half of the `checkTableFill()` helpers shared by `ValueMapSymbol`, `NameSymbol` and
/// `VarnodeListSymbol`: the pattern value's range must lie within the table.
fn table_is_filled(patval: &Option<PatternExpression>, len: usize) -> bool {
    let Some(p) = patval else {
        return false;
    };
    match (p.min_value(), p.max_value()) {
        (Ok(min), Ok(max)) => min >= 0 && max < len as i64,
        _ => false,
    }
}

/// A context-variable symbol: a named bit-field of a context register.
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.ContextSymbol` (Java `ContextSymbol
/// extends ValueSymbol`, whose run-time behaviour it inherits). Per this module's id-based
/// convention the Java `vn` reference to the backing [`VarnodeSymbol`] is held as `varnode_id`
/// and resolved through the [`SymbolTable`].
pub struct ContextSymbol {
    pub header: SymbolHeader,
    /// The context field (`PatternValue`) this symbol's value is read from.
    pub patval: Option<PatternExpression>,
    /// Id of the [`VarnodeSymbol`] naming the context register this field lives in.
    pub varnode_id: i32,
    /// Least significant bit of the field within the context varnode (`low`).
    pub low: i32,
    /// Most significant bit of the field within the context varnode (`high`).
    pub high: i32,
    /// Whether the value of this context variable follows flow (`flow`).
    pub flow: bool,
}

impl ContextSymbol {
    /// Mirrors `ContextSymbol.followsFlow()`.
    pub fn follows_flow(&self) -> bool {
        self.flow
    }

    /// Mirrors `ContextSymbol.getVarnode()`, resolved through `table`.
    pub fn get_varnode<'t>(&self, table: &'t SymbolTable) -> Option<&'t VarnodeSymbol> {
        match table.find_symbol(self.varnode_id)? {
            SleighSymbol::Varnode(v) => Some(v),
            _ => None,
        }
    }

    /// Mirrors `ContextSymbol.getLow()`: the least significant bit of the field within the
    /// context varnode.
    pub fn get_low(&self) -> i32 {
        self.low
    }

    /// Mirrors `ContextSymbol.getHigh()`: the most significant bit of the field within the
    /// context varnode.
    pub fn get_high(&self) -> i32 {
        self.high
    }

    /// Mirrors `ContextSymbol.getInternalLow()`: the start bit of the field within the packed
    /// context words (`((ContextField) patval).getStartBit()`).
    pub fn get_internal_low(&self) -> Option<i32> {
        match &self.patval {
            Some(PatternExpression::ContextField(f)) => Some(f.bitstart),
            _ => None,
        }
    }

    /// Mirrors `ContextSymbol.getInternalHigh()`: the end bit of the field within the packed
    /// context words.
    pub fn get_internal_high(&self) -> Option<i32> {
        match &self.patval {
            Some(PatternExpression::ContextField(f)) => Some(f.bitend),
            _ => None,
        }
    }

    /// Mirrors `ContextSymbol.decode(Decoder, SleighLanguage)`. As with the other symbol kinds,
    /// the `ELEM_CONTEXT_SYM` element was already opened (and `ATTRIB_ID` read) by
    /// [`SymbolTable::decode`]'s dispatch loop.
    ///
    /// # Errors
    /// Returns an error if the `low`/`high` attributes are missing ("Missing high/low
    /// attributes", as Java's `DecoderException`), or on any underlying decode failure.
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.flow = false;
        self.varnode_id = decoder.read_unsigned_integer_with_id(ATTRIB_VARNODE)? as i32;
        let mut low_missing = true;
        let mut high_missing = true;
        loop {
            let attrib = decoder.get_next_attribute_id()?;
            if attrib == 0 {
                break;
            }
            if attrib == ATTRIB_LOW.id {
                self.low = decoder.read_signed_integer()? as i32;
                low_missing = false;
            } else if attrib == ATTRIB_HIGH.id {
                self.high = decoder.read_signed_integer()? as i32;
                high_missing = false;
            } else if attrib == ATTRIB_FLOW.id {
                self.flow = decoder.read_bool()?;
            }
        }
        if low_missing || high_missing {
            return Err(DecoderError::Generic("Missing high/low attributes".to_string()));
        }
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        decoder.close_element(ELEM_CONTEXT_SYM.id)?;
        Ok(())
    }
}

/// A symbol whose value selects one of a list of varnodes (`attach variables`).
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.VarnodeListSymbol`. The Java
/// `VarnodeSymbol[] varnode_table` is held as ids (`None` for Java's `null` holes) per this
/// module's convention.
pub struct VarnodeListSymbol {
    pub header: SymbolHeader,
    /// The pattern value selecting an entry of the table.
    pub patval: Option<PatternExpression>,
    /// Ids of the [`VarnodeSymbol`]s in the table, `None` where the `.sla` has a hole.
    pub varnode_ids: Vec<Option<i32>>,
    /// True if every value the pattern can produce has an entry (`tableisfilled`).
    pub tableisfilled: bool,
}

impl VarnodeListSymbol {
    /// Mirrors `VarnodeListSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        self.varnode_ids.clear();
        while decoder.peek_element()? != 0 {
            let subel = decoder.open_element()?;
            if subel == ELEM_VAR.id {
                self.varnode_ids
                    .push(Some(decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32));
            } else {
                self.varnode_ids.push(None);
            }
            decoder.close_element(subel)?;
        }
        self.tableisfilled = table_is_filled(&self.patval, self.varnode_ids.len())
            && self.varnode_ids.iter().all(Option::is_some);
        decoder.close_element(ELEM_VARLIST_SYM.id)?;
        Ok(())
    }
}

/// A table of constructors, selected between by a decision tree.
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol`.
pub struct SubtableSymbol {
    pub header: SymbolHeader,
    pub constructors: Vec<Arc<Constructor>>,
    pub decision_tree: Option<DecisionNode>,
}

impl SubtableSymbol {
    /// Port of `SubtableSymbol.getDecisionNode()`.
    pub fn get_decision_node(&self) -> Option<&DecisionNode> {
        self.decision_tree.as_ref()
    }

    /// Port of `SubtableSymbol.getNumConstructors()`.
    pub fn get_num_constructors(&self) -> usize {
        self.constructors.len()
    }

    /// Port of `SubtableSymbol.getConstructor(int)`.
    pub fn get_constructor(&self, i: usize) -> Option<&Arc<Constructor>> {
        self.constructors.get(i)
    }

    /// Port of `SubtableSymbol.resolve(ParserWalker, SleighDebugLogger)`: the constructor the
    /// decision tree selects for the walker's position.
    ///
    /// # Errors
    /// [`SleighError::UnknownInstruction`] if no constructor matches.
    pub fn resolve(&self, walker: &ParserWalker<'_>) -> Result<Arc<Constructor>, SleighError> {
        let tree = self.decision_tree.as_ref().ok_or_else(|| {
            UnknownInstructionException::with_message(format!(
                "Subtable {} has no decision tree",
                self.header.name
            ))
        })?;
        tree.resolve(walker, self)
    }

    /// Mirrors `SubtableSymbol.decode(Decoder, SleighLanguage)` (element already open).
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let num_ct = decoder.read_signed_integer_with_id(ATTRIB_NUMCT)? as usize;
        self.constructors.reserve(num_ct);
        for i in 0..num_ct {
            let mut ct = Constructor::new();
            ct.id = i as i32;
            ct.decode(decoder, sleigh)?;
            self.constructors.push(Arc::new(ct));
        }
        if decoder.peek_element()? != 0 {
            let mut tree = DecisionNode::new();
            tree.decode(decoder, sleigh, self)?;
            self.decision_tree = Some(tree);
        }
        decoder.close_element(ELEM_SUBTABLE_SYM.id)?;
        Ok(())
    }
}

/// An operand of a constructor: either defined by another symbol (`triple_id`) or by an
/// expression (`defexp`).
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol`.
#[derive(Clone, Debug)]
pub struct OperandSymbol {
    pub header: SymbolHeader,
    /// Relative offset (`reloffset`), in bytes, from the end of operand `offset_base`.
    pub rel_offset: i32,
    /// Base operand to which the offset is relative (`offsetbase`), negative for the start of
    /// the constructor.
    pub offset_base: i32,
    /// Minimum size of the operand within tokens (`minimumlength`).
    pub minimum_length: i32,
    /// Index of this operand in its constructor (`hand`).
    pub hand: i32,
    /// Id of the defining symbol (`triple`), if any.
    pub triple_id: Option<i32>,
    /// Whether the operand is used as an address (`codeaddress`).
    pub code_address: bool,
    /// The operand's own value expression (`localexp`, an `OperandValue`).
    pub localexp: Option<PatternExpression>,
    /// The defining expression (`defexp`), when there is no defining symbol.
    pub defexp: Option<PatternExpression>,
}

impl OperandSymbol {
    /// Port of `OperandSymbol.getRelativeOffset()`.
    pub fn get_relative_offset(&self) -> i32 {
        self.rel_offset
    }

    /// Port of `OperandSymbol.getOffsetBase()`.
    pub fn get_offset_base(&self) -> i32 {
        self.offset_base
    }

    /// Port of `OperandSymbol.getMinimumLength()`.
    pub fn get_minimum_length(&self) -> i32 {
        self.minimum_length
    }

    /// Port of `OperandSymbol.getDefiningExpression()`.
    pub fn get_defining_expression(&self) -> Option<&PatternExpression> {
        self.defexp.as_ref()
    }

    /// Port of `OperandSymbol.getIndex()`.
    pub fn get_index(&self) -> i32 {
        self.hand
    }

    /// Port of `OperandSymbol.isCodeAddress()`.
    pub fn is_code_address(&self) -> bool {
        self.code_address
    }

    /// Port of `OperandSymbol.toString()`: `"name : id"`.
    pub fn to_display_string(&self) -> String {
        format!("{} : {}", self.header.name, self.header.id)
    }

    /// Port of `OperandSymbol.getDefiningSymbol()`, resolved through `table`.
    pub fn get_defining_symbol<'t>(&self, table: &'t SymbolTable) -> Option<&'t SleighSymbol> {
        table.find_symbol(self.triple_id?)
    }

    /// Mirrors `OperandSymbol.decode(Decoder, SleighLanguage)` (element already open): the
    /// attributes, then the operand's own `OperandValue`, then an optional defining expression.
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.defexp = None;
        self.triple_id = None;
        self.code_address = false;
        loop {
            let attr = decoder.get_next_attribute_id()?;
            if attr == 0 {
                break;
            }
            if attr == ATTRIB_INDEX.id {
                self.hand = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_OFF.id {
                self.rel_offset = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_BASE.id {
                self.offset_base = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_MINLEN.id {
                self.minimum_length = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_SUBSYM.id {
                self.triple_id = Some(decoder.read_unsigned_integer()? as i32);
            } else if attr == ATTRIB_CODE.id {
                self.code_address = decoder.read_bool()?;
            }
        }
        self.localexp = Some(PatternExpression::decode(decoder, lang)?);
        if decoder.peek_element()? != 0 {
            self.defexp = Some(PatternExpression::decode(decoder, lang)?);
        }
        decoder.close_element(ELEM_OPERAND_SYM.id)?;
        Ok(())
    }

    /// Port of `OperandSymbol.print(ParserWalker)`.
    pub fn print(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        walker.push_operand(self.hand as usize);
        let res = self.print_at_operand(walker);
        walker.pop_operand();
        res
    }

    fn print_at_operand(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        let table = walker.symbol_table();
        if let Some(triple) = table.and_then(|t| self.get_defining_symbol(t)) {
            if let SleighSymbol::Subtable(_) = triple {
                let ct = walker
                    .get_constructor()
                    .ok_or_else(|| SleighException::with_message("unresolved subtable operand"))?;
                return ct.print(walker);
            }
            return triple.print(walker);
        }
        // Must be expression resulting in a constant
        let defexp = self
            .defexp
            .as_ref()
            .ok_or_else(|| SleighException::with_message("operand has no definition"))?;
        let val = defexp.get_value(walker)?;
        Ok(format_hex_value(val))
    }

    /// Port of `OperandSymbol.printList(ParserWalker, ArrayList<Object>)`.
    pub fn print_list(
        &self,
        walker: &mut ParserWalker<'_>,
        list: &mut Vec<PrintListItem>,
    ) -> Result<(), SleighError> {
        walker.push_operand(self.hand as usize);
        let res = self.print_list_at_operand(walker, list);
        walker.pop_operand();
        res
    }

    fn print_list_at_operand(
        &self,
        walker: &mut ParserWalker<'_>,
        list: &mut Vec<PrintListItem>,
    ) -> Result<(), SleighError> {
        let table = walker.symbol_table();
        if let Some(triple) = table.and_then(|t| self.get_defining_symbol(t)) {
            if let SleighSymbol::Subtable(_) = triple {
                let ct = walker
                    .get_constructor()
                    .ok_or_else(|| SleighException::with_message("unresolved subtable operand"))?;
                return ct.print_list(walker, list);
            }
            return triple.print_list(walker, list);
        }
        let mut handle = walker.get_parent_handle();
        if handle.offset_size == 0 {
            handle.offset_size = walker.get_current_length();
            walker.set_parent_handle(handle.clone());
        }
        list.push(PrintListItem::Handle {
            key: walker.parent_handle_key(),
            handle,
        });
        Ok(())
    }
}

/// The symbol `inst_start`: the address of the current instruction. Port of
/// `ghidra.app.plugin.processors.sleigh.symbol.StartSymbol`; its pattern expression is a
/// `StartInstructionValue` and its behaviour is on [`SleighSymbol`].
#[derive(Clone, Debug)]
pub struct StartSymbol {
    pub header: SymbolHeader,
}

/// The symbol `inst_next`: the address of the next instruction. Port of
/// `ghidra.app.plugin.processors.sleigh.symbol.EndSymbol`.
#[derive(Clone, Debug)]
pub struct EndSymbol {
    pub header: SymbolHeader,
}

/// The symbol `inst_next2`: the address of the instruction after the next. Port of
/// `ghidra.app.plugin.processors.sleigh.symbol.Next2Symbol`.
#[derive(Clone, Debug)]
pub struct Next2Symbol {
    pub header: SymbolHeader,
}

/// The empty operand (`epsilon`), a constant zero. Port of
/// `ghidra.app.plugin.processors.sleigh.symbol.EpsilonSymbol`.
#[derive(Clone, Debug)]
pub struct EpsilonSymbol {
    pub header: SymbolHeader,
}

/// A symbol of the sleigh symbol table. See the module docs.
pub enum SleighSymbol {
    /// `UseropSymbol`.
    Userop(UseropSymbol),
    /// `VarnodeSymbol`.
    Varnode(VarnodeSymbol),
    /// `ValueSymbol`.
    Value(ValueSymbol),
    /// `ValueMapSymbol`.
    ValueMap(ValueMapSymbol),
    /// `NameSymbol`.
    Name(NameSymbol),
    /// `SubtableSymbol`.
    Subtable(SubtableSymbol),
    /// `OperandSymbol`.
    Operand(OperandSymbol),
    /// `ContextSymbol`.
    Context(ContextSymbol),
    /// `VarnodeListSymbol`.
    VarnodeList(VarnodeListSymbol),
    /// `StartSymbol` (`inst_start`).
    Start(StartSymbol),
    /// `EndSymbol` (`inst_next`).
    End(EndSymbol),
    /// `Next2Symbol` (`inst_next2`).
    Next2(Next2Symbol),
    /// `EpsilonSymbol`.
    Epsilon(EpsilonSymbol),
    /// A symbol whose header element is not one of the kinds above (Java rejects the file with
    /// "Bad symbol encoding"); its body is skipped.
    Other(SymbolHeader, i32),
}

impl SleighSymbol {
    pub fn header(&self) -> &SymbolHeader {
        match self {
            Self::Userop(s) => &s.header,
            Self::Varnode(s) => &s.header,
            Self::Value(s) => &s.header,
            Self::ValueMap(s) => &s.header,
            Self::Name(s) => &s.header,
            Self::Subtable(s) => &s.header,
            Self::Operand(s) => &s.header,
            Self::Context(s) => &s.header,
            Self::VarnodeList(s) => &s.header,
            Self::Start(s) => &s.header,
            Self::End(s) => &s.header,
            Self::Next2(s) => &s.header,
            Self::Epsilon(s) => &s.header,
            Self::Other(h, _) => h,
        }
    }

    /// Port of `Symbol.getName()`.
    pub fn get_name(&self) -> &str {
        &self.header().name
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        match self {
            Self::Userop(s) => s.decode(decoder),
            Self::Varnode(s) => s.decode(decoder),
            Self::Value(s) => s.decode(decoder, sleigh),
            Self::ValueMap(s) => s.decode(decoder, sleigh),
            Self::Name(s) => s.decode(decoder, sleigh),
            Self::Subtable(s) => s.decode(decoder, sleigh),
            Self::Operand(s) => s.decode(decoder, sleigh),
            Self::Context(s) => s.decode(decoder, sleigh),
            Self::VarnodeList(s) => s.decode(decoder, sleigh),
            Self::Start(_) => decoder.close_element(ELEM_START_SYM.id),
            Self::End(_) => decoder.close_element(ELEM_END_SYM.id),
            Self::Next2(_) => decoder.close_element(ELEM_NEXT2_SYM.id),
            Self::Epsilon(_) => decoder.close_element(ELEM_EPSILON_SYM.id),
            Self::Other(_, tag_id) => decoder.close_element_skipping(*tag_id),
        }
    }

    /// The value pattern of a value-family symbol (`ValueSymbol` and its subclasses).
    fn patval(&self) -> Option<&PatternExpression> {
        match self {
            Self::Value(s) => s.patval.as_ref(),
            Self::ValueMap(s) => s.patval.as_ref(),
            Self::Name(s) => s.patval.as_ref(),
            Self::Context(s) => s.patval.as_ref(),
            Self::VarnodeList(s) => s.patval.as_ref(),
            _ => None,
        }
    }

    fn not_a_triple(&self) -> SleighError {
        SleighException::with_message(format!(
            "Symbol {} cannot be used as an operand",
            self.get_name()
        ))
        .into()
    }

    fn subtable_in_expression() -> SleighError {
        SleighException::with_message("Cannot use subtable in expression").into()
    }

    /// The table index a value-family symbol's pattern value selects.
    fn table_index(&self, walker: &ParserWalker<'_>) -> Result<i64, SleighError> {
        let patval = self
            .patval()
            .ok_or_else(|| SleighException::with_message("symbol has no pattern value"))?;
        Ok(patval.get_value(walker)?)
    }

    /// Port of `TripleSymbol.getPatternExpression()`.
    ///
    /// # Errors
    /// For a subtable ("Cannot use subtable in expression") or a symbol that is not a
    /// `TripleSymbol`.
    pub fn get_pattern_expression(&self) -> Result<PatternExpression, SleighError> {
        match self {
            Self::Operand(s) => s
                .localexp
                .clone()
                .ok_or_else(|| SleighException::with_message("operand has no value").into()),
            Self::Value(_) | Self::ValueMap(_) | Self::Name(_) | Self::Context(_)
            | Self::VarnodeList(_) => self
                .patval()
                .cloned()
                .ok_or_else(|| SleighException::with_message("symbol has no pattern value").into()),
            Self::Start(_) => Ok(PatternExpression::StartInstruction),
            Self::End(_) => Ok(PatternExpression::EndInstruction),
            Self::Next2(_) => Ok(PatternExpression::Next2Instruction),
            // PatternlessSymbol: a constant zero
            Self::Varnode(_) | Self::Epsilon(_) => Ok(PatternExpression::Constant(0)),
            Self::Subtable(_) => Err(Self::subtable_in_expression()),
            Self::Userop(_) | Self::Other(..) => Err(self.not_a_triple()),
        }
    }

    /// Port of `TripleSymbol.resolve(ParserWalker, SleighDebugLogger)`: the constructor a
    /// subtable selects, a check that a table-driven symbol has an entry for the value at hand,
    /// or nothing to do for every other kind.
    ///
    /// # Errors
    /// [`SleighError::UnknownInstruction`] if no constructor or table entry matches.
    pub fn resolve(
        &self,
        walker: &ParserWalker<'_>,
    ) -> Result<Option<Arc<Constructor>>, SleighError> {
        match self {
            Self::Subtable(s) => s.resolve(walker).map(Some),
            Self::ValueMap(s) if !s.tableisfilled => {
                let ind = self.table_index(walker)?;
                if ind >= s.valuetable.len() as i64
                    || ind < 0
                    || s.valuetable[ind as usize] == BAD_VALUE
                {
                    return Err(UnknownInstructionException::with_message(format!(
                        "No corresponding entry in valuetable <{}>, index={ind}",
                        s.header.name
                    ))
                    .into());
                }
                Ok(None)
            }
            Self::Name(s) if !s.tableisfilled => {
                let ind = self.table_index(walker)?;
                if ind >= s.nametable.len() as i64 || ind < 0 || s.nametable[ind as usize].is_none()
                {
                    return Err(UnknownInstructionException::with_message(format!(
                        "No corresponding entry in nametable <{}>, index={ind}",
                        s.header.name
                    ))
                    .into());
                }
                Ok(None)
            }
            Self::VarnodeList(s) if !s.tableisfilled => {
                let ind = self.table_index(walker)?;
                if ind < 0 || ind >= s.varnode_ids.len() as i64 || s.varnode_ids[ind as usize].is_none()
                {
                    return Err(UnknownInstructionException::with_message(format!(
                        "Failed to resolve varnode <{}>, index={ind}",
                        s.header.name
                    ))
                    .into());
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn varnode_list_entry<'t>(
        &self,
        s: &VarnodeListSymbol,
        walker: &ParserWalker<'t>,
    ) -> Result<&'t VarnodeSymbol, SleighError> {
        let ind = self.table_index(walker)?;
        let id = s
            .varnode_ids
            .get(ind as usize)
            .copied()
            .flatten()
            .ok_or_else(|| SleighException::with_message("varnode list entry is empty"))?;
        match walker.symbol_table().and_then(|t| t.find_symbol(id)) {
            Some(SleighSymbol::Varnode(v)) => Ok(v),
            _ => Err(SleighException::with_message("varnode list entry is not a varnode").into()),
        }
    }

    /// Port of `TripleSymbol.getFixedHandle(FixedHandle, ParserWalker)`: fills `hand` with the
    /// storage this symbol denotes at the walker's position.
    pub fn get_fixed_handle(
        &self,
        hand: &mut FixedHandle,
        walker: &ParserWalker<'_>,
    ) -> Result<(), SleighError> {
        match self {
            Self::Value(_) | Self::Name(_) | Self::Context(_) => {
                hand.space = Some(walker.get_const_space());
                hand.offset_space = None;
                hand.offset_offset = self.table_index(walker)?;
                hand.size = 0; // Cannot provide size
            }
            Self::ValueMap(s) => {
                let ind = self.table_index(walker)? as i32;
                // Entry has already been tested for null by the resolve routine
                hand.space = Some(walker.get_const_space());
                hand.offset_space = None; // Not a dynamic variable
                hand.offset_offset = s.valuetable[ind as usize];
                hand.size = 0; // Cannot provide size
            }
            Self::VarnodeList(s) => self.varnode_list_entry(s, walker)?.fill_handle(hand),
            Self::Varnode(s) => s.fill_handle(hand),
            Self::Operand(s) => {
                let h = walker.get_fixed_handle(s.hand as usize);
                hand.space = h.space;
                hand.offset_space = h.offset_space;
                hand.offset_offset = h.offset_offset;
                hand.offset_size = h.offset_size;
                hand.size = h.size;
                hand.temp_space = h.temp_space;
                hand.temp_offset = h.temp_offset;
            }
            Self::Start(_) | Self::End(_) | Self::Next2(_) => {
                let space = walker.get_cur_space();
                hand.offset_offset = self.inst_address(walker)?.offset();
                hand.size = space.pointer_size();
                hand.space = Some(space);
                hand.offset_space = None;
            }
            Self::Epsilon(_) => {
                hand.space = Some(walker.get_const_space());
                hand.offset_space = None; // Not a dynamic value
                hand.offset_offset = 0;
                hand.size = 0; // Cannot provide size
            }
            Self::Subtable(_) => return Err(Self::subtable_in_expression()),
            Self::Userop(_) | Self::Other(..) => return Err(self.not_a_triple()),
        }
        Ok(())
    }

    /// The address `inst_start`/`inst_next`/`inst_next2` denote.
    fn inst_address(
        &self,
        walker: &ParserWalker<'_>,
    ) -> Result<crate::program::model::address::Address, SleighError> {
        match self {
            Self::Start(_) => Ok(walker.get_addr()),
            Self::End(_) => walker
                .get_naddr()
                .ok_or_else(|| SleighException::with_message("inst_next is undefined").into()),
            _ => Ok(walker.get_n2addr()),
        }
    }

    /// Port of `TripleSymbol.print(ParserWalker)`.
    pub fn print(&self, walker: &mut ParserWalker<'_>) -> Result<String, SleighError> {
        match self {
            Self::Value(_) | Self::Context(_) => Ok(format_hex_value(self.table_index(walker)?)),
            Self::ValueMap(s) => {
                // ind is already known to be a valid array index via resolve
                let ind = self.table_index(walker)? as i32;
                Ok(format_hex_value(s.valuetable[ind as usize]))
            }
            Self::Name(s) => {
                let ind = self.table_index(walker)? as i32;
                s.nametable
                    .get(ind as usize)
                    .cloned()
                    .flatten()
                    .ok_or_else(|| SleighException::with_message("name table entry is empty").into())
            }
            Self::VarnodeList(s) => Ok(self.varnode_list_entry(s, walker)?.header.name.clone()),
            Self::Varnode(s) => Ok(s.header.name.clone()), // Use the symbol name for printing
            Self::Operand(s) => s.print(walker),
            Self::Start(_) | Self::End(_) | Self::Next2(_) => {
                Ok(format!("0x{:x}", self.inst_address(walker)?.offset() as u64))
            }
            Self::Epsilon(_) => Ok("0".to_string()),
            Self::Subtable(_) => Err(Self::subtable_in_expression()),
            Self::Userop(_) | Self::Other(..) => Err(self.not_a_triple()),
        }
    }

    /// Port of `TripleSymbol.printList(ParserWalker, ArrayList<Object>)`.
    pub fn print_list(
        &self,
        walker: &mut ParserWalker<'_>,
        list: &mut Vec<PrintListItem>,
    ) -> Result<(), SleighError> {
        match self {
            Self::Name(s) => {
                let ind = self.table_index(walker)? as i32;
                let token = s
                    .nametable
                    .get(ind as usize)
                    .cloned()
                    .flatten()
                    .ok_or_else(|| SleighException::with_message("name table entry is empty"))?;
                list.extend(token.chars().map(PrintListItem::Char));
                Ok(())
            }
            Self::Operand(s) => s.print_list(walker, list),
            Self::Value(_)
            | Self::ValueMap(_)
            | Self::Context(_)
            | Self::VarnodeList(_)
            | Self::Varnode(_)
            | Self::Start(_)
            | Self::End(_)
            | Self::Next2(_)
            | Self::Epsilon(_) => {
                list.push(PrintListItem::Handle {
                    key: walker.parent_handle_key(),
                    handle: walker.get_parent_handle(),
                });
                Ok(())
            }
            Self::Subtable(_) => Err(Self::subtable_in_expression()),
            Self::Userop(_) | Self::Other(..) => Err(self.not_a_triple()),
        }
    }
}

/// A single scope of symbol names for sleigh.
///
/// Port of `ghidra.app.plugin.processors.sleigh.symbol.SymbolScope`. Java's `SymbolScope` holds a
/// `parent` reference to the next-most-global `SymbolScope`, a `tree: HashMap<String, Symbol>`
/// mapping name to `Symbol`, and a unique scope `id`.
///
/// This crate's sleigh symbol family already stores symbols by id in a shared [`SymbolTable`]
/// rather than as owned/reference-counted objects (see [`SleighSymbol`]), so this struct follows
/// that same convention: `parent_id` and `symbols` hold ids instead of `SymbolScope`/`Symbol`
/// references. [`Self::get_parent`], [`Self::add_symbol`], [`Self::find_symbol`], and
/// [`Self::get_id`] reproduce the exact Java API and behavior -- including the fact that
/// `addSymbol` mutates the map *before* throwing on a duplicate name (Java's `HashMap.put`
/// replaces the old entry and returns it, then `SymbolScope.addSymbol` throws only after the
/// replacement already happened; nothing rolls the map back). See
/// `duplicate_add_symbol_replaces_entry_then_errors` below.
pub struct SymbolScope {
    pub id: i32,
    pub parent_id: Option<i32>,
    pub symbols: HashMap<String, i32>,
}

impl SymbolScope {
    /// Mirrors `SymbolScope(SymbolScope p, int i)`.
    pub fn new(parent_id: Option<i32>, id: i32) -> Self {
        Self {
            id,
            parent_id,
            symbols: HashMap::new(),
        }
    }

    /// Returns the next-most-global scope's id, or `None` for the global scope.
    ///
    /// Mirrors `SymbolScope.getParent()`.
    pub fn get_parent(&self) -> Option<i32> {
        self.parent_id
    }

    /// Adds `name` -> `id` to this scope.
    ///
    /// Mirrors `SymbolScope.addSymbol(Symbol a)`: throws (here, returns `Err`) a
    /// `SleighException` if a symbol with that name already exists in this scope. As in Java,
    /// the new entry replaces the old one in the map regardless of whether the duplicate error
    /// is raised.
    pub fn add_symbol(&mut self, name: String, id: i32) -> Result<(), SleighException> {
        let previous = self.symbols.insert(name, id);
        if previous.is_some() {
            return Err(SleighException::with_message("Duplicate symbol"));
        }
        Ok(())
    }

    /// Looks up `nm` in this scope only (does not walk to the parent scope).
    ///
    /// Mirrors `SymbolScope.findSymbol(String nm)`.
    pub fn find_symbol(&self, nm: &str) -> Option<i32> {
        self.symbols.get(nm).copied()
    }

    /// Mirrors `SymbolScope.getId()`.
    pub fn get_id(&self) -> i32 {
        self.id
    }
}

/// The sleigh symbol table. Port of `ghidra.app.plugin.processors.sleigh.symbol.SymbolTable`.
pub struct SymbolTable {
    pub symbols: Vec<Option<SleighSymbol>>,
    pub scopes: Vec<SymbolScope>,
    /// Ids of the user-defined ops, in the order their bodies were decoded (`userOps`).
    pub user_ops: Vec<i32>,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            scopes: Vec::new(),
            user_ops: Vec::new(),
        }
    }

    /// Port of `SymbolTable.findSymbol(int)`.
    pub fn find_symbol(&self, id: i32) -> Option<&SleighSymbol> {
        self.symbols.get(id as usize)?.as_ref()
    }

    pub fn find_symbol_by_name(&self, name: &str, scope_id: i32) -> Option<&SleighSymbol> {
        let mut cur_scope = scope_id;
        loop {
            let scope = self.scopes.get(cur_scope as usize)?;
            if let Some(&id) = scope.symbols.get(name) {
                return self.find_symbol(id);
            }
            if let Some(parent) = scope.parent_id {
                cur_scope = parent;
            } else {
                break;
            }
        }
        None
    }

    /// Port of `SymbolTable.findGlobalSymbol(String)`: a lookup in the global scope only.
    pub fn find_global_symbol(&self, name: &str) -> Option<&SleighSymbol> {
        let id = self.scopes.first()?.find_symbol(name)?;
        self.find_symbol(id)
    }

    /// The [`OperandSymbol`] with id `id`, if that is what it is.
    pub fn find_operand(&self, id: i32) -> Option<&OperandSymbol> {
        match self.find_symbol(id)? {
            SleighSymbol::Operand(op) => Some(op),
            _ => None,
        }
    }

    /// Constructor `ct` of subtable `table` (how an `OperandValue` names its constructor).
    pub fn find_constructor(&self, table: i32, ct: i32) -> Option<&Arc<Constructor>> {
        match self.find_symbol(table)? {
            SleighSymbol::Subtable(sub) => sub.get_constructor(ct as usize),
            _ => None,
        }
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_SYMBOL_TABLE)?;

        let scope_size = decoder.read_signed_integer_with_id(ATTRIB_SCOPESIZE)? as usize;
        self.scopes.reserve(scope_size);

        let sym_size = decoder.read_signed_integer_with_id(ATTRIB_SYMBOLSIZE)? as usize;
        self.symbols.resize_with(sym_size, || None);

        for _ in 0..scope_size {
            let subel = decoder.open_element_with_id(ELEM_SCOPE)?;
            let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
            let parent = decoder.read_unsigned_integer_with_id(ATTRIB_PARENT)? as i32;

            let parent_id = if parent == id { None } else { Some(parent) };
            self.scopes.push(SymbolScope::new(parent_id, id));
            decoder.close_element(subel)?;
        }

        for _ in 0..sym_size {
            let tag = decoder.peek_element()?;
            let (header, _) = SymbolHeader::decode(decoder)?;
            let h = header.clone();

            let sym = if tag == ELEM_USEROP_HEAD.id {
                SleighSymbol::Userop(UseropSymbol {
                    header: h,
                    index: 0,
                })
            } else if tag == ELEM_EPSILON_SYM_HEAD.id {
                SleighSymbol::Epsilon(EpsilonSymbol { header: h })
            } else if tag == ELEM_VALUE_SYM_HEAD.id {
                SleighSymbol::Value(ValueSymbol {
                    header: h,
                    patval: None,
                })
            } else if tag == ELEM_VALUEMAP_SYM_HEAD.id {
                SleighSymbol::ValueMap(ValueMapSymbol {
                    header: h,
                    patval: None,
                    valuetable: Vec::new(),
                    tableisfilled: false,
                })
            } else if tag == ELEM_NAME_SYM_HEAD.id {
                SleighSymbol::Name(NameSymbol {
                    header: h,
                    patval: None,
                    nametable: Vec::new(),
                    tableisfilled: false,
                })
            } else if tag == ELEM_VARNODE_SYM_HEAD.id {
                SleighSymbol::Varnode(VarnodeSymbol {
                    header: h,
                    space: None,
                    offset: 0,
                    size: 0,
                })
            } else if tag == ELEM_CONTEXT_SYM_HEAD.id {
                SleighSymbol::Context(ContextSymbol {
                    header: h,
                    patval: None,
                    varnode_id: 0,
                    low: 0,
                    high: 0,
                    flow: false,
                })
            } else if tag == ELEM_VARLIST_SYM_HEAD.id {
                SleighSymbol::VarnodeList(VarnodeListSymbol {
                    header: h,
                    patval: None,
                    varnode_ids: Vec::new(),
                    tableisfilled: false,
                })
            } else if tag == ELEM_OPERAND_SYM_HEAD.id {
                SleighSymbol::Operand(OperandSymbol {
                    header: h,
                    rel_offset: 0,
                    offset_base: 0,
                    minimum_length: 0,
                    hand: 0,
                    triple_id: None,
                    code_address: false,
                    localexp: None,
                    defexp: None,
                })
            } else if tag == ELEM_START_SYM_HEAD.id {
                SleighSymbol::Start(StartSymbol { header: h })
            } else if tag == ELEM_END_SYM_HEAD.id {
                SleighSymbol::End(EndSymbol { header: h })
            } else if tag == ELEM_NEXT2_SYM_HEAD.id {
                SleighSymbol::Next2(Next2Symbol { header: h })
            } else if tag == ELEM_SUBTABLE_SYM_HEAD.id {
                SleighSymbol::Subtable(SubtableSymbol {
                    header: h,
                    constructors: Vec::new(),
                    decision_tree: None,
                })
            } else {
                SleighSymbol::Other(h, tag)
            };

            let id = header.id as usize;
            let scope_id = header.scope_id as usize;
            if id < self.symbols.len() {
                self.symbols[id] = Some(sym);
            }
            if scope_id < self.scopes.len() {
                // Mirrors `table[sym.getScopeId()].addSymbol(sym);` in
                // `SymbolTable.decodeSymbolHeader` -- throws (here, `DecoderError`) on a
                // duplicate name within the same scope.
                self.scopes[scope_id]
                    .add_symbol(header.name, header.id)
                    .map_err(|e| DecoderError::Generic(e.message().to_string()))?;
            }
        }

        while decoder.peek_element()? != 0 {
            let tag = decoder.open_element()?;
            let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as usize;
            match self.symbols.get_mut(id).and_then(Option::as_mut) {
                Some(sym) => {
                    sym.decode(decoder, sleigh)?;
                    if let SleighSymbol::Userop(s) = sym {
                        self.user_ops.push(s.header.id);
                    }
                }
                None => decoder.close_element_skipping(tag)?,
            }
        }

        decoder.close_element(el)?;
        Ok(())
    }
}

#[cfg(test)]
mod symbol_header_tests {
    use super::SymbolHeader;

    fn header(name: &str, id: i32, scope_id: i32) -> SymbolHeader {
        SymbolHeader {
            name: name.to_string(),
            id,
            scope_id,
        }
    }

    #[test]
    fn get_name_returns_the_symbols_name() {
        let h = header("myUserop", 3, 0);
        assert_eq!(h.get_name(), "myUserop");
    }

    #[test]
    fn get_id_returns_the_unique_id() {
        let h = header("sym", 42, 0);
        assert_eq!(h.get_id(), 42);
    }

    #[test]
    fn get_scope_id_returns_the_containing_scope() {
        let h = header("sym", 1, 7);
        assert_eq!(h.get_scope_id(), 7);
    }

    #[test]
    fn clone_produces_an_independent_equal_header() {
        let h = header("sym", 1, 2);
        let cloned = h.clone();
        assert_eq!(cloned.get_name(), h.get_name());
        assert_eq!(cloned.get_id(), h.get_id());
        assert_eq!(cloned.get_scope_id(), h.get_scope_id());
    }
}

#[cfg(test)]
mod userop_symbol_tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::{PackedDecode, PackedEncode};

    fn header(name: &str, id: i32, scope_id: i32) -> SymbolHeader {
        SymbolHeader {
            name: name.to_string(),
            id,
            scope_id,
        }
    }

    #[test]
    fn get_index_returns_the_stored_index() {
        let sym = UseropSymbol {
            header: header("break", 5, 0),
            index: 3,
        };
        assert_eq!(sym.get_index(), 3);
    }

    #[test]
    fn decode_reads_the_index_attribute_and_closes_the_already_open_element() {
        // Mirrors the real caller: `SymbolTable::decode`'s dispatch loop opens the `ELEM_USEROP`
        // element and reads `ATTRIB_ID` before calling `UseropSymbol::decode` -- Java's own
        // `decoder.openElement(ELEM_USEROP)` call inside `UseropSymbol.decode` is commented out
        // for exactly this reason (the element is already open by the time `decode` runs).
        // Wrapped in an outer element, matching real usage: `UseropSymbol::decode` is only ever
        // invoked from inside `SymbolTable::decode`'s `ELEM_SYMBOL_TABLE` element, never at the
        // top of a standalone byte stream.
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_SYMBOL_TABLE).unwrap();
        encoder.open_element(ELEM_USEROP).unwrap();
        encoder.write_unsigned_integer(ATTRIB_ID, 7).unwrap();
        encoder.write_signed_integer(ATTRIB_INDEX, 42).unwrap();
        encoder.close_element(ELEM_USEROP).unwrap();
        encoder.close_element(ELEM_SYMBOL_TABLE).unwrap();

        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, encoder.into_inner());

        let outer = decoder.open_element().unwrap();
        assert_eq!(outer, ELEM_SYMBOL_TABLE.id);

        let el = decoder.open_element().unwrap();
        assert_eq!(el, ELEM_USEROP.id);
        assert_eq!(decoder.read_unsigned_integer_with_id(ATTRIB_ID).unwrap(), 7);

        let mut sym = UseropSymbol {
            header: header("myop", 7, 0),
            index: 0,
        };
        sym.decode(&decoder).unwrap();
        assert_eq!(sym.get_index(), 42);

        // `decode` closed the `ELEM_USEROP` element itself; nothing left but the outer close.
        assert_eq!(decoder.peek_element().unwrap(), 0);
        decoder.close_element(outer).unwrap();
    }
}

#[cfg(test)]
mod symbol_scope_tests {
    use super::*;

    #[test]
    fn new_scope_has_no_symbols_and_the_given_id_and_parent() {
        let scope = SymbolScope::new(Some(0), 1);
        assert_eq!(scope.get_id(), 1);
        assert_eq!(scope.get_parent(), Some(0));
        assert_eq!(scope.find_symbol("anything"), None);
    }

    #[test]
    fn global_scope_has_no_parent() {
        let scope = SymbolScope::new(None, 0);
        assert_eq!(scope.get_parent(), None);
    }

    #[test]
    fn add_symbol_then_find_symbol_round_trips() {
        let mut scope = SymbolScope::new(None, 0);
        scope.add_symbol("r0".to_string(), 5).unwrap();
        assert_eq!(scope.find_symbol("r0"), Some(5));
    }

    #[test]
    fn find_symbol_only_looks_in_this_scope_not_the_parent() {
        // Java's `SymbolScope.findSymbol` only consults its own `tree`; walking up to the parent
        // is the caller's job (`SymbolTable.findSymbolInternal`), not `SymbolScope`'s.
        let mut parent = SymbolScope::new(None, 0);
        parent.add_symbol("global_sym".to_string(), 1).unwrap();
        let child = SymbolScope::new(Some(0), 1);
        assert_eq!(child.find_symbol("global_sym"), None);
    }

    #[test]
    fn add_symbol_rejects_a_duplicate_name_in_the_same_scope() {
        let mut scope = SymbolScope::new(None, 0);
        scope.add_symbol("dup".to_string(), 1).unwrap();
        let err = scope.add_symbol("dup".to_string(), 2).unwrap_err();
        assert_eq!(err.message(), "Duplicate symbol");
    }

    #[test]
    fn duplicate_add_symbol_replaces_entry_then_errors() {
        // Faithful reproduction of a real Java quirk: `SymbolScope.addSymbol` does
        // `tree.put(a.getName(), a)` *then* throws if the previous value was non-null. Java's
        // `HashMap.put` has already installed the new value by the time the exception is raised,
        // so the old symbol is gone even though the caller sees an error. `HashMap::insert` in
        // Rust has the identical replace-then-return-old-value semantics, so this falls out
        // naturally rather than needing special-cased rollback logic.
        let mut scope = SymbolScope::new(None, 0);
        scope.add_symbol("dup".to_string(), 1).unwrap();
        let err = scope.add_symbol("dup".to_string(), 2).unwrap_err();
        assert_eq!(err.message(), "Duplicate symbol");
        // The second (colliding) id is what's actually stored, not the first.
        assert_eq!(scope.find_symbol("dup"), Some(2));
    }

    #[test]
    fn get_id_returns_the_scopes_unique_id() {
        let scope = SymbolScope::new(None, 42);
        assert_eq!(scope.get_id(), 42);
    }
}

/// Run-time behaviour of the individual symbol kinds (the `TripleSymbol` API), exercised on a
/// parser context over fixed bytes: byte 0 = 0x2c, byte 1 = 0xf0.
#[cfg(test)]
mod behaviour_tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::lang::sleigh::expression::{ContextField, TokenField};
    use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer};

    fn header(name: &str) -> SymbolHeader {
        SymbolHeader {
            name: name.to_string(),
            id: 0,
            scope_id: 0,
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    /// A 2-byte instruction at ram:0x500 (so `inst_next` is 0x502) with context word
    /// 0x40000000 and a constant space.
    fn context() -> SleighParserContext {
        let addr = Address::new(ram(), 0x500);
        let mem: Arc<dyn MemBuffer> =
            Arc::new(ByteMemBufferImpl::new(addr.clone(), vec![0x2c, 0xf0], true));
        let snippet = SleighParserContext::for_snippet(
            addr.clone(),
            Some(addr.add(2).unwrap()),
            None,
            None,
            Some(AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0)),
        );
        SleighParserContext::with_mem_for_tests(snippet, mem, vec![0x4000_0000])
    }

    /// Byte `byte` of the instruction, bits `start..=end`.
    fn field(signbit: bool, start: i32, end: i32, byte: i32) -> PatternExpression {
        PatternExpression::TokenField(TokenField {
            bigendian: true,
            signbit,
            bitstart: start,
            bitend: end,
            bytestart: byte,
            byteend: byte,
            shift: start,
        })
    }

    fn walker(ctx: &SleighParserContext) -> ParserWalker<'_> {
        let mut w = ParserWalker::new(ctx);
        w.base_state();
        w
    }

    #[test]
    fn value_symbols_print_and_export_their_value() {
        let ctx = context();
        let mut w = walker(&ctx);
        let sym = SleighSymbol::Value(ValueSymbol {
            header: header("imm"),
            patval: Some(field(true, 0, 7, 1)),
        });
        // 0xf0 as a signed byte
        assert_eq!(sym.print(&mut w).unwrap(), "-0x10");
        let mut hand = FixedHandle::new();
        sym.get_fixed_handle(&mut hand, &w).unwrap();
        assert_eq!(hand.offset_offset, -16);
        assert_eq!(hand.size, 0);
        assert_eq!(hand.space.unwrap().space_type(), AddressSpaceType::Constant);
        let mut list = Vec::new();
        sym.print_list(&mut w, &mut list).unwrap();
        assert!(matches!(list.as_slice(), [PrintListItem::Handle { key: 0, .. }]));
        assert!(sym.resolve(&w).unwrap().is_none());
    }

    #[test]
    fn value_map_symbols_look_their_value_up() {
        let ctx = context();
        let mut w = walker(&ctx);
        // low nibble of byte 0 (0xc) indexes the table
        let mut table = vec![BAD_VALUE; 16];
        table[0xc] = 0x77;
        let sym = SleighSymbol::ValueMap(ValueMapSymbol {
            header: header("vm"),
            patval: Some(field(false, 0, 3, 0)),
            valuetable: table.clone(),
            tableisfilled: false,
        });
        assert!(sym.resolve(&w).unwrap().is_none());
        assert_eq!(sym.print(&mut w).unwrap(), "0x77");
        let mut hand = FixedHandle::new();
        sym.get_fixed_handle(&mut hand, &w).unwrap();
        assert_eq!(hand.offset_offset, 0x77);

        // a hole in the table is no instruction
        table[0xc] = BAD_VALUE;
        let holed = SleighSymbol::ValueMap(ValueMapSymbol {
            header: header("vm"),
            patval: Some(field(false, 0, 3, 0)),
            valuetable: table,
            tableisfilled: false,
        });
        match holed.resolve(&w) {
            Err(SleighError::UnknownInstruction(e)) => {
                assert_eq!(e.message(), "No corresponding entry in valuetable <vm>, index=12")
            }
            other => panic!("expected an unknown instruction, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn name_symbols_print_names_as_characters() {
        let ctx = context();
        let mut w = walker(&ctx);
        // high nibble of byte 0 (2)
        let sym = SleighSymbol::Name(NameSymbol {
            header: header("cc"),
            patval: Some(field(false, 4, 7, 0)),
            nametable: vec![Some("eq".into()), Some("ne".into()), Some("lt".into()), None],
            tableisfilled: false,
        });
        assert!(sym.resolve(&w).unwrap().is_none());
        assert_eq!(sym.print(&mut w).unwrap(), "lt");
        let mut list = Vec::new();
        sym.print_list(&mut w, &mut list).unwrap();
        assert_eq!(list, vec![PrintListItem::Char('l'), PrintListItem::Char('t')]);
    }

    #[test]
    fn varnode_and_address_symbols_export_fixed_storage() {
        let ctx = context();
        let mut w = walker(&ctx);
        let reg = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        let vn = SleighSymbol::Varnode(VarnodeSymbol {
            header: header("sp"),
            space: Some(reg.clone()),
            offset: 0x10,
            size: 4,
        });
        assert_eq!(vn.print(&mut w).unwrap(), "sp");
        let mut hand = FixedHandle::new();
        vn.get_fixed_handle(&mut hand, &w).unwrap();
        assert_eq!((hand.offset_offset, hand.size), (0x10, 4));
        assert_eq!(hand.space.unwrap().name(), "register");
        assert!(matches!(vn.get_pattern_expression().unwrap(), PatternExpression::Constant(0)));

        let start = SleighSymbol::Start(StartSymbol { header: header("inst_start") });
        assert_eq!(start.print(&mut w).unwrap(), "0x500");
        let mut hand = FixedHandle::new();
        start.get_fixed_handle(&mut hand, &w).unwrap();
        assert_eq!((hand.offset_offset, hand.size), (0x500, 4));
        assert_eq!(hand.space.unwrap().name(), "ram");

        let end = SleighSymbol::End(EndSymbol { header: header("inst_next") });
        assert_eq!(end.print(&mut w).unwrap(), "0x502");
        assert!(matches!(
            end.get_pattern_expression().unwrap(),
            PatternExpression::EndInstruction
        ));

        let next2 = SleighSymbol::Next2(Next2Symbol { header: header("inst_next2") });
        assert!(matches!(
            next2.get_pattern_expression().unwrap(),
            PatternExpression::Next2Instruction
        ));
        let mut hand = FixedHandle::new();
        next2.get_fixed_handle(&mut hand, &w).unwrap();
        // a snippet context cannot parse ahead, so inst_next2 is NO_ADDRESS
        let no_address = crate::program::model::address::SpecialAddress::no_address();
        assert_eq!(hand.offset_offset, no_address.offset());
        assert_eq!(hand.space.unwrap().name(), "ram");
        assert_eq!(next2.print(&mut w).unwrap(), format!("0x{:x}", no_address.offset() as u64));

        let eps = SleighSymbol::Epsilon(EpsilonSymbol { header: header("epsilon") });
        assert_eq!(eps.print(&mut w).unwrap(), "0");
        let mut hand = FixedHandle::new();
        eps.get_fixed_handle(&mut hand, &w).unwrap();
        assert_eq!((hand.offset_offset, hand.size), (0, 0));
    }

    #[test]
    fn context_symbols_read_the_packed_context() {
        let ctx = context();
        let mut w = walker(&ctx);
        let sym = ContextSymbol {
            header: header("TMode"),
            patval: Some(PatternExpression::ContextField(ContextField {
                signbit: false,
                bitstart: 1,
                bitend: 1,
                bytestart: 0,
                byteend: 0,
                shift: 6,
            })),
            varnode_id: 0,
            low: 1,
            high: 1,
            flow: true,
        };
        assert_eq!((sym.get_internal_low(), sym.get_internal_high()), (Some(1), Some(1)));
        assert!(sym.follows_flow());
        let sym = SleighSymbol::Context(sym);
        // context word 0x40000000: bit 1 (msb first) is set
        assert_eq!(sym.print(&mut w).unwrap(), "0x1");
    }

    #[test]
    fn subtables_and_user_ops_cannot_be_used_as_values() {
        let ctx = context();
        let mut w = walker(&ctx);
        let sub = SleighSymbol::Subtable(SubtableSymbol {
            header: header("rel"),
            constructors: Vec::new(),
            decision_tree: None,
        });
        match sub.print(&mut w) {
            Err(SleighError::Sleigh(e)) => assert_eq!(e.message(), "Cannot use subtable in expression"),
            other => panic!("expected an error, got {other:?}"),
        }
        let mut hand = FixedHandle::new();
        assert!(sub.get_fixed_handle(&mut hand, &w).is_err());
        assert!(sub.get_pattern_expression().is_err());
        // a subtable without a decision tree resolves nothing
        assert!(matches!(sub.resolve(&w), Err(SleighError::UnknownInstruction(_))));

        let op = SleighSymbol::Userop(UseropSymbol { header: header("syscall"), index: 0 });
        assert!(op.print(&mut w).is_err());
    }

    #[test]
    fn expression_operands_print_their_value_and_record_a_handle() {
        let ctx = context();
        let mut w = walker(&ctx);
        w.allocate_operand().unwrap();
        let mut hand = FixedHandle::new();
        hand.space = Some(AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0));
        hand.offset_offset = 0x2c;
        w.set_parent_handle(hand);
        w.set_current_length(1);
        w.pop_operand();
        let op = OperandSymbol {
            header: header("imm"),
            rel_offset: 0,
            offset_base: -1,
            minimum_length: 1,
            hand: 0,
            triple_id: None,
            code_address: false,
            localexp: None,
            defexp: Some(field(false, 0, 7, 0)),
        };
        assert_eq!(op.to_display_string(), "imm : 0");
        assert_eq!(op.print(&mut w).unwrap(), "0x2c");
        let mut list = Vec::new();
        op.print_list(&mut w, &mut list).unwrap();
        match list.as_slice() {
            // offset_size is filled in with the operand's length
            [PrintListItem::Handle { key: 1, handle }] => assert_eq!(handle.offset_size, 1),
            other => panic!("unexpected list {other:?}"),
        }
        // ... and written back to the context, as Java mutates the shared handle
        assert_eq!(w.get_fixed_handle(0).offset_size, 1);
        let mut copy = FixedHandle::new();
        SleighSymbol::Operand(op).get_fixed_handle(&mut copy, &w).unwrap();
        assert_eq!(copy.offset_offset, 0x2c);
    }

    #[test]
    fn hex_values_print_like_java() {
        assert_eq!(format_hex_value(0), "0x0");
        assert_eq!(format_hex_value(255), "0xff");
        assert_eq!(format_hex_value(-1), "-0x1");
        assert_eq!(format_hex_value(i64::MIN), "-0x8000000000000000");
    }
}
