use super::constructor::Constructor;
use super::decision::DecisionNode;
use super::expression::PatternExpression;
use super::SleighLanguage;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::program::model::address::AddressSpace;
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

pub struct VarnodeSymbol {
    pub header: SymbolHeader,
    pub space: Option<Arc<AddressSpace>>,
    pub offset: u64,
    pub size: i32,
}

impl VarnodeSymbol {
    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        self.space = Some(decoder.read_space_with_id(ATTRIB_SPACE)?);
        self.offset = decoder.read_unsigned_integer_with_id(ATTRIB_OFFSET)?;
        self.size = decoder.read_signed_integer_with_id(ATTRIB_SIZE)? as i32;
        decoder.close_element(ELEM_VARNODE_SYM.id)?;
        Ok(())
    }
}

pub struct ValueSymbol {
    pub header: SymbolHeader,
    pub patval: Option<PatternExpression>,
}

impl ValueSymbol {
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        self.patval = Some(PatternExpression::decode(decoder, lang)?);
        decoder.close_element(ELEM_VALUE_SYM.id)?;
        Ok(())
    }
}

pub struct SubtableSymbol {
    pub header: SymbolHeader,
    pub constructors: Vec<Arc<Constructor>>,
    pub decision_tree: Option<DecisionNode>,
}

impl SubtableSymbol {
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let num_ct = decoder.read_signed_integer_with_id(ATTRIB_NUMCT)? as usize;
        self.constructors.reserve(num_ct);
        for _ in 0..num_ct {
            let mut ct = Constructor::new();
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

#[derive(Clone, Debug)]
pub struct OperandSymbol {
    pub header: SymbolHeader,
    pub rel_offset: i32,
    pub offset_base: i32,
    pub minimum_length: i32,
    pub hand: i32,
    pub triple_id: Option<i32>,
    pub code_address: bool,
    pub defexp: Option<PatternExpression>,
}

impl OperandSymbol {
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
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
        if decoder.peek_element()? != 0 {
            self.defexp = Some(PatternExpression::decode(decoder, lang)?);
        }
        decoder.close_element(ELEM_OPERAND_SYM.id)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TripleSymbol {
    pub header: SymbolHeader,
}

pub enum SleighSymbol {
    Userop(UseropSymbol),
    Varnode(VarnodeSymbol),
    Value(ValueSymbol),
    Subtable(SubtableSymbol),
    Operand(OperandSymbol),
    Triple(TripleSymbol),
    Other(SymbolHeader, i32),
}

impl SleighSymbol {
    pub fn header(&self) -> &SymbolHeader {
        match self {
            Self::Userop(s) => &s.header,
            Self::Varnode(s) => &s.header,
            Self::Value(s) => &s.header,
            Self::Subtable(s) => &s.header,
            Self::Operand(s) => &s.header,
            Self::Triple(s) => &s.header,
            Self::Other(h, _) => h,
        }
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
            Self::Subtable(s) => s.decode(decoder, sleigh),
            Self::Operand(s) => s.decode(decoder, sleigh),
            Self::Triple(_) => {
                decoder.close_element_skipping(ELEM_VARNODE_SYM.id)?; // Triple symbols are usually Varnodes or similar in SLA
                Ok(())
            }
            Self::Other(_, tag_id) => {
                decoder.close_element_skipping(*tag_id)?;
                Ok(())
            }
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

pub struct SymbolTable {
    pub symbols: Vec<Option<SleighSymbol>>,
    pub scopes: Vec<SymbolScope>,
    pub user_ops: Vec<i32>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            scopes: Vec::new(),
            user_ops: Vec::new(),
        }
    }

    pub fn find_symbol(&self, id: i32) -> Option<&SleighSymbol> {
        self.symbols.get(id as usize)?.as_ref()
    }

    pub fn find_symbol_by_name(&self, name: &str, scope_id: i32) -> Option<&SleighSymbol> {
        let mut cur_scope = scope_id;
        loop {
            let scope = &self.scopes[cur_scope as usize];
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

            let sym = if tag == ELEM_USEROP_HEAD.id {
                SleighSymbol::Userop(UseropSymbol {
                    header: header.clone(),
                    index: 0,
                })
            } else if tag == ELEM_VARNODE_SYM_HEAD.id {
                SleighSymbol::Varnode(VarnodeSymbol {
                    header: header.clone(),
                    space: None,
                    offset: 0,
                    size: 0,
                })
            } else if tag == ELEM_VALUE_SYM_HEAD.id {
                SleighSymbol::Value(ValueSymbol {
                    header: header.clone(),
                    patval: None,
                })
            } else if tag == ELEM_OPERAND_SYM_HEAD.id {
                SleighSymbol::Operand(OperandSymbol {
                    header: header.clone(),
                    rel_offset: 0,
                    offset_base: 0,
                    minimum_length: 0,
                    hand: 0,
                    triple_id: None,
                    code_address: false,
                    defexp: None,
                })
            } else if tag == ELEM_SUBTABLE_SYM_HEAD.id {
                SleighSymbol::Subtable(SubtableSymbol {
                    header: header.clone(),
                    constructors: Vec::new(),
                    decision_tree: None,
                })
            } else {
                SleighSymbol::Other(header.clone(), tag)
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
            if id < self.symbols.len() {
                if let Some(sym) = self.symbols[id].as_mut() {
                    sym.decode(decoder, sleigh)?;
                } else {
                    decoder.close_element_skipping(tag)?;
                }
            } else {
                decoder.close_element_skipping(tag)?;
            }
        }

        for sym_opt in &self.symbols {
            if let Some(SleighSymbol::Userop(s)) = sym_opt {
                self.user_ops.push(s.header.id);
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
