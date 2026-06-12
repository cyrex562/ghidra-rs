use super::constructor::Constructor;
use super::decision::DecisionNode;
use super::expression::PatternExpression;
use super::SleighLanguage;
use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::ids::*;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SymbolHeader {
    pub name: String,
    pub id: i32,
    pub scope_id: i32,
}

impl SymbolHeader {
    pub fn decode(decoder: &dyn Decoder) -> Result<(Self, i32), DecoderError> {
        let el = decoder.open_element()?;
        let name = decoder.read_string_with_id(ATTRIB_NAME)?;
        let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
        let scope_id = decoder.read_unsigned_integer_with_id(ATTRIB_SCOPE)? as i32;
        decoder.close_element(el)?;
        Ok((Self { name, id, scope_id }, el))
    }
}

pub struct UseropSymbol {
    pub header: SymbolHeader,
    pub index: i32,
}

impl UseropSymbol {
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

pub struct SymbolScope {
    pub id: i32,
    pub parent_id: Option<i32>,
    pub symbols: HashMap<String, i32>,
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
            self.scopes.push(SymbolScope {
                id,
                parent_id,
                symbols: HashMap::new(),
            });
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
                self.scopes[scope_id].symbols.insert(header.name, header.id);
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
