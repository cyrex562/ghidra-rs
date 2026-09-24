//! Port of `ghidra.app.plugin.processors.sleigh.ContextCommit`.

use crate::program::model::lang::sleigh::walker::{ParserWalker, SleighError};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_ID, ATTRIB_MASK, ATTRIB_NUMBER, ELEM_COMMIT,
};

/// A `globalset` directive: commit the masked bits of context word `num` to the address the
/// symbol `sym` resolves to.
///
/// Port of `ghidra.app.plugin.processors.sleigh.ContextCommit`; the Java `TripleSymbol sym` is
/// held as its symbol id (resolved through the language's symbol table when the commit is
/// applied, since the symbol's body may not be decoded yet when the constructor is).
#[derive(Debug, Clone)]
pub struct ContextCommit {
    /// Id of the symbol giving the address the change takes effect at.
    pub sym: Option<i32>,
    /// Context word being committed (`num`).
    pub num: i32,
    /// Bits being committed (`mask`).
    pub mask: u32,
}

impl Default for ContextCommit {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextCommit {
    pub fn new() -> Self {
        Self {
            sym: None,
            num: 0,
            mask: 0,
        }
    }

    /// Port of `ContextCommit.apply(ParserWalker, SleighDebugLogger)`: records the pending
    /// commit with the parser context, at the walker's current node.
    ///
    /// # Errors
    /// Never in practice; kept fallible to match the other [`ContextChange`](super::ContextChange).
    pub fn apply(&self, walker: &ParserWalker<'_>) -> Result<(), SleighError> {
        let point = walker
            .get_state()
            .expect("context commits are applied on a tree node");
        walker.get_parser_context().add_commit(
            point,
            self.sym.unwrap_or(-1),
            self.num,
            self.mask as i32,
        );
        Ok(())
    }

    /// Port of `ContextCommit.decode(Decoder, SleighLanguage)`.
    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        _lang: &SleighLanguage,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_COMMIT)?;
        self.sym = Some(decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32);
        self.num = decoder.read_signed_integer_with_id(ATTRIB_NUMBER)? as i32;
        self.mask = decoder.read_unsigned_integer_with_id(ATTRIB_MASK)? as u32;
        decoder.close_element(el)?;
        Ok(())
    }
}
