//! Port of `ghidra.app.decompiler.ClangToken`.
//!
//! A source code language token: display text plus attributes, optionally linked to the
//! data-flow analysis.
//!
//! # Shape
//!
//! Java's `ClangToken` is a concrete class that eleven other classes extend (`ClangBreak`,
//! `ClangCommentToken`, `ClangFuncNameToken`, `ClangOpToken`, `ClangSyntaxToken`,
//! `ClangVariableToken`, ...), carrying both shared state and behaviour that subclasses override.
//! That splits in Rust into:
//!
//! - [`ClangTokenBase`] -- the shared state (parent, containing line, text, syntax type, matching
//!   flag) and the concrete methods over it. It is directly instantiable, mirroring `new
//!   ClangToken(par)`.
//! - [`ClangToken`] -- the trait declaring the operations subclasses override
//!   ([`is_variable_ref`](ClangToken::is_variable_ref),
//!   [`get_varnode`](ClangToken::get_varnode), [`get_pcode_op`](ClangToken::get_pcode_op),
//!   [`get_high_variable`](ClangToken::get_high_variable),
//!   [`get_high_symbol`](ClangToken::get_high_symbol), [`get_scalar`](ClangToken::get_scalar),
//!   [`decode`](ClangToken::decode)), each with the base-class default. Implementors supply
//!   [`base`](ClangToken::base)/[`base_mut`](ClangToken::base_mut) so the shared accessors come
//!   for free.
//!
//! # Not modeled
//!
//! `ClangToken.iterator(boolean)` is a one-line factory for `new TokenIterator(this, forward)`;
//! all of its behaviour (the lazy `Parent()`/`Child()` tree walk with an explicit ancestor stack)
//! lives in `TokenIterator`, which is not ported. It therefore comes with `TokenIterator`'s own
//! port rather than being guessed at here -- returning, say, a self-only iterator would be
//! silently wrong for every caller.
//!
//! The eleven subclasses are likewise not ported yet, so
//! [`build_token`](ClangTokenBase::build_token) validates the element id and produces a plain
//! [`ClangTokenBase`] for each of them (see its docs), and
//! [`kind`](ClangToken::kind)/[`ClangTokenKind`] stand in for the `instanceof` checks callers such
//! as [`PrettyPrinter`](crate::app::decompiler::pretty_printer::PrettyPrinter) perform against
//! those subclasses.

use std::sync::Arc;

use crate::app::decompiler::clang_line::ClangLine;
use crate::app::decompiler::clang_node::ClangNode;
use crate::app::seam_stubs::ClangFunction;
use crate::program::model::address::Address;
use crate::program::model::pcode::{
    Decoder, DecoderException, HighFunction, HighVariable, PcodeFactory, PcodeOp, Varnode,
    ATTRIB_COLOR, ATTRIB_CONTENT, ELEM_BITFIELD, ELEM_BREAK, ELEM_COMMENT, ELEM_FIELD,
    ELEM_FUNCNAME, ELEM_LABEL, ELEM_OP, ELEM_SYNTAX, ELEM_TYPE, ELEM_VALUE, ELEM_VARIABLE,
};
use crate::program::model::scalar::scalar::Scalar;
use crate::program::seam_stubs::HighSymbol;

/// Syntax-highlight color of a keyword. Port of `ClangToken.KEYWORD_COLOR`.
///
/// These constants must match the Decompiler's `syntax_highlight` values.
pub const KEYWORD_COLOR: i32 = 0;
/// Port of `ClangToken.COMMENT_COLOR`.
pub const COMMENT_COLOR: i32 = 1;
/// Port of `ClangToken.TYPE_COLOR`.
pub const TYPE_COLOR: i32 = 2;
/// Port of `ClangToken.FUNCTION_COLOR`.
pub const FUNCTION_COLOR: i32 = 3;
/// Port of `ClangToken.VARIABLE_COLOR`.
pub const VARIABLE_COLOR: i32 = 4;
/// Port of `ClangToken.CONST_COLOR`.
pub const CONST_COLOR: i32 = 5;
/// Port of `ClangToken.PARAMETER_COLOR`.
pub const PARAMETER_COLOR: i32 = 6;
/// Port of `ClangToken.GLOBAL_COLOR`.
pub const GLOBAL_COLOR: i32 = 7;
/// Port of `ClangToken.DEFAULT_COLOR`.
pub const DEFAULT_COLOR: i32 = 8;
/// Port of `ClangToken.ERROR_COLOR`.
pub const ERROR_COLOR: i32 = 9;
/// Port of `ClangToken.SPECIAL_COLOR`.
pub const SPECIAL_COLOR: i32 = 10;
/// One past the largest legal color code. Port of `ClangToken.MAX_COLOR`.
pub const MAX_COLOR: i32 = 11;

/// Which `ClangToken` subclass a token stands for, standing in for Java's `instanceof` checks
/// while those subclasses are unported.
///
/// [`PrettyPrinter::get_text`](crate::app::decompiler::pretty_printer::PrettyPrinter::get_text) is
/// the only place this crate currently distinguishes subclasses -- it name-transforms
/// `ClangFuncNameToken`/`ClangVariableToken`/`ClangTypeToken`/`ClangFieldToken`/`ClangLabelToken`
/// and leaves everything else alone. `Generic` covers every other subclass (`ClangOpToken`,
/// `ClangSyntaxToken`, `ClangBreak`, ...). Once a subclass is ported it should carry its identity
/// in its own type and override [`ClangToken::kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClangTokenKind {
    Generic,
    FuncName,
    Variable,
    Type,
    Field,
    Label,
}

/// The shared state and concrete behaviour of `ghidra.app.decompiler.ClangToken`.
///
/// Directly usable as a token in its own right (mirroring `new ClangToken(par)`), and embedded by
/// each ported subclass, which reaches it through [`ClangToken::base`]/[`ClangToken::base_mut`].
pub struct ClangTokenBase {
    parent: Option<Arc<dyn ClangNode>>,
    /// The line number of the [`ClangLine`] this token belongs to, or `None` if it hasn't been
    /// added to one.
    ///
    /// Java holds the `ClangLine` itself here, but a `ClangLine` owns its tokens, so a real
    /// back-pointer would be a self-reference. The line number is what identifies the line, so
    /// that is what is retained; see [`ClangToken::get_line_parent`].
    line_parent: Option<i32>,
    text: String,
    syntax_type: i32,
    matching_token: bool,
    kind: ClangTokenKind,
}

impl ClangTokenBase {
    /// Port of `ClangToken(ClangNode)`. The text starts out empty (Java starts it as `null`;
    /// `getText()` is typed as a plain `String` here, so the empty string stands in for the
    /// not-yet-decoded state).
    pub fn new(par: Option<Arc<dyn ClangNode>>) -> Self {
        Self {
            parent: par,
            line_parent: None,
            text: String::new(),
            syntax_type: DEFAULT_COLOR,
            matching_token: false,
            kind: ClangTokenKind::Generic,
        }
    }

    /// Port of `ClangToken(ClangNode, String)`.
    pub fn with_text(par: Option<Arc<dyn ClangNode>>, txt: impl Into<String>) -> Self {
        Self {
            text: txt.into(),
            ..Self::new(par)
        }
    }

    /// Port of `ClangToken(ClangNode, String, int)`.
    pub fn with_color(
        par: Option<Arc<dyn ClangNode>>,
        txt: impl Into<String>,
        color: i32,
    ) -> Self {
        Self {
            syntax_type: color,
            ..Self::with_text(par, txt)
        }
    }

    /// Build a token that stands in for one of the unported `ClangToken` subclasses, tagged with
    /// the [`ClangTokenKind`] callers use in place of `instanceof`. Has no Java counterpart --
    /// Java constructs the subclass itself.
    pub fn with_kind(
        par: Option<Arc<dyn ClangNode>>,
        txt: impl Into<String>,
        kind: ClangTokenKind,
        color: i32,
    ) -> Self {
        Self {
            kind,
            ..Self::with_color(par, txt, color)
        }
    }

    /// Decode one specialized token from the current position in an encoded stream. This serves
    /// as a factory for allocating the various objects derived from `ClangToken`. Port of
    /// `ClangToken.buildToken(int, ClangNode, Decoder, PcodeFactory)`.
    ///
    /// Java allocates a different subclass per element id; those subclasses are not ported yet,
    /// so every recognized id yields a [`ClangTokenBase`] carrying the corresponding
    /// [`ClangTokenKind`] (`Generic` where the subclass isn't one callers distinguish). The
    /// element-id validation -- and hence the `DecoderException` for anything else -- is faithful,
    /// as is decoding the token's own attributes.
    pub fn build_token(
        node: i32,
        par: Option<Arc<dyn ClangNode>>,
        decoder: &dyn Decoder,
        pfactory: &dyn PcodeFactory,
    ) -> Result<Box<dyn ClangToken>, DecoderException> {
        let kind = if node == ELEM_VARIABLE.id {
            ClangTokenKind::Variable
        } else if node == ELEM_FUNCNAME.id {
            ClangTokenKind::FuncName
        } else if node == ELEM_TYPE.id {
            ClangTokenKind::Type
        } else if node == ELEM_LABEL.id {
            ClangTokenKind::Label
        } else if node == ELEM_FIELD.id {
            ClangTokenKind::Field
        } else if node == ELEM_OP.id
            || node == ELEM_SYNTAX.id
            || node == ELEM_BREAK.id
            || node == ELEM_COMMENT.id
            || node == ELEM_BITFIELD.id
            || node == ELEM_VALUE.id
        {
            ClangTokenKind::Generic
        } else {
            return Err(DecoderException::new("Expecting token element"));
        };

        let mut token = ClangTokenBase::new(par);
        token.kind = kind;
        token.decode(decoder, pfactory)?;
        Ok(Box::new(token))
    }

    /// Build a spacer token indenting `indent` levels, each level being `indent_str`. Port of
    /// `ClangToken.buildSpacer(ClangNode, int, String)` (which builds a `ClangSyntaxToken`; that
    /// subclass adds only open/close brace bookkeeping, which a spacer never uses).
    pub fn build_spacer(
        par: Option<Arc<dyn ClangNode>>,
        indent: i32,
        indent_str: &str,
    ) -> ClangTokenBase {
        ClangTokenBase::with_text(par, indent_str.repeat(indent.max(0) as usize))
    }
}

impl ClangNode for ClangTokenBase {
    /// Port of `ClangToken.Parent()`.
    fn parent(&self) -> Option<&dyn ClangNode> {
        self.parent.as_deref()
    }

    /// Port of `ClangToken.getMinAddress()`: a bare token has no address.
    fn get_min_address(&self) -> Option<Address> {
        None
    }

    /// Port of `ClangToken.getMaxAddress()`: a bare token has no address.
    fn get_max_address(&self) -> Option<Address> {
        None
    }

    /// Port of `ClangToken.numChildren()`: a token is a leaf.
    fn num_children(&self) -> usize {
        0
    }

    /// Port of `ClangToken.Child(int)`, which always returns `null`.
    ///
    /// # Panics
    /// Always -- a token has no children, so there is no reference to hand back.
    fn child(&self, i: usize) -> &dyn ClangNode {
        panic!("ClangToken has no children, requested index {i}")
    }

    /// Port of `ClangToken.getClangFunction()`.
    ///
    /// # Panics
    /// Panics if this token has no parent, mirroring the `null` Java returns in that case (and
    /// matching [`ClangTokenGroup::get_clang_function`](crate::app::decompiler::ClangTokenGroup)).
    fn get_clang_function(&self) -> Box<dyn ClangFunction> {
        self.parent
            .as_ref()
            .expect("ClangToken.getClangFunction() called with no parent")
            .get_clang_function()
    }

    /// Port of `ClangToken.flatten(List<ClangNode>)`: a token flattens to itself.
    fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
        list.push(self);
    }
}

impl std::fmt::Display for ClangTokenBase {
    /// Port of `ClangToken.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text)
    }
}

/// The operations a `ClangToken` subclass overrides, plus the shared accessors over
/// [`ClangTokenBase`].
///
/// Every method below has the base-class behaviour as its default, so a subclass overrides only
/// what Java's subclass overrides.
pub trait ClangToken: ClangNode {
    /// The shared token state. Implementors return their embedded [`ClangTokenBase`].
    fn base(&self) -> &ClangTokenBase;

    /// Mutable counterpart of [`base`](Self::base).
    fn base_mut(&mut self) -> &mut ClangTokenBase;

    /// Get the line number of the line of text containing this token, or `None` if it isn't part
    /// of a line yet. Port of `ClangToken.getLineParent()`, which returns the `ClangLine` itself;
    /// see [`ClangTokenBase::line_parent`](ClangTokenBase) for why only the number is kept.
    fn get_line_parent(&self) -> Option<i32> {
        self.base().line_parent
    }

    /// Set (change) the line which this text element is part of. Port of
    /// `ClangToken.setLineParent(ClangLine)`.
    fn set_line_parent(&mut self, line: &ClangLine) {
        self.base_mut().line_parent = Some(line.get_line_number());
    }

    /// Whether this token has been added to a [`ClangLine`].
    fn has_line_parent(&self) -> bool {
        self.base().line_parent.is_some()
    }

    /// Set whether or not additional "matching" highlighting is applied to this token. Currently
    /// this means a bounding box is drawn around the token. Port of
    /// `ClangToken.setMatchingToken(boolean)`.
    fn set_matching_token(&mut self, matching_token: bool) {
        self.base_mut().matching_token = matching_token;
    }

    /// `true` if this token should be displayed with "matching" highlighting. Port of
    /// `ClangToken.isMatchingToken()`.
    fn is_matching_token(&self) -> bool {
        self.base().matching_token
    }

    /// Get the "syntax" type (color) associated with this token (keyword, type, etc). Port of
    /// `ClangToken.getSyntaxType()`.
    fn get_syntax_type(&self) -> i32 {
        self.base().syntax_type
    }

    /// Set the "syntax" type (color) associated with this token. Port of the package-private
    /// `ClangToken.setSyntaxType(int)`.
    fn set_syntax_type(&mut self, syntax_type: i32) {
        self.base_mut().syntax_type = syntax_type;
    }

    /// This token's display text. Port of `ClangToken.getText()`.
    fn get_text(&self) -> &str {
        &self.base().text
    }

    /// Set this token's display text. Port of the package-private
    /// `ClangToken.setText(String)`.
    fn set_text(&mut self, text: &str) {
        self.base_mut().text = text.to_string();
    }

    /// Which `ClangToken` subclass this token stands for. See [`ClangTokenKind`]; this has no
    /// Java counterpart (Java uses `instanceof`).
    fn kind(&self) -> ClangTokenKind {
        self.base().kind
    }

    /// `true` if this token represents a variable (in source code). Port of
    /// `ClangToken.isVariableRef()`.
    fn is_variable_ref(&self) -> bool {
        false
    }

    /// The high-level variable associated with this token, or `None`. Port of
    /// `ClangToken.getHighVariable()`.
    fn get_high_variable(&self) -> Option<Arc<dyn HighVariable>> {
        None
    }

    /// The symbol associated with this token, or `None`. The token may be directly associated
    /// with the symbol or with a reference, in which case the symbol is looked up in the
    /// containing `HighFunction`. Port of `ClangToken.getHighSymbol(HighFunction)`.
    fn get_high_symbol(&self, high_function: &dyn HighFunction) -> Option<Arc<dyn HighSymbol>> {
        let _ = high_function;
        None
    }

    /// The variable (`Varnode`) in the data-flow this token represents, or `None`. Port of
    /// `ClangToken.getVarnode()`.
    fn get_varnode(&self) -> Option<&Varnode> {
        None
    }

    /// The p-code operator in the data-flow this token represents, or `None`. Port of
    /// `ClangToken.getPcodeOp()`.
    fn get_pcode_op(&self) -> Option<&PcodeOp> {
        None
    }

    /// The underlying integer constant this token represents, or `None`. Port of
    /// `ClangToken.getScalar()`.
    fn get_scalar(&self) -> Option<Scalar> {
        None
    }

    /// Decode this token from the current position in an encoded stream. Port of
    /// `ClangToken.decode(Decoder, PcodeFactory)`.
    ///
    /// `pfactory` is unused by the base implementation; subclasses use it to look up the p-code
    /// objects their attributes reference.
    fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pfactory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException> {
        let _ = pfactory;
        let base = self.base_mut();
        base.syntax_type = DEFAULT_COLOR;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_COLOR.id {
                base.syntax_type = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
                break;
            }
        }
        base.text = decoder
            .read_string_with_id(ATTRIB_CONTENT)
            .map_err(decode_err)?;
        if base.syntax_type < 0 || base.syntax_type >= MAX_COLOR {
            base.syntax_type = DEFAULT_COLOR;
        }
        Ok(())
    }
}

impl ClangToken for ClangTokenBase {
    fn base(&self) -> &ClangTokenBase {
        self
    }

    fn base_mut(&mut self) -> &mut ClangTokenBase {
        self
    }
}

fn decode_err(e: crate::program::model::pcode::DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode ClangToken", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::pcode::DecoderError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`Decoder`] that replays a scripted attribute stream: `attribs` are handed out one per
    /// `getNextAttributeId()` call (terminated by a `0`), `color` answers
    /// `readUnsignedInteger()`, and `content` answers `readString(ATTRIB_CONTENT)`.
    struct ScriptedDecoder {
        attribs: Vec<i32>,
        idx: AtomicUsize,
        color: u64,
        content: String,
    }

    impl ScriptedDecoder {
        fn new(attribs: Vec<i32>, color: u64, content: &str) -> Self {
            Self {
                attribs,
                idx: AtomicUsize::new(0),
                color,
                content: content.to_string(),
            }
        }
    }

    impl Decoder for ScriptedDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let i = self.idx.fetch_add(1, Ordering::SeqCst);
            Ok(self.attribs.get(i).copied().unwrap_or(0))
        }
        fn rewind_attributes(&self) {
            self.idx.store(0, Ordering::SeqCst);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_signed_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<i64, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            Ok(self.color)
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            Ok(self.content.clone())
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            Ok(self.content.clone())
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct StubPcodeFactory;

    impl PcodeFactory for StubPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_data_type_manager(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::PcodeDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn new_varnode_with_ref(&self, _sz: i32, _addr: Address, _ref_id: i32) -> Varnode {
            unimplemented!("not exercised by these tests")
        }
        fn get_join_address(
            &self,
            _storage: &dyn crate::program::model::listing::variable_storage::VariableStorage,
        ) -> Option<Address> {
            unimplemented!("not exercised by these tests")
        }
        fn build_storage(
            &self,
            _vn: &Varnode,
        ) -> Result<
            Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_ref(&self, _refid: i32) -> Option<Varnode> {
            unimplemented!("not exercised by these tests")
        }
        fn get_op_ref(&self, _refid: i32) -> Option<PcodeOp> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn HighSymbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn new_op(
            &self,
            _sq: crate::program::model::pcode::SequenceNumber,
            _opc: crate::program::model::pcode::OpCode,
            _inputs: Vec<Varnode>,
            _output: Option<Varnode>,
        ) -> PcodeOp {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn color_constants_match_decompiler_syntax_highlight_values() {
        // Constants must match the Decompiler's syntax_highlight numbering.
        assert_eq!(
            [
                KEYWORD_COLOR,
                COMMENT_COLOR,
                TYPE_COLOR,
                FUNCTION_COLOR,
                VARIABLE_COLOR,
                CONST_COLOR,
                PARAMETER_COLOR,
                GLOBAL_COLOR,
                DEFAULT_COLOR,
                ERROR_COLOR,
                SPECIAL_COLOR,
                MAX_COLOR,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
    }

    #[test]
    fn constructors_default_to_default_color_and_no_line_parent() {
        let plain = ClangTokenBase::new(None);
        assert_eq!(plain.get_syntax_type(), DEFAULT_COLOR);
        assert_eq!(plain.get_text(), "");
        assert_eq!(plain.get_line_parent(), None);
        assert!(!plain.is_matching_token());

        let texted = ClangTokenBase::with_text(None, "int");
        assert_eq!(texted.get_text(), "int");
        assert_eq!(texted.get_syntax_type(), DEFAULT_COLOR);

        let colored = ClangTokenBase::with_color(None, "x", VARIABLE_COLOR);
        assert_eq!(colored.get_text(), "x");
        assert_eq!(colored.get_syntax_type(), VARIABLE_COLOR);
    }

    #[test]
    fn base_token_is_an_addressless_childless_leaf() {
        let token = ClangTokenBase::with_text(None, "if");
        assert_eq!(token.get_min_address(), None);
        assert_eq!(token.get_max_address(), None);
        assert_eq!(token.num_children(), 0);
        assert!(token.parent().is_none());
        assert!(!token.is_variable_ref());
        assert!(token.get_varnode().is_none());
        assert!(token.get_pcode_op().is_none());
        assert!(token.get_high_variable().is_none());
        assert!(token.get_scalar().is_none());

        let mut flat: Vec<&dyn ClangNode> = Vec::new();
        token.flatten(&mut flat);
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].to_string(), "if");
    }

    #[test]
    fn set_line_parent_records_the_lines_number() {
        let line = ClangLine::new(42, 0);
        let mut token = ClangTokenBase::with_text(None, "x");
        assert!(!token.has_line_parent());
        token.set_line_parent(&line);
        assert_eq!(token.get_line_parent(), Some(42));
        assert!(token.has_line_parent());
    }

    #[test]
    fn decode_reads_color_then_content() {
        let decoder = ScriptedDecoder::new(vec![ATTRIB_COLOR.id], CONST_COLOR as u64, "0x1f");
        let mut token = ClangTokenBase::new(None);
        token
            .decode(&decoder, &StubPcodeFactory)
            .expect("decode should succeed");
        assert_eq!(token.get_syntax_type(), CONST_COLOR);
        assert_eq!(token.get_text(), "0x1f");
    }

    #[test]
    fn decode_skips_unrelated_attributes_and_defaults_the_color() {
        // Attributes other than "color" are stepped over; with none present the color stays
        // DEFAULT_COLOR.
        let decoder = ScriptedDecoder::new(
            vec![ATTRIB_CONTENT.id, crate::program::model::pcode::ATTRIB_ID.id],
            SPECIAL_COLOR as u64,
            "while",
        );
        let mut token = ClangTokenBase::with_color(None, "stale", ERROR_COLOR);
        token
            .decode(&decoder, &StubPcodeFactory)
            .expect("decode should succeed");
        assert_eq!(token.get_syntax_type(), DEFAULT_COLOR);
        assert_eq!(token.get_text(), "while");
    }

    #[test]
    fn decode_clamps_out_of_range_color_to_default() {
        let decoder = ScriptedDecoder::new(vec![ATTRIB_COLOR.id], MAX_COLOR as u64, "junk");
        let mut token = ClangTokenBase::new(None);
        token
            .decode(&decoder, &StubPcodeFactory)
            .expect("decode should succeed");
        assert_eq!(token.get_syntax_type(), DEFAULT_COLOR);
    }

    #[test]
    fn build_token_dispatches_on_element_id_and_decodes() {
        let cases = [
            (ELEM_VARIABLE.id, ClangTokenKind::Variable),
            (ELEM_FUNCNAME.id, ClangTokenKind::FuncName),
            (ELEM_TYPE.id, ClangTokenKind::Type),
            (ELEM_LABEL.id, ClangTokenKind::Label),
            (ELEM_FIELD.id, ClangTokenKind::Field),
            (ELEM_OP.id, ClangTokenKind::Generic),
            (ELEM_SYNTAX.id, ClangTokenKind::Generic),
            (ELEM_BREAK.id, ClangTokenKind::Generic),
            (ELEM_COMMENT.id, ClangTokenKind::Generic),
            (ELEM_BITFIELD.id, ClangTokenKind::Generic),
            (ELEM_VALUE.id, ClangTokenKind::Generic),
        ];
        for (elem, expected_kind) in cases {
            let decoder = ScriptedDecoder::new(vec![ATTRIB_COLOR.id], TYPE_COLOR as u64, "tok");
            let token = ClangTokenBase::build_token(elem, None, &decoder, &StubPcodeFactory)
                .expect("known token element should decode");
            assert_eq!(token.kind(), expected_kind, "element id {elem}");
            assert_eq!(token.get_text(), "tok");
            assert_eq!(token.get_syntax_type(), TYPE_COLOR);
        }
    }

    #[test]
    fn build_token_rejects_a_non_token_element() {
        let decoder = ScriptedDecoder::new(vec![], DEFAULT_COLOR as u64, "");
        let result = ClangTokenBase::build_token(
            crate::program::model::pcode::ELEM_BLOCK.id,
            None,
            &decoder,
            &StubPcodeFactory,
        );
        let err = match result {
            Err(e) => e,
            Ok(tok) => panic!("a group element is not a token element, got {tok}"),
        };
        assert!(err.to_string().contains("Expecting token element"));
    }

    #[test]
    fn build_spacer_repeats_the_indent_string_per_level() {
        let spacer = ClangTokenBase::build_spacer(None, 3, "  ");
        assert_eq!(spacer.get_text(), "      ");
        assert_eq!(ClangTokenBase::build_spacer(None, 0, "  ").get_text(), "");
    }

    #[test]
    fn display_is_the_token_text() {
        assert_eq!(ClangTokenBase::with_text(None, "return").to_string(), "return");
    }

    #[test]
    fn setters_update_the_shared_state() {
        let mut token = ClangTokenBase::new(None);
        token.set_text("else");
        token.set_syntax_type(KEYWORD_COLOR);
        token.set_matching_token(true);
        assert_eq!(token.get_text(), "else");
        assert_eq!(token.get_syntax_type(), KEYWORD_COLOR);
        assert!(token.is_matching_token());
    }
}
