//! Port of `ghidra.program.model.pcode.HighFunction`.
//!
//! High-level abstraction associated with a low-level function made up of assembly instructions,
//! based on information the decompiler has produced after working on a function.
//!
//! The Java class `extends PcodeSyntaxTree`, whose real port does not exist yet (not even as a
//! placeholder -- the same convention already followed by
//! [`HighParamID`](crate::program::model::pcode::high_param_id::HighParamID) and
//! [`DynamicHash`](crate::program::model::pcode::dynamic_hash::DynamicHash)'s module docs), so
//! this class was selected as a dependency-cycle cut-point and is modeled as a trait rather than a
//! concrete struct. This promotes the minimal placeholder that used to live in `seam_stubs.rs`
//! (see `STUBS.tsv`); every existing importer keeps compiling against the methods that placeholder
//! already exposed ([`get_function`](HighFunction::get_function),
//! [`get_function_prototype`](HighFunction::get_function_prototype),
//! [`get_compiler_spec`](HighFunction::get_compiler_spec),
//! [`get_local_symbol_map`](HighFunction::get_local_symbol_map),
//! [`get_global_symbol_map`](HighFunction::get_global_symbol_map),
//! [`get_pc_address`](HighFunction::get_pc_address)), with additional public API filled in below.
//!
//! [`JumpTable`](crate::program::seam_stubs::JumpTable) is a new, empty placeholder in
//! `seam_stubs.rs` (`HighFunction` only ever passes it through opaquely via
//! [`get_jump_tables`](HighFunction::get_jump_tables), never calling a member on it), and
//! [`LocalSymbolMap`](crate::program::seam_stubs::LocalSymbolMap) was grown with
//! [`find_local`](crate::program::seam_stubs::LocalSymbolMap::find_local) for
//! [`get_mapped_symbol`](HighFunction::get_mapped_symbol); see `STUBS.tsv`.
//!
//! Not modeled with a default body, each documented at its own definition:
//! - [`grab_from_function`](HighFunction::grab_from_function), [`decode`](HighFunction::decode),
//!   [`encode`](HighFunction::encode), [`split_out_merge_group`](HighFunction::split_out_merge_group),
//!   [`set_volatile`](HighFunction::set_volatile), and [`get_id`](HighFunction::get_id) are all
//!   required methods with no default body: each mutates private state
//!   (`jumpTables`/`protoOverrides`/`localSymbols`/`globalSymbols`) or depends on collaborators
//!   (`PcodeSyntaxTree`'s AST decode/encode, `AddressXML`, `PcodeDataTypeManager`, the real
//!   `HighLocal`/`HighParam`/`HighOther` subtypes, a `SymbolTable` capable of resolving a dynamic
//!   symbol id) that are not reachable generically here, the same convention already followed by
//!   [`HighParamID::decode`](crate::program::model::pcode::high_param_id::HighParamID::decode) and
//!   [`FunctionPrototype::decode_prototype`](crate::program::model::pcode::function_prototype::FunctionPrototype::decode_prototype).
//! - The constructor is construction-time plumbing, not modeled (same convention as
//!   `FunctionPrototype`/`HighParamID`).
//! - The private `grabOverrides`/`decodeHigh`/`decodeHighlist`/`decodeJumpTableList` helpers are
//!   not modeled separately; they are implementation details of
//!   [`grab_from_function`](HighFunction::grab_from_function)/[`decode`](HighFunction::decode).
//! - The static namespace-management helpers `findNamespace`, `createLabelSymbol`, `deleteSymbol`,
//!   `clearNamespace`, and `findCreateNamespace` are not modeled: each needs a namespace-scoped
//!   `SymbolTable` query/mutation (`getNamespace(String, Namespace)`, `createNameSpace`,
//!   `getSymbol(String, Address, Namespace)`, `removeSymbolSpecial`, `getSymbols(Namespace)`) that
//!   the already-ported [`SymbolTable`](crate::program::model::symbol::SymbolTable) trait does not
//!   expose yet; per
//!   [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)'s
//!   own precedent for `changeConflictingSymbolNames`/`setGlobalName`, growing that trait is left
//!   until those capabilities are actually needed by a concrete implementor.
//! - [`find_override_space`] and [`find_create_override_space`] (the latter moved here from its
//!   former home as `seam_stubs::high_function_find_create_override_space`) are kept as free
//!   functions always returning `None` for the same reason: both need mutable `SymbolTable` access
//!   via `Function::get_program()`'s `Arc<dyn Program>`, which cannot yield `&mut dyn Program`.
//! - [`is_override_namespace`], [`collapse_to_global`], [`encode_namespace`], and
//!   [`tag_find_exclude`] *are* fully portable pure algorithms over already-ported
//!   `Namespace`/`Encoder`/`NameTransformer` (or, for `tag_find_exclude`, plain strings), so they
//!   are ported faithfully as free functions with real tests below.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::lang::{CompilerSpec, Language};
use crate::program::model::listing::Function;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::function_prototype::FunctionPrototype;
use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
use crate::program::model::pcode::high_variable::HighVariable;
use crate::program::model::pcode::ids::{ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_LABEL, ELEM_PARENT, ELEM_VAL};
use crate::program::model::pcode::pcode_exception::PcodeException;
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{NameTransformer, Namespace, NamespaceType};
use crate::program::seam_stubs::{HighSymbol, JumpTable, LocalSymbolMap};

/// Port of `HighFunction.DECOMPILER_TAG_MAP`. Not re-exported from the `pcode` module root since
/// it would collide with the identically-named
/// [`high_param_id::DECOMPILER_TAG_MAP`](crate::program::model::pcode::high_param_id::DECOMPILER_TAG_MAP)
/// (both Java classes independently declare the same constant).
pub const DECOMPILER_TAG_MAP: &str = "decompiler_tags";

/// Port of `HighFunction.OVERRIDE_NAMESPACE_NAME`.
pub const OVERRIDE_NAMESPACE_NAME: &str = "override";

/// High-level abstraction associated with a low-level function made up of assembly instructions,
/// based on information the decompiler has produced after working on a function.
///
/// Port of `ghidra.program.model.pcode.HighFunction`. See the module docs for what was
/// intentionally left out of this trait.
pub trait HighFunction: Send + Sync {
    /// Get the associated low level function. Port of `HighFunction.getFunction()`.
    fn get_function(&self) -> Box<dyn Function>;

    /// Get the id associated with the function symbol, if it exists, otherwise a dynamic id based
    /// on the entry point. See the module docs for why this has no default body.
    ///
    /// Port of `HighFunction.getID()`.
    fn get_id(&self) -> i64;

    /// Get the language parser used to disassemble. Port of `HighFunction.getLanguage()`.
    fn get_language(&self) -> Box<dyn Language>;

    /// Port of `HighFunction.getCompilerSpec()`.
    fn get_compiler_spec(&self) -> Box<dyn CompilerSpec>;

    /// The function prototype for the function (how things are passed/returned). Port of
    /// `HighFunction.getFunctionPrototype()`. Defaults to `None`, mirroring a `HighFunction` built
    /// without a recovered prototype.
    fn get_function_prototype(&self) -> Option<Box<dyn FunctionPrototype>> {
        None
    }

    /// An array of jump table definitions found for this function decompilation. Port of
    /// `HighFunction.getJumpTables()`. Defaults to empty, mirroring a `HighFunction` before/without
    /// any jump table overrides recovered.
    fn get_jump_tables(&self) -> Vec<Box<dyn JumpTable>> {
        Vec::new()
    }

    /// The local variable map describing the defined local variables. Port of
    /// `HighFunction.getLocalSymbolMap()`.
    fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap>;

    /// A map describing global variables accessed by this function. Port of
    /// `HighFunction.getGlobalSymbolMap()`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap>;

    /// Port of `HighFunction.getMappedSymbol(Address, Address)`. Defaults to delegating to
    /// [`LocalSymbolMap::find_local`](crate::program::seam_stubs::LocalSymbolMap::find_local).
    fn get_mapped_symbol(&self, addr: &Address, pcaddr: &Address) -> Option<Arc<dyn HighSymbol>> {
        self.get_local_symbol_map().find_local(addr, pcaddr)
    }

    /// Port of `HighFunction.getSymbol(long)` (overriding the abstract `PcodeSyntaxTree` method of
    /// the same name -- not modeled separately since `PcodeSyntaxTree` itself isn't ported).
    /// Defaults to delegating to
    /// [`LocalSymbolMap::get_symbol`](crate::program::seam_stubs::LocalSymbolMap::get_symbol).
    fn get_symbol(&self, symbol_id: i64) -> Option<Arc<dyn HighSymbol>> {
        self.get_local_symbol_map().get_symbol(symbol_id)
    }

    /// Populate the information for the `HighFunction` from the information in the `Function`
    /// object. See the module docs for why this has no default body.
    ///
    /// `override_extrapop` is the value to use if extrapop is overridden. `include_default_names`
    /// is true if default symbol names should be considered locked. `do_override` is true if
    /// extrapop is overridden.
    ///
    /// Port of `HighFunction.grabFromFunction(int, boolean, boolean)`.
    fn grab_from_function(
        &mut self,
        override_extrapop: i32,
        include_default_names: bool,
        do_override: bool,
    );

    /// Decode this `HighFunction` from a stream. See the module docs for why this has no default
    /// body.
    ///
    /// Port of `HighFunction.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException>;

    /// Instruction address the given varnode comes into scope within the function. Port of the
    /// protected `HighFunction.getPCAddress(Varnode)`. Defaults to `None`; the real algorithm needs
    /// the `VarnodeAST`-specific `isAddrTied()`/`getPCAddress()` state that this crate's plain
    /// [`Varnode`] does not carry, so concrete implementors backed by a real AST are expected to
    /// override this (matching the precedent set when this method was first added to the
    /// placeholder for
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode)).
    fn get_pc_address(&self, representative: &Varnode) -> Option<Address> {
        let _ = representative;
        None
    }

    /// If a `HighVariable` consists of more than one (forced) merge group, split out the group
    /// that contains `vn` as a separate `HighVariable`. See the module docs for why this has no
    /// default body.
    ///
    /// Port of `HighFunction.splitOutMergeGroup(HighVariable, Varnode)`.
    ///
    /// # Errors
    /// Returns an error if the split can't be performed.
    fn split_out_merge_group(
        &mut self,
        high: Box<dyn HighVariable>,
        vn: &Varnode,
    ) -> Result<Box<dyn HighVariable>, PcodeException>;

    /// Encode this `HighFunction` to a stream. The size describes how many bytes starting from the
    /// entry point are used by the function. See the module docs for why this has no default body.
    ///
    /// `entry_point` of `None` uses the function's own entry point; `Some` forces the given entry
    /// point instead. `size` describes how many bytes the function occupies as code.
    ///
    /// Port of `HighFunction.encode(Encoder, long, Namespace, Address, int)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(
        &self,
        encoder: &mut dyn Encoder,
        id: i64,
        namespace: &dyn Namespace,
        entry_point: Option<Address>,
        size: i32,
    ) -> io::Result<()>;

    /// Mark a varnode as volatile (or not). Port of `HighFunction.setVolatile(Varnode, boolean)`
    /// (overriding the abstract `PcodeSyntaxTree` method of the same name). See the module docs
    /// for why this has no default body: marking a varnode volatile gives the
    /// [`GlobalSymbolMap`](crate::program::seam_stubs::GlobalSymbolMap) a chance to populate an
    /// annotation, which needs mutable access that this trait's `Arc<dyn GlobalSymbolMap>`-returning
    /// [`get_global_symbol_map`](HighFunction::get_global_symbol_map) cannot provide.
    fn set_volatile(&mut self, vn: &Varnode, val: bool);
}

/// The decompiler treats some namespaces as equivalent to the "global" namespace. Returns true if
/// `namespace` is treated as equivalent (i.e. is a
/// [`Library`](crate::program::model::listing::Library)).
///
/// Port of the static `HighFunction.collapseToGlobal(Namespace)`.
pub fn collapse_to_global(namespace: &dyn Namespace) -> bool {
    namespace.get_type() == NamespaceType::Library
}

/// Port of the static `HighFunction.isOverrideNamespace(Namespace)`.
pub fn is_override_namespace(namespace: &dyn Namespace) -> bool {
    if namespace.get_name() != OVERRIDE_NAMESPACE_NAME {
        return false;
    }
    namespace
        .get_parent_namespace()
        .map(|parent| parent.get_type() == NamespaceType::Function)
        .unwrap_or(false)
}

/// Port of the static `HighFunction.findOverrideSpace(Function)`. The real method looks up the
/// function's program symbol table's `"override"` child namespace; this needs mutable
/// `SymbolTable` access via `Function::get_program()`'s `Arc<dyn Program>`, unreachable here for
/// the same reason documented on several
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// helpers (e.g. its `changeConflictingSymbolNames`/`setGlobalName` stand-ins) -- always returns
/// `None` until that access path is ported.
pub fn find_override_space(function: &dyn Function) -> Option<Arc<dyn Namespace>> {
    let _ = function;
    None
}

/// Port of the static `HighFunction.findCreateOverrideSpace(Function)`. Moved here from its former
/// home as `seam_stubs::high_function_find_create_override_space` now that `HighFunction` itself
/// is ported; see [`find_override_space`] for why this always returns `None`.
pub fn find_create_override_space(function: &mut dyn Function) -> Option<Arc<dyn Namespace>> {
    let _ = function;
    None
}

/// Encode a `<parent>` element to the stream describing the formal path elements from the root
/// (global) namespace up to the given namespace.
///
/// Port of the static `HighFunction.encodeNamespace(Encoder, Namespace, NameTransformer)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_namespace(
    encoder: &mut dyn Encoder,
    namespace: Option<&dyn Namespace>,
    transformer: &dyn NameTransformer,
) -> io::Result<()> {
    encoder.open_element(ELEM_PARENT)?;
    if let Some(namespace) = namespace {
        struct Scope {
            id: i64,
            name: String,
        }

        // Walk from `namespace` up to (and including) the root/library scope, mirroring Java's
        // `arr.add(0, curspc)` loop; built innermost-first here and reversed below to match `arr`'s
        // final outermost-first order.
        let mut chain = vec![Scope {
            id: namespace.get_id(),
            name: namespace.get_name(),
        }];
        let mut current = if collapse_to_global(namespace) {
            None
        } else {
            namespace.get_parent_namespace()
        };
        while let Some(scope) = current {
            chain.push(Scope {
                id: scope.get_id(),
                name: scope.get_name(),
            });
            if collapse_to_global(scope.as_ref()) {
                break;
            }
            current = scope.get_parent_namespace();
        }
        chain.reverse();

        encoder.open_element(ELEM_VAL)?; // Force global scope to have empty name
        encoder.close_element(ELEM_VAL)?;

        for scope in chain.iter().skip(1) {
            encoder.open_element(ELEM_VAL)?;
            encoder.write_unsigned_integer(ATTRIB_ID, scope.id as u64)?;
            let alt_name = transformer.simplify(&scope.name);
            if alt_name.as_ref() != scope.name {
                encoder.write_string(ATTRIB_LABEL, alt_name.as_ref())?;
            }
            encoder.write_string(ATTRIB_CONTENT, &scope.name)?;
            encoder.close_element(ELEM_VAL)?;
        }
    }
    encoder.close_element(ELEM_PARENT)?;
    Ok(())
}

/// Returns all characters between the beginning and ending XML tags named `tagname`, excluding the
/// tags themselves, or `None` if `doc` is `None` or the opening tag cannot be found (well-formed)
/// within it. Assumes `tagname` is ASCII and the opening tag has no attributes (`"<tagname>"` or
/// self-closing `"<tagname/>"`), matching the only way this is used in Ghidra.
///
/// Port of the static `HighFunction.tagFindExclude(String, String)`.
pub fn tag_find_exclude(tagname: &str, doc: Option<&str>) -> Option<String> {
    let doc = doc?;
    let length = tagname.len();
    let bindex = doc.find(&format!("<{tagname}"))?;
    if bindex + length + 3 > doc.len() {
        return None;
    }
    if doc.as_bytes()[bindex + length + 1] == b'/' {
        return Some(String::new());
    }
    let eindex = doc.find(&format!("</{tagname}>"))?;
    let start = bindex + length + 2;
    if start > eindex {
        return None;
    }
    Some(doc[start..eindex].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::symbol::{SourceType, Symbol, SymbolType};
    use std::collections::HashMap;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockSymbol {
        name: String,
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_addr(0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockNamespace {
        id: i64,
        name: String,
        parent: Option<Arc<dyn Namespace>>,
        ns_type: NamespaceType,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.name.clone(),
                id: self.id,
            })
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
        fn get_type(&self) -> NamespaceType {
            self.ns_type
        }
    }

    #[test]
    fn is_override_namespace_requires_matching_name_and_function_parent() {
        let function_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 1,
            name: "myfunc".to_string(),
            parent: None,
            ns_type: NamespaceType::Function,
        });
        let plain_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 2,
            name: "myns".to_string(),
            parent: None,
            ns_type: NamespaceType::Namespace,
        });

        let good = MockNamespace {
            id: 3,
            name: OVERRIDE_NAMESPACE_NAME.to_string(),
            parent: Some(function_ns.clone()),
            ns_type: NamespaceType::Namespace,
        };
        assert!(is_override_namespace(&good));

        let wrong_name = MockNamespace {
            id: 4,
            name: "other".to_string(),
            parent: Some(function_ns),
            ns_type: NamespaceType::Namespace,
        };
        assert!(!is_override_namespace(&wrong_name));

        let wrong_parent = MockNamespace {
            id: 5,
            name: OVERRIDE_NAMESPACE_NAME.to_string(),
            parent: Some(plain_ns),
            ns_type: NamespaceType::Namespace,
        };
        assert!(!is_override_namespace(&wrong_parent));

        let no_parent = MockNamespace {
            id: 6,
            name: OVERRIDE_NAMESPACE_NAME.to_string(),
            parent: None,
            ns_type: NamespaceType::Namespace,
        };
        assert!(!is_override_namespace(&no_parent));
    }

    #[test]
    fn collapse_to_global_is_true_only_for_library_namespaces() {
        let library = MockNamespace {
            id: 1,
            name: "mylib".to_string(),
            parent: None,
            ns_type: NamespaceType::Library,
        };
        assert!(collapse_to_global(&library));

        let plain = MockNamespace {
            id: 2,
            name: "myns".to_string(),
            parent: None,
            ns_type: NamespaceType::Namespace,
        };
        assert!(!collapse_to_global(&plain));
    }

    #[test]
    fn tag_find_exclude_extracts_body_and_handles_edge_cases() {
        assert_eq!(
            tag_find_exclude("foo", Some("prefix<foo>hello</foo>suffix")),
            Some("hello".to_string())
        );
        assert_eq!(tag_find_exclude("foo", Some("<foo/>")), Some(String::new()));
        assert_eq!(tag_find_exclude("foo", Some("no tags here")), None);
        assert_eq!(tag_find_exclude("foo", None), None);
        assert_eq!(tag_find_exclude("foo", Some("<foo>")), None);
    }

    /// Records every call made to it, so [`encode_namespace`]'s exact output shape can be
    /// verified rather than just checked for success.
    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            Ok(())
        }
        fn write_space_indexed(
            &mut self,
            _attrib_id: AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    struct RenameTransformer;
    impl NameTransformer for RenameTransformer {
        fn simplify<'a>(&self, input: &'a str) -> std::borrow::Cow<'a, str> {
            if input == "child" {
                std::borrow::Cow::Borrowed("renamed_child")
            } else {
                std::borrow::Cow::Borrowed(input)
            }
        }
    }

    #[test]
    fn encode_namespace_writes_only_non_global_scopes_with_labels_when_renamed() {
        let global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 0,
            name: "Global".to_string(),
            parent: None,
            ns_type: NamespaceType::Namespace,
        });
        let child = MockNamespace {
            id: 42,
            name: "child".to_string(),
            parent: Some(global),
            ns_type: NamespaceType::Namespace,
        };

        let mut encoder = RecordingEncoder::default();
        encode_namespace(&mut encoder, Some(&child), &RenameTransformer).unwrap();

        assert_eq!(
            encoder.events,
            vec![
                "open:parent".to_string(),
                "open:val".to_string(),
                "close:val".to_string(),
                "open:val".to_string(),
                "attr:id=42".to_string(),
                "attr:label=renamed_child".to_string(),
                "attr:XMLcontent=child".to_string(),
                "close:val".to_string(),
                "close:parent".to_string(),
            ]
        );
    }

    #[test]
    fn encode_namespace_with_no_namespace_writes_empty_parent() {
        let mut encoder = RecordingEncoder::default();
        encode_namespace(&mut encoder, None, &crate::program::model::symbol::IdentityNameTransformer)
            .unwrap();
        assert_eq!(
            encoder.events,
            vec!["open:parent".to_string(), "close:parent".to_string()]
        );
    }

    struct MockHighSymbol {
        id: i64,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[derive(Default)]
    struct MockLocalSymbolMap {
        symbols: HashMap<i64, Arc<dyn HighSymbol>>,
    }

    impl LocalSymbolMap for MockLocalSymbolMap {
        fn get_param_symbol(&self, _index: i32) -> Arc<dyn HighSymbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_symbol(&self, id: i64) -> Option<Arc<dyn HighSymbol>> {
            self.symbols.get(&id).cloned()
        }
        fn find_local(&self, addr: &Address, _pcaddr: &Address) -> Option<Arc<dyn HighSymbol>> {
            self.symbols.get(&addr.offset()).cloned()
        }
    }

    struct MockHighFunction {
        local_symbols: HashMap<i64, Arc<dyn HighSymbol>>,
    }

    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap> {
            Box::new(MockLocalSymbolMap {
                symbols: self.local_symbols.clone(),
            })
        }
        fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {}
        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            Ok(())
        }
        fn split_out_merge_group(
            &mut self,
            high: Box<dyn HighVariable>,
            _vn: &Varnode,
        ) -> Result<Box<dyn HighVariable>, PcodeException> {
            Ok(high)
        }
        fn encode(
            &self,
            _encoder: &mut dyn Encoder,
            _id: i64,
            _namespace: &dyn Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> io::Result<()> {
            Ok(())
        }
        fn set_volatile(&mut self, _vn: &Varnode, _val: bool) {}
    }

    /// Proves [`HighFunction`] is dyn-object-safe (usable as `Box<dyn HighFunction>`) and that its
    /// default [`HighFunction::get_mapped_symbol`]/[`HighFunction::get_symbol`] correctly delegate
    /// to the underlying [`LocalSymbolMap`] -- real behavior, not a trivially-true assertion.
    #[test]
    fn default_lookup_methods_delegate_to_local_symbol_map() {
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(99, Arc::new(MockHighSymbol { id: 99 }));
        symbols.insert(0x1000, Arc::new(MockHighSymbol { id: 0x1000 }));

        let high_function: Box<dyn HighFunction> = Box::new(MockHighFunction {
            local_symbols: symbols,
        });

        assert_eq!(high_function.get_symbol(99).map(|s| s.get_id()), Some(99));
        assert!(high_function.get_symbol(123).is_none());

        let addr = ram_addr(0x1000);
        let pcaddr = ram_addr(0x2000);
        assert_eq!(
            high_function.get_mapped_symbol(&addr, &pcaddr).map(|s| s.get_id()),
            Some(0x1000)
        );
        assert!(high_function.get_mapped_symbol(&ram_addr(0x9999), &pcaddr).is_none());
    }
}
