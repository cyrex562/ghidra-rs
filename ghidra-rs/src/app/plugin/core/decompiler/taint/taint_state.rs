//! Port of `ghidra.app.plugin.core.decompiler.taint.TaintState`.
//!
//! The interface for the methods that collect desired taint information from the decompiler
//! window and store them for construction of queries and indexing.
//!
//! # Shape
//!
//! Java's `TaintState` is an interface with 27 abstract methods and exactly one in-repo
//! implementor (`AbstractTaintState`, not yet ported), extended by `ExtensionPoint` so the
//! `ClassSearcher` can discover concrete engines at runtime. That is a genuine open extension
//! point, so this ports to a `pub trait TaintState: ExtensionPoint`.
//!
//! `TaintPlugin`, `TaintLabel`, `TaintOptions`, and `TaintQueryResult` are not ported yet;
//! [`TaintState`]'s own methods never call anything on them (they are only held or returned), so
//! minimal marker-trait placeholders live in [`crate::app::seam_stubs`] rather than here.
//!
//! # Static/default methods
//!
//! Java's `newInstance`, `varName`, `getParentToken`, `isActualParam` (all `public static`) and
//! `hvarName` (`private static`) are not part of the polymorphic interface -- they are utility
//! functions, ported here as free functions rather than trait methods:
//!
//! - [`new_instance`] mirrors `newInstance(TaintPlugin, String)`. Java discovers implementations
//!   by scanning the classpath via `ClassSearcher`; this crate has no equivalent runtime scan, so
//!   [`crate::app::seam_stubs::ClassSearcher::get_taint_state_classes`] yields nothing until a
//!   real provider registry exists, and this always takes the "no match" branch that Java takes
//!   whenever the classpath doesn't contain a matching engine.
//! - [`var_name`]/[`hvar_name`] mirror `varName`/`hvarName`. `ClangFieldToken`/`ClangVariableToken`
//!   are represented in this crate as a plain [`ClangToken`] tagged with
//!   [`ClangTokenKind::Field`]/[`ClangTokenKind::Variable`] (see
//!   [`clang_token`](crate::app::decompiler::clang_token)), so the `instanceof` checks become
//!   `kind()` checks. Likewise `HighConstant`/`HighLocal`/`HighGlobal`/`HighOther` are represented
//!   as a plain [`HighVariable`] tagged with [`HighVariableKind`], following the same convention.
//!   The `hv.getRepresentative().getAddress().isUniqueAddress()` branch, which computes `"hv" +
//!   new DynamicHash(rep, hf).getHash()`, cannot be ported: this crate's
//!   [`DynamicHash`](crate::program::model::pcode::dynamic_hash::DynamicHash) is a trait with no
//!   constructible implementation (the real hashing algorithm over the p-code graph is not
//!   ported), so that branch is a documented `None` until one exists. The `HighGlobal` branch's
//!   `fn.getProgram().getSymbolTable().getPrimarySymbol(addr)` lookup is similarly not reachable:
//!   [`Program::get_symbol_table`](crate::program::model::listing::Program::get_symbol_table)
//!   needs `&mut dyn Program`, but [`Function::get_program`] only hands back a shared
//!   `Arc<dyn Program>`, so this falls back to the representative's address the same way Java
//!   does when no primary symbol exists at that address.
//! - [`get_parent_token`] mirrors `getParentToken(ClangFieldToken)`. It downcasts `token.parent()`
//!   to the concrete [`ClangTokenGroup`] via [`ClangNode::as_any`] (added by this port -- Java's
//!   `(ClangTokenGroup) token.Parent()` cast has no Rust equivalent otherwise) and walks
//!   [`ClangTokenGroup::token_iterator`] comparing tokens by pointer identity, mirroring Java's
//!   reference-equality `ftoken.equals(token)` (`ClangToken` does not override `equals`). Every
//!   token this crate currently builds is constructed with `parent: None`
//!   ([`ClangTokenBase::build_token`] never wires it up), so in practice this always takes the
//!   `token.parent()` is `None` short-circuit; see that function's doc for why the "found" branch
//!   is not (yet) exercisable by a test.
//! - [`is_actual_param`] mirrors `isActualParam(ClangToken)` faithfully; both p-code op mnemonics
//!   and varnode equality are fully available in this crate already.

use std::collections::BTreeMap;
use std::path::Path;

use crate::app::decompiler::{ClangNode, ClangToken, ClangTokenGroup, ClangTokenKind};
use crate::app::seam_stubs::{
    ClassSearcher, TaintLabel, TaintOptions, TaintPlugin, TaintQueryResult,
};
use crate::app::services::ConsoleService;
use crate::program::model::address::address_set::AddressSet;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::pcode::{HighVariable, HighVariableKind, PcodeException};
use crate::sarif::SarifSchema210;
use crate::script::seam_stubs::GhidraScript;
use crate::util::classfinder::extension_point::ExtensionPoint;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// The kind of taint mark a [`ClangToken`] can carry. Port of `TaintState.MarkType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkType {
    Source,
    Sink,
    Gate,
}

/// The kind of index query to run. Port of `TaintState.QueryType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    SrcSink,
    Default,
    Custom,
}

/// The kind of update being applied to the taint varnode map. Port of `TaintState.TaskType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    SetTaint,
    SetDelta,
    ApplyDelta,
}

/// The methods that collect desired taint information from the decompiler window and store them
/// for construction of queries and indexing. Port of `TaintState`.
///
/// NOTE: ALL `TaintState` implementors must end in "TaintState". If not, the `ClassSearcher` will
/// not find them (see [`new_instance`]).
pub trait TaintState: ExtensionPoint + Send + Sync {
    fn get_name(&self) -> String;

    /// Perform a Source-Sink query on the index database.
    ///
    /// `query_type` selects the default query (do not build the query from the selected source)
    /// versus one built from the current selection. Returns success.
    fn query_index(&mut self, program: &mut dyn Program, tool: &dyn TaintPlugin, query_type: QueryType) -> bool;

    fn get_query_name(&self) -> String;

    fn toggle_mark(
        &mut self,
        mtype: MarkType,
        token: &dyn ClangToken,
    ) -> Result<Box<dyn TaintLabel>, PcodeException>;

    fn get_taint_labels(&self, mtype: MarkType) -> Vec<Box<dyn TaintLabel>>;

    fn is_valid(&self) -> bool;

    fn get_taint_address_set(&self) -> AddressSet;

    fn set_taint_address_set(&mut self, aset: AddressSet);

    fn augment_address_set(&mut self, token: &dyn ClangToken);

    fn clear_taint(&mut self);

    fn is_sink(&self, hvar: &dyn HighVariable) -> bool;

    fn clear_markers(&mut self);

    fn load_taint_data(&mut self, program: &mut dyn Program, sarif_file: &Path);

    fn get_data(&self) -> Option<SarifSchema210>;

    fn clear_data(&mut self);

    fn get_options(&self) -> Box<dyn TaintOptions>;

    /// Predicate that indicates there are sources, sinks, or gates.
    fn has_marks(&self) -> bool;

    fn set_monitor(&mut self, monitor: &dyn TaskMonitor);

    fn is_cancelled(&self) -> bool;

    fn cancel(&mut self);

    fn set_taint_varnode_map(
        &mut self,
        vmap: BTreeMap<Address, Vec<Box<dyn TaintQueryResult>>>,
        delta: TaskType,
    );

    fn get_taint_varnode_map(&self) -> BTreeMap<Address, Vec<Box<dyn TaintQueryResult>>>;

    fn get_query_set(&self, addr: &Address) -> Vec<Box<dyn TaintQueryResult>>;

    fn build_index(
        &mut self,
        param_list: &[String],
        engine_path: &str,
        facts_path: &str,
        index_directory: &str,
    );

    fn get_export_script(&self, console: &dyn ConsoleService, per_function: bool) -> Box<dyn GhidraScript>;

    fn set_task_type(&mut self, task_type: TaskType);

    fn get_label_for_token(&self, mtype: MarkType, token: &dyn ClangToken) -> Option<Box<dyn TaintLabel>>;
}

/// Look up the `TaintState` engine whose class name contains `engine_type` (case-insensitively on
/// the class name only, matching Java) and construct it with `plugin`. Port of
/// `TaintState.newInstance(TaintPlugin, String)`.
///
/// See the module docs: this always takes the "no match" branch until a real class-discovery
/// registry replaces [`ClassSearcher::get_taint_state_classes`]'s empty result.
pub fn new_instance(plugin: &dyn TaintPlugin, engine_type: &str) -> Option<Box<dyn TaintState>> {
    for class in ClassSearcher::get_taint_state_classes() {
        if class.name.to_lowercase().contains(engine_type) {
            return Some((class.construct)(plugin));
        }
    }
    Msg::error("TaintState", &format!("No match for engine = {engine_type}"));
    None
}

/// Compute the display name backing a taint variable for `token`. Port of
/// `TaintState.varName(ClangToken, boolean)`.
///
/// `append` has no effect: Java's own method body never reads its `append` parameter either.
pub fn var_name(token: &dyn ClangToken, _append: bool) -> Option<String> {
    let token_text = token.get_text().to_string();

    if token.kind() == ClangTokenKind::Field {
        return Some(match get_parent_token(token) {
            None => token_text,
            Some(vtoken) => {
                let hv = vtoken
                    .get_high_variable()
                    .expect("a ClangVariableToken found by get_parent_token must carry a HighVariable");
                hv.get_representative().get_address().to_string()
            }
        });
    }

    let hv = match token.get_high_variable() {
        None => return Some(token_text),
        Some(hv) => hv,
    };

    if hv.kind() == HighVariableKind::Local && token.get_varnode().is_none() {
        let offset = hv.get_offset() as i64;
        let rep = hv.get_representative();
        let addr = rep.get_address().subtract_no_wrap(offset).unwrap_or_else(|_| {
            rep.get_address().clone()
        });
        return Some(addr.to_string());
    }

    hvar_name(hv.as_ref())
}

/// Compute the display name for a `HighVariable`, independent of any originating token. Port of
/// the private `TaintState.hvarName(HighVariable)`.
///
/// See the module docs for why the unique-address (`DynamicHash`) branch and the `HighGlobal`
/// primary-symbol lookup are documented limitations rather than full ports.
fn hvar_name(hv: &dyn HighVariable) -> Option<String> {
    let rep = hv.get_representative();
    if rep.get_address().is_unique_address() {
        // `new DynamicHash(rep, hf).getHash()` is not computable: `DynamicHash` is a trait with
        // no constructible implementation in this crate yet.
        return None;
    }

    let name = hv.get_name();
    if name.is_empty() || name == "UNNAMED" {
        return match hv.kind() {
            HighVariableKind::Constant | HighVariableKind::Local | HighVariableKind::Other => {
                Some(rep.get_address().to_string())
            }
            HighVariableKind::Global => {
                // `fn.getProgram().getSymbolTable().getPrimarySymbol(addr)` needs `&mut dyn
                // Program`, unavailable through the shared `Arc<dyn Program>` this crate's
                // `Function::get_program` hands back; fall back to the address, matching what
                // Java returns when no primary symbol exists there.
                Some(rep.get_address().to_string())
            }
            HighVariableKind::Generic => None,
        };
    }
    Some(name)
}

/// Find the nearest preceding `ClangVariableToken` sibling of `token` within its parent group.
/// Port of the package-private `TaintState.getParentToken(ClangFieldToken)`.
///
/// # Limitations
///
/// This crate currently never wires up a token's `parent()` (every token
/// [`ClangTokenBase::build_token`](crate::app::decompiler::clang_token::ClangTokenBase::build_token)
/// decodes is constructed with `parent: None`, and [`ClangTokenGroup`] has no way to retroactively
/// set a child's parent once it owns that child), so `token.parent()` is always `None` for any
/// token reachable from production code today, and this always returns `None`. The full
/// downcast-and-scan algorithm below is still implemented against that eventual wiring.
pub fn get_parent_token<'a>(token: &'a dyn ClangToken) -> Option<&'a dyn ClangToken> {
    let group_node = ClangNode::parent(token)?;
    let group = group_node.as_any().downcast_ref::<ClangTokenGroup>()?;

    let mut parent: Option<&dyn ClangToken> = None;
    for next in group.token_iterator(true) {
        let Some(next_token) = downcast_clang_token(next) else {
            continue;
        };
        if next_token.kind() == ClangTokenKind::Variable {
            parent = Some(next_token);
        }
        if next_token.kind() == ClangTokenKind::Field && std::ptr::eq(next_token, token) {
            return parent;
        }
    }
    None
}

/// Downcast a `&dyn ClangNode` leaf yielded by [`ClangTokenGroup::token_iterator`] to `&dyn
/// ClangToken`, via the concrete [`ClangTokenBase`](crate::app::decompiler::ClangTokenBase) --
/// the only production [`ClangToken`] implementor -- since [`ClangNode::as_any`] only recovers
/// the concrete type, not the `ClangToken` trait object.
fn downcast_clang_token(node: &dyn ClangNode) -> Option<&dyn ClangToken> {
    node.as_any()
        .downcast_ref::<crate::app::decompiler::clang_token::ClangTokenBase>()
        .map(|base| base as &dyn ClangToken)
}

/// `true` if `token` is used as an actual (input) parameter of a `CALL`-family p-code op. Port of
/// `TaintState.isActualParam(ClangToken)`.
pub fn is_actual_param(token: &dyn ClangToken) -> bool {
    let Some(pcode_op) = token.get_pcode_op() else {
        return false;
    };
    if !pcode_op.opcode.mnemonic().contains("CALL") {
        return false;
    }
    let Some(varnode) = token.get_varnode() else {
        return false;
    };
    pcode_op.inputs.iter().any(|input| input == varnode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::ClangTokenBase;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};
    use crate::program::model::pcode::high_function::HighFunction;
    use crate::program::seam_stubs::HighSymbol;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    struct MockHighVariable {
        representative: Varnode,
        name: String,
        kind: HighVariableKind,
        offset: i32,
    }

    impl HighVariable for MockHighVariable {
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not exercised by these tests")
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_representative(&self) -> Varnode {
            self.representative.clone()
        }
        fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn set_representative(&mut self, _rep: Varnode) {}
        fn set_instances(&mut self, _instances: Vec<Varnode>) {}
        fn kind(&self) -> HighVariableKind {
            self.kind
        }
        fn decode(
            &mut self,
            _decoder: &dyn crate::program::model::pcode::Decoder,
        ) -> Result<(), crate::program::model::pcode::DecoderException> {
            Ok(())
        }
    }

    /// A minimal [`ClangToken`] test double: text plus an optional `HighVariable`/`Varnode`/
    /// `PcodeOp`, tagged with a [`ClangTokenKind`].
    struct MockToken {
        base: ClangTokenBase,
        high_variable: Option<Arc<dyn HighVariable>>,
        varnode: Option<Varnode>,
        pcode_op: Option<PcodeOp>,
    }

    impl MockToken {
        fn new(text: &str, kind: ClangTokenKind) -> Self {
            Self {
                base: ClangTokenBase::with_kind(None, text, kind, crate::app::decompiler::clang_token::DEFAULT_COLOR),
                high_variable: None,
                varnode: None,
                pcode_op: None,
            }
        }
    }

    impl std::fmt::Display for MockToken {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.base.get_text())
        }
    }

    impl ClangNode for MockToken {
        fn parent(&self) -> Option<&dyn ClangNode> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_max_address(&self) -> Option<Address> {
            None
        }
        fn num_children(&self) -> usize {
            0
        }
        fn child(&self, i: usize) -> &dyn ClangNode {
            panic!("MockToken has no children, requested index {i}")
        }
        fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
            unimplemented!("not exercised by these tests")
        }
        fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
            list.push(self);
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl ClangToken for MockToken {
        fn base(&self) -> &ClangTokenBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut ClangTokenBase {
            &mut self.base
        }
        fn get_high_variable(&self) -> Option<Arc<dyn HighVariable>> {
            self.high_variable.clone()
        }
        fn get_varnode(&self) -> Option<&Varnode> {
            self.varnode.as_ref()
        }
        fn get_pcode_op(&self) -> Option<&PcodeOp> {
            self.pcode_op.as_ref()
        }
    }

    fn call_op(inputs: Vec<Varnode>) -> PcodeOp {
        let space = ram_space();
        PcodeOp::new(
            OpCode::Call,
            SequenceNumber::new(addr(&space, 0), 0),
            inputs,
            None,
        )
    }

    #[test]
    fn is_actual_param_true_when_varnode_is_a_call_input() {
        let space = ram_space();
        let vn = Varnode::new(addr(&space, 0x1000), 4);
        let mut token = MockToken::new("param", ClangTokenKind::Variable);
        token.varnode = Some(vn.clone());
        token.pcode_op = Some(call_op(vec![vn]));

        assert!(is_actual_param(&token));
    }

    #[test]
    fn is_actual_param_false_when_opcode_is_not_call() {
        let space = ram_space();
        let vn = Varnode::new(addr(&space, 0x1000), 4);
        let mut token = MockToken::new("x", ClangTokenKind::Variable);
        token.varnode = Some(vn.clone());
        token.pcode_op = Some(PcodeOp::new(
            OpCode::IntAdd,
            SequenceNumber::new(addr(&space, 0), 0),
            vec![vn],
            None,
        ));

        assert!(!is_actual_param(&token));
    }

    #[test]
    fn is_actual_param_false_when_varnode_is_not_among_call_inputs() {
        let space = ram_space();
        let vn = Varnode::new(addr(&space, 0x1000), 4);
        let other = Varnode::new(addr(&space, 0x2000), 4);
        let mut token = MockToken::new("x", ClangTokenKind::Variable);
        token.varnode = Some(vn);
        token.pcode_op = Some(call_op(vec![other]));

        assert!(!is_actual_param(&token));
    }

    #[test]
    fn is_actual_param_false_when_no_pcode_op() {
        let token = MockToken::new("x", ClangTokenKind::Variable);
        assert!(!is_actual_param(&token));
    }

    #[test]
    fn var_name_returns_token_text_when_no_high_variable() {
        let token = MockToken::new("literal_text", ClangTokenKind::Generic);
        assert_eq!(var_name(&token, false), Some("literal_text".to_string()));
    }

    #[test]
    fn var_name_uses_high_variable_name_when_present() {
        let space = ram_space();
        let mut token = MockToken::new("ignored", ClangTokenKind::Variable);
        token.high_variable = Some(Arc::new(MockHighVariable {
            representative: Varnode::new(addr(&space, 0x4000), 4),
            name: "local_x".to_string(),
            kind: HighVariableKind::Generic,
            offset: -1,
        }));
        assert_eq!(var_name(&token, false), Some("local_x".to_string()));
    }

    #[test]
    fn var_name_high_local_without_varnode_subtracts_offset_from_representative() {
        let space = ram_space();
        let mut token = MockToken::new("ignored", ClangTokenKind::Variable);
        token.high_variable = Some(Arc::new(MockHighVariable {
            representative: Varnode::new(addr(&space, 0x4010), 4),
            name: String::new(),
            kind: HighVariableKind::Local,
            offset: 0x10,
        }));
        // token.varnode stays None, matching Java's `token.getVarnode() == null` guard.

        let expected = addr(&space, 0x4010).subtract_no_wrap(0x10).unwrap().to_string();
        assert_eq!(var_name(&token, false), Some(expected));
    }

    #[test]
    fn var_name_field_token_with_no_parent_returns_its_own_text() {
        // No token built by this crate currently has a wired-up parent (see get_parent_token's
        // docs), so a field token always falls back to its own text.
        let token = MockToken::new("field_text", ClangTokenKind::Field);
        assert_eq!(var_name(&token, false), Some("field_text".to_string()));
    }

    #[test]
    fn get_parent_token_returns_none_when_token_has_no_parent() {
        let token = MockToken::new("f", ClangTokenKind::Field);
        assert!(get_parent_token(&token).is_none());
    }

    #[test]
    fn hvar_name_falls_back_to_address_for_unnamed_local() {
        let space = ram_space();
        let hv = MockHighVariable {
            representative: Varnode::new(addr(&space, 0x5000), 4),
            name: "UNNAMED".to_string(),
            kind: HighVariableKind::Local,
            offset: -1,
        };
        assert_eq!(hvar_name(&hv), Some(addr(&space, 0x5000).to_string()));
    }

    #[test]
    fn hvar_name_returns_none_for_generic_unnamed_variable() {
        let space = ram_space();
        let hv = MockHighVariable {
            representative: Varnode::new(addr(&space, 0x5000), 4),
            name: String::new(),
            kind: HighVariableKind::Generic,
            offset: -1,
        };
        assert_eq!(hvar_name(&hv), None);
    }

    #[test]
    fn new_instance_has_no_registry_yet_and_returns_none() {
        struct MockPlugin;
        impl TaintPlugin for MockPlugin {}
        assert!(new_instance(&MockPlugin, "ctadl").is_none());
    }

    /// Proves the trait is object-safe and its default-free method surface can actually be
    /// implemented, mirroring `ExtensionPoint`'s own `marker_trait_is_implementable_and_object_safe`
    /// smoke test.
    struct StubTaintState;

    impl ExtensionPoint for StubTaintState {}

    impl TaintState for StubTaintState {
        fn get_name(&self) -> String {
            "stub".to_string()
        }
        fn query_index(&mut self, _program: &mut dyn Program, _tool: &dyn TaintPlugin, _query_type: QueryType) -> bool {
            false
        }
        fn get_query_name(&self) -> String {
            String::new()
        }
        fn toggle_mark(&mut self, _mtype: MarkType, _token: &dyn ClangToken) -> Result<Box<dyn TaintLabel>, PcodeException> {
            Err(PcodeException::new("not implemented"))
        }
        fn get_taint_labels(&self, _mtype: MarkType) -> Vec<Box<dyn TaintLabel>> {
            Vec::new()
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_taint_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn set_taint_address_set(&mut self, _aset: AddressSet) {}
        fn augment_address_set(&mut self, _token: &dyn ClangToken) {}
        fn clear_taint(&mut self) {}
        fn is_sink(&self, _hvar: &dyn HighVariable) -> bool {
            false
        }
        fn clear_markers(&mut self) {}
        fn load_taint_data(&mut self, _program: &mut dyn Program, _sarif_file: &Path) {}
        fn get_data(&self) -> Option<SarifSchema210> {
            None
        }
        fn clear_data(&mut self) {}
        fn get_options(&self) -> Box<dyn TaintOptions> {
            struct StubOptions;
            impl TaintOptions for StubOptions {}
            Box::new(StubOptions)
        }
        fn has_marks(&self) -> bool {
            false
        }
        fn set_monitor(&mut self, _monitor: &dyn TaskMonitor) {}
        fn is_cancelled(&self) -> bool {
            false
        }
        fn cancel(&mut self) {}
        fn set_taint_varnode_map(&mut self, _vmap: BTreeMap<Address, Vec<Box<dyn TaintQueryResult>>>, _delta: TaskType) {}
        fn get_taint_varnode_map(&self) -> BTreeMap<Address, Vec<Box<dyn TaintQueryResult>>> {
            BTreeMap::new()
        }
        fn get_query_set(&self, _addr: &Address) -> Vec<Box<dyn TaintQueryResult>> {
            Vec::new()
        }
        fn build_index(&mut self, _param_list: &[String], _engine_path: &str, _facts_path: &str, _index_directory: &str) {}
        fn get_export_script(&self, _console: &dyn ConsoleService, _per_function: bool) -> Box<dyn GhidraScript> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_task_type(&mut self, _task_type: TaskType) {}
        fn get_label_for_token(&self, _mtype: MarkType, _token: &dyn ClangToken) -> Option<Box<dyn TaintLabel>> {
            None
        }
    }

    #[test]
    fn trait_is_implementable_and_object_safe() {
        let mut state: Box<dyn TaintState> = Box::new(StubTaintState);
        assert_eq!(state.get_name(), "stub");
        assert!(state.is_valid());
        assert!(!state.has_marks());
        state.clear_taint();
    }
}
