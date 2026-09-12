//! Port of `ghidra.program.model.symbol.SymbolType`.
//!
//! Java models `SymbolType` as an abstract class whose public static final instances (`LABEL`,
//! `LIBRARY`, `NAMESPACE`, `CLASS`, `FUNCTION`, `PARAMETER`, `LOCAL_VAR`, `GLOBAL_VAR`, `GLOBAL`)
//! each override `isValidParent`/`isValidAddress`/`isValidSourceType` with distinct per-instance
//! behavior. Following this crate's composition-over-inheritance convention, that behavior is
//! ported as a single enum with a `match` in each method rather than as one struct per instance.

use std::sync::Arc;

use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Namespace, SourceType, GLOBAL_NAMESPACE_ID};

/// Class to represent the various types of Symbols.
///
/// Port of `ghidra.program.model.symbol.SymbolType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    Label,
    Library,
    Namespace,
    Class,
    Function,
    Parameter,
    LocalVar,
    GlobalVar,
    Global,
}

impl SymbolType {
    /// Deprecated alias for [`SymbolType::Label`], matching Java's deprecated `SymbolType.CODE`.
    #[deprecated(note = "use SymbolType::Label instead")]
    pub const CODE: SymbolType = SymbolType::Label;

    /// Returns the display name for this symbol type, matching Java's `toString()`.
    pub fn name(&self) -> &'static str {
        match self {
            SymbolType::Label => "Label",
            SymbolType::Library => "Library",
            SymbolType::Namespace => "Namespace",
            SymbolType::Class => "Class",
            SymbolType::Function => "Function",
            SymbolType::Parameter => "Parameter",
            SymbolType::LocalVar => "Local Var",
            SymbolType::GlobalVar => "Global Register Var",
            // Matches Java's use of GlobalNamespace.GLOBAL_NAMESPACE_NAME ("Global") for GLOBAL's
            // display name.
            SymbolType::Global => "Global",
        }
    }

    /// Returns the id of this symbol type, matching Java's `getID()`.
    pub fn get_id(&self) -> i8 {
        match self {
            SymbolType::Label => 0,
            SymbolType::Library => 1,
            SymbolType::Namespace => 3,
            SymbolType::Class => 4,
            SymbolType::Function => 5,
            SymbolType::Parameter => 6,
            SymbolType::LocalVar => 7,
            SymbolType::GlobalVar => 8,
            SymbolType::Global => -1,
        }
    }

    /// Returns the `SymbolType` for the given id, matching Java's `getSymbolType(int)`.
    ///
    /// Java looks up non-global ids in a dense array `{LABEL, LIBRARY, null, NAMESPACE, CLASS,
    /// FUNCTION, PARAMETER, LOCAL_VAR, GLOBAL_VAR}` indexed by id. Id `2` was never assigned a
    /// type (the slot is a deliberate `null` hole left over from a removed/reserved id) and
    /// Java's `getSymbolType(2)` faithfully returns `null` rather than throwing or skipping to
    /// the next type. This port reproduces that hole: `get_symbol_type(2)` returns `None`, same
    /// as any other id outside the assigned set.
    pub fn get_symbol_type(id: i32) -> Option<SymbolType> {
        if id == -1 {
            return Some(SymbolType::Global);
        }
        match id {
            0 => Some(SymbolType::Label),
            1 => Some(SymbolType::Library),
            2 => None, // Deliberate hole in Java's backing array; see doc comment above.
            3 => Some(SymbolType::Namespace),
            4 => Some(SymbolType::Class),
            5 => Some(SymbolType::Function),
            6 => Some(SymbolType::Parameter),
            7 => Some(SymbolType::LocalVar),
            8 => Some(SymbolType::GlobalVar),
            _ => None,
        }
    }

    /// Returns true if this symbol type allows duplicate names, matching Java's
    /// `allowsDuplicates()`. Defaults to `false` in the Java base class; only `LABEL` and
    /// `FUNCTION` override it to return `true`.
    pub fn allows_duplicates(&self) -> bool {
        matches!(self, SymbolType::Label | SymbolType::Function)
    }

    /// Returns true if this symbol represents a namespace, matching Java's `isNamespace()`.
    pub fn is_namespace(&self) -> bool {
        matches!(
            self,
            SymbolType::Library
                | SymbolType::Namespace
                | SymbolType::Class
                | SymbolType::Function
                | SymbolType::Global
        )
    }

    /// Returns true if the given namespace is a valid parent for a symbol of this type with the
    /// given address and external status, matching Java's `isValidParent(Program, Namespace,
    /// Address, boolean)`.
    ///
    /// `program` is the program that would contain the symbol; it is compared (by identity, as
    /// Java does via `!=`/`==` on `Program` references) against the program that owns `parent`'s
    /// symbol wherever Java's override performs that check.
    pub fn is_valid_parent(
        &self,
        program: Option<&Arc<dyn Program>>,
        parent: &dyn Namespace,
        symbol_addr: &Address,
        is_external_symbol: bool,
    ) -> bool {
        match self {
            SymbolType::Label => {
                let external_parent = parent.is_external();
                if symbol_addr.is_external_address() != external_parent {
                    return false;
                }
                if parent.get_id() != GLOBAL_NAMESPACE_ID
                    && !programs_match(program, parent_program(parent).as_ref())
                {
                    return false;
                }
                // CODE symbol may not have an external function parent.
                !(parent.as_function().is_some() && external_parent)
            }
            SymbolType::Library => parent.get_id() == GLOBAL_NAMESPACE_ID,
            SymbolType::Namespace => {
                let is_external_parent = parent.is_external();
                if is_external_symbol != is_external_parent {
                    return false;
                }
                if parent.get_id() != GLOBAL_NAMESPACE_ID
                    && !programs_match(program, parent_program(parent).as_ref())
                {
                    return false;
                }
                true
            }
            SymbolType::Class => {
                if is_external_symbol != parent.is_external() {
                    return false;
                }
                if parent.get_id() != GLOBAL_NAMESPACE_ID
                    && !programs_match(program, parent_program(parent).as_ref())
                {
                    return false;
                }
                // CLASS can not be contained within a function.
                !has_function_ancestor(parent)
            }
            SymbolType::Function => {
                if symbol_addr.is_external_address() != parent.is_external() {
                    return false;
                }
                if parent.get_id() != GLOBAL_NAMESPACE_ID
                    && !programs_match(program, parent_program(parent).as_ref())
                {
                    return false;
                }
                // FUNCTION can not be contained within a function.
                !has_function_ancestor(parent)
            }
            SymbolType::Parameter | SymbolType::LocalVar => match parent.as_function() {
                Some(function) => programs_match(program, Some(&function.get_program())),
                None => false,
            },
            SymbolType::GlobalVar => parent.get_id() == GLOBAL_NAMESPACE_ID,
            SymbolType::Global => false,
        }
    }

    /// Returns true if the given address is valid for this symbol type, matching Java's
    /// `isValidAddress(Program, Address)`.
    ///
    /// Java's signature takes a `Program`, but no override actually reads it; the parameter is
    /// kept here (unused) purely for signature fidelity with the original method contract.
    pub fn is_valid_address(&self, _program: Option<&Arc<dyn Program>>, symbol_address: &Address) -> bool {
        match self {
            SymbolType::Label => {
                symbol_address.is_memory_address() || symbol_address.is_external_address()
            }
            SymbolType::Library | SymbolType::Namespace | SymbolType::Class => {
                *symbol_address == SpecialAddress::no_address()
            }
            SymbolType::Function => {
                symbol_address.is_memory_address() || symbol_address.is_external_address()
            }
            SymbolType::Parameter | SymbolType::LocalVar | SymbolType::GlobalVar => {
                symbol_address.is_variable_address()
            }
            SymbolType::Global => false,
        }
    }

    /// Returns true if the given `SourceType` is valid for this symbol type, matching Java's
    /// `isValidSourceType(SourceType, Address)`.
    pub fn is_valid_source_type(&self, source_type: SourceType, symbol_address: &Address) -> bool {
        match self {
            SymbolType::Label => {
                source_type != SourceType::Default || symbol_address.is_external_address()
            }
            SymbolType::Library
            | SymbolType::Namespace
            | SymbolType::Class
            | SymbolType::GlobalVar
            | SymbolType::Global => source_type != SourceType::Default,
            SymbolType::Function | SymbolType::Parameter | SymbolType::LocalVar => true,
        }
    }
}

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Returns the program that owns `namespace`'s symbol, if known.
fn parent_program(namespace: &dyn Namespace) -> Option<Arc<dyn Program>> {
    namespace.get_symbol().get_program()
}

/// Compares two (optional) programs by identity, matching Java's `==`/`!=` reference comparison
/// on `Program`. Two `None`s are considered equal (both "unknown"), matching the conservative
/// default used throughout this port for not-yet-wired-up program back-references.
fn programs_match(a: Option<&Arc<dyn Program>>, b: Option<&Arc<dyn Program>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

/// Walks `parent`'s namespace chain up to (but not including) the global namespace, returning
/// true if any ancestor (including `parent` itself) is a `Function`. Matches Java's:
/// ```java
/// while (parent.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
///     if (parent instanceof Function) return false;
///     parent = parent.getParentNamespace();
/// }
/// ```
/// Java would throw `NullPointerException` if a non-global namespace's `getParentNamespace()`
/// returned `null` (an inconsistent namespace tree); this port instead simply stops the walk in
/// that case, since a `None` parent while `get_id() != GLOBAL_NAMESPACE_ID` cannot arise from a
/// well-formed namespace tree in practice.
fn has_function_ancestor(parent: &dyn Namespace) -> bool {
    let mut current_id = parent.get_id();
    let mut current_is_function = parent.as_function().is_some();
    let mut current_next = parent.get_parent_namespace();
    loop {
        if current_id == GLOBAL_NAMESPACE_ID {
            return false;
        }
        if current_is_function {
            return true;
        }
        match current_next {
            Some(ns) => {
                current_id = ns.get_id();
                current_is_function = ns.as_function().is_some();
                current_next = ns.get_parent_namespace();
            }
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Function;
    use crate::program::model::symbol::Symbol;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn variable_addr(offset: i64) -> Address {
        let space = AddressSpace::new("variable", 32, 1, AddressSpaceType::Variable, 11);
        Address::new(space, offset)
    }

    fn external_addr(offset: i64) -> Address {
        let space = AddressSpace::new("external", 0, 1, AddressSpaceType::External, 10);
        Address::new(space, offset)
    }

    struct MockSymbol {
        symbol_type: SymbolType,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_addr(0)
        }
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockNamespace {
        id: i64,
        external: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                symbol_type: SymbolType::Namespace,
            })
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn is_external(&self) -> bool {
            self.external
        }
    }

    fn global_namespace() -> Arc<dyn Namespace> {
        Arc::new(MockNamespace {
            id: GLOBAL_NAMESPACE_ID,
            external: false,
            parent: None,
        })
    }

    #[test]
    fn ids_match_java_values() {
        assert_eq!(SymbolType::Label.get_id(), 0);
        assert_eq!(SymbolType::Library.get_id(), 1);
        assert_eq!(SymbolType::Namespace.get_id(), 3);
        assert_eq!(SymbolType::Class.get_id(), 4);
        assert_eq!(SymbolType::Function.get_id(), 5);
        assert_eq!(SymbolType::Parameter.get_id(), 6);
        assert_eq!(SymbolType::LocalVar.get_id(), 7);
        assert_eq!(SymbolType::GlobalVar.get_id(), 8);
        assert_eq!(SymbolType::Global.get_id(), -1);
    }

    #[test]
    fn get_symbol_type_round_trips_and_reproduces_the_id_2_hole() {
        assert_eq!(SymbolType::get_symbol_type(0), Some(SymbolType::Label));
        assert_eq!(SymbolType::get_symbol_type(1), Some(SymbolType::Library));
        assert_eq!(SymbolType::get_symbol_type(3), Some(SymbolType::Namespace));
        assert_eq!(SymbolType::get_symbol_type(8), Some(SymbolType::GlobalVar));
        assert_eq!(SymbolType::get_symbol_type(-1), Some(SymbolType::Global));

        // Java: `types[2]` is a deliberate `null` hole in the backing array (RefType id 2 was
        // never assigned to a SymbolType). `getSymbolType(2)` faithfully returns `null`.
        assert_eq!(SymbolType::get_symbol_type(2), None);
        assert_eq!(SymbolType::get_symbol_type(9), None);
        assert_eq!(SymbolType::get_symbol_type(-2), None);
    }

    #[test]
    fn display_names_match_java() {
        assert_eq!(SymbolType::Label.to_string(), "Label");
        assert_eq!(SymbolType::Library.to_string(), "Library");
        assert_eq!(SymbolType::Namespace.to_string(), "Namespace");
        assert_eq!(SymbolType::Class.to_string(), "Class");
        assert_eq!(SymbolType::Function.to_string(), "Function");
        assert_eq!(SymbolType::Parameter.to_string(), "Parameter");
        assert_eq!(SymbolType::LocalVar.to_string(), "Local Var");
        assert_eq!(SymbolType::GlobalVar.to_string(), "Global Register Var");
        assert_eq!(SymbolType::Global.to_string(), "Global");
    }

    #[test]
    fn namespace_and_duplicate_flags_match_java_defaults() {
        assert!(!SymbolType::Label.is_namespace());
        assert!(SymbolType::Library.is_namespace());
        assert!(SymbolType::Namespace.is_namespace());
        assert!(SymbolType::Class.is_namespace());
        assert!(SymbolType::Function.is_namespace());
        assert!(!SymbolType::Parameter.is_namespace());
        assert!(!SymbolType::LocalVar.is_namespace());
        assert!(!SymbolType::GlobalVar.is_namespace());
        assert!(SymbolType::Global.is_namespace());

        assert!(SymbolType::Label.allows_duplicates());
        assert!(SymbolType::Function.allows_duplicates());
        assert!(!SymbolType::Namespace.allows_duplicates());
        assert!(!SymbolType::Library.allows_duplicates());
        assert!(!SymbolType::Parameter.allows_duplicates());
        assert!(!SymbolType::LocalVar.allows_duplicates());
        assert!(!SymbolType::GlobalVar.allows_duplicates());
        assert!(!SymbolType::Global.allows_duplicates());
    }

    #[test]
    fn label_is_valid_address_accepts_memory_and_external() {
        assert!(SymbolType::Label.is_valid_address(None, &ram_addr(0x1000)));
        assert!(SymbolType::Label.is_valid_address(None, &external_addr(1)));
        assert!(!SymbolType::Label.is_valid_address(None, &variable_addr(0)));
    }

    #[test]
    fn library_namespace_class_require_no_address() {
        assert!(SymbolType::Library.is_valid_address(None, &SpecialAddress::no_address()));
        assert!(!SymbolType::Library.is_valid_address(None, &ram_addr(0)));
        assert!(SymbolType::Namespace.is_valid_address(None, &SpecialAddress::no_address()));
        assert!(SymbolType::Class.is_valid_address(None, &SpecialAddress::no_address()));
    }

    #[test]
    fn variable_types_require_variable_address() {
        assert!(SymbolType::Parameter.is_valid_address(None, &variable_addr(0)));
        assert!(!SymbolType::Parameter.is_valid_address(None, &ram_addr(0)));
        assert!(SymbolType::LocalVar.is_valid_address(None, &variable_addr(1)));
        assert!(SymbolType::GlobalVar.is_valid_address(None, &variable_addr(2)));
    }

    #[test]
    fn global_is_never_a_valid_address_or_parent() {
        assert!(!SymbolType::Global.is_valid_address(None, &SpecialAddress::no_address()));
        assert!(!SymbolType::Global.is_valid_parent(None, &*global_namespace(), &ram_addr(0), false));
    }

    #[test]
    fn is_valid_source_type_matches_java_per_type() {
        // LABEL: DEFAULT is only valid for external addresses.
        assert!(!SymbolType::Label.is_valid_source_type(SourceType::Default, &ram_addr(0)));
        assert!(SymbolType::Label.is_valid_source_type(SourceType::Default, &external_addr(1)));
        assert!(SymbolType::Label.is_valid_source_type(SourceType::UserDefined, &ram_addr(0)));

        // LIBRARY/NAMESPACE/CLASS/GLOBAL_VAR/GLOBAL: DEFAULT never valid.
        assert!(!SymbolType::Library.is_valid_source_type(SourceType::Default, &ram_addr(0)));
        assert!(SymbolType::Library.is_valid_source_type(SourceType::Analysis, &ram_addr(0)));
        assert!(!SymbolType::Global.is_valid_source_type(SourceType::Default, &ram_addr(0)));

        // FUNCTION/PARAMETER/LOCAL_VAR: always valid.
        assert!(SymbolType::Function.is_valid_source_type(SourceType::Default, &ram_addr(0)));
        assert!(SymbolType::Parameter.is_valid_source_type(SourceType::Default, &ram_addr(0)));
        assert!(SymbolType::LocalVar.is_valid_source_type(SourceType::Default, &ram_addr(0)));
    }

    #[test]
    fn library_and_global_var_require_global_namespace_parent() {
        let global = global_namespace();
        let non_global: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 5,
            external: false,
            parent: Some(global.clone()),
        });

        assert!(SymbolType::Library.is_valid_parent(None, &*global, &ram_addr(0), false));
        assert!(!SymbolType::Library.is_valid_parent(None, &*non_global, &ram_addr(0), false));
        assert!(SymbolType::GlobalVar.is_valid_parent(None, &*global, &variable_addr(0), false));
        assert!(!SymbolType::GlobalVar.is_valid_parent(None, &*non_global, &variable_addr(0), false));
    }

    #[test]
    fn label_rejects_mismatched_external_status() {
        let global = global_namespace();
        let external_parent: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 7,
            external: true,
            parent: Some(global.clone()),
        });

        // Memory address under an external parent: mismatch -> invalid.
        assert!(!SymbolType::Label.is_valid_parent(None, &*external_parent, &ram_addr(0), false));
        // External address under a non-external (global) parent: mismatch -> invalid.
        assert!(!SymbolType::Label.is_valid_parent(None, &*global, &external_addr(1), false));
        // External address under an external parent: matches -> valid (parent not a Function).
        assert!(SymbolType::Label.is_valid_parent(None, &*external_parent, &external_addr(1), false));
    }

    #[test]
    fn class_and_function_accept_non_function_ancestor() {
        let global = global_namespace();
        let plain_namespace: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 9,
            external: false,
            parent: Some(global.clone()),
        });
        assert!(SymbolType::Class.is_valid_parent(None, &*plain_namespace, &ram_addr(0), false));
        // FUNCTION's parent check compares `symbol_addr.is_external_address()` against
        // `parent.is_external()` (the `is_external_symbol` bool is unused for this branch, just
        // as in Java); `plain_namespace` is non-external, so a non-external address is required.
        assert!(SymbolType::Function.is_valid_parent(None, &*plain_namespace, &ram_addr(0), false));
    }

    #[test]
    fn class_and_function_reject_function_ancestor() {
        // A namespace whose `as_function()` returns `Some(_)`, standing in for `instanceof
        // Function`. Placed two levels below global so the ancestor walk must actually climb
        // past the immediate parent to find it.
        struct MockFunctionNamespace {
            parent: Arc<dyn Namespace>,
        }

        impl Namespace for MockFunctionNamespace {
            fn get_symbol(&self) -> Arc<dyn Symbol> {
                Arc::new(MockSymbol {
                    symbol_type: SymbolType::Function,
                })
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
                Some(self.parent.clone())
            }
            fn get_id(&self) -> i64 {
                42
            }
            fn as_function(&self) -> Option<Arc<dyn Function>> {
                Some(Arc::new(MockFunction::new(Arc::new(MockProgram))))
            }
        }

        let global = global_namespace();
        let function_namespace: Arc<dyn Namespace> = Arc::new(MockFunctionNamespace {
            parent: global.clone(),
        });
        let grandchild: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 99,
            external: false,
            parent: Some(function_namespace.clone()),
        });

        // Direct Function parent is rejected.
        assert!(!SymbolType::Class.is_valid_parent(None, &*function_namespace, &SpecialAddress::no_address(), false));
        assert!(!SymbolType::Function.is_valid_parent(None, &*function_namespace, &ram_addr(0), false));
        // A Function *ancestor* (not just the immediate parent) is also rejected: the walk
        // climbs from `grandchild` up through `function_namespace` before reaching global.
        assert!(!SymbolType::Class.is_valid_parent(None, &*grandchild, &SpecialAddress::no_address(), false));
        assert!(!SymbolType::Function.is_valid_parent(None, &*grandchild, &ram_addr(0), false));
    }

    #[test]
    fn parameter_and_local_var_require_function_parent() {
        let global = global_namespace();
        let plain_namespace: Arc<dyn Namespace> = Arc::new(MockNamespace {
            id: 3,
            external: false,
            parent: Some(global),
        });

        // Non-function parent: always invalid regardless of program identity.
        assert!(!SymbolType::Parameter.is_valid_parent(None, &*plain_namespace, &variable_addr(0), false));
        assert!(!SymbolType::LocalVar.is_valid_parent(None, &*plain_namespace, &variable_addr(0), false));
    }

    #[test]
    fn parameter_and_local_var_require_matching_program_identity() {
        struct FunctionNamespace {
            function: Arc<dyn Function>,
        }

        impl Namespace for FunctionNamespace {
            fn get_symbol(&self) -> Arc<dyn Symbol> {
                Arc::new(MockSymbol {
                    symbol_type: SymbolType::Function,
                })
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
                None
            }
            fn get_id(&self) -> i64 {
                7
            }
            fn as_function(&self) -> Option<Arc<dyn Function>> {
                Some(self.function.clone())
            }
        }

        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let other_program: Arc<dyn Program> = Arc::new(MockProgram);
        let parent: Arc<dyn Namespace> = Arc::new(FunctionNamespace {
            // The function's owning program is the *same* Arc as `program` below, so identity
            // comparison (`Arc::ptr_eq`) can actually succeed.
            function: Arc::new(MockFunction::new(program.clone())),
        });

        // Same program instance as the function's owning program: valid.
        assert!(SymbolType::Parameter.is_valid_parent(Some(&program), &*parent, &variable_addr(0), false));
        assert!(SymbolType::LocalVar.is_valid_parent(Some(&program), &*parent, &variable_addr(0), false));
        // A different program instance: invalid (mirrors Java's `program ==
        // parent.getSymbol().getProgram()` reference-identity check).
        assert!(!SymbolType::Parameter.is_valid_parent(Some(&other_program), &*parent, &variable_addr(0), false));
    }

    /// Minimal `Program` used purely as an identity token for program-equality tests; no method
    /// beyond identity comparison is exercised.
    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// Minimal `Function` used purely as an `as_function()` marker (`instanceof Function`
    /// stand-in) for the ancestor-walk and program-identity tests; every method other than
    /// `get_program` is unreachable from those tests, so it is left `unimplemented!()`.
    struct MockFunction {
        program: Arc<dyn Program>,
    }

    impl MockFunction {
        fn new(program: Arc<dyn Program>) -> Self {
            Self { program }
        }
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for these tests")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            unimplemented!()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!()
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!()
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!()
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!()
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!()
        }
        fn get_entry_point(&self) -> Address {
            unimplemented!()
        }
        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!()
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> SourceType {
            unimplemented!()
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {
            unimplemented!()
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!()
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            unimplemented!()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!()
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!()
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!()
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException>
        {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!()
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!()
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!()
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!()
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!()
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!()
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError>
        {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {
            unimplemented!()
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!()
        }
        fn has_var_args(&self) -> bool {
            unimplemented!()
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!()
        }
        fn is_inline(&self) -> bool {
            unimplemented!()
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!()
        }
        fn has_no_return(&self) -> bool {
            unimplemented!()
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!()
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!()
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!()
        }
        fn get_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!()
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!()
        }
        fn set_calling_convention(
            &mut self,
            _name: &str,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!()
        }
        fn is_thunk(&self) -> bool {
            unimplemented!()
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            unimplemented!()
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            unimplemented!()
        }
        fn is_external(&self) -> bool {
            unimplemented!()
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!()
        }
        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!()
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!()
        }
        fn is_deleted(&self) -> bool {
            unimplemented!()
        }
    }
}
