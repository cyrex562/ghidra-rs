//! Port of `ghidra.app.util.demangler.DemangledObject`.
//!
//! A demangled object: the shared state every demangled symbol carries (mangled/demangled
//! strings, namespace, qualifiers) plus the machinery that applies that symbol to a program.
//!
//! # Shape
//!
//! Java's `DemangledObject` is an `abstract class` that both carries state (23 instance fields)
//! and declares one abstract operation (`getSignature(boolean)`), with seven in-repo subclasses
//! (`DemangledFunction`, `DemangledVariable`, `DemangledLabel`, `DemangledUnknown`,
//! `DemangledAddressTable`, `DemangledString`, `DemangledFunctionIndirect`'s family, ...). That
//! splits in Rust into:
//!
//! - [`DemangledObjectBase`] -- the shared state and the concrete methods over it (name
//!   normalization, plate-comment bookkeeping, and the apply-to-program helpers
//!   [`apply_demangled_name`](DemangledObjectBase::apply_demangled_name) /
//!   [`create_namespace`](DemangledObjectBase::create_namespace) /
//!   [`is_already_demangled`](DemangledObjectBase::is_already_demangled)). Unlike the Java class
//!   it is directly instantiable, since it is pure state.
//! - [`DemangledObject`] -- the trait declaring the abstract operation
//!   ([`get_signature_formatted`](DemangledObject::get_signature_formatted)) plus the concrete
//!   methods that *call* it and so cannot live on the state struct
//!   ([`generate_plate_comment`](DemangledObject::generate_plate_comment),
//!   [`apply_to`](DemangledObject::apply_to),
//!   [`apply_plate_comment_only`](DemangledObject::apply_plate_comment_only),
//!   [`apply_using_context`](DemangledObject::apply_using_context)). Implementors supply
//!   [`base`](DemangledObject::base)/[`base_mut`](DemangledObject::base_mut).
//!
//! `DemangledObject implements Demangled`, so [`DemangledObject`] has
//! [`Demangled`] as a supertrait. Rust cannot supply supertrait method bodies, so an implementor
//! writes one-line delegations to the matching [`DemangledObjectBase`] accessors; the test module
//! below shows the full pattern.
//!
//! # Deviations
//!
//! - Java's nullable `name`/`demangledName`/`originalDemangled`/`rawDemangled` are `Option`s
//!   here (nullability is load-bearing: `generatePlateComment` branches on it and `setName`
//!   accepts `null`). The [`Demangled`] trait's `String`-returning accessors flatten `None` to
//!   the empty string at the trait boundary.
//! - The apply-to-program methods take `&mut dyn Program`, which this port's `Program` mutation
//!   API requires. [`apply_using_context`](DemangledObject::apply_using_context) therefore takes
//!   the program as an explicit argument rather than reading it out of the stored
//!   [`MangledContext`], whose `Arc<dyn Program>` cannot yield a `&mut`; it still uses the
//!   context's address and options, and still fails when no context is set.
//! - `applyDemangledName`'s `setPrimary` step runs through `SetLabelPrimaryCmd` in Java. That
//!   command's function-symbol branch needs `Symbol.setNameAndNamespace`/`Symbol.delete`, neither
//!   of which is ported, so this port performs only the plain label branch via the grown
//!   [`SymbolTable::set_primary_symbol`](crate::program::model::symbol::SymbolTable::set_primary_symbol).
//! - `updateExternalSymbol` reaches the external manager through the passed-in program rather
//!   than Java's `symbol.getProgram()` (this port's `Symbol` has no program back-reference; it is
//!   the same program either way).
//!
//! Grown (all defaulted, so pre-existing implementors keep compiling) to support this port:
//! [`Memory::contains`](crate::program::model::mem::Memory::contains),
//! [`ExternalManager::get_external_location`](crate::program::model::symbol::ExternalManager::get_external_location),
//! [`SymbolTable::get_or_create_name_space`](crate::program::model::symbol::SymbolTable::get_or_create_name_space),
//! and [`SymbolTable::set_primary_symbol`](crate::program::model::symbol::SymbolTable::set_primary_symbol).

use std::sync::Arc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangler_options::DemanglerOptions;
use crate::demangler::mangled_context::MangledContext;
use crate::demangler::seam_stubs::{namespace_qualified_name, strip_superfluous_signature_spaces};
use crate::program::model::address::Address;
use crate::program::model::listing::{CommentType, Program};
use crate::program::model::symbol::{
    GetOrCreateNamespaceError, Namespace, SourceType, Symbol, SymbolType, SymbolUtilities,
    DefaultSymbolUtilities, DELIMITER, MAX_SYMBOL_NAME_LENGTH,
};
use crate::util::exception::InvalidInputException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Port of `DemangledObject.SPACE`.
pub const SPACE: &str = " ";

/// Port of `DemangledObject.NAMESPACE_SEPARATOR`, which aliases `Namespace.DELIMITER`.
pub const NAMESPACE_SEPARATOR: &str = DELIMITER;

/// Port of `DemangledObject.EMPTY_STRING`.
pub const EMPTY_STRING: &str = "";

/// Port of `DemangledObject.SPACE_PATTERN`, the compiled [`SPACE`] pattern subclasses split on.
pub fn space_pattern() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(SPACE).unwrap())
}

/// The originator string used for this class's log messages, standing in for Java's
/// `DemangledObject.class`.
const LOG_ORIGINATOR: &str = "DemangledObject";

/// The shared state of a demangled object, and the concrete behaviour over it.
///
/// Port of the state half of `ghidra.app.util.demangler.DemangledObject`; see the module docs for
/// how the class is split. The field naming is Java's and is, per the original's own comment,
/// due for a refactor there:
///
/// - `mangled` -- the original mangled string as seen in the program; used to see whether a
///   program symbol has already been demangled.
/// - `raw_demangled` -- the raw string returned from the demangler; for debugging.
/// - `original_demangled` -- the starting demangled string, usually the same as the raw one but
///   possibly with simplifications applied; for display.
/// - `demangled_name` -- the name as created by the parser, which may transform or even replace
///   the demangler's string; for display.
/// - `name` -- derived from `demangled_name` and made suitable for use as a symbol name. May be
///   `None` while building, but is expected to be set by the time `apply_to` is called.
pub struct DemangledObjectBase {
    /// The mangled context, which includes the mangled string.
    pub mangled_context: Option<MangledContext>,

    /// The original mangled string. `final` in Java, hence no setter; read via
    /// [`DemangledObjectBase::get_mangled_string`].
    mangled: String,

    /// The demangled string from the demangler, without any simplifications.
    pub raw_demangled: Option<String>,

    /// The starting demangled string, which may have been simplified.
    pub original_demangled: Option<String>,

    /// The updated demangled string, possibly with changes made while building. Private in Java;
    /// set through [`DemangledObjectBase::set_name`].
    demangled_name: Option<String>,

    /// The version of the demangled name suitable for symbols. Private in Java; set through
    /// [`DemangledObjectBase::set_name`].
    name: Option<String>,

    /// A prefix such as `virtual thunk to`.
    pub special_prefix: Option<String>,

    /// The namespace containing this object.
    pub namespace: Option<Box<dyn Demangled>>,

    /// `public`, `protected`, etc.
    pub visibility: Option<String>,

    /// `const`, `volatile`, etc.
    ///
    /// Note (carried over from the original's TODO): `storage_class` refers to things such as
    /// `static`, while `const`/`volatile` are type qualifiers.
    pub storage_class: Option<String>,

    /// Whether the `static` keyword applies.
    pub is_static: bool,

    /// Whether the `virtual` keyword applies.
    pub is_virtual: bool,

    /// Whether the `const` qualifier applies.
    pub is_const: bool,

    /// Whether the `volatile` qualifier applies.
    pub is_volatile: bool,

    /// Whether the `__ptr64` qualifier applies.
    pub is_pointer64: bool,

    /// Whether this object is a thunk.
    pub is_thunk: bool,

    /// Whether the `__unaligned` qualifier applies.
    pub is_unaligned: bool,

    /// Whether the `__restrict` qualifier applies.
    pub is_restrict: bool,

    /// The rendered `__based(...)` clause name.
    pub based_name: Option<String>,

    /// The rendered member-pointer scope qualification.
    pub member_scope: Option<String>,

    /// A message pertaining to issues encountered while applying this object. Public getter and
    /// protected setter in Java.
    pub error_message: Option<String>,

    /// The backup plate comment, used when no original demangled string is available. Private in
    /// Java; set through [`DemangledObjectBase::set_backup_plate_comment`].
    plate_comment: Option<String>,

    /// Whether the mangled string was converted successfully to a demangled string. Private in
    /// Java; derived by [`DemangledObjectBase::set_name`].
    demangled_name_succeeded: bool,
}

impl DemangledObjectBase {
    /// Creates a new base without a mangled context.
    ///
    /// Mirrors the older `DemangledObject(String mangled, String originalDemangled)` constructor.
    pub fn new(mangled: impl Into<String>, original_demangled: Option<String>) -> Self {
        Self {
            mangled_context: None,
            mangled: mangled.into(),
            raw_demangled: original_demangled.clone(),
            original_demangled,
            demangled_name: None,
            name: None,
            special_prefix: None,
            namespace: None,
            visibility: None,
            storage_class: None,
            is_static: false,
            is_virtual: false,
            is_const: false,
            is_volatile: false,
            is_pointer64: false,
            is_thunk: false,
            is_unaligned: false,
            is_restrict: false,
            based_name: None,
            member_scope: None,
            error_message: None,
            plate_comment: None,
            demangled_name_succeeded: false,
        }
    }

    /// Creates a new base from a mangled context, which supplies the mangled string.
    ///
    /// Mirrors `DemangledObject(MangledContext mangledContext, String originalDemangled)`.
    pub fn with_context(
        mangled_context: MangledContext,
        original_demangled: Option<String>,
    ) -> Self {
        let mut this = Self::new(mangled_context.mangled().to_string(), original_demangled);
        this.mangled_context = Some(mangled_context);
        this
    }

    /// The original mangled string.
    ///
    /// Mirrors `getMangledString()`.
    pub fn get_mangled_string(&self) -> &str {
        &self.mangled
    }

    /// The unmodified demangled name, which may contain characters unsuitable for a symbol name.
    ///
    /// Mirrors `getDemangledName()`.
    pub fn get_demangled_name(&self) -> Option<&str> {
        self.demangled_name.as_deref()
    }

    /// The demangled name made suitable for use as a symbol name.
    ///
    /// Mirrors `getName()`.
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the name of the demangled object.
    ///
    /// Mirrors `setName(String)`: the unmodified name is kept as the demangled name, while the
    /// symbol name has its superfluous signature spaces stripped, is trimmed of the
    /// leading/trailing whitespace demanglers sometimes emit, and has its remaining spaces
    /// replaced with underscores. Passing `None` mirrors Java's `null` argument.
    pub fn set_name(&mut self, name: Option<&str>) {
        self.demangled_name = name.map(str::to_string);
        self.name = name
            .map(|n| strip_superfluous_signature_spaces(n).trim().replace(' ', "_"));
        // Note the comparison is against the *untransformed* argument, as in Java, and that a
        // `null` name therefore counts as a success.
        self.demangled_name_succeeded = Some(self.mangled.as_str()) != name;
    }

    /// Whether the mangled string was converted successfully into a demangled string.
    ///
    /// Mirrors `demangledNameSuccessfully()`.
    pub fn demangled_name_successfully(&self) -> bool {
        self.demangled_name_succeeded
    }

    /// The namespace containing this demangled object.
    ///
    /// Mirrors `getNamespace()`.
    pub fn get_namespace(&self) -> Option<&dyn Demangled> {
        self.namespace.as_deref()
    }

    /// Sets the namespace of this demangled object.
    ///
    /// Mirrors `setNamespace(Demangled)`.
    pub fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
        self.namespace = namespace;
    }

    /// Renders this object as a fully-qualified namespace: the parent namespace path (if any)
    /// followed by `namespace_name`.
    ///
    /// Mirrors `getNamespaceString()`. `getNamespaceName()` is overridable in Java, so the
    /// caller passes its own value in rather than this method assuming the base's.
    pub fn namespace_string_with(&self, namespace_name: &str) -> String {
        let mut buffer = String::new();
        if let Some(namespace) = &self.namespace {
            buffer.push_str(&namespace.get_namespace_string());
            buffer.push_str(DELIMITER);
        }
        buffer.push_str(namespace_name);
        buffer
    }

    /// The plate comment used when no original demangled string is available.
    ///
    /// Backs [`DemangledObject::generate_plate_comment`]; Java reads the private field directly.
    pub fn plate_comment(&self) -> Option<&str> {
        self.plate_comment.as_deref()
    }

    /// Sets the plate comment to be used if `original_demangled` is not available.
    ///
    /// Mirrors `setBackupPlateComment(String)`.
    pub fn set_backup_plate_comment(&mut self, plate_comment: Option<String>) {
        self.plate_comment = plate_comment;
    }

    /// Determines whether the symbol at `address` has already been demangled. Memory symbols are
    /// checked for the presence of the demangled name, while external symbols simply check
    /// whether a demangled/alternate name has already been assigned.
    ///
    /// Mirrors `isAlreadyDemangled(Program, Address)`. Returns `false` when this object has no
    /// name yet, where Java would throw a `NullPointerException` out of `ensureNameLength`.
    pub fn is_already_demangled(&self, program: &mut dyn Program, address: &Address) -> bool {
        let Some(symbol_name) = self.name.as_deref().map(ensure_name_length) else {
            return false;
        };

        if address.is_external_address() {
            let Some(symbol_table) = program.get_symbol_table() else {
                return false;
            };
            let Some(ext_symbol) = symbol_table.get_primary_symbol(address).ok().flatten() else {
                return false;
            };
            let Some(external_manager) = program.get_external_manager() else {
                return false;
            };
            return external_manager
                .get_external_location(ext_symbol)
                .is_some_and(|ext_loc| ext_loc.get_original_imported_name().is_some());
        }

        let Some(symbol_table) = program.get_symbol_table() else {
            return false;
        };
        let symbols = symbol_table.get_symbols(address).unwrap_or_default();
        symbols.iter().any(|symbol| {
            symbol.get_name() == symbol_name
                && symbol.get_parent_namespace().is_some_and(|ns| !ns.is_global())
                && matches!(symbol.get_symbol_type(), SymbolType::Label | SymbolType::Function)
        })
    }

    /// Applies this object's name as a symbol at `addr`, creating the demangled namespace as
    /// needed. Passing `None` for `symbol_name` uses this object's own name.
    ///
    /// Mirrors both `applyDemangledName` overloads (Rust has no overloading; the no-name Java
    /// overload is `symbol_name: None`).
    ///
    /// Note: if the original mangled symbol incorrectly resides within a non-global namespace,
    /// that namespace is ignored when applying the demangled symbol.
    pub fn apply_demangled_name(
        &self,
        symbol_name: Option<&str>,
        addr: &Address,
        set_primary: bool,
        function_namespace_permitted: bool,
        prog: &mut dyn Program,
    ) -> Result<Option<Arc<dyn Symbol>>, InvalidInputException> {
        let symbol_name = match symbol_name.or(self.name.as_deref()) {
            Some(name) => ensure_name_length(name),
            None => {
                return Err(InvalidInputException::with_message(
                    "demangled object has no name to apply",
                ))
            }
        };

        if addr.is_external_address() {
            return Ok(self.update_external_symbol(prog, addr, &symbol_name));
        }

        // Create the demangled symbol. If the name already exists at the address in the global
        // space, it will be moved into the specified namespace by the symbol table.
        let ns = Self::create_namespace(prog, self.namespace.as_deref(), None, function_namespace_permitted);
        let demangled_symbol = DefaultSymbolUtilities.create_preferred_label_or_function_symbol(
            prog,
            addr,
            ns.clone(),
            &symbol_name,
            SourceType::Analysis,
        )?;

        if demangled_symbol.is_none() || !set_primary {
            return Ok(demangled_symbol);
        }

        Ok(set_label_primary(prog, addr, &symbol_name, ns))
    }

    /// Renames the external symbol at `external_addr`, moving it into the demangled namespace.
    ///
    /// Mirrors the private `updateExternalSymbol(Program, Address, String, Demangled)`, whose
    /// `demangledNamespace` argument is always this object's own namespace.
    fn update_external_symbol(
        &self,
        program: &mut dyn Program,
        external_addr: &Address,
        symbol_name: &str,
    ) -> Option<Arc<dyn Symbol>> {
        let symbol = program
            .get_symbol_table()
            .and_then(|symbol_table| symbol_table.get_primary_symbol(external_addr).ok().flatten());
        let Some(symbol) = symbol else {
            Msg::error(
                LOG_ORIGINATOR,
                &format!("No such external address {external_addr} for {symbol_name}"),
            );
            return None;
        };

        let parent_namespace = symbol.get_parent_namespace();
        let ns =
            Self::create_namespace(program, self.namespace.as_deref(), parent_namespace, false);

        let result = ns.and_then(|ns| {
            program
                .get_external_manager()
                .and_then(|external_manager| {
                    external_manager.get_external_location_mut(Arc::clone(&symbol))
                })
                .map(|ext_loc| ext_loc.set_name(ns, symbol_name, SourceType::Imported))
        });
        if let Some(Err(e)) = result {
            Msg::error_with_error(
                LOG_ORIGINATOR,
                &format!(
                    "Unexpected Exception setting name and namespace for {symbol_name} in {}",
                    symbol
                        .get_parent_namespace()
                        .map_or_else(String::new, |ns| ns.get_name_with_path(true))
                ),
                &e,
            );
        }

        Some(symbol)
    }

    /// Gets or creates the given demangled namespace under `parent_namespace`, defaulting to the
    /// program's global namespace. The result may be only a partial namespace if errors occur;
    /// the caller should check it and adjust any symbol creation accordingly.
    ///
    /// Mirrors the static `createNamespace(Program, Demangled, Namespace, boolean)`. Returns
    /// `None` only when no parent was supplied and the program has no global namespace.
    pub fn create_namespace(
        program: &mut dyn Program,
        type_namespace: Option<&dyn Demangled>,
        parent_namespace: Option<Arc<dyn Namespace>>,
        function_permitted: bool,
    ) -> Option<Arc<dyn Namespace>> {
        let mut namespace = match parent_namespace {
            Some(parent) => parent,
            None => program.get_global_namespace()?,
        };

        let namespace_names = namespace_list(type_namespace);
        let symbol_table = program.get_symbol_table()?;
        for namespace_name in namespace_names {
            // TODO - This is compensating for too long templates. We should probably genericize
            //        templates so that any class with the same number of template parameters and
            //        same name is the same class--would that reflect reality?
            let namespace_name = ensure_name_length(&namespace_name);

            match symbol_table.get_or_create_name_space(
                Arc::clone(&namespace),
                &namespace_name,
                SourceType::Imported,
            ) {
                Ok(created) => namespace = created,
                Err(GetOrCreateNamespaceError::Duplicate(_)) => {
                    Msg::error(
                        LOG_ORIGINATOR,
                        &format!(
                            "Failed to create namespace due to name conflict: {}",
                            namespace_qualified_name(namespace.as_ref(), &namespace_name)
                        ),
                    );
                    break;
                }
                Err(GetOrCreateNamespaceError::InvalidInput(e)) => {
                    Msg::error(LOG_ORIGINATOR, &format!("Failed to create namespace: {e}"));
                    break;
                }
            }

            let ns_symbol = namespace.get_symbol();
            if !is_permitted_namespace_type(ns_symbol.get_symbol_type(), function_permitted) {
                let mut allowed_types = "SymbolType.CLASS, SymbolType.NAMESPACE".to_string();
                if function_permitted {
                    allowed_types.push_str(", SymbolType.FUNCTION");
                }

                Msg::error(
                    LOG_ORIGINATOR,
                    &format!(
                        "Bad namespace type - must be one of: {allowed_types}{}",
                        namespace_qualified_name(namespace.as_ref(), &namespace_name)
                    ),
                );
                break;
            }
        }

        Some(namespace)
    }
}

/// Ensures a name does not pass the length limit defined by Ghidra.
///
/// Mirrors the protected static `ensureNameLength(String)`. Over-long names are usually API
/// methods templated so heavily that the name becomes unreadable; rather than lose the type
/// specificity the template arguments provide, the name is trimmed to a length that still leaves
/// some of them, with some trailing data appended in case that is helpful.
pub fn ensure_name_length(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let length = chars.len();
    if length <= MAX_SYMBOL_NAME_LENGTH {
        return name.to_string();
    }

    let mut buffy: String = chars[..MAX_SYMBOL_NAME_LENGTH / 2].iter().collect();
    buffy.push_str("...");
    buffy.extend(chars[length - 100..].iter());
    buffy
}

/// Builds the outermost-first list of namespace names for a demangled namespace chain.
///
/// Mirrors the private static `getNamespaceList(Demangled)`.
fn namespace_list(type_namespace: Option<&dyn Demangled>) -> Vec<String> {
    let mut list = Vec::new();
    let mut ns = type_namespace;
    while let Some(current) = ns {
        list.insert(0, current.get_namespace_name());
        ns = current.get_namespace();
    }
    list
}

/// Mirrors the private static `isPermittedNamespaceType(SymbolType, boolean)`.
fn is_permitted_namespace_type(symbol_type: SymbolType, function_permitted: bool) -> bool {
    matches!(symbol_type, SymbolType::Class | SymbolType::Namespace)
        || (function_permitted && symbol_type == SymbolType::Function)
}

/// Makes the label named `symbol_name` in `namespace` the primary symbol at `addr`, and returns
/// the resulting primary symbol.
///
/// Stands in for `new SetLabelPrimaryCmd(addr, symbolName, ns).applyTo(prog)` followed by
/// `symbolTable.getPrimarySymbol(addr)`. Only the command's plain-label branch is modeled: its
/// function-symbol branch swaps names between the function symbol and the new label using
/// `Symbol.setNameAndNamespace`/`Symbol.delete`, neither of which is ported. As in the original,
/// failure to promote is not propagated -- the command reports it through `getStatusMsg()`, which
/// this call site never reads -- so the current primary symbol is returned either way.
fn set_label_primary(
    prog: &mut dyn Program,
    addr: &Address,
    symbol_name: &str,
    namespace: Option<Arc<dyn Namespace>>,
) -> Option<Arc<dyn Symbol>> {
    let namespace = namespace.or_else(|| prog.get_global_namespace())?;
    let symbol_table = prog.get_symbol_table()?;
    let symbol = symbol_table
        .find_symbol_by_name_address_namespace(symbol_name, addr, namespace.as_ref())
        .ok()
        .flatten();
    if let Some(symbol) = symbol {
        let _ = symbol_table.set_primary_symbol(symbol.get_id());
    }
    symbol_table.get_primary_symbol(addr).ok().flatten()
}

/// A demangled object: something the demangler produced that can be applied to a program.
///
/// Port of the behaviour half of `ghidra.app.util.demangler.DemangledObject`; see the module docs
/// for how the class is split between this trait and [`DemangledObjectBase`].
pub trait DemangledObject: Demangled {
    /// The shared demangled-object state. Implementors return their embedded
    /// [`DemangledObjectBase`].
    fn base(&self) -> &DemangledObjectBase;

    /// Mutable counterpart of [`base`](Self::base).
    fn base_mut(&mut self) -> &mut DemangledObjectBase;

    /// Returns a complete signature for the demangled symbol, e.g. `unsigned long foo`,
    /// `unsigned char * ClassA::getFoo(float, short *)`, or `void * getBar(int **, MyStruct &)`.
    ///
    /// Note: based on the underlying mangling scheme, the return type may or may not be specified
    /// in the signature.
    ///
    /// Mirrors the abstract `getSignature(boolean format)`, where `format` requests pretty
    /// printing. [`Demangled::get_signature`] is `getSignature(false)`.
    fn get_signature_formatted(&self, format: bool) -> String;

    /// Creates descriptive text intended to be used as documentation. The text defaults to the
    /// original demangled text; if that is not available, then any text set by
    /// [`DemangledObjectBase::set_backup_plate_comment`] is used. The last choice is the
    /// signature generated by [`get_signature_formatted`](Self::get_signature_formatted).
    ///
    /// Mirrors the protected `generatePlateComment()`.
    fn generate_plate_comment(&self) -> String {
        if let Some(original_demangled) = self.base().original_demangled.as_deref() {
            return original_demangled.to_string();
        }
        match self.base().plate_comment() {
            Some(plate_comment) => plate_comment.to_string(),
            None => self.get_signature_formatted(true),
        }
    }

    /// Applies this demangled object's detail to the specified program.
    ///
    /// NOTE: An open program transaction must be established prior to invoking this method.
    ///
    /// Mirrors `applyTo(Program, Address, DemanglerOptions, TaskMonitor)`, whose base
    /// implementation applies the plate comment only; subclasses override to apply more.
    fn apply_to(
        &self,
        program: &mut dyn Program,
        address: &Address,
        options: &DemanglerOptions,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, DemangledException> {
        let _ = (options, monitor);
        self.apply_plate_comment_only(program, address)
    }

    /// Applies this demangled object's detail using the address and options of the
    /// [`MangledContext`] previously set on it.
    ///
    /// NOTE: An open program transaction must be established prior to invoking this method.
    ///
    /// Mirrors `applyUsingContext(TaskMonitor)`. `program` is passed explicitly rather than read
    /// from the context; see the module's deviations.
    fn apply_using_context(
        &self,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, DemangledException> {
        let Some(mangled_context) = self.base().mangled_context.clone() else {
            return Err(DemangledException::from_message(format!(
                "Null context found for: {}",
                self.base().get_mangled_string()
            )));
        };
        let Some(address) = mangled_context.address() else {
            return Err(DemangledException::from_message(format!(
                "Null address in context for: {}",
                self.base().get_mangled_string()
            )));
        };
        self.apply_to(program, &address, mangled_context.options(), monitor)
    }

    /// Applies this object's plate comment at `address`, appending it to any existing plate
    /// comment that does not already contain it.
    ///
    /// Mirrors `applyPlateCommentOnly(Program, Address)`: symbols outside program memory are
    /// skipped (reported as applied), and a symbol that did not demangle is an error.
    fn apply_plate_comment_only(
        &self,
        program: &mut dyn Program,
        address: &Address,
    ) -> Result<bool, DemangledException> {
        if !self.base().demangled_name_successfully() {
            return Err(DemangledException::from_message(format!(
                "Symbol did not demangle at address: {address}"
            )));
        }

        let in_memory = program.get_memory().is_some_and(|memory| memory.contains(address));
        if !address.is_memory_address() || !in_memory {
            return Ok(true); // skip this symbol
        }

        let new_comment = self.generate_plate_comment();
        let Some(listing) = program.get_listing() else {
            return Ok(true);
        };
        let comment = listing.get_comment(CommentType::Plate, address);
        let updated = match comment {
            Some(comment) if comment.contains(&new_comment) => None,
            Some(comment) => Some(format!("{comment}\n{new_comment}")),
            None => Some(new_comment),
        };
        if let Some(updated) = updated {
            listing.set_comment(address, CommentType::Plate, Some(updated));
        }
        Ok(true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal concrete `DemangledObject`, standing in for one of the Java subclasses so the
    /// base's behaviour can be exercised through the trait. It renders a signature the way
    /// `DemangledVariable` does: the (optionally namespace-qualified) name, with the storage
    /// class prefixed when pretty printing is requested.
    pub(crate) struct TestDemangledObject {
        base: DemangledObjectBase,
    }

    impl TestDemangledObject {
        pub(crate) fn new(mangled: &str, original_demangled: Option<&str>, name: &str) -> Self {
            let mut base =
                DemangledObjectBase::new(mangled, original_demangled.map(str::to_string));
            base.set_name(Some(name));
            Self { base }
        }
    }

    impl DemangledObject for TestDemangledObject {
        fn base(&self) -> &DemangledObjectBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut DemangledObjectBase {
            &mut self.base
        }

        fn get_signature_formatted(&self, format: bool) -> String {
            let mut buffer = String::new();
            if format {
                if let Some(storage_class) = &self.base.storage_class {
                    buffer.push_str(storage_class);
                    buffer.push_str(SPACE);
                }
            }
            buffer.push_str(&self.get_namespace_string());
            buffer
        }
    }

    impl Demangled for TestDemangledObject {
        fn set_mangled_context(&mut self, mangled_context: MangledContext) {
            self.base.mangled_context = Some(mangled_context);
        }

        fn get_mangled_context(&self) -> Option<MangledContext> {
            self.base.mangled_context.clone()
        }

        fn get_mangled_string(&self) -> String {
            self.base.get_mangled_string().to_string()
        }

        fn get_original_demangled(&self) -> String {
            self.base.original_demangled.clone().unwrap_or_default()
        }

        fn get_name(&self) -> String {
            self.base.get_name().unwrap_or_default().to_string()
        }

        fn set_name(&mut self, name: &str) {
            self.base.set_name(Some(name));
        }

        fn get_demangled_name(&self) -> String {
            self.base.get_demangled_name().unwrap_or_default().to_string()
        }

        fn get_namespace(&self) -> Option<&dyn Demangled> {
            self.base.get_namespace()
        }

        fn set_namespace(&mut self, namespace: Option<Box<dyn Demangled>>) {
            self.base.set_namespace(namespace);
        }

        fn get_namespace_string(&self) -> String {
            self.base.namespace_string_with(&self.get_namespace_name())
        }

        fn get_namespace_name(&self) -> String {
            self.get_name()
        }

        fn get_signature(&self) -> String {
            self.get_signature_formatted(false)
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }
    }

    #[test]
    fn set_name_strips_signature_spaces_trims_and_underscores() {
        // Java: setName(" ClassA::getFoo(float, short *) ") keeps the raw text as the demangled
        // name, and derives the symbol name by stripping the superfluous spaces around
        // `(`/`,`/`*`, trimming, then replacing the remaining spaces with underscores.
        let obj = TestDemangledObject::new(
            "_ZN6ClassA6getFooEfPs",
            None,
            " ClassA::getFoo(float, short *) ",
        );
        assert_eq!(obj.get_demangled_name(), " ClassA::getFoo(float, short *) ");
        assert_eq!(obj.get_name(), "ClassA::getFoo(float,short*)");
    }

    #[test]
    fn demangled_name_succeeds_unless_the_name_equals_the_mangled_string() {
        let demangled = TestDemangledObject::new("_Z3foov", None, "foo");
        assert!(demangled.base().demangled_name_successfully());

        // Java: `demangledNameSucceeded = !mangled.equals(name)`, so a "demangled" name that is
        // just the mangled string back again counts as a failure.
        let not_demangled = TestDemangledObject::new("_Z3foov", None, "_Z3foov");
        assert!(!not_demangled.base().demangled_name_successfully());
    }

    #[test]
    fn namespace_string_prepends_the_parent_path() {
        use crate::demangler::demangled_type::DemangledType;

        let mut obj = TestDemangledObject::new("_ZN3Foo3BarE", None, "Bar");
        obj.set_namespace(Some(Box::new(DemangledType::new("m", "o", "Foo"))));

        assert_eq!(obj.get_namespace_string(), "Foo::Bar");
        // getNamespaceName() defaults to getName(), so it omits the parent path
        assert_eq!(obj.get_namespace_name(), "Bar");
        // the final getSignature() is getSignature(false)
        assert_eq!(obj.get_signature(), "Foo::Bar");
    }

    #[test]
    fn generate_plate_comment_prefers_original_then_backup_then_signature() {
        // 1. the original demangled string wins
        let mut obj = TestDemangledObject::new("_Z3foov", Some("foo()"), "foo");
        obj.base_mut().set_backup_plate_comment(Some("backup".to_string()));
        assert_eq!(obj.generate_plate_comment(), "foo()");

        // 2. with no original demangled string, the backup comment is used
        obj.base_mut().original_demangled = None;
        assert_eq!(obj.generate_plate_comment(), "backup");

        // 3. with neither, the pretty-printed signature is used
        obj.base_mut().set_backup_plate_comment(None);
        obj.base_mut().storage_class = Some("const".to_string());
        assert_eq!(obj.generate_plate_comment(), "const foo");
    }

    #[test]
    fn apply_plate_comment_only_errors_when_the_symbol_did_not_demangle() {
        let obj = TestDemangledObject::new("_Z3foov", None, "_Z3foov");
        let mut program = MockProgram;
        let address = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        )
        .address(0x1000);

        let err = obj
            .apply_plate_comment_only(&mut program, &address)
            .expect_err("a symbol that did not demangle is an error");
        assert!(
            err.to_string().contains("Symbol did not demangle at address"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn apply_plate_comment_only_skips_addresses_outside_program_memory() {
        // Java returns true (reporting success) without touching the listing when the address is
        // not a memory address the program contains.
        let obj = TestDemangledObject::new("_Z3foov", Some("foo()"), "foo");
        let mut program = MockProgram;
        let address = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            1,
        )
        .address(0x1000);

        assert!(obj.apply_plate_comment_only(&mut program, &address).unwrap());
    }

    #[test]
    fn apply_using_context_requires_a_context() {
        let obj = TestDemangledObject::new("_Z3foov", None, "foo");
        let mut program = MockProgram;
        let err = obj
            .apply_using_context(&mut program, &crate::util::task::DummyMonitor)
            .expect_err("no context was set");
        assert!(err.to_string().contains("Null context found for: _Z3foov"), "unexpected: {err}");
    }

    #[test]
    fn with_context_takes_its_mangled_string_from_the_context() {
        let context =
            MangledContext::new(None, DemanglerOptions::new(), "_Z3foov".to_string(), None);
        let base = DemangledObjectBase::with_context(context, Some("foo()".to_string()));
        assert_eq!(base.get_mangled_string(), "_Z3foov");
        // the constructor seeds both demangled strings from the same argument
        assert_eq!(base.original_demangled.as_deref(), Some("foo()"));
        assert_eq!(base.raw_demangled.as_deref(), Some("foo()"));
        assert!(base.mangled_context.is_some());
    }

    #[test]
    fn ensure_name_length_trims_over_long_names() {
        let short = "a".repeat(MAX_SYMBOL_NAME_LENGTH);
        assert_eq!(ensure_name_length(&short), short);

        // Java keeps the first half of the limit, then "...", then the trailing 100 characters.
        let long: String =
            "a".repeat(MAX_SYMBOL_NAME_LENGTH).chars().chain("b".repeat(200).chars()).collect();
        let trimmed = ensure_name_length(&long);
        assert_eq!(trimmed.chars().count(), MAX_SYMBOL_NAME_LENGTH / 2 + 3 + 100);
        assert!(trimmed.starts_with(&"a".repeat(MAX_SYMBOL_NAME_LENGTH / 2)));
        assert!(trimmed.ends_with(&"b".repeat(100)));
        assert!(trimmed.contains("..."));
    }
}
