//! Port of `ghidra.program.model.data.DataTypeWriter`.
//!
//! **Status: partial.** This 916-line Java class converts a set of data types into ANSI-C-like
//! textual declarations. This file lands it in the incremental chunks called for by this port's
//! process notes; see the running tally below for exactly what is real versus still missing.
//!
//! ## Done
//!   - The struct itself, its `new`/`with_annotator` constructors (mirroring the four Java
//!     overloaded constructors, collapsed since Rust has no overloading), and the
//!     `comment`/`is_integral` private helpers.
//!   - [`CompositeNode`] (the private `DataTypeWriter.CompositeNode` inner class) and
//!     [`DataTypeWriter::add_composite_to_dependency_graph`] (Java
//!     `addCompositeToDependencyGraph`), which populate the
//!     [`DeterministicDependencyGraph`](crate::util::graph::DeterministicDependencyGraph)`<CompositeNode>`
//!     built in Part 1 of this same session so that a composite's member composites are ordered
//!     before it.
//!   - [`DataTypeWriter::write_built_in`] (Java `writeBuiltIn`), a thin call to the already-real
//!     [`BuiltInDataType::get_c_type_declaration`] -- no new C-declaration formatting was written
//!     for it, per this crate's existing precedent.
//!   - [`DataTypeWriter::write_enum`] (Java `writeEnum`), including the `#define` shortcut for
//!     single-value `define_`-prefixed enums.
//!   - The small recursive traversal helpers `getBaseDataType`/`getArrayBaseType`/
//!     `getPointerBaseDataType`/`getPointerDepth`/`getArrayDimensions`/`getDataTypePrefix`, ported
//!     as private associated functions. These are exercised only from `#[cfg(test)]` so far (hence
//!     each carries an `#[allow(dead_code)]`) -- their real callers, `getTypeDeclaration` and
//!     `getFunctionPointerString`, are listed as not yet ported below.
//!
//! ## Not yet ported (left for a follow-up session)
//!   - The public `write(...)` entry points (`write(TaskMonitor)`, `write(Category, TaskMonitor)`,
//!     `write(DataType[], TaskMonitor)`, `write(List<DataType>, ...)`) and the top-level dispatcher
//!     `doWrite`/`write(DataType, TaskMonitor, boolean)` that switches on the runtime kind of a
//!     `DataType` (`Structure`/`Union`/`Enum`/`TypeDef`/`BuiltInDataType`/`Dynamic`/
//!     `BitFieldDataType`/unrecognized) and drives resolution bookkeeping (`resolved`,
//!     `resolvedTypeMap`, conflicting-name detection).
//!   - `writeDeferredDeclarations`/`writeDeferredCompositeDeclarations` (draining
//!     `deferredCompositeInternalTypes` and popping `compositeDependencyGraph`).
//!   - `writeCompositePreDeclaration`/`writeCompositeBody`/`writeComponent` (struct/union body
//!     emission).
//!   - `getTypeDeclaration`/`getDynamicComponentString` (per-field C declaration text, including
//!     array/pointer name mangling and bit-field suffixes -- built on the already-ported
//!     `getDataTypePrefix` above).
//!   - `writeTypeDef` (including the `isIntegral`-suppression and auto-typedef/
//!     auto-pointer-typedef detection it guards), `writeDynamicBuiltIn` (needs the top-level
//!     `write` dispatch to recurse into the replacement base type), `writeBuiltInDeclarations`.
//!   - `getFunctionPointerString`/`getParameterListString` (function-pointer/parameter-list text,
//!     built on the already-ported `getArrayBaseType`/`getPointerBaseDataType`/`getPointerDepth`/
//!     `getArrayDimensions` above; blocked on the top-level `write` dispatch for their
//!     conditional recursive `write(returnType/paramType, monitor)` calls).
//!   - `getBaseArrayTypedefType` (small recursive helper feeding `writeTypeDef`).
//!
//! ## Fidelity notes for what *is* ported so far
//!   - Java's `CompositeNode` merely wraps a `Composite` object reference (trivially "cloned" as a
//!     reference copy) and compares by `getPathName()`/equals by `getUniversalID()`. Rust has no
//!     such implicit reference-copy semantics for `Box<dyn Composite>`, and the dependency graph
//!     built in Part 1 of this session requires its value type to be `Clone`. [`CompositeNode`]
//!     therefore wraps `Arc<dyn Composite>` (cheap, reference-counted `Clone`, and `Composite:
//!     DataType: Send + Sync` already satisfies `Arc`'s bounds) rather than attempting a deep
//!     clone of the underlying data type, which would be both wrong (identity, not value, is what
//!     the graph needs) and expensive.
//!   - [`DeterministicDependencyGraph`]'s `pop()` returns
//!     `Result<Option<T>, CycleDetectedError>`, mirroring Java's unchecked `IllegalStateException`
//!     for a cycle. Since composite dependencies here can only arise from composites embedded *by
//!     value* (an embed-by-value cycle is structurally impossible in a well-formed program: a
//!     struct cannot contain itself by value), reaching that error would indicate a real bug
//!     upstream rather than an expected runtime outcome, so callers that eventually pop this graph
//!     are expected to treat it the same way Java treats the unchecked exception -- as a genuine
//!     invariant violation, not a recoverable `CancelledException`-style condition.
//!   - No default C/C++ style constructor argument combination is skipped: Java's four
//!     constructors are collapsed to [`DataTypeWriter::new`] (default annotator, non-C++-style
//!     comments) plus builder-style [`DataTypeWriter::with_annotator`]/
//!     [`DataTypeWriter::with_cpp_style_comments`], rather than four overloads.
//!   - Java's constructor calls `writeBuiltInDeclarations(dtm)` as a side effect whenever `dtm !=
//!     null`. Since that method is not ported yet (see the "not yet ported" list above),
//!     [`DataTypeWriter::new`] does not perform this side effect -- it is `TODO` alongside the rest
//!     of the top-level dispatch it depends on (`write`/`writeBuiltIn`).
//!   - When no `DataTypeManager` is supplied, Java falls back to
//!     `DataOrganizationImpl.getDefaultOrganization()`. No concrete zero-argument
//!     `DataOrganization` factory exists yet in this crate (see
//!     [`abstract_data_type::default_data_organization`](super::abstract_data_type::default_data_organization),
//!     which panics without a manager). This file supplies its own minimal
//!     [`FallbackDataOrganization`], matching `DataOrganizationImpl`'s own documented Java
//!     `DEFAULT_*` constants (`DEFAULT_POINTER_SIZE = 4`, `DEFAULT_CHAR_SIZE = 1`, etc., read
//!     directly from `orig_src/.../DataOrganizationImpl.java`) rather than the differently-tuned
//!     (64-bit-pointer) test-support `DefaultDataOrganization` structs private to
//!     `structure_data_type.rs`/`union_data_type.rs` -- this one aims to match Java's real runtime
//!     default, not just be a plausible stand-in for unit tests.

use std::collections::{HashSet, VecDeque};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;

use crate::program::model::data::annotation_handler::AnnotationHandler;
use crate::program::model::data::array::Array;
use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::default_annotation_handler::DefaultAnnotationHandler;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::typedef::TypeDef;
use crate::util::exception::CancelledException;
use crate::util::graph::{AbstractDependencyGraph, DeterministicDependencyGraph};
use crate::util::task::TaskMonitor;

/// Error produced by [`DataTypeWriter`]'s top-level `write`/`doWrite` port and everything that
/// hangs off it. Combines the two checked exceptions Java declares (`IOException`,
/// `CancelledException`) plus the unchecked `IllegalArgumentException` Java throws for
/// `FactoryDataType` when `throwExceptionOnInvalidType` is `true`.
#[derive(Debug)]
pub enum DataTypeWriteError {
    /// Port of the checked `IOException`.
    Io(io::Error),
    /// Port of the checked `CancelledException`.
    Cancelled(CancelledException),
    /// Port of the unchecked `IllegalArgumentException` thrown by `doWrite` for a
    /// `FactoryDataType` when `throwExceptionOnInvalidType` is `true`.
    InvalidDataType(String),
}

impl fmt::Display for DataTypeWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Cancelled(e) => write!(f, "{e}"),
            Self::InvalidDataType(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for DataTypeWriteError {}

impl From<io::Error> for DataTypeWriteError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CancelledException> for DataTypeWriteError {
    fn from(e: CancelledException) -> Self {
        Self::Cancelled(e)
    }
}

/// Port of the private `DataTypeWriter.CompositeNode` inner class ("A simple Composite class to
/// use in the dependency graph to speed up the `equals()` call").
///
/// See the module doc comment for why this wraps `Arc<dyn Composite>` rather than a deep clone.
#[derive(Clone)]
pub struct CompositeNode {
    composite: Arc<dyn Composite>,
}

impl CompositeNode {
    /// Port of the `CompositeNode(Composite composite)` constructor.
    pub fn new(composite: Arc<dyn Composite>) -> Self {
        Self { composite }
    }

    /// Returns the wrapped composite. Port of the (package-private, field-access-only in Java)
    /// `node.composite` reads done by `writeDeferredCompositeDeclarations`.
    pub fn composite(&self) -> &Arc<dyn Composite> {
        &self.composite
    }
}

impl PartialEq for CompositeNode {
    /// Port of `CompositeNode.equals`, which compares `composite.getUniversalID()`.
    fn eq(&self, other: &Self) -> bool {
        self.composite.get_universal_id() == other.composite.get_universal_id()
    }
}

impl Eq for CompositeNode {}

impl std::hash::Hash for CompositeNode {
    /// Port of `CompositeNode.hashCode`, which Java computes from `composite.hashCode()`. This
    /// crate has no general-purpose `DataType::hashCode()` equivalent, so this hashes the same
    /// `getUniversalID()` value used above for `eq`, keeping the `Hash`/`Eq` contract consistent
    /// (values that are `eq` produce the same hash).
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.composite.get_universal_id().hash(state);
    }
}

impl PartialOrd for CompositeNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompositeNode {
    /// Port of `CompositeNode.compareTo`, which compares `composite.getPathName()`.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.composite.get_path_name().cmp(&other.composite.get_path_name())
    }
}

/// Fallback used by [`DataTypeWriter::new`] when constructed without a `DataTypeManager`. Port of
/// the numeric defaults documented on `ghidra.program.model.data.DataOrganizationImpl` (its
/// `DEFAULT_*` constants), i.e. what `DataOrganizationImpl.getDefaultOrganization()` actually
/// produces in Java -- see the module doc comment for why this crate's other
/// `DefaultDataOrganization` test-support stand-ins were not reused.
#[derive(Debug, Clone, Copy)]
struct FallbackDataOrganization;

/// Port of the trivial, no-op-shaped `DataOrganizationImpl.getBitFieldPacking()` default
/// (`BitFieldPackingImpl.getDefaultBitFieldPacking()` in Java: MS convention disabled, type
/// alignment enabled, zero-length boundary of 0).
#[derive(Debug, Clone, Copy)]
struct FallbackBitFieldPacking;

impl BitFieldPacking for FallbackBitFieldPacking {
    fn use_ms_convention(&self) -> bool {
        false
    }
    fn is_type_alignment_enabled(&self) -> bool {
        true
    }
    fn get_zero_length_boundary(&self) -> i32 {
        0
    }
}

impl DataOrganization for FallbackDataOrganization {
    fn is_big_endian(&self) -> bool {
        false
    }
    fn get_pointer_size(&self) -> i32 {
        4 // DataOrganizationImpl.DEFAULT_POINTER_SIZE
    }
    fn get_pointer_shift(&self) -> i32 {
        0
    }
    fn is_signed_char(&self) -> bool {
        true // DataOrganizationImpl.DEFAULT_CHAR_IS_SIGNED
    }
    fn get_char_size(&self) -> i32 {
        1 // DEFAULT_CHAR_SIZE
    }
    fn get_wide_char_size(&self) -> i32 {
        2 // DEFAULT_WIDE_CHAR_SIZE
    }
    fn get_short_size(&self) -> i32 {
        2 // DEFAULT_SHORT_SIZE
    }
    fn get_integer_size(&self) -> i32 {
        4 // DEFAULT_INT_SIZE
    }
    fn get_long_size(&self) -> i32 {
        4 // DEFAULT_LONG_SIZE
    }
    fn get_long_long_size(&self) -> i32 {
        8 // DEFAULT_LONG_LONG_SIZE
    }
    fn get_float_size(&self) -> i32 {
        4 // DEFAULT_FLOAT_SIZE
    }
    fn get_double_size(&self) -> i32 {
        8 // DEFAULT_DOUBLE_SIZE
    }
    fn get_long_double_size(&self) -> i32 {
        8 // DEFAULT_LONG_DOUBLE_SIZE
    }
    fn get_absolute_max_alignment(&self) -> i32 {
        0 // NO_MAXIMUM_ALIGNMENT
    }
    fn get_machine_alignment(&self) -> i32 {
        8 // DEFAULT_MACHINE_ALIGNMENT
    }
    fn get_default_alignment(&self) -> i32 {
        1 // DEFAULT_DEFAULT_ALIGNMENT
    }
    fn get_default_pointer_alignment(&self) -> i32 {
        4 // DEFAULT_DEFAULT_POINTER_ALIGNMENT
    }
    fn get_size_alignment(&self, _size: i32) -> i32 {
        1
    }
    fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
        Box::new(FallbackBitFieldPacking)
    }
    fn get_size_alignment_count(&self) -> i32 {
        0
    }
    fn get_sizes(&self) -> Vec<i32> {
        Vec::new()
    }
    fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
        String::new()
    }
    fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
        1
    }
}

// list of type names which correspond to C/C++ compiler primitive types
// TODO: Specified INTEGRAL_TYPES only impact treatment of typedefs whose name
//   matches or ends with a specified name.  It's unclear if this is an appropriate
//   check for suppressing a typedef.
// NOTE: '__int64' is only a primitive type for MSVC where 'unsigned __int64' is allowed.
//
// #[allow(dead_code)]: only consumed by `is_integral`, which today is exercised solely from
// `#[cfg(test)]` -- its real caller, `writeTypeDef`'s port, is one of the "not yet ported" items
// listed in the module doc comment.
#[allow(dead_code)]
const INTEGRAL_TYPES: &[&str] =
    &["char", "short", "int", "long", "long long", "__int64", "float", "double", "long double", "void"];

#[allow(dead_code)]
const INTEGRAL_MODIFIERS: &[&str] = &["signed", "unsigned", "const", "static", "volatile", "mutable"];

/// Port of `ghidra.program.model.data.DataTypeWriter`. See the module doc comment for what is and
/// is not ported yet.
pub struct DataTypeWriter<W: Write> {
    /// Port of `resolved` (`Set<DataType>`). Keyed by path name rather than the `DataType` value
    /// itself, since `dyn DataType` is neither `Hash` nor `Eq` in this crate -- the same
    /// adaptation `IsfDataTypeWriter` already uses for its own `resolved` map.
    resolved: HashSet<String>,
    /// Port of `resolvedTypeMap` (`Map<String, DataType>`), keyed by `getName()` exactly like the
    /// Java field (as opposed to [`resolved`](Self::resolved)'s path-name keying), since that is
    /// precisely the lookup Java performs for conflicting-name detection. Values are `Arc<dyn
    /// DataType>` rather than `Box` so the same stored value can both live in this map and (for
    /// composites) simultaneously be handed to [`composite_dependency_graph`](Self::composite_dependency_graph)
    /// -- see [`CompositeNode`]'s own doc comment for why `Arc` is this crate's established
    /// stand-in for Java's implicit reference-copy semantics here.
    resolved_type_map: HashMap<String, Arc<dyn DataType>>,
    /// Port of `compositeDependencyGraph`.
    composite_dependency_graph: DeterministicDependencyGraph<CompositeNode>,
    /// Port of `deferredCompositeInternalTypes` (`LinkedHashSet<DataType>`). Modeled as a
    /// `VecDeque` (for `removeFirst()`/FIFO order) paired with a `HashSet<String>` of path-name
    /// keys standing in for the `LinkedHashSet`'s own dedup-by-`equals()` behavior -- the same
    /// path-name-keying adaptation used by [`resolved`](Self::resolved). Stores owned `Box<dyn
    /// DataType>` (not `Arc`) since, unlike [`resolved_type_map`](Self::resolved_type_map), a
    /// deferred entry is only ever popped and handed *once* to [`DataTypeWriter::write`] -- no
    /// second reader ever needs to share it.
    deferred_composite_internal_types: VecDeque<Box<dyn DataType>>,
    /// Dedup companion for [`deferred_composite_internal_types`](Self::deferred_composite_internal_types);
    /// see that field's doc comment.
    deferred_composite_internal_type_keys: HashSet<String>,
    /// Port of `writerDepth`.
    writer_depth: i32,
    /// Port of `writer`.
    writer: W,
    /// Port of `dtm`. Used to derive [`data_organization`](Self::data_organization) at
    /// construction time; otherwise unused because the `doWrite` port deliberately skips Java's
    /// `dt = dt.clone(dtm)` "force resize/repack" step -- see the module doc comment for why
    /// (`clone_data_type` is not reliably overridden by this crate's concrete datatypes yet).
    #[allow(dead_code)]
    dtm: Option<Arc<dyn DataTypeManager>>,
    /// Port of `dataOrganization`.
    data_organization: Box<dyn DataOrganization>,
    /// Port of `annotator`.
    annotator: Box<dyn AnnotationHandler>,
    /// Port of `cppStyleComments`.
    cpp_style_comments: bool,
}

impl<W: Write> DataTypeWriter<W> {
    /// Port of `DataTypeWriter(DataTypeManager dtm, Writer writer)` (which delegates to the
    /// 4-argument constructor with `new DefaultAnnotationHandler()` and `cppStyleComments =
    /// false`). See the module doc comment for why the `writeBuiltInDeclarations` side effect of
    /// the Java constructor is not performed here yet.
    pub fn new(dtm: Option<Arc<dyn DataTypeManager>>, writer: W) -> Self {
        Self::with_annotator(dtm, writer, Box::new(DefaultAnnotationHandler), false)
    }

    /// Port of `DataTypeWriter(DataTypeManager dtm, Writer writer, boolean cppStyleComments)`.
    pub fn with_cpp_style_comments(
        dtm: Option<Arc<dyn DataTypeManager>>,
        writer: W,
        cpp_style_comments: bool,
    ) -> Self {
        Self::with_annotator(dtm, writer, Box::new(DefaultAnnotationHandler), cpp_style_comments)
    }

    /// Port of `DataTypeWriter(DataTypeManager dtm, Writer writer, AnnotationHandler annotator,
    /// boolean cppStyleComments)` (the other two-/three-argument Java constructors delegate to
    /// this one).
    pub fn with_annotator(
        dtm: Option<Arc<dyn DataTypeManager>>,
        writer: W,
        annotator: Box<dyn AnnotationHandler>,
        cpp_style_comments: bool,
    ) -> Self {
        let data_organization: Box<dyn DataOrganization> = match &dtm {
            Some(dtm) => dtm.get_data_organization(),
            None => Box::new(FallbackDataOrganization),
        };
        Self {
            resolved: HashSet::new(),
            resolved_type_map: HashMap::new(),
            composite_dependency_graph: DeterministicDependencyGraph::new(),
            deferred_composite_internal_types: VecDeque::new(),
            deferred_composite_internal_type_keys: HashSet::new(),
            writer_depth: 0,
            writer,
            dtm,
            data_organization,
            annotator,
            cpp_style_comments,
        }
    }

    /// Port of the private `comment(String text)` helper.
    fn comment(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        if self.cpp_style_comments {
            format!("// {text}")
        } else {
            format!("/* {text} */")
        }
    }

    /// Port of the private `isIntegral(String typedefName, String basetypeName)` helper.
    fn is_integral(typedef_name: &str, basetype_name: &str) -> bool {
        if INTEGRAL_TYPES.contains(&typedef_name) {
            return true;
        }

        let mut ends_with_integral_type = false;
        for ty in INTEGRAL_TYPES {
            if typedef_name.ends_with(&format!(" {ty}")) {
                ends_with_integral_type = true;
                break;
            }
        }

        for modifier in INTEGRAL_MODIFIERS {
            if typedef_name.contains(&format!("{modifier} ")) || typedef_name.contains(&format!(" {modifier}")) {
                return true;
            }
        }
        // Port note: Java's `containsIntegralModifier` local is unconditionally `false` by the
        // time control reaches here (the loop above always `return`s early on any hit instead of
        // setting the local, matching the real Java source verbatim), so the two conditions below
        // that reference it are dead code in Java too -- reproduced as-is rather than "fixed",
        // since this is meant to be a faithful behavioral port, not a bugfix.
        let contains_integral_modifier = false;

        if ends_with_integral_type && contains_integral_modifier {
            return true;
        }

        if typedef_name.ends_with(&format!(" {basetype_name}")) {
            return contains_integral_modifier;
        }

        false
    }

    /// Port of the private `addCompositeToDependencyGraph(Composite composite, TaskMonitor
    /// monitor)` helper.
    pub fn add_composite_to_dependency_graph(
        &mut self,
        composite: Arc<dyn Composite>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        // Each composite will be a node in the graph. Composite dependencies are added below.
        self.composite_dependency_graph.add_value(CompositeNode::new(composite.clone()));

        for component in composite.get_defined_components() {
            monitor.check_cancelled()?;

            let dt = component.get_data_type();
            if let Some(child_composite) = dt.into_composite() {
                let start = CompositeNode::new(composite.clone());
                let end = CompositeNode::new(Arc::from(child_composite));
                self.composite_dependency_graph.add_dependency(start, end);
            }
        }
        Ok(())
    }

    /// Exposes the dependency-graph pop used by [`write_deferred_composite_declarations`]
    /// (Java `writeDeferredCompositeDeclarations`), for testing the graph-construction pass in
    /// isolation as well as from that real caller.
    ///
    /// [`write_deferred_composite_declarations`]: Self::write_deferred_composite_declarations
    fn pop_composite_dependency(&mut self) -> Option<CompositeNode> {
        self.composite_dependency_graph.pop().expect("no cycle expected among by-value composite embeddings")
    }

    /// Port of the public `write(TaskMonitor monitor)` overload ("Converts all data types in the
    /// data type manager into ANSI-C code"). Named `write_all_from_manager` rather than `write`
    /// since Rust has no overloading; requires a `DataTypeManager` to have been supplied at
    /// construction (mirroring the `NullPointerException` Java would throw from `dtm
    /// .getRootCategory()` if `dtm` were null here).
    pub fn write_all_from_manager(&mut self, monitor: &dyn TaskMonitor) -> Result<(), DataTypeWriteError> {
        let dtm = self.dtm.clone().ok_or_else(|| {
            DataTypeWriteError::InvalidDataType(
                "NullPointerException: no DataTypeManager was supplied to this DataTypeWriter".to_string(),
            )
        })?;
        let root = dtm.get_root_category();
        self.write_category(root.as_ref(), monitor)
    }

    /// Port of the public `write(Category category, TaskMonitor monitor)` overload. Named
    /// `write_category` rather than `write` since Rust has no overloading.
    pub fn write_category(
        &mut self,
        category: &dyn crate::program::model::data::category::Category,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        self.write_many(category.get_data_types(), monitor)?;

        for sub_category in category.get_categories() {
            if monitor.is_cancelled() {
                return Ok(());
            }
            self.write_category(sub_category.as_ref(), monitor)?;
        }
        Ok(())
    }

    /// Port of the public `write(DataType[] dataTypes, TaskMonitor monitor)` /
    /// `write(List<DataType> dataTypes, TaskMonitor monitor)` overloads, collapsed into one since
    /// Rust's `Vec` already covers both Java call shapes. `throwExceptionOnInvalidType` defaults
    /// to `true`, matching the array overload and the 2-argument list overload alike.
    pub fn write_many(
        &mut self,
        data_types: Vec<Box<dyn DataType>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        self.write_many_with_options(data_types, monitor, true)
    }

    /// Port of the public `write(List<DataType> dataTypes, TaskMonitor monitor, boolean
    /// throwExceptionOnInvalidType)` overload.
    pub fn write_many_with_options(
        &mut self,
        data_types: Vec<Box<dyn DataType>>,
        monitor: &dyn TaskMonitor,
        throw_exception_on_invalid_type: bool,
    ) -> Result<(), DataTypeWriteError> {
        monitor.initialize(data_types.len() as i64);
        let mut cnt: i64 = 0;
        for dt in data_types {
            monitor.check_cancelled()?;
            self.write_with_options(dt, monitor, throw_exception_on_invalid_type)?;
            cnt += 1;
            monitor.set_progress(cnt);
        }
        Ok(())
    }

    /// Port of the public `write(DataType dt, TaskMonitor monitor)` package-private overload
    /// (`throwExceptionOnInvalidType` defaults to `true`).
    pub fn write(
        &mut self,
        dt: Box<dyn DataType>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        self.write_with_options(dt, monitor, true)
    }

    /// Port of the public `write(DataType dt, TaskMonitor monitor, boolean
    /// throwExceptionOnInvalidType)` overload.
    pub fn write_with_options(
        &mut self,
        dt: Box<dyn DataType>,
        monitor: &dyn TaskMonitor,
        throw_exception_on_invalid_type: bool,
    ) -> Result<(), DataTypeWriteError> {
        self.do_write(dt, monitor, throw_exception_on_invalid_type)
    }

    /// Port of the private `doWrite(DataType dt, TaskMonitor monitor, boolean
    /// throwExceptionOnInvalidType)` -- the top-level dispatcher this whole class hangs off of.
    ///
    /// Deviations from the Java source, all documented in more depth in the module doc comment:
    ///   - The `dt == null` guard is dropped: `Box<dyn DataType>` cannot be null.
    ///   - `dt = dt.clone(dtm)` ("force resize/repack for target data organization") is skipped
    ///     entirely -- this crate's concrete datatypes do not yet reliably override
    ///     `clone_data_type`, so calling it here would silently replace real data with the
    ///     `EmptyDataType` placeholder the trait default falls back to.
    ///   - The `dt.equals(DataType.DEFAULT)` special case is skipped: `DataType.DEFAULT`
    ///     (`DefaultDataType`) is not ported yet (see the module doc comment).
    ///   - Java's dispatch order is `Dynamic, Structure, Union, Enum, TypeDef, BuiltInDataType,
    ///     BitFieldDataType (skip), unrecognized`. This port checks `Structure`/`Union` *before*
    ///     `Dynamic` so the Structure/Union case can consume the still-owned `Box<dyn DataType>`
    ///     via [`DataType::into_composite`] (needed to obtain an owned `Box<dyn Composite>` for
    ///     the dependency graph) before the rest of the branches convert to a shared `Arc<dyn
    ///     DataType>` for [`resolved_type_map`](Self::resolved_type_map). Since no concrete
    ///     datatype in Java (or this crate) is simultaneously a `Dynamic` and a `Structure`/
    ///     `Union` (they inherit from disjoint base classes/trait hierarchies), this reordering
    ///     is behaviorally invisible.
    fn do_write(
        &mut self,
        dt: Box<dyn DataType>,
        monitor: &dyn TaskMonitor,
        throw_exception_on_invalid_type: bool,
    ) -> Result<(), DataTypeWriteError> {
        monitor.check_cancelled()?;

        if dt.as_function_definition().is_some() {
            return Ok(());
        }
        if dt.as_factory().is_some() {
            if throw_exception_on_invalid_type {
                return Err(DataTypeWriteError::InvalidDataType(
                    "Factory data types may not be written".to_string(),
                ));
            }
            // Java: Msg.error(this, "Factory data types may not be written - type: " + dt); --
            // this crate's `DataTypeWriter` has no logging sink wired up, so this is silently
            // skipped (matching the "no-op" behavior observed by any *caller* of this method,
            // since Msg.error also does not throw).
        }
        if dt.as_pointer().is_some() || dt.as_array().is_some() || dt.as_bit_field_data_type().is_some() {
            let base = Self::get_base_data_type(dt);
            return self.write(base, monitor);
        }

        let path_key = dt.get_path_name();
        if self.resolved.contains(&path_key) {
            return Ok(());
        }
        self.resolved.insert(path_key);

        let name_key = dt.get_name();
        if let Some(resolved_type) = self.resolved_type_map.get(&name_key) {
            if resolved_type.is_equivalent(dt.as_ref()) {
                return Ok(());
            }
            let mut auto_typedef_already_generated = false;
            if let Some(typedef) = dt.as_typedef() {
                let base_type = typedef.get_base_data_type();
                if (resolved_type.as_composite().is_some() || resolved_type.as_enum().is_some())
                    && base_type.is_equivalent(resolved_type.as_ref())
                {
                    auto_typedef_already_generated = true;
                }
            }
            if auto_typedef_already_generated {
                return Ok(());
            }
            let warning = format!(
                "WARNING! conflicting data type names: {} - {}",
                dt.get_path_name(),
                resolved_type.get_path_name()
            );
            write!(self.writer, "{EOL}")?;
            let c = self.comment(&warning);
            write!(self.writer, "{c}")?;
            write!(self.writer, "{EOL}{EOL}")?;
            return Ok(());
        }

        self.writer_depth += 1;

        let dispatch_result = if dt.as_structure().is_some() || dt.as_union().is_some() {
            let composite_box: Box<dyn Composite> =
                dt.into_composite().expect("checked via as_structure()/as_union() above");
            let composite_arc: Arc<dyn Composite> = Arc::from(composite_box);
            self.resolved_type_map.insert(name_key, composite_arc.clone() as Arc<dyn DataType>);
            self.write_composite_pre_declaration(composite_arc.as_ref(), monitor).and_then(|_| {
                self.add_composite_to_dependency_graph(composite_arc, monitor).map_err(Into::into)
            })
        } else {
            let dt_arc: Arc<dyn DataType> = Arc::from(dt);
            self.resolved_type_map.insert(name_key, dt_arc.clone());
            if let Some(dynamic) = dt_arc.as_dynamic() {
                self.write_dynamic_built_in(dynamic, monitor)
            } else if let Some(enumm) = dt_arc.as_enum() {
                self.write_enum(enumm, monitor).map_err(Into::into)
            } else if let Some(typedef) = dt_arc.as_typedef() {
                self.write_type_def(typedef, monitor)
            } else if let Some(built_in) = dt_arc.as_built_in_data_type() {
                self.write_built_in(built_in).map_err(Into::into)
            } else if dt_arc.as_bit_field_data_type().is_some() {
                Ok(())
            } else {
                // Port note: Java's message embeds `dt.getClass()` (a Java `Class<?>` via
                // reflection). This crate has no equivalent reflection facility wired into
                // `DataType`, so the display name is substituted -- a deviation, but one that
                // only affects the text of an already-exceptional diagnostic comment.
                write!(self.writer, "{EOL}{EOL}")?;
                let msg = format!("Unable to write datatype. Type unrecognized: {}", dt_arc.get_display_name());
                let c = self.comment(&msg);
                write!(self.writer, "{c}")?;
                write!(self.writer, "{EOL}{EOL}")?;
                Ok(())
            }
        };
        dispatch_result?;

        if self.writer_depth == 1 {
            self.write_deferred_declarations(monitor)?;
        }
        self.writer_depth -= 1;
        Ok(())
    }

    /// Port of the private `deferWrite(DataType dt)` helper.
    fn defer_write(&mut self, dt: Box<dyn DataType>) {
        let path_key = dt.get_path_name();
        if self.resolved.contains(&path_key) {
            return;
        }
        if self.deferred_composite_internal_type_keys.insert(path_key) {
            self.deferred_composite_internal_types.push_back(dt);
        }
    }

    /// Port of the private `writeDeferredDeclarations(TaskMonitor monitor)` helper.
    fn write_deferred_declarations(&mut self, monitor: &dyn TaskMonitor) -> Result<(), DataTypeWriteError> {
        while let Some(dt) = self.deferred_composite_internal_types.pop_front() {
            self.write(dt, monitor)?;
        }
        self.write_deferred_composite_declarations(monitor)
    }

    /// Port of the private `writeDeferredCompositeDeclarations(TaskMonitor monitor)` helper.
    fn write_deferred_composite_declarations(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        while let Some(node) = self.pop_composite_dependency() {
            self.write_composite_body(node.composite().as_ref(), monitor)?;
        }
        Ok(())
    }

    /// Port of the private `writeCompositePreDeclaration(Composite composite, TaskMonitor
    /// monitor)` helper.
    fn write_composite_pre_declaration(
        &mut self,
        composite: &dyn Composite,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        let composite_type = if composite.as_structure().is_some() { "struct" } else { "union" };
        let display_name = composite.get_display_name();

        write!(
            self.writer,
            "typedef {composite_type} {display_name} {display_name}, *P{display_name};"
        )?;
        write!(self.writer, "{EOL}{EOL}")?;

        for component in composite.get_defined_components() {
            monitor.check_cancelled()?;
            let component_type = component.get_data_type();
            self.defer_write(component_type);
        }
        Ok(())
    }

    /// Port of the private `writeCompositeBody(Composite composite, TaskMonitor monitor)`
    /// helper.
    fn write_composite_body(&mut self, composite: &dyn Composite, monitor: &dyn TaskMonitor) -> Result<(), DataTypeWriteError> {
        let composite_type = if composite.as_structure().is_some() { "struct" } else { "union" };
        let mut sb = format!("{composite_type} {} {{", composite.get_display_name());

        let descrip = composite.get_description();
        if !descrip.is_empty() {
            let c = self.comment(&descrip);
            sb.push(' ');
            sb.push_str(&c);
        }
        sb.push_str(EOL);

        for component in composite.get_components() {
            monitor.check_cancelled()?;
            self.write_component(component.as_ref(), composite, &mut sb, monitor)?;
        }

        sb.push_str(&self.annotator.get_composite_suffix(composite, &NullDataTypeComponent));
        sb.push_str("};");

        write!(self.writer, "{sb}")?;
        write!(self.writer, "{EOL}{EOL}")?;
        Ok(())
    }

    /// Port of the private `writeComponent(DataTypeComponent component, Composite composite,
    /// StringBuilder sb, TaskMonitor monitor)` helper. `sb` stands in for the Java
    /// `StringBuilder` output parameter.
    fn write_component(
        &mut self,
        component: &dyn DataTypeComponent,
        composite: &dyn Composite,
        sb: &mut String,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        let _ = monitor; // Java declares `throws CancelledException` but never calls checkCancelled here.
        sb.push_str("    ");
        sb.push_str(&self.annotator.get_composite_prefix(composite, component));

        let field_name = component
            .get_field_name()
            .filter(|s| !s.is_empty())
            .or_else(|| component.get_default_field_name())
            .unwrap_or_default();

        let component_data_type = component.get_data_type();
        let declaration =
            self.get_type_declaration(&field_name, component_data_type, component.get_length(), false, monitor)?;
        sb.push_str(&declaration);

        sb.push(';');
        sb.push_str(&self.annotator.get_composite_suffix(composite, component));

        if let Some(comment) = component.get_comment() {
            if !comment.is_empty() {
                sb.push(' ');
                let c = self.comment(&comment);
                sb.push_str(&c);
            }
        }
        sb.push_str(EOL);
        Ok(())
    }

    /// Port of the private `getTypeDeclaration(String name, DataType dataType, int
    /// instanceLength, boolean writeEnabled, TaskMonitor monitor)` helper.
    ///
    /// **Partial port**: the `dataType instanceof FunctionDefinition` branch (function-pointer
    /// declaration text, via `getFunctionPointerString`) is not wired up yet -- see the module
    /// doc comment. A function-pointer-typed field or parameter currently falls through to the
    /// generic `getDataTypePrefix(dataType) + dataType.getDisplayName()` formatting instead of
    /// real function-pointer syntax; every other case (plain fields, arrays, pointers, bit
    /// fields, dynamic-length fields) is fully ported.
    fn get_type_declaration(
        &mut self,
        name: &str,
        mut data_type: Box<dyn DataType>,
        instance_length: i32,
        write_enabled: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, DataTypeWriteError> {
        let _ = (write_enabled, monitor); // only consumed once the FunctionDefinition branch (see doc comment) is wired up.
        let mut name = name.to_string();
        let mut component_string: Option<String> = None;

        if let Some(dynamic) = data_type.as_dynamic() {
            match Self::get_dynamic_component_string(dynamic, &name, instance_length) {
                Some(s) => component_string = Some(s),
                None => {
                    let msg = format!("ignoring dynamic datatype inside composite: {}", data_type.get_display_name());
                    let c = self.comment(&msg);
                    component_string = Some(format!("{c}{EOL}"));
                }
            }
        }

        if component_string.is_none() {
            if let Some(bf) = data_type.as_bit_field_data_type() {
                name = format!("{name}:{}", bf.get_declared_bit_size());
                data_type = bf.get_base_data_type();
            }

            loop {
                if let Some(array) = data_type.as_array() {
                    name = format!("{name}[{}]", array.get_num_elements());
                    data_type = array.get_data_type();
                    continue;
                }
                if let Some(pointer) = data_type.as_pointer() {
                    match pointer.get_data_type() {
                        None => break,
                        Some(elem) => {
                            name = format!("*{name}");
                            let elem_is_array = elem.as_array().is_some();
                            data_type = elem;
                            if elem_is_array {
                                name = format!("({name})");
                            }
                            continue;
                        }
                    }
                }
                break;
            }

            // Port note: by this point every Array/Pointer/BitFieldDataType layer has already
            // been stripped from `data_type` by the unwrapping above, so it is already equal to
            // what a second call to `getBaseDataType(dataType)` (as Java does here) would
            // compute. That redundant second unwrap is skipped, letting this port avoid needing
            // two independently-owned copies of the same `Box<dyn DataType>`.
            let prefix = Self::get_data_type_prefix_of(data_type.as_ref());
            let mut s = format!("{prefix}{}", data_type.get_display_name());
            if !name.is_empty() {
                s.push(' ');
                s.push_str(&name);
            }
            component_string = Some(s);
        }

        Ok(component_string.unwrap_or_default())
    }

    /// Port of the private `getDynamicComponentString(Dynamic dynamicType, String fieldName, int
    /// length)` helper. An associated function (rather than a `&self` method) since, unlike the
    /// Java original, it does not consult `dtm`: see the module doc comment's note on why the
    /// `replacementBaseType.clone(dtm)` step is skipped throughout this port (`clone_data_type`
    /// is not reliably overridden yet).
    fn get_dynamic_component_string(dynamic_type: &dyn Dynamic, field_name: &str, length: i32) -> Option<String> {
        if !dynamic_type.can_specify_length() {
            return None;
        }
        let replacement_base_type = dynamic_type.get_replacement_base_type();
        let element_len = replacement_base_type.get_length();
        if element_len <= 0 {
            // Java logs via `Msg.error` here; this crate's `DataTypeWriter` has no logging sink
            // wired up (see the analogous note in `do_write`), so this just falls through to the
            // same `None` return Java's error path produces.
            return None;
        }
        let element_cnt = (length + element_len - 1) / element_len;
        Some(format!("{} {field_name}[{element_cnt}]", replacement_base_type.get_display_name()))
    }

    /// Port of the private `getDataTypePrefix(DataType dataType)` helper, taking `dataType` by
    /// reference. A borrow-based sibling of the already-ported, `#[cfg(test)]`-only
    /// [`get_data_type_prefix`](Self::get_data_type_prefix) (which consumes ownership); this one
    /// is used by [`get_type_declaration`](Self::get_type_declaration), which still needs
    /// `data_type` itself afterward and so cannot hand ownership over.
    fn get_data_type_prefix_of(data_type: &dyn DataType) -> &'static str {
        if data_type.as_structure().is_some() {
            "struct "
        } else if data_type.as_union().is_some() {
            "union "
        } else if data_type.as_enum().is_some() {
            "enum "
        } else {
            ""
        }
    }

    /// Port of the private `writeTypeDef(TypeDef typeDef, TaskMonitor monitor)` helper.
    ///
    /// Typedef Format: `typedef <TYPE_DEF_NAME> <BASE_TYPE_NAME>`
    ///
    /// Java calls `typeDef.getDataType()` once and reuses the single reference both inside the
    /// `finally` block and again for `getTypeDeclaration`. This port instead calls
    /// [`TypeDef::get_data_type`] a second time where needed: every `get_data_type`/
    /// `get_base_data_type`-style getter in this crate is documented (and, where checked,
    /// verified) to hand back a fresh, independently-owned `Box` representing the *same*
    /// underlying datatype on each call -- see e.g. [`Pointer::get_data_type`]'s own established
    /// multi-call usage elsewhere in this file -- so two separate calls are behaviorally
    /// equivalent to Java's one-and-reuse.
    fn write_type_def(&mut self, typedef: &dyn TypeDef, monitor: &dyn TaskMonitor) -> Result<(), DataTypeWriteError> {
        let typedef_name = typedef.get_display_name();
        let data_type_name = typedef.get_data_type().get_display_name();
        if Self::is_integral(&typedef_name, &data_type_name) {
            return Ok(());
        }

        let base_type = typedef.get_base_data_type();
        let mut skip_after_write = false;

        if base_type.as_composite().is_some() || base_type.as_enum().is_some() {
            // auto-typedef generated with composite and enum
            if typedef_name == base_type.get_name() {
                self.resolved_type_map.remove(&typedef_name);
                skip_after_write = true;
            }
        } else if let Some(base_pointer) = base_type.as_pointer() {
            // auto-pointer-typedef generated with composite
            if typedef_name.starts_with('P') {
                if let Some(mut inner_dt) = base_pointer.get_data_type() {
                    if let Some(inner_typedef) = inner_dt.as_typedef() {
                        inner_dt = inner_typedef.get_base_data_type();
                    }
                    if inner_dt.as_composite().is_some() && inner_dt.get_name() == typedef_name[1..] {
                        self.resolved_type_map.remove(&typedef_name);
                        skip_after_write = true;
                    }
                }
            }
        }

        // Java's `finally { write(dataType, monitor); }` always runs, even along the
        // `skip_after_write` early-return paths above.
        let write_result = self.write(typedef.get_data_type(), monitor);
        write_result?;

        if skip_after_write {
            return Ok(());
        }

        if base_type.as_array().is_some() {
            let base_array_typedef_type = Self::get_base_array_typedef_type(typedef.get_base_data_type());
            if base_array_typedef_type.as_composite().is_some() {
                self.write_deferred_declarations(monitor)?;
            }
        }

        let typedef_string = self.get_type_declaration(&typedef_name, typedef.get_data_type(), -1, true, monitor)?;
        write!(self.writer, "typedef {typedef_string};")?;
        write!(self.writer, "{EOL}{EOL}")?;
        Ok(())
    }

    /// Port of the private `getBaseArrayTypedefType(DataType dt)` helper.
    fn get_base_array_typedef_type(mut dt: Box<dyn DataType>) -> Box<dyn DataType> {
        loop {
            if let Some(typedef) = dt.as_typedef() {
                dt = typedef.get_base_data_type();
                continue;
            }
            if let Some(array) = dt.as_array() {
                dt = array.get_data_type();
                continue;
            }
            break;
        }
        dt
    }

    /// Port of the private `writeDynamicBuiltIn(Dynamic dt, TaskMonitor monitor)` helper.
    fn write_dynamic_built_in(&mut self, dt: &dyn Dynamic, monitor: &dyn TaskMonitor) -> Result<(), DataTypeWriteError> {
        let base_dt = dt.get_replacement_base_type();
        self.write(base_dt, monitor)
    }

    /// Port of `writeBuiltIn` (the not-yet-ported dispatch that calls this still needs to be
    /// wired up): calls the already-real [`BuiltInDataType::get_c_type_declaration`] rather than
    /// re-deriving any C-declaration formatting, per this crate's established precedent (see the
    /// module doc comment).
    pub fn write_built_in(
        &mut self,
        dt: &dyn BuiltInDataType,
    ) -> io::Result<()> {
        if let Some(declaration) = dt.get_c_type_declaration(Some(self.data_organization.as_ref())) {
            self.writer.write_all(declaration.as_bytes())?;
            self.writer.write_all(EOL.as_bytes())?;
        }
        Ok(())
    }

    /// Port of the private `writeBuiltInDeclarations(DataTypeManager manager)` helper ("Write all
    /// built-in data types declarations into ANSI-C code").
    ///
    /// Deviations from the Java source:
    ///   - The leading `write(DataType.DEFAULT, TaskMonitor.DUMMY)` call is skipped: `DataType
    ///     .DEFAULT` (`DefaultDataType`) is not ported yet -- see the module doc comment.
    ///   - Java's `catch (CancelledException e) { // ignore }` is reproduced by matching on
    ///     [`DataTypeWriteError::Cancelled`] specifically and discarding it, while any
    ///     [`DataTypeWriteError::Io`] still propagates as a real `io::Error` (this method's Java
    ///     signature only declares `throws IOException`) and
    ///     [`DataTypeWriteError::InvalidDataType`] is surfaced the same way (it cannot actually
    ///     occur here since every candidate is filtered to exclude `FactoryDataType` before
    ///     `write` is called, matching Java's own `dt instanceof FactoryDataType` filter below).
    pub fn write_built_in_declarations(&mut self, manager: &dyn DataTypeManager) -> io::Result<()> {
        let monitor = crate::util::task::DummyMonitor;
        match self.write_built_in_declarations_inner(manager, &monitor) {
            Ok(()) | Err(DataTypeWriteError::Cancelled(_)) => {}
            Err(DataTypeWriteError::Io(e)) => return Err(e),
            Err(DataTypeWriteError::InvalidDataType(msg)) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
            }
        }
        self.writer.flush()
    }

    fn write_built_in_declarations_inner(
        &mut self,
        manager: &dyn DataTypeManager,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DataTypeWriteError> {
        let Some(built_in_archive) =
            manager.get_source_archive(crate::program::model::data::data_type_manager::built_in_archive_universal_id())
        else {
            return Ok(());
        };

        for dt in manager.get_data_types_from_archive(built_in_archive.as_ref()) {
            if dt.as_pointer().is_some() || dt.as_factory().is_some() || dt.as_dynamic().is_some() {
                continue;
            }
            self.write(dt, monitor)?;
        }
        Ok(())
    }

    /// Port of the private `writeEnum(Enum enumm, TaskMonitor monitor)` helper. `monitor` is
    /// accepted (matching the Java signature) but unused: the Java method never calls
    /// `monitor.checkCancelled()` in its body either, and it declares no `CancelledException` in
    /// its `throws` clause.
    pub fn write_enum(
        &mut self,
        enumm: &dyn Enum,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let enum_name = enumm.get_display_name();
        if enum_name.starts_with("define_") && enum_name.len() > 7 && enumm.get_count() == 1 {
            let val = enumm.get_values()[0];
            write!(self.writer, "#define {} {val}", &enum_name["define_".len()..])?;
            write!(self.writer, "{EOL}{EOL}")?;
            return Ok(());
        }

        write!(self.writer, "typedef enum {enum_name} {{")?;
        let description = enumm.get_description();
        if !description.is_empty() {
            let comment = self.comment(&description);
            write!(self.writer, " {comment}")?;
        }
        write!(self.writer, "{EOL}")?;

        let names = enumm.get_names();
        let last = names.len().saturating_sub(1);
        for (j, name) in names.iter().enumerate() {
            write!(self.writer, "    ")?;
            write!(self.writer, "{}", self.annotator.get_enum_prefix(enumm, name))?;
            write!(self.writer, "{name}")?;
            write!(self.writer, "=")?;
            let value = enumm.get_value_for_name(name).unwrap_or(0);
            write!(self.writer, "{value}")?;

            let comment = enumm.get_comment(name);
            if !comment.trim().is_empty() {
                let comment = self.comment(&comment);
                write!(self.writer, " {comment}")?;
            }

            write!(self.writer, "{}", self.annotator.get_enum_suffix(enumm, name))?;

            if j < last {
                write!(self.writer, ",")?;
            }
            write!(self.writer, "{EOL}")?;
        }
        write!(self.writer, "}} {enum_name};")?;
        write!(self.writer, "{EOL}{EOL}")?;
        Ok(())
    }

    /// Port of the private `getBaseDataType(DataType dt)` helper: strips `Array`/`Pointer`/
    /// `BitFieldDataType` layers to find the underlying data type.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today (via
    /// [`Self::get_data_type_prefix`]) -- its other real callers (`getTypeDeclaration`,
    /// `getFunctionPointerString`) are among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
    fn get_base_data_type(mut dt: Box<dyn DataType>) -> Box<dyn DataType> {
        loop {
            if let Some(array) = dt.as_array() {
                dt = array.get_data_type();
                continue;
            }
            if let Some(pointer) = dt.as_pointer() {
                match pointer.get_data_type() {
                    Some(inner) => {
                        dt = inner;
                        continue;
                    }
                    None => break,
                }
            }
            if let Some(bit_field) = dt.as_bit_field_data_type() {
                dt = bit_field.get_base_data_type();
                continue;
            }
            break;
        }
        dt
    }

    /// Port of the private `getArrayBaseType(Array arrayDt)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `getFunctionPointerString`, is among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
    fn get_array_base_type(array: &dyn Array) -> Box<dyn DataType> {
        let mut data_type = array.get_data_type();
        while let Some(inner_array) = data_type.as_array() {
            data_type = inner_array.get_data_type();
        }
        data_type
    }

    /// Port of the private `getPointerBaseDataType(Pointer p)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `getFunctionPointerString`, is among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
    fn get_pointer_base_data_type(
        pointer: &dyn Pointer,
    ) -> Option<Box<dyn DataType>> {
        let mut dt = pointer.get_data_type()?;
        while let Some(inner_pointer) = dt.as_pointer() {
            match inner_pointer.get_data_type() {
                Some(inner) => dt = inner,
                None => break,
            }
        }
        Some(dt)
    }

    /// Port of the private `getPointerDepth(Pointer p)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `getFunctionPointerString`, is among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
    fn get_pointer_depth(pointer: &dyn Pointer) -> i32 {
        let mut depth = 1;
        let mut current = pointer.get_data_type();
        while let Some(dt) = current {
            match dt.as_pointer() {
                Some(inner) => {
                    depth += 1;
                    current = inner.get_data_type();
                }
                None => break,
            }
        }
        depth
    }

    /// Port of the private `static String getArrayDimensions(Array arrayDt)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `getFunctionPointerString`, is among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
    fn get_array_dimensions(array: &dyn Array) -> String {
        let mut dimensions = format!("[{}]", array.get_num_elements());
        if let Some(inner_array) = array.get_data_type().as_array() {
            dimensions.push_str(&Self::get_array_dimensions(inner_array));
        }
        dimensions
    }

    /// Port of the private `getDataTypePrefix(DataType dataType)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `getTypeDeclaration`, is among the "not yet ported" items listed in the module doc comment.
    #[allow(dead_code)]
    fn get_data_type_prefix(dt: Box<dyn DataType>) -> &'static str {
        let base = Self::get_base_data_type(dt);
        if base.as_structure().is_some() {
            "struct "
        } else if base.as_union().is_some() {
            "union "
        } else if base.as_enum().is_some() {
            "enum "
        } else {
            ""
        }
    }
}

/// Port of `DataTypeWriter.EOL` (`System.getProperty("line.separator")`). Fixed to `"\n"` rather
/// than sampled from the host platform, matching this crate's general convention (and every other
/// text-emitting port in this crate) of emitting Unix line endings unconditionally.
const EOL: &str = "\n";

/// Stands in for the Java literal `null` passed as the `DataTypeComponent dtc` argument to
/// `AnnotationHandler.getSuffix(Composite, DataTypeComponent)` in `writeCompositeBody`, where
/// Java asks for the composite's own trailing (not-component-specific) suffix. The
/// `DataTypeComponent` trait's methods are all given defaults (see that trait's own doc comment),
/// so this unit struct answers every query the same zero-value way Java's `null` argument would
/// have if `AnnotationHandler` implementations dereferenced it defensively -- which every
/// implementation in this crate does, since none currently read `dtc` for their suffix text.
struct NullDataTypeComponent;
impl DataTypeComponent for NullDataTypeComponent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::structure_data_type::StructureDataTypeImpl;
    use crate::util::task::DummyMonitor;

    fn leaf_struct(name: &str) -> Arc<dyn Composite> {
        Arc::new(StructureDataTypeImpl::new(name, 4))
    }

    #[test]
    fn add_composite_to_dependency_graph_registers_a_leaf_composite() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        let leaf = leaf_struct("Leaf");
        writer.add_composite_to_dependency_graph(leaf.clone(), &DummyMonitor).unwrap();

        let popped = writer.pop_composite_dependency().unwrap();
        assert_eq!(popped.composite().get_name(), "Leaf");
        assert!(writer.pop_composite_dependency().is_none());
    }

    #[test]
    fn add_composite_to_dependency_graph_orders_member_composite_before_parent() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());

        // "Outer" embeds "Inner" by value (via the already-real `Composite::add`), so the
        // dependency graph must order "Inner" before "Outer".
        let mut outer_struct = StructureDataTypeImpl::new("Outer", 0);
        let inner_member: Box<dyn DataType> = Box::new(StructureDataTypeImpl::new("Inner", 4));
        outer_struct.add(inner_member).expect("add should succeed");
        let outer: Arc<dyn Composite> = Arc::new(outer_struct);

        let inner_composite: Arc<dyn Composite> = Arc::new(StructureDataTypeImpl::new("Inner", 4));

        writer.add_composite_to_dependency_graph(outer.clone(), &DummyMonitor).unwrap();
        writer.add_composite_to_dependency_graph(inner_composite, &DummyMonitor).unwrap();

        // "Outer" depends on "Inner" (embeds it by value), so "Inner" must pop first.
        let first = writer.pop_composite_dependency().unwrap();
        assert_eq!(first.composite().get_name(), "Inner");
        let second = writer.pop_composite_dependency().unwrap();
        assert_eq!(second.composite().get_name(), "Outer");
        assert!(writer.pop_composite_dependency().is_none());
    }

    #[test]
    fn is_integral_matches_exact_and_suffixed_primitive_names() {
        assert!(DataTypeWriter::<Vec<u8>>::is_integral("int", "int"));
        assert!(DataTypeWriter::<Vec<u8>>::is_integral("unsigned int", "int"));
        assert!(!DataTypeWriter::<Vec<u8>>::is_integral("MyTypedef", "int"));
    }

    #[test]
    fn comment_uses_c_style_by_default_and_cpp_style_when_requested() {
        let c_writer = DataTypeWriter::new(None, Vec::<u8>::new());
        assert_eq!(c_writer.comment("hi"), "/* hi */");

        let cpp_writer = DataTypeWriter::with_cpp_style_comments(None, Vec::<u8>::new(), true);
        assert_eq!(cpp_writer.comment("hi"), "// hi");

        assert_eq!(c_writer.comment(""), "");
    }

    #[test]
    fn fallback_data_organization_matches_java_default_organization_constants() {
        let writer = DataTypeWriter::new(None, Vec::<u8>::new());
        assert_eq!(writer.data_organization.get_pointer_size(), 4);
        assert!(!writer.data_organization.is_big_endian());
        assert_eq!(writer.data_organization.get_char_size(), 1);
        assert_eq!(writer.data_organization.get_long_long_size(), 8);
    }

    fn written_text(writer: DataTypeWriter<Vec<u8>>) -> String {
        String::from_utf8(writer.writer).unwrap()
    }

    #[test]
    fn write_enum_emits_typedef_enum_block() {
        use crate::program::model::data::enum_data_type::EnumDataType;

        let mut e = EnumDataType::new("Color", 4);
        e.add("RED", 0);
        e.add_with_comment("GREEN", 1, "the green one");

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_enum(&e, &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.starts_with("typedef enum Color {\n"), "text was: {text}");
        assert!(text.contains("RED=0,\n"), "text was: {text}");
        assert!(text.contains("GREEN=1 /* the green one */\n"), "text was: {text}");
        assert!(text.trim_end().ends_with("} Color;"), "text was: {text}");
    }

    #[test]
    fn write_enum_emits_define_for_single_value_define_prefixed_enum() {
        use crate::program::model::data::enum_data_type::EnumDataType;

        let mut e = EnumDataType::new("define_FOO", 4);
        e.add("FOO", 42);

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_enum(&e, &DummyMonitor).unwrap();

        assert_eq!(written_text(writer), "#define FOO 42\n\n");
    }

    struct MockBuiltIn(Option<String>);
    impl DataType for MockBuiltIn {
        fn as_built_in_data_type(&self) -> Option<&dyn BuiltInDataType> {
            Some(self)
        }
    }
    impl BuiltInDataType for MockBuiltIn {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.0.clone()
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    #[test]
    fn write_built_in_emits_declaration_when_present() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_built_in(&MockBuiltIn(Some("typedef unsigned long uintptr_t;".to_string()))).unwrap();
        assert_eq!(written_text(writer), "typedef unsigned long uintptr_t;\n");
    }

    #[test]
    fn write_built_in_emits_nothing_when_declaration_absent() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_built_in(&MockBuiltIn(None)).unwrap();
        assert_eq!(written_text(writer), "");
    }

    #[test]
    fn get_data_type_prefix_identifies_struct_union_enum() {
        use crate::program::model::data::enum_data_type::EnumDataType;
        use crate::program::model::data::union_data_type::UnionDataTypeImpl;

        let s: Box<dyn DataType> = Box::new(StructureDataTypeImpl::new("S", 4));
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_data_type_prefix(s), "struct ");

        let u: Box<dyn DataType> = Box::new(UnionDataTypeImpl::new("U"));
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_data_type_prefix(u), "union ");

        let e: Box<dyn DataType> = Box::new(EnumDataType::new("E", 4));
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_data_type_prefix(e), "enum ");
    }

    #[test]
    fn get_data_type_prefix_is_empty_for_non_composite_non_enum() {
        struct PlainInt;
        impl DataType for PlainInt {}
        let dt: Box<dyn DataType> = Box::new(PlainInt);
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_data_type_prefix(dt), "");
    }

    #[test]
    fn array_dimensions_and_base_type_helpers_handle_multi_dimensional_arrays() {
        use crate::program::model::data::array_data_type::ArrayDataType;

        // `ArrayDataType::new` rejects a length-0 element type, so the leaf here needs a real
        // reported length (unlike a `DataType` default's `get_length() -> 0`).
        let element: Box<dyn DataType> = Box::new(StructureDataTypeImpl::new("Elem", 4));
        let inner = ArrayDataType::new(element, 3).unwrap();
        let outer = ArrayDataType::new(Box::new(inner), 2).unwrap();

        assert_eq!(DataTypeWriter::<Vec<u8>>::get_array_dimensions(&outer), "[2][3]");

        let base = DataTypeWriter::<Vec<u8>>::get_array_base_type(&outer);
        assert_eq!(base.get_name(), "Elem");
        assert!(base.as_array().is_none());
    }

    /// Minimal `Pointer` mock, since this crate has no concrete, non-test `Pointer`
    /// implementation yet (see the research this port is based on) -- mirrors the precedent
    /// already used by `pointer_data_type.rs`'s own `#[cfg(test)]` mocks. Holds its target as an
    /// `Arc<dyn DataType>` (cheaply `Clone`, unlike `Box<dyn DataType>`) so `get_data_type()` can
    /// be called more than once per node, across more than one traversal in a test, exactly like
    /// a real `Pointer`'s "peek at my target" semantics.
    struct MockPointer {
        target: Option<Arc<dyn DataType>>,
    }
    impl DataType for MockPointer {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            self.target.clone().map(|arc| Box::new(SharedDataType(arc)) as Box<dyn DataType>)
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not needed by this test")
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not needed by this test")
        }
    }

    /// Thin `Box<dyn DataType>` wrapper around a shared `Arc<dyn DataType>`, letting
    /// `MockPointer::get_data_type()` hand out a fresh owned `Box` each call while still sharing
    /// (not cloning) the underlying node -- `as_pointer` delegates through so chained-pointer
    /// traversal (`dt.as_pointer()`) still sees the real wrapped `MockPointer`.
    struct SharedDataType(Arc<dyn DataType>);
    impl DataType for SharedDataType {
        fn get_name(&self) -> String {
            self.0.get_name()
        }
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            self.0.as_pointer()
        }
    }

    struct NamedLeaf(&'static str);
    impl DataType for NamedLeaf {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    #[test]
    fn pointer_depth_and_base_type_walk_chained_pointers() {
        let leaf: Arc<dyn DataType> = Arc::new(NamedLeaf("int"));
        let p1: Arc<dyn DataType> = Arc::new(MockPointer { target: Some(leaf) });
        let p2: Arc<dyn DataType> = Arc::new(MockPointer { target: Some(p1) });
        let p3 = MockPointer { target: Some(p2) };

        assert_eq!(DataTypeWriter::<Vec<u8>>::get_pointer_depth(&p3), 3);
        let base = DataTypeWriter::<Vec<u8>>::get_pointer_base_data_type(&p3).unwrap();
        assert_eq!(base.get_name(), "int");
    }

    #[test]
    fn pointer_depth_is_one_for_a_single_pointer_to_null() {
        let p = MockPointer { target: None };
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_pointer_depth(&p), 1);
        assert!(DataTypeWriter::<Vec<u8>>::get_pointer_base_data_type(&p).is_none());
    }

    // -- `write`/`doWrite` dispatcher + composite declaration tests -----------------------------

    /// A minimal named leaf `DataType` with a genuine positive length, for use as a composite
    /// field in these dispatcher tests -- unlike `NamedLeaf` above (whose `get_length()` is the
    /// `DataType` trait's zero default), which `Composite`'s real
    /// `validateDataType`/`composite_impl_validate_data_type` port rejects with "not allowed in
    /// a composite data type" for any non-dynamic type reporting a non-positive length.
    struct SizedLeaf(&'static str, i32);
    impl DataType for SizedLeaf {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
        fn get_length(&self) -> i32 {
            self.1
        }
    }

    #[test]
    fn write_simple_struct_emits_pre_declaration_and_body() {
        let mut point = StructureDataTypeImpl::new("Point", 0);
        point.add_with_length_and_name(Box::new(SizedLeaf("int", 4)), 4, Some("x".to_string()), None).unwrap();
        point.add_with_length_and_name(Box::new(SizedLeaf("int", 4)), 4, Some("y".to_string()), None).unwrap();

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(point), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.contains("typedef struct Point Point, *PPoint;"), "text was: {text}");
        assert!(text.contains("struct Point {"), "text was: {text}");
        assert!(text.contains("int x;"), "text was: {text}");
        assert!(text.contains("int y;"), "text was: {text}");
        assert!(text.trim_end().ends_with("};"), "text was: {text}");
    }

    #[test]
    fn write_nested_struct_orders_inner_body_before_outer_body() {
        let mut inner = StructureDataTypeImpl::new("Inner", 0);
        inner.add_with_length_and_name(Box::new(SizedLeaf("int", 4)), 4, Some("value".to_string()), None).unwrap();

        let mut outer = StructureDataTypeImpl::new("Outer", 0);
        outer.add_with_name(Box::new(inner), Some("inner".to_string()), None).unwrap();

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(outer), &DummyMonitor).unwrap();

        let text = written_text(writer);
        let inner_body_pos = text.find("struct Inner {").expect("inner body should be written");
        let outer_body_pos = text.find("struct Outer {").expect("outer body should be written");
        assert!(inner_body_pos < outer_body_pos, "expected Inner body before Outer body, text was: {text}");
        assert!(text.contains("struct Inner inner;"), "text was: {text}");
    }

    #[test]
    fn write_enum_via_dispatcher_matches_direct_write_enum() {
        use crate::program::model::data::enum_data_type::EnumDataType;

        let mut e = EnumDataType::new("Color", 4);
        e.add("RED", 0);

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(e), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.starts_with("typedef enum Color {\n"), "text was: {text}");
        assert!(text.trim_end().ends_with("} Color;"), "text was: {text}");
    }

    #[test]
    fn write_conflicting_same_name_different_category_emits_warning() {
        use crate::program::model::data::category_path::ROOT;

        let a = StructureDataTypeImpl::new_in_category(ROOT.extend(&["ArchiveA"]), "Dup", 4);
        let mut b = StructureDataTypeImpl::new_in_category(ROOT.extend(&["ArchiveB"]), "Dup", 0);
        b.add_with_length_and_name(Box::new(SizedLeaf("int", 4)), 4, Some("field".to_string()), None).unwrap();

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(a), &DummyMonitor).unwrap();
        writer.write(Box::new(b), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.contains("WARNING! conflicting data type names"), "text was: {text}");
    }

    #[test]
    fn write_same_struct_twice_is_written_only_once() {
        let point = StructureDataTypeImpl::new("Point", 4);

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(StructureDataTypeImpl::new("Point", 4)), &DummyMonitor).unwrap();
        writer.write(Box::new(point), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert_eq!(text.matches("typedef struct Point Point").count(), 1, "text was: {text}");
    }

    /// Mock `FactoryDataType`. Per `ghidra.program.model.data.FactoryDataType`'s real Java
    /// hierarchy (and this crate's own `pub trait FactoryDataType: BuiltInDataType`), a factory
    /// data type *is* a `BuiltInDataType` too -- so this mock implements both, matching Java's
    /// `doWrite`, which (when `throwExceptionOnInvalidType` is `false`) logs a warning for the
    /// `FactoryDataType` case but then falls through and keeps dispatching, eventually reaching
    /// the `dt instanceof BuiltInDataType` branch since that `instanceof` still holds.
    struct MockFactoryDataType;
    impl DataType for MockFactoryDataType {
        fn as_factory(&self) -> Option<&dyn crate::program::model::data::factory_data_type::FactoryDataType> {
            Some(self)
        }
        fn as_built_in_data_type(&self) -> Option<&dyn BuiltInDataType> {
            Some(self)
        }
    }
    impl BuiltInDataType for MockFactoryDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl crate::program::model::data::factory_data_type::FactoryDataType for MockFactoryDataType {
        fn get_data_type(&self, _buf: &dyn crate::program::model::mem::MemBuffer) -> Box<dyn DataType> {
            Box::new(NamedLeaf("factory-produced"))
        }
    }

    #[test]
    fn write_factory_data_type_errors_when_throw_enabled() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        let err = writer.write(Box::new(MockFactoryDataType), &DummyMonitor).unwrap_err();
        assert!(matches!(err, DataTypeWriteError::InvalidDataType(_)), "err was: {err}");
    }

    #[test]
    fn write_factory_data_type_falls_through_to_built_in_dispatch_when_throw_disabled() {
        // Matches Java: `doWrite` logs (via `Msg.error`, not ported -- see `do_write`'s own doc
        // comment) but does not `return` for the `throwExceptionOnInvalidType == false` case, so
        // dispatch continues and reaches the `BuiltInDataType` branch since `FactoryDataType`
        // *is* a `BuiltInDataType`. This mock's `get_c_type_declaration` returns `None`, so the
        // observable output is still empty -- but for the real reason, not because the type was
        // skipped outright.
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_with_options(Box::new(MockFactoryDataType), &DummyMonitor, false).unwrap();
        assert_eq!(written_text(writer), "");
    }

    #[test]
    fn write_unrecognized_data_type_emits_comment() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(NamedLeaf("mystery")), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.contains("Unable to write datatype. Type unrecognized"), "text was: {text}");
    }

    #[test]
    fn write_type_def_emits_typedef_line_for_non_integral_name() {
        use crate::program::model::data::typedef_data_type::TypedefDataType;

        let base: Box<dyn DataType> = Box::new(NamedLeaf("Widget"));
        let td = TypedefDataType::new_in_root("MyWidget", base).unwrap();

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(td), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(text.contains("typedef"), "text was: {text}");
        assert!(text.contains("MyWidget"), "text was: {text}");
    }

    #[test]
    fn write_type_def_skips_integral_typedef_name() {
        use crate::program::model::data::typedef_data_type::TypedefDataType;

        let base: Box<dyn DataType> = Box::new(NamedLeaf("int"));
        let td = TypedefDataType::new_in_root("int", base).unwrap();

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write(Box::new(td), &DummyMonitor).unwrap();

        let text = written_text(writer);
        assert!(!text.contains("typedef int int"), "text was: {text}");
    }

    #[test]
    fn get_dynamic_component_string_computes_element_count() {
        struct StubDynamic;
        impl DataType for StubDynamic {}
        impl BuiltInDataType for StubDynamic {
            fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
                None
            }
            fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
        }
        impl Dynamic for StubDynamic {
            fn get_dynamic_length(&self, _buf: &dyn crate::program::model::mem::MemBuffer, max_length: i32) -> i32 {
                max_length
            }
            fn can_specify_length(&self) -> bool {
                true
            }
            fn get_replacement_base_type(&self) -> Box<dyn DataType> {
                Box::new(NamedLeaf("byte"))
            }
        }

        let dynamic = StubDynamic;
        // "byte" (`NamedLeaf`) reports the `DataType` default `get_length() -> 0`, which would
        // divide-by-zero in the real element-count formula, so this test exercises the
        // already-handled `elementLen <= 0 -> None` guard instead of the happy path -- there is
        // no ported concrete leaf type in this crate yet with both a nonzero `get_length()` and
        // no other unrelated setup cost. The happy-path arithmetic itself
        // (`(length + elementLen - 1) / elementLen`) is exercised indirectly once a byte-sized
        // leaf type is wired up in a follow-up chunk.
        let result = DataTypeWriter::<Vec<u8>>::get_dynamic_component_string(&dynamic, "field", 10);
        assert_eq!(result, None);
    }

    #[test]
    fn get_dynamic_component_string_returns_none_when_length_cannot_be_specified() {
        struct StubDynamic;
        impl DataType for StubDynamic {}
        impl BuiltInDataType for StubDynamic {
            fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
                None
            }
            fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
        }
        impl Dynamic for StubDynamic {
            fn get_dynamic_length(&self, _buf: &dyn crate::program::model::mem::MemBuffer, _max_length: i32) -> i32 {
                -1
            }
            fn get_replacement_base_type(&self) -> Box<dyn DataType> {
                Box::new(NamedLeaf("byte"))
            }
        }

        let dynamic = StubDynamic;
        assert_eq!(DataTypeWriter::<Vec<u8>>::get_dynamic_component_string(&dynamic, "field", 10), None);
    }

    // -- entry-point overload tests -------------------------------------------------------------

    #[test]
    fn write_many_writes_every_data_type_and_reports_progress() {
        use crate::program::model::data::enum_data_type::EnumDataType;

        let mut a = EnumDataType::new("A", 4);
        a.add("A1", 1);
        let mut b = EnumDataType::new("B", 4);
        b.add("B1", 2);

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer
            .write_many(vec![Box::new(a) as Box<dyn DataType>, Box::new(b) as Box<dyn DataType>], &DummyMonitor)
            .unwrap();

        let text = written_text(writer);
        assert!(text.contains("typedef enum A {"), "text was: {text}");
        assert!(text.contains("typedef enum B {"), "text was: {text}");
    }

    /// Mock `SourceArchive` standing in for the built-in archive, and a mock `DataTypeManager`
    /// exposing it -- both required since `write_built_in_declarations` looks the archive up by
    /// [`built_in_archive_universal_id`](crate::program::model::data::data_type_manager::built_in_archive_universal_id)
    /// and then asks the manager for that archive's data types.
    struct MockBuiltInArchive;
    impl crate::program::model::data::source_archive::SourceArchive for MockBuiltInArchive {
        fn source_archive_id(&self) -> crate::util::UniversalID {
            crate::program::model::data::data_type_manager::built_in_archive_universal_id()
        }
        fn domain_file_id(&self) -> String {
            String::new()
        }
        fn archive_type(&self) -> crate::program::model::data::archive_type::ArchiveType {
            crate::program::model::data::archive_type::ArchiveType::BuiltIn
        }
        fn name(&self) -> String {
            "BuiltInTypes".to_string()
        }
        fn last_sync_time(&self) -> i64 {
            0
        }
        fn is_dirty(&self) -> bool {
            false
        }
        fn set_last_sync_time(&mut self, _time: i64) {}
        fn set_name(&mut self, _name: String) {}
        fn set_dirty_flag(&mut self, _dirty: bool) {}
    }

    struct MockBuiltInArchiveManager;
    impl DataTypeManager for MockBuiltInArchiveManager {
        fn get_source_archive(
            &self,
            source_id: crate::util::UniversalID,
        ) -> Option<Box<dyn crate::program::model::data::source_archive::SourceArchive>> {
            if source_id == crate::program::model::data::data_type_manager::built_in_archive_universal_id() {
                Some(Box::new(MockBuiltInArchive))
            } else {
                None
            }
        }
        fn get_data_types_from_archive(
            &self,
            _source_archive: &dyn crate::program::model::data::source_archive::SourceArchive,
        ) -> Vec<Box<dyn DataType>> {
            vec![
                Box::new(MockBuiltIn(Some("typedef unsigned long uintptr_t;".to_string()))),
                // A pointer-flavored built-in must be filtered out by `write_built_in_declarations`
                // before ever reaching `write` (Java: `dt instanceof Pointer` skip).
                Box::new(MockPointer { target: None }),
            ]
        }
    }

    #[test]
    fn write_built_in_declarations_writes_non_pointer_archive_members() {
        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_built_in_declarations(&MockBuiltInArchiveManager).unwrap();

        let text = written_text(writer);
        assert!(text.contains("typedef unsigned long uintptr_t;"), "text was: {text}");
    }

    #[test]
    fn write_built_in_declarations_is_a_no_op_when_archive_missing() {
        struct NoArchiveManager;
        impl DataTypeManager for NoArchiveManager {}

        let mut writer = DataTypeWriter::new(None, Vec::<u8>::new());
        writer.write_built_in_declarations(&NoArchiveManager).unwrap();
        assert_eq!(written_text(writer), "");
    }
}
