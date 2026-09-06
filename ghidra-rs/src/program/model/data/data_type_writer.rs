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

use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::Arc;

use crate::program::model::data::annotation_handler::AnnotationHandler;
use crate::program::model::data::array::Array;
use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::default_annotation_handler::DefaultAnnotationHandler;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::pointer::Pointer;
use crate::util::exception::CancelledException;
use crate::util::graph::{AbstractDependencyGraph, DeterministicDependencyGraph};
use crate::util::task::TaskMonitor;

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
    ///
    /// #[allow(dead_code)]: not yet read/written by anything -- its real user, the `doWrite`
    /// dispatch port, is one of the "not yet ported" items listed in the module doc comment.
    #[allow(dead_code)]
    resolved: HashSet<String>,
    /// Port of `compositeDependencyGraph`.
    composite_dependency_graph: DeterministicDependencyGraph<CompositeNode>,
    /// Port of `writerDepth`.
    #[allow(dead_code)]
    writer_depth: i32,
    /// Port of `writer`.
    writer: W,
    /// Port of `dtm`.
    #[allow(dead_code)]
    dtm: Option<Arc<dyn DataTypeManager>>,
    /// Port of `dataOrganization`.
    data_organization: Box<dyn DataOrganization>,
    /// Port of `annotator`.
    #[allow(dead_code)]
    annotator: Box<dyn AnnotationHandler>,
    /// Port of `cppStyleComments`.
    #[allow(dead_code)]
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
            composite_dependency_graph: DeterministicDependencyGraph::new(),
            writer_depth: 0,
            writer,
            dtm,
            data_organization,
            annotator,
            cpp_style_comments,
        }
    }

    /// Port of the private `comment(String text)` helper.
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real callers
    /// throughout `doWrite`/`writeEnum`/etc. are among the "not yet ported" items listed in the
    /// module doc comment.
    #[allow(dead_code)]
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
    ///
    /// #[allow(dead_code)]: only exercised from `#[cfg(test)]` today -- its real caller,
    /// `writeTypeDef`'s port, is among the "not yet ported" items listed in the module doc
    /// comment.
    #[allow(dead_code)]
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

    /// Exposes the dependency-graph pop used by the not-yet-ported
    /// `writeDeferredCompositeDeclarations`, for testing the graph-construction pass in isolation
    /// ahead of the body-emission logic it will eventually drive.
    #[cfg(test)]
    fn pop_composite_dependency(&mut self) -> Option<CompositeNode> {
        self.composite_dependency_graph.pop().expect("no cycle expected among by-value composite embeddings")
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
    impl DataType for MockBuiltIn {}
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
}
