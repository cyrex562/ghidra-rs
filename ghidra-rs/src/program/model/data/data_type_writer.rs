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
//!   - `getTypeDeclaration`/`getDataTypePrefix`/`getDynamicComponentString` (per-field C
//!     declaration text, including array/pointer name mangling and bit-field suffixes).
//!   - `writeEnum`, `writeTypeDef` (including the `isIntegral`-suppression and
//!     auto-typedef/auto-pointer-typedef detection it guards), `writeDynamicBuiltIn`, `writeBuiltIn`
//!     (this one should be a thin call to the already-real
//!     [`BuiltInDataType::get_c_type_declaration`](super::built_in_data_type::BuiltInDataType::get_c_type_declaration),
//!     per this crate's existing precedent -- no new C-declaration formatting should be written for
//!     it), `writeBuiltInDeclarations`.
//!   - `getFunctionPointerString`/`getParameterListString` (function-pointer/parameter-list text).
//!   - `getArrayDimensions`/`getBaseDataType`/`getArrayBaseType`/`getPointerBaseDataType`/
//!     `getPointerDepth`/`getBaseArrayTypedefType` (small recursive helpers feeding the above).
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
use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::default_annotation_handler::DefaultAnnotationHandler;
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

    /// Port of `writeBuiltIn`'s core (the not-yet-ported caller still needs to be wired up): calls
    /// the already-real [`BuiltInDataType::get_c_type_declaration`] rather than re-deriving any
    /// C-declaration formatting, per this crate's established precedent (see the module doc
    /// comment).
    #[allow(dead_code)]
    fn write_built_in(
        &mut self,
        dt: &dyn crate::program::model::data::built_in_data_type::BuiltInDataType,
    ) -> io::Result<()> {
        if let Some(declaration) = dt.get_c_type_declaration(Some(self.data_organization.as_ref())) {
            self.writer.write_all(declaration.as_bytes())?;
            self.writer.write_all(b"\n")?;
        }
        Ok(())
    }
}

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
}
