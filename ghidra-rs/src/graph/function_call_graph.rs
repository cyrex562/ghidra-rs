use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Function;

use super::fcg_direction::FcgDirection;
use super::fcg_vertex_expansion_listener::FcgVertexExpansionListener;
use super::seam_stubs::{FcgEdge, FcgLevel, FcgVertex, FcgVisualGraphLayout};

/// A wrapper for `Arc<dyn Function>` that implements `Hash`/`Eq` based on pointer identity,
/// mirroring Java's default `Object` identity semantics (`Function` is not overridden to use
/// value equality). Allows `Arc<dyn Function>` to be used as a `HashMap` key.
#[derive(Clone)]
struct FunctionKey(Arc<dyn Function>);

impl PartialEq for FunctionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FunctionKey {}

impl std::hash::Hash for FunctionKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as *const () as usize).hash(state);
    }
}

/// A wrapper for `Arc<dyn FcgVertex>` that implements `Hash`/`Eq` based on pointer identity,
/// mirroring Java's default `Object` identity semantics for `FcgVertex`.
#[derive(Clone)]
struct VertexKey(Arc<dyn FcgVertex>);

impl PartialEq for VertexKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for VertexKey {}

impl std::hash::Hash for VertexKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as *const () as usize).hash(state);
    }
}

/// A graph for the function call graph plugin (`functioncalls.plugin.FunctionCallGraphPlugin`).
///
/// Port of `functioncalls.graph.FunctionCallGraph`. In Java this class extends the generic,
/// still-unported base `ghidra.graph.graphs.FilteringVisualGraph<FcgVertex, FcgEdge>`; since
/// `FunctionCallGraph` is the base's only concrete subclass in this crate so far, the storage
/// and behavior it inherits (`addVertex`/`addEdge`/`getAllVertices`/`getAllEdges`/
/// `getFilteredVertices`/`getFilteredEdges`/`filterVertices`/`filterEdges`) is implemented
/// directly as part of this struct rather than as a separate base type. Only the members this
/// file actually exercises are included: the base's visible-vs-complete vertex tracking (used to
/// support `unfilterVertices`/`removeVertex`/etc., none of which `FunctionCallGraph.java` calls)
/// is not modeled.
pub struct FunctionCallGraph {
    layout: Option<Box<dyn FcgVisualGraphLayout>>,
    source: Option<Arc<dyn FcgVertex>>,
    all_vertices: Vec<Arc<dyn FcgVertex>>,
    all_edges: Vec<FcgEdge>,
    filtered_vertices: Vec<Arc<dyn FcgVertex>>,
    filtered_edges: Vec<FcgEdge>,
    vertices_by_function: HashMap<FunctionKey, Arc<dyn FcgVertex>>,
    vertices_by_level: HashMap<FcgLevel, BTreeMap<Address, Arc<dyn FcgVertex>>>,
}

impl FunctionCallGraph {
    pub fn new() -> Self {
        Self {
            layout: None,
            source: None,
            all_vertices: Vec::new(),
            all_edges: Vec::new(),
            filtered_vertices: Vec::new(),
            filtered_edges: Vec::new(),
            vertices_by_function: HashMap::new(),
            vertices_by_level: HashMap::new(),
        }
    }

    /// Sets the source vertex from which the graph is created.
    ///
    /// Mirrors `setSource`; panics if the source has already been set, matching Java's
    /// `IllegalStateException`.
    pub fn set_source(&mut self, source: Arc<dyn FcgVertex>) {
        if self.source.is_some() {
            panic!("Cannot change graph source once it has been set");
        }

        self.source = Some(source.clone());
        self.add_vertex(source);
    }

    /// Returns the vertex from which the graph is created.
    pub fn get_source(&self) -> Option<&Arc<dyn FcgVertex>> {
        self.source.as_ref()
    }

    /// Returns the vertex mapped to the given function; `None` if there is no matching vertex.
    pub fn get_vertex(&self, f: &Arc<dyn Function>) -> Option<&Arc<dyn FcgVertex>> {
        self.vertices_by_function.get(&FunctionKey(f.clone()))
    }

    /// Returns true if this graph contains a vertex for the given function.
    pub fn contains_function(&self, f: &Arc<dyn Function>) -> bool {
        self.vertices_by_function.contains_key(&FunctionKey(f.clone()))
    }

    /// Returns all vertices in the given level. The result will be non-null (an empty iterator
    /// if the level has no vertices).
    pub fn get_vertices_by_level(&self, level: &FcgLevel) -> impl Iterator<Item = &Arc<dyn FcgVertex>> {
        self.vertices_by_level.get(level).into_iter().flat_map(|m| m.values())
    }

    /// Returns the largest level (the furthest level from the source node) in the given
    /// direction.
    pub fn get_largest_level(&self, direction: FcgDirection) -> FcgLevel {
        let mut greatest = FcgLevel::new(1, direction);

        for level in self.vertices_by_level.keys() {
            if level.get_direction() != direction {
                continue;
            }

            if level.get_row() > greatest.get_row() {
                greatest = *level;
            }
        }

        greatest
    }

    pub fn get_layout(&self) -> Option<&dyn FcgVisualGraphLayout> {
        self.layout.as_deref()
    }

    pub fn set_layout(&mut self, layout: Box<dyn FcgVisualGraphLayout>) {
        self.layout = Some(layout);
    }

    /// Copies this graph, sharing the same vertex and edge instances with the original.
    pub fn copy(&self) -> FunctionCallGraph {
        let mut new_graph = FunctionCallGraph::new();
        self.do_copy(&mut new_graph);
        new_graph
    }

    /// Mirrors `FilteringVisualGraph.doCopy`: copies all vertices and edges (and the filtered
    /// subset) into `new_graph`, reusing the same vertex/edge instances.
    fn do_copy(&self, new_graph: &mut FunctionCallGraph) {
        for v in &self.all_vertices {
            new_graph.add_vertex(v.clone());
        }
        for e in &self.all_edges {
            new_graph.add_edge(e.clone());
        }
        new_graph.filter_vertices(self.filtered_vertices.clone());
        new_graph.filter_edges(self.filtered_edges.clone());
    }

    /// Adds a vertex to the graph and updates the function/level indices.
    ///
    /// Mirrors the inherited `FilteringVisualGraph.addVertex`, followed by this class's
    /// `verticesAdded` override. Like the JUNG-backed graph it wraps in Java, adding a vertex
    /// that is already present (by identity) is a no-op and does not re-trigger the
    /// `verticesAdded` hook -- this matters because `setSource` unconditionally calls
    /// `addVertex` on a vertex that may already have been added elsewhere (e.g. by
    /// `clone_graph`).
    pub fn add_vertex(&mut self, v: Arc<dyn FcgVertex>) {
        if self.all_vertices.iter().any(|existing| Arc::ptr_eq(existing, &v)) {
            return;
        }
        self.all_vertices.push(v.clone());
        self.vertices_added(&[v]);
    }

    /// Adds an edge to the graph.
    ///
    /// Mirrors the inherited `FilteringVisualGraph.addEdge` (no override in this class).
    pub fn add_edge(&mut self, e: FcgEdge) {
        self.all_edges.push(e);
    }

    /// Removes a single vertex. Mirrors `FilteringVisualGraph.removeVertex`, which -- unlike the
    /// plural `removeVertices` -- does *not* invoke the `verticesRemoved` hook.
    pub fn remove_vertex(&mut self, v: &Arc<dyn FcgVertex>) -> bool {
        let before = self.all_vertices.len();
        self.all_vertices.retain(|existing| !Arc::ptr_eq(existing, v));
        self.all_vertices.len() != before
    }

    /// Removes multiple vertices and updates the function/level indices.
    ///
    /// Mirrors the inherited `FilteringVisualGraph.removeVertices`, followed by this class's
    /// `verticesRemoved` override.
    pub fn remove_vertices(&mut self, to_remove: &[Arc<dyn FcgVertex>]) {
        let mut removed = Vec::new();
        for v in to_remove {
            if self.remove_vertex(v) {
                removed.push(v.clone());
            }
        }
        self.vertices_removed(&removed);
    }

    pub fn get_all_vertices(&self) -> impl Iterator<Item = &Arc<dyn FcgVertex>> {
        self.all_vertices.iter()
    }

    pub fn get_all_edges(&self) -> impl Iterator<Item = &FcgEdge> {
        self.all_edges.iter()
    }

    pub fn get_filtered_vertices(&self) -> impl Iterator<Item = &Arc<dyn FcgVertex>> {
        self.filtered_vertices.iter()
    }

    pub fn get_filtered_edges(&self) -> impl Iterator<Item = &FcgEdge> {
        self.filtered_edges.iter()
    }

    pub fn filter_vertices(&mut self, to_filter: Vec<Arc<dyn FcgVertex>>) {
        self.filtered_vertices.extend(to_filter);
    }

    pub fn filter_edges(&mut self, to_filter: Vec<FcgEdge>) {
        self.filtered_edges.extend(to_filter);
    }

    /// Mirrors `verticesAdded`, updating the function/level indices for newly-added vertices.
    fn vertices_added(&mut self, added: &[Arc<dyn FcgVertex>]) {
        for v in added {
            let f = v.get_function();
            self.vertices_by_function.insert(FunctionKey(f), v.clone());
            self.vertices_by_level
                .entry(v.get_level())
                .or_default()
                .insert(v.get_address(), v.clone());
        }
    }

    /// Mirrors `verticesRemoved`, removing the function/level index entries for removed
    /// vertices.
    fn vertices_removed(&mut self, removed: &[Arc<dyn FcgVertex>]) {
        for v in removed {
            let f = v.get_function();
            self.vertices_by_function.remove(&FunctionKey(f));
            if let Some(level_set) = self.vertices_by_level.get_mut(&v.get_level()) {
                level_set.remove(&v.get_address());
            }
        }
    }

    /// Clones this graph and its vertices and edges.
    ///
    /// `expansion_listener` is the listener needed to create each new vertex.
    pub fn clone_graph(&self, expansion_listener: &dyn FcgVertexExpansionListener) -> FunctionCallGraph {
        let mut new_graph = FunctionCallGraph::new();
        let cloned_layout = self.layout.as_ref().map(|l| l.clone_layout(&new_graph));
        new_graph.layout = cloned_layout;

        let mut old_to_new_vertices: HashMap<VertexKey, Arc<dyn FcgVertex>> = HashMap::new();
        for v in &self.all_vertices {
            let new_v: Arc<dyn FcgVertex> = Arc::from(v.clone_vertex(expansion_listener));
            old_to_new_vertices.insert(VertexKey(v.clone()), new_v.clone());
            new_graph.add_vertex(new_v);
        }

        let mut old_to_new_edges: HashMap<(Address, Address), FcgEdge> = HashMap::new();
        for e in &self.all_edges {
            let old_start = e.get_start();
            let old_end = e.get_end();
            let new_start = old_to_new_vertices
                .get(&VertexKey(old_start.clone()))
                .expect("edge start vertex was not cloned")
                .clone();
            let new_end = old_to_new_vertices
                .get(&VertexKey(old_end.clone()))
                .expect("edge end vertex was not cloned")
                .clone();
            let new_e = e.clone_edge(new_start, new_end);
            old_to_new_edges.insert((old_start.get_address(), old_end.get_address()), new_e.clone());
            new_graph.add_edge(new_e);
        }

        let filtered_vertices: Vec<Arc<dyn FcgVertex>> = self
            .filtered_vertices
            .iter()
            .filter_map(|v| old_to_new_vertices.get(&VertexKey(v.clone())).cloned())
            .collect();
        new_graph.filter_vertices(filtered_vertices);

        let filtered_edges: Vec<FcgEdge> = self
            .filtered_edges
            .iter()
            .filter_map(|e| {
                old_to_new_edges
                    .get(&(e.get_start().get_address(), e.get_end().get_address()))
                    .cloned()
            })
            .collect();
        new_graph.filter_edges(filtered_edges);

        if let Some(source) = &self.source {
            if let Some(new_source) = old_to_new_vertices.get(&VertexKey(source.clone())) {
                new_graph.set_source(new_source.clone());
            }
        }

        new_graph
    }
}

impl Default for FunctionCallGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::Namespace;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockFunction {
        name: String,
        entry: Address,
    }

    impl MockFunction {
        fn new(name: &str, entry_offset: i64) -> Self {
            Self {
                name: name.to_string(),
                entry: mock_address(entry_offset),
            }
        }
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> Address {
            self.entry.clone()
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!()
        }

        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            vec![]
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }

        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(&mut self, _custom_storage: bool) {}

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }

        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }

        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn is_inline(&self) -> bool {
            false
        }

        fn set_inline(&mut self, _is_inline: bool) {}

        fn has_no_return(&self) -> bool {
            false
        }

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            String::from("unknown")
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn set_body(&mut self, _new_body: &dyn crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct MockVertex {
        function: Arc<dyn Function>,
        level: FcgLevel,
    }

    impl MockVertex {
        fn new(function: Arc<dyn Function>, level: FcgLevel) -> Self {
            Self { function, level }
        }
    }

    impl FcgVertex for MockVertex {
        fn clone_vertex(&self, _new_listener: &dyn FcgVertexExpansionListener) -> Box<dyn FcgVertex> {
            Box::new(MockVertex::new(self.function.clone(), self.level))
        }
        fn get_function(&self) -> Arc<dyn Function> {
            self.function.clone()
        }
        fn get_address(&self) -> Address {
            self.function.get_entry_point()
        }
        fn get_options(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_level(&self) -> FcgLevel {
            self.level
        }
        fn get_degree(&self) -> i32 {
            0
        }
        fn get_direction(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_hovered(&self, _hovered: bool) {}
        fn get_incoming_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_outgoing_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_has_incoming_references(&self, _has_incoming: bool) {}
        fn set_has_outgoing_references(&self, _has_outgoing: bool) {}
        fn set_too_many_incoming_references(&self, _too_many: bool) {}
        fn set_too_many_outgoing_references(&self, _too_many: bool) {}
        fn has_too_many_incoming_references(&self) -> bool {
            false
        }
        fn has_too_many_outgoing_references(&self) -> bool {
            false
        }
        fn is_incoming_expanded(&self) -> bool {
            false
        }
        fn is_outgoing_expanded(&self) -> bool {
            false
        }
        fn is_expanded(&self) -> bool {
            false
        }
        fn can_expand(&self) -> bool {
            false
        }
        fn can_expand_incoming_references(&self) -> bool {
            false
        }
        fn can_expand_outgoing_references(&self) -> bool {
            false
        }
        fn set_incoming_expanded(&self, _set_expanded: bool) {}
        fn set_outgoing_expanded(&self, _set_expanded: bool) {}
        fn to_string(&self) -> String {
            Function::get_name(self.function.as_ref())
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            false
        }
        fn dispose(&self) {}
    }

    fn source_vertex() -> Arc<dyn FcgVertex> {
        let f = Arc::new(MockFunction::new("main", 0x400000)) as Arc<dyn Function>;
        Arc::new(MockVertex::new(f, FcgLevel::new(0, FcgDirection::InAndOut)))
    }

    fn vertex_at(name: &str, offset: i64, level: FcgLevel) -> Arc<dyn FcgVertex> {
        let f = Arc::new(MockFunction::new(name, offset)) as Arc<dyn Function>;
        Arc::new(MockVertex::new(f, level))
    }

    #[test]
    fn test_new_graph_is_empty() {
        let graph = FunctionCallGraph::new();
        assert!(graph.get_source().is_none());
        assert_eq!(graph.get_all_vertices().count(), 0);
        assert_eq!(graph.get_all_edges().count(), 0);
    }

    #[test]
    fn test_set_source_adds_vertex() {
        let mut graph = FunctionCallGraph::new();
        let source = source_vertex();
        graph.set_source(source.clone());

        assert!(Arc::ptr_eq(graph.get_source().unwrap(), &source));
        assert_eq!(graph.get_all_vertices().count(), 1);
    }

    #[test]
    #[should_panic(expected = "Cannot change graph source once it has been set")]
    fn test_set_source_twice_panics() {
        let mut graph = FunctionCallGraph::new();
        graph.set_source(source_vertex());
        graph.set_source(source_vertex());
    }

    #[test]
    fn test_get_vertex_and_contains_function() {
        let mut graph = FunctionCallGraph::new();
        let level = FcgLevel::new(0, FcgDirection::InAndOut);
        let v = vertex_at("foo", 0x1000, level);
        let f = v.get_function();
        graph.add_vertex(v.clone());

        assert!(graph.contains_function(&f));
        assert!(Arc::ptr_eq(graph.get_vertex(&f).unwrap(), &v));

        let other_f = Arc::new(MockFunction::new("bar", 0x2000)) as Arc<dyn Function>;
        assert!(!graph.contains_function(&other_f));
        assert!(graph.get_vertex(&other_f).is_none());
    }

    #[test]
    fn test_get_vertices_by_level() {
        let mut graph = FunctionCallGraph::new();
        // Row 1 is reserved for IN_AND_OUT (the source level), so a non-source direction's
        // smallest valid level is distance 1 (row 2).
        let in_level = FcgLevel::new(1, FcgDirection::In);
        let v1 = vertex_at("in1", 0x1000, in_level);
        let v2 = vertex_at("in2", 0x2000, in_level);
        graph.add_vertex(v1);
        graph.add_vertex(v2);

        assert_eq!(graph.get_vertices_by_level(&in_level).count(), 2);

        let out_level = FcgLevel::new(1, FcgDirection::Out);
        assert_eq!(graph.get_vertices_by_level(&out_level).count(), 0);
    }

    #[test]
    fn test_get_largest_level() {
        let mut graph = FunctionCallGraph::new();
        // distance 1 -> row 2; distance 3 -> row 4 (IN direction; row 1 is reserved for the
        // IN_AND_OUT source level).
        let v1 = vertex_at("in1", 0x1000, FcgLevel::new(1, FcgDirection::In));
        let v2 = vertex_at("in2", 0x2000, FcgLevel::new(3, FcgDirection::In));
        graph.add_vertex(v1);
        graph.add_vertex(v2);

        let largest = graph.get_largest_level(FcgDirection::In);
        assert_eq!(largest.get_row(), 4);
        assert_eq!(largest.get_direction(), FcgDirection::In);
    }

    #[test]
    fn test_get_largest_level_defaults_when_empty() {
        let graph = FunctionCallGraph::new();
        let largest = graph.get_largest_level(FcgDirection::Out);
        // Matches Java's `new FcgLevel(1, direction)` seed value.
        assert_eq!(largest.get_row(), -2);
    }

    #[test]
    fn test_add_edge_and_get_all_edges() {
        let mut graph = FunctionCallGraph::new();
        let level = FcgLevel::new(0, FcgDirection::InAndOut);
        let start = vertex_at("start", 0x1000, level);
        let end = vertex_at("end", 0x2000, level);
        let edge = FcgEdge::new(start.clone(), end.clone());
        graph.add_edge(edge);

        assert_eq!(graph.get_all_edges().count(), 1);
        assert_eq!(graph.get_filtered_edges().count(), 0);
    }

    #[test]
    fn test_filter_vertices() {
        let mut graph = FunctionCallGraph::new();
        let v = vertex_at("foo", 0x1000, FcgLevel::new(0, FcgDirection::InAndOut));
        graph.add_vertex(v.clone());

        graph.filter_vertices(vec![v.clone()]);

        assert_eq!(graph.get_all_vertices().count(), 1);
        assert_eq!(graph.get_filtered_vertices().count(), 1);
        // Filtering does not remove the function/level index entries (mirrors Java: filtering
        // does not invoke the `verticesRemoved` hook).
        assert!(graph.contains_function(&v.get_function()));
    }

    #[test]
    fn test_remove_vertices_updates_indices() {
        let mut graph = FunctionCallGraph::new();
        let v = vertex_at("foo", 0x1000, FcgLevel::new(0, FcgDirection::InAndOut));
        let f = v.get_function();
        graph.add_vertex(v.clone());
        assert!(graph.contains_function(&f));

        graph.remove_vertices(&[v]);

        assert!(!graph.contains_function(&f));
        assert_eq!(graph.get_all_vertices().count(), 0);
    }

    #[test]
    fn test_copy_shares_same_vertices() {
        let mut graph = FunctionCallGraph::new();
        let source = source_vertex();
        graph.set_source(source.clone());

        let copy = graph.copy();

        assert_eq!(copy.get_all_vertices().count(), 1);
        let copied_vertex = copy.get_all_vertices().next().unwrap();
        assert!(Arc::ptr_eq(copied_vertex, &source));
    }

    #[test]
    fn test_clone_graph_creates_new_vertex_instances() {
        struct NoopListener;
        impl FcgVertexExpansionListener for NoopListener {
            fn toggle_incoming_vertices(&self, _v: &dyn FcgVertex) {}
            fn toggle_outgoing_vertices(&self, _v: &dyn FcgVertex) {}
        }

        let mut graph = FunctionCallGraph::new();
        let source = source_vertex();
        graph.set_source(source.clone());

        let level = FcgLevel::new(1, FcgDirection::Out);
        let other = vertex_at("callee", 0x5000, level);
        graph.add_vertex(other.clone());

        let edge = FcgEdge::new(source.clone(), other.clone());
        graph.add_edge(edge);

        let cloned = graph.clone_graph(&NoopListener);

        assert_eq!(cloned.get_all_vertices().count(), 2);
        assert_eq!(cloned.get_all_edges().count(), 1);

        // The clone must use brand-new vertex instances, not the same references.
        for v in cloned.get_all_vertices() {
            assert!(!Arc::ptr_eq(v, &source));
            assert!(!Arc::ptr_eq(v, &other));
        }

        // But the source function identity is preserved.
        assert!(cloned.contains_function(&source.get_function()));
        assert!(cloned.get_source().is_some());
    }
}
