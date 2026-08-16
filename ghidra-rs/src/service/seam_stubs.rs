//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use crate::docking::widgets::EventTrigger;
use crate::service::graph::AttributedVertex;
use crate::service::graph::AttributedGraph;
use crate::docking::action::docking_action_if::DockingActionIf;
use crate::util::task::TaskMonitor;

/// Placeholder for `ghidra.service.graph.GraphDisplay`, referenced by `GraphDisplayListener`.
pub trait GraphDisplay: Send + Sync {
    fn set_graph_display_listener(&self, listener: &dyn GraphDisplayListener);
    fn set_focused_vertex(&self, vertex: &AttributedVertex, event_trigger: &EventTrigger);
    fn get_graph(&self) -> AttributedGraph;
    fn get_focused_vertex(&self) -> Option<AttributedVertex>;
    fn select_vertices(&self, vertex_set: Vec<AttributedVertex>, event_trigger: &EventTrigger);
    fn get_selected_vertices(&self) -> Vec<AttributedVertex>;
    fn close(&self);
    fn set_graph(&self, graph: &AttributedGraph, title: &str, append: bool, monitor: &dyn TaskMonitor) -> std::io::Result<()>;
    fn clear(&self);
    fn update_vertex_name(&self, vertex: &AttributedVertex, new_name: &str);
    fn get_graph_title(&self) -> String;
    fn add_action(&self, action: &dyn DockingActionIf);
    fn get_actions(&self) -> Vec<Box<dyn DockingActionIf>>;
}

// Re-export GraphDisplayListener from its canonical location
pub use super::graph::graph_display_listener::GraphDisplayListener;
