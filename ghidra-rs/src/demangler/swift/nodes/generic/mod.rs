//! Port of the `ghidra.app.util.demangler.swift.nodes.generic` package.

pub mod swift_generic_index_node;
pub mod swift_generic_passthrough_node;
pub mod swift_generic_text_node;

pub use swift_generic_index_node::SwiftGenericIndexNode;
pub use swift_generic_passthrough_node::SwiftGenericPassthroughNode;
pub use swift_generic_text_node::SwiftGenericTextNode;
