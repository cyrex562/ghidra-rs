//! Port of `ghidra.features.codecompare.graphanalysis`: control-flow and data-flow graph
//! n-gram hashing used by the Pinning algorithm to match two decompiled functions.

pub mod ctrl_n_gram;
pub mod data_n_gram;

pub use ctrl_n_gram::CtrlNGram;
pub use data_n_gram::DataNGram;
