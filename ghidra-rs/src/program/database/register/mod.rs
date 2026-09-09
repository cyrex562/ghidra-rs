//! Port of `ghidra.program.database.register`.
//!
//! Address-range-keyed value storage used by register context / register-value maps: an
//! in-memory coalescing map ([`AddressRangeObjectMap`]), a small adapter trait
//! ([`crate::program::util::RangeMapAdapter`], already ported before this package existed) with
//! two implementations -- one backed by a database table
//! ([`DatabaseRangeMapAdapter`]) and one purely in-memory ([`InMemoryRangeMapAdapter`]) -- and a
//! small iterator adapter bridging index-based ranges to address-based ones
//! ([`IndexToAddressRangeIteratorAdapter`]).

pub mod address_range_object_map;
pub mod database_range_map_adapter;
pub mod in_memory_range_map_adapter;
pub mod index_to_address_range_iterator_adapter;

pub use address_range_object_map::AddressRangeObjectMap;
pub use database_range_map_adapter::DatabaseRangeMapAdapter;
pub use in_memory_range_map_adapter::InMemoryRangeMapAdapter;
pub use index_to_address_range_iterator_adapter::IndexToAddressRangeIteratorAdapter;
