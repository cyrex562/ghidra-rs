pub mod relocation_db_adapter;
pub mod relocation_db_adapter_no_table;
pub mod relocation_db_adapter_v1;
pub mod relocation_db_adapter_v2;
pub mod relocation_db_adapter_v3;
pub mod relocation_db_adapter_v4;
pub mod relocation_db_adapter_v5;
pub mod relocation_db_adapter_v6;
pub mod relocation_manager;
#[cfg(test)]
mod test_support;

pub use relocation_db_adapter::{
    get_adapter, get_byte_length, get_flags, get_status, schema, RelocationAdapterKind,
    RelocationDBAdapter, ADDR_COL, BYTES_COL, FLAGS_COL, LENGTH_FLAGS_MASK, LENGTH_FLAGS_SHIFT,
    LENGTH_MAX, STATUS_FLAGS_MASK, SYMBOL_NAME_COL, TABLE_NAME, TYPE_COL, VALUE_COL,
};
pub use relocation_db_adapter_no_table::RelocationDbAdapterNoTable;
pub use relocation_db_adapter_v1::RelocationDbAdapterV1;
pub use relocation_db_adapter_v2::RelocationDbAdapterV2;
pub use relocation_db_adapter_v3::RelocationDbAdapterV3;
pub use relocation_db_adapter_v4::RelocationDbAdapterV4;
pub use relocation_db_adapter_v5::RelocationDbAdapterV5;
pub use relocation_db_adapter_v6::RelocationDbAdapterV6;
pub use relocation_manager::RelocationManager;
