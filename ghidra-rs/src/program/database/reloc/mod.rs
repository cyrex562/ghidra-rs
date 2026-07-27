pub mod relocation_db_adapter;

pub use relocation_db_adapter::{
    get_byte_length, get_flags, get_status, RelocationDBAdapter, ADDR_COL, BYTES_COL, FLAGS_COL,
    LENGTH_FLAGS_MASK, LENGTH_FLAGS_SHIFT, LENGTH_MAX, STATUS_FLAGS_MASK, SYMBOL_NAME_COL,
    TABLE_NAME, TYPE_COL, VALUE_COL,
};
