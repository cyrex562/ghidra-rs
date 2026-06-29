pub mod decmpfs_compression_types;
pub mod decmpfs_constants;
pub mod decmpfs_states;

pub use decmpfs_compression_types::{CMP_TYPE1, CMP_TYPE3, CMP_TYPE4, CMP_TYPE10, CMP_MAX};
pub use decmpfs_constants::{DECMPFS_MAGIC, DECMPFS_MAGIC_BYTES, MAX_DECMPFS_XATTR_SIZE};
pub use decmpfs_states::{
    FILE_TYPE_UNKNOWN, FILE_IS_NOT_COMPRESSED, FILE_IS_COMPRESSED, FILE_IS_CONVERTING,
};
