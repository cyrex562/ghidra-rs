pub mod deleted_match;
pub mod vt_match_tag_db_adapter;

pub use deleted_match::DeletedMatch;
pub use vt_match_tag_db_adapter::{
    ColumnDescription, VTMatchTagDBAdapter, VTMatchTagDBAdapterBase, TABLE_NAME,
};
