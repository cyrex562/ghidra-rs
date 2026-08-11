pub mod deleted_match;
pub mod vt_match_table_db_adapter;
pub mod vt_match_tag_db_adapter;

pub use deleted_match::DeletedMatch;
pub use vt_match_table_db_adapter::{
    ColumnDescription as MatchTableColumnDescription, VTMatchTableDBAdapter,
    VTMatchTableDBAdapterBase, TABLE_NAME as MATCH_TABLE_TABLE_NAME,
};
pub use vt_match_tag_db_adapter::{
    ColumnDescription, VTMatchTagDBAdapter, VTMatchTagDBAdapterBase, TABLE_NAME,
};
