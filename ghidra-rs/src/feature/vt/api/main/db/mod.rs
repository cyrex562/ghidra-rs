pub mod deleted_match;
pub mod vt_address_correlator_adapter;
pub mod vt_association_table_db_adapter;
pub mod vt_match_set_table_db_adapter;
pub mod vt_match_table_db_adapter;
pub mod vt_match_tag_db_adapter;

pub use deleted_match::DeletedMatch;
pub use vt_address_correlator_adapter::{
    ColumnDescription as AddressCorrelationTableColumnDescription, VTAddressCorrelatorAdapter,
    VTAddressCorrelatorAdapterBase, TABLE_NAME as ADDRESS_CORRELATION_TABLE_TABLE_NAME,
};
pub use vt_association_table_db_adapter::{
    ColumnDescription as AssociationTableColumnDescription, VTAssociationTableDBAdapter,
    VTAssociationTableDBAdapterBase, TABLE_NAME as ASSOCIATION_TABLE_TABLE_NAME,
};
pub use vt_match_set_table_db_adapter::{
    ColumnDescription as MatchSetTableColumnDescription, VTMatchSetTableDBAdapter,
    VTMatchSetTableDBAdapterBase, TABLE_NAME as MATCH_SET_TABLE_TABLE_NAME,
};
pub use vt_match_table_db_adapter::{
    ColumnDescription as MatchTableColumnDescription, VTMatchTableDBAdapter,
    VTMatchTableDBAdapterBase, TABLE_NAME as MATCH_TABLE_TABLE_NAME,
};
pub use vt_match_tag_db_adapter::{
    ColumnDescription, VTMatchTagDBAdapter, VTMatchTagDBAdapterBase, TABLE_NAME,
};
