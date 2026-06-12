use crate::program::model::address::Address;
use std::io;
use std::sync::Arc;

pub mod address_label_pair;
pub mod external_path;
pub mod label_history;
pub mod source_type;
pub mod symbol_type;
pub mod name_transformer;

pub use address_label_pair::AddressLabelPair;
pub use external_path::{ExternalPath, ExternalPathError, EXTERNAL_PATH_DELIMITER};
pub use label_history::{LabelHistory, LabelHistoryAction};
pub use name_transformer::{IdentityNameTransformer, NameTransformer};
pub use source_type::SourceType;
pub use symbol_type::SymbolType;

pub trait Symbol: Send + Sync {
    fn get_address(&self) -> Address;
    fn get_name(&self) -> &str;
    fn get_symbol_type(&self) -> SymbolType;
    fn get_source(&self) -> SourceType;
    fn is_primary(&self) -> bool;
    fn get_id(&self) -> i64;
    fn get_parent_id(&self) -> i64;
}

pub trait SymbolTable: Send + Sync {
    fn create_label(
        &mut self,
        addr: &Address,
        name: &str,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>>;

    fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>>;

    fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>>;
}
