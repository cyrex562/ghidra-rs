use crate::program::model::address::Address;
use std::io;
use std::sync::Arc;

pub mod address_label_pair;
pub mod entry_point_reference;
pub mod equate;
pub mod equate_reference;
pub mod equate_table;
pub mod external_location;
pub mod external_location_iterator;
pub mod external_path;
pub mod external_reference;
pub mod illegal_char_cpp_transformer;
pub mod label_history;
pub mod mem_reference_impl;
pub mod name_transformer;
pub mod namespace;
pub mod offset_reference;
pub mod ref_type;
pub mod ref_type_factory;
pub mod reference;
pub mod reference_iterator;
pub mod reference_listener;
pub mod shifted_reference;
pub mod source_type;
pub mod stack_reference;
pub mod symbol_iterator;
pub mod symbol_table_listener;
pub mod symbol_type;
pub mod symbol_utilities;
pub mod thunk_reference;

pub use address_label_pair::AddressLabelPair;
pub use entry_point_reference::EntryPointReference;
pub use equate::{Equate, SimpleEquate, UniversalId};
pub use equate_reference::{EquateReference, SimpleEquateReference};
pub use equate_table::{EquateTable, SimpleEquateTable};
pub use external_location::{ExternalLocation, SetExternalLocationError};
pub use external_location_iterator::{
    EmptyExternalLocationIterator, ExternalLocationAdapter, ExternalLocationIterator,
    ExternalLocationIteratorAdapter,
};
pub use external_path::{ExternalPath, ExternalPathError, EXTERNAL_PATH_DELIMITER};
pub use external_reference::ExternalReference;
pub use illegal_char_cpp_transformer::IllegalCharCppTransformer;
pub use label_history::{LabelHistory, LabelHistoryAction};
pub use mem_reference_impl::MemReferenceImpl;
pub use name_transformer::{IdentityNameTransformer, NameTransformer};
#[allow(deprecated)]
pub use namespace::NAMESPACE_DELIMITER;
pub use namespace::{Namespace, NamespaceType, SetParentNamespaceError, DELIMITER, GLOBAL_NAMESPACE_ID};
pub use offset_reference::OffsetReference;
pub use ref_type::RefType;
pub use ref_type_factory::RefTypeFactory;
pub use reference::{DynamicReference, Reference, MNEMONIC, OTHER};
pub use reference_iterator::{
    EmptyReferenceIterator, ReferenceAdapter, ReferenceIterator, ReferenceIteratorAdapter,
};
pub use reference_listener::ReferenceListener;
pub use shifted_reference::ShiftedReference;
pub use source_type::SourceType;
pub use stack_reference::StackReference;
pub use symbol_iterator::{EmptySymbolIterator, SymbolIterator, SymbolIteratorAdapter};
pub use symbol_table_listener::SymbolTableListener;
pub use symbol_type::SymbolType;
pub use symbol_utilities::*;
pub use thunk_reference::ThunkReference;

pub trait Symbol: Send + Sync {
    fn get_address(&self) -> Address;
    fn get_name(&self) -> &str;
    fn get_symbol_type(&self) -> SymbolType;
    fn get_source(&self) -> SourceType;
    fn is_primary(&self) -> bool;
    fn get_id(&self) -> i64;
    fn get_parent_id(&self) -> i64;

    /// Returns true if this symbol is external (i.e. associated with a
    /// [`Library`](crate::program::model::listing::library::Library) rather than program
    /// memory). Real abstract method on `Symbol`.
    ///
    /// Defaults to `false` so existing implementors are unaffected; concrete implementations
    /// should override once external-symbol support is ported.
    fn is_external(&self) -> bool {
        false
    }

    /// The namespace this symbol represents, when its [`SymbolType`] is `Namespace`, `Class`,
    /// `Library`, or `Function`. Stands in for `Symbol.getObject()` narrowed to the `Namespace`
    /// case, since Rust trait objects cannot be downcast to another trait object without extra
    /// machinery.
    ///
    /// Defaults to `None` so existing implementors are unaffected.
    fn as_namespace(&self) -> Option<Arc<dyn Namespace>> {
        None
    }
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
