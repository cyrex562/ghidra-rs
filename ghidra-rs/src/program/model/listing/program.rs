use crate::program::model::address::AddressFactory;
use std::sync::Arc;

pub trait Program: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_language_id(&self) -> &str;

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        None
    }
}
