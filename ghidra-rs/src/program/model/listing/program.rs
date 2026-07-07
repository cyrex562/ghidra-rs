use crate::framework::model::DomainObject;
use crate::program::model::address::AddressFactory;
use crate::program::model::listing::Listing;
use std::sync::Arc;

pub trait Program: DomainObject + Send + Sync {
    fn get_name(&self) -> String;
    fn get_language_id(&self) -> String;

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        None
    }

    fn get_listing(&mut self) -> Option<&mut dyn Listing> {
        None
    }
}
