use super::ids::{AttributeId, ElementId};
use crate::program::model::address::{AddressFactory, AddressSpace};
use crate::util::exception::CancelledException;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DecoderError {
    #[error("Decoding error: {0}")]
    Generic(String),
    #[error("Unexpected end of stream")]
    UnexpectedEndOfStream,
    #[error("Missing attribute: {0}")]
    MissingAttribute(String),
    #[error("Invalid element: expected {expected}, found {actual}")]
    InvalidElement { expected: String, actual: String },
    #[error("Cancelled")]
    Cancelled(#[from] CancelledException),
    #[error("IO error: {0}")]
    Io(String),
}

pub trait Decoder: Send + Sync {
    fn get_address_factory(&self) -> Arc<dyn AddressFactory>;
    fn set_address_factory(&self, factory: Arc<dyn AddressFactory>);

    fn peek_element(&self) -> Result<i32, DecoderError>;
    fn open_element(&self) -> Result<i32, DecoderError>;
    fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError>;
    fn close_element(&self, id: i32) -> Result<(), DecoderError>;
    fn close_element_skipping(&self, id: i32) -> Result<(), DecoderError>;

    fn get_next_attribute_id(&self) -> Result<i32, DecoderError>;
    fn rewind_attributes(&self);

    fn read_bool(&self) -> Result<bool, DecoderError>;
    fn read_bool_with_id(&self, attrib_id: AttributeId) -> Result<bool, DecoderError>;

    fn read_signed_integer(&self) -> Result<i64, DecoderError>;
    fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError>;

    fn read_unsigned_integer(&self) -> Result<u64, DecoderError>;
    fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError>;

    fn read_string(&self) -> Result<String, DecoderError>;
    fn read_string_with_id(&self, attrib_id: AttributeId) -> Result<String, DecoderError>;

    fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError>;
    fn read_space_with_id(&self, attrib_id: AttributeId)
        -> Result<Arc<AddressSpace>, DecoderError>;
}
