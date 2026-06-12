use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
#[error("{0}")]
pub struct UsrException(pub String);

impl UsrException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Operation cancelled: {0}")]
pub struct CancelledException(pub String);

impl CancelledException {
    pub const DEFAULT_MESSAGE: &'static str = "Operation cancelled";

    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn default() -> Self {
        Self(Self::DEFAULT_MESSAGE.to_string())
    }

    pub fn is_default_message(&self) -> bool {
        self.0 == Self::DEFAULT_MESSAGE
    }
}

#[derive(Error, Debug, PartialEq)]
#[error("Address overflow: {0}")]
pub struct AddressOverflowException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Address out of bounds: {0}")]
pub struct AddressOutOfBoundsException(pub String);

#[derive(Error, Debug, PartialEq)]
#[error("Assertion failed: {0}")]
pub struct AssertException(pub String);

impl AssertException {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }

    pub fn from_error(err: &dyn std::error::Error) -> Self {
        Self(format!("Unexpected Error: {}", err))
    }
}
