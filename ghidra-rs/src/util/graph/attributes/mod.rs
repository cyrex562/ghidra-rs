pub mod attribute;
pub mod attribute_manager;
pub mod double_attribute;

#[allow(deprecated)]
pub use attribute::Attribute;
#[allow(deprecated)]
pub use attribute_manager::{
    AttributeManager, DOUBLE_TYPE, INTEGER_TYPE, LONG_TYPE, OBJECT_TYPE, STRING_TYPE,
};
#[allow(deprecated)]
pub use double_attribute::DoubleAttribute;
