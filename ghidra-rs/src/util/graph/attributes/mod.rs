pub mod attribute;
pub mod attribute_manager;
pub mod double_attribute;
pub mod integer_attribute;
pub mod long_attribute;
pub mod object_attribute;
pub mod string_attribute;

#[allow(deprecated)]
pub use attribute::Attribute;
#[allow(deprecated)]
pub use attribute_manager::{
    AttributeManager, DOUBLE_TYPE, INTEGER_TYPE, LONG_TYPE, OBJECT_TYPE, STRING_TYPE,
};
#[allow(deprecated)]
pub use double_attribute::DoubleAttribute;
#[allow(deprecated)]
pub use integer_attribute::IntegerAttribute;
#[allow(deprecated)]
pub use long_attribute::LongAttribute;
#[allow(deprecated)]
pub use object_attribute::ObjectAttribute;
#[allow(deprecated)]
pub use string_attribute::StringAttribute;
