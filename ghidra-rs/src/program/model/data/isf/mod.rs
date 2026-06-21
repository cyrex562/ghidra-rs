/// Marker trait corresponding to the empty `IsfObject` Java interface.
pub trait IsfObject {}

pub mod isf_data_type_null;
pub mod isf_linux_program;

pub use isf_data_type_null::IsfDataTypeNull;
pub use isf_linux_program::IsfLinuxProgram;
