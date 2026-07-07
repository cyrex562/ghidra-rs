pub mod console_api_native;
pub mod job_api_native;

pub use console_api_native::{
    Bool, Coord, DWord, FALSE, HResult, ProcThreadAttributeList, ProcessInformation,
    SecurityAttributes, StartupInfoEx, StartupInfoW, ULong, ULongLong,
};
