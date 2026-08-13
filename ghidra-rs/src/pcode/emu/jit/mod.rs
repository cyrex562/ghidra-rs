pub mod alloc;
pub mod analysis;
pub mod decode;
pub mod gen;
pub mod jit_jvm_type_utils;
pub mod jit_pcode_emulator;
pub mod jit_pcode_thread;
pub mod op;
pub mod var;

pub use alloc::VarHandler;
pub use jit_jvm_type_utils::{JavaType, WildcardBound};
pub use op::{JitBoolBinOp, JitCallOtherOpIf};
pub use var::JitVar;
