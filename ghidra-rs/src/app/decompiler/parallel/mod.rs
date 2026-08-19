pub mod parallel_decompiler;

pub use parallel_decompiler::{
    create_chunking_parallel_decompiler, decompile_functions, decompile_functions_in_address_set,
    decompile_functions_streaming, THREAD_POOL_NAME,
};
