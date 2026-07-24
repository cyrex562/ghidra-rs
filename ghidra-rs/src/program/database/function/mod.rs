pub mod function_adapter;
pub mod function_tag_adapter;
pub mod overlapping_function_exception;

pub use function_adapter::{
    get_signature_source_flag_bits, FunctionAdapter, TranslatedRecordIterator,
    CALLING_CONVENTION_ID_COL, FUNCTION_CUSTOM_PARAM_STORAGE_FLAG, FUNCTION_FLAGS_COL,
    FUNCTION_INLINE_FLAG, FUNCTION_NO_RETURN_FLAG, FUNCTION_SIGNATURE_SOURCE,
    FUNCTION_SIGNATURE_SOURCE_SHIFT, FUNCTION_VARARG_FLAG, RETURN_DATA_TYPE_ID_COL,
    RETURN_STORAGE_COL, STACK_LOCAL_SIZE_COL, STACK_PURGE_COL, STACK_RETURN_OFFSET_COL,
};
pub use function_tag_adapter::{FunctionTagAdapter, COMMENT_COL, NAME_COL};
pub use overlapping_function_exception::OverlappingFunctionException;
