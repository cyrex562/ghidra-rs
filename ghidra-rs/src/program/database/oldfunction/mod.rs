pub mod old_function_db_adapter;
pub mod old_stack_variable_db_adapter;

pub use old_function_db_adapter::{
    OldFunctionDBAdapter, REPEATABLE_COMMENT_COL, RETURN_DATA_TYPE_ID_COL, STACK_DEPTH_COL,
    STACK_LOCAL_SIZE_COL, STACK_PARAM_OFFSET_COL, STACK_RETURN_OFFSET_COL,
};
pub use old_stack_variable_db_adapter::OldStackVariableDBAdapter;
