pub mod method_handle_bytecode_behaviors;

pub use method_handle_bytecode_behaviors::{
    get_name, REF_GET_FIELD, REF_GET_STATIC, REF_INVOKE_INTERFACE, REF_INVOKE_SPECIAL,
    REF_INVOKE_STATIC, REF_INVOKE_VIRTUAL, REF_NEW_INVOKE_SPECIAL, REF_PUT_FIELD,
    REF_PUT_STATIC,
};
