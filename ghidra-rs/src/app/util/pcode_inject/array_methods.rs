//! Port of `ghidra.app.util.pcodeInject.ArrayMethods`.
//!
//! Utility functions for generating pcode for the `multianewarray` operation, which creates new
//! multi-dimensional arrays. The `newarray` operation, which creates arrays of primitive types,
//! does not reference the constant pool and does not require pcode injection (see
//! `ConstantPoolJava::get_record`).
//!
//! Java's version is a final class of statics (private constructor that throws), so it is ported
//! as a plain module of `pub const`s and `pub fn`s rather than a zero-instance struct, per this
//! crate's convention for statics holders.

use crate::app::seam_stubs::{constant_pool_java, descriptor_decoder, PcodeOpEmitter};
use crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava;
use crate::format::javaclass::java_class_constants::{
    T_BOOLEAN, T_BYTE, T_CHAR, T_DOUBLE, T_FLOAT, T_INT, T_LONG, T_SHORT,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

const ARRAY_REF: &str = "arrayref";
const CLASS_NAME: &str = "className";
const DIMENSION: &str = "dim";
const MULTIANEWARRAY: &str = "multianewarrayOp";
const PROCESS_ADDITIONAL_DIMENSIONS: &str = "multianewarrayProcessAdditionalDimensionsOp";
const MAX_PCODE_OP_ARGS: i32 = 7;

/// Emits pcode for the multianewarray op, which is used to create new multi-dimensional arrays.
/// It is modeled with two black-box pcode ops: `multianewarrayOp` and
/// `multianewarrayProcessAdditionalDimensionsOp`. The second op is needed because pcode
/// operations are limited to 8 input parameters, whereas multianewarray takes between 1 and 256
/// parameters.
///
/// The first argument to `multianewarrayOp` is a reference to the class of the new array. The
/// remaining seven arguments are array dimensions. Additional array dimensions are consumed from
/// the stack with calls to `multianewarrayProcessAdditionalDimensionsOp`, which takes a reference
/// returned by `multianewarrayOp` as its first argument and a dimension as its second argument.
///
/// `constant_pool` is unused, mirroring the Java original (`constantPool` is an unread parameter
/// there too).
pub fn get_pcode_for_multi_a_new_array(
    p_code: &impl PcodeOpEmitter,
    constant_pool_index: i32,
    _constant_pool: &[AbstractConstantPoolInfoJava],
    dimensions: i32,
) {
    // pop all of the dimensions off the stack
    for i in (1..=dimensions).rev() {
        p_code.emit_pop_cat1_value(&format!("{DIMENSION}{i}"));
    }

    p_code.emit_assign_varnode_from_pcode_op_call(
        CLASS_NAME,
        4,
        constant_pool_java::CPOOL_OP,
        &[
            "0".to_string(),
            constant_pool_index.to_string(),
            constant_pool_java::CPOOL_MULTIANEWARRAY.to_string(),
        ],
    );

    // The Java original builds a `multianewarrayOpArgs` array here (sized to the dimension
    // count, `-1` slot reserved for the class reference) but never passes it to the call below --
    // the call always hardcodes "dim1"/"dim2" regardless of `dimensions`. That dead computation
    // is dropped here; the emitted pcode (which is all that's observable) is unaffected.
    p_code.emit_assign_varnode_from_pcode_op_call(
        ARRAY_REF,
        4,
        MULTIANEWARRAY,
        &[CLASS_NAME.to_string(), "dim1".to_string(), "dim2".to_string()],
    );

    // consume any additional arguments
    for i in MAX_PCODE_OP_ARGS..=dimensions {
        p_code.emit_void_pcode_op_call(
            PROCESS_ADDITIONAL_DIMENSIONS,
            &[ARRAY_REF.to_string(), format!("{DIMENSION}{i}")],
        );
    }

    p_code.emit_push_cat1_value(ARRAY_REF);
}

/// The array type codes can be found in the JVM documentation for the `newarray` instruction.
///
/// # Panics
/// Panics if `code` is not one of the `T_*` primitive array type codes, mirroring Java's
/// `IllegalArgumentException`.
pub fn get_primitive_array_token(code: i32) -> &'static str {
    match u8::try_from(code).ok() {
        Some(T_BOOLEAN) => "boolean",
        Some(T_CHAR) => "char",
        Some(T_FLOAT) => "float",
        Some(T_DOUBLE) => "double",
        Some(T_BYTE) => "byte",
        Some(T_SHORT) => "short",
        Some(T_INT) => "int",
        Some(T_LONG) => "long",
        _ => panic!("Invalid primitive type code: {code}"),
    }
}

/// # Panics
/// Panics if `i` is not one of the `T_*` primitive array type codes, mirroring Java's
/// `IllegalArgumentException`.
pub fn get_array_base_type(i: i32, dt_manager: &dyn DataTypeManager) -> Box<dyn DataType> {
    let primitive_type = match u8::try_from(i).ok() {
        Some(T_BOOLEAN) => "Z",
        Some(T_CHAR) => "C",
        Some(T_FLOAT) => "F",
        Some(T_DOUBLE) => "D",
        Some(T_BYTE) => "B",
        Some(T_SHORT) => "S",
        Some(T_INT) => "I",
        Some(T_LONG) => "J",
        _ => panic!("Invalid primitive type code: {i}"),
    };
    descriptor_decoder::get_data_type_of_descriptor(primitive_type, dt_manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingEmitter {
        calls: Mutex<Vec<String>>,
    }

    impl PcodeOpEmitter for RecordingEmitter {
        fn emit_push_cat1_value(&self, value_name: &str) {
            self.calls.lock().unwrap().push(format!("push {value_name}"));
        }

        fn emit_pop_cat1_value(&self, dest_name: &str) {
            self.calls.lock().unwrap().push(format!("pop {dest_name}"));
        }

        fn emit_assign_varnode_from_pcode_op_call(
            &self,
            varnode_name: &str,
            size: i32,
            pcodeop: &str,
            args: &[String],
        ) {
            self.calls.lock().unwrap().push(format!(
                "assign {varnode_name}:{size} = {pcodeop}({})",
                args.join(", ")
            ));
        }

        fn emit_void_pcode_op_call(&self, pcodeop: &str, args: &[String]) {
            self.calls.lock().unwrap().push(format!("call {pcodeop}({})", args.join(", ")));
        }
    }

    #[test]
    fn get_primitive_array_token_matches_jvm_newarray_codes() {
        assert_eq!(get_primitive_array_token(T_BOOLEAN as i32), "boolean");
        assert_eq!(get_primitive_array_token(T_CHAR as i32), "char");
        assert_eq!(get_primitive_array_token(T_FLOAT as i32), "float");
        assert_eq!(get_primitive_array_token(T_DOUBLE as i32), "double");
        assert_eq!(get_primitive_array_token(T_BYTE as i32), "byte");
        assert_eq!(get_primitive_array_token(T_SHORT as i32), "short");
        assert_eq!(get_primitive_array_token(T_INT as i32), "int");
        assert_eq!(get_primitive_array_token(T_LONG as i32), "long");
    }

    #[test]
    #[should_panic(expected = "Invalid primitive type code: 99")]
    fn get_primitive_array_token_rejects_unknown_code() {
        get_primitive_array_token(99);
    }

    #[test]
    fn get_pcode_for_multi_a_new_array_two_dimensions_matches_java_sequence() {
        let emitter = RecordingEmitter::default();
        get_pcode_for_multi_a_new_array(&emitter, 5, &[], 2);

        assert_eq!(
            emitter.calls.into_inner().unwrap(),
            vec![
                "pop dim2".to_string(),
                "pop dim1".to_string(),
                "assign className:4 = cpool(0, 5, 12)".to_string(),
                "assign arrayref:4 = multianewarrayOp(className, dim1, dim2)".to_string(),
                "push arrayref".to_string(),
            ]
        );
    }

    #[test]
    fn get_pcode_for_multi_a_new_array_beyond_max_args_emits_additional_dimension_calls() {
        let emitter = RecordingEmitter::default();
        get_pcode_for_multi_a_new_array(&emitter, 1, &[], 8);

        let calls = emitter.calls.into_inner().unwrap();
        // 8 pops, 1 class-name assign, 1 multianewarrayOp assign, 2 additional-dimension calls
        // (i = 7, 8), 1 push.
        assert_eq!(calls.len(), 13);
        assert_eq!(calls[10], "call multianewarrayProcessAdditionalDimensionsOp(arrayref, dim7)");
        assert_eq!(calls[11], "call multianewarrayProcessAdditionalDimensionsOp(arrayref, dim8)");
        assert_eq!(calls[12], "push arrayref");
    }
}
