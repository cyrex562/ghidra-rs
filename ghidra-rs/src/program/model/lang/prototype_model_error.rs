//! Port of `ghidra.program.model.lang.PrototypeModelError`.
//!
//! A `PrototypeModel` cloned from another, so that it acts as a placeholder after the user has
//! changed or deleted the original model: it behaves exactly like its copy source but reports
//! [`is_error_placeholder`](PrototypeModel::is_error_placeholder) `true`. In Java this is a
//! subclass created through the alias copy constructor; here it is a [`PrototypeModel`] value of
//! the `ErrorPlaceholder` kind (see that module's docs).

use std::sync::Arc;

use crate::program::model::lang::prototype_model::{ModelKind, PrototypeModel};

impl PrototypeModel {
    /// A placeholder named `name` that behaves like `copy_model`.
    ///
    /// Port of `PrototypeModelError(String, PrototypeModel)`.
    pub fn new_error_placeholder(name: impl Into<String>, copy_model: &Arc<PrototypeModel>) -> PrototypeModel {
        let mut model = PrototypeModel::new_alias(name, copy_model);
        model.kind = ModelKind::ErrorPlaceholder;
        model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::compiler_spec::CALLING_CONVENTION_THISCALL;
    use crate::program::model::lang::cspec_test_support::{parser, TestCompilerSpec};
    use crate::program::model::pcode::ids::{ATTRIB_NAME, ATTRIB_PARENT, ELEM_MODELALIAS};
    use crate::program::model::pcode::Encoder;

    fn stdcall() -> Arc<PrototypeModel> {
        let mut m = PrototypeModel::new();
        m.restore_xml(
            &mut parser(
                r#"<prototype name="__stdcall" extrapop="4" stackshift="4">
                     <input><pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack"/></pentry></input>
                     <output><pentry minsize="1" maxsize="4"><register name="EAX"/></pentry></output>
                     <unaffected><register name="RBX"/></unaffected>
                   </prototype>"#,
            ),
            &TestCompilerSpec::x86_64(),
            None,
        )
        .unwrap();
        Arc::new(m)
    }

    #[test]
    fn is_error_placeholder_and_keeps_own_name() {
        let model = PrototypeModel::new_error_placeholder("bad_model", &stdcall());
        assert!(model.is_error_placeholder());
        assert!(!stdcall().is_error_placeholder());
        assert_eq!(model.get_name(), Some("bad_model".to_string()));
    }

    #[test]
    fn behaves_like_copy_model() {
        let model = PrototypeModel::new_error_placeholder("bad_model", &stdcall());
        assert_eq!(model.get_extrapop(), 4);
        assert_eq!(model.get_stackshift(), 4);
        assert_eq!(model.get_unaffected_list().len(), 1);
        assert_eq!(model.get_stack_parameter_alignment(), 4);
        assert_eq!(model.get_stack_parameter_offset(), Some(4));
        assert!(!model.is_merged());
        assert!(!model.is_program_extension());
    }

    #[test]
    fn has_this_pointer_true_when_named_thiscall() {
        assert!(!PrototypeModel::new_error_placeholder("bad_stdcall", &stdcall()).has_this_pointer());
        assert!(PrototypeModel::new_error_placeholder(CALLING_CONVENTION_THISCALL, &stdcall()).has_this_pointer());
    }

    #[test]
    fn alias_parent_is_copy_model_and_kinds_differ() {
        let parent = stdcall();
        let model = PrototypeModel::new_error_placeholder("bad_model", &parent);
        assert_eq!(model.get_alias_parent().unwrap().get_name(), Some("__stdcall".to_string()));
        // Java's getClass() check: an error placeholder is never equivalent to a plain alias.
        let alias = PrototypeModel::new_alias("bad_model", &parent);
        assert!(!model.is_equivalent(&alias));
        assert!(model.is_equivalent(&PrototypeModel::new_error_placeholder("bad_model", &parent)));
    }

    #[test]
    fn encode_writes_modelalias_with_name_and_parent() {
        #[derive(Default)]
        struct RecordingEncoder {
            opened: Vec<&'static str>,
            strings: Vec<(&'static str, String)>,
        }
        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                self.opened.push(elem_id.name);
                Ok(())
            }
            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                Ok(())
            }
            fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: bool) -> std::io::Result<()> {
                Ok(())
            }
            fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: i64) -> std::io::Result<()> {
                Ok(())
            }
            fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: u64) -> std::io::Result<()> {
                Ok(())
            }
            fn write_string(&mut self, attrib_id: crate::program::model::pcode::ids::AttributeId, val: &str) -> std::io::Result<()> {
                self.strings.push((attrib_id.name, val.to_string()));
                Ok(())
            }
            fn write_string_indexed(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _index: i32,
                _val: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_space(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _spc: &AddressSpace) -> std::io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _index: i32,
                _name: &str,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode(
                &mut self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
                _opcode: crate::decompiler::opcodes::op_code::OpCode,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> std::io::Result<()> {
                Ok(())
            }
        }

        let model = PrototypeModel::new_error_placeholder("bad_stdcall", &stdcall());
        let mut encoder = RecordingEncoder::default();
        model.encode(&mut encoder, None).unwrap();
        assert_eq!(encoder.opened, vec![ELEM_MODELALIAS.name]);
        assert!(encoder.strings.contains(&(ATTRIB_NAME.name, "bad_stdcall".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_PARENT.name, "__stdcall".to_string())));
    }
}
