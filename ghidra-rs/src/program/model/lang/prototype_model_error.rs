//! Port of `ghidra.program.model.lang.PrototypeModelError`.
//!
//! In Java this `extends PrototypeModel`, using the copy-constructor overload
//! `PrototypeModel(String name, PrototypeModel model)`: "Create a named alias of another
//! `PrototypeModel`. All elements of the original model are copied except: 1) The name, 2) The
//! generic calling convention (which is based on name), 3) The `hasThis` property (which allows
//! `__thiscall` to alias something else), 4) The 'fact of' the model being an alias." --
//! `PrototypeModelError` itself then overrides only `isErrorPlaceholder()` to return `true`.
//!
//! [`PrototypeModel`](crate::program::model::lang::prototype_model::PrototypeModel) is ported in
//! this crate as a trait with defaulted accessors (see that module's docs for why), not a
//! concrete struct with fields to literally copy. Following this session's established
//! "`extends X`" convention (composition over inheritance), this port wraps the source model
//! (`copy_model: Arc<dyn PrototypeModel>`) and delegates every accessor that Java's copy
//! constructor actually copies field-for-field; only the handful of properties the copy
//! constructor computes fresh (`name`, `isExtension`/`is_program_extension`, `hasThis`/
//! `has_this_pointer`) or that `PrototypeModelError` itself overrides (`isErrorPlaceholder`) get
//! their own logic here. `get_alias_parent` is also overridden, since Java's copy constructor
//! always sets `compatModel = model` (the source model), so `getAliasParent()` on a
//! `PrototypeModelError` always returns `Some`, unlike the trait's `None` default.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CALLING_CONVENTION_THISCALL;
use crate::program::model::lang::input_list_type::InputListType;
use crate::program::model::lang::param_list::WithSlotRec;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ATTRIB_PARENT, ELEM_MODELALIAS};
use crate::program::model::pcode::{Encoder, Varnode};
use crate::program::seam_stubs::{ParameterPieces, PcodeInjectLibrary, PrototypePieces};

/// A [`PrototypeModel`] cloned from another, but marked as an error placeholder.
///
/// Port of `ghidra.program.model.lang.PrototypeModelError`. See the module docs for how this
/// port maps Java's copy-constructor field-copying onto delegation, given that
/// [`PrototypeModel`] is a trait here rather than a concrete base class.
pub struct PrototypeModelError {
    name: String,
    copy_model: Arc<dyn PrototypeModel>,
}

impl PrototypeModelError {
    /// Creates a named alias of `copy_model`, marked as an error placeholder.
    ///
    /// Port of `PrototypeModelError(String, PrototypeModel)`, which delegates to
    /// `PrototypeModel(String, PrototypeModel)`.
    pub fn new(name: impl Into<String>, copy_model: Arc<dyn PrototypeModel>) -> Self {
        Self { name: name.into(), copy_model }
    }
}

impl PrototypeModel for PrototypeModelError {
    fn get_name(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn get_unaffected_list(&self) -> Vec<Varnode> {
        self.copy_model.get_unaffected_list()
    }

    fn get_killed_by_call_list(&self) -> Vec<Varnode> {
        self.copy_model.get_killed_by_call_list()
    }

    fn get_likely_trash(&self) -> Vec<Varnode> {
        self.copy_model.get_likely_trash()
    }

    fn get_internal_storage(&self) -> Vec<Varnode> {
        self.copy_model.get_internal_storage()
    }

    fn get_return_address(&self) -> Option<Vec<Varnode>> {
        self.copy_model.get_return_address()
    }

    // `is_merged()` is intentionally NOT overridden: Java's `PrototypeModel.isMerged()` is a
    // hardcoded `return false`, not a copied field, and `PrototypeModelError` (like the base
    // class) doesn't override it either. The trait's own default (`false`) already matches.

    // `is_program_extension()` is intentionally NOT overridden: the copy constructor always sets
    // `isExtension = false`, which is exactly the trait's default.

    fn get_extrapop(&self) -> i32 {
        self.copy_model.get_extrapop()
    }

    fn get_stackshift(&self) -> i32 {
        self.copy_model.get_stackshift()
    }

    fn has_this_pointer(&self) -> bool {
        // Port of `hasThis = model.hasThis || name.equals(CompilerSpec.CALLING_CONVENTION_thiscall);`
        self.copy_model.has_this_pointer() || self.name == CALLING_CONVENTION_THISCALL
    }

    fn is_constructor(&self) -> bool {
        self.copy_model.is_constructor()
    }

    fn get_input_list_type(&self) -> InputListType {
        self.copy_model.get_input_list_type()
    }

    fn has_injection(&self) -> bool {
        self.copy_model.has_injection()
    }

    fn assign_parameter_storage(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        // Java's `PrototypeModelError` doesn't override `assignParameterStorage`, so it runs
        // the base class method using ITS OWN (copied) `inputParams`/`outputParams`/`hasThis`
        // fields -- which are the very same `ParamList` objects `copy_model` holds, so
        // delegating here is behaviorally equivalent for every real call site.
        //
        // TODO(port): one narrow edge case is NOT reproduced: Java's base method consults
        // `this.hasThis` (this object's own, possibly name-derived, `hasThis`) when deciding
        // whether to mark a "this" parameter, whereas delegating straight to `copy_model` here
        // uses `copy_model`'s own `has_this_pointer()`. These differ only when `name ==
        // "__thiscall"` and `copy_model.has_this_pointer()` was `false` -- an alias renaming a
        // non-thiscall model to `__thiscall`. No concrete (non-stub) `PrototypeModel` exists yet
        // in this crate to construct a test proving the divergence either way.
        self.copy_model.assign_parameter_storage(proto, dt_manager, res, add_auto_params)
    }

    fn get_storage_locations(
        &self,
        program: &dyn Program,
        data_types: &[Arc<dyn DataType>],
        add_auto_params: bool,
        is_var_args: bool,
    ) -> Vec<Box<dyn VariableStorage>> {
        self.copy_model.get_storage_locations(program, data_types, add_auto_params, is_var_args)
    }

    fn get_alias_parent(&self) -> Option<Arc<dyn PrototypeModel>> {
        // Port of `compatModel = model;` in the copy constructor, and `getAliasParent()` simply
        // returning `compatModel`: a `PrototypeModelError` is always an alias of `copy_model`.
        Some(self.copy_model.clone())
    }

    fn is_error_placeholder(&self) -> bool {
        // Port of `PrototypeModelError.isErrorPlaceholder()`: the one method this class actually
        // overrides.
        true
    }

    fn encode(
        &self,
        encoder: &mut dyn Encoder,
        _inject_library: &dyn PcodeInjectLibrary,
    ) -> std::io::Result<()> {
        // Port of `PrototypeModel.encode(Encoder, PcodeInjectLibrary)`'s `compatModel != null`
        // branch, which is unconditionally taken here since a `PrototypeModelError` always has a
        // `compatModel` (see `get_alias_parent` above): writes a `<modelalias>` element naming
        // this alias and its parent, and nothing else -- never delegating to `copy_model`'s own
        // `encode`, nor writing any parameter-list/injection detail.
        encoder.open_element(ELEM_MODELALIAS)?;
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        let parent_name = self.copy_model.get_name().unwrap_or_default();
        encoder.write_string(ATTRIB_PARENT, &parent_name)?;
        encoder.close_element(ELEM_MODELALIAS)
    }

    fn possible_input_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        self.copy_model.possible_input_param_with_slot(loc, size, res)
    }

    fn possible_output_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        self.copy_model.possible_output_param_with_slot(loc, size, res)
    }

    fn get_stack_parameter_alignment(&self) -> i32 {
        self.copy_model.get_stack_parameter_alignment()
    }

    fn get_stack_parameter_offset(&self) -> Option<i64> {
        self.copy_model.get_stack_parameter_offset()
    }

    fn get_potential_input_register_storage(&self, prog: &dyn Program) -> Vec<Box<dyn VariableStorage>> {
        self.copy_model.get_potential_input_register_storage(prog)
    }

    // `is_equivalent` is intentionally NOT overridden. Java's `PrototypeModel.isEquivalent`
    // starts with `getClass() != obj.getClass()`, a runtime-class identity check with no
    // meaningful port onto `&dyn PrototypeModel` trait objects (there is no reflection-free way
    // to ask "is this the same concrete Rust type as that trait object" here). The trait's own
    // default (`false`) is the same conservative answer the base class would give for any
    // `PrototypeModelError` compared against a model that mismatches on any of its many other
    // compared fields anyway.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A minimal `__stdcall`-like model, standing in for the "original" model an error
    /// placeholder is cloned from.
    struct StdCallModel;
    impl PrototypeModel for StdCallModel {
        fn get_name(&self) -> Option<String> {
            Some("__stdcall".to_string())
        }
        fn get_extrapop(&self) -> i32 {
            4
        }
        fn get_stackshift(&self) -> i32 {
            4
        }
        fn has_this_pointer(&self) -> bool {
            false
        }
        fn is_constructor(&self) -> bool {
            false
        }
        fn has_injection(&self) -> bool {
            true
        }
        fn get_unaffected_list(&self) -> Vec<Varnode> {
            vec![Varnode::new(mock_address(0x1000), 4)]
        }
        fn is_equivalent(&self, other: &dyn PrototypeModel) -> bool {
            self.get_name() == other.get_name()
        }
    }

    #[test]
    fn is_error_placeholder_is_always_true() {
        let model = PrototypeModelError::new("bad_model", Arc::new(StdCallModel));
        assert!(model.is_error_placeholder());
    }

    #[test]
    fn get_name_reports_own_name_not_copy_models() {
        let model = PrototypeModelError::new("bad_model", Arc::new(StdCallModel));
        assert_eq!(model.get_name(), Some("bad_model".to_string()));
    }

    #[test]
    fn delegated_accessors_report_copy_models_values() {
        let model = PrototypeModelError::new("bad_model", Arc::new(StdCallModel));
        assert_eq!(model.get_extrapop(), 4);
        assert_eq!(model.get_stackshift(), 4);
        assert!(model.has_injection());
        assert_eq!(model.get_unaffected_list().len(), 1);
    }

    #[test]
    fn has_this_pointer_delegates_when_not_thiscall() {
        let model = PrototypeModelError::new("bad_stdcall", Arc::new(StdCallModel));
        assert!(!model.has_this_pointer(), "copy model has no this pointer, and the name isn't __thiscall");
    }

    #[test]
    fn has_this_pointer_true_when_aliased_as_thiscall() {
        // Port of `hasThis = model.hasThis || name.equals(CALLING_CONVENTION_thiscall)`: even
        // though StdCallModel itself has no `this` pointer, naming the alias `__thiscall`
        // forces `has_this_pointer()` to `true`.
        let model = PrototypeModelError::new(CALLING_CONVENTION_THISCALL, Arc::new(StdCallModel));
        assert!(model.has_this_pointer());
    }

    #[test]
    fn is_program_extension_is_always_false() {
        // Port of `isExtension = false;` in the copy constructor -- this is never delegated to
        // copy_model, unconditionally false regardless of what copy_model reports.
        struct ExtensionModel;
        impl PrototypeModel for ExtensionModel {
            fn is_program_extension(&self) -> bool {
                true
            }
        }
        let model = PrototypeModelError::new("bad_model", Arc::new(ExtensionModel));
        assert!(!model.is_program_extension());
    }

    #[test]
    fn is_merged_is_always_false() {
        struct MergedModel;
        impl PrototypeModel for MergedModel {
            fn is_merged(&self) -> bool {
                true
            }
        }
        let model = PrototypeModelError::new("bad_model", Arc::new(MergedModel));
        assert!(!model.is_merged());
    }

    #[test]
    fn get_alias_parent_always_returns_copy_model() {
        let model = PrototypeModelError::new("bad_model", Arc::new(StdCallModel));
        let parent = model.get_alias_parent().expect("PrototypeModelError is always an alias");
        assert_eq!(parent.get_name(), Some("__stdcall".to_string()));
    }

    #[test]
    fn encode_writes_modelalias_with_name_and_parent() {
        #[derive(Default)]
        struct RecordingEncoder {
            opened: Vec<crate::program::model::pcode::ids::ElementId>,
            closed: Vec<crate::program::model::pcode::ids::ElementId>,
            strings: Vec<(crate::program::model::pcode::ids::AttributeId, String)>,
        }
        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                self.opened.push(elem_id);
                Ok(())
            }
            fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> std::io::Result<()> {
                self.closed.push(elem_id);
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
                self.strings.push((attrib_id, val.to_string()));
                Ok(())
            }
            fn write_string_indexed(
                &mut self,
                attrib_id: crate::program::model::pcode::ids::AttributeId,
                index: i32,
                val: &str,
            ) -> std::io::Result<()> {
                self.strings.push((attrib_id, format!("[{index}]{val}")));
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

        struct MockPcodeInjectLibrary;
        impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

        let model = PrototypeModelError::new("bad_stdcall", Arc::new(StdCallModel));
        let mut encoder = RecordingEncoder::default();
        model.encode(&mut encoder, &MockPcodeInjectLibrary).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_MODELALIAS]);
        assert_eq!(encoder.closed, vec![ELEM_MODELALIAS]);
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "bad_stdcall".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_PARENT, "__stdcall".to_string())));
    }

    #[test]
    fn usable_as_trait_object() {
        let models: Vec<Box<dyn PrototypeModel>> = vec![
            Box::new(PrototypeModelError::new("bad_model", Arc::new(StdCallModel) as Arc<dyn PrototypeModel>)),
        ];
        assert!(models[0].is_error_placeholder());
        assert_eq!(models[0].get_name(), Some("bad_model".to_string()));
    }
}
