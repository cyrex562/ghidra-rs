//! Port of `ghidra.program.database.code.PrototypeManager`.
//!
//! The Java type is a package-private class that maintains the DB-backed table of instruction
//! prototypes (and their original bytes/context) and an in-memory cache mapping prototypes to
//! their IDs. Its constructor, DB-schema constants, and private helpers (`init`,
//! `populatePrototypes`, `createPrototype`, `findAdapters`, `loadContextTable`, and the
//! version-upgrade routines, plus the private nested `ProtoProcessorContext` they use to
//! instantiate a prototype from a DB record) are all construction/persistence details that belong
//! with whichever type ends up owning the concrete DB-backed implementation -- this port only
//! models the package-visible instance API, as an object-safe trait. This follows the same
//! convention already used for
//! [`ProtoDBAdapter`](crate::program::database::code::ProtoDBAdapter) and
//! [`CommentHistoryAdapter`](crate::program::database::code::CommentHistoryAdapter). This trait
//! was itself selected as a dependency-cycle cut-point.

use std::io;
use std::sync::Arc;

use crate::program::model::lang::{InstructionPrototype, Language, ProcessorContextView, Register};
use crate::program::seam_stubs::{MemBuffer, PrototypeManagerProgram, RegisterValue};
use crate::util::exception::NoValueException;

/// Maintains a list of instruction prototypes and their corresponding IDs.
///
/// NOTE: the prototype ID will be negative if the prototype is in a delay slot (per the original
/// Java documentation), though the abstract API itself imposes no such constraint.
///
/// Port of `ghidra.program.database.code.PrototypeManager`. See the module docs for what was
/// intentionally left out (construction/persistence details).
pub trait PrototypeManager {
    /// Changes the language used by this manager, discarding all previously cached prototypes
    /// and DB records.
    ///
    /// Stands in for `PrototypeManager.setLanguage(Language)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn set_language(&mut self, language: Arc<dyn Language>) -> io::Result<()>;

    /// Associates this manager with its owning program, taking the program's language and
    /// (re)populating the prototype cache from it.
    ///
    /// Stands in for `PrototypeManager.setProgram(ProgramDB)`.
    fn set_program(&mut self, program: Arc<dyn PrototypeManagerProgram>);

    /// Gets the unique ID for `prototype`. If a matching prototype doesn't exist yet, this one is
    /// stored (recording `mem_buf`'s bytes and `context`'s base-context register value, if any)
    /// and given a new ID; if a matching prototype already exists, the ID already assigned to it
    /// is returned. This relies on the assumption that the language module provides a good
    /// equality check for prototypes.
    ///
    /// Stands in for `PrototypeManager.getID(InstructionPrototype, MemBuffer,
    /// ProcessorContextView)`.
    fn get_id(
        &mut self,
        prototype: Arc<dyn InstructionPrototype>,
        mem_buf: &dyn MemBuffer,
        context: &dyn ProcessorContextView,
    ) -> i32;

    /// Gets the prototype with the given ID, or `None` if not found.
    ///
    /// Stands in for `PrototypeManager.getPrototype(int)`.
    fn get_prototype(&self, proto_id: i32) -> Option<Arc<dyn InstructionPrototype>>;

    /// Discards the in-memory prototype cache and repopulates it from the database if new
    /// records have been added since the cache was last built.
    ///
    /// Stands in for `PrototypeManager.clearCache()`.
    fn clear_cache(&mut self);

    /// Gets the number of original bytes recorded for the prototype with the given ID, or `0` if
    /// not found.
    ///
    /// Stands in for `PrototypeManager.getOriginalPrototypeLength(int)`.
    fn get_original_prototype_length(&self, proto_id: i32) -> i32;

    /// Gets the originally recorded context register value for `prototype`, relative to
    /// `base_context_reg`, or `None` if no value was recorded.
    ///
    /// Stands in for `PrototypeManager.getOriginalPrototypeContext(InstructionPrototype,
    /// Register)`.
    ///
    /// # Errors
    ///
    /// Returns [`NoValueException`] if `prototype` is not known to this manager.
    fn get_original_prototype_context(
        &self,
        prototype: &dyn InstructionPrototype,
        base_context_reg: &Register,
    ) -> Result<Option<Box<dyn RegisterValue>>, NoValueException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct StoredProto {
        prototype: Arc<dyn InstructionPrototype>,
        length: i32,
        context_value: Option<i128>,
    }

    /// A minimal in-memory `PrototypeManager`, standing in for a real DB-backed implementation
    /// (which would use a `ProtoDBAdapter`); exercises the same cache semantics as the Java class
    /// (dedup by identity, negative/zero results for unknown IDs) without any DB machinery.
    struct MockPrototypeManager {
        by_id: RefCell<HashMap<i32, StoredProto>>,
        next_id: RefCell<i32>,
    }

    impl MockPrototypeManager {
        fn new() -> Self {
            MockPrototypeManager {
                by_id: RefCell::new(HashMap::new()),
                next_id: RefCell::new(0),
            }
        }
    }

    impl PrototypeManager for MockPrototypeManager {
        fn set_language(&mut self, _language: Arc<dyn Language>) -> io::Result<()> {
            self.by_id.borrow_mut().clear();
            *self.next_id.borrow_mut() = 0;
            Ok(())
        }

        fn set_program(&mut self, _program: Arc<dyn PrototypeManagerProgram>) {
            self.by_id.borrow_mut().clear();
            *self.next_id.borrow_mut() = 0;
        }

        fn get_id(
            &mut self,
            prototype: Arc<dyn InstructionPrototype>,
            mem_buf: &dyn MemBuffer,
            context: &dyn ProcessorContextView,
        ) -> i32 {
            let _ = mem_buf;
            for (id, stored) in self.by_id.borrow().iter() {
                if Arc::ptr_eq(&stored.prototype, &prototype) {
                    return *id;
                }
            }

            let id = *self.next_id.borrow();
            *self.next_id.borrow_mut() = id + 1;

            let context_value = context
                .get_base_context_register()
                .and_then(|reg| context.get_value(&reg.borrow(), false));

            let length = prototype.get_length();
            self.by_id.borrow_mut().insert(
                id,
                StoredProto {
                    prototype,
                    length,
                    context_value,
                },
            );
            id
        }

        fn get_prototype(&self, proto_id: i32) -> Option<Arc<dyn InstructionPrototype>> {
            if proto_id < 0 {
                return None;
            }
            self.by_id
                .borrow()
                .get(&proto_id)
                .map(|stored| stored.prototype.clone())
        }

        fn clear_cache(&mut self) {
            self.by_id.borrow_mut().clear();
        }

        fn get_original_prototype_length(&self, proto_id: i32) -> i32 {
            self.by_id
                .borrow()
                .get(&proto_id)
                .map(|stored| stored.length)
                .unwrap_or(0)
        }

        fn get_original_prototype_context(
            &self,
            prototype: &dyn InstructionPrototype,
            _base_context_reg: &Register,
        ) -> Result<Option<Box<dyn RegisterValue>>, NoValueException> {
            for stored in self.by_id.borrow().values() {
                if std::ptr::eq(
                    stored.prototype.as_ref() as *const dyn InstructionPrototype as *const (),
                    prototype as *const dyn InstructionPrototype as *const (),
                ) {
                    return Ok(None);
                }
            }
            Err(NoValueException::new())
        }
    }

    struct MockInstructionPrototype {
        length: i32,
        mnemonic: String,
    }

    impl InstructionPrototype for MockInstructionPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<
            Box<dyn crate::program::seam_stubs::ParserContext>,
            crate::program::model::mem::MemoryAccessException,
        > {
            unimplemented!("not exercised by this test")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &crate::program::model::address::Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<
            Box<dyn crate::program::seam_stubs::ParserContext>,
            crate::program::model::lang::instruction_prototype::GetPseudoParserContextError,
        > {
            unimplemented!("not exercised by this test")
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn crate::program::model::lang::InstructionContext) -> String {
            self.mnemonic.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_flow_type(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::FallThrough
        }

        fn get_delay_slot_depth(&self, _context: &dyn crate::program::model::lang::InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_op_type(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> i32 {
            0
        }

        fn get_fall_through(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_fall_through_offset(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> i32 {
            self.length
        }

        fn get_flows(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Vec<crate::program::model::address::Address>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::address::Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::scalar::Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_result_objects(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::PatchEncoder,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _operand_index: i32,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this test")
        }
    }

    #[test]
    fn mock_manager_is_object_safe_and_dedups_prototypes() {
        let mut manager: Box<dyn PrototypeManager> = Box::new(MockPrototypeManager::new());

        let proto_a: Arc<dyn InstructionPrototype> = Arc::new(MockInstructionPrototype {
            length: 4,
            mnemonic: "MOV".to_string(),
        });
        let proto_b: Arc<dyn InstructionPrototype> = Arc::new(MockInstructionPrototype {
            length: 2,
            mnemonic: "NOP".to_string(),
        });

        struct EmptyMemBuffer;
        impl MemBuffer for EmptyMemBuffer {
            fn get_address(&self) -> crate::program::model::address::Address {
                unimplemented!("not exercised by this test")
            }
        }

        struct EmptyProcessorContextView;
        impl ProcessorContextView for EmptyProcessorContextView {
            fn get_base_context_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
                vec![]
            }
            fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
                None
            }
            fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
                None
            }
            fn has_value(&self, _register: &Register) -> bool {
                false
            }
        }

        let mem_buf = EmptyMemBuffer;
        let context = EmptyProcessorContextView;

        let id_a = manager.get_id(proto_a.clone(), &mem_buf, &context);
        let id_a_again = manager.get_id(proto_a.clone(), &mem_buf, &context);
        assert_eq!(id_a, id_a_again, "same prototype must map to the same ID");

        let id_b = manager.get_id(proto_b.clone(), &mem_buf, &context);
        assert_ne!(id_a, id_b, "distinct prototypes must map to distinct IDs");

        assert_eq!(manager.get_original_prototype_length(id_a), 4);
        assert_eq!(manager.get_original_prototype_length(id_b), 2);
        assert_eq!(manager.get_original_prototype_length(999), 0);

        assert!(manager.get_prototype(id_a).is_some());
        assert!(manager.get_prototype(-1).is_none());
        assert!(manager.get_prototype(999).is_none());

        let space = crate::program::model::address::AddressSpace::new(
            "register",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Register,
            1,
        );
        let base_reg_ref = Register::new(
            "base",
            "base context register",
            crate::program::model::address::Address::new(space, 0),
            4,
            false,
            0,
        );
        let base_reg = base_reg_ref.borrow();
        assert!(manager
            .get_original_prototype_context(proto_a.as_ref(), &base_reg)
            .unwrap()
            .is_none());

        let unknown_proto = MockInstructionPrototype {
            length: 1,
            mnemonic: "BAD".to_string(),
        };
        assert!(manager
            .get_original_prototype_context(&unknown_proto, &base_reg)
            .is_err());

        manager.clear_cache();
        assert!(manager.get_prototype(id_a).is_none());
    }
}
