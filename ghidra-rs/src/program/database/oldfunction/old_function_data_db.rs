//! Port of `ghidra.program.database.oldfunction.OldFunctionDataDB` as a trait (cycle cut-point).
//!
//! The Java class is package-private and is constructed *by* `OldFunctionManager`
//! (`OldFunctionManager.getFunction(DBRecord)` builds `new OldFunctionDataDB(this, addrMap, rec,
//! null)`), while `OldFunctionDataDB` itself hands `this` straight back to a freshly-constructed
//! `OldStackFrameDB(this)` and exposes a package-private `getFunctionManager()` used by that same
//! `OldStackFrameDB` and by `OldFunctionManager`'s own upgrade pass. That three-way mutual
//! construction/reference is what makes this class a cycle cut-point, mirroring the same
//! `FunctionManagerDB`/`FunctionDB` relationship captured by
//! [`FunctionDb`](crate::program::database::function::FunctionDb).
//!
//! Neither `OldFunctionManager` nor `OldStackFrameDB` is ported yet. `OldFunctionManager` is
//! referenced here only as this type's `getFunctionManager()` return value (never called through
//! by this trait's own default methods), so it gets a bare marker placeholder,
//! [`OldFunctionManager`](crate::program::seam_stubs::OldFunctionManager), in `seam_stubs.rs`.
//! `OldStackFrameDB` needs no placeholder at all: `OldStackFrameDB implements StackFrame`, and
//! `getStackFrame()` is this type's only reference to it, so that method is modeled directly in
//! terms of the already-ported [`StackFrame`] trait object.
//!
//! Mapped over directly as required methods (each backed by real, non-trivial logic in the DB
//! -- record decoding, adapter lookups, register/stack parameter merging -- that a concrete
//! implementor must supply): [`get_address_map`](OldFunctionDataDB::get_address_map),
//! [`get_function_manager`](OldFunctionDataDB::get_function_manager),
//! [`get_program`](OldFunctionDataDB::get_program),
//! [`get_comment`](OldFunctionDataDB::get_comment),
//! [`get_repeatable_comment`](OldFunctionDataDB::get_repeatable_comment),
//! [`get_entry_point`](OldFunctionDataDB::get_entry_point),
//! [`get_body`](OldFunctionDataDB::get_body),
//! [`get_return_type`](OldFunctionDataDB::get_return_type),
//! [`get_stack_frame`](OldFunctionDataDB::get_stack_frame),
//! [`get_stack_depth_change`](OldFunctionDataDB::get_stack_depth_change) (`getStackPurgeSize`'s
//! doc comment, despite naming the trait method after the field it actually reads,
//! `STACK_DEPTH_COL`), [`get_stack_param_offset`](OldFunctionDataDB::get_stack_param_offset),
//! [`get_stack_return_offset`](OldFunctionDataDB::get_stack_return_offset),
//! [`get_stack_local_size`](OldFunctionDataDB::get_stack_local_size),
//! [`get_parameters`](OldFunctionDataDB::get_parameters), and
//! [`get_key`](OldFunctionDataDB::get_key).
//!
//! Given default implementations, since each is a pure algorithm over already-required state
//! (the same treatment [`FunctionDb`](crate::program::database::function::FunctionDb) gives
//! `updateSignatureSourceAfterVariableChange`/`getInferredSignatureSource`):
//! [`get_comment_as_array`](OldFunctionDataDB::get_comment_as_array) and
//! [`get_repeatable_comment_as_array`](OldFunctionDataDB::get_repeatable_comment_as_array)
//! (`StringUtilities.toLines`, reimplemented inline as a private `\n`-split helper since no
//! Rust port of that helper exists yet) and
//! [`is_stack_depth_valid`](OldFunctionDataDB::is_stack_depth_valid) (`> 0xffffff` check).
//!
//! Left out of this port:
//! - The constructor, and the private `loadRegisterParameterList`/`getRegisterParameter` helpers
//!   it indirectly sets up: these are implementation details of how a concrete DB-backed
//!   implementor builds its cached register-parameter list and `OldStackFrameDB`, not API another
//!   type calls; their externally-visible effect is folded into the required
//!   [`get_parameters`](OldFunctionDataDB::get_parameters) method.
//! - The private `OldFunctionParameter` inner class (a trivial `ParameterImpl` subclass adding no
//!   behavior beyond forwarding its constructor args): a concrete `get_parameters` implementation
//!   can build ordinary [`Parameter`] trait objects directly, the same way
//!   [`DatabaseVariableImpl`](crate::program::seam_stubs::DatabaseVariableImpl) already stands in
//!   for the sibling `FunctionDB`-package `ParameterImpl`/`ReturnParameterImpl`/`LocalVariableImpl`
//!   trio.
//! - `equals`/`hashCode`/`toString`: Rust has no `Object` identity contract to satisfy.

use std::sync::Arc;

use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{Parameter, Program, StackFrame};
use crate::program::seam_stubs::OldFunctionManager;

/// In-memory representation of an old (pre-migration) function, read from the pre-2.2 function
/// tables.
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionDataDB`. See the module docs for what
/// was intentionally left out (the constructor/private helpers and the trivial
/// `OldFunctionParameter` inner class) and which methods were given pure-algorithm default
/// bodies.
pub trait OldFunctionDataDB {
    /// Gets the map used to convert addresses to longs and longs to addresses.
    ///
    /// Stands in for the package-private `OldFunctionDataDB.getAddressMap()`.
    fn get_address_map(&self) -> &dyn AddressMap;

    /// Gets the function manager which owns this old function.
    ///
    /// Stands in for the package-private `OldFunctionDataDB.getFunctionManager()`.
    fn get_function_manager(&self) -> Arc<dyn OldFunctionManager>;

    /// Stands in for `OldFunctionDataDB.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Stands in for `OldFunctionDataDB.getComment()`.
    fn get_comment(&self) -> String;

    /// Stands in for `OldFunctionDataDB.getCommentAsArray()`.
    fn get_comment_as_array(&self) -> Vec<String> {
        split_into_lines(&self.get_comment())
    }

    /// Stands in for `OldFunctionDataDB.getRepeatableComment()`.
    fn get_repeatable_comment(&self) -> String;

    /// Stands in for `OldFunctionDataDB.getRepeatableCommentAsArray()`.
    fn get_repeatable_comment_as_array(&self) -> Vec<String> {
        split_into_lines(&self.get_repeatable_comment())
    }

    /// Stands in for `OldFunctionDataDB.getEntryPoint()`.
    fn get_entry_point(&self) -> Address;

    /// Stands in for `OldFunctionDataDB.getBody()`.
    fn get_body(&self) -> Box<dyn AddressSetView>;

    /// Stands in for `OldFunctionDataDB.getReturnType()`.
    fn get_return_type(&self) -> Box<dyn DataType>;

    /// Stands in for `OldFunctionDataDB.getStackFrame()`.
    fn get_stack_frame(&self) -> Box<dyn StackFrame>;

    /// Stands in for `OldFunctionDataDB.getStackDepthChange()` (the `STACK_DEPTH_COL` field;
    /// despite the Java method's `@see ... getStackPurgeSize()` doc reference, it reads the same
    /// column as [`is_stack_depth_valid`](Self::is_stack_depth_valid)).
    fn get_stack_depth_change(&self) -> i32;

    /// Stands in for `OldFunctionDataDB.isStackDepthValid()`.
    fn is_stack_depth_valid(&self) -> bool {
        self.get_stack_depth_change() <= 0xffffff
    }

    /// Get the first parameter offset for the function stack frame.
    ///
    /// Stands in for the package-private `OldFunctionDataDB.getStackParamOffset()`.
    fn get_stack_param_offset(&self) -> i32;

    /// Get the return value offset for the function stack frame.
    ///
    /// Stands in for the package-private `OldFunctionDataDB.getStackReturnOffset()`.
    fn get_stack_return_offset(&self) -> i32;

    /// Get the stack space used by this function.
    ///
    /// Stands in for the package-private `OldFunctionDataDB.getStackLocalSize()`.
    fn get_stack_local_size(&self) -> i32;

    /// Stands in for `OldFunctionDataDB.getParameters()`: the merged list of register parameters
    /// (loaded from the register variable adapter) followed by stack parameters (from
    /// [`get_stack_frame`](Self::get_stack_frame)).
    fn get_parameters(&self) -> Vec<Box<dyn Parameter>>;

    /// Stands in for `OldFunctionDataDB.getKey()`.
    fn get_key(&self) -> i64;
}

/// Stands in for `StringUtilities.toLines(String)` (default `preserveTokens = true` overload):
/// splits `s` into lines on `\n`, returning an empty list for an empty string.
fn split_into_lines(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('\n').map(str::to_string).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::{Function, Variable};
    use crate::program::model::symbol::SourceType;
    use crate::program::seam_stubs::{PlaceholderDataType, PlaceholderVariableStorage, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use std::cmp::Ordering;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockOldFunctionManager;
    impl OldFunctionManager for MockOldFunctionManager {}

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// Minimal [`Parameter`] used by [`MockOldFunctionDataDB::get_parameters`], mirroring the
    /// Java `OldFunctionParameter`'s shape (name, ordinal, data type, storage).
    struct MockParameter {
        name: String,
        ordinal: i32,
    }

    impl Variable for MockParameter {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            Some(self.name.clone())
        }
        fn get_length(&self) -> i32 {
            0
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(
            &mut self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            Some(Box::new(PlaceholderVariableStorage))
        }
        fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            true
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(
            &self,
        ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
                "not a stack variable".to_string(),
            ))
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            true
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }
        fn is_equivalent(&self, other: &dyn Variable) -> bool {
            self.get_name() == other.get_name()
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(
            &self,
        ) -> Option<crate::program::model::listing::AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }
    }

    /// A minimal `OldFunctionDataDB`, exercising object-safety plus the comment-splitting,
    /// stack-depth-validity, and register/stack parameter merging behavior described by the Java
    /// class.
    struct MockOldFunctionDataDB {
        comment: String,
        repeatable_comment: String,
        stack_depth_change: i32,
        register_params: Vec<String>,
        stack_params: Vec<String>,
    }

    impl OldFunctionDataDB for MockOldFunctionDataDB {
        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }

        fn get_function_manager(&self) -> Arc<dyn OldFunctionManager> {
            Arc::new(MockOldFunctionManager)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_comment(&self) -> String {
            self.comment.clone()
        }

        fn get_repeatable_comment(&self) -> String {
            self.repeatable_comment.clone()
        }

        fn get_entry_point(&self) -> Address {
            mock_address(0x1000)
        }

        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("mock does not exercise get_stack_frame")
        }

        fn get_stack_depth_change(&self) -> i32 {
            self.stack_depth_change
        }

        fn get_stack_param_offset(&self) -> i32 {
            -4
        }

        fn get_stack_return_offset(&self) -> i32 {
            0
        }

        fn get_stack_local_size(&self) -> i32 {
            16
        }

        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            let mut ordinal = 0;
            let mut params: Vec<Box<dyn Parameter>> = Vec::new();
            for name in &self.register_params {
                params.push(Box::new(MockParameter {
                    name: name.clone(),
                    ordinal,
                }));
                ordinal += 1;
            }
            for name in &self.stack_params {
                params.push(Box::new(MockParameter {
                    name: name.clone(),
                    ordinal,
                }));
                ordinal += 1;
            }
            params
        }

        fn get_key(&self) -> i64 {
            42
        }
    }

    #[test]
    fn object_safe_and_splits_comments_into_lines() {
        let func: Box<dyn OldFunctionDataDB> = Box::new(MockOldFunctionDataDB {
            comment: "line one\nline two\nline three".to_string(),
            repeatable_comment: String::new(),
            stack_depth_change: 0,
            register_params: Vec::new(),
            stack_params: Vec::new(),
        });

        assert_eq!(
            func.get_comment_as_array(),
            vec!["line one", "line two", "line three"]
        );
        assert!(func.get_repeatable_comment_as_array().is_empty());
        assert_eq!(func.get_key(), 42);
    }

    #[test]
    fn stack_depth_validity_matches_java_threshold() {
        let valid: Box<dyn OldFunctionDataDB> = Box::new(MockOldFunctionDataDB {
            comment: String::new(),
            repeatable_comment: String::new(),
            stack_depth_change: 0xffffff,
            register_params: Vec::new(),
            stack_params: Vec::new(),
        });
        assert!(valid.is_stack_depth_valid());

        let invalid: Box<dyn OldFunctionDataDB> = Box::new(MockOldFunctionDataDB {
            comment: String::new(),
            repeatable_comment: String::new(),
            stack_depth_change: 0x1000000,
            register_params: Vec::new(),
            stack_params: Vec::new(),
        });
        assert!(!invalid.is_stack_depth_valid());
    }

    #[test]
    fn parameters_merge_register_then_stack_params_in_ordinal_order() {
        let func = MockOldFunctionDataDB {
            comment: String::new(),
            repeatable_comment: String::new(),
            stack_depth_change: 0,
            register_params: vec!["r0".to_string(), "r1".to_string()],
            stack_params: vec!["local_8".to_string()],
        };

        let params = func.get_parameters();
        let names: Vec<String> = params.iter().filter_map(|p| p.get_name()).collect();
        assert_eq!(names, vec!["r0", "r1", "local_8"]);

        let ordinals: Vec<i32> = params.iter().map(|p| p.get_ordinal()).collect();
        assert_eq!(ordinals, vec![0, 1, 2]);
    }
}
