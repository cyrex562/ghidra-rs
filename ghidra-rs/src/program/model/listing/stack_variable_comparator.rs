use std::cmp::Ordering;

use crate::program::model::listing::Variable;

/// One side of a [`StackVariableComparator`] comparison.
///
/// Mirrors the two `Object` shapes accepted by Ghidra's `StackVariableComparator.compare`:
/// either a [`Variable`] (whose stack offset is derived from its storage) or a raw stack
/// offset `Integer`.
pub enum StackVariableOperand<'a> {
    /// A variable; its stack offset is looked up via its storage.
    Variable(&'a dyn Variable),
    /// A raw stack offset.
    Offset(i32),
}

/// Compares stack variable offsets.
///
/// Mirrors Ghidra's `StackVariableComparator`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StackVariableComparator;

impl StackVariableComparator {
    /// Returns a shared instance of a `StackVariableComparator`.
    ///
    /// The comparator is stateless, so this simply returns a new zero-sized instance rather
    /// than mirroring the Java class's lazily-initialized static field.
    pub fn get() -> Self {
        Self
    }

    /// Compares two stack variable offsets. One or both operands may be a [`Variable`] or a
    /// raw offset.
    ///
    /// Operands without a stack offset (i.e. a [`Variable`] that lacks stack storage) sort
    /// after operands with one; two such operands compare as equal.
    pub fn compare(op1: &StackVariableOperand, op2: &StackVariableOperand) -> Ordering {
        let offset1 = Self::get_stack_offset(op1);
        let offset2 = Self::get_stack_offset(op2);

        match (offset1, offset2) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(&b),
        }
    }

    fn get_stack_offset(op: &StackVariableOperand) -> Option<i32> {
        match op {
            StackVariableOperand::Variable(var) => {
                if var.has_stack_storage() {
                    var.get_last_storage_varnode()
                        .map(|varnode| varnode.get_address().offset() as i32)
                } else {
                    None
                }
            }
            StackVariableOperand::Offset(offset) => Some(*offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{
        SetVariableNameError, UnsupportedOperationError,
    };
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::VariableStorage;
    use crate::util::exception::InvalidInputException;
    use std::sync::Arc;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockVariable {
        stack_offset: Option<i32>,
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0);
        Address::new(space, offset)
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
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
            None
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn is_valid(&self) -> bool {
            true
        }

        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock"
                }
                fn get_language_id(&self) -> &str {
                    "mock:LE:32:default"
                }
            }
            Arc::new(MockProgram)
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), SetVariableNameError> {
            Ok(())
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }

        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.get_last_storage_varnode()
        }

        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.stack_offset
                .map(|offset| Varnode::new(test_address(offset as i64), 4))
        }

        fn is_stack_variable(&self) -> bool {
            self.stack_offset.is_some()
        }

        fn has_stack_storage(&self) -> bool {
            self.stack_offset.is_some()
        }

        fn is_register_variable(&self) -> bool {
            false
        }

        fn get_register(&self) -> Option<RegisterRef> {
            None
        }

        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            None
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.stack_offset
                .ok_or_else(|| UnsupportedOperationError("not a simple stack variable".to_string()))
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
            self.get_variable_storage().is_some()
        }

        fn get_first_use_offset(&self) -> i32 {
            0
        }

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }

        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    #[test]
    fn compares_two_offsets() {
        let a = StackVariableOperand::Offset(-8);
        let b = StackVariableOperand::Offset(4);
        assert_eq!(StackVariableComparator::compare(&a, &b), Ordering::Less);
        assert_eq!(StackVariableComparator::compare(&b, &a), Ordering::Greater);
        assert_eq!(StackVariableComparator::compare(&a, &a), Ordering::Equal);
    }

    #[test]
    fn compares_variable_to_offset() {
        let var = MockVariable {
            stack_offset: Some(-4),
        };
        let a = StackVariableOperand::Variable(&var);
        let b = StackVariableOperand::Offset(-8);
        assert_eq!(StackVariableComparator::compare(&a, &b), Ordering::Greater);
        assert_eq!(StackVariableComparator::compare(&b, &a), Ordering::Less);
    }

    #[test]
    fn compares_two_variables() {
        let var1 = MockVariable {
            stack_offset: Some(-4),
        };
        let var2 = MockVariable {
            stack_offset: Some(-4),
        };
        let a = StackVariableOperand::Variable(&var1);
        let b = StackVariableOperand::Variable(&var2);
        assert_eq!(StackVariableComparator::compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn variable_without_stack_storage_sorts_after_offset() {
        let var = MockVariable { stack_offset: None };
        let a = StackVariableOperand::Variable(&var);
        let b = StackVariableOperand::Offset(0);
        assert_eq!(StackVariableComparator::compare(&a, &b), Ordering::Greater);
        assert_eq!(StackVariableComparator::compare(&b, &a), Ordering::Less);
    }

    #[test]
    fn two_variables_without_stack_storage_are_equal() {
        let var1 = MockVariable { stack_offset: None };
        let var2 = MockVariable { stack_offset: None };
        let a = StackVariableOperand::Variable(&var1);
        let b = StackVariableOperand::Variable(&var2);
        assert_eq!(StackVariableComparator::compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn get_returns_stateless_instance() {
        let a = StackVariableComparator::get();
        let b = StackVariableComparator::get();
        assert_eq!(a, b);
    }
}
