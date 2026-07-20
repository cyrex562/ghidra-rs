use crate::program::model::address::Address;
use crate::program::seam_stubs::{CodeBlock, FlowType};

/// A `CodeBlockReference` represents the flow from one [`CodeBlock`] to another. Flow consists
/// of:
/// - The source and destination `CodeBlock`s
/// - The type of flow (JMP, CALL, Fallthrough, etc.)
/// - The referent - the instruction's address in the source block that causes the flow
/// - The reference - the address in the destination block that is flowed to
///
/// Port of `ghidra.program.model.block.CodeBlockReference`.
pub trait CodeBlockReference {
    /// Returns the Source Block address.
    /// The source address should only occur in one block.
    fn get_source_address(&self) -> Address;

    /// Returns the Destination Block address.
    /// The destination address should only occur in one block.
    fn get_destination_address(&self) -> Address;

    /// Returns the type of flow from the Source to the Destination `CodeBlock`.
    fn get_flow_type(&self) -> Box<dyn FlowType>;

    /// Returns the address in the Destination block that is referenced by the Source block.
    fn get_reference(&self) -> Address;

    /// Returns the address of the instruction in the Source Block that refers to the
    /// Destination block.
    fn get_referent(&self) -> Address;

    /// Returns the Destination `CodeBlock`.
    fn get_destination_block(&self) -> Box<dyn CodeBlock>;

    /// Returns the Source `CodeBlock`.
    fn get_source_block(&self) -> Box<dyn CodeBlock>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct MockCodeBlock;

    impl CodeBlock for MockCodeBlock {}

    struct MockFlowType;

    impl FlowType for MockFlowType {}

    /// A mock unconditional-jump reference from one address to another, proving
    /// `CodeBlockReference` is object-safe and that its accessors round-trip real addresses.
    struct JumpCodeBlockReference {
        source: Address,
        destination: Address,
    }

    impl CodeBlockReference for JumpCodeBlockReference {
        fn get_source_address(&self) -> Address {
            self.source.clone()
        }

        fn get_destination_address(&self) -> Address {
            self.destination.clone()
        }

        fn get_flow_type(&self) -> Box<dyn FlowType> {
            Box::new(MockFlowType)
        }

        fn get_reference(&self) -> Address {
            self.destination.clone()
        }

        fn get_referent(&self) -> Address {
            self.source.clone()
        }

        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            Box::new(MockCodeBlock)
        }

        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            Box::new(MockCodeBlock)
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn accessors_reflect_source_and_destination_addresses() {
        let space = test_space();
        let source = Address::new(space.clone(), 0x400000);
        let destination = Address::new(space, 0x400100);

        let reference: Box<dyn CodeBlockReference> = Box::new(JumpCodeBlockReference {
            source: source.clone(),
            destination: destination.clone(),
        });

        assert_eq!(reference.get_source_address().offset(), source.offset());
        assert_eq!(
            reference.get_destination_address().offset(),
            destination.offset()
        );
        assert_eq!(reference.get_referent().offset(), source.offset());
        assert_eq!(reference.get_reference().offset(), destination.offset());
    }
}
