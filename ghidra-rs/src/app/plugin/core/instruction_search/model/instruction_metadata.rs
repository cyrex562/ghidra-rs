//! Port of `ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata`.

use crate::app::seam_stubs::{MaskContainer, OperandMetadata};
use crate::program::model::address::Address;

/// Data container encapsulating all pertinent mask information about a single instruction.
///
/// In some cases, the user may have selected a set of instructions that contains data elements
/// that are technically NOT instructions, but are captured using this data structure anyway
/// (hence the private `is_instruction` boolean).
///
/// Port of `ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata`.
///
/// # Deviations from Java
///
/// * Java's `addr`/`mnemonic` fields have no value until `setAddr`/`setTextRep` is called (`null`
///   until then, tolerated by every getter); modeled as `Option<Address>`/`Option<String>` rather
///   than requiring a placeholder value up front.
/// * `MaskContainer`/`OperandMetadata` are not yet ported; `InstructionMetadata` itself never
///   calls either type's methods (only stores and returns them), so the minimal forward-reference
///   placeholders in `crate::app::seam_stubs` are used as-is -- see their own docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionMetadata {
    addr: Option<Address>,
    mnemonic: Option<String>,
    is_instruction: bool,
    mnemonic_masked: bool,
    mask_container: MaskContainer,
    operands: Vec<OperandMetadata>,
}

impl InstructionMetadata {
    /// Construct with a mask container. We always need to have a mask container, so force users
    /// to pass it in.
    ///
    /// Port of `InstructionMetadata(MaskContainer)`.
    pub fn new(mask_container: MaskContainer) -> Self {
        Self {
            addr: None,
            mnemonic: None,
            is_instruction: false,
            mnemonic_masked: false,
            mask_container,
            operands: Vec::new(),
        }
    }

    /// Java: `getMaskContainer()`.
    pub fn get_mask_container(&self) -> &MaskContainer {
        &self.mask_container
    }

    /// Java: `getAddr()`.
    pub fn get_addr(&self) -> Option<&Address> {
        self.addr.as_ref()
    }

    /// Java: `setAddr(Address)`.
    pub fn set_addr(&mut self, addr: Address) {
        self.addr = Some(addr);
    }

    /// Java: `getTextRep()`.
    pub fn get_text_rep(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Java: `setTextRep(String)`.
    pub fn set_text_rep(&mut self, text_rep: impl Into<String>) {
        self.mnemonic = Some(text_rep.into());
    }

    /// Java: `isInstruction()`.
    pub fn is_instruction(&self) -> bool {
        self.is_instruction
    }

    /// Java: `setIsInstruction(boolean)`.
    pub fn set_is_instruction(&mut self, instruction: bool) {
        self.is_instruction = instruction;
    }

    /// Java: `getOperands()`.
    pub fn get_operands(&self) -> &[OperandMetadata] {
        &self.operands
    }

    /// Java: `setOperands(List<OperandMetadata>)`.
    pub fn set_operands(&mut self, operands: Vec<OperandMetadata>) {
        self.operands = operands;
    }

    /// Java: `isMasked()`.
    pub fn is_masked(&self) -> bool {
        self.mnemonic_masked
    }

    /// Java: `setMasked(boolean)`.
    pub fn set_masked(&mut self, mask: bool) {
        self.mnemonic_masked = mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn mask_container() -> MaskContainer {
        MaskContainer::new(vec![0xFF, 0x00], vec![0x12, 0x34])
    }

    #[test]
    fn new_starts_with_no_address_no_text_and_unmasked_empty_operands() {
        let meta = InstructionMetadata::new(mask_container());

        assert_eq!(meta.get_addr(), None);
        assert_eq!(meta.get_text_rep(), None);
        assert!(!meta.is_instruction());
        assert!(!meta.is_masked());
        assert!(meta.get_operands().is_empty());
        assert_eq!(meta.get_mask_container(), &mask_container());
    }

    #[test]
    fn setters_are_visible_through_their_matching_getters() {
        let mut meta = InstructionMetadata::new(mask_container());
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x400);

        meta.set_addr(addr.clone());
        meta.set_text_rep("MOV");
        meta.set_is_instruction(true);
        meta.set_masked(true);
        let operands = vec![OperandMetadata { text_rep: Some("EAX".to_string()), ..Default::default() }];
        meta.set_operands(operands.clone());

        assert_eq!(meta.get_addr(), Some(&addr));
        assert_eq!(meta.get_text_rep(), Some("MOV"));
        assert!(meta.is_instruction());
        assert!(meta.is_masked());
        assert_eq!(meta.get_operands(), operands.as_slice());
    }

    #[test]
    fn two_instances_with_the_same_state_are_equal() {
        let mut a = InstructionMetadata::new(mask_container());
        let mut b = InstructionMetadata::new(mask_container());
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x800);

        a.set_addr(addr.clone());
        b.set_addr(addr);
        a.set_text_rep("NOP");
        b.set_text_rep("NOP");

        assert_eq!(a, b);
    }
}
