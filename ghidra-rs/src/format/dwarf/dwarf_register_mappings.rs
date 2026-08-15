use std::collections::HashMap;
use std::fmt;

use crate::program::model::lang::register::RegisterRef;

/// Immutable mapping information between DWARF and Ghidra.
///
/// Use `DWARFRegisterMappingsManager` to get an instance for a Program's specific
/// language.
///
/// The data held in this struct is read from DWARF register mapping information contained
/// in xml files referenced from the language *.ldefs file in an
/// `<external_name tool="DWARF.register.mapping.file" name="register_mapping_filename_here"/>`
///
/// The format is:
/// ```xml
/// <dwarf>
///   <register_mappings>
///       <!-- Simple single mapping: -->
///       <!-- NN == dwarf register number -->
///       <!-- RegName == Ghidra register name string -->
///       <!-- <register_mapping dwarf="NN" ghidra="RegName" /> -->
///
///       <!-- Example: -->
///     <register_mapping dwarf="0" ghidra="r0" />
///
///       <!-- Single mapping specifying stack pointer: -->
///       <!-- NN == dwarf register number -->
///       <!-- RegName == Ghidra register name string -->
///       <!-- <register_mapping dwarf="NN" ghidra="RegName" stackpointer="true"/> -->
///
///       <!-- Example: -->
///     <register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/>
///
///       <!-- Multiple mapping: -->
///       <!-- NN == dwarf register number -->
///       <!-- XX == number of times to repeat -->
///       <!-- RegNameYY == Ghidra register name string with a mandatory integer suffix -->
///       <!-- <register_mapping dwarf="NN" ghidra="RegNameYY" auto_count="XX"/> -->
///
///       <!-- Example, creates mapping from 0..12 to r0..r12: -->
///     <register_mapping dwarf="0" ghidra="r0" auto_count="12"/>
///
///       <!-- Example, creates mapping from 17..32 to XMM0..XMM15: -->
///     <register_mapping dwarf="17" ghidra="XMM0" auto_count="16"/>
///
///   </register_mappings>
///
///     <!-- Call Frame CFA Value: -->
///   <call_frame_cfa value="NN"/>
///
///     <!-- Use Formal Parameter Storage toggle: -->
///   <use_formal_parameter_storage/>
/// </dwarf>
/// ```
pub struct DWARFRegisterMappings {
    /// Maps DWARF register number to Ghidra architecture registers.
    dwarf_register_map: HashMap<i32, RegisterRef>,
    call_frame_cfa: Option<i32>,
    stack_pointer_index: i32,
    use_formal_parameter_storage: bool,
    stack_frame_register: Option<RegisterRef>,
    stack_frame_register_offset: i32,
}

impl DWARFRegisterMappings {
    pub fn new(
        regmap: HashMap<i32, RegisterRef>,
        call_frame_cfa: Option<i32>,
        stack_pointer_index: i32,
        stack_frame_register: Option<RegisterRef>,
        stack_frame_register_offset: i32,
        use_fps: bool,
    ) -> Self {
        Self {
            dwarf_register_map: regmap,
            call_frame_cfa,
            stack_pointer_index,
            stack_frame_register,
            use_formal_parameter_storage: use_fps,
            stack_frame_register_offset,
        }
    }

    /// Mirrors the Java `DWARFRegisterMappings.DUMMY` static instance.
    pub fn dummy() -> Self {
        Self::new(HashMap::new(), None, -1, None, 0, false)
    }

    pub fn ghidra_reg(&self, dwarf_reg_num: i32) -> Option<RegisterRef> {
        self.dwarf_register_map.get(&dwarf_reg_num).cloned()
    }

    /// 'Static' value for a function's CFA value (instead of trying to extract it from the
    /// func's CIE metadata).
    ///
    /// # Panics
    /// Panics if there is no static CFA, mirroring the Java `Integer` auto-unboxing NPE.
    pub fn call_frame_cfa(&self) -> i32 {
        self.call_frame_cfa.unwrap()
    }

    pub fn has_static_cfa(&self) -> bool {
        self.call_frame_cfa.is_some()
    }

    pub fn dwarf_stack_pointer_reg_num(&self) -> i32 {
        self.stack_pointer_index
    }

    pub fn stack_register(&self) -> Option<RegisterRef> {
        if self.stack_pointer_index != -1 {
            self.ghidra_reg(self.stack_pointer_index)
        } else {
            None
        }
    }

    pub fn stack_frame_register(&self) -> Option<RegisterRef> {
        self.stack_frame_register.clone()
    }

    pub fn stack_frame_register_offset(&self) -> i32 {
        self.stack_frame_register_offset
    }

    pub fn is_use_formal_parameter_storage(&self) -> bool {
        self.use_formal_parameter_storage
    }
}

impl fmt::Display for DWARFRegisterMappings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DWARFRegisterMappings [dwarfRegisterMap={:?}, callFrameCFA={:?}, stackPointerIndex={}, useFormalParameterStorage={}]",
            self.dwarf_register_map, self.call_frame_cfa, self.stack_pointer_index, self.use_formal_parameter_storage
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;

    fn register_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn make_register(name: &str) -> RegisterRef {
        let space = register_space();
        Register::new(name, "", space.address(0x0), 4, false, Register::TYPE_NONE)
    }

    #[test]
    fn dummy_has_no_mappings_and_no_static_cfa() {
        let dummy = DWARFRegisterMappings::dummy();
        assert!(!dummy.has_static_cfa());
        assert_eq!(dummy.dwarf_stack_pointer_reg_num(), -1);
        assert!(dummy.stack_register().is_none());
        assert!(dummy.stack_frame_register().is_none());
        assert_eq!(dummy.stack_frame_register_offset(), 0);
        assert!(!dummy.is_use_formal_parameter_storage());
        assert!(dummy.ghidra_reg(0).is_none());
    }

    #[test]
    fn ghidra_reg_looks_up_by_dwarf_number() {
        let r0 = make_register("r0");
        let mut map = HashMap::new();
        map.insert(0, r0.clone());

        let mappings = DWARFRegisterMappings::new(map, None, -1, None, 0, false);
        assert!(mappings
            .ghidra_reg(0)
            .is_some_and(|r| std::rc::Rc::ptr_eq(&r, &r0)));
        assert!(mappings.ghidra_reg(1).is_none());
    }

    #[test]
    fn stack_register_resolves_via_stack_pointer_index() {
        let esp = make_register("ESP");
        let mut map = HashMap::new();
        map.insert(4, esp.clone());

        let mappings = DWARFRegisterMappings::new(map, None, 4, None, 0, false);
        assert!(mappings
            .stack_register()
            .is_some_and(|r| std::rc::Rc::ptr_eq(&r, &esp)));
    }

    #[test]
    fn stack_register_is_none_when_no_stack_pointer_index() {
        let mappings = DWARFRegisterMappings::new(HashMap::new(), None, -1, None, 0, false);
        assert!(mappings.stack_register().is_none());
    }

    #[test]
    fn call_frame_cfa_reports_static_value() {
        let mappings = DWARFRegisterMappings::new(HashMap::new(), Some(16), -1, None, 0, false);
        assert!(mappings.has_static_cfa());
        assert_eq!(mappings.call_frame_cfa(), 16);
    }

    #[test]
    #[should_panic]
    fn call_frame_cfa_panics_when_not_static() {
        let mappings = DWARFRegisterMappings::dummy();
        mappings.call_frame_cfa();
    }

    #[test]
    fn stack_frame_register_and_offset_round_trip() {
        let ebp = make_register("EBP");
        let mappings =
            DWARFRegisterMappings::new(HashMap::new(), None, -1, Some(ebp.clone()), 8, true);
        assert!(mappings
            .stack_frame_register()
            .is_some_and(|r| std::rc::Rc::ptr_eq(&r, &ebp)));
        assert_eq!(mappings.stack_frame_register_offset(), 8);
        assert!(mappings.is_use_formal_parameter_storage());
    }
}
