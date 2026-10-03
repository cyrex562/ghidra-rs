//! Port of `ghidra.app.util.bin.format.golang.GoParamStorageAllocator`.

use super::go_register_info::{is_int_type, GoRegisterInfo};
use super::go_register_info_manager::GoRegisterInfoManager;
use super::go_ver::GoVer;
use crate::format::dwarf::dwarf_util::is_zero_byte_data_type;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::Program;
use crate::util::seam_stubs::NumericUtilities;

const INTREG: usize = 0;
const FLOATREG: usize = 1;

/// Logic and helper for allocating storage for a function's parameters and return value.
///
/// Not threadsafe. `Clone` is Java's `clone()`: a copy of the allocation state.
#[derive(Clone)]
pub struct GoParamStorageAllocator {
    regs: [Vec<Register>; 2],
    next_reg: [usize; 2],
    callspec_info: GoRegisterInfo,
    stack_offset: i64,
    is_big_endian: bool,
    arch_description: String,
}

impl std::fmt::Debug for GoParamStorageAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |regs: &[Register]| regs.iter().map(|r| r.name().to_string()).collect::<Vec<_>>();
        f.debug_struct("GoParamStorageAllocator")
            .field("int_regs", &names(&self.regs[INTREG]))
            .field("float_regs", &names(&self.regs[FLOATREG]))
            .field("next_reg", &self.next_reg)
            .field("stack_offset", &self.stack_offset)
            .field("arch_description", &self.arch_description)
            .finish()
    }
}

impl GoParamStorageAllocator {
    /// Creates a new Go function call storage allocator for the program's language and Go
    /// version (`GoParamStorageAllocator(Program, GoVer)`); see
    /// [`GoRegisterInfoManager::get_register_info_for_lang`].
    ///
    /// Returns `None` if the program has no language.
    pub fn new(program: &dyn Program, go_version: GoVer) -> Option<Self> {
        let lang = program.get_language()?;
        let callspec_info = GoRegisterInfoManager::get_instance().get_register_info_for_lang(lang.as_ref(), go_version);
        Some(Self::from_lang(callspec_info, lang.as_ref()))
    }

    /// `GoParamStorageAllocator(GoRegisterInfo, Program)`. Returns `None` if the program has no
    /// language.
    pub fn with_register_info(callspec_info: GoRegisterInfo, program: &dyn Program) -> Option<Self> {
        let lang = program.get_language()?;
        Some(Self::from_lang(callspec_info, lang.as_ref()))
    }

    /// Creates an allocator from register info and the language's endianness / description.
    pub fn from_lang(callspec_info: GoRegisterInfo, lang: &dyn Language) -> Self {
        let desc = lang.get_language_description();
        let arch_description = format!("{}_{}", desc.get_processor().name(), desc.get_size());
        Self::from_parts(callspec_info, lang.is_big_endian(), arch_description)
    }

    /// Creates an allocator from its parts.
    pub fn from_parts(callspec_info: GoRegisterInfo, is_big_endian: bool, arch_description: String) -> Self {
        GoParamStorageAllocator {
            stack_offset: callspec_info.get_stack_initial_offset() as i64,
            regs: [
                callspec_info.get_int_registers().to_vec(),
                callspec_info.get_float_registers().to_vec(),
            ],
            next_reg: [0, 0],
            callspec_info,
            is_big_endian,
            arch_description,
        }
    }

    /// `getArchDescription()`: `"<processor>_<size>"`.
    pub fn get_arch_description(&self) -> &str {
        &self.arch_description
    }

    /// `isBigEndian()`.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// `resetRegAllocation()`.
    pub fn reset_reg_allocation(&mut self) {
        self.next_reg = [0, 0];
    }

    fn allocate_reg(&mut self, count: usize, reg_type: usize, dt: &dyn DataType, result: &mut Vec<Register>) -> bool {
        let new_next_reg = self.next_reg[reg_type] + count;
        if new_next_reg > self.regs[reg_type].len() {
            return false;
        }
        let mut remaining_size = dt.get_length();
        for reg_num in self.next_reg[reg_type]..new_next_reg {
            let reg = get_best_fit_register(&self.regs[reg_type][reg_num], remaining_size);
            remaining_size -= reg.minimum_byte_size();
            result.push(reg);
        }
        self.next_reg[reg_type] = new_next_reg;
        true
    }

    /// `setAbi0Mode()`: no registers are used for parameters.
    pub fn set_abi0_mode(&mut self) {
        self.regs = [Vec::new(), Vec::new()];
    }

    /// `isAbi0Mode()`.
    pub fn is_abi0_mode(&self) -> bool {
        self.regs[INTREG].is_empty() && self.regs[FLOATREG].is_empty()
    }

    /// Returns the integer parameter register that follows `reg`, or `None`
    /// (`getNextIntParamRegister(Register)`).
    pub fn get_next_int_param_register(&self, reg: &Register) -> Option<Register> {
        let int_regs = &self.regs[INTREG];
        (0..int_regs.len().saturating_sub(1)).find(|&i| &int_regs[i] == reg).map(|i| int_regs[i + 1].clone())
    }

    /// Returns the registers that will store the data type, marking them used
    /// (`getRegistersFor(DataType)`); see [`get_registers_for_with`](Self::get_registers_for_with).
    pub fn get_registers_for(&mut self, dt: &dyn DataType) -> Option<Vec<Register>> {
        self.get_registers_for_with(dt, true)
    }

    /// Returns the registers that will store the data type, marking them used
    /// (`getRegistersFor(DataType, boolean)`). The list is empty for a zero-length array, and
    /// `None` when the data type is not compatible with register storage (no registers are
    /// consumed then). With `allow_endian_fixups`, a multi-register result in a little endian
    /// program is reversed to match how storage varnodes are laid out.
    pub fn get_registers_for_with(&mut self, dt: &dyn DataType, allow_endian_fixups: bool) -> Option<Vec<Register>> {
        let saved = self.next_reg;
        let mut result = Vec::new();
        if !self.count_registers_for(dt, &mut result) {
            self.next_reg = saved;
            return None;
        }
        if allow_endian_fixups && !self.is_big_endian && result.len() > 1 {
            result.reverse();
        }
        Some(result)
    }

    /// Returns the stack offset for the data type, marking that stack area as used
    /// (`getStackAllocation(DataType)`).
    pub fn get_stack_allocation(&mut self, dt: &dyn DataType) -> i64 {
        if dt.is_zero_length() {
            return self.stack_offset;
        }
        self.align_stack_for(dt);
        let result = self.stack_offset;
        self.stack_offset += dt.get_length() as i64;
        result
    }

    /// `getStackOffset()`.
    pub fn get_stack_offset(&self) -> i64 {
        self.stack_offset
    }

    /// `setStackOffset(long)`.
    pub fn set_stack_offset(&mut self, new_stack_offset: i64) {
        self.stack_offset = new_stack_offset;
    }

    /// `alignStackFor(DataType)`.
    pub fn align_stack_for(&mut self, dt: &dyn DataType) {
        let alignment_size = self.callspec_info.get_alignment_for_type(dt);
        self.stack_offset = NumericUtilities::get_unsigned_aligned_value(self.stack_offset, alignment_size as i64);
    }

    /// `alignStack()`: aligns to the max alignment.
    pub fn align_stack(&mut self) {
        self.stack_offset =
            NumericUtilities::get_unsigned_aligned_value(self.stack_offset, self.callspec_info.get_max_align() as i64);
    }

    /// `getClosureContextRegister()`.
    pub fn get_closure_context_register(&self) -> Option<&Register> {
        self.callspec_info.get_closure_context_register()
    }

    fn count_registers_for(&mut self, dt: &dyn DataType, result: &mut Vec<Register>) -> bool {
        if is_zero_byte_data_type(dt) {
            return false;
        }
        if let Some(td) = dt.as_typedef() {
            let base = td.get_base_data_type();
            return self.count_registers_for_base(base.as_ref(), result);
        }
        self.count_registers_for_base(dt, result)
    }

    fn count_registers_for_base(&mut self, dt: &dyn DataType, result: &mut Vec<Register>) -> bool {
        if dt.as_pointer().is_some() || dt.is_pointer() {
            return self.allocate_reg(1, INTREG, dt, result);
        }
        if is_int_type(dt) {
            let size = dt.get_length() as i64;
            let int_reg_size = self.callspec_info.get_int_register_size() as i64;
            if size <= int_reg_size * 2 {
                let count = NumericUtilities::get_unsigned_aligned_value(size, int_reg_size) / int_reg_size;
                return self.allocate_reg(count as usize, INTREG, dt, result);
            }
        }
        if dt.is_floating_point() {
            return self.allocate_reg(1, FLOATREG, dt, result);
        }
        if let Some(array) = dt.as_array() {
            let num_elements = array.get_num_elements();
            if num_elements == 0 {
                return true;
            }
            return num_elements == 1 && self.count_registers_for(array.get_data_type().as_ref(), result);
        }
        if let Some(structure) = dt.as_structure() {
            for dtc in structure.get_defined_components() {
                if !self.count_registers_for(dtc.get_data_type().as_ref(), result) {
                    return false;
                }
            }
            return true;
        }
        false
    }
}

/// `getBestFitRegister(Register, int)`: the smallest first-child register still holding `size`.
fn get_best_fit_register(reg: &Register, size: i32) -> Register {
    let mut reg = reg.clone();
    while reg.minimum_byte_size() > size && reg.has_children() {
        match reg.child_registers().into_iter().next() {
            Some(child) => reg = child,
            None => break,
        }
    }
    reg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_register_info::RegType;
    use crate::format::golang::go_ver_set::GoVerSet;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::abstract_float_data_type::get_float_data_type;
    use crate::program::model::data::abstract_integer_data_type::get_unsigned_data_type;
    use crate::program::model::data::array_data_type::ArrayDataType;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::structure_data_type::StructureDataType;
    use crate::program::seam_stubs::share_data_type;

    fn reg(name: &str, offset: i64, size: i32) -> Register {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        Register::new(name, name, Address::new(space, offset), size, false, 0)
    }

    /// x86-64 Go 1.17+ abi-internal: 9 int regs, 15 float regs, stack offset 8, max align 8.
    fn amd64_allocator() -> GoParamStorageAllocator {
        let ints = ["RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"];
        let int_regs: Vec<Register> = ints.iter().enumerate().map(|(i, n)| reg(n, i as i64 * 8, 8)).collect();
        let float_regs: Vec<Register> = (0..15).map(|i| reg(&format!("XMM{i}"), 0x1200 + i * 0x20, 16)).collect();
        let info = GoRegisterInfo::new(
            int_regs,
            float_regs,
            8,
            8,
            Some(reg("R14", 0xb0, 8)),
            Some(reg("XMM15", 0x1400, 16)),
            false,
            Some(reg("RDI", 0x38, 8)),
            None,
            Some(RegType::Int),
            Some(reg("RDX", 0x10, 8)),
            GoVerSet::parse("1.17-").unwrap(),
        );
        GoParamStorageAllocator::from_parts(info, false, "x86_64".to_string())
    }

    fn names(regs: &[Register]) -> Vec<&str> {
        regs.iter().map(|r| r.name()).collect()
    }

    #[test]
    fn allocates_int_and_float_registers_in_order() {
        let mut a = amd64_allocator();
        let u8dt = get_unsigned_data_type(8, None);
        let f8 = get_float_data_type(8, None);
        assert_eq!(names(&a.get_registers_for(u8dt.as_ref()).unwrap()), ["RAX"]);
        assert_eq!(names(&a.get_registers_for(f8.as_ref()).unwrap()), ["XMM0"]);
        assert_eq!(names(&a.get_registers_for(u8dt.as_ref()).unwrap()), ["RBX"]);
        // a 16 byte int takes two int regs, reversed for little endian storage
        let u16dt = get_unsigned_data_type(16, None);
        assert_eq!(names(&a.get_registers_for(u16dt.as_ref()).unwrap()), ["RDI", "RCX"]);
        assert_eq!(a.get_next_int_param_register(&reg("RAX", 0, 8)).map(|r| r.name().to_string()).as_deref(), Some("RBX"));
        a.reset_reg_allocation();
        assert_eq!(names(&a.get_registers_for(u8dt.as_ref()).unwrap()), ["RAX"]);
    }

    #[test]
    fn structs_and_arrays() {
        let mut a = amd64_allocator();
        let u8dt = get_unsigned_data_type(8, None);
        // Go string: { *byte, int } -> two int regs
        let mut s = StructureDataType::new("string", 0);
        s.add_with_name(share_data_type(&u8dt), Some("str".into()), None).unwrap();
        s.add_with_name(share_data_type(&u8dt), Some("len".into()), None).unwrap();
        assert_eq!(names(&a.get_registers_for_with(&s, false).unwrap()), ["RAX", "RBX"]);

        let one = ArrayDataType::new(u8dt.clone(), 1).unwrap();
        assert_eq!(names(&a.get_registers_for(&one).unwrap()), ["RCX"]);
        let empty = ArrayDataType::with_element_length(u8dt.clone(), 0, 8).unwrap();
        assert!(a.get_registers_for(&empty).is_none(), "zero-byte types never go in registers");
        let two = ArrayDataType::new(u8dt.clone(), 2).unwrap();
        assert!(a.get_registers_for(&two).is_none());
        // the failed allocation left the next register untouched
        assert_eq!(names(&a.get_registers_for(u8dt.as_ref()).unwrap()), ["RDI"]);
    }

    #[test]
    fn exhausting_registers_and_stack_allocation() {
        let mut a = amd64_allocator();
        let u8dt = get_unsigned_data_type(8, None);
        for _ in 0..9 {
            assert!(a.get_registers_for(u8dt.as_ref()).is_some());
        }
        assert!(a.get_registers_for(u8dt.as_ref()).is_none());

        assert_eq!(a.get_stack_offset(), 8);
        let u1 = get_unsigned_data_type(1, None);
        assert_eq!(a.get_stack_allocation(u1.as_ref()), 8);
        assert_eq!(a.get_stack_offset(), 9);
        // 8 byte value aligned to 8
        assert_eq!(a.get_stack_allocation(u8dt.as_ref()), 16);
        assert_eq!(a.get_stack_offset(), 24);
        a.set_stack_offset(25);
        a.align_stack();
        assert_eq!(a.get_stack_offset(), 32);

        let mut abi0 = amd64_allocator();
        abi0.set_abi0_mode();
        assert!(abi0.is_abi0_mode());
        assert!(abi0.get_registers_for(u8dt.as_ref()).is_none());
        assert_eq!(abi0.get_closure_context_register().map(|r| r.name()), Some("RDX"));
        assert_eq!(abi0.get_arch_description(), "x86_64");
        assert!(!abi0.is_big_endian());
    }

    #[test]
    fn unsigned_aligned_value() {
        assert_eq!(NumericUtilities::get_unsigned_aligned_value(9, 8), 16);
        assert_eq!(NumericUtilities::get_unsigned_aligned_value(16, 8), 16);
        assert_eq!(NumericUtilities::get_unsigned_aligned_value(5, 0), 5);
        // Java aligns -3 to 0: -(-3 + 4) = -1 rounds up to 0
        assert_eq!(NumericUtilities::get_unsigned_aligned_value(-3, 4), 0);
        assert_eq!(NumericUtilities::get_unsigned_aligned_value(-6, 4), -4);
    }
}
