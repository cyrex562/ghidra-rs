//! Port of `ghidra.app.util.bin.format.golang.GoRegisterInfo`.

use std::sync::Arc;

use super::go_ver_set::GoVerSet;
use crate::format::dwarf::dwarf_util::convert_register_list_to_varnode_storage;
use crate::program::model::data::abstract_float_data_type::get_float_data_type;
use crate::program::model::data::abstract_integer_data_type::get_unsigned_data_type;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::void_data_type;
use crate::program::model::lang::register::Register;
use crate::program::model::listing::Program;
use crate::program::model::pcode::Varnode;

/// The kind of register a duffzero "zero value" parameter is passed in (`GoRegisterInfo.RegType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegType {
    /// An integer register.
    Int,
    /// A floating point register.
    Float,
}

/// One parameter of the `runtime.duffzero` function, as described by
/// [`GoRegisterInfo::get_duffzero_params`].
///
/// Java builds `ParameterImpl` instances (`new ParameterImpl(name, UNASSIGNED_ORDINAL, dt,
/// storage, true, program, IMPORTED)`); `ParameterImpl` is only a mixin trait in this port, so the
/// same name / data type / register storage triple is returned as a value for the caller to turn
/// into a function parameter.
#[derive(Clone)]
pub struct GoDuffzeroParam {
    /// Parameter name (`"dest"` or `"zeroValue"`).
    pub name: String,
    /// Parameter data type.
    pub data_type: Arc<dyn DataType>,
    /// Register storage of the parameter.
    pub storage: Vec<Varnode>,
}

/// Immutable information about registers, alignment sizes, etc needed to allocate storage
/// for parameters during a function call.
#[derive(Clone)]
pub struct GoRegisterInfo {
    valid_versions: GoVerSet,
    int_registers: Vec<Register>,
    float_registers: Vec<Register>,
    stack_initial_offset: i32,
    /// 4 or 8.
    max_align: i32,
    /// Always points to g.
    current_goroutine_register: Option<Register>,
    /// Always contains a zero value.
    zero_register: Option<Register>,
    /// Zero register is provided by cpu, or is manually set.
    zero_register_is_builtin: bool,
    duffzero_dest_param: Option<Register>,
    /// If duffzero has 2nd param.
    duffzero_zero_param: Option<Register>,
    duffzero_zero_param_type: Option<RegType>,
    closure_context_register: Option<Register>,
}

impl std::fmt::Debug for GoRegisterInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |regs: &[Register]| regs.iter().map(|r| r.name().to_string()).collect::<Vec<_>>();
        let name = |r: &Option<Register>| r.as_ref().map(|r| r.name().to_string());
        f.debug_struct("GoRegisterInfo")
            .field("int_registers", &names(&self.int_registers))
            .field("float_registers", &names(&self.float_registers))
            .field("stack_initial_offset", &self.stack_initial_offset)
            .field("max_align", &self.max_align)
            .field("current_goroutine_register", &name(&self.current_goroutine_register))
            .field("zero_register", &name(&self.zero_register))
            .field("closure_context_register", &name(&self.closure_context_register))
            .finish()
    }
}

impl GoRegisterInfo {
    /// The package-private constructor `GoRegisterInfo(...)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        int_registers: Vec<Register>,
        float_registers: Vec<Register>,
        stack_initial_offset: i32,
        max_align: i32,
        current_goroutine_register: Option<Register>,
        zero_register: Option<Register>,
        zero_register_is_builtin: bool,
        duffzero_dest_param: Option<Register>,
        duffzero_zero_param: Option<Register>,
        duffzero_zero_param_type: Option<RegType>,
        closure_context_register: Option<Register>,
        valid_versions: GoVerSet,
    ) -> Self {
        GoRegisterInfo {
            valid_versions,
            int_registers,
            float_registers,
            stack_initial_offset,
            max_align,
            current_goroutine_register,
            zero_register,
            zero_register_is_builtin,
            duffzero_dest_param,
            duffzero_zero_param,
            duffzero_zero_param_type,
            closure_context_register,
        }
    }

    /// `getValidVersions()`.
    pub fn get_valid_versions(&self) -> &GoVerSet {
        &self.valid_versions
    }

    /// `getIntRegisterSize()`: Java returns the max alignment here (marked as a hack upstream).
    pub fn get_int_register_size(&self) -> i32 {
        self.max_align
    }

    /// `getMaxAlign()`.
    pub fn get_max_align(&self) -> i32 {
        self.max_align
    }

    /// `getCurrentGoroutineRegister()`.
    pub fn get_current_goroutine_register(&self) -> Option<&Register> {
        self.current_goroutine_register.as_ref()
    }

    /// `getZeroRegister()`.
    pub fn get_zero_register(&self) -> Option<&Register> {
        self.zero_register.as_ref()
    }

    /// `isZeroRegisterIsBuiltin()`.
    pub fn is_zero_register_is_builtin(&self) -> bool {
        self.zero_register_is_builtin
    }

    /// `getIntRegisters()`.
    pub fn get_int_registers(&self) -> &[Register] {
        &self.int_registers
    }

    /// `getFloatRegisters()`.
    pub fn get_float_registers(&self) -> &[Register] {
        &self.float_registers
    }

    /// `getStackInitialOffset()`.
    pub fn get_stack_initial_offset(&self) -> i32 {
        self.stack_initial_offset
    }

    /// `hasAbiInternalParamRegisters()`.
    pub fn has_abi_internal_param_registers(&self) -> bool {
        !self.int_registers.is_empty() || !self.float_registers.is_empty()
    }

    /// `getDuffzeroParams(Program)`: the `dest` (and optional `zeroValue`) parameters of
    /// `runtime.duffzero`. See [`GoDuffzeroParam`] for how this differs from Java's
    /// `List<Variable>`.
    pub fn get_duffzero_params(&self, program: &dyn Program) -> Vec<GoDuffzeroParam> {
        let Some(dest) = &self.duffzero_dest_param else {
            return Vec::new();
        };
        let dtm = program.get_data_type_manager();
        let dtm_ref = dtm.as_deref();
        let void_ptr: Arc<dyn DataType> = match dtm_ref {
            Some(dtm) => Arc::from(dtm.get_pointer(void_data_type::void().as_ref()) as Box<dyn DataType>),
            None => return Vec::new(),
        };

        let mut params = vec![GoDuffzeroParam {
            name: "dest".to_string(),
            storage: storage_for_reg(dest, void_ptr.get_length()),
            data_type: void_ptr,
        }];
        if let (Some(zero), Some(zero_type)) = (&self.duffzero_zero_param, self.duffzero_zero_param_type) {
            let reg_size = zero.minimum_byte_size();
            let dt = match zero_type {
                RegType::Float => get_float_data_type(reg_size, dtm_ref),
                RegType::Int => get_unsigned_data_type(reg_size, dtm_ref),
            };
            params.push(GoDuffzeroParam {
                name: "zeroValue".to_string(),
                data_type: dt,
                storage: storage_for_reg(zero, reg_size),
            });
        }
        params
    }

    /// `getClosureContextRegister()`.
    pub fn get_closure_context_register(&self) -> Option<&Register> {
        self.closure_context_register.as_ref()
    }

    /// `getAlignmentForType(DataType)`: the stack alignment Go uses for a value of `dt`
    /// (typedefs and arrays are reduced to their base / element type first).
    pub fn get_alignment_for_type(&self, dt: &dyn DataType) -> i32 {
        if let Some(td) = dt.as_typedef() {
            return self.get_alignment_for_type(td.get_base_data_type().as_ref());
        }
        if let Some(a) = dt.as_array() {
            return self.get_alignment_for_type(a.get_data_type().as_ref());
        }
        if is_int_type(dt) && is_intrinsic_size(dt.get_length()) {
            return self.max_align.min(dt.get_length());
        }
        if is_complex8(dt) {
            // Go complex64
            return 4;
        }
        if dt.is_floating_point() {
            return self.max_align.min(dt.get_length());
        }
        self.max_align
    }
}

/// Java `getStorageForReg`: the varnodes of `reg` holding a `len` byte value.
fn storage_for_reg(reg: &Register, len: i32) -> Vec<Varnode> {
    convert_register_list_to_varnode_storage(std::slice::from_ref(reg), len)
}

/// Java `instanceof Complex8DataType`. `Complex8DataType` is only a mixin trait in this port, so
/// the built-in is recognized by its fixed name and size.
fn is_complex8(dt: &dyn DataType) -> bool {
    dt.get_name() == "complex8" && dt.get_length() == 8
}

/// `isIntType(DataType)`: integer, wide char, enum and boolean types.
pub(crate) fn is_int_type(dt: &dyn DataType) -> bool {
    dt.as_abstract_integer().is_some()
        || dt.is_integer_type()
        || dt.is_wide_char_type()
        || dt.as_enum().is_some()
        || dt.is_boolean_type()
}

/// `isIntrinsicSize(int)`: a power of two.
pub(crate) fn is_intrinsic_size(size: i32) -> bool {
    size.count_ones() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::boolean_data_type::BooleanDataType;

    fn reg(name: &str, offset: i64, size: i32) -> Register {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        Register::new(name, name, Address::new(space, offset), size, false, 0)
    }

    fn info(int_regs: Vec<Register>, max_align: i32) -> GoRegisterInfo {
        GoRegisterInfo::new(
            int_regs,
            vec![],
            8,
            max_align,
            None,
            None,
            false,
            Some(reg("RDI", 0x38, 8)),
            None,
            Some(RegType::Int),
            Some(reg("RDX", 0x10, 8)),
            GoVerSet::all(),
        )
    }

    #[test]
    fn accessors_and_abi_internal() {
        let ri = info(vec![reg("RAX", 0, 8)], 8);
        assert!(ri.has_abi_internal_param_registers());
        assert_eq!(ri.get_int_register_size(), 8);
        assert_eq!(ri.get_stack_initial_offset(), 8);
        assert_eq!(ri.get_closure_context_register().unwrap().name(), "RDX");
        assert!(ri.get_valid_versions().contains(crate::format::golang::go_ver::GoVer::new(1, 21, 0)));
        let abi0 = info(vec![], 4);
        assert!(!abi0.has_abi_internal_param_registers());
    }

    #[test]
    fn alignment_for_types() {
        let ri = info(vec![], 8);
        // boolean: int type of intrinsic size 1
        assert_eq!(ri.get_alignment_for_type(&BooleanDataType::new(None)), 1);
        // float4: AbstractFloatDataType -> min(maxAlign, 4)
        let f4 = get_float_data_type(4, None);
        assert_eq!(ri.get_alignment_for_type(f4.as_ref()), 4);
        // uint8 (8 bytes)
        let u8dt = get_unsigned_data_type(8, None);
        assert_eq!(ri.get_alignment_for_type(u8dt.as_ref()), 8);
        let ri4 = info(vec![], 4);
        assert_eq!(ri4.get_alignment_for_type(u8dt.as_ref()), 4);
        // a 3-byte integer is not intrinsic: falls through to maxAlign
        let u3 = get_unsigned_data_type(3, None);
        assert_eq!(ri.get_alignment_for_type(u3.as_ref()), 8);
        assert!(is_intrinsic_size(4) && !is_intrinsic_size(6) && !is_intrinsic_size(0));
    }
}
