//! Port of `ghidra.app.util.bin.format.golang.GoFunctionMultiReturn`.

use once_cell::sync::Lazy;
use regex::Regex;

use super::go_param_storage_allocator::GoParamStorageAllocator;
use crate::format::dwarf::dwarf_data_type_conflict_handler::DWARFDataTypeConflictHandler;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_conflict_handler::{ConflictResult, DataTypeConflictHandler};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::data::structure_data_type::StructureDataType;

/// `MULTIVALUE_RETURNTYPE_SUFFIX`.
pub const MULTIVALUE_RETURNTYPE_SUFFIX: &str = "_multivalue_return_type";
/// `SHORT_MULTIVALUE_RETURNTYPE_PREFIX`.
pub const SHORT_MULTIVALUE_RETURNTYPE_PREFIX: &str = "multireturn{";
/// `SHORT_MULTIVALUE_RETURNTYPE_SUFFIX`.
pub const SHORT_MULTIVALUE_RETURNTYPE_SUFFIX: &str = "}";
const ORDINAL_PREFIX: &str = "ordinal: ";
const TMP_NAME: &str = "--TEMP_NAME_REPLACE_ASAP--";

/// Matches a substring that is `"ordinal: NN"`, marking the number portion as group 1.
static ORDINAL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(&format!(r"^.*{ORDINAL_PREFIX}(\d+)[^\d]*$")).expect("valid regex"));

/// Handles creating a Ghidra structure to represent multiple return values returned from a Go
/// function.
///
/// Assigning custom storage for the return value is complicated by:
///
/// * Go storage allocations depend on the formal ordering of the return values
/// * stack storage must be last in a list of varnodes
/// * the decompiler maps a structure's contents to the list of varnodes in an endian-dependent
///   manner.
///
/// To meet these complications, the structure's layout is modified to put all items that were
/// marked as being stack parameters to either the front or back of the structure.
///
/// To allow this artificial structure to be adjusted by the user and reused at some later time
/// to re-calculate the correct storage, the items in the structure are tagged with the original
/// ordinal of that item as a text comment of each structure field, so that the correct ordering
/// of items can be re-created when needed.
///
/// If the structure layout is modified to conform to an arch's requirements, the structure's
/// name will be modified to include that arch's description at the end (eg. `"_x86_64"`).
///
/// The Java `List<DWARFVariable>` constructor is not ported (`DWARFVariable` is not ported yet).
/// The component lists hold snapshots taken from the finished arch-adjusted structure (Java's
/// lists hold its live components).
pub struct GoFunctionMultiReturn {
    structure: StructureDataType,
    normal_storage_components: Vec<Box<dyn DataTypeComponent>>,
    stack_storage_components: Vec<Box<dyn DataTypeComponent>>,
}

impl GoFunctionMultiReturn {
    /// `isMultiReturnDataType(DataType)`: a structure named like a multi-value return type.
    pub fn is_multi_return_data_type(dt: &dyn DataType) -> bool {
        dt.as_structure().is_some() && {
            let name = dt.get_name();
            name.ends_with(MULTIVALUE_RETURNTYPE_SUFFIX) || name.starts_with(SHORT_MULTIVALUE_RETURNTYPE_PREFIX)
        }
    }

    /// `fromStructure(DataType, DataTypeManager, GoParamStorageAllocator)`: `None` unless `dt` is
    /// a multi-value return structure.
    pub fn from_structure(
        dt: &dyn DataType,
        dtm: Option<&dyn DataTypeManager>,
        storage_allocator: Option<&GoParamStorageAllocator>,
    ) -> Option<GoFunctionMultiReturn> {
        if !Self::is_multi_return_data_type(dt) {
            return None;
        }
        let mut copy = StructureDataType::with_manager(dt.get_category_path(), dt.get_name(), 0, dtm);
        copy.try_replace_with(dt).ok()?;
        Some(Self::from_owned_structure(copy, dtm, storage_allocator))
    }

    /// `GoFunctionMultiReturn(Structure, DataTypeManager, GoParamStorageAllocator)`.
    pub fn from_owned_structure(
        structure: StructureDataType,
        dtm: Option<&dyn DataTypeManager>,
        storage_allocator: Option<&GoParamStorageAllocator>,
    ) -> GoFunctionMultiReturn {
        regenerate_multireturn_struct(structure, dtm, storage_allocator)
    }

    /// `GoFunctionMultiReturn(CategoryPath, List<DataType>, DataTypeManager,
    /// GoParamStorageAllocator)`: return values named `~r0`, `~r1`, ...
    ///
    /// # Errors
    /// A data type that can't be added to a structure.
    pub fn from_types(
        category_path: CategoryPath,
        types: &[std::sync::Arc<dyn DataType>],
        dtm: Option<&dyn DataTypeManager>,
        storage_allocator: Option<&GoParamStorageAllocator>,
    ) -> Result<GoFunctionMultiReturn, String> {
        let mut new_struct = mk_struct(category_path, dtm);
        for (ordinal_num, dt) in types.iter().enumerate() {
            new_struct.add_with_name(
                crate::program::seam_stubs::share_data_type(dt),
                Some(format!("~r{ordinal_num}")),
                Some(format!("{ORDINAL_PREFIX}{ordinal_num}")),
            )?;
        }
        Ok(regenerate_multireturn_struct(new_struct, dtm, storage_allocator))
    }

    /// `GoFunctionMultiReturn(CategoryPath, ParameterDefinition[], DataTypeManager,
    /// GoParamStorageAllocator)`: unnamed return values are named `~rN`.
    ///
    /// # Errors
    /// A data type that can't be added to a structure.
    pub fn from_params(
        category_path: CategoryPath,
        return_params: &[Box<dyn ParameterDefinition>],
        dtm: Option<&dyn DataTypeManager>,
        storage_allocator: Option<&GoParamStorageAllocator>,
    ) -> Result<GoFunctionMultiReturn, String> {
        let mut new_struct = mk_struct(category_path, dtm);
        for (ordinal_num, pd) in return_params.iter().enumerate() {
            let ret_param_name = match pd.get_name() {
                Some(n) if !n.trim().is_empty() => n,
                _ => format!("~r{ordinal_num}"),
            };
            new_struct.add_with_name(
                pd.get_data_type(),
                Some(ret_param_name),
                Some(format!("{ORDINAL_PREFIX}{ordinal_num}")),
            )?;
        }
        Ok(regenerate_multireturn_struct(new_struct, dtm, storage_allocator))
    }

    /// `getStruct()`.
    pub fn get_struct(&self) -> &StructureDataType {
        &self.structure
    }

    /// Takes the structure.
    pub fn into_struct(self) -> StructureDataType {
        self.structure
    }

    /// `getNormalStorageComponents()`: the values allocated to registers.
    pub fn get_normal_storage_components(&self) -> &[Box<dyn DataTypeComponent>] {
        &self.normal_storage_components
    }

    /// `getStackStorageComponents()`: the values allocated on the stack.
    pub fn get_stack_storage_components(&self) -> &[Box<dyn DataTypeComponent>] {
        &self.stack_storage_components
    }

    /// `getComponentsInOriginalOrder()`.
    pub fn get_components_in_original_order(&self) -> Vec<Box<dyn DataTypeComponent>> {
        get_components_in_original_order(&self.structure)
    }
}

fn mk_struct(cp: CategoryPath, dtm: Option<&dyn DataTypeManager>) -> StructureDataType {
    let mut new_struct = StructureDataType::with_manager(cp, TMP_NAME, 0, dtm);
    new_struct.set_packing_enabled(true);
    let _ = new_struct.set_explicit_packing_value(1);
    let _ = new_struct.set_description("Artificial data type to hold a function's return values");
    new_struct
}

fn regenerate_multireturn_struct(
    mut new_struct: StructureDataType,
    dtm: Option<&dyn DataTypeManager>,
    storage_allocator: Option<&GoParamStorageAllocator>,
) -> GoFunctionMultiReturn {
    let original_order = get_components_in_original_order(&new_struct);
    let name = format!(
        "{SHORT_MULTIVALUE_RETURNTYPE_PREFIX}{}{SHORT_MULTIVALUE_RETURNTYPE_SUFFIX}",
        original_order.iter().map(|dtc| dtc.get_data_type().get_name()).collect::<Vec<_>>().join(";")
    );

    if new_struct.get_name() == TMP_NAME {
        let _ = new_struct.set_name(&name); // should not fail
    }

    let Some(storage_allocator) = storage_allocator else {
        let stack_storage_components = get_components_in_original_order(&new_struct);
        return GoFunctionMultiReturn {
            structure: new_struct,
            normal_storage_components: Vec::new(),
            stack_storage_components,
        };
    };

    let mut adjusted_struct = StructureDataType::with_manager(
        new_struct.get_category_path(),
        format!("{name}_{}", storage_allocator.get_arch_description()),
        0,
        dtm,
    );
    adjusted_struct.set_packing_enabled(true);
    let _ = adjusted_struct.set_explicit_packing_value(1);

    let mut storage_allocator = storage_allocator.clone();
    let mut stack_results: Vec<(Box<dyn DataTypeComponent>, String)> = Vec::new();
    for (comp_num, dtc) in original_order.into_iter().enumerate() {
        let dt = dtc.get_data_type();
        match storage_allocator.get_registers_for(dt.as_ref()) {
            Some(regs) if !regs.is_empty() => {
                let reg_names: Vec<&str> = regs.iter().map(|r| r.name()).collect();
                let comment = format!("[{}] {ORDINAL_PREFIX}{comp_num}", reg_names.join(", "));
                let _ = adjusted_struct.add_with_name(dt, dtc.get_field_name(), Some(comment));
            }
            _ => {
                let stack_offset = storage_allocator.get_stack_allocation(dt.as_ref());
                let comment = format!("stack[{stack_offset}] {ORDINAL_PREFIX}{comp_num}");
                stack_results.push((dtc, comment));
            }
        }
    }

    // add the stack items to the struct first (LE) or last (BE), depending on endianness
    let stack_count = stack_results.len();
    for (i, (dtc, comment)) in stack_results.into_iter().enumerate() {
        let dt = dtc.get_data_type();
        let _ = if storage_allocator.is_big_endian() {
            adjusted_struct.add_with_name(dt, dtc.get_field_name(), Some(comment))
        }
        else {
            adjusted_struct.insert_with_length_and_name(i as i32, dt, -1, dtc.get_field_name(), Some(comment))
        };
    }

    // Java's component lists hold the adjusted struct's components: register values in order,
    // with the stack values first (LE) or last (BE)
    let comps = adjusted_struct.get_defined_components();
    let (stack_storage_components, normal_storage_components): (Vec<_>, Vec<_>) = if storage_allocator.is_big_endian() {
        let split = comps.len() - stack_count;
        let mut c = comps;
        let stack = c.split_off(split);
        (stack, c)
    }
    else {
        let mut c = comps;
        let normal = c.split_off(stack_count);
        (c, normal)
    };

    let is_equiv = DWARFDataTypeConflictHandler::INSTANCE.resolve_conflict(&adjusted_struct, &new_struct)
        == ConflictResult::UseExisting;
    GoFunctionMultiReturn {
        structure: if is_equiv { new_struct } else { adjusted_struct },
        normal_storage_components,
        stack_storage_components,
    }
}

/// `getOrdinalNumber(DataTypeComponent)`: the `ordinal: N` tag in the component's comment, or
/// `-1`.
fn get_ordinal_number(dtc: &dyn DataTypeComponent) -> i32 {
    let comment = dtc.get_comment().unwrap_or_default();
    ORDINAL_REGEX
        .captures(&comment)
        .and_then(|m| m.get(1))
        .and_then(|g| g.as_str().parse::<i32>().ok())
        .unwrap_or(-1)
}

fn get_components_in_original_order(structure: &StructureDataType) -> Vec<Box<dyn DataTypeComponent>> {
    let mut dtcs = structure.get_defined_components();
    // stable sort, like Collections.sort
    dtcs.sort_by_key(|dtc| get_ordinal_number(dtc.as_ref()));
    dtcs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::go_register_info::{GoRegisterInfo, RegType};
    use crate::format::golang::go_ver_set::GoVerSet;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::abstract_integer_data_type::get_unsigned_data_type;
    use crate::program::model::lang::register::Register;

    fn reg(name: &str, offset: i64) -> Register {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        Register::new(name, name, Address::new(space, offset), 8, false, 0)
    }

    /// An allocator with only two int registers, so the third value spills to the stack.
    fn two_reg_allocator(big_endian: bool) -> GoParamStorageAllocator {
        let info = GoRegisterInfo::new(
            vec![reg("RAX", 0), reg("RBX", 8)],
            vec![],
            8,
            8,
            None,
            None,
            false,
            None,
            None,
            Some(RegType::Int),
            None,
            GoVerSet::all(),
        );
        GoParamStorageAllocator::from_parts(info, big_endian, "x86_64".to_string())
    }

    fn types() -> Vec<std::sync::Arc<dyn DataType>> {
        let u8dt = get_unsigned_data_type(8, None);
        let u4dt = get_unsigned_data_type(4, None);
        vec![u8dt.clone(), u4dt, u8dt]
    }

    #[test]
    fn without_allocator_keeps_original_struct() {
        let mr = GoFunctionMultiReturn::from_types(CategoryPath::parse("/golang").unwrap(), &types(), None, None).unwrap();
        let s = mr.get_struct();
        assert_eq!(s.get_name(), "multireturn{qword;dword;qword}");
        assert!(GoFunctionMultiReturn::is_multi_return_data_type(s));
        assert_eq!(mr.get_stack_storage_components().len(), 3);
        assert!(mr.get_normal_storage_components().is_empty());
        let comps = s.get_defined_components();
        assert_eq!(comps[0].get_field_name().as_deref(), Some("~r0"));
        assert_eq!(comps[2].get_comment().as_deref(), Some("ordinal: 2"));
        assert_eq!(s.get_length(), 20); // packing 1
    }

    #[test]
    fn little_endian_puts_stack_values_first() {
        let alloc = two_reg_allocator(false);
        let mr = GoFunctionMultiReturn::from_types(CategoryPath::parse("/golang").unwrap(), &types(), None, Some(&alloc))
            .unwrap();
        let s = mr.get_struct();
        assert_eq!(s.get_name(), "multireturn{qword;dword;qword}_x86_64");
        let comps = s.get_defined_components();
        let comments: Vec<String> = comps.iter().map(|c| c.get_comment().unwrap_or_default()).collect();
        assert_eq!(comments, ["stack[8] ordinal: 2", "[RAX] ordinal: 0", "[RBX] ordinal: 1"]);
        assert_eq!(mr.get_stack_storage_components().len(), 1);
        assert_eq!(mr.get_normal_storage_components().len(), 2);
        let order: Vec<Option<String>> =
            mr.get_components_in_original_order().iter().map(|c| c.get_field_name()).collect();
        assert_eq!(order, [Some("~r0".to_string()), Some("~r1".to_string()), Some("~r2".to_string())]);
        // the allocator passed in is not consumed
        assert_eq!(alloc.get_stack_offset(), 8);
    }

    #[test]
    fn big_endian_puts_stack_values_last_and_round_trips() {
        let alloc = two_reg_allocator(true);
        let mr = GoFunctionMultiReturn::from_types(CategoryPath::parse("/golang").unwrap(), &types(), None, Some(&alloc))
            .unwrap();
        // big endian: the stack value stays last, so the arch-adjusted layout is equivalent to the
        // original and the original structure is kept (as Java does)
        assert_eq!(mr.get_struct().get_name(), "multireturn{qword;dword;qword}");
        let normal: Vec<String> =
            mr.get_normal_storage_components().iter().map(|c| c.get_comment().unwrap_or_default()).collect();
        assert_eq!(normal, ["[RAX] ordinal: 0", "[RBX] ordinal: 1"]);
        let stack: Vec<String> =
            mr.get_stack_storage_components().iter().map(|c| c.get_comment().unwrap_or_default()).collect();
        assert_eq!(stack, ["stack[8] ordinal: 2"]);

        let again = GoFunctionMultiReturn::from_structure(mr.get_struct(), None, Some(&alloc)).unwrap();
        assert_eq!(again.get_struct().get_name(), "multireturn{qword;dword;qword}");
        assert!(GoFunctionMultiReturn::from_structure(get_unsigned_data_type(8, None).as_ref(), None, None).is_none());
    }
}
