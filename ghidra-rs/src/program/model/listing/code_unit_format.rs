//! Port of `ghidra.program.model.listing.CodeUnitFormat`.
//!
//! This was selected as a dependency-cycle cut-point and ported to a trait rather than a
//! concrete class. The trait's ~9 methods mirror the Java class's public API 1:1; every private
//! helper method behind them is ported as an ordinary (non-trait) function in this module, taking
//! a `&CodeUnitFormatOptions` explicitly rather than reaching for `self`, so the trait itself
//! stays a minimal, object-safe surface. [`DefaultCodeUnitFormat`] is a straightforward concrete
//! implementor carrying the Java class's constructors.
//!
//! A few referenced Java types are not yet ported in this crate:
//! - `CodeUnitFormatOptions` (with its `ShowBlockName`/`ShowNamespace` nested enums) is stubbed as
//!   a plain data struct in [`seam_stubs`](crate::program::seam_stubs).
//! - `ghidra.app.util.NamespaceUtils` and `ghidra.app.util.viewer.field.CommentUtils` are stubbed
//!   as free functions in `seam_stubs` (`namespace_utils`/`comment_utils` modules); the former is
//!   a faithful port of its one algorithm, the latter is an identity passthrough since annotation
//!   parsing is out of scope.
//!
//! A handful of simplifications versus the Java source, made necessary by gaps in the currently
//! ported API surface, are called out at their point of use:
//! - Address "physical address"/`SegmentedAddress` handling is not modeled; plain [`Address`]
//!   equality/`addressable_word_offset` is used instead.
//! - Reference-identity comparisons of `Variable`/`MemoryBlock` objects (Java's `==`) are
//!   approximated with [`Variable::is_equivalent`]/name-based equality, since this crate's
//!   `FunctionManager`/`Memory` accessors return fresh `Box`/`Arc` handles rather than
//!   interned/reference-stable objects.
//! - Equate lookup for scalar operand mark-up is fetched once per operand (rather than Java's
//!   lazy fetch on first scalar) to sidestep the borrow lifetime of `EquateTable`'s `&SimpleEquate`
//!   results, which cannot outlive the `Arc<dyn Program>` mutable-access closure they come from.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::pointer_data_type;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::instruction::{Instruction, OperandValue};
use crate::program::model::listing::label_string::{LabelString, LabelType};
use crate::program::model::listing::operand_representation_list::{
    OperandRepresentationElement, OperandRepresentationList, OperandRepresentationListImpl,
};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable::Variable;
use crate::program::model::listing::variable_offset::{VariableOffset, VariableOffsetImpl};
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    mem_reference_impl::MemReferenceImpl, offset_reference::OffsetReference, ref_type::RefType,
    reference::Reference, stack_reference::StackReference, symbol_utilities::DefaultSymbolUtilities,
    symbol_utilities::SymbolUtilities, Equate, Namespace, Symbol,
};
use crate::program::seam_stubs::{
    comment_utils, namespace_utils, CodeUnitFormatOptions, CommentType, MemBuffer, ShowBlockName,
    ShowNamespace,
};

const PLUS: &str = "+";
const UNDERSCORE: &str = "_";

/// Stands in for `Address.SEPARATOR_CHAR`, not yet ported onto [`Address`].
const ADDRESS_SEPARATOR_CHAR: char = ':';

/// Stands in for the symbolic-arrow delimiter used when combining a sub-operand with its
/// non-consumed primary reference ("extended reference mark-up").
pub const EXTENDED_REFERENCE_DELIMITER: &str = "=>";
/// Delimiter used when an extended pointer reference is followed to its indirect target.
pub const EXTENDED_INDIRECT_REFERENCE_DELIMITER: &str = "->";

/// Supported memory address shift cases (bits).
const SHIFT_CASES: &[u32] = &[1, 2, 8, 16];
/// Supported memory address mask cases (mask value).
const MASK_CASES: &[i64] = &[0x0ffff, 0x0ffffffff];

/// Formats code units and their operands for display, applying reference/variable mark-up.
///
/// Port of `ghidra.program.model.listing.CodeUnitFormat`.
pub trait CodeUnitFormat {
    /// The format options backing this formatter.
    fn options(&self) -> &CodeUnitFormatOptions;

    /// Returns a formatted string representation of the specified code unit, including mnemonic
    /// and operand(s) only. Stands in for `getRepresentationString(CodeUnit)`.
    fn get_representation_string(&self, cu: &dyn CodeUnit) -> String {
        self.get_representation_string_with_eol(cu, false)
    }

    /// Returns a formatted string representation of the specified code unit mnemonic and
    /// operand(s). Stands in for `getRepresentationString(CodeUnit, boolean)`.
    fn get_representation_string_with_eol(&self, cu: &dyn CodeUnit, include_eol_comment: bool) -> String {
        get_representation_string_impl(self.options(), cu, include_eol_comment)
    }

    /// Returns a formatted code unit mnemonic. Stands in for `getMnemonicRepresentation`.
    fn get_mnemonic_representation(&self, cu: &dyn CodeUnit) -> String {
        get_mnemonic_representation_impl(self.options(), cu)
    }

    /// Returns a formatted string representation of the specified code unit operand. Stands in
    /// for `getOperandRepresentationString`.
    fn get_operand_representation_string(&self, cu: &dyn CodeUnit, op_index: i32) -> String {
        match self.get_operand_representation_list(cu, op_index) {
            Some(list) => list.to_display_string(),
            None => "<UNSUPPORTED>".to_string(),
        }
    }

    /// Returns a formatted list of operand objects for the specified code unit operand, or `None`
    /// for an unsupported language. Stands in for `getOperandRepresentationList`.
    fn get_operand_representation_list(
        &self,
        cu: &dyn CodeUnit,
        op_index: i32,
    ) -> Option<Box<dyn OperandRepresentationList>> {
        get_operand_representation_list_impl(self.options(), cu, op_index)
    }

    /// Returns a formatted data value for the specified data unit. Stands in for
    /// `getDataValueRepresentation`.
    fn get_data_value_representation(&self, data: &dyn Data) -> Box<dyn OperandRepresentationList> {
        get_data_value_representation_impl(self.options(), data)
    }

    /// Returns a formatted data value for the specified data unit. Stands in for
    /// `getDataValueRepresentationString`.
    fn get_data_value_representation_string(&self, data: &dyn Data) -> String {
        self.get_data_value_representation(data).to_display_string()
    }

    /// Returns a marked-up representation of the reference destination, or `None` if a suitable
    /// string could not be produced. Stands in for `getReferenceRepresentationString`.
    fn get_reference_representation_string(
        &self,
        from_code_unit: &dyn CodeUnit,
        reference: &dyn Reference,
    ) -> Option<String> {
        get_reference_representation_string_impl(self.options(), from_code_unit, reference)
    }

    /// Generates an offcut label string. Stands in for `getOffcutLabelString`.
    fn get_offcut_label_string(
        &self,
        offcut_address: &Address,
        cu: &dyn CodeUnit,
        markup_address: Option<&Address>,
        symbol: &dyn Symbol,
    ) -> String {
        get_offcut_label_string_impl(self.options(), offcut_address, cu, markup_address, symbol)
    }

    /// Returns the current [`ShowBlockName`] setting. Stands in for `getShowBlockName`.
    fn get_show_block_name(&self) -> ShowBlockName {
        self.options().show_block_name
    }
}

/// Straightforward concrete [`CodeUnitFormat`] implementor carrying the Java class's
/// constructors.
#[derive(Debug, Clone)]
pub struct DefaultCodeUnitFormat {
    options: CodeUnitFormatOptions,
}

impl DefaultCodeUnitFormat {
    /// Stands in for the default constructor using default format options.
    pub fn new() -> Self {
        DefaultCodeUnitFormat { options: CodeUnitFormatOptions::new() }
    }

    /// Stands in for `CodeUnitFormat(ShowBlockName, ShowNamespace)`.
    pub fn with_show_options(show_block_name: ShowBlockName, show_namespace: ShowNamespace) -> Self {
        DefaultCodeUnitFormat {
            options: CodeUnitFormatOptions::with_show_options(show_block_name, show_namespace),
        }
    }

    /// Stands in for `CodeUnitFormat(CodeUnitFormatOptions)`.
    pub fn with_options(options: CodeUnitFormatOptions) -> Self {
        DefaultCodeUnitFormat { options }
    }
}

impl Default for DefaultCodeUnitFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeUnitFormat for DefaultCodeUnitFormat {
    fn options(&self) -> &CodeUnitFormatOptions {
        &self.options
    }
}

//==================================================================================================
// Private helpers (free functions; not part of the trait's public API surface)
//==================================================================================================

/// Attempts to gain exclusive access to `cu`'s program and runs `f` against it. Returns `None` if
/// exclusive access could not be obtained (another `Arc<dyn Program>` handle is outstanding).
/// Mirrors the `Arc::get_mut(&mut program)` idiom already established elsewhere in this crate
/// (see `data_utilities.rs`) for reaching `Program`'s `&mut self` manager accessors.
fn with_program_mut<T>(cu: &dyn CodeUnit, f: impl for<'r> FnOnce(&'r mut dyn Program) -> Option<T>) -> Option<T> {
    let mut program = cu.get_program();
    match Arc::get_mut(&mut program) {
        Some(p) => f(p),
        None => None,
    }
}

fn operand_value_to_element(value: OperandValue) -> OperandRepresentationElement {
    match value {
        OperandValue::Register(r) => OperandRepresentationElement::Register(r),
        OperandValue::Address(a) => OperandRepresentationElement::Address(a),
        OperandValue::Scalar(s) => OperandRepresentationElement::Scalar(s),
        OperandValue::Character(c) => OperandRepresentationElement::Character(c),
        OperandValue::Text(s) => OperandRepresentationElement::Text(s),
    }
}

fn get_mnemonic_representation_impl(options: &CodeUnitFormatOptions, cu: &dyn CodeUnit) -> String {
    let mnemonic = cu.get_mnemonic_string();
    let mut result = String::new();
    if options.show_data_mutability {
        if let Some(data) = cu.as_data() {
            if data.is_constant() {
                result.push_str("const ");
            } else if data.is_volatile() {
                result.push_str("volatile ");
            }
        }
    }
    result.push_str(&mnemonic);
    result
}

fn get_operand_representation_string_impl(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    op_index: i32,
) -> String {
    match get_operand_representation_list_impl(options, cu, op_index) {
        Some(list) => list.to_display_string(),
        None => "<UNSUPPORTED>".to_string(),
    }
}

fn get_representation_string_impl(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    include_eol_comment: bool,
) -> String {
    let mut result = get_mnemonic_representation_impl(options, cu);
    if let Some(instr) = cu.as_instruction() {
        let n = instr.get_num_operands();
        for i in 0..n {
            if i == 0 {
                result.push(' ');
            } else if let Some(sep) = instr.get_separator(i) {
                if !sep.is_empty() {
                    result.push_str(&sep);
                }
            }
            result.push_str(&get_operand_representation_string_impl(options, cu, i));
        }
    } else {
        let data_rep = get_operand_representation_string_impl(options, cu, 0);
        if !data_rep.trim().is_empty() {
            result.push(' ');
            result.push_str(&data_rep);
        }
    }
    if include_eol_comment {
        if let Some(eol) = cu.get_comment(CommentType::Eol) {
            let eol = comment_utils::get_display_string(&eol, cu.get_program().as_ref());
            result.push_str("  // ");
            result.push_str(&eol);
        }
    }
    result
}

fn get_operand_representation_list_impl(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    op_index: i32,
) -> Option<Box<dyn OperandRepresentationList>> {
    if let Some(data) = cu.as_data() {
        if op_index == 0 {
            return Some(get_data_value_representation_impl(options, data));
        }
        return None;
    }

    let instr = cu.as_instruction()?;

    let program = cu.get_program();
    let supports_pcode = program.get_language().map(|l| l.supports_pcode()).unwrap_or(false);
    if !supports_pcode {
        return None;
    }

    let raw = instr.get_default_operand_representation_list(op_index);
    let Some(raw) = raw else {
        return Some(Box::new(OperandRepresentationListImpl::from_error("<BAD-Instruction>")));
    };
    let mut representation_list: Vec<OperandRepresentationElement> =
        raw.into_iter().map(operand_value_to_element).collect();

    let mut reg_index_map = build_register_index_map(&representation_list);

    let address = instr.get_min_address();
    let func = with_program_mut(cu, |p| {
        p.get_function_manager().and_then(|fm| fm.get_function_containing(&address))
    });

    let mut primary_ref = cu.get_primary_reference(op_index);
    let mut referenced_variable: Option<Arc<dyn Variable>> = None;
    if let (Some(pref), Some(_)) = (primary_ref.as_ref(), func.as_ref()) {
        referenced_variable = with_program_mut(cu, |p| {
            p.get_reference_manager().and_then(|rm| rm.get_referenced_variable(pref.as_ref()))
        })
        .map(Arc::<dyn Variable>::from);
    }

    if perform_address_markup(options, instr, primary_ref.as_deref(), &mut representation_list) {
        primary_ref = None;
        referenced_variable = None;
    }

    if perform_scalar_markup(
        options,
        instr,
        op_index,
        func.as_ref(),
        primary_ref.clone(),
        referenced_variable.clone(),
        &mut reg_index_map,
        &mut representation_list,
    ) {
        primary_ref = None;
        referenced_variable = None;
    }

    if perform_register_markup(
        options,
        instr,
        op_index,
        func.as_ref(),
        primary_ref.as_ref(),
        referenced_variable.as_ref(),
        &reg_index_map,
        &mut representation_list,
    ) {
        primary_ref = None;
        referenced_variable = None;
    }

    if perform_extended_markup(options, cu, primary_ref.as_ref(), referenced_variable.as_ref(), &mut representation_list) {
        primary_ref = None;
    }

    Some(Box::new(OperandRepresentationListImpl::new(representation_list, primary_ref.is_some())))
}

/// Register-index map keyed by register value-equality (not `HashMap`, since [`RegisterRef`] is
/// an `Rc<RefCell<Register>>` with no `Hash` impl). Stands in for `HashMap<Register, Integer>`.
struct RegIndexMap(Vec<(RegisterRef, usize)>);

impl RegIndexMap {
    fn new() -> Self {
        RegIndexMap(Vec::new())
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn insert(&mut self, reg: RegisterRef, idx: usize) {
        self.0.push((reg, idx));
    }

    fn remove(&mut self, reg: &RegisterRef) -> Option<usize> {
        let pos = self.0.iter().position(|(r, _)| *r.borrow() == *reg.borrow())?;
        Some(self.0.remove(pos).1)
    }

    fn get(&self, reg: &RegisterRef) -> Option<usize> {
        self.0.iter().find(|(r, _)| *r.borrow() == *reg.borrow()).map(|(_, i)| *i)
    }

    fn get_register_by_address(&self, addr: &Address) -> Option<RegisterRef> {
        self.0.iter().find(|(r, _)| r.borrow().address() == addr).map(|(r, _)| r.clone())
    }

    fn keys(&self) -> impl Iterator<Item = &RegisterRef> {
        self.0.iter().map(|(r, _)| r)
    }
}

/// Build register index map based upon a raw operand representation list where the index
/// corresponds to the index within the list. Stands in for `getRegisterIndexMap`.
fn build_register_index_map(list: &[OperandRepresentationElement]) -> RegIndexMap {
    let mut map = RegIndexMap::new();
    for (i, el) in list.iter().enumerate() {
        if let OperandRepresentationElement::Register(reg) = el {
            if map.remove(reg).is_none() {
                map.insert(reg.clone(), i);
            }
        }
    }
    map
}

/// Determine if the specified register is read by the specified instruction.
fn is_read(reg: &RegisterRef, instr: &dyn Instruction) -> bool {
    instr
        .get_input_objects()
        .iter()
        .any(|obj| matches!(obj, OperandValue::Register(r) if *r.borrow() == *reg.borrow()))
}

/// Determine if the specified register is written by the specified instruction.
fn is_written(reg: &RegisterRef, instr: &dyn Instruction) -> bool {
    instr
        .get_result_objects()
        .iter()
        .any(|obj| matches!(obj, OperandValue::Register(r) if *r.borrow() == *reg.borrow()))
}

fn has_register_write_reference(instr: &dyn Instruction, reg: &RegisterRef) -> bool {
    instr
        .get_references_from()
        .iter()
        .any(|r| r.reference_type().is_write() && r.to_address() == *reg.borrow().address())
}

/// Determine if two registers' byte ranges overlap.
///
/// Faithfully mirrors the Java source's `registersOverlap`, including its apparent reuse of
/// `reg1`'s byte size (rather than `reg2`'s) when computing `reg2`'s max address.
fn registers_overlap(reg1: Option<&RegisterRef>, reg2: &RegisterRef) -> bool {
    let Some(reg1) = reg1 else { return false };
    let reg1_b = reg1.borrow();
    let reg2_b = reg2.borrow();

    let reg1_min = reg1_b.address().clone();
    let reg2_min = reg2_b.address().clone();

    let mut reg1_max = reg1_min.clone();
    let size = reg1_b.minimum_byte_size();
    if size > 1 {
        if let Ok(a) = reg1_min.add((size - 1) as i64) {
            reg1_max = a;
        }
    }
    if reg2_min > reg1_max {
        return false;
    }
    if reg1_max < reg2_min {
        return false;
    }

    let mut reg2_max = reg2_min.clone();
    let size = reg1_b.minimum_byte_size();
    if size > 1 {
        if let Ok(a) = reg2_min.add((size - 1) as i64) {
            reg2_max = a;
        }
    }
    if reg1_min > reg2_max {
        return false;
    }
    if reg2_max < reg1_min {
        return false;
    }

    true
}

fn find_register(v: &Varnode, reg_index_map: &RegIndexMap) -> Option<RegisterRef> {
    if v.is_register() {
        return reg_index_map.get_register_by_address(v.get_address());
    }
    None
}

fn varnode_equals_scalar(v: &Varnode, value: &Scalar) -> bool {
    let s = Scalar::new_with_signedness((v.get_size() * 8) as u8, v.get_offset(), value.is_signed());
    s.get_value() == value.get_value()
}

/// Find a register which has a direct association with the specified scalar via an `INT_ADD`
/// p-code operation. Stands in for `findAssociatedOperandRegister`.
fn find_associated_operand_register(
    scalar: &Scalar,
    reg_index_map: &RegIndexMap,
    pcode: &[PcodeOp],
) -> Option<RegisterRef> {
    if reg_index_map.is_empty() || pcode.is_empty() {
        return None;
    }
    for op in pcode {
        if op.opcode == OpCode::IntAdd {
            let inputs = &op.inputs;
            if inputs.len() < 2 {
                continue;
            }
            let reg = if inputs[0].is_constant() && varnode_equals_scalar(&inputs[0], scalar) {
                find_register(&inputs[1], reg_index_map)
            } else if inputs[1].is_constant() && varnode_equals_scalar(&inputs[1], scalar) {
                find_register(&inputs[0], reg_index_map)
            } else {
                None
            };
            if reg.is_some() {
                return reg;
            }
        }
    }
    None
}

fn find_equate(scalar: &Scalar, equates: &[(i64, String)]) -> Option<String> {
    equates
        .iter()
        .find(|(v, _)| *v == scalar.get_signed_value() || *v == scalar.get_value())
        .map(|(_, name)| name.clone())
}

/// A simple helper to find the scalars and addresses in the operand representation list and to
/// keep track of whether to process a scalar with a zero value. Stands in for the private inner
/// class `InstructionScalarInfo`.
struct InstructionScalarInfo {
    process_zero_scalar: bool,
    scalar_count: i32,
    address_count: i32,
    last_address_index: i32,
}

impl InstructionScalarInfo {
    fn new(representation_list: &[OperandRepresentationElement], primary_ref: Option<&dyn Reference>) -> Self {
        let mut scalar_count = 0;
        let mut address_count = 0;
        let mut last_address_index: i32 = -1;
        let mut has_zero_scalar = false;
        for (i, obj) in representation_list.iter().enumerate() {
            match obj {
                OperandRepresentationElement::Scalar(s) => {
                    if s.get_unsigned_value() == 0 {
                        has_zero_scalar = true;
                    } else {
                        scalar_count += 1;
                        address_count = 0;
                    }
                }
                OperandRepresentationElement::Address(_) => {
                    if scalar_count == 0 {
                        address_count += 1;
                        last_address_index = i as i32;
                    }
                }
                _ => {}
            }
        }
        let mut process_zero_scalar = false;
        if has_zero_scalar && scalar_count == 0 && address_count == 0 && primary_ref.is_none() {
            scalar_count += 1;
            process_zero_scalar = true;
        }
        InstructionScalarInfo { process_zero_scalar, scalar_count, address_count, last_address_index }
    }

    fn get_scalar(&self, representation_list: &[OperandRepresentationElement], index: usize) -> Option<Scalar> {
        let OperandRepresentationElement::Scalar(scalar) = &representation_list[index] else {
            return None;
        };
        if scalar.get_unsigned_value() == 0 {
            return self.process_zero_scalar.then_some(*scalar);
        }
        Some(*scalar)
    }

    fn has_single_address_with_no_scalars(&self) -> bool {
        self.scalar_count == 0 && self.address_count == 1
    }

    fn get_address_index(&self) -> usize {
        self.last_address_index as usize
    }

    fn has_no_scalars(&self) -> bool {
        self.scalar_count == 0
    }
}

/// Perform register markup with explicit and implied register variable reference. Stands in for
/// `performRegisterMarkup`.
fn perform_register_markup(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    op_index: i32,
    func: Option<&Arc<dyn Function>>,
    primary_ref: Option<&Arc<dyn Reference>>,
    referenced_variable: Option<&Arc<dyn Variable>>,
    reg_index_map: &RegIndexMap,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    if func.is_none() || !options.do_reg_variable_markup {
        return false;
    }

    let mut primary_ref = primary_ref.cloned();
    let mut referenced_variable = referenced_variable.cloned();
    let mut referenced_register: Option<RegisterRef> = None;

    if let Some(rv) = referenced_variable.as_ref() {
        if rv.is_register_variable() {
            referenced_register = rv.get_register();
        }
    }
    if referenced_register.is_none() {
        for reference in instr.get_references_from() {
            if reference.operand_index() == crate::program::model::symbol::MNEMONIC
                && reference.reference_type().is_write()
            {
                let rv = with_program_mut(instr, |p| {
                    p.get_reference_manager().and_then(|rm| rm.get_referenced_variable(reference.as_ref()))
                })
                .map(Arc::<dyn Variable>::from);
                if let Some(rv) = rv {
                    if rv.is_register_variable() {
                        referenced_register = rv.get_register();
                        primary_ref = Some(reference.clone());
                        referenced_variable = Some(rv);
                        break;
                    }
                }
            }
        }
    }

    for reg in reg_index_map.keys() {
        let mut var_off: Option<Box<dyn VariableOffset>> = None;
        if registers_overlap(referenced_register.as_ref(), reg) {
            if let (Some(pref), Some(rv)) = (primary_ref.as_ref(), referenced_variable.as_ref()) {
                var_off = Some(Box::new(VariableOffsetImpl::from_reference(pref.as_ref(), rv.clone())));
            }
            primary_ref = None;
            referenced_variable = None;
        } else if options.include_inferred_variable_markup {
            let is_read_flag = is_read(reg, instr);
            let operand_is_only_reg = Instruction::get_register(instr, op_index).is_some();
            let (reg_addr, reg_size) = {
                let r = reg.borrow();
                (r.address().clone(), r.minimum_byte_size())
            };
            let reg_var = with_program_mut(instr, |p| {
                p.get_function_manager().and_then(|fm| {
                    fm.get_referenced_variable(&instr.get_min_address(), &reg_addr, reg_size, is_read_flag)
                })
            })
            .map(Arc::<dyn Variable>::from);

            if let Some(reg_var) = reg_var {
                let mut skip = false;
                if is_read_flag
                    && is_written(reg, instr)
                    && !has_register_write_reference(instr, reg)
                    && operand_is_only_reg
                {
                    let reg_write_var = with_program_mut(instr, |p| {
                        p.get_function_manager().and_then(|fm| {
                            fm.get_referenced_variable(&instr.get_min_address(), &reg_addr, reg_size, false)
                        })
                    })
                    .map(Arc::<dyn Variable>::from);
                    let same = reg_write_var.map(|w| w.is_equivalent(reg_var.as_ref())).unwrap_or(false);
                    if !same {
                        skip = true;
                    }
                }
                if !skip {
                    let mut offset = 0i64;
                    if operand_is_only_reg {
                        offset = reg_var
                            .get_variable_storage()
                            .map(|s| s.get_register_offset(&reg.borrow()))
                            .unwrap_or(0);
                        if offset < 0 {
                            offset = 0;
                        }
                    }
                    var_off = Some(Box::new(VariableOffsetImpl::new(reg_var, offset, !operand_is_only_reg, true)));
                }
            }
        }
        if let Some(mut vo) = var_off {
            vo.set_replaced_element_register(reg.clone());
            if let Some(idx) = reg_index_map.get(reg) {
                representation_list[idx] = OperandRepresentationElement::VariableOffset(Arc::from(vo));
            }
        }
    }
    primary_ref.is_none()
}

/// If `primary_ref` is not already shown in other markup, add to end of operand representation.
/// Stands in for `performExtendedMarkup`.
fn perform_extended_markup(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    primary_ref: Option<&Arc<dyn Reference>>,
    referenced_variable: Option<&Arc<dyn Variable>>,
    representation_list: &mut Vec<OperandRepresentationElement>,
) -> bool {
    if !options.always_show_primary_reference {
        return false;
    }
    let Some(primary_ref) = primary_ref else { return false };
    if representation_list.is_empty() {
        return false;
    }
    let Some(ref_rep) = get_reference_representation(options, cu, primary_ref.as_ref(), referenced_variable) else {
        return false;
    };
    let index = representation_list.len() - 1;
    let mut compound = OperandRepresentationListImpl::default();
    compound.push(representation_list[index].clone());
    compound.push(OperandRepresentationElement::Text(EXTENDED_REFERENCE_DELIMITER.to_string()));
    compound.push(ref_rep);
    representation_list[index] = OperandRepresentationElement::Nested(Arc::new(compound));
    true
}

/// Attempt to markup any or all addresses contained within the representation list. Stands in
/// for `performAddressMarkup`.
fn perform_address_markup(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    primary_ref: Option<&dyn Reference>,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    let Some(primary_ref) = primary_ref else { return false };
    if !primary_ref.is_memory_reference() {
        return false;
    }
    let ref_addr = primary_ref.to_address();
    for i in 0..representation_list.len() {
        if let OperandRepresentationElement::Address(addr) = &representation_list[i] {
            if *addr == ref_addr {
                representation_list[i] = get_memory_reference_label(options, instr, primary_ref);
                return true;
            }
        }
    }
    false
}

/// Attempt to markup any or all Scalars contained within the representation list. Stands in for
/// `performScalarMarkup`.
fn perform_scalar_markup(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    op_index: i32,
    func: Option<&Arc<dyn Function>>,
    mut primary_ref: Option<Arc<dyn Reference>>,
    mut referenced_variable: Option<Arc<dyn Variable>>,
    reg_index_map: &mut RegIndexMap,
    representation_list: &mut Vec<OperandRepresentationElement>,
) -> bool {
    let info = InstructionScalarInfo::new(representation_list, primary_ref.as_deref());
    if info.has_single_address_with_no_scalars() {
        let address_index = info.get_address_index();
        return markup_address_as_register(instr, primary_ref.as_deref(), representation_list, address_index)
            || markup_address_as_scalar(options, instr, primary_ref.as_deref(), representation_list, address_index);
    }

    if info.has_no_scalars() {
        return false;
    }

    let mut equates: Option<Vec<(i64, String)>> = None;
    let mut pcode: Option<Vec<PcodeOp>> = None;
    let size = representation_list.len();

    for i in 0..size {
        let Some(scalar) = info.get_scalar(representation_list, i) else { continue };

        if pcode.is_none() {
            pcode = Some(instr.get_pcode_for_operand(op_index));
        }
        let pcode_ref: &[PcodeOp] = pcode.as_deref().unwrap_or(&[]);

        let operand_register = find_associated_operand_register(&scalar, reg_index_map, pcode_ref);

        let mut handled = false;
        if operand_register.is_none() {
            if markup_scalar_with_memory_reference(options, instr, &scalar, i, primary_ref.as_deref(), representation_list) {
                primary_ref = None;
                referenced_variable = None;
                handled = true;
            }
        } else if primary_ref.as_deref().map(|r| r.is_stack_reference()).unwrap_or(false) {
            let reg = operand_register.clone().unwrap();
            let handled_stack = markup_scalar_with_stack_reference(
                options,
                &scalar,
                i,
                primary_ref.as_deref().unwrap(),
                referenced_variable.as_ref(),
                representation_list,
            );
            if handled_stack {
                reg_index_map.remove(&reg);
                return true;
            }
            return false;
        } else if is_register_associated_with_referenced_variable(referenced_variable.as_deref(), operand_register.as_ref()) {
            let reg = operand_register.clone().unwrap();
            if markup_scalar_with_referenced_register_variable(
                options,
                &scalar,
                i,
                primary_ref.as_deref(),
                referenced_variable.as_ref().unwrap(),
                representation_list,
            ) {
                primary_ref = None;
                referenced_variable = None;
                reg_index_map.remove(&reg);
                handled = true;
            }
        } else if markup_scalar_with_memory_reference(options, instr, &scalar, i, primary_ref.as_deref(), representation_list) {
            primary_ref = None;
            referenced_variable = None;
            handled = true;
        } else if markup_scalar_with_implied_register_variable(
            options,
            instr,
            func,
            &scalar,
            i,
            operand_register.as_ref(),
            representation_list,
        ) {
            reg_index_map.remove(operand_register.as_ref().unwrap());
            handled = true;
        }

        if handled {
            continue;
        }

        if equates.is_none() {
            let addr = instr.get_min_address();
            equates = Some(
                with_program_mut(instr, |p| {
                    p.get_equate_table().map(|t| {
                        t.equates_at_operand(&addr, op_index as i16)
                            .into_iter()
                            .map(|e| (e.value(), e.display_name()))
                            .collect::<Vec<_>>()
                    })
                })
                .unwrap_or_default(),
            );
        }
        markup_scalar_with_equate(&scalar, i, equates.as_deref().unwrap_or(&[]), representation_list);
    }
    primary_ref.is_none()
}

fn markup_address_as_register(
    instr: &dyn Instruction,
    primary_ref: Option<&dyn Reference>,
    representation_list: &mut [OperandRepresentationElement],
    address_index: usize,
) -> bool {
    if primary_ref.is_some() {
        return false;
    }
    let addr = match &representation_list[address_index] {
        OperandRepresentationElement::Address(a) => a.clone(),
        _ => return false,
    };
    if let Some(reg) = instr.get_program().get_register_at(&addr) {
        representation_list[address_index] = OperandRepresentationElement::Text(reg.borrow().name().to_string());
        return true;
    }
    false
}

fn markup_address_as_scalar(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    primary_ref: Option<&dyn Reference>,
    representation_list: &mut [OperandRepresentationElement],
    address_index: usize,
) -> bool {
    let addr = match &representation_list[address_index] {
        OperandRepresentationElement::Address(a) => a.clone(),
        _ => return primary_ref.is_none(),
    };
    let space = addr.space().clone();
    let mut offset = addr.offset();
    let unit_size = space.unit_size();
    if unit_size != 1 {
        if crate::util::math_utilities::MathUtilities::unsigned_modulo(offset, unit_size as i64) == 0 {
            offset = crate::util::math_utilities::MathUtilities::unsigned_divide(offset, unit_size as i64);
        } else {
            return false;
        }
    } else {
        offset = crate::util::math_utilities::MathUtilities::unsigned_divide(offset, unit_size as i64);
    }
    let scalar = Scalar::new_with_signedness(space.size() as u8, offset, false);
    if markup_scalar_with_memory_reference(options, instr, &scalar, address_index, primary_ref, representation_list) {
        return true;
    }
    primary_ref.is_none()
}

/// Markup scalar with implied register variable reference if one can be determined. Stands in
/// for `markupScalarWithImpliedRegisterVariable`.
fn markup_scalar_with_implied_register_variable(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    func: Option<&Arc<dyn Function>>,
    scalar_to_replace: &Scalar,
    scalar_index: usize,
    associated_register: Option<&RegisterRef>,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    if func.is_none() || !options.do_reg_variable_markup || !options.include_inferred_variable_markup {
        return false;
    }
    let Some(associated_register) = associated_register else { return false };

    let scalar_value = scalar_to_replace.get_value();
    if scalar_to_replace.is_signed() && scalar_value <= 0 {
        return false;
    }

    let (reg_addr, reg_size) = {
        let reg = associated_register.borrow();
        (reg.address().clone(), reg.minimum_byte_size())
    };
    let reg_var = with_program_mut(instr, |p| {
        p.get_function_manager()
            .and_then(|fm| fm.get_referenced_variable(&instr.get_min_address(), &reg_addr, reg_size, true))
    })
    .map(Arc::<dyn Variable>::from);
    let Some(reg_var) = reg_var else { return false };

    let dt = remove_typedefs(reg_var.get_data_type());
    let Some(inner_dt) = dt.as_pointer().and_then(|p| p.get_data_type()) else { return false };
    let inner_dt = remove_typedefs(inner_dt);
    if inner_dt.as_composite().is_none() || scalar_value > inner_dt.get_length() as i64 {
        return false;
    }

    let mut variable_offset = VariableOffsetImpl::new(reg_var, scalar_value, true, true);
    variable_offset.set_replaced_element_scalar(*scalar_to_replace, options.include_scalar_reference_adjustment);
    representation_list[scalar_index] = OperandRepresentationElement::VariableOffset(Arc::new(variable_offset));
    true
}

fn remove_typedefs(dt: Box<dyn DataType>) -> Box<dyn DataType> {
    if dt.is_typedef() {
        if let Some(base) = dt.typedef_base_data_type() {
            return base;
        }
    }
    dt
}

fn markup_scalar_with_equate(
    scalar_to_replace: &Scalar,
    scalar_index: usize,
    equates: &[(i64, String)],
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    if let Some(name) = find_equate(scalar_to_replace, equates) {
        representation_list[scalar_index] = OperandRepresentationElement::Text(name);
        return true;
    }
    false
}

fn markup_scalar_with_memory_reference(
    options: &CodeUnitFormatOptions,
    instr: &dyn Instruction,
    scalar_to_replace: &Scalar,
    scalar_index: usize,
    primary_ref: Option<&dyn Reference>,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    let Some(primary_ref) = primary_ref else { return false };
    if !primary_ref.is_memory_reference() {
        return false;
    }
    let label = get_memory_reference_label(options, instr, primary_ref);
    let rep_obj = add_scalar_adjustment(
        options,
        label,
        &primary_ref.to_address(),
        Some(scalar_to_replace),
        representation_list.len() == 1,
    );
    match rep_obj {
        Some(rep_obj) => {
            representation_list[scalar_index] = rep_obj;
            true
        }
        None => false,
    }
}

fn markup_scalar_with_stack_reference(
    options: &CodeUnitFormatOptions,
    scalar_to_replace: &Scalar,
    scalar_index: usize,
    primary_ref: &dyn Reference,
    referenced_variable: Option<&Arc<dyn Variable>>,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    if !options.do_stack_variable_markup {
        return false;
    }
    if let Some(var_rep) =
        get_variable_reference_representation(options, Some(primary_ref), referenced_variable, Some(scalar_to_replace))
    {
        representation_list[scalar_index] = var_rep;
    }
    true
}

fn markup_scalar_with_referenced_register_variable(
    options: &CodeUnitFormatOptions,
    scalar_to_replace: &Scalar,
    scalar_index: usize,
    primary_reference: Option<&dyn Reference>,
    referenced_variable: &Arc<dyn Variable>,
    representation_list: &mut [OperandRepresentationElement],
) -> bool {
    if !options.do_reg_variable_markup {
        return false;
    }
    if let Some(var_rep) = get_variable_reference_representation(
        options,
        primary_reference,
        Some(referenced_variable),
        Some(scalar_to_replace),
    ) {
        representation_list[scalar_index] = var_rep;
    }
    true
}

fn is_register_associated_with_referenced_variable(
    variable: Option<&dyn Variable>,
    register: Option<&RegisterRef>,
) -> bool {
    let (Some(variable), Some(register)) = (variable, register) else { return false };
    if !variable.is_register_variable() {
        return false;
    }
    match variable.get_register() {
        Some(var_reg) => *var_reg.borrow() == *register.borrow(),
        None => false,
    }
}

/// Add scalar adjustment markup to the specified sub-operand object. Stands in for
/// `addScalarAdjustment`.
fn add_scalar_adjustment(
    options: &CodeUnitFormatOptions,
    op_obj: OperandRepresentationElement,
    addr: &Address,
    original_scalar: Option<&Scalar>,
    scalar_operand: bool,
) -> Option<OperandRepresentationElement> {
    let Some(original_scalar) = original_scalar else { return Some(op_obj) };

    let original_value: i64 = if addr.is_stack_address() && original_scalar.bit_length() as i32 == addr.space().size() {
        original_scalar.get_signed_value()
    } else {
        original_scalar.get_unsigned_value() as i64
    };

    let addr_offset = addr.addressable_word_offset();

    if original_value == addr_offset || original_value == addr.offset() {
        return Some(op_obj);
    }

    let mut list = OperandRepresentationListImpl::default();
    if addr.is_memory_address() {
        list.push(OperandRepresentationElement::Text("offset ".to_string()));

        for &element in SHIFT_CASES {
            if original_value != 0 && ((addr_offset as u64) >> element) as i64 == original_value {
                list.push(op_obj.clone());
                if options.include_scalar_reference_adjustment {
                    list.push(OperandRepresentationElement::Text(" >>".to_string()));
                    list.push(OperandRepresentationElement::Text(element.to_string()));
                }
                return Some(OperandRepresentationElement::Nested(Arc::new(list)));
            }
        }

        for &element in MASK_CASES {
            if (addr_offset & element) == original_value {
                list.push(op_obj.clone());
                if options.include_scalar_reference_adjustment {
                    list.push(OperandRepresentationElement::Text(" &".to_string()));
                    list.push(OperandRepresentationElement::Text(format!("0x{element:x}")));
                }
                return Some(OperandRepresentationElement::Nested(Arc::new(list)));
            }
        }

        if !scalar_operand {
            return None;
        }
    }

    list.push(op_obj);
    if options.include_scalar_reference_adjustment {
        let mut delta = original_value - addr_offset;
        if delta < 0 {
            list.push(OperandRepresentationElement::Character('-'));
            delta = -delta;
        } else {
            list.push(OperandRepresentationElement::Character('+'));
        }
        list.push(OperandRepresentationElement::Scalar(Scalar::new(addr.space().size() as u8, delta)));
    }
    Some(OperandRepresentationElement::Nested(Arc::new(list)))
}

/// Build a suitable variable or stack reference representation with optional scalar replacement.
/// Stands in for `getVariableReferenceRepresentation`.
fn get_variable_reference_representation(
    options: &CodeUnitFormatOptions,
    reference: Option<&dyn Reference>,
    var: Option<&Arc<dyn Variable>>,
    replaced_scalar: Option<&Scalar>,
) -> Option<OperandRepresentationElement> {
    if let Some(var) = var {
        let reference = reference?;
        let mut var_offset = VariableOffsetImpl::from_reference(reference, var.clone());
        if let Some(scalar) = replaced_scalar {
            var_offset.set_replaced_element_scalar(*scalar, options.include_scalar_reference_adjustment);
        }
        return Some(OperandRepresentationElement::VariableOffset(Arc::new(var_offset)));
    }
    let reference = reference?;
    if reference.is_stack_reference() {
        let stack_offset = reference.as_stack_reference().map(StackReference::stack_offset).unwrap_or(0);
        let mut list = OperandRepresentationListImpl::default();
        list.push(OperandRepresentationElement::Text("Stack".to_string()));
        list.push(OperandRepresentationElement::Character('['));
        list.push(OperandRepresentationElement::Scalar(Scalar::new_with_signedness(32, stack_offset as i64, true)));
        list.push(OperandRepresentationElement::Character(']'));
        return add_scalar_adjustment(
            options,
            OperandRepresentationElement::Nested(Arc::new(list)),
            &reference.to_address(),
            replaced_scalar,
            false,
        );
    }
    None
}

/// Returns a marked-up representation of the reference destination. Stands in for
/// `getReferenceRepresentationString`.
fn get_reference_representation_string_impl(
    options: &CodeUnitFormatOptions,
    from_code_unit: &dyn CodeUnit,
    reference: &dyn Reference,
) -> Option<String> {
    let min_addr = from_code_unit.get_min_address();
    let to_addr = reference.to_address();
    let ref_var = with_program_mut(from_code_unit, |p| {
        p.get_function_manager().and_then(|fm| fm.get_referenced_variable(&min_addr, &to_addr, 0, false))
    })
    .map(Arc::<dyn Variable>::from);

    get_reference_representation(options, from_code_unit, reference, ref_var.as_ref()).map(|e| e.to_string())
}

/// Get a representation object corresponding to the specified reference. Stands in for the
/// private `getReferenceRepresentation`.
fn get_reference_representation(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    reference: &dyn Reference,
    var: Option<&Arc<dyn Variable>>,
) -> Option<OperandRepresentationElement> {
    if !reference.is_external_reference()
        && (var.is_some() || reference.is_stack_reference() || reference.is_register_reference())
    {
        return get_variable_reference_representation(options, Some(reference), var, None);
    }

    if reference.is_memory_reference() {
        if let Some(offset_ref) = reference.as_offset_reference() {
            return Some(get_offset_reference_representation(options, cu, offset_ref, reference));
        }
    }

    if reference.is_memory_reference() || reference.is_external_reference() {
        return Some(get_memory_reference_label(options, cu, reference));
    }

    None
}

fn get_offset_reference_representation(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    offset_ref: &dyn OffsetReference,
    original_ref: &dyn Reference,
) -> OperandRepresentationElement {
    let base_ref = MemReferenceImpl::new(
        original_ref.from_address(),
        offset_ref.base_address(),
        RefType::Data,
        original_ref.source(),
        original_ref.operand_index(),
        original_ref.is_primary(),
    );
    let base_ref_obj = get_memory_reference_label(options, cu, &base_ref);
    let offset = offset_ref.offset();
    let sign = if offset < 0 { "" } else { "+" };
    let offset_scalar = Scalar::new_with_signedness(64, offset, true);
    let mut list = OperandRepresentationListImpl::default();
    list.push(base_ref_obj);
    list.push(OperandRepresentationElement::Text(sign.to_string()));
    list.push(OperandRepresentationElement::Scalar(offset_scalar));
    OperandRepresentationElement::Nested(Arc::new(list))
}

fn same_block(a: Option<&Arc<dyn crate::program::model::mem::MemoryBlock>>, b: Option<&Arc<dyn crate::program::model::mem::MemoryBlock>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.get_name() == b.get_name(),
        _ => false,
    }
}

/// Get a LabelString object which corresponds to the specified memory reference. Stands in for
/// the private `getMemoryReferenceLabel`.
fn get_memory_reference_label(
    options: &CodeUnitFormatOptions,
    from_code_unit: &dyn CodeUnit,
    reference: &dyn Reference,
) -> OperandRepresentationElement {
    let program = from_code_unit.get_program();
    let to_address = reference.to_address();

    let mut with_block_name = false;
    let mut ref_block = None;
    if to_address.is_memory_address() {
        if let Some(mem) = program.get_memory() {
            ref_block = mem.get_block(&to_address);
            if options.show_block_name == ShowBlockName::Always {
                with_block_name = true;
            } else if options.show_block_name == ShowBlockName::NonLocal {
                let block = mem.get_block(&from_code_unit.get_min_address());
                with_block_name = !same_block(block.as_ref(), ref_block.as_ref());
            }
        }
    }

    let to_symbol = with_program_mut(from_code_unit, |p| {
        p.get_symbol_table().and_then(|st| st.get_symbol_for_reference(reference).ok().flatten())
    });

    let result = match &to_symbol {
        Some(sym) => get_symbol_label_string(options, from_code_unit, sym.as_ref(), &from_code_unit.get_min_address()),
        None => to_address.to_string(),
    };
    let result = add_block_name(&result, ref_block.as_deref(), with_block_name);

    let label_type = match &to_symbol {
        Some(sym) if sym.is_external() => LabelType::External,
        _ => LabelType::CodeLabel,
    };
    let label = LabelString::new(result, label_type);

    let reference_type = reference.reference_type();
    if options.follow_referenced_pointers && (reference_type.is_indirect() || reference_type == RefType::Read) {
        if let Some(ext_label) = get_extended_pointer_reference_markup(options, from_code_unit, reference) {
            let mut list = OperandRepresentationListImpl::default();
            list.push(OperandRepresentationElement::Text(EXTENDED_INDIRECT_REFERENCE_DELIMITER.to_string()));
            list.push(OperandRepresentationElement::Label(ext_label));
            return OperandRepresentationElement::Nested(Arc::new(list));
        }
    }

    OperandRepresentationElement::Label(label)
}

fn get_extended_pointer_reference_markup(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    reference: &dyn Reference,
) -> Option<LabelString> {
    let to_address = reference.to_address();

    let has_defined_data =
        with_program_mut(cu, |p| p.get_listing().and_then(|l| l.get_defined_data_at(&to_address))).is_some();
    if !has_defined_data {
        return None;
    }

    let references_from =
        with_program_mut(cu, |p| p.get_reference_manager().map(|rm| rm.get_references_from(to_address.clone())))
            .unwrap_or_default();
    if references_from.len() != 1 || references_from[0].reference_type() != RefType::Data {
        return None;
    }
    let target_ref = references_from[0].as_ref();

    let symbol =
        with_program_mut(cu, |p| p.get_symbol_table().and_then(|st| st.get_symbol_for_reference(target_ref).ok().flatten()));
    if let Some(symbol) = symbol {
        if !symbol.is_dynamic() {
            let result = get_symbol_label_string(options, cu, symbol.as_ref(), &reference.from_address());
            let label_type = if symbol.is_external() { LabelType::External } else { LabelType::CodeLabel };
            return Some(LabelString::with_symbol(result, symbol, label_type));
        }
    }
    None
}

fn add_block_name(name: &str, ref_block: Option<&dyn crate::program::model::mem::MemoryBlock>, with_block_name: bool) -> String {
    if with_block_name {
        if let Some(block) = ref_block {
            return format!("{}{}{}", block.get_name(), ADDRESS_SEPARATOR_CHAR, name);
        }
    }
    name.to_string()
}

fn add_namespace(
    options: &CodeUnitFormatOptions,
    cu: &dyn CodeUnit,
    parent_namespace: Option<Arc<dyn Namespace>>,
    name: &str,
    markup_address: &Address,
) -> String {
    let Some(parent_namespace) = parent_namespace else { return name.to_string() };
    if options.show_namespace == ShowNamespace::Never {
        return name.to_string();
    }
    if parent_namespace.get_id() == crate::program::model::symbol::GLOBAL_NAMESPACE_ID {
        return name.to_string();
    }

    let to_namespace =
        with_program_mut(cu, |p| p.get_symbol_table().and_then(|st| st.get_namespace(markup_address).ok().flatten()));
    let is_local = to_namespace.map(|ns| ns.get_id() == parent_namespace.get_id()).unwrap_or(false);
    if is_local && options.show_namespace == ShowNamespace::NonLocal {
        return name.to_string();
    }
    if !is_local && options.show_namespace == ShowNamespace::Local {
        return name.to_string();
    }

    let mut namespace_name = if is_local { options.local_prefix_override.clone() } else { None };
    if namespace_name.is_none() {
        namespace_name = Some(if !options.show_library_in_namespace {
            namespace_utils::get_namespace_path_without_library(Some(parent_namespace.clone()))
        } else {
            parent_namespace.get_name_with_path(true)
        });
    }
    let mut namespace_name = namespace_name.unwrap_or_default();
    if !namespace_name.is_empty() && !namespace_name.ends_with(crate::program::model::symbol::DELIMITER) {
        namespace_name.push_str(crate::program::model::symbol::DELIMITER);
    }
    format!("{namespace_name}{name}")
}

/// Generate a string for the given symbol, accounting for offcut situations. Stands in for the
/// private `getSymbolLabelString`.
fn get_symbol_label_string(
    options: &CodeUnitFormatOptions,
    ctx_cu: &dyn CodeUnit,
    symbol: &dyn Symbol,
    markup_address: &Address,
) -> String {
    let symbol_address = symbol.get_address();
    if symbol_address.is_memory_address() {
        let cu_at = with_program_mut(ctx_cu, |p| p.get_listing().and_then(|l| l.get_code_unit_containing(&symbol_address)));
        if let Some(cu_at) = cu_at.as_deref() {
            if is_offcut(&symbol_address, Some(cu_at)) {
                return get_offcut_label_string_impl(options, &symbol_address, cu_at, Some(markup_address), symbol);
            } else if is_string_data(cu_at) {
                if let Some(data) = cu_at.as_data() {
                    return get_label_string_for_string_data(options, data, symbol);
                }
            }
        }
    }
    let name = symbol.get_name().to_string();
    let display_name = add_namespace(options, ctx_cu, symbol.get_parent_namespace(), &name, markup_address);
    options.simplify_template(&display_name)
}

fn is_string_data(cu: &dyn CodeUnit) -> bool {
    cu.as_data().map(|d| d.has_string_value()).unwrap_or(false)
}

fn get_label_string_for_string_data(options: &CodeUnitFormatOptions, data: &dyn Data, symbol: &dyn Symbol) -> String {
    if !symbol.is_dynamic() {
        return options.simplify_template(symbol.get_name());
    }
    let data_type = data.get_base_data_type();
    let buf: &dyn MemBuffer = data;
    let settings: &dyn Settings = data;
    let prefix = data_type.get_default_label_prefix_for_data(buf, settings, data.get_length(), &options.display_options);
    match prefix {
        Some(prefix) => format!("{prefix}{UNDERSCORE}{}", DefaultSymbolUtilities.get_address_string(&symbol.get_address())),
        None => symbol.get_name().to_string(),
    }
}

fn is_offcut(address: &Address, cu: Option<&dyn CodeUnit>) -> bool {
    cu.map(|c| c.get_min_address() != *address).unwrap_or(false)
}

fn get_offcut_data_string(options: &CodeUnitFormatOptions, offcut_address: &Address, data: &dyn Data) -> String {
    let offcut_symbol =
        with_program_mut(data, |p| p.get_symbol_table().and_then(|st| st.get_primary_symbol(offcut_address).ok().flatten()));
    let Some(offcut_symbol) = offcut_symbol else {
        return offcut_address.to_string();
    };
    let data_address = data.get_min_address();
    let diff = offcut_address.subtract(&data_address) as i32;
    let is_dynamic_string_offset_label = offcut_symbol.is_dynamic() && data.has_string_value();
    if is_dynamic_string_offset_label && !options.show_offcut_info {
        return trim_offset(offcut_symbol.get_name());
    }
    if is_dynamic_string_offset_label && options.display_options.use_abbreviated_form() {
        let address_string = DefaultSymbolUtilities.get_address_string(&data_address);
        let prefix = get_prefix_for_string_data(options, data, diff, data.get_base_data_type().as_ref());
        return add_offcut_information(prefix.as_deref().unwrap_or(""), &address_string, diff, options.show_offcut_info);
    }
    let simplify = !is_dynamic_string_offset_label;
    let decorate = false;
    get_default_offcut_string(options, offcut_symbol.as_ref(), data, diff as i64, decorate, simplify)
}

fn trim_offset(name: &str) -> String {
    match name.rfind('_') {
        Some(idx) if idx > 0 => name[..idx].to_string(),
        _ => name.to_string(),
    }
}

/// Generate label string for an offcut address within an instruction. Stands in for
/// `getOffcutLabelStringForInstruction`.
fn get_offcut_label_string_for_instruction(
    options: &CodeUnitFormatOptions,
    offcut_address: &Address,
    instruction: &dyn Instruction,
    markup_address: Option<&Address>,
    symbol: &dyn Symbol,
) -> String {
    let instruction_address = instruction.get_min_address();
    let diff = offcut_address.subtract(&instruction_address);
    let decorate = false;
    let simplify = true;
    if symbol.is_dynamic() {
        let containing_symbol = with_program_mut(instruction, |p| {
            p.get_symbol_table().and_then(|st| st.get_primary_symbol(&instruction_address).ok().flatten())
        });
        if let Some(containing_symbol) = containing_symbol {
            let mut display_name = containing_symbol.get_name().to_string();
            if let Some(markup_address) = markup_address {
                display_name =
                    add_namespace(options, instruction, containing_symbol.get_parent_namespace(), &display_name, markup_address);
            }
            return format!("{}{PLUS}{}", options.simplify_template(&display_name), DefaultSymbolUtilities.get_diff_string(diff));
        }
    }
    get_default_offcut_string(options, symbol, instruction, diff, decorate, simplify)
}

fn add_offcut_information(prefix: &str, address_string: &str, diff: i32, decorate: bool) -> String {
    if !decorate {
        return prefix.to_string();
    }
    format!("{prefix}{UNDERSCORE}{address_string}{PLUS}{}", DefaultSymbolUtilities.get_diff_string(diff as i64))
}

fn get_prefix_for_string_data(options: &CodeUnitFormatOptions, data: &dyn Data, diff: i32, dt: &dyn DataType) -> Option<String> {
    if data.has_string_value() {
        let len = data.get_length();
        let buf: &dyn MemBuffer = data;
        let settings: &dyn Settings = data;
        dt.get_default_offcut_label_prefix(buf, settings, len, &options.display_options, diff)
    } else {
        None
    }
}

fn get_default_offcut_string(
    options: &CodeUnitFormatOptions,
    symbol: &dyn Symbol,
    cu: &dyn CodeUnit,
    diff: i64,
    decorate: bool,
    simplify: bool,
) -> String {
    let mut name = symbol.get_name().to_string();
    if simplify {
        name = options.simplify_template(&name);
    }
    if decorate {
        let mut cu_location = cu.get_min_address().to_string();
        if let Some(primary) = cu.get_primary_symbol() {
            if !primary.is_dynamic() {
                cu_location = primary.get_name().to_string();
            }
        }
        return format!("{name} ({cu_location}{PLUS}{})", DefaultSymbolUtilities.get_diff_string(diff));
    }
    name
}

/// Generate an offcut label string. Stands in for the public `getOffcutLabelString`.
fn get_offcut_label_string_impl(
    options: &CodeUnitFormatOptions,
    offcut_address: &Address,
    cu: &dyn CodeUnit,
    markup_address: Option<&Address>,
    symbol: &dyn Symbol,
) -> String {
    if let Some(instr) = cu.as_instruction() {
        return get_offcut_label_string_for_instruction(options, offcut_address, instr, markup_address, symbol);
    }
    if let Some(data) = cu.as_data() {
        return get_offcut_data_string(options, offcut_address, data);
    }
    String::new()
}

/// Returns a formatted data value for the specified data unit. Stands in for the public
/// `getDataValueRepresentation`.
fn get_data_value_representation_impl(options: &CodeUnitFormatOptions, data: &dyn Data) -> Box<dyn OperandRepresentationList> {
    let reference = data.get_primary_reference(0);
    let mut list = OperandRepresentationListImpl::default();

    let data_type = data.get_data_type();
    let length = data.get_length();

    if (length != 0 || !data_type.is_zero_length()) && data_type.get_length() > length {
        list.push(OperandRepresentationElement::Text(format!(
            "Data type \"{}\" is too big for available space. Size = {} bytes, available = {} bytes",
            data_type.get_display_name(),
            data_type.get_length(),
            length
        )));
        list.set_has_error(true);
        list.set_primary_reference_hidden(reference.is_some());
        return Box::new(list);
    }

    let data_value = Data::get_value(data);

    let base_data_type = data.get_base_data_type();
    if let Some(reference) = reference.as_ref() {
        if base_data_type.as_composite().is_none() && !base_data_type.is_array() {
            let parent = data.get_parent();
            let parent_is_union = parent.as_ref().map(|p| p.get_base_data_type().is_union()).unwrap_or(false);
            let value_is_address = data_value.as_ref().and_then(|v| v.downcast_ref::<Address>()).is_some();

            if !parent_is_union || base_data_type.as_pointer().is_some() || value_is_address {
                if let Some(ref_rep) = get_reference_representation(options, data, reference.as_ref(), None) {
                    list.push(ref_rep);
                    return Box::new(list);
                }
            }
        }
    }

    if let Some(scalar) = data_value.as_ref().and_then(|v| v.downcast_ref::<Scalar>()) {
        let min_addr = data.get_min_address();
        let value = scalar.get_value();
        let equate_name = with_program_mut(data, |p| {
            p.get_equate_table().and_then(|t| t.equate_at_value(&min_addr, 0, value).map(|e| e.display_name()))
        });
        if let Some(name) = equate_name {
            list.push(OperandRepresentationElement::Text(name));
            list.set_primary_reference_hidden(reference.is_some());
            return Box::new(list);
        }
    }

    if let Some(dynamic) = data_type.as_dynamic() {
        if dynamic.can_specify_length() {
            let buf: &dyn MemBuffer = data;
            let preferred_length = dynamic.get_dynamic_length(buf, length);
            if preferred_length > length {
                list.set_has_error(true);
            }
        }
    }

    list.set_primary_reference_hidden(reference.is_some());

    if data.is_defined() && data_value.is_none() {
        let mut base_dt = data.get_data_type();
        if base_dt.is_typedef() {
            if let Some(inner) = base_dt.typedef_base_data_type() {
                base_dt = inner;
            }
        }
        if base_dt.as_pointer().is_some() {
            let buf: &dyn MemBuffer = data;
            let settings: &dyn Settings = data;
            let mut messages = Vec::new();
            pointer_data_type::get_address_value(buf, base_dt.get_length(), settings, &mut |m| messages.push(m));
            for m in messages {
                list.push(OperandRepresentationElement::Text(m));
            }
        }
        list.set_has_error(true);
    }

    if list.is_empty() {
        let buf: &dyn MemBuffer = data;
        let settings: &dyn Settings = data;
        list.push(OperandRepresentationElement::Text(data_type.get_representation(buf, settings, length)));
    }

    if let Some(addr) = data_value.as_ref().and_then(|v| v.downcast_ref::<Address>()) {
        if reference.is_none() {
            let program = data.get_program();
            let has_block = program.get_memory().and_then(|m| m.get_block(addr)).is_some();
            if !has_block {
                list.set_has_error(true);
            }
        }
    }

    Box::new(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address as Addr, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::symbol::{ExternalLocation, ExternalReference, ReferenceIterator, SourceType, SymbolType};
    use crate::program::model::util::PropertySet;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn mock_address(offset: i64) -> Addr {
        Addr::new(ram_space(), offset)
    }

    struct MockProgram;

    impl crate::program::model::listing::program::Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            String::new()
        }
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    struct MockSymbol {
        name: String,
        address: Addr,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Addr {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_dynamic(&self) -> bool {
            false
        }
    }

    struct MockInstruction {
        address: Addr,
        label: Option<Arc<dyn Symbol>>,
    }

    impl MemBuffer for MockInstruction {
        fn get_address(&self) -> Addr {
            self.address.clone()
        }
    }
    impl PropertySet for MockInstruction {}

    impl CodeUnit for MockInstruction {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            self.address.to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            self.label.clone()
        }
        fn get_min_address(&self) -> Addr {
            self.address.clone()
        }
        fn get_max_address(&self) -> Addr {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            2
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0, 0])
        }
        fn get_bytes_in_code_unit(&self, _buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Addr) -> bool {
            *test_addr == self.address
        }
        fn compare_to(&self, addr: &Addr) -> i32 {
            (self.address.offset() - addr.offset()) as i32
        }
        fn add_mnemonic_reference(&mut self, _ref_addr: Addr, _ref_type: crate::program::model::symbol::RefType, _source_type: SourceType) {}
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Addr) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Addr, _ref_type: crate::program::model::symbol::RefType, _source_type: SourceType) {}
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Addr) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: crate::program::model::symbol::RefType) {}
        fn set_register_reference(&mut self, _op_index: i32, _reg: &Register, _source_type: SourceType, _ref_type: crate::program::model::symbol::RefType) {}
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Addr> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    /// Mock proving the trait is object-safe and exercising real (non-default)
    /// `get_mnemonic_representation`/`get_representation_string` behavior. `MockInstruction` is
    /// neither `Data` nor `Instruction` (`as_data`/`as_instruction` both default to `None`), so
    /// `get_representation_string` falls back to treating operand 0 like a data value, which is
    /// unsupported here -- exercising the `<UNSUPPORTED>` fallback path alongside real mnemonic
    /// formatting.
    #[test]
    fn trait_object_usage_is_object_safe_and_formats_mnemonic() {
        let fmt: Box<dyn CodeUnitFormat> = Box::new(DefaultCodeUnitFormat::new());
        let instr = MockInstruction { address: mock_address(0x1000), label: None };
        assert_eq!(fmt.get_mnemonic_representation(&instr), "MOV");
        assert_eq!(fmt.get_representation_string(&instr), "MOV <UNSUPPORTED>");
        assert_eq!(fmt.get_show_block_name(), ShowBlockName::Never);
    }

    #[test]
    fn show_data_mutability_prefixes_const_for_constant_data() {
        // Exercise the `show_data_mutability` branch via `as_data`, using the existing
        // `data.rs` `MockData` shape inline (kept minimal: only what `get_mnemonic_representation`
        // touches).
        struct MockData {
            address: Addr,
        }
        impl MemBuffer for MockData {
            fn get_address(&self) -> Addr {
                self.address.clone()
            }
        }
        impl PropertySet for MockData {}
        impl CodeUnit for MockData {
            fn get_address_string(&self, _s: bool, _p: bool) -> String {
                self.address.to_string()
            }
            fn get_label(&self) -> Option<String> {
                None
            }
            fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
                Vec::new()
            }
            fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
                None
            }
            fn get_min_address(&self) -> Addr {
                self.address.clone()
            }
            fn get_max_address(&self) -> Addr {
                self.address.clone()
            }
            fn get_mnemonic_string(&self) -> String {
                "db".to_string()
            }
            fn get_comment(&self, _c: CommentType) -> Option<String> {
                None
            }
            fn get_comment_as_array(&self, _c: CommentType) -> Vec<String> {
                Vec::new()
            }
            fn set_comment(&mut self, _c: CommentType, _v: Option<String>) {}
            fn set_comment_as_array(&mut self, _c: CommentType, _v: &[String]) {}
            fn get_length(&self) -> i32 {
                1
            }
            fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
                Ok(vec![0])
            }
            fn get_bytes_in_code_unit(&self, _b: &mut [u8], _o: i32) -> Result<(), MemoryAccessException> {
                Ok(())
            }
            fn contains(&self, a: &Addr) -> bool {
                *a == self.address
            }
            fn compare_to(&self, a: &Addr) -> i32 {
                (self.address.offset() - a.offset()) as i32
            }
            fn add_mnemonic_reference(&mut self, _a: Addr, _t: crate::program::model::symbol::RefType, _s: SourceType) {}
            fn remove_mnemonic_reference(&mut self, _a: &Addr) {}
            fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_operand_references(&self, _i: i32) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_primary_reference(&self, _i: i32) -> Option<Arc<dyn Reference>> {
                None
            }
            fn add_operand_reference(&mut self, _i: i32, _a: Addr, _t: crate::program::model::symbol::RefType, _s: SourceType) {}
            fn remove_operand_reference(&mut self, _i: i32, _a: &Addr) {}
            fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
                Box::new(crate::program::model::symbol::EmptyReferenceIterator)
            }
            fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
                Arc::new(MockProgram)
            }
            fn get_external_reference(&self, _o: i32) -> Option<Arc<dyn ExternalReference>> {
                None
            }
            fn remove_external_reference(&mut self, _o: i32) {}
            fn set_primary_memory_reference(&mut self, _r: Arc<dyn Reference>) {}
            fn set_stack_reference(&mut self, _o: i32, _off: i32, _s: SourceType, _t: crate::program::model::symbol::RefType) {}
            fn set_register_reference(&mut self, _o: i32, _r: &Register, _s: SourceType, _t: crate::program::model::symbol::RefType) {}
            fn get_num_operands(&self) -> i32 {
                1
            }
            fn get_address(&self, _o: i32) -> Option<Addr> {
                None
            }
            fn get_scalar(&self, _o: i32) -> Option<Scalar> {
                None
            }
            fn as_data(&self) -> Option<&dyn Data> {
                Some(self)
            }
        }
        impl crate::docking::settings::settings::Settings for MockData {}
        impl Data for MockData {
            fn get_value(&self) -> Option<Box<dyn std::any::Any>> {
                None
            }
            fn get_value_class(&self) -> Option<std::any::TypeId> {
                None
            }
            fn has_string_value(&self) -> bool {
                false
            }
            fn is_constant(&self) -> bool {
                true
            }
            fn is_writable(&self) -> bool {
                false
            }
            fn is_volatile(&self) -> bool {
                false
            }
            fn is_defined(&self) -> bool {
                true
            }
            fn get_data_type(&self) -> Box<dyn DataType> {
                struct EmptyDt;
                impl DataType for EmptyDt {}
                Box::new(EmptyDt)
            }
            fn get_base_data_type(&self) -> Box<dyn DataType> {
                struct EmptyDt;
                impl DataType for EmptyDt {}
                Box::new(EmptyDt)
            }
            fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
                Vec::new()
            }
            fn add_value_reference(&mut self, _ref_addr: Addr, _ref_type: Box<dyn crate::program::seam_stubs::RefType>) {}
            fn remove_value_reference(&mut self, _ref_addr: Addr) {}
            fn get_field_name(&self) -> Option<String> {
                None
            }
            fn get_path_name(&self) -> String {
                String::new()
            }
            fn get_component_path_name(&self) -> String {
                String::new()
            }
            fn is_pointer(&self) -> bool {
                false
            }
            fn is_union(&self) -> bool {
                false
            }
            fn is_structure(&self) -> bool {
                false
            }
            fn is_array(&self) -> bool {
                false
            }
            fn is_dynamic(&self) -> bool {
                false
            }
            fn get_parent(&self) -> Option<Box<dyn Data>> {
                None
            }
            fn get_root(&self) -> Box<dyn Data> {
                unimplemented!("not exercised by this smoke test")
            }
            fn get_root_offset(&self) -> i32 {
                0
            }
            fn get_parent_offset(&self) -> i32 {
                0
            }
            fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_path(&self) -> Vec<i32> {
                Vec::new()
            }
            fn get_num_components(&self) -> i32 {
                0
            }
            #[allow(deprecated)]
            fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
                None
            }
            fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_index(&self) -> i32 {
                -1
            }
            fn get_component_level(&self) -> i32 {
                0
            }
            fn get_default_value_representation(&self) -> String {
                String::new()
            }
            fn get_default_label_prefix(
                &self,
                _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
            ) -> Option<String> {
                None
            }
        }

        let fmt = DefaultCodeUnitFormat::with_options(CodeUnitFormatOptions {
            show_data_mutability: true,
            ..CodeUnitFormatOptions::new()
        });
        let data = MockData { address: mock_address(0x2000) };
        assert_eq!(fmt.get_mnemonic_representation(&data), "const db");
    }
}
