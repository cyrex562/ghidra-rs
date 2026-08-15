use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::dwarf::dwarf_register_mappings::DWARFRegisterMappings;
use crate::format::seam_stubs::{
    DWARFCompilationUnit, DWARFExpression, DWARFExpressionException, DWARFExpressionInstruction,
    DWARFExpressionOpCode, DWARFProgram, DWARFUtil,
};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::Varnode;
use crate::program::model::scalar::scalar::Scalar;

use DWARFExpressionOpCode::*;

/// Default limit for the number of execution steps to allow in an expression.
const DEFAULT_MAX_STEP_COUNT: i32 = 1000;

/// A value on the DWARF expression evaluation stack.
///
/// Java pushes bare `Object`s and type-tests them on the way back out; the only two things that
/// ever reach the stack are a [`Scalar`] and a [`Varnode`] (`push(Address)` and `push(Register)`
/// wrap their argument in a varnode, `push(long)` and `push(boolean)` wrap theirs in a scalar, and
/// a [`ValueReader`] hands back one of the two), so they are modeled as an enum here.
#[derive(Debug, Clone, PartialEq)]
pub enum StackValue {
    Scalar(Scalar),
    Varnode(Varnode),
}

impl fmt::Display for StackValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackValue::Scalar(s) => write!(f, "{s}"),
            StackValue::Varnode(vn) => write!(f, "{vn}"),
        }
    }
}

/// Fetches the value held in a register or memory location for the evaluator.
///
/// Mirrors the `DWARFExpressionEvaluator.ValueReader` interface. The default implementation
/// ([`DummyValueReader`]) always fails, but future work may plug in a constant propagation
/// callback.
pub trait ValueReader {
    fn get_value(&self, vn: &Varnode) -> Result<StackValue, DWARFExpressionException>;
}

/// The `ValueReader.DUMMY` instance: every value fetch fails.
pub struct DummyValueReader;

impl ValueReader for DummyValueReader {
    fn get_value(&self, vn: &Varnode) -> Result<StackValue, DWARFExpressionException> {
        Err(DWARFExpressionException::value(vn.clone()))
    }
}

/// The [`ValueReader`] returned by
/// [`DWARFExpressionEvaluator::with_static_stack_register_values`]: resolves reads of the stack
/// pointer and the stack frame register to fixed stack locations, and fails everything else.
pub struct StaticStackRegisterValueReader {
    lang: Option<Arc<dyn Language>>,
    register_mappings: Arc<DWARFRegisterMappings>,
    stack_space: Option<Arc<AddressSpace>>,
    stack_offset: Option<i32>,
    stack_frame_offset: Option<i32>,
}

impl ValueReader for StaticStackRegisterValueReader {
    fn get_value(&self, vn: &Varnode) -> Result<StackValue, DWARFExpressionException> {
        let reg = match (vn.is_register(), self.lang.as_ref()) {
            (true, Some(lang)) => lang.get_register_at(vn.get_address(), 0),
            _ => None,
        };
        if let Some(reg) = reg {
            if same_register(&reg, self.register_mappings.stack_frame_register().as_ref()) {
                if let Some(stack_frame_offset) = self.stack_frame_offset {
                    return new_stack_varnode(
                        self.stack_space.as_ref(),
                        stack_frame_offset as i64,
                        0,
                    )
                    .map(StackValue::Varnode);
                }
            }
            if same_register(&reg, self.register_mappings.stack_register().as_ref()) {
                if let Some(stack_offset) = self.stack_offset {
                    return new_stack_varnode(self.stack_space.as_ref(), stack_offset as i64, 0)
                        .map(StackValue::Varnode);
                }
            }
        }
        Err(DWARFExpressionException::value(vn.clone()))
    }
}

/// Java compares registers with `==`, and `Register` does not override `equals`, so identity is the
/// comparison being ported.
fn same_register(reg: &RegisterRef, other: Option<&RegisterRef>) -> bool {
    other.is_some_and(|other| Rc::ptr_eq(reg, other))
}

/// `DWARFProgram.getStackSpace().getAddress(offset)`, wrapped in a varnode.
fn new_stack_varnode(
    stack_space: Option<&Arc<AddressSpace>>,
    offset: i64,
    size: i32,
) -> Result<Varnode, DWARFExpressionException> {
    let stack_space = stack_space.ok_or_else(|| {
        DWARFExpressionException::new("DWARF program does not have a stack address space")
    })?;
    Ok(Varnode::new(stack_space.address(offset), size))
}

/// Evaluates a [`DWARFExpression`].
///
/// If an instruction needs a value in a register or memory location, the current [`ValueReader`]
/// callback will be called to fetch the value. The default implementation is to fail, but future
/// work may plug in a constant propagation callback.
pub struct DWARFExpressionEvaluator {
    cu: Arc<dyn DWARFCompilationUnit>,
    lang: Option<Arc<dyn Language>>,
    /// `DWARFProgram.getStackSpace()`, cached because `dprog` can only be borrowed from `cu`.
    stack_space: Option<Arc<AddressSpace>>,
    register_mappings: Arc<DWARFRegisterMappings>,

    val_reader: Box<dyn ValueReader>,

    max_step_count: i32,

    /// The subprogram's `DW_AT_frame_base` value.
    frame_base_val: Option<Varnode>,

    stack: Vec<StackValue>,

    expr: Option<DWARFExpression>,
    instr: Option<DWARFExpressionInstruction>,
    instr_index: i32,
    step_count: i32,
}

impl DWARFExpressionEvaluator {
    pub fn new(cu: Arc<dyn DWARFCompilationUnit>) -> Self {
        let dprog = cu.get_program();
        let register_mappings = dprog
            .and_then(|dprog| dprog.get_register_mappings())
            .unwrap_or_else(|| Arc::new(DWARFRegisterMappings::dummy()));
        let lang = dprog.and_then(|dprog| dprog.get_language());
        let stack_space = dprog.and_then(|dprog| dprog.get_stack_space());

        DWARFExpressionEvaluator {
            cu,
            lang,
            stack_space,
            register_mappings,
            val_reader: Box::new(DummyValueReader),
            max_step_count: DEFAULT_MAX_STEP_COUNT,
            frame_base_val: None,
            stack: Vec::new(),
            expr: None,
            instr: None,
            instr_index: -1,
            step_count: 0,
        }
    }

    pub fn get_dwarf_compilation_unit(&self) -> &Arc<dyn DWARFCompilationUnit> {
        &self.cu
    }

    pub fn get_expr(&self) -> Option<&DWARFExpression> {
        self.expr.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    pub fn get_ptr_size(&self) -> i32 {
        self.cu.get_pointer_size() as i32
    }

    pub fn set_frame_base_stack_location(
        &mut self,
        offset: i32,
    ) -> Result<(), DWARFExpressionException> {
        self.frame_base_val = Some(self.new_stack_varnode(offset as i64, 0)?);
        Ok(())
    }

    pub fn set_frame_base_val(&mut self, frame_base_val: Varnode) {
        self.frame_base_val = Some(frame_base_val);
    }

    pub fn set_val_reader(&mut self, val_reader: Box<dyn ValueReader>) {
        self.val_reader = val_reader;
    }

    /// Builds a [`ValueReader`] that resolves the stack pointer and the stack frame register to
    /// the given fixed stack offsets.
    pub fn with_static_stack_register_values(
        &self,
        stack_offset: Option<i32>,
        stack_frame_offset: Option<i32>,
    ) -> Box<dyn ValueReader> {
        Box::new(StaticStackRegisterValueReader {
            lang: self.lang.clone(),
            register_mappings: Arc::clone(&self.register_mappings),
            stack_space: self.stack_space.clone(),
            stack_offset,
            stack_frame_offset,
        })
    }

    pub fn get_max_step_count(&self) -> i32 {
        self.max_step_count
    }

    pub fn set_max_step_count(&mut self, max_step_count: i32) {
        self.max_step_count = max_step_count;
    }

    pub fn push_addr(&mut self, addr: crate::program::model::address::Address) {
        self.push(StackValue::Varnode(Varnode::new(addr, 0)));
    }

    pub fn push_reg(&mut self, reg: &RegisterRef) {
        let reg = reg.borrow();
        self.push(StackValue::Varnode(Varnode::new(
            reg.address().clone(),
            reg.minimum_byte_size(),
        )));
    }

    pub fn push_bool(&mut self, b: bool) {
        self.push_long(if b { 1 } else { 0 });
    }

    pub fn push_long(&mut self, l: i64) {
        let bit_length = (self.get_ptr_size() * 8) as u8;
        self.push(StackValue::Scalar(Scalar::new(bit_length, l)));
    }

    pub fn push(&mut self, val: StackValue) {
        self.stack.push(val);
    }

    /// Peek at the top value of the stack.
    ///
    /// Fails if the stack is empty.
    pub fn peek(&self) -> Result<&StackValue, DWARFExpressionException> {
        self.stack
            .last()
            .ok_or_else(|| DWARFExpressionException::new("DWARF expression stack empty"))
    }

    /// Pop the top value off the stack.
    ///
    /// Fails if the stack is empty.
    pub fn pop(&mut self) -> Result<StackValue, DWARFExpressionException> {
        self.stack
            .pop()
            .ok_or_else(|| DWARFExpressionException::new("DWARF expression stack empty"))
    }

    /// Pop the top value off the stack, and coerce it into a scalar.
    ///
    /// Fails if the stack is empty or the value can not be used as a scalar.
    pub fn pop_scalar(&mut self) -> Result<Scalar, DWARFExpressionException> {
        let val = self.pop()?;
        self.stack_value_to_scalar(val)
    }

    fn stack_value_to_scalar(
        &self,
        val: StackValue,
    ) -> Result<Scalar, DWARFExpressionException> {
        match val {
            StackValue::Scalar(s) => Ok(s),
            StackValue::Varnode(ref varnode) => {
                if varnode.is_register() {
                    // try to deref the register and hopefully get a const varnode
                    let deref = self.val_reader.get_value(varnode)?;
                    return self.stack_value_to_scalar(deref);
                }
                if DWARFUtil::is_const_varnode(varnode) {
                    return Ok(Scalar::new(
                        (varnode.get_size() * 8) as u8,
                        varnode.get_offset(),
                    ));
                }
                Err(DWARFExpressionException::new(format!(
                    "Unable to convert stack value to scalar: {val}"
                )))
            }
        }
    }

    /// Pop the top value off the stack, and coerce it into a varnode.
    ///
    /// Fails if the stack is empty or the value can not be used as a varnode.
    pub fn pop_varnode(&mut self) -> Result<Varnode, DWARFExpressionException> {
        let tmp = self.pop()?;
        match tmp {
            StackValue::Scalar(s) if s.bit_length() as i32 == self.get_ptr_size() * 8 => {
                self.new_addr_varnode(s.get_unsigned_value() as i64)
            }
            StackValue::Varnode(varnode) => Ok(varnode),
            _ => Err(DWARFExpressionException::new(format!(
                "Unable to convert DWARF expression stack value {tmp} to address"
            ))),
        }
    }

    /// Pop the top value off the stack, and coerce it into a scalar long.
    ///
    /// Fails if the stack is empty or the value can not be used as a long.
    pub fn pop_long(&mut self) -> Result<i64, DWARFExpressionException> {
        Ok(self.pop_scalar()?.get_value())
    }

    /// Executes the instructions found in the raw bytes of an expression.
    pub fn evaluate_bytes(&mut self, expr_bytes: &[u8]) -> Result<(), DWARFExpressionException> {
        let expr = DWARFExpression::read(expr_bytes, &*self.cu)?;
        self.evaluate(expr)
    }

    /// Executes the instructions found in the raw bytes of an expression, after pushing
    /// `stack_args` onto the stack.
    pub fn evaluate_bytes_with_args(
        &mut self,
        expr_bytes: &[u8],
        stack_args: &[i64],
    ) -> Result<(), DWARFExpressionException> {
        let expr = DWARFExpression::read(expr_bytes, &*self.cu)?;
        self.evaluate_with_args(expr, stack_args)
    }

    /// Sets the current expression.
    pub fn set_expression(&mut self, expr: DWARFExpression) {
        self.expr = Some(expr);
        self.instr = None;
        self.instr_index = 0;
        self.step_count = 0;
    }

    /// Returns true if there are instructions that can be evaluated.
    pub fn has_next(&self) -> bool {
        self.expr.as_ref().is_some_and(|expr| self.instr_index < expr.get_instruction_count())
    }

    /// Evaluates the next instruction in the expression, returning true if there are more
    /// instructions.
    pub fn step(&mut self) -> Result<bool, DWARFExpressionException> {
        if self.has_next() {
            let instr = self
                .expr
                .as_ref()
                .and_then(|expr| expr.get_instruction(self.instr_index))
                .cloned()
                .expect("has_next() guarantees the instruction index is in range");
            match self.evaluate_instruction(instr) {
                Ok(()) => {
                    self.instr_index += 1;
                    self.step_count += 1;
                }
                Err(mut dee) => {
                    if dee.get_expression().is_none() {
                        if let Some(expr) = self.expr.clone() {
                            dee.set_expression(expr);
                        }
                        dee.set_instruction_index(self.instr_index);
                    }
                    return Err(dee);
                }
            }
        }

        Ok(self.has_next())
    }

    /// Executes the instructions found in the expression, after pushing `stack_args` onto the
    /// stack 0..N, so `stack_args[0]` will be deepest and `stack_args[N]` topmost.
    pub fn evaluate_with_args(
        &mut self,
        expr: DWARFExpression,
        stack_args: &[i64],
    ) -> Result<(), DWARFExpressionException> {
        for l in stack_args {
            self.push_long(*l);
        }
        self.evaluate(expr)
    }

    /// Executes the instructions found in the expression.
    ///
    /// Java also aborts the loop when the current thread has been interrupted; Rust threads have
    /// no interrupt flag, so [`Self::set_max_step_count`] is the only run-length guard here.
    pub fn evaluate(&mut self, expr: DWARFExpression) -> Result<(), DWARFExpressionException> {
        self.set_expression(expr);
        while self.has_next() {
            if self.step_count >= self.max_step_count {
                return Err(DWARFExpressionException::new(format!(
                    "Excessive expression run length, terminating after {} operations",
                    self.step_count
                )));
            }
            self.step()?;
        }
        Ok(())
    }

    fn get_reg(&self, dwarf_reg_num: i32) -> Result<RegisterRef, DWARFExpressionException> {
        self.register_mappings.ghidra_reg(dwarf_reg_num).ok_or_else(|| {
            DWARFExpressionException::new(format!(
                "Unknown/unmapped DWARF register: {dwarf_reg_num}"
            ))
        })
    }

    fn evaluate_instruction(
        &mut self,
        instr: DWARFExpressionInstruction,
    ) -> Result<(), DWARFExpressionException> {
        self.instr = Some(instr.clone());
        let opcode = instr.opcode;

        if DWARFExpressionOpCode::is_in_range(opcode, DW_OP_lit0, DW_OP_lit31) {
            self.push_long(opcode.get_relative_op_code_offset(DW_OP_lit0) as i64);
        } else if DWARFExpressionOpCode::is_in_range(opcode, DW_OP_breg0, DW_OP_breg31) {
            // Retrieve address held in register X and add offset from operand0 and push result on
            // stack.
            let register = self.get_reg(opcode.get_relative_op_code_offset(DW_OP_breg0))?;
            let offset = instr.get_operand_value(0);
            let reg_val = self.val_reader.get_value(&self.new_register_varnode(&register))?;
            match reg_val {
                StackValue::Varnode(ref reg_vn)
                    if DWARFUtil::is_stack_varnode(reg_vn) || reg_vn.is_constant() =>
                {
                    let addr = add_to_address(reg_vn, offset)?;
                    self.push(StackValue::Varnode(Varnode::new(addr, 0)));
                }
                StackValue::Scalar(s) => self.push_long(s.get_value().wrapping_add(offset)),
                _ => {
                    return Err(DWARFExpressionException::new(format!(
                        "Unable to deref register value {reg_val}"
                    )))
                }
            }
        } else if DWARFExpressionOpCode::is_in_range(opcode, DW_OP_reg0, DW_OP_reg31) {
            let register = self.get_reg(opcode.get_relative_op_code_offset(DW_OP_reg0))?;
            let reg_val = self.val_reader.get_value(&self.new_register_varnode(&register))?;
            self.push(reg_val);
        } else {
            match opcode {
                DW_OP_addr => {
                    let addr = self.get_data_address(instr.get_operand_value(0))?;
                    self.push_addr(addr);
                }

                DW_OP_const1u | DW_OP_const2u | DW_OP_const4u | DW_OP_const8u | DW_OP_const1s
                | DW_OP_const2s | DW_OP_const4s | DW_OP_const8s | DW_OP_constu | DW_OP_consts => {
                    self.push_long(instr.get_operand_value(0));
                }

                // Register Based Addressing
                DW_OP_regx => {
                    let register = self.get_reg(instr.get_operand_value(0) as i32)?;
                    self.push_reg(&register);
                }

                // NOTE: Java's `case DW_OP_fbreg:` block has no `break`, so it falls through into
                // `case DW_OP_dup:` and pushes the frame base location twice. Replicated here so
                // that the ported evaluator leaves the same stack behind.
                DW_OP_fbreg | DW_OP_dup => {
                    if opcode == DW_OP_fbreg {
                        let frame_base_val = self.frame_base_val.clone().ok_or_else(|| {
                            DWARFExpressionException::new(
                                "Frame base has not been set, DW_OP_fbreg can not be evaluated",
                            )
                        })?;
                        let fb_offset = instr.get_operand_value(0);
                        let addr = add_to_address(&frame_base_val, fb_offset)?;
                        self.push(StackValue::Varnode(Varnode::new(addr, 0)));
                    }
                    // Stack Operations
                    let top = self.peek()?.clone();
                    self.push(top);
                }
                DW_OP_drop => {
                    self.pop()?;
                }
                DW_OP_pick => {
                    let index = instr.get_operand_value(0) as i32;
                    if index < 0 || index as usize >= self.stack.len() {
                        return Err(DWARFExpressionException::new(format!(
                            "Invalid index for DW_OP_pick: {index}"
                        )));
                    }
                    let elem = self.stack[self.stack.len() - index as usize - 1].clone();
                    self.push(elem);
                }
                DW_OP_over => {
                    if self.stack.len() < 2 {
                        return Err(DWARFExpressionException::new(format!(
                            "Not enough items on stack[size={}] for DW_OP_over",
                            self.stack.len()
                        )));
                    }
                    let elem = self.stack[self.stack.len() - 2].clone();
                    self.push(elem);
                }
                DW_OP_swap => {
                    let first_value = self.pop()?;
                    let second_value = self.pop()?;
                    self.push(first_value);
                    self.push(second_value);
                }
                DW_OP_rot => {
                    let first_value = self.pop()?;
                    let second_value = self.pop()?;
                    let third_value = self.pop()?;
                    self.push(first_value);
                    self.push(third_value);
                    self.push(second_value);
                }
                DW_OP_deref => {
                    // Treat top stack value as a location, deref it and fetch a ptrSize'd value
                    // and push it on stack
                    let last_instr_index = self
                        .expr
                        .as_ref()
                        .map_or(-1, |expr| expr.get_instruction_count() - 1);
                    if self.instr_index == last_instr_index {
                        // If this was the last instruction, fail with a special error that lets
                        // the caller figure out what happened and accommodate this in some
                        // situations.
                        let location = self.pop_varnode()?;
                        return Err(DWARFExpressionException::terminal_deref(instr, location));
                    }
                    return Err(DWARFExpressionException::unsupported_op(instr));
                }

                DW_OP_call_frame_cfa => {
                    if !self.register_mappings.has_static_cfa() {
                        return Err(DWARFExpressionException::new(
                            "CFA not specified in DWARF register mappings for this arch",
                        ));
                    }
                    let cfa = self.register_mappings.call_frame_cfa();
                    let vn = self.new_stack_varnode(cfa as i64, 0)?;
                    self.push(StackValue::Varnode(vn));
                }

                // Arithmetic and Logical Operations
                DW_OP_abs => {
                    let val = self.pop_scalar()?;
                    let abs_val =
                        Scalar::new(val.bit_length(), val.get_signed_value().wrapping_abs());
                    self.push(StackValue::Scalar(abs_val));
                }
                DW_OP_and => {
                    // bitwise and
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = first_value.get_unsigned_value() & second_value.get_unsigned_value();
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp as i64)));
                }
                DW_OP_div => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    if first_value.get_value() == 0 {
                        return Err(DWARFExpressionException::new("Divide by zero"));
                    }
                    let tmp = second_value.get_value().wrapping_div(first_value.get_value());
                    self.push(StackValue::Scalar(Scalar::new(second_value.bit_length(), tmp)));
                }
                DW_OP_minus => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value().wrapping_sub(first_value.get_value());
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp)));
                }
                DW_OP_mod => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    if first_value.get_value() == 0 {
                        return Err(DWARFExpressionException::new("Divide by zero"));
                    }
                    let tmp = second_value.get_value().wrapping_rem(first_value.get_value());
                    self.push(StackValue::Scalar(Scalar::new(second_value.bit_length(), tmp)));
                }
                DW_OP_mul => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value().wrapping_mul(first_value.get_value());
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp)));
                }
                DW_OP_neg => {
                    let first_value = self.pop_scalar()?;
                    let tmp = first_value.get_signed_value().wrapping_neg();
                    self.push(StackValue::Scalar(Scalar::new(first_value.bit_length(), tmp)));
                }
                DW_OP_not => {
                    // bitwise neg
                    let first_value = self.pop_scalar()?;
                    let tmp = !first_value.get_value();
                    self.push(StackValue::Scalar(Scalar::new(first_value.bit_length(), tmp)));
                }
                DW_OP_or => {
                    // bitwise or
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value() | first_value.get_value();
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp)));
                }
                DW_OP_plus => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value().wrapping_add(first_value.get_value());
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp)));
                }
                DW_OP_plus_uconst => {
                    let first_value = self.pop_scalar()?;
                    let op_value = instr.get_operand_value(0);
                    let tmp = first_value.get_value().wrapping_add(op_value);
                    self.push(StackValue::Scalar(Scalar::new(first_value.bit_length(), tmp)));
                }
                DW_OP_shl => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value() << shift_distance(first_value.get_value());
                    self.push(StackValue::Scalar(Scalar::new(second_value.bit_length(), tmp)));
                }
                DW_OP_shr => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    // Java's >>> : the value is shifted as an unsigned quantity
                    let tmp = ((second_value.get_value() as u64)
                        >> shift_distance(first_value.get_value()))
                        as i64;
                    self.push(StackValue::Scalar(Scalar::new(second_value.bit_length(), tmp)));
                }
                DW_OP_shra => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value() >> shift_distance(first_value.get_value());
                    self.push(StackValue::Scalar(Scalar::new(second_value.bit_length(), tmp)));
                }
                DW_OP_xor => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    let tmp = second_value.get_value() ^ first_value.get_value();
                    let bit_count = first_value.bit_length().max(second_value.bit_length());
                    self.push(StackValue::Scalar(Scalar::new(bit_count, tmp)));
                }
                // Control Flow Operations, values treated as signed for comparison
                DW_OP_le => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(
                        second_value.get_signed_value() <= first_value.get_signed_value(),
                    );
                }
                DW_OP_ge => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(
                        second_value.get_signed_value() >= first_value.get_signed_value(),
                    );
                }
                DW_OP_eq => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(second_value.get_value() == first_value.get_value());
                }
                DW_OP_lt => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(
                        second_value.get_signed_value() < first_value.get_signed_value(),
                    );
                }
                DW_OP_gt => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(
                        second_value.get_signed_value() > first_value.get_signed_value(),
                    );
                }
                DW_OP_ne => {
                    let first_value = self.pop_scalar()?;
                    let second_value = self.pop_scalar()?;
                    self.push_bool(
                        second_value.get_signed_value() != first_value.get_signed_value(),
                    );
                }
                DW_OP_skip => {
                    let dest_offset = instr.get_operand_value(0) + instr.get_offset() as i64;
                    let new_instr_index = self.find_instruction_by_offset(dest_offset);
                    if new_instr_index == -1 {
                        return Err(DWARFExpressionException::new(format!(
                            "Invalid skip offset {dest_offset}"
                        )));
                    }
                    // 1 before the target op index because step() will ++ the index value
                    self.instr_index = new_instr_index - 1;
                }
                DW_OP_bra => {
                    let dest_offset = instr.get_operand_value(0) + instr.get_offset() as i64;
                    let first_value = self.pop_scalar()?;
                    if first_value.get_value() != 0 {
                        let new_instr_index = self.find_instruction_by_offset(dest_offset);
                        if new_instr_index == -1 {
                            return Err(DWARFExpressionException::new(format!(
                                "Invalid bra offset {dest_offset}"
                            )));
                        }
                        // 1 before the target op index because step() will ++ the index value
                        self.instr_index = new_instr_index - 1;
                    }
                }

                // Special Operations
                DW_OP_nop => {}
                DW_OP_stack_value => {
                    // This op is a flag to the debugger that the requested value does not exist in
                    // memory (on the host) but that the result of this expression gives you the
                    // value
                    return Err(DWARFExpressionException::unsupported_op(instr));
                }
                // DW_OP_constx is the same as DW_OP_addrx, but with different relocation-able
                // specifications
                DW_OP_addrx | DW_OP_constx => {
                    let index = instr.get_operand_value(0);
                    let addr = self
                        .cu
                        .get_die_container()
                        .ok_or(())
                        .and_then(|container| {
                            container
                                .get_address(DWARFForm::DwFormAddrx, index, &*self.cu)
                                .map_err(|_| ())
                        })
                        .map_err(|()| {
                            DWARFExpressionException::new(format!(
                                "Invalid indirect address index: {index}"
                            ))
                        })?;
                    self.push_long(addr);
                }

                _ => return Err(DWARFExpressionException::unsupported_op(instr)),
            }
        }
        Ok(())
    }

    fn find_instruction_by_offset(&self, offset: i64) -> i32 {
        self.expr.as_ref().map_or(-1, |expr| expr.find_instruction_by_offset(offset))
    }

    fn get_data_address(
        &self,
        offset: i64,
    ) -> Result<crate::program::model::address::Address, DWARFExpressionException> {
        self.cu
            .get_program()
            .and_then(|dprog| dprog.get_data_address(offset))
            .ok_or_else(|| {
                DWARFExpressionException::new(format!(
                    "Unable to resolve DWARF data address {offset:#x}"
                ))
            })
    }

    fn new_stack_varnode(
        &self,
        offset: i64,
        size: i32,
    ) -> Result<Varnode, DWARFExpressionException> {
        new_stack_varnode(self.stack_space.as_ref(), offset, size)
    }

    fn new_register_varnode(&self, reg: &RegisterRef) -> Varnode {
        let reg = reg.borrow();
        Varnode::new(reg.address().clone(), reg.minimum_byte_size())
    }

    fn new_addr_varnode(&self, l: i64) -> Result<Varnode, DWARFExpressionException> {
        Ok(Varnode::new(self.get_data_address(l)?, self.cu.get_pointer_size() as i32))
    }

    fn get_stack_as_string(&self) -> String {
        use std::fmt::Write;

        let mut sb = String::new();
        for (stackindex, stack_val) in self.stack.iter().rev().enumerate() {
            let _ = writeln!(sb, "{stackindex:3}: {stack_val}");
        }
        sb
    }

    fn get_status_string(&self) -> &'static str {
        if self.instr_index == -1 {
            return "Not started";
        }
        match &self.expr {
            Some(expr) if self.instr_index == expr.get_instruction_count() => "Finished",
            _ => "Running",
        }
    }
}

/// Java's `Address.add(long)`, which throws `AddressOutOfBoundsException` when the result leaves
/// the address space.
fn add_to_address(
    vn: &Varnode,
    offset: i64,
) -> Result<crate::program::model::address::Address, DWARFExpressionException> {
    vn.get_address().add(offset).map_err(|e| {
        DWARFExpressionException::new(format!("Unable to add {offset} to {vn}: {e}"))
    })
}

/// Java masks a `long` shift distance down to its low 6 bits.
fn shift_distance(distance: i64) -> u32 {
    (distance as u64 & 0x3f) as u32
}

/// Mirrors Java's `String.indent(int)`: indent every line and guarantee a trailing newline.
fn indent(s: &str, n: usize) -> String {
    let prefix = " ".repeat(n);
    let mut out = String::new();
    for line in s.lines() {
        out.push_str(&prefix);
        out.push_str(line);
        out.push('\n');
    }
    out
}

impl fmt::Display for DWARFExpressionEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame_base_val = match &self.frame_base_val {
            Some(vn) => vn.to_string(),
            None => "not set".to_string(),
        };
        let instructions = match &self.expr {
            Some(expr) => indent(
                &expr.to_string_formatted(
                    self.instr_index,
                    true,
                    true,
                    Some(&self.register_mappings),
                ),
                2,
            ),
            None => "  no expr".to_string(),
        };
        write!(
            f,
            "DWARFExpressionEvaluator\n  frameBaseVal = {}\n  stepCount = {}\n  status: {}\n\nStack:\n{}Instructions:\n{}",
            frame_base_val,
            self.step_count,
            self.get_status_string(),
            indent(&self.get_stack_as_string(), 2),
            instructions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::DWARFExpressionExceptionKind;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockCompUnit {
        pointer_size: i8,
    }

    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            5
        }
        fn get_pointer_size(&self) -> i8 {
            self.pointer_size
        }
    }

    /// An evaluator over a 64 bit compilation unit with no `DWARFProgram` behind it (so the dummy
    /// register mappings and the failing value reader are in play).
    fn evaluator() -> DWARFExpressionEvaluator {
        DWARFExpressionEvaluator::new(Arc::new(MockCompUnit { pointer_size: 8 }))
    }

    /// Builds an expression out of single-byte instructions laid out back to back, so instruction
    /// `i` sits at offset `i`.
    fn expr_of(opcodes: &[DWARFExpressionOpCode]) -> DWARFExpression {
        DWARFExpression::of(
            opcodes
                .iter()
                .enumerate()
                .map(|(i, op)| DWARFExpressionInstruction::new(*op, vec![], i as i32))
                .collect(),
        )
    }

    #[test]
    fn lit_opcodes_push_their_relative_offset_and_plus_adds() {
        let mut eval = evaluator();
        eval.evaluate(expr_of(&[DW_OP_lit5, DW_OP_lit3, DW_OP_plus])).unwrap();

        assert_eq!(eval.pop_long().unwrap(), 8);
        assert!(eval.is_empty());
    }

    #[test]
    fn pushed_scalars_are_pointer_sized() {
        let mut eval = evaluator();
        assert_eq!(eval.get_ptr_size(), 8);
        eval.evaluate(expr_of(&[DW_OP_lit1])).unwrap();

        match eval.pop().unwrap() {
            StackValue::Scalar(s) => {
                assert_eq!(s.bit_length(), 64);
                assert_eq!(s.get_value(), 1);
            }
            other => panic!("expected a scalar, got {other}"),
        }
    }

    #[test]
    fn minus_subtracts_the_top_of_stack_from_the_one_below_it() {
        // DW_OP_const1u 10, DW_OP_lit2, DW_OP_minus  ==>  10 - 2
        let mut eval = evaluator();
        let expr = DWARFExpression::of(vec![
            DWARFExpressionInstruction::new(DW_OP_const1u, vec![10], 0),
            DWARFExpressionInstruction::new(DW_OP_lit2, vec![], 2),
            DWARFExpressionInstruction::new(DW_OP_minus, vec![], 3),
        ]);
        eval.evaluate(expr).unwrap();

        assert_eq!(eval.pop_long().unwrap(), 8);
    }

    #[test]
    fn stack_manipulation_ops_reorder_the_stack() {
        // push 1, 2, 3 then DW_OP_rot: [1,2,3] -> [3,1,2] (topmost last)
        let mut eval = evaluator();
        eval.evaluate(expr_of(&[DW_OP_lit1, DW_OP_lit2, DW_OP_lit3, DW_OP_rot])).unwrap();

        assert_eq!(eval.pop_long().unwrap(), 2);
        assert_eq!(eval.pop_long().unwrap(), 1);
        assert_eq!(eval.pop_long().unwrap(), 3);
        assert!(eval.is_empty());
    }

    #[test]
    fn comparison_ops_push_one_or_zero() {
        let mut eval = evaluator();
        eval.evaluate(expr_of(&[DW_OP_lit7, DW_OP_lit9, DW_OP_lt])).unwrap();
        assert_eq!(eval.pop_long().unwrap(), 1, "7 < 9");

        eval.evaluate(expr_of(&[DW_OP_lit9, DW_OP_lit7, DW_OP_lt])).unwrap();
        assert_eq!(eval.pop_long().unwrap(), 0, "9 < 7");
    }

    #[test]
    fn skip_jumps_to_the_instruction_at_the_target_offset() {
        // @0 lit1, @1 skip(+4 -> offset 5), @4 lit7 (skipped), @5 lit9
        let mut eval = evaluator();
        let expr = DWARFExpression::of(vec![
            DWARFExpressionInstruction::new(DW_OP_lit1, vec![], 0),
            DWARFExpressionInstruction::new(DW_OP_skip, vec![4], 1),
            DWARFExpressionInstruction::new(DW_OP_lit7, vec![], 4),
            DWARFExpressionInstruction::new(DW_OP_lit9, vec![], 5),
        ]);
        eval.evaluate(expr).unwrap();

        assert_eq!(eval.pop_long().unwrap(), 9);
        assert_eq!(eval.pop_long().unwrap(), 1, "the skipped-over lit7 never ran");
        assert!(eval.is_empty());
    }

    #[test]
    fn skip_to_an_unknown_offset_reports_the_expression_and_instruction_index() {
        let mut eval = evaluator();
        let expr = DWARFExpression::of(vec![
            DWARFExpressionInstruction::new(DW_OP_lit1, vec![], 0),
            DWARFExpressionInstruction::new(DW_OP_skip, vec![99], 1),
        ]);
        let err = eval.evaluate(expr).unwrap_err();

        assert!(err.to_string().starts_with("Invalid skip offset 100"), "{err}");
        assert_eq!(err.get_instruction_index(), 1);
        assert!(err.get_expression().is_some());
    }

    #[test]
    fn divide_by_zero_is_an_error() {
        let mut eval = evaluator();
        let err = eval.evaluate(expr_of(&[DW_OP_lit4, DW_OP_lit0, DW_OP_div])).unwrap_err();

        assert!(err.to_string().starts_with("Divide by zero"), "{err}");
    }

    #[test]
    fn popping_an_empty_stack_is_an_error() {
        let mut eval = evaluator();
        let err = eval.pop().unwrap_err();

        assert_eq!(err.to_string(), "DWARF expression stack empty");
    }

    #[test]
    fn unsupported_opcode_carries_the_offending_instruction() {
        let mut eval = evaluator();
        let err = eval.evaluate(expr_of(&[DW_OP_stack_value])).unwrap_err();

        assert!(matches!(err.kind(), DWARFExpressionExceptionKind::UnsupportedOp(_)));
        assert_eq!(err.get_instruction().unwrap().opcode, DW_OP_stack_value);
        assert!(err.to_string().starts_with("Unsupported instruction DW_OP_stack_value"), "{err}");
    }

    #[test]
    fn trailing_deref_reports_the_location_it_would_have_read() {
        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let mut eval = evaluator();
        eval.push_addr(ram.address(0x1000));

        let err = eval.evaluate(expr_of(&[DW_OP_deref])).unwrap_err();

        assert!(matches!(err.kind(), DWARFExpressionExceptionKind::TerminalDeref(..)));
        assert_eq!(err.get_varnode().unwrap(), &Varnode::new(ram.address(0x1000), 0));
    }

    #[test]
    fn non_trailing_deref_is_merely_unsupported() {
        let mut eval = evaluator();
        let err = eval.evaluate(expr_of(&[DW_OP_deref, DW_OP_nop])).unwrap_err();

        assert!(matches!(err.kind(), DWARFExpressionExceptionKind::UnsupportedOp(_)));
    }

    #[test]
    fn call_frame_cfa_needs_a_static_cfa_in_the_register_mappings() {
        // the dummy register mappings have no CFA
        let mut eval = evaluator();
        let err = eval.evaluate(expr_of(&[DW_OP_call_frame_cfa])).unwrap_err();

        assert!(
            err.to_string()
                .starts_with("CFA not specified in DWARF register mappings for this arch"),
            "{err}"
        );
    }

    #[test]
    fn unmapped_dwarf_register_is_named_in_the_error() {
        // DW_OP_reg3 with the dummy (empty) register mappings
        let mut eval = evaluator();
        let err = eval.evaluate(expr_of(&[DW_OP_reg3])).unwrap_err();

        assert!(err.to_string().starts_with("Unknown/unmapped DWARF register: 3"), "{err}");
    }

    #[test]
    fn fbreg_needs_a_frame_base() {
        let mut eval = evaluator();
        let expr = DWARFExpression::of(vec![DWARFExpressionInstruction::new(
            DW_OP_fbreg,
            vec![-8],
            0,
        )]);
        let err = eval.evaluate(expr).unwrap_err();

        assert!(
            err.to_string()
                .starts_with("Frame base has not been set, DW_OP_fbreg can not be evaluated"),
            "{err}"
        );
    }

    #[test]
    fn fbreg_offsets_the_frame_base_location() {
        let stack = AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 0);
        let mut eval = evaluator();
        eval.set_frame_base_val(Varnode::new(stack.address(0), 0));

        let expr = DWARFExpression::of(vec![DWARFExpressionInstruction::new(
            DW_OP_fbreg,
            vec![-8],
            0,
        )]);
        eval.evaluate(expr).unwrap();

        // Java's DW_OP_fbreg case falls through into DW_OP_dup, leaving two copies
        assert_eq!(eval.pop_varnode().unwrap(), Varnode::new(stack.address(-8), 0));
        assert_eq!(eval.pop_varnode().unwrap(), Varnode::new(stack.address(-8), 0));
        assert!(eval.is_empty());
    }

    #[test]
    fn excessive_run_length_is_capped_by_max_step_count() {
        // @0 lit1, @1 bra(-1 -> offset 0): an infinite loop
        let mut eval = evaluator();
        eval.set_max_step_count(10);
        assert_eq!(eval.get_max_step_count(), 10);

        let expr = DWARFExpression::of(vec![
            DWARFExpressionInstruction::new(DW_OP_lit1, vec![], 0),
            DWARFExpressionInstruction::new(DW_OP_bra, vec![-1], 1),
        ]);
        let err = eval.evaluate(expr).unwrap_err();

        assert!(
            err.to_string()
                .starts_with("Excessive expression run length, terminating after 10 operations"),
            "{err}"
        );
    }

    #[test]
    fn evaluate_with_args_pushes_deepest_first() {
        let mut eval = evaluator();
        eval.evaluate_with_args(expr_of(&[DW_OP_minus]), &[10, 4]).unwrap();

        assert_eq!(eval.pop_long().unwrap(), 6, "10 - 4");
    }

    #[test]
    fn status_string_tracks_progress() {
        let mut eval = evaluator();
        assert_eq!(eval.get_status_string(), "Not started");
        assert!(!eval.has_next());

        eval.set_expression(expr_of(&[DW_OP_lit1, DW_OP_lit2]));
        assert_eq!(eval.get_status_string(), "Running");
        assert!(eval.has_next());

        assert!(eval.step().unwrap(), "another instruction remains");
        assert!(!eval.step().unwrap(), "expression is exhausted");
        assert_eq!(eval.get_status_string(), "Finished");
    }

    #[test]
    fn display_shows_the_frame_base_stack_and_instructions() {
        let mut eval = evaluator();
        eval.evaluate(expr_of(&[DW_OP_lit1])).unwrap();
        let s = eval.to_string();

        assert!(s.contains("frameBaseVal = not set"), "{s}");
        assert!(s.contains("stepCount = 1"), "{s}");
        assert!(s.contains("status: Finished"), "{s}");
        assert!(s.contains("  0: 0x1"), "{s}");
        assert!(s.contains("DW_OP_lit1"), "{s}");
    }
}
