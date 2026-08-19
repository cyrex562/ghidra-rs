//! A userop library wherein native (Rust) functions are exported as userops.
//!
//! Corresponds to `ghidra.pcode.exec.AnnotatedPcodeUseropLibrary`.
//!
//! Java exports a method as a userop by annotating it `@PcodeUserop` and then, in the library's
//! constructor, reflecting over its own class: it collects the annotated methods, derives each
//! parameter's role from the annotation on it (`@OpExecutor`, `@OpState`, `@OpLibrary`,
//! `@OpOutput`, `@OpOp`) or, failing that, from its declared type, binds a `MethodHandle` to the
//! library instance, and files the result under the method's name. Rust has neither annotations
//! nor reflection, so that whole apparatus becomes an explicit declaration:
//!
//! * `@PcodeUserop`'s attributes become the [`PcodeUserop`] struct, carrying Java's defaults.
//! * The parameter roles become fixed positions in the callback's signature: the annotated
//!   parameters (executor, state, library, output varnode, op) all arrive in a single
//!   [`UseropContext`], and the non-annotated ones -- the userop's inputs -- arrive as a slice of
//!   [`UseropValue`], already converted per the declared [`UseropValueKind`] of each. This is the
//!   port of the `ParamAnnotProc` scan and of the `UseropInputParam` conversions.
//! * The reflective class scan becomes [`AnnotatedPcodeUseropLibrary::collect_definitions`], the
//!   one operation a concrete library must supply. Java's `CACHE_BY_CLASS` memoizes the scan; a
//!   direct call needs no such cache, and `getMethodLookup()` (which only exists to give
//!   reflection access to non-public methods) has no analog either.
//! * Java binds each handle to the library instance (`bindTo(library)`) so a userop can reach the
//!   library's own state. A closure returned by `collect_definitions` gets there instead by
//!   capturing shared handles (e.g. a cloned `Arc`) to that state, which avoids making each
//!   definition a back-reference into the library that owns it.
//!
//! The type checks Java performs at construction (a parameter's type must match its annotation;
//! an input must be a `Varnode`, a non-`char` primitive, or assignable from `T`; the return must
//! be assignable to `T`) are all statically enforced here by [`UseropValueKind`] and the callback
//! signature. The checks that remain genuinely dynamic -- a variadic userop must have a parameter
//! for its inputs, and a call must supply the declared number of inputs -- are ported.

use std::any::TypeId;
use std::sync::Arc;

use crate::pcode::exec::default_pcode_userop_library::DefaultPcodeUseropLibrary;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_userop_library::{
    operand_type, ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// The attributes with which a userop is exported.
///
/// Port of the `@PcodeUserop` annotation. [`Default`] reproduces the annotation's defaults, so a
/// declaration usually reads `PcodeUserop { functional: true, ..Default::default() }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcodeUserop {
    /// Set to true to receive all inputs in one parameter. See [`UseropInputs`].
    pub variadic: bool,
    /// Set to true to attest that the userop is a pure function.
    ///
    /// An incorrect attestation can lead to erroneous execution results.
    pub functional: bool,
    /// Set to false to attest the userop has no side effects.
    ///
    /// An incorrect attestation can lead to erroneous execution results.
    pub has_side_effects: bool,
    /// Set to true to indicate the userop can modify the decode context.
    ///
    /// Failure to indicate context modifications can lead to erroneous decodes and thus incorrect
    /// execution results.
    pub modifies_context: bool,
    /// Set to true to suggest inlining.
    pub can_inline: bool,
}

impl Default for PcodeUserop {
    fn default() -> Self {
        Self {
            variadic: false,
            functional: false,
            has_side_effects: true,
            modifies_context: false,
            can_inline: false,
        }
    }
}

/// The declared type of a userop's input parameter or of its output.
///
/// Port of the Java parameter/return types the annotation processor recognizes: a [`Varnode`], a
/// value of the library's operand type `T`, or a non-`char` primitive (plus `int[]`, for
/// multi-precision integers). [`Void`](UseropValueKind::Void) stands for Java's `void` return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseropValueKind {
    /// The input variable itself, undereferenced. Java: a parameter of type `Varnode`.
    Varnode,
    /// The input's value in the library's operand domain. Java: a parameter assignable from `T`.
    Value,
    /// The input's value, concretized and truncated to 8 bits. Java: `byte`.
    Byte,
    /// The input's value, concretized and truncated to 16 bits. Java: `short`.
    Short,
    /// The input's value, concretized and truncated to 32 bits. Java: `int`.
    Int,
    /// The input's value, concretized to 64 bits. Java: `long`.
    Long,
    /// The input's value, concretized and split into 32-bit limbs, least significant first.
    /// Java: `int[]`.
    IntArray,
    /// The input's value, concretized as a single-precision float. Java: `float`.
    Float,
    /// The input's value, concretized as a double-precision float. Java: `double`.
    Double,
    /// The input's value, concretized as a condition. Java: `boolean`.
    Boolean,
    /// No value. Java: a `void` return.
    Void,
}

impl UseropValueKind {
    /// The runtime type this kind denotes, for `T` the library's operand type.
    ///
    /// Java's `getOutputType()` answers with the `Class<?>` of the declared type;
    /// [`TypeId`] is Rust's counterpart, and `()` stands for `void.class`.
    pub fn type_id<T: 'static>(self) -> TypeId {
        match self {
            Self::Varnode => TypeId::of::<Varnode>(),
            Self::Value => TypeId::of::<T>(),
            Self::Byte => TypeId::of::<i8>(),
            Self::Short => TypeId::of::<i16>(),
            Self::Int => TypeId::of::<i32>(),
            Self::Long => TypeId::of::<i64>(),
            Self::IntArray => TypeId::of::<Vec<i32>>(),
            Self::Float => TypeId::of::<f32>(),
            Self::Double => TypeId::of::<f64>(),
            Self::Boolean => TypeId::of::<bool>(),
            Self::Void => TypeId::of::<()>(),
        }
    }
}

/// A value handed to a userop callback as one of its inputs, or handed back as its output.
///
/// Java passes these as `Object`s through a `MethodHandle`, recovering the static types from the
/// method's own signature; a Rust callback has one signature for every userop, so the value's kind
/// travels with it. Which variant an input arrives as is fixed by the declared
/// [`UseropValueKind`], so a callback may match on just the variant(s) it declared.
#[derive(Debug, Clone, PartialEq)]
pub enum UseropValue<T> {
    /// The input variable itself. Only ever an input; a userop cannot return a variable.
    Varnode(Varnode),
    /// A value in the library's operand domain.
    Value(T),
    /// A concrete 8-bit integer.
    Byte(i8),
    /// A concrete 16-bit integer.
    Short(i16),
    /// A concrete 32-bit integer.
    Int(i32),
    /// A concrete 64-bit integer.
    Long(i64),
    /// A concrete multi-precision integer, as 32-bit limbs, least significant first. Only ever an
    /// input; Java would fail to store such a return into the output variable.
    IntArray(Vec<i32>),
    /// A concrete single-precision float.
    Float(f32),
    /// A concrete double-precision float.
    Double(f64),
    /// A concrete condition.
    Boolean(bool),
}

impl<T> UseropValue<T> {
    /// The input variable, if this is a [`Varnode`](UseropValue::Varnode).
    pub fn as_varnode(&self) -> Option<&Varnode> {
        match self {
            Self::Varnode(vn) => Some(vn),
            _ => None,
        }
    }

    /// The operand-domain value, if this is a [`Value`](UseropValue::Value).
    pub fn as_value(&self) -> Option<&T> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }

    /// The value as a 64-bit integer, if this is one of the concrete integer kinds. The narrower
    /// kinds are sign-extended, as they would be when widened to `long` in Java.
    pub fn as_long(&self) -> Option<i64> {
        match *self {
            Self::Byte(v) => Some(v as i64),
            Self::Short(v) => Some(v as i64),
            Self::Int(v) => Some(v as i64),
            Self::Long(v) => Some(v),
            _ => None,
        }
    }
}

/// How a userop receives its inputs.
///
/// Port of the split between `FixedArgsAnnotatedPcodeUseropDefinition` (one parameter per input)
/// and `VariadicAnnotatedPcodeUseropDefinition` (one parameter for all of them). Java picks the
/// implementation from `@PcodeUserop(variadic = ...)`; here the two must agree, and
/// [`AnnotatedPcodeUseropDefinition::new`] checks that they do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UseropInputs {
    /// One parameter per input, each converted according to its declared kind.
    Fixed(Vec<UseropValueKind>),
    /// All inputs as variables. Java: a variadic parameter of type `Varnode[]`.
    VariadicVarnodes,
    /// All inputs as values. Java: a variadic parameter assignable from `T[]`.
    VariadicValues,
}

/// Everything a userop callback receives besides its inputs.
///
/// Port of the parameters Java marks `@OpExecutor`, `@OpState`, `@OpLibrary`, `@OpOutput`, and
/// `@OpOp`. Java lets a method declare only the ones it wants, in any position; a Rust callback
/// has one signature, so it gets them all and ignores the rest.
pub struct UseropContext<'a, T: 'static> {
    /// The executor invoking the userop. Java: the `@OpExecutor` parameter.
    pub executor: &'a PcodeExecutor<T>,
    /// The *complete* library for this execution, which may have been composed from more than the
    /// one defining this userop. Java: the `@OpLibrary` parameter.
    pub library: &'a dyn PcodeUseropLibrary<T>,
    /// The `CALLOTHER` op being executed. Java: the `@OpOp` parameter.
    pub op: &'a PcodeOp,
    /// The destination variable for the userop's output, or `None` when it was invoked for effect
    /// only. Java: the `@OpOutput` parameter.
    pub out_var: Option<&'a Varnode>,
}

impl<'a, T: 'static> UseropContext<'a, T> {
    /// The executor's state. Java: the `@OpState` parameter, which is just `executor.getState()`.
    pub fn state(&self) -> &'a std::sync::Mutex<dyn crate::pcode::exec::PcodeExecutorState<T>> {
        self.executor.get_state()
    }
}

/// The native function behind an annotated userop.
///
/// Port of the bound `MethodHandle`. It returns the userop's output, or `None` where Java's method
/// returns `void` (or `null`); the output is written to the destination variable, if there is one.
pub type UseropCallback<T> =
    dyn Fn(&UseropContext<'_, T>, &[UseropValue<T>]) -> Option<UseropValue<T>>;

/// A native function exported as a userop definition.
///
/// Port of `AnnotatedPcodeUseropLibrary.AnnotatedPcodeUseropDefinition` and its two subclasses;
/// since the fixed-args/variadic distinction is entirely a matter of how the inputs are placed, it
/// is carried by the [`UseropInputs`] field rather than by two types.
pub struct AnnotatedPcodeUseropDefinition<T: 'static> {
    name: String,
    annotation: PcodeUserop,
    inputs: UseropInputs,
    output: UseropValueKind,
    callback: Box<UseropCallback<T>>,
}

impl<T: 'static> AnnotatedPcodeUseropDefinition<T> {
    /// Export `callback` as the userop named `name`.
    ///
    /// Port of `AnnotatedPcodeUseropDefinition.create` together with the constructor's validation:
    /// `inputs` must agree with `annotation.variadic` (Java's `initFinished`), and a fixed input
    /// may not be declared [`Void`](UseropValueKind::Void).
    ///
    /// # Panics
    ///
    /// If `inputs` and `annotation.variadic` disagree, or a fixed input is `Void` -- all cases
    /// where Java throws `IllegalArgumentException` while reflecting over the method.
    pub fn new(
        name: impl Into<String>,
        annotation: PcodeUserop,
        inputs: UseropInputs,
        output: UseropValueKind,
        callback: Box<UseropCallback<T>>,
    ) -> Self {
        let name = name.into();
        match (&inputs, annotation.variadic) {
            (UseropInputs::Fixed(kinds), false) => {
                if let Some(i) = kinds.iter().position(|k| *k == UseropValueKind::Void) {
                    panic!(
                        "Input parameter {i} of userop {name} must be non-char primitive type, \
                         Varnode, or accept the operand type"
                    );
                }
            }
            (UseropInputs::Fixed(_), true) => {
                panic!("Variadic userop must have a parameter for the inputs")
            }
            (_, true) => {}
            (_, false) => {
                panic!("Only a variadic userop may receive all its inputs in one parameter")
            }
        }
        Self { name, annotation, inputs, output, callback }
    }

    /// The attributes this userop was exported with. Java reads these off the annotation each time
    /// through the individual `isFunctional()`/`hasSideEffects()`/... accessors.
    pub fn annotation(&self) -> PcodeUserop {
        self.annotation
    }

    /// How this userop receives its inputs.
    pub fn inputs(&self) -> &UseropInputs {
        &self.inputs
    }

    /// Port of `validateInputs`: a fixed-args userop must be given exactly as many inputs as it
    /// declared. A variadic one accepts any number.
    fn validate_inputs(&self, in_vars: &[Varnode]) {
        if let UseropInputs::Fixed(kinds) = &self.inputs {
            if in_vars.len() != kinds.len() {
                panic!(
                    "Incorrect input parameter count for userop {}. Expected {} but got {}",
                    self.name,
                    kinds.len(),
                    in_vars.len()
                );
            }
        }
    }

    /// Port of `placeInputs`: convert each input variable per its declared kind.
    fn place_inputs(
        &self,
        executor: &PcodeExecutor<T>,
        in_vars: &[Varnode],
    ) -> Vec<UseropValue<T>> {
        let kind_of = |i: usize| match &self.inputs {
            UseropInputs::Fixed(kinds) => kinds[i],
            UseropInputs::VariadicVarnodes => UseropValueKind::Varnode,
            UseropInputs::VariadicValues => UseropValueKind::Value,
        };
        in_vars
            .iter()
            .enumerate()
            .map(|(i, vn)| convert_input(kind_of(i), vn, executor))
            .collect()
    }
}

/// Port of the `UseropInputParam` records: read `vn` and present it as the declared kind.
fn convert_input<T: 'static>(
    kind: UseropValueKind,
    vn: &Varnode,
    executor: &PcodeExecutor<T>,
) -> UseropValue<T> {
    if kind == UseropValueKind::Varnode {
        return UseropValue::Varnode(vn.clone());
    }
    let value = executor
        .get_state()
        .lock()
        .expect("executor state lock poisoned")
        .get_var_varnode(vn, executor.get_reason());
    if kind == UseropValueKind::Value {
        return UseropValue::Value(value);
    }
    let arithmetic = executor.get_arithmetic();
    let arithmetic = arithmetic.as_ref();
    match kind {
        UseropValueKind::Byte => {
            UseropValue::Byte(concrete(arithmetic.to_long(&value, Purpose::Other)) as i8)
        }
        UseropValueKind::Short => {
            UseropValue::Short(concrete(arithmetic.to_long(&value, Purpose::Other)) as i16)
        }
        UseropValueKind::Int => {
            UseropValue::Int(concrete(arithmetic.to_long(&value, Purpose::Other)) as i32)
        }
        UseropValueKind::Long => {
            UseropValue::Long(concrete(arithmetic.to_long(&value, Purpose::Other)))
        }
        UseropValueKind::IntArray => {
            let mut big = concrete(arithmetic.to_big_integer(&value, Purpose::Other));
            let limbs = ((vn.get_size() + 3) / 4).max(0) as usize;
            let mut result = Vec::with_capacity(limbs);
            for _ in 0..limbs {
                result.push(big as i32);
                big >>= i32::BITS;
            }
            UseropValue::IntArray(result)
        }
        UseropValueKind::Float => {
            UseropValue::Float(concrete(arithmetic.to_float(&value, Purpose::Other)))
        }
        UseropValueKind::Double => {
            UseropValue::Double(concrete(arithmetic.to_double(&value, Purpose::Other)))
        }
        UseropValueKind::Boolean => {
            UseropValue::Boolean(concrete(arithmetic.is_true(&value, Purpose::Other)))
        }
        // `Varnode` and `Value` returned above; `Void` is rejected when the definition is built.
        UseropValueKind::Varnode | UseropValueKind::Value | UseropValueKind::Void => {
            unreachable!("handled before concretization")
        }
    }
}

/// Java lets the `ConcretionError` (a `PcodeExecutionException`) propagate out of `execute`; this
/// port's `execute` returns nothing, matching the already-ported
/// [`PcodeUseropDefinition::execute`], so a failed concretization panics instead.
fn concrete<V>(result: Result<V, ConcretionError>) -> V {
    result.unwrap_or_else(|e| panic!("Error executing userop: {e}"))
}

/// Port of `AnnotatedPcodeUseropDefinition.fromPrimitive`: lift a callback's return value into the
/// library's operand domain, sized to the destination variable.
fn from_primitive<T: 'static>(
    value: UseropValue<T>,
    size: i32,
    arithmetic: &dyn PcodeArithmetic<T>,
) -> T {
    match value {
        UseropValue::Value(v) => v,
        UseropValue::Byte(v) => arithmetic.from_const_u64(v as i64 as u64, size),
        UseropValue::Short(v) => arithmetic.from_const_u64(v as i64 as u64, size),
        UseropValue::Int(v) => arithmetic.from_const_u64(v as i64 as u64, size),
        UseropValue::Long(v) => arithmetic.from_const_u64(v as u64, size),
        UseropValue::Float(v) => arithmetic.from_const_f32(v, size),
        UseropValue::Double(v) => arithmetic.from_const_f64(v, size),
        UseropValue::Boolean(v) => arithmetic.from_const_bool(v, size),
        // Java's `fromPrimitive` falls through to an unchecked cast to `T`, which fails here.
        UseropValue::Varnode(_) | UseropValue::IntArray(_) => panic!(
            "Error executing userop: output must be a non-char primitive or the operand type"
        ),
    }
}

impl<T: 'static> PcodeUseropDefinition<T> for AnnotatedPcodeUseropDefinition<T> {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_input_count(&self) -> i32 {
        match &self.inputs {
            UseropInputs::Fixed(kinds) => kinds.len() as i32,
            UseropInputs::VariadicVarnodes | UseropInputs::VariadicValues => -1,
        }
    }

    fn execute(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
        op: &PcodeOp,
        out_var: Option<&Varnode>,
        in_vars: &[Varnode],
    ) {
        self.validate_inputs(in_vars);
        let args = self.place_inputs(executor, in_vars);
        let context = UseropContext { executor, library, op, out_var };
        let result = (self.callback)(&context, &args);
        // Java stores the result only if the method returned one *and* there is somewhere to put
        // it; a userop invoked for effect only discards it.
        if let (Some(result), Some(out_var)) = (result, out_var) {
            let arithmetic = executor.get_arithmetic();
            let value = from_primitive(result, out_var.get_size(), arithmetic.as_ref());
            executor
                .get_state()
                .lock()
                .expect("executor state lock poisoned")
                .set_var_varnode(out_var, &value);
        }
    }

    fn is_functional(&self) -> bool {
        self.annotation.functional
    }

    fn has_side_effects(&self) -> bool {
        self.annotation.has_side_effects
    }

    fn modifies_context(&self) -> bool {
        self.annotation.modifies_context
    }

    fn can_inline_pcode(&self) -> bool {
        self.annotation.can_inline
    }

    fn get_output_type(&self) -> Option<TypeId> {
        Some(self.output.type_id::<T>())
    }

    fn get_java_method(&self) -> Option<()> {
        None
    }

    /// Java returns the library the userop was declared in, reached through the reference each
    /// bound `MethodHandle` holds. A definition here is owned by the library's own map, so a
    /// back-reference would be a cycle -- and a borrow of it is not expressible from `&self`
    /// anyway -- so, as with
    /// [`AbstractSleighPcodeUseropDefinitionBase`](crate::pcode::exec::AbstractSleighPcodeUseropDefinitionBase),
    /// this is always `None`. A callback that needs library state captures a handle to it instead.
    fn get_defining_library(&self) -> Option<&dyn ErasedPcodeUseropLibrary> {
        None
    }
}

/// The shared state and concrete behavior of an annotated userop library.
///
/// Java's `AnnotatedPcodeUseropLibrary<T>` is an abstract class extending
/// [`DefaultPcodeUseropLibrary`], so the userops it collects live in that superclass's `ops` map.
/// Rust has no field inheritance, so this struct holds that map (by holding the default library
/// itself, as Java holds its superclass state) plus the constructor's work; a concrete library
/// embeds it and implements [`AnnotatedPcodeUseropLibrary`].
pub struct AnnotatedPcodeUseropLibraryBase<T: 'static> {
    ops: DefaultPcodeUseropLibrary<T>,
}

impl<T: 'static> AnnotatedPcodeUseropLibraryBase<T> {
    /// Construct the base with no userops yet collected.
    pub fn new() -> Self {
        Self { ops: DefaultPcodeUseropLibrary::new() }
    }

    /// Port of the constructor's loop: file each collected definition under its own name.
    pub fn install(&mut self, definitions: Vec<AnnotatedPcodeUseropDefinition<T>>) {
        for definition in definitions {
            self.ops.put_op(Arc::new(definition));
        }
    }

    /// The collected userops, keyed by name. A concrete library forwards
    /// [`PcodeUseropLibrary::get_userops`] here.
    pub fn get_userops(&self) -> &UseropMap<T> {
        self.ops.get_userops()
    }
}

impl<T: 'static> Default for AnnotatedPcodeUseropLibraryBase<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The operations a concrete annotated userop library must supply.
///
/// [`collect_definitions`](Self::collect_definitions) is the port of Java's reflective scan of the
/// subclass for `@PcodeUserop`-annotated methods -- the one thing an implementor writes -- and
/// [`base_mut`](Self::base_mut) exposes the embedded
/// [`AnnotatedPcodeUseropLibraryBase`] that the scan's results are installed into, standing in for
/// Java reaching its own inherited `ops` field. Everything else has a conventional implementation
/// here, mirroring the Java class's bodies.
pub trait AnnotatedPcodeUseropLibrary<T: 'static>: PcodeUseropLibrary<T> {
    /// The embedded shared state, so [`init`](Self::init) can install into it.
    fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<T>;

    /// The userops this library exports.
    ///
    /// Port of `collectDefinitions`/`AnnotatedPcodeUseropDefinition.create`. A definition whose
    /// callback needs the library's own state should capture a shared handle to it (Java binds the
    /// method handle to the library instead).
    fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<T>>;

    /// Collect this library's userops and file them.
    ///
    /// Port of the default constructor. Java runs this implicitly, during construction; Rust
    /// cannot dispatch to an override from a base constructor, so a concrete library calls this
    /// itself once it is fully built.
    fn init(&mut self) {
        let definitions = self.collect_definitions();
        self.base_mut().install(definitions);
    }

    /// Determine the operand type by examining the type substituted for `T`.
    ///
    /// Port of `getOperandType()`. Java resolves `T` reflectively and can therefore be overridden;
    /// here `T` is statically known, so this reports its [`TypeId`]. See
    /// [`operand_type`](crate::pcode::exec::operand_type).
    fn get_operand_type(&self) -> TypeId {
        operand_type::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, Reason};
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    /// Little-endian `i64` arithmetic, matching the one used in `paired_pcode_executor_state`'s
    /// tests. Everything but `from_const_bytes`/`to_concrete` comes from the trait's defaults, so
    /// `to_long`, `to_big_integer`, `from_const_u64`, etc. behave as the real thing would.
    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn binary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64, _sizein2: i32, _in2: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }
        fn mod_after_load(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    /// A state backed by an in-memory map keyed by offset.
    struct MapState {
        cells: HashMap<i64, i64>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, val: &i64) {
            self.cells.insert(*offset, *val);
        }
        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, _reason: Reason) -> i64 {
            *self.cells.get(offset).unwrap_or(&0)
        }
        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}


    /// A language just complete enough to bind a [`PcodeExecutor`]: it answers the two things the
    /// executor's constructor asks of it -- the program counter (none here) and the default space
    /// -- and nothing else. Paths are spelled out rather than imported, to keep the double local.
    struct MockLanguage {
        default_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            Box::new(crate::program::model::address::DefaultAddressFactory::new(vec![Arc::clone(
                &self.default_space,
            )]))
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// A real executor over [`MapState`], standing in for whatever executor would be invoking
    /// these userops.
    fn test_executor() -> PcodeExecutor<i64> {
        PcodeExecutor::new(
            Arc::new(MockLanguage {
                default_space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            }),
            Arc::new(I64Arithmetic),
            Arc::new(Mutex::new(MapState { cells: HashMap::new() })),
            Reason::ExecuteRead,
        )
    }

    fn poke(executor: &PcodeExecutor<i64>, var: &Varnode, value: i64) {
        executor.get_state().lock().unwrap().set_var_varnode(var, &value);
    }

    fn peek(executor: &PcodeExecutor<i64>, var: &Varnode) -> i64 {
        executor.get_state().lock().unwrap().get_var_varnode(var, Reason::Inspect)
    }

    /// The Rust rendering of a Java library declaring:
    ///
    /// ```java
    /// @PcodeUserop(functional = true, hasSideEffects = false)
    /// public long __add(long a, long b) { calls++; return a + b; }
    ///
    /// @PcodeUserop(variadic = true)
    /// public void __sink(Varnode[] ins) { seen = ins.length; }
    /// ```
    struct SumLibrary {
        base: AnnotatedPcodeUseropLibraryBase<i64>,
        /// Library state a userop mutates -- what Java reaches through `bindTo(library)`.
        calls: Arc<AtomicUsize>,
        seen: Arc<AtomicUsize>,
    }

    impl SumLibrary {
        fn new() -> Self {
            let mut library = Self {
                base: AnnotatedPcodeUseropLibraryBase::new(),
                calls: Arc::new(AtomicUsize::new(0)),
                seen: Arc::new(AtomicUsize::new(0)),
            };
            library.init();
            library
        }
    }

    impl ErasedPcodeUseropLibrary for SumLibrary {}

    impl PcodeUseropLibrary<i64> for SumLibrary {
        fn get_userops(&self) -> &UseropMap<i64> {
            self.base.get_userops()
        }
    }

    impl AnnotatedPcodeUseropLibrary<i64> for SumLibrary {
        fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<i64> {
            &mut self.base
        }

        fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<i64>> {
            let calls = Arc::clone(&self.calls);
            let seen = Arc::clone(&self.seen);
            vec![
                AnnotatedPcodeUseropDefinition::new(
                    "__add",
                    PcodeUserop {
                        functional: true,
                        has_side_effects: false,
                        ..Default::default()
                    },
                    UseropInputs::Fixed(vec![UseropValueKind::Long, UseropValueKind::Long]),
                    UseropValueKind::Long,
                    Box::new(move |_ctx, args| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Some(UseropValue::Long(
                            args[0].as_long().unwrap() + args[1].as_long().unwrap(),
                        ))
                    }),
                ),
                AnnotatedPcodeUseropDefinition::new(
                    "__sink",
                    PcodeUserop { variadic: true, ..Default::default() },
                    UseropInputs::VariadicVarnodes,
                    UseropValueKind::Void,
                    Box::new(move |_ctx, args| {
                        seen.store(args.len(), Ordering::SeqCst);
                        assert!(args.iter().all(|a| a.as_varnode().is_some()));
                        None
                    }),
                ),
            ]
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(ram().address(offset), size)
    }

    fn callother() -> PcodeOp {
        PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(ram().address(0), 0),
            Vec::new(),
            None,
        )
    }

    #[test]
    fn library_collects_its_definitions_keyed_by_name() {
        // Java's constructor does `ops.put(m.getName(), ...)` for every annotated method.
        let library = SumLibrary::new();
        let mut names: Vec<&str> = library.get_userops().keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, vec!["__add", "__sink"]);

        let add = &library.get_userops()["__add"];
        assert_eq!(add.get_name(), "__add");
        assert_eq!(add.get_input_count(), 2);
        assert!(add.is_functional());
        assert!(!add.has_side_effects());
        assert!(!add.modifies_context());
        assert!(!add.can_inline_pcode());
        // getOutputType(): the declared `long` return.
        assert_eq!(add.get_output_type(), Some(TypeId::of::<i64>()));

        // A variadic userop reports an input count of -1, and a void return.
        let sink = &library.get_userops()["__sink"];
        assert_eq!(sink.get_input_count(), -1);
        assert!(sink.has_side_effects(), "hasSideEffects defaults to true");
        assert_eq!(sink.get_output_type(), Some(TypeId::of::<()>()));

        assert_eq!(library.get_operand_type(), TypeId::of::<i64>());
    }

    #[test]
    fn execute_reads_inputs_invokes_the_callback_and_stores_the_result() {
        let library = SumLibrary::new();
        let executor = test_executor();

        let in0 = varnode(0x1000, 8);
        let in1 = varnode(0x1008, 8);
        let out = varnode(0x2000, 8);
        poke(&executor, &in0, 30);
        poke(&executor, &in1, 12);

        library.get_userops()["__add"].execute(
            &executor,
            &library,
            &callother(),
            Some(&out),
            &[in0.clone(), in1.clone()],
        );

        // Java: the return value is written back to the output varnode via
        // state.setVar(outVar, fromPrimitive(result, outVar.getSize(), arithmetic)).
        assert_eq!(peek(&executor, &out), 42);
        assert_eq!(library.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execute_without_an_output_variable_discards_the_result() {
        // Java: `if (result != null && outVar != null)`. Invoked for effect only, the sum is
        // computed but has nowhere to go.
        let library = SumLibrary::new();
        let executor = test_executor();
        let in0 = varnode(0x1000, 8);
        let in1 = varnode(0x1008, 8);
        poke(&executor, &in0, 30);
        poke(&executor, &in1, 12);

        library.get_userops()["__add"].execute(
            &executor,
            &library,
            &callother(),
            None,
            &[in0, in1],
        );

        assert_eq!(library.calls.load(Ordering::SeqCst), 1);
        assert_eq!(peek(&executor, &varnode(0x2000, 8)), 0);
    }

    #[test]
    #[should_panic(expected = "Incorrect input parameter count for userop __add. Expected 2 but got 1")]
    fn execute_rejects_the_wrong_number_of_inputs() {
        // Java: FixedArgsAnnotatedPcodeUseropDefinition.validateInputs throws
        // PcodeExecutionException with exactly this message.
        let library = SumLibrary::new();
        let executor = test_executor();
        library.get_userops()["__add"].execute(
            &executor,
            &library,
            &callother(),
            None,
            &[varnode(0x1000, 8)],
        );
    }

    #[test]
    fn a_variadic_userop_accepts_any_number_of_inputs() {
        let library = SumLibrary::new();
        let executor = test_executor();
        let sink = Arc::clone(&library.get_userops()["__sink"]);

        sink.execute(&executor, &library, &callother(), None, &[]);
        assert_eq!(library.seen.load(Ordering::SeqCst), 0);

        sink.execute(
            &executor,
            &library,
            &callother(),
            None,
            &[varnode(0x1000, 8), varnode(0x1008, 8), varnode(0x1010, 8)],
        );
        assert_eq!(library.seen.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn declared_input_kinds_drive_the_conversion_of_each_input() {
        // One userop taking every conversion the Java annotation processor recognizes, so each
        // UseropInputParam record's behavior is pinned. 0x4142434445464748 read as: a Varnode,
        // the raw i64 value, then truncated to 8/16/32/64 bits, split into 32-bit limbs
        // (least-significant first), and finally tested as a condition.
        let executor = test_executor();
        let input = varnode(0x1000, 8);
        poke(&executor, &input, 0x4142434445464748);

        let kinds = vec![
            UseropValueKind::Varnode,
            UseropValueKind::Value,
            UseropValueKind::Byte,
            UseropValueKind::Short,
            UseropValueKind::Int,
            UseropValueKind::Long,
            UseropValueKind::IntArray,
            UseropValueKind::Boolean,
        ];
        let seen: Arc<Mutex<Vec<UseropValue<i64>>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let definition = AnnotatedPcodeUseropDefinition::new(
            "__probe",
            PcodeUserop::default(),
            UseropInputs::Fixed(kinds.clone()),
            UseropValueKind::Void,
            Box::new(move |_ctx, args| {
                *recorder.lock().unwrap() = args.to_vec();
                None
            }),
        );

        let library = crate::pcode::exec::pcode_userop_library::nil::<i64>();
        let in_vars: Vec<Varnode> = kinds.iter().map(|_| input.clone()).collect();
        definition.execute(&executor, &library, &callother(), None, &in_vars);

        let args = seen.lock().unwrap().clone();
        assert_eq!(args[0], UseropValue::Varnode(input.clone()));
        assert_eq!(args[1], UseropValue::Value(0x4142434445464748));
        assert_eq!(args[2], UseropValue::Byte(0x48));
        assert_eq!(args[3], UseropValue::Short(0x4748));
        assert_eq!(args[4], UseropValue::Int(0x45464748));
        assert_eq!(args[5], UseropValue::Long(0x4142434445464748));
        // (size + 3) / 4 == 2 limbs for an 8-byte variable, least significant first.
        assert_eq!(args[6], UseropValue::IntArray(vec![0x45464748, 0x41424344]));
        assert_eq!(args[7], UseropValue::Boolean(true));
    }

    #[test]
    fn a_returned_primitive_is_lifted_into_the_operand_domain() {
        // Java's fromPrimitive: each primitive goes through the matching
        // PcodeArithmetic.fromConst overload, sized to the output varnode.
        let arithmetic = I64Arithmetic;
        assert_eq!(from_primitive(UseropValue::Byte(-1i8), 8, &arithmetic), -1i64);
        assert_eq!(from_primitive(UseropValue::Int(0x1234), 8, &arithmetic), 0x1234);
        assert_eq!(from_primitive(UseropValue::Boolean(true), 8, &arithmetic), 1);
        assert_eq!(from_primitive(UseropValue::Value(7i64), 8, &arithmetic), 7);
        // fromConst(float, size) stores the raw bits.
        assert_eq!(
            from_primitive(UseropValue::Float(1.5f32), 8, &arithmetic),
            1.5f32.to_bits() as i64
        );
    }

    #[test]
    #[should_panic(expected = "Variadic userop must have a parameter for the inputs")]
    fn a_variadic_annotation_needs_a_parameter_for_the_inputs() {
        // Java: VariadicAnnotatedPcodeUseropDefinition.initFinished throws when posIns == -1.
        let _: AnnotatedPcodeUseropDefinition<i64> = AnnotatedPcodeUseropDefinition::new(
            "__bad",
            PcodeUserop { variadic: true, ..Default::default() },
            UseropInputs::Fixed(vec![UseropValueKind::Long]),
            UseropValueKind::Void,
            Box::new(|_ctx, _args| None),
        );
    }
}
