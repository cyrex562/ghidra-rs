//! An executor state piece which internally uses `long` to address contents.
//!
//! Corresponds to `ghidra.pcode.exec.AbstractLongOffsetPcodeExecutorStatePiece`.
//!
//! This also provides an internal mechanism for breaking the piece down into the spaces defined by
//! a language. It also provides for the special treatment of the `unique` space.
//!
//! Java's abstract class carries both state (five fields) and behavior. Rust has no field
//! inheritance, so the two are split:
//!
//! * [`AbstractLongOffsetPcodeExecutorStatePieceBase`] holds the fields and the concrete methods.
//!   The ones that dispatch back into the subclass are associated functions taking the piece
//!   itself, following the same convention as
//!   [`AbstractSleighPcodeUseropDefinitionBase::execute`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase::execute).
//! * [`AbstractLongOffsetPcodeExecutorStatePiece`] declares the operations Java leaves abstract,
//!   plus the handful Java implements but explicitly documents as overridable (`setUnique`,
//!   `getUnique`, `getFromNullSpace`, `checkSize`, and the protected `setVarInternal`/
//!   `getVarInternal` cores), which only a trait can express.
//!
//! A concrete piece embeds the base, implements this trait, and implements
//! [`PcodeExecutorStatePiece`] by forwarding each method to the matching associated function on
//! the base. It must forward *all* of `set_var`/`set_var_abstract`/`get_var`/`get_var_abstract`
//! (and the `_internal` variants): the ported [`PcodeExecutorStatePiece`] defaults implement the
//! `long`-addressed forms in terms of the abstract-domain ones, while this class inverts that, so
//! leaving either side to the trait default would recurse forever.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::{rng_set, PcodeStateCallbacks, NONE};
use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::pcode::OpCode;
use crate::util::msg::Msg;

/// The shared state and concrete behavior of a long-offset executor state piece.
///
/// `A` is the type used to address contents (convertible to and from `long`), `T` is the type of
/// values stored, and `CB` is the concrete type of the callbacks receiving emulation events.
///
/// `CB` is a type parameter rather than a trait object because
/// [`PcodeStateCallbacks`]'s methods are generic per call, which makes that trait not object-safe.
/// The callbacks are held in an `Arc` (Java holds a plain reference to a shared object): the write
/// path needs them while the piece itself is mutably borrowed, which a borrow of the field could
/// not survive.
pub struct AbstractLongOffsetPcodeExecutorStatePieceBase<A, T, CB> {
    language: Arc<dyn Language>,
    address_arithmetic: Arc<dyn PcodeArithmetic<A>>,
    arithmetic: Arc<dyn PcodeArithmetic<T>>,
    cb: Arc<CB>,
    unique_space: Arc<AddressSpace>,
}

impl<A, T, CB> AbstractLongOffsetPcodeExecutorStatePieceBase<A, T, CB>
where
    CB: PcodeStateCallbacks,
{
    /// Construct a state piece for the given language and arithmetic.
    ///
    /// Port of the constructor `AbstractLongOffsetPcodeExecutorStatePiece(Language,
    /// PcodeArithmetic<A>, PcodeArithmetic<T>, PcodeStateCallbacks)`.
    ///
    /// * `language` -- the language (used for its memory model)
    /// * `address_arithmetic` -- an arithmetic used to generate default values of `A`
    /// * `arithmetic` -- an arithmetic used to generate default values of `T`. It must be able to
    ///   derive concrete sizes, i.e., [`PcodeArithmetic::size_of`] must always return the correct
    ///   value.
    /// * `cb` -- callbacks to receive emulation events
    ///
    /// Panics if the language defines no unique space; Java would store `null` and fail later.
    pub fn new(
        language: Arc<dyn Language>,
        address_arithmetic: Arc<dyn PcodeArithmetic<A>>,
        arithmetic: Arc<dyn PcodeArithmetic<T>>,
        cb: Arc<CB>,
    ) -> Self {
        let unique_space = language
            .get_address_factory()
            .get_unique_space()
            .expect("language defines no unique space");
        Self { language, address_arithmetic, arithmetic, cb, unique_space }
    }

    /// The language whose memory model this piece uses.
    ///
    /// Port of `getLanguage()`. The ported [`PcodeExecutorStatePiece::get_language`] returns an
    /// owned `Box<dyn Language>`, which cannot be produced from a shared handle, so a concrete
    /// piece satisfies that method however its own language representation allows.
    pub fn language(&self) -> &Arc<dyn Language> {
        &self.language
    }

    /// Port of `getAddressArithmetic()`.
    pub fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<A>> {
        Arc::clone(&self.address_arithmetic)
    }

    /// Port of `getArithmetic()`.
    pub fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        Arc::clone(&self.arithmetic)
    }

    /// The callbacks receiving emulation events, Java's `cb` field.
    pub fn cb(&self) -> &Arc<CB> {
        &self.cb
    }

    /// The language's unique space, resolved once at construction.
    pub fn unique_space(&self) -> &Arc<AddressSpace> {
        &self.unique_space
    }

    /// Set the value of a variable, addressed by an offset in the abstract domain `A`.
    ///
    /// Port of `setVar(AddressSpace, A, int, boolean, T)`: concretize the offset, then take the
    /// `long`-addressed path. Java's `toLong` throws `ConcretionError`; this panics.
    pub fn set_var_abstract<S, P>(
        piece: &mut P,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        quantize: bool,
        val: &T,
    ) where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
        T: Clone,
    {
        let l_offset = Self::to_long_offset(piece, offset, Purpose::Store);
        Self::set_var(piece, space, l_offset, size, quantize, val);
    }

    /// Set the value of a variable without issuing callbacks, addressed by an offset in the
    /// abstract domain `A`.
    ///
    /// Port of `setVarInternal(AddressSpace, A, int, T)`.
    pub fn set_var_internal_abstract<S, P>(
        piece: &mut P,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        val: &T,
    ) where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        let l_offset = Self::to_long_offset(piece, offset, Purpose::Store);
        Self::set_var_internal(piece, space, l_offset, size, val);
    }

    /// Set the value of a variable.
    ///
    /// Port of `setVar(AddressSpace, long, int, boolean, T)`: validate the range, check the value
    /// size, then write with this piece's own callbacks.
    pub fn set_var<S, P>(
        piece: &mut P,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        val: &T,
    ) where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
        T: Clone,
    {
        piece.check_range(space, offset, size);
        let val = piece.check_size(size, val);
        let cb = Arc::clone(piece.base().cb());
        piece.set_var_internal_with_callbacks(space, offset, size, quantize, &val, cb.as_ref());
    }

    /// Set the value of a variable without issuing callbacks.
    ///
    /// Port of `setVarInternal(AddressSpace, long, int, T)`: never quantizes, and passes
    /// [`NONE`] rather than this piece's callbacks.
    pub fn set_var_internal<S, P>(
        piece: &mut P,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        val: &T,
    ) where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        piece.set_var_internal_with_callbacks(space, offset, size, false, val, &NONE);
    }

    /// Get the value of a variable, addressed by an offset in the abstract domain `A`.
    ///
    /// Port of `getVar(AddressSpace, A, int, boolean, Reason)`.
    pub fn get_var_abstract<S, P>(
        piece: &P,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> T
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        let l_offset = Self::to_long_offset(piece, offset, Purpose::Load);
        Self::get_var(piece, space, l_offset, size, quantize, reason)
    }

    /// Get the value of a variable without issuing callbacks, addressed by an offset in the
    /// abstract domain `A`.
    ///
    /// Port of `getVarInternal(AddressSpace, A, int, Reason)`.
    pub fn get_var_internal_abstract<S, P>(
        piece: &P,
        space: &Arc<AddressSpace>,
        offset: &A,
        size: i32,
        reason: Reason,
    ) -> T
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        let l_offset = Self::to_long_offset(piece, offset, Purpose::Load);
        Self::get_var_internal(piece, space, l_offset, size, reason)
    }

    /// Get the value of a variable.
    ///
    /// Port of `getVar(AddressSpace, long, int, boolean, Reason)`.
    pub fn get_var<S, P>(
        piece: &P,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> T
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        piece.check_range(space, offset, size);
        piece.get_var_internal_with_callbacks(
            space,
            offset,
            size,
            quantize,
            reason,
            piece.base().cb().as_ref(),
        )
    }

    /// Get the value of a variable without issuing callbacks.
    ///
    /// Port of `getVarInternal(AddressSpace, long, int, Reason)`: never quantizes, and passes
    /// [`NONE`] rather than this piece's callbacks.
    pub fn get_var_internal<S, P>(
        piece: &P,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        reason: Reason,
    ) -> T
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        piece.get_var_internal_with_callbacks(space, offset, size, false, reason, &NONE)
    }

    /// Get all register values known to this piece.
    ///
    /// Port of `getRegisterValues()`: group the language's registers by their address space, and
    /// scan each internal space that exists for the registers living in it. Java collects into a
    /// `HashMap`; the ported [`PcodeExecutorStatePiece::get_register_values`] returns a `Vec` of
    /// pairs, so the grouping is a `Vec` too, which also keeps the result in the language's own
    /// register order.
    pub fn get_register_values<S, P>(piece: &P) -> Vec<(RegisterRef, T)>
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        let mut regs_by_space: Vec<(Arc<AddressSpace>, Vec<RegisterRef>)> = Vec::new();
        for register in piece.base().language().get_registers() {
            let space = register.borrow().address_space();
            match regs_by_space.iter_mut().find(|(s, _)| *s == space) {
                Some((_, registers)) => registers.push(register),
                None => regs_by_space.push((space, vec![register])),
            }
        }
        let mut result = Vec::new();
        for (space, registers) in &regs_by_space {
            if let Some(s) = piece.get_for_space(space) {
                result.extend(piece.get_register_values_from_space(s, registers));
            }
        }
        result
    }

    /// Concretize an offset of domain `A` to a `long`, panicking where Java throws
    /// `ConcretionError`.
    fn to_long_offset<S, P>(piece: &P, offset: &A, purpose: Purpose) -> i64
    where
        P: AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>,
    {
        piece
            .base()
            .get_address_arithmetic()
            .to_long(offset, purpose)
            .expect("offset could not be made concrete to address this state piece")
    }
}

/// Copy every internal space of `from` into `into`, passing each through `forker`.
///
/// Port of the static helper `forkMap(Map<AddressSpace, S>, Map<AddressSpace, S>, Function<S, S>)`.
/// It is a free function rather than an associated function on
/// [`AbstractLongOffsetPcodeExecutorStatePieceBase`] because, like Java's `static <S>`, it is
/// generic only in the internal space type.
pub fn fork_map<S>(
    into: &mut HashMap<Arc<AddressSpace>, S>,
    from: &HashMap<Arc<AddressSpace>, S>,
    forker: impl Fn(&S) -> S,
) {
    for (space, s) in from {
        into.insert(Arc::clone(space), forker(s));
    }
}

/// The operations a concrete long-offset state piece must supply.
///
/// `S` is the type of an execute state space, internally associated with an address space.
///
/// Beyond the four operations Java declares abstract, this declares the methods Java implements
/// but documents as overridable, since only a trait can express an override in Rust.
///
/// Java's `getForSpace(AddressSpace, boolean toWrite)` becomes two members. The read side is
/// [`get_for_space`](Self::get_for_space), which returns `None` where Java returns `null`. The
/// write side is fused into [`set_in_space`](Self::set_in_space): Java's `toWrite = true` lookup
/// never returns `null`, and its result is used only to hand to `setInSpace`, which the borrow
/// checker forbids -- a `&mut S` borrowed out of the piece cannot be live while the piece's own
/// state is also in use, and two of the in-tree subclasses' `setInSpace` implementations do read
/// their own fields. Fusing them lets the implementor do the lazy creation and the write under a
/// single `&mut self`.
pub trait AbstractLongOffsetPcodeExecutorStatePiece<A, T, S, CB>: PcodeExecutorStatePiece<A, T>
where
    CB: PcodeStateCallbacks,
{
    /// The embedded shared state.
    fn base(&self) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<A, T, CB>;

    /// Get the internal space for the given address space, for reading.
    ///
    /// Port of `getForSpace(AddressSpace, false)`. Where internal spaces are generated lazily,
    /// this returns `None` if the space has not been created yet.
    fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&S>;

    /// Set a value in the given space.
    ///
    /// Port of `getForSpace(space, true)` followed by `setInSpace(S, long, int, T,
    /// PcodeStateCallbacks)`: the internal space must be created if it does not exist, then
    /// written to. `offset` has already been quantized, if requested.
    fn set_in_space<C: PcodeStateCallbacks>(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        val: &T,
        cb: &C,
    );

    /// Get a value from the given space.
    ///
    /// Port of `getFromSpace(S, long, int, Reason, PcodeStateCallbacks)`.
    fn get_from_space<C: PcodeStateCallbacks>(
        &self,
        space: &S,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> T;

    /// Scan the given space for register values, as in
    /// [`PcodeExecutorStatePiece::get_register_values`].
    ///
    /// Port of `getRegisterValuesFromSpace(S, List<Register>)`. `registers` are the registers
    /// known to be in the corresponding address space.
    fn get_register_values_from_space(
        &self,
        space: &S,
        registers: &[RegisterRef],
    ) -> Vec<(RegisterRef, T)>;

    /// In case spaces are generated lazily, and we're reading from a space that doesn't yet
    /// exist, "read" a default value.
    ///
    /// Port of `getFromNullSpace(int, Reason, PcodeStateCallbacks)`. By default, the returned
    /// value is 0, which should be reasonable for all implementations.
    fn get_from_null_space<C: PcodeStateCallbacks>(
        &self,
        size: i32,
        _reason: Reason,
        _cb: &C,
    ) -> T {
        self.base().get_arithmetic().from_const_u64(0, size)
    }

    /// Set a value in the unique space.
    ///
    /// Port of `setUnique(long, int, T, PcodeStateCallbacks)`. Some state pieces treat unique
    /// values in a way that merits a separate implementation. This permits the standard path to be
    /// overridden.
    fn set_unique<C: PcodeStateCallbacks>(&mut self, offset: i64, size: i32, val: &T, cb: &C) {
        let unique_space = Arc::clone(self.base().unique_space());
        self.set_in_space(&unique_space, offset, size, val, cb);
    }

    /// Get a value from the unique space.
    ///
    /// Port of `getUnique(long, int, Reason, PcodeStateCallbacks)`. Some state pieces treat unique
    /// values in a way that merits a separate implementation. This permits the standard path to be
    /// overridden.
    fn get_unique<C: PcodeStateCallbacks>(
        &self,
        offset: i64,
        size: i32,
        reason: Reason,
        cb: &C,
    ) -> T {
        let unique_space = Arc::clone(self.base().unique_space());
        match self.get_for_space(&unique_space) {
            None => self.get_from_null_space(size, reason, cb),
            Some(s) => self.get_from_space(s, offset, size, reason, cb),
        }
    }

    /// Check that the size of the value matches that given.
    ///
    /// Port of `checkSize(int, T)`. Extensions may override this and do nothing when the abstract
    /// type has no defined size. Java returns the value, possibly adjusted; a value smaller than
    /// the variable is zero-extended (with a warning), and one larger is rejected -- Java throws
    /// `IllegalArgumentException`, this panics.
    fn check_size(&self, size: i32, val: &T) -> T
    where
        T: Clone,
    {
        let arithmetic = self.base().get_arithmetic();
        let val_size = arithmetic.size_of(val) as i32;
        if val_size > size {
            panic!("Value is larger than variable: {} > {}", val_size, size);
        }
        if val_size < size {
            Msg::warn(
                "AbstractLongOffsetPcodeExecutorStatePiece",
                &format!(
                    "Value is smaller than variable: {} < {}. Zero extending",
                    val_size, size
                ),
            );
            return arithmetic.unary_op(OpCode::IntZext, size, val_size, val);
        }
        val.clone()
    }

    /// The core write path, taking the callbacks to notify explicitly.
    ///
    /// Port of the protected `setVarInternal(AddressSpace, long, int, boolean, T,
    /// PcodeStateCallbacks)`. Writes to the constant space are rejected (Java throws
    /// `IllegalArgumentException`, this panics), writes to the unique space are routed through
    /// [`set_unique`](Self::set_unique), and everything else goes to
    /// [`set_in_space`](Self::set_in_space).
    fn set_var_internal_with_callbacks<C: PcodeStateCallbacks>(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        val: &T,
        cb: &C,
    ) {
        if space.space_type() == AddressSpaceType::Constant {
            panic!("Cannot write to constant space");
        }
        if space.space_type() == AddressSpaceType::Unique {
            self.set_unique(offset, size, val, cb);
            return;
        }
        let offset = if quantize { self.quantize_offset(space, offset) } else { offset };
        self.set_in_space(space, offset, size, val, cb);
    }

    /// The core read path, taking the callbacks to notify explicitly.
    ///
    /// Port of the protected `getVarInternal(AddressSpace, long, int, boolean, Reason,
    /// PcodeStateCallbacks)`. Reads from the constant space return the offset itself, reads from
    /// the unique space are routed through [`get_unique`](Self::get_unique), and a read from a
    /// space that does not exist yet gives the callbacks a chance to initialize it before falling
    /// back to [`get_from_null_space`](Self::get_from_null_space).
    fn get_var_internal_with_callbacks<C: PcodeStateCallbacks>(
        &self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        reason: Reason,
        cb: &C,
    ) -> T
    where
        Self: Sized,
    {
        if space.space_type() == AddressSpaceType::Constant {
            return self.base().get_arithmetic().from_const_u64(offset as u64, size);
        }
        if space.space_type() == AddressSpaceType::Unique {
            return self.get_unique(offset, size, reason, cb);
        }
        if self.get_for_space(space).is_none() {
            let set = rng_set(space, offset, size);
            let erased: &dyn PcodeExecutorStatePiece<A, T> = self;
            if set.has_same_addresses(&cb.read_uninitialized(erased, &set, reason)) {
                return self.get_from_null_space(size, reason, cb);
            }
            if self.get_for_space(space).is_none() {
                return self.get_from_null_space(size, reason, cb);
            }
        }
        let offset = if quantize { self.quantize_offset(space, offset) } else { offset };
        let s = self.get_for_space(space).expect("space was just confirmed present");
        self.get_from_space(s, offset, size, reason, cb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, DefaultAddressFactory,
    };
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::Register;
    use crate::program::model::mem::mem_buffer::MemBuffer;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2)
    }

    fn unique_space() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 3)
    }

    fn const_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
    }

    /// A word-addressable space (two bytes per addressable unit), to exercise quantization.
    fn word_space() -> Arc<AddressSpace> {
        AddressSpace::new("code", 32, 2, AddressSpaceType::Code, 4)
    }

    /// Little-endian arithmetic over concrete byte vectors -- the `byte[]` domain every in-tree
    /// subclass of this class uses for its addresses. `size_of` really is the value's length, as
    /// the constructor's contract requires, so `check_size` behaves as it does in Java.
    struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            assert_eq!(opcode, OpCode::IntZext, "only zero extension is exercised here");
            let mut out = in1.clone();
            out.resize(sizeout as usize, 0);
            out
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &Vec<u8>,
            _sizein2: i32,
            _in2: &Vec<u8>,
        ) -> Vec<u8> {
            unimplemented!("not exercised by these tests")
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }

        fn to_concrete(
            &self,
            value: &Vec<u8>,
            _purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }

        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// Callbacks that record every `readUninitialized` they are asked about, and otherwise behave
    /// like [`NONE`] (reporting the whole range as still uninitialized).
    #[derive(Default)]
    struct RecordingCallbacks {
        /// `(space name, offset, length)` of each concrete `read_uninitialized` call.
        reads: RefCell<Vec<(String, i64, u64)>>,
    }

    impl PcodeStateCallbacks for RecordingCallbacks {
        fn read_uninitialized<A, T>(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<A, T>,
            set: &dyn AddressSetView,
            _reason: Reason,
        ) -> AddressSet {
            if let Some(range) = set.first_range() {
                self.reads.borrow_mut().push((
                    range.min_address().space().name().to_string(),
                    range.min_address().offset(),
                    range.length(),
                ));
            }
            AddressSet::from_set(set)
        }
    }

    /// An internal space: a byte-addressed map, as in `BytesPcodeExecutorStateSpace`.
    #[derive(Default)]
    struct TestSpace {
        bytes: HashMap<i64, u8>,
    }

    impl TestSpace {
        fn write(&mut self, offset: i64, val: &[u8]) {
            for (i, b) in val.iter().enumerate() {
                self.bytes.insert(offset + i as i64, *b);
            }
        }

        fn read(&self, offset: i64, size: i32) -> Vec<u8> {
            (0..size as i64).map(|i| *self.bytes.get(&(offset + i)).unwrap_or(&0)).collect()
        }
    }

    /// A concrete piece in the shape every real subclass takes: internal spaces created lazily,
    /// keyed by address space.
    struct MapPiece {
        base: AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, RecordingCallbacks>,
        spaces: HashMap<Arc<AddressSpace>, TestSpace>,
    }

    impl MapPiece {
        fn new(cb: Arc<RecordingCallbacks>) -> Self {
            Self {
                base: AbstractLongOffsetPcodeExecutorStatePieceBase::new(
                    Arc::new(MockLanguage),
                    Arc::new(BytesArithmetic),
                    Arc::new(BytesArithmetic),
                    cb,
                ),
                spaces: HashMap::new(),
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for MapPiece {}

    impl AbstractLongOffsetPcodeExecutorStatePiece<Vec<u8>, Vec<u8>, TestSpace, RecordingCallbacks>
        for MapPiece
    {
        fn base(
            &self,
        ) -> &AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, RecordingCallbacks>
        {
            &self.base
        }

        fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&TestSpace> {
            self.spaces.get(space)
        }

        fn set_in_space<C: PcodeStateCallbacks>(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: i64,
            _size: i32,
            val: &Vec<u8>,
            _cb: &C,
        ) {
            self.spaces.entry(Arc::clone(space)).or_default().write(offset, val);
        }

        fn get_from_space<C: PcodeStateCallbacks>(
            &self,
            space: &TestSpace,
            offset: i64,
            size: i32,
            _reason: Reason,
            _cb: &C,
        ) -> Vec<u8> {
            space.read(offset, size)
        }

        fn get_register_values_from_space(
            &self,
            space: &TestSpace,
            registers: &[RegisterRef],
        ) -> Vec<(RegisterRef, Vec<u8>)> {
            registers
                .iter()
                .map(|register| {
                    let (offset, size) = {
                        let reg = register.borrow();
                        (reg.address().offset(), reg.minimum_byte_size())
                    };
                    (Rc::clone(register), space.read(offset, size))
                })
                .collect()
        }
    }

    impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for MapPiece {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            self.base.get_address_arithmetic()
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            self.base.get_arithmetic()
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }

        fn set_var_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            quantize: bool,
            val: &Vec<u8>,
        ) {
            Base::set_var_abstract(self, space, offset, size, quantize, val);
        }

        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            val: &Vec<u8>,
        ) {
            Base::set_var_internal_abstract(self, space, offset, size, val);
        }

        fn set_var(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            quantize: bool,
            val: &Vec<u8>,
        ) {
            Base::set_var(self, space, offset, size, quantize, val);
        }

        fn set_var_internal(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            val: &Vec<u8>,
        ) {
            Base::set_var_internal(self, space, offset, size, val);
        }

        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            quantize: bool,
            reason: Reason,
        ) -> Vec<u8> {
            Base::get_var_abstract(self, space, offset, size, quantize, reason)
        }

        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            reason: Reason,
        ) -> Vec<u8> {
            Base::get_var_internal_abstract(self, space, offset, size, reason)
        }

        fn get_var(
            &self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            quantize: bool,
            reason: Reason,
        ) -> Vec<u8> {
            Base::get_var(self, space, offset, size, quantize, reason)
        }

        fn get_var_internal(
            &self,
            space: &Arc<AddressSpace>,
            offset: i64,
            size: i32,
            reason: Reason,
        ) -> Vec<u8> {
            Base::get_var_internal(self, space, offset, size, reason)
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
            Base::get_register_values(self)
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }

        fn clear(&mut self) {
            self.spaces.clear();
        }
    }

    /// Shorthand for the base, whose associated functions carry the concrete behavior.
    type Base =
        AbstractLongOffsetPcodeExecutorStatePieceBase<Vec<u8>, Vec<u8>, RecordingCallbacks>;

    fn piece() -> MapPiece {
        MapPiece::new(Arc::new(RecordingCallbacks::default()))
    }

    #[test]
    fn set_var_and_get_var_round_trip_through_a_lazily_created_space() {
        let mut piece = piece();
        let ram = ram_space();

        // Nothing exists yet; the space is created on the write.
        assert!(piece.get_for_space(&ram).is_none());
        piece.set_var(&ram, 0x1000, 4, false, &vec![1, 2, 3, 4]);

        assert!(piece.get_for_space(&ram).is_some());
        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![1, 2, 3, 4]);
        // Bytes really landed at the given offset, so a shifted read sees the tail.
        assert_eq!(piece.get_var(&ram, 0x1002, 2, false, Reason::ExecuteRead), vec![3, 4]);
    }

    #[test]
    fn abstract_offsets_are_concretized_to_long_offsets() {
        let mut piece = piece();
        let ram = ram_space();
        // Little-endian byte offset for 0x1000, as the byte[] address domain represents it.
        let offset = vec![0x00, 0x10, 0x00, 0x00];

        piece.set_var_abstract(&ram, &offset, 2, false, &vec![0xaa, 0xbb]);

        assert_eq!(piece.get_var(&ram, 0x1000, 2, false, Reason::ExecuteRead), vec![0xaa, 0xbb]);
        assert_eq!(
            piece.get_var_abstract(&ram, &offset, 2, false, Reason::ExecuteRead),
            vec![0xaa, 0xbb]
        );
    }

    #[test]
    fn unique_space_access_is_routed_through_set_unique_and_get_unique() {
        let mut piece = piece();
        let unique = unique_space();

        piece.set_var(&unique, 0x20, 2, false, &vec![7, 8]);

        // setUnique writes into the space the language reports as unique, which the constructor
        // resolved once; the piece's own map is therefore keyed by that same space.
        assert!(piece.get_for_space(&unique).is_some());
        assert_eq!(piece.get_var(&unique, 0x20, 2, false, Reason::ExecuteRead), vec![7, 8]);
    }

    #[test]
    fn get_unique_falls_back_to_the_null_space_value_before_anything_is_written() {
        let piece = piece();
        // Java: getUnique finds no space and returns getFromNullSpace, i.e. fromConst(0, size).
        assert_eq!(
            piece.get_var(&unique_space(), 0x20, 4, false, Reason::ExecuteRead),
            vec![0, 0, 0, 0]
        );
        // The unique path never consults readUninitialized.
        assert!(piece.base.cb().reads.borrow().is_empty());
    }

    #[test]
    fn constant_space_reads_return_the_offset_itself() {
        let piece = piece();
        // Java: arithmetic.fromConst(offset, size), little endian here.
        assert_eq!(
            piece.get_var(&const_space(), 0x42, 4, false, Reason::ExecuteRead),
            vec![0x42, 0, 0, 0]
        );
        // No space was consulted, so the callbacks were never asked to initialize anything.
        assert!(piece.base.cb().reads.borrow().is_empty());
    }

    #[test]
    #[should_panic(expected = "Cannot write to constant space")]
    fn constant_space_writes_are_rejected() {
        piece().set_var(&const_space(), 0x42, 4, false, &vec![1, 2, 3, 4]);
    }

    #[test]
    fn reading_a_missing_space_consults_the_callbacks_then_reads_the_null_space_value() {
        let cb = Arc::new(RecordingCallbacks::default());
        let mut piece = MapPiece::new(Arc::clone(&cb));
        let ram = ram_space();

        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![0, 0, 0, 0]);
        // Java: rngSet(space, offset, size) is handed to readUninitialized exactly once.
        assert_eq!(cb.reads.borrow().as_slice(), &[("ram".to_string(), 0x1000, 4)]);

        // Once the space exists, the callback is not consulted again.
        piece.set_var(&ram, 0x1000, 4, false, &vec![9, 9, 9, 9]);
        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![9, 9, 9, 9]);
        assert_eq!(cb.reads.borrow().len(), 1);
    }

    #[test]
    fn get_var_internal_skips_the_callbacks() {
        let cb = Arc::new(RecordingCallbacks::default());
        let piece = MapPiece::new(Arc::clone(&cb));

        // Java passes PcodeStateCallbacks.NONE, whose readUninitialized reports the whole range
        // uninitialized without reaching this state's own callbacks.
        assert_eq!(
            piece.get_var_internal(&ram_space(), 0x1000, 4, Reason::ExecuteRead),
            vec![0, 0, 0, 0]
        );
        assert!(cb.reads.borrow().is_empty());
    }

    #[test]
    fn check_size_zero_extends_a_value_smaller_than_the_variable() {
        let mut piece = piece();
        let ram = ram_space();

        // Java warns and applies INT_ZEXT to widen the value to the variable's size.
        piece.set_var(&ram, 0x1000, 4, false, &vec![1, 2]);

        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![1, 2, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "Value is larger than variable: 4 > 2")]
    fn check_size_rejects_a_value_larger_than_the_variable() {
        piece().set_var(&ram_space(), 0x1000, 2, false, &vec![1, 2, 3, 4]);
    }

    #[test]
    fn set_var_internal_does_not_check_the_value_size() {
        let mut piece = piece();
        let ram = ram_space();

        // Java's setVarInternal bypasses checkSize entirely, so a short value stays short.
        piece.set_var_internal(&ram, 0x1000, 4, &vec![1, 2]);

        assert_eq!(piece.get_var(&ram, 0x1000, 4, false, Reason::ExecuteRead), vec![1, 2, 0, 0]);
        assert_eq!(piece.get_var(&ram, 0x1002, 2, false, Reason::ExecuteRead), vec![0, 0]);
    }

    #[test]
    fn quantize_rounds_the_offset_to_the_addressable_unit() {
        let mut piece = piece();
        let words = word_space();

        // quantizeOffset(0x1005) == truncateAddressableWordOffset(0x1005) * 2 == 0x200a.
        piece.set_var(&words, 0x1005, 2, true, &vec![0xde, 0xad]);

        assert_eq!(piece.get_var(&words, 0x200a, 2, false, Reason::ExecuteRead), vec![0xde, 0xad]);
        assert_eq!(piece.get_var(&words, 0x1005, 2, false, Reason::ExecuteRead), vec![0, 0]);
    }

    #[test]
    fn get_register_values_groups_registers_by_space_and_skips_absent_spaces() {
        let mut piece = piece();
        let registers = register_space();

        // Nothing written yet: neither the register space nor ram exists, so no values at all.
        assert!(piece.get_register_values().is_empty());

        piece.set_var(&registers, 0x0, 2, false, &vec![0x11, 0x22]);
        let values = piece.get_register_values();

        // MockLanguage reports R0 (register space) and RAM0 (ram space); only R0's space exists.
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0.borrow().name(), "R0");
        assert_eq!(values[0].1, vec![0x11, 0x22]);
    }

    #[test]
    fn fork_map_copies_every_space_through_the_forker() {
        let mut from: HashMap<Arc<AddressSpace>, TestSpace> = HashMap::new();
        from.entry(ram_space()).or_default().write(0x10, &[1, 2, 3]);
        let mut into: HashMap<Arc<AddressSpace>, TestSpace> = HashMap::new();

        fork_map(&mut into, &from, |s| TestSpace { bytes: s.bytes.clone() });

        assert_eq!(into.len(), 1);
        assert_eq!(into[&ram_space()].read(0x10, 3), vec![1, 2, 3]);
    }

    use std::rc::Rc;

    /// A language exposing just what this class needs: an address factory (for the unique space)
    /// and a register list spanning two address spaces.
    struct MockLanguage;

    fn mock_registers() -> Vec<RegisterRef> {
        vec![
            Register::new("R0", "", register_space().address(0), 2, false, Register::TYPE_NONE),
            Register::new("RAM0", "", ram_space().address(0x8000), 2, false, Register::TYPE_NONE),
        ]
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>>
        {
            unimplemented!("not exercised by these tests")
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
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![
                ram_space(),
                register_space(),
                unique_space(),
                word_space(),
            ]))
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
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
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::InstructionPrototype>,
            crate::program::model::lang::ParseError,
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
            mock_registers()
        }
        fn get_register_names(&self) -> Vec<String> {
            vec!["R0".to_string(), "RAM0".to_string()]
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
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
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext,
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
        ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
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
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
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
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(
            &self,
        ) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }
}
