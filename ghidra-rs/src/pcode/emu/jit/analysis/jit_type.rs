//! The p-code type of an operand.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitType`.
//!
//! A type is an integer or floating-point value of a specific size in bytes. All values and
//! variables in p-code are just bit vectors; the operators interpret those vectors according to a
//! `JitTypeBehavior`. While types only technically belong to the operands, we also talk about
//! values, variables, and varnodes being assigned types, so that we can allocate suitable JVM
//! locals.
//!
//! # Differences from Java
//!
//! - Java nests every p-code type inside the `JitType` interface. Rust has no nested types, so the
//!   whole family is flattened into this module: [`JitType`], [`LeggedJitType`], [`SimpleJitType`],
//!   and the concrete [`IntJitType`], [`LongJitType`], [`FloatJitType`], [`DoubleJitType`],
//!   [`MpIntJitType`], and [`MpFloatJitType`].
//! - The recursive self type parameter (`JT extends SimpleJitType<T, JT>`) is dropped, matching the
//!   existing port of [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::SimpleOpnd). Where Java
//!   narrows a return type covariantly (`SimpleJitType.ext()`, `IntJitType.ext()`, ...), Rust uses
//!   `-> Self` on the narrowing trait instead.
//! - Java's wildcard types `JitType` and `SimpleJitType<?, ?>` appear in return position wherever
//!   the concrete type is not statically known (`unify`, `legTypesBE`, `asInt`, ...). Rust models
//!   those with the closed enums [`AnyJitType`] and [`AnySimpleJitType`]: the set of p-code types
//!   is fixed by this module, so an enum captures it exactly, avoiding a vtable and an allocation
//!   per type value.
//! - `LeggedJitType.castLegsLE` is not ported. It is an unchecked cast that exists only to recover
//!   the leg type Java erased from `Opnd`; Rust erases nothing, so there is nothing to cast. This
//!   is the same reason the [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::simple_opnd) port
//!   omits `SimpleOpndEm.castBack`.
//! - `MpIntJitType.FOR_SIZES` and `MpFloatJitType.FOR_SIZES` are dropped. Those caches intern
//!   instances so that Java's reference equality (`a == b` in `unify`) holds for equal sizes; the
//!   Rust types compare structurally, which gives the same answer without the global map.
//! - Java's `Class<?>` argument to `forJavaType` is modeled as a JVM type descriptor string, the
//!   same convention [`Types`](crate::pcode::emu::jit::gen::util::types) uses for Java classes.

use std::cmp::Ordering;

use crate::pcode::emu::jit::gen::util::types::{
    BPrim, TDouble, TFloat, TInt, TLong, T_DOUBLE, T_FLOAT, T_INT, T_LONG,
};
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;

/// The size of a JVM `int` in bytes, i.e., Java's `Integer.BYTES`.
const INT_BYTES: i32 = 4;
/// The size of a JVM `float` in bytes, i.e., Java's `Float.BYTES`.
const FLOAT_BYTES: i32 = 4;
/// The size of a JVM `double` in bytes, i.e., Java's `Double.BYTES`.
const DOUBLE_BYTES: i32 = 8;

// ── The type traits ───────────────────────────────────────────────────────────

/// The p-code type of an operand.
///
/// Port of `ghidra.pcode.emu.jit.analysis.JitType`.
pub trait JitType {
    /// The preference for this type. Smaller is more preferred.
    ///
    /// Port of `JitType.pref()`.
    fn pref(&self) -> i32;

    /// Part of the name of a JVM local variable allocated for this type.
    ///
    /// Port of `JitType.nm()`.
    fn nm(&self) -> &'static str;

    /// The size of this type in bytes.
    ///
    /// Port of `JitType.size()`.
    fn size(&self) -> i32;

    /// Extend this p-code type to the p-code type that fills its entire host JVM type.
    ///
    /// This is useful, e.g., when multiplying two [`IntJitType::I3`] values using `imul`: the
    /// result might be an [`IntJitType::I4`] and so may need additional conversion.
    ///
    /// Port of `JitType.ext()`.
    fn ext(&self) -> AnyJitType;

    /// The p-code type describing the part of the variable in each leg, in big-endian order.
    ///
    /// Each whole leg has the type [`IntJitType::I4`]; the partial leg, if applicable, has its
    /// appropriate smaller integer type.
    ///
    /// Port of `JitType.legTypesBE()`.
    fn leg_types_be(&self) -> Vec<AnySimpleJitType>;

    /// The p-code type describing the part of the variable in each leg, in little-endian order.
    ///
    /// Port of `JitType.legTypesLE()`.
    fn leg_types_le(&self) -> Vec<AnySimpleJitType>;
}

/// A type comprising legs, each of simple type.
///
/// Port of `JitType.LeggedJitType<T, LT>`. Java's `T` (the JVM type of each leg) is recoverable
/// from [`Leg`](Self::Leg) via [`SimpleJitType::B`], so only the leg's p-code type is carried here.
pub trait LeggedJitType: JitType {
    /// The p-code type of each leg. Java's `LT`.
    type Leg: SimpleJitType;

    /// The typed form of [`JitType::leg_types_be`].
    ///
    /// Port of `LeggedJitType.legTypesBE()`, which narrows the return element type to `LT`.
    fn leg_types_be_typed(&self) -> Vec<Self::Leg>;

    /// The typed form of [`JitType::leg_types_le`].
    ///
    /// Java narrows only `legTypesBE`, leaving `legTypesLE` on `JitType`, even though every
    /// implementor returns the same element type for both. Rust narrows both, for symmetry.
    fn leg_types_le_typed(&self) -> Vec<Self::Leg>;
}

/// A p-code type that can be represented in a single JVM variable.
///
/// Port of `JitType.SimpleJitType<T, JT>`.
pub trait SimpleJitType: LeggedJitType<Leg = Self> + Copy {
    /// The JVM type of the variable that can represent a p-code variable of this type.
    ///
    /// Java's `T`, bounded by `BPrim`.
    type B: BPrim;

    /// The JVM type (not boxed) of the variable representing a p-code variable of this type.
    ///
    /// Port of `SimpleJitType.bType()`.
    fn b_type(&self) -> Self::B;

    /// Re-apply the integer behavior to this type.
    ///
    /// This may be slightly faster than resolving through `JitTypeBehavior.INTEGER`, because each
    /// type can pick its int type directly, and integer types can just return themselves.
    ///
    /// Port of `SimpleJitType.asInt()`.
    fn as_int(&self) -> AnySimpleJitType;

    /// The narrowed form of [`JitType::ext`]: extending a simple type yields a simple type, and in
    /// fact always one of this same kind.
    ///
    /// Port of `SimpleJitType.ext()`, whose Java return type is `SimpleJitType<T, JT>`.
    fn ext_simple(&self) -> Self;

    /// Erase this type to the closed [`AnySimpleJitType`] enum.
    ///
    /// Bridges a generic `JT: SimpleJitType` type parameter to the erased enum that
    /// [`lookup_simple`](crate::pcode::emu::jit::gen::access::access_gen::lookup_simple) requires:
    /// Java's `AccessGen.lookupSimple(Endian, JT)` recovers the concrete `JT` via an unchecked
    /// cast justified by the sealed `SimpleJitType` hierarchy, but Rust has no covariant
    /// existential return to do the same from a generic call site (see that function's module
    /// docs), so generic callers erase with this method instead.
    fn erase_simple(&self) -> AnySimpleJitType;
}

// ── Concrete types ────────────────────────────────────────────────────────────

/// The p-code type for integers of size 1 through 4, i.e., that fit in a JVM `int`.
///
/// Port of `JitType.IntJitType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntJitType {
    /// The size in bytes, 1 through 4.
    pub size: i32,
}

impl IntJitType {
    /// `int1`: a 1-byte integer.
    pub const I1: Self = Self { size: 1 };
    /// `int2`: a 2-byte integer.
    pub const I2: Self = Self { size: 2 };
    /// `int3`: a 3-byte integer.
    pub const I3: Self = Self { size: 3 };
    /// `int4`: a 4-byte integer.
    pub const I4: Self = Self { size: 4 };

    /// The type for an integer of the given size 1 through 4.
    ///
    /// Panics for any size *not* 1 through 4, mirroring Java's `IllegalArgumentException`.
    ///
    /// Port of `IntJitType.forSize(int)`.
    pub fn for_size(size: i32) -> Self {
        match size {
            1 => Self::I1,
            2 => Self::I2,
            3 => Self::I3,
            4 => Self::I4,
            _ => panic!("size:{}", size),
        }
    }
}

impl JitType for IntJitType {
    fn pref(&self) -> i32 {
        0
    }

    fn nm(&self) -> &'static str {
        "i"
    }

    fn size(&self) -> i32 {
        self.size
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::Int(self.ext_simple())
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Int(*self)]
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Int(*self)]
    }
}

impl LeggedJitType for IntJitType {
    type Leg = Self;

    fn leg_types_be_typed(&self) -> Vec<Self> {
        vec![*self]
    }

    fn leg_types_le_typed(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl SimpleJitType for IntJitType {
    type B = TInt;

    fn b_type(&self) -> TInt {
        T_INT
    }

    fn as_int(&self) -> AnySimpleJitType {
        AnySimpleJitType::Int(*self)
    }

    fn ext_simple(&self) -> Self {
        Self::I4
    }

    fn erase_simple(&self) -> AnySimpleJitType {
        AnySimpleJitType::Int(*self)
    }
}

/// The p-code type for integers of size 5 through 8, i.e., that fit in a JVM `long`.
///
/// Port of `JitType.LongJitType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LongJitType {
    /// The size in bytes, 1 through 8. Sizes below 5 are used only as intermediates during
    /// conversion; [`IntJitType`] is the type for those sizes otherwise.
    pub size: i32,
}

impl LongJitType {
    /// `int5`: a 5-byte integer.
    pub const I5: Self = Self { size: 5 };
    /// `int6`: a 6-byte integer.
    pub const I6: Self = Self { size: 6 };
    /// `int7`: a 7-byte integer.
    pub const I7: Self = Self { size: 7 };
    /// `int8`: an 8-byte integer.
    pub const I8: Self = Self { size: 8 };

    /// A 1-byte integer in a JVM `long`. Needed only as an intermediate during conversion.
    pub const I1: Self = Self { size: 1 };
    /// A 2-byte integer in a JVM `long`. Needed only as an intermediate during conversion.
    pub const I2: Self = Self { size: 2 };
    /// A 3-byte integer in a JVM `long`. Needed only as an intermediate during conversion.
    pub const I3: Self = Self { size: 3 };
    /// A 4-byte integer in a JVM `long`. Needed only as an intermediate during conversion.
    pub const I4: Self = Self { size: 4 };

    /// The type for an integer of the given size 5 through 8, or 1 through 4 for intermediate
    /// conversion.
    ///
    /// Panics for any other size, mirroring Java's `IllegalArgumentException`.
    ///
    /// Port of `LongJitType.forSize(int)`.
    pub fn for_size(size: i32) -> Self {
        match size {
            5 => Self::I5,
            6 => Self::I6,
            7 => Self::I7,
            8 => Self::I8,
            // For intermediate conversion only
            1 => Self::I1,
            2 => Self::I2,
            3 => Self::I3,
            4 => Self::I4,
            _ => panic!("size:{}", size),
        }
    }
}

impl JitType for LongJitType {
    fn pref(&self) -> i32 {
        1
    }

    fn nm(&self) -> &'static str {
        "l"
    }

    fn size(&self) -> i32 {
        self.size
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::Long(self.ext_simple())
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Long(*self)]
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Long(*self)]
    }
}

impl LeggedJitType for LongJitType {
    type Leg = Self;

    fn leg_types_be_typed(&self) -> Vec<Self> {
        vec![*self]
    }

    fn leg_types_le_typed(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl SimpleJitType for LongJitType {
    type B = TLong;

    fn b_type(&self) -> TLong {
        T_LONG
    }

    fn as_int(&self) -> AnySimpleJitType {
        AnySimpleJitType::Long(*self)
    }

    fn ext_simple(&self) -> Self {
        Self::I8
    }

    fn erase_simple(&self) -> AnySimpleJitType {
        AnySimpleJitType::Long(*self)
    }
}

/// The p-code type for floating-point of size 4, i.e., that fits in a JVM `float`.
///
/// Port of `JitType.FloatJitType`, a Java enum with the single constant `F4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FloatJitType;

impl FloatJitType {
    /// `float4`: a 4-byte float.
    pub const F4: Self = FloatJitType;
}

impl JitType for FloatJitType {
    fn pref(&self) -> i32 {
        2
    }

    fn nm(&self) -> &'static str {
        "f"
    }

    fn size(&self) -> i32 {
        FLOAT_BYTES
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::Float(self.ext_simple())
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Float(*self)]
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Float(*self)]
    }
}

impl LeggedJitType for FloatJitType {
    type Leg = Self;

    fn leg_types_be_typed(&self) -> Vec<Self> {
        vec![*self]
    }

    fn leg_types_le_typed(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl SimpleJitType for FloatJitType {
    type B = TFloat;

    fn b_type(&self) -> TFloat {
        T_FLOAT
    }

    fn as_int(&self) -> AnySimpleJitType {
        AnySimpleJitType::Int(IntJitType::I4)
    }

    fn ext_simple(&self) -> Self {
        *self
    }

    fn erase_simple(&self) -> AnySimpleJitType {
        AnySimpleJitType::Float(*self)
    }
}

/// The p-code type for floating-point of size 8, i.e., that fits in a JVM `double`.
///
/// Port of `JitType.DoubleJitType`, a Java enum with the single constant `F8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DoubleJitType;

impl DoubleJitType {
    /// `float8`: an 8-byte float.
    pub const F8: Self = DoubleJitType;
}

impl JitType for DoubleJitType {
    fn pref(&self) -> i32 {
        3
    }

    fn nm(&self) -> &'static str {
        "d"
    }

    fn size(&self) -> i32 {
        DOUBLE_BYTES
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::Double(self.ext_simple())
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Double(*self)]
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        vec![AnySimpleJitType::Double(*self)]
    }
}

impl LeggedJitType for DoubleJitType {
    type Leg = Self;

    fn leg_types_be_typed(&self) -> Vec<Self> {
        vec![*self]
    }

    fn leg_types_le_typed(&self) -> Vec<Self> {
        vec![*self]
    }
}

impl SimpleJitType for DoubleJitType {
    type B = TDouble;

    fn b_type(&self) -> TDouble {
        T_DOUBLE
    }

    fn as_int(&self) -> AnySimpleJitType {
        AnySimpleJitType::Long(LongJitType::I8)
    }

    fn ext_simple(&self) -> Self {
        *self
    }

    fn erase_simple(&self) -> AnySimpleJitType {
        AnySimpleJitType::Double(*self)
    }
}

/// The p-code type for integers of size 9 and greater.
///
/// We take the strategy of inlined manipulation of `int` locals, composed to form the full
/// variable. When stored on the stack, the least-significant portion is always toward the top, no
/// matter the language endianness.
///
/// Port of `JitType.MpIntJitType`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MpIntJitType {
    /// The size in bytes.
    pub size: i32,
    /// The type of each leg, in big-endian order.
    pub leg_types_be: Vec<IntJitType>,
    /// The type of each leg, in little-endian order.
    pub leg_types_le: Vec<IntJitType>,
}

/// The total number of JVM `int` variables ("legs") required to store an integer of `size` bytes.
fn legs_alloc(size: i32) -> i32 {
    (size + INT_BYTES - 1) / INT_BYTES
}

/// The number of bytes filled in the last leg of an integer of `size` bytes, or 0 if all legs are
/// whole.
fn partial_size(size: i32) -> i32 {
    size % INT_BYTES
}

/// The type of each leg, in big-endian order, for an integer of `size` bytes.
///
/// Port of `MpIntJitType.computeLegTypesBE(int)`.
fn compute_leg_types_be(size: i32) -> Vec<IntJitType> {
    let mut types = Vec::with_capacity(legs_alloc(size) as usize);
    if partial_size(size) != 0 {
        types.push(IntJitType::for_size(partial_size(size)));
    }
    while (types.len() as i32) < legs_alloc(size) {
        types.push(IntJitType::I4);
    }
    types
}

impl MpIntJitType {
    /// The type for an integer of the given size 9 or greater.
    ///
    /// Port of `MpIntJitType.forSize(int)`. Java memoizes in a static map so that instances for
    /// equal sizes are reference-equal; this port compares structurally instead, so it just
    /// constructs.
    pub fn for_size(size: i32) -> Self {
        let leg_types_be = compute_leg_types_be(size);
        let leg_types_le = leg_types_be.iter().rev().copied().collect();
        Self { size, leg_types_be, leg_types_le }
    }

    /// The total number of JVM `int` variables ("legs") required to store the int.
    ///
    /// Port of `MpIntJitType.legsAlloc()`.
    pub fn legs_alloc(&self) -> i32 {
        legs_alloc(self.size)
    }

    /// The number of legs that are filled.
    ///
    /// Port of `MpIntJitType.legsWhole()`.
    pub fn legs_whole(&self) -> i32 {
        self.size / INT_BYTES
    }

    /// The number of bytes filled in the last leg, if partial, or 0 if all legs are whole.
    ///
    /// Port of `MpIntJitType.partialSize()`.
    pub fn partial_size(&self) -> i32 {
        partial_size(self.size)
    }
}

impl JitType for MpIntJitType {
    fn pref(&self) -> i32 {
        4
    }

    fn nm(&self) -> &'static str {
        "I"
    }

    fn size(&self) -> i32 {
        self.size
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::MpInt(MpIntJitType::for_size(self.legs_alloc() * INT_BYTES))
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        self.leg_types_be.iter().copied().map(AnySimpleJitType::Int).collect()
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        self.leg_types_le.iter().copied().map(AnySimpleJitType::Int).collect()
    }
}

impl LeggedJitType for MpIntJitType {
    type Leg = IntJitType;

    fn leg_types_be_typed(&self) -> Vec<IntJitType> {
        self.leg_types_be.clone()
    }

    fn leg_types_le_typed(&self) -> Vec<IntJitType> {
        self.leg_types_le.clone()
    }
}

/// **WIP**: The p-code type for floats of size other than 4 and 8.
///
/// Port of `JitType.MpFloatJitType`. As in Java, the leg types are not implemented yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MpFloatJitType {
    /// The size in bytes.
    pub size: i32,
}

impl MpFloatJitType {
    /// The type for a float of the given size other than 4 and 8.
    ///
    /// Port of `MpFloatJitType.forSize(int)`. As with [`MpIntJitType::for_size`], Java's interning
    /// map is dropped in favor of structural equality.
    pub fn for_size(size: i32) -> Self {
        Self { size }
    }
}

impl JitType for MpFloatJitType {
    fn pref(&self) -> i32 {
        5
    }

    fn nm(&self) -> &'static str {
        "F"
    }

    fn size(&self) -> i32 {
        self.size
    }

    fn ext(&self) -> AnyJitType {
        AnyJitType::MpFloat(*self)
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        unimplemented!("MpFloat")
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        unimplemented!("MpFloat")
    }
}

impl LeggedJitType for MpFloatJitType {
    type Leg = IntJitType;

    fn leg_types_be_typed(&self) -> Vec<IntJitType> {
        unimplemented!("MpFloat")
    }

    fn leg_types_le_typed(&self) -> Vec<IntJitType> {
        unimplemented!("MpFloat")
    }
}

// ── Erased type values ────────────────────────────────────────────────────────

/// Any p-code type that can be represented in a single JVM variable.
///
/// Stands in for Java's `SimpleJitType<?, ?>` wildcard. Each variant's `bType` differs, so this
/// enum cannot itself implement [`SimpleJitType`]; match on it to recover the JVM type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnySimpleJitType {
    /// An integer of size 1 through 4.
    Int(IntJitType),
    /// An integer of size 5 through 8.
    Long(LongJitType),
    /// A 4-byte float.
    Float(FloatJitType),
    /// An 8-byte float.
    Double(DoubleJitType),
}

impl AnySimpleJitType {
    /// Re-apply the integer behavior to this type.
    ///
    /// Port of `SimpleJitType.asInt()`, dispatched over the erased type.
    pub fn as_int(&self) -> AnySimpleJitType {
        match self {
            Self::Int(t) => t.as_int(),
            Self::Long(t) => t.as_int(),
            Self::Float(t) => t.as_int(),
            Self::Double(t) => t.as_int(),
        }
    }

    /// The narrowed form of [`JitType::ext`]: extending a simple type yields a simple type.
    ///
    /// Port of `SimpleJitType.ext()`, dispatched over the erased type.
    pub fn ext_simple(&self) -> AnySimpleJitType {
        match self {
            Self::Int(t) => Self::Int(t.ext_simple()),
            Self::Long(t) => Self::Long(t.ext_simple()),
            Self::Float(t) => Self::Float(t.ext_simple()),
            Self::Double(t) => Self::Double(t.ext_simple()),
        }
    }
}

impl JitType for AnySimpleJitType {
    fn pref(&self) -> i32 {
        match self {
            Self::Int(t) => t.pref(),
            Self::Long(t) => t.pref(),
            Self::Float(t) => t.pref(),
            Self::Double(t) => t.pref(),
        }
    }

    fn nm(&self) -> &'static str {
        match self {
            Self::Int(t) => t.nm(),
            Self::Long(t) => t.nm(),
            Self::Float(t) => t.nm(),
            Self::Double(t) => t.nm(),
        }
    }

    fn size(&self) -> i32 {
        match self {
            Self::Int(t) => t.size(),
            Self::Long(t) => t.size(),
            Self::Float(t) => t.size(),
            Self::Double(t) => t.size(),
        }
    }

    fn ext(&self) -> AnyJitType {
        self.ext_simple().into()
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        vec![*self]
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        vec![*self]
    }
}

/// Any p-code type.
///
/// Stands in for Java's `JitType` in value position -- the erased result of `unify`, `ext`, and
/// `JitTypeBehavior.type(int)`. The set of p-code types is closed by this module, so an enum
/// captures it exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnyJitType {
    /// An integer of size 1 through 4.
    Int(IntJitType),
    /// An integer of size 5 through 8.
    Long(LongJitType),
    /// A 4-byte float.
    Float(FloatJitType),
    /// An 8-byte float.
    Double(DoubleJitType),
    /// An integer of size 9 or greater.
    MpInt(MpIntJitType),
    /// A float of size other than 4 and 8.
    MpFloat(MpFloatJitType),
}

impl From<AnySimpleJitType> for AnyJitType {
    fn from(t: AnySimpleJitType) -> Self {
        match t {
            AnySimpleJitType::Int(t) => Self::Int(t),
            AnySimpleJitType::Long(t) => Self::Long(t),
            AnySimpleJitType::Float(t) => Self::Float(t),
            AnySimpleJitType::Double(t) => Self::Double(t),
        }
    }
}

impl JitType for AnyJitType {
    fn pref(&self) -> i32 {
        match self {
            Self::Int(t) => t.pref(),
            Self::Long(t) => t.pref(),
            Self::Float(t) => t.pref(),
            Self::Double(t) => t.pref(),
            Self::MpInt(t) => t.pref(),
            Self::MpFloat(t) => t.pref(),
        }
    }

    fn nm(&self) -> &'static str {
        match self {
            Self::Int(t) => t.nm(),
            Self::Long(t) => t.nm(),
            Self::Float(t) => t.nm(),
            Self::Double(t) => t.nm(),
            Self::MpInt(t) => t.nm(),
            Self::MpFloat(t) => t.nm(),
        }
    }

    fn size(&self) -> i32 {
        match self {
            Self::Int(t) => t.size(),
            Self::Long(t) => t.size(),
            Self::Float(t) => t.size(),
            Self::Double(t) => t.size(),
            Self::MpInt(t) => t.size(),
            Self::MpFloat(t) => t.size(),
        }
    }

    fn ext(&self) -> AnyJitType {
        match self {
            Self::Int(t) => t.ext(),
            Self::Long(t) => t.ext(),
            Self::Float(t) => t.ext(),
            Self::Double(t) => t.ext(),
            Self::MpInt(t) => t.ext(),
            Self::MpFloat(t) => t.ext(),
        }
    }

    fn leg_types_be(&self) -> Vec<AnySimpleJitType> {
        match self {
            Self::Int(t) => t.leg_types_be(),
            Self::Long(t) => t.leg_types_be(),
            Self::Float(t) => t.leg_types_be(),
            Self::Double(t) => t.leg_types_be(),
            Self::MpInt(t) => t.leg_types_be(),
            Self::MpFloat(t) => t.leg_types_be(),
        }
    }

    fn leg_types_le(&self) -> Vec<AnySimpleJitType> {
        match self {
            Self::Int(t) => t.leg_types_le(),
            Self::Long(t) => t.leg_types_le(),
            Self::Float(t) => t.leg_types_le(),
            Self::Double(t) => t.leg_types_le(),
            Self::MpInt(t) => t.leg_types_le(),
            Self::MpFloat(t) => t.leg_types_le(),
        }
    }
}

// ── Static interface methods ──────────────────────────────────────────────────

/// The smallest type to which both of the given types can be converted without loss.
///
/// When the given types are a mix of integral and floating-point, this chooses an integral type
/// whose size is the greater of the two.
///
/// Port of `JitType.unify(JitType, JitType)`. Java short-circuits on reference equality; this port
/// short-circuits on structural equality, which is what Java's interning was arranged to make
/// equivalent.
pub fn unify(a: &AnyJitType, b: &AnyJitType) -> AnyJitType {
    if a == b {
        return a.clone();
    }
    let size = a.size().max(b.size());
    JitTypeBehavior::Integer.type_of(size)
}

/// Similar to [`unify`], except that it takes the lesser size.
///
/// This is used when culling of unnecessary loads is desired and loss of precision is acceptable.
///
/// Port of `JitType.unifyLeast(JitType, JitType)`.
pub fn unify_least(a: &AnyJitType, b: &AnyJitType) -> AnyJitType {
    if a == b {
        return a.clone();
    }
    let size = a.size().min(b.size());
    JitTypeBehavior::Integer.type_of(size)
}

/// Compare two types by preference. The type with the more preferred behavior, then the smaller
/// size, is preferred.
///
/// Port of `JitType.compare(JitType, JitType)`, whose comparator-style `int` becomes an
/// [`Ordering`].
pub fn compare(t1: &impl JitType, t2: &impl JitType) -> Ordering {
    t1.pref().cmp(&t2.pref()).then_with(|| t1.size().cmp(&t2.size()))
}

/// The p-code type that is exactly represented by the given JVM type.
///
/// This is used during Direct userop invocation to convert the arguments and return value. The
/// Java `Class<?>` for a primitive is given here as its JVM type descriptor: `"Z"`, `"B"`, `"S"`,
/// `"I"`, `"J"`, `"F"`, or `"D"`.
///
/// Returns `None` for any other descriptor, where Java throws `IllegalArgumentException`.
///
/// Port of `JitType.forJavaType(Class)`, which just delegates to `SimpleJitType.forJavaType`.
pub fn for_java_type(descriptor: &str) -> Option<AnySimpleJitType> {
    Some(match descriptor {
        "Z" => AnySimpleJitType::Int(IntJitType::I1),
        "B" => AnySimpleJitType::Int(IntJitType::I1),
        "S" => AnySimpleJitType::Int(IntJitType::I2),
        "I" => AnySimpleJitType::Int(IntJitType::I4),
        "J" => AnySimpleJitType::Long(LongJitType::I8),
        "F" => AnySimpleJitType::Float(FloatJitType::F4),
        "D" => AnySimpleJitType::Double(DoubleJitType::F8),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::types::SType;

    #[test]
    fn int_type_pref_nm_and_ext() {
        // Java: IntJitType.pref() == 0, nm() == "i", ext() == I4 for every size.
        assert_eq!(IntJitType::I3.pref(), 0);
        assert_eq!(IntJitType::I3.nm(), "i");
        assert_eq!(IntJitType::I3.size(), 3);
        assert_eq!(IntJitType::I1.ext(), AnyJitType::Int(IntJitType::I4));
        assert_eq!(IntJitType::I4.ext(), AnyJitType::Int(IntJitType::I4));
        assert_eq!(IntJitType::I3.b_type().descriptor(), "I");
    }

    #[test]
    fn int_for_size_covers_one_through_four() {
        assert_eq!(IntJitType::for_size(1), IntJitType::I1);
        assert_eq!(IntJitType::for_size(4), IntJitType::I4);
    }

    #[test]
    #[should_panic(expected = "size:5")]
    fn int_for_size_rejects_five() {
        // Java throws IllegalArgumentException("size:5").
        IntJitType::for_size(5);
    }

    #[test]
    fn long_type_pref_nm_and_ext() {
        // Java: LongJitType.pref() == 1, nm() == "l", ext() == I8.
        assert_eq!(LongJitType::I5.pref(), 1);
        assert_eq!(LongJitType::I5.nm(), "l");
        assert_eq!(LongJitType::I5.size(), 5);
        assert_eq!(LongJitType::I5.ext(), AnyJitType::Long(LongJitType::I8));
        assert_eq!(LongJitType::I5.b_type().descriptor(), "J");
        // Sizes 1 through 4 exist only as conversion intermediates, but they do exist.
        assert_eq!(LongJitType::for_size(2), LongJitType::I2);
    }

    #[test]
    fn float_and_double_sizes_and_prefs() {
        // Java: FloatJitType.F4 -> pref 2, size Float.BYTES; DoubleJitType.F8 -> pref 3, size 8.
        assert_eq!(FloatJitType::F4.pref(), 2);
        assert_eq!(FloatJitType::F4.nm(), "f");
        assert_eq!(FloatJitType::F4.size(), FLOAT_BYTES);
        assert_eq!(FloatJitType::F4.b_type().descriptor(), "F");
        assert_eq!(DoubleJitType::F8.pref(), 3);
        assert_eq!(DoubleJitType::F8.nm(), "d");
        assert_eq!(DoubleJitType::F8.size(), DOUBLE_BYTES);
        assert_eq!(DoubleJitType::F8.b_type().descriptor(), "D");
    }

    #[test]
    fn as_int_maps_floats_to_their_host_int_types() {
        // Java: FloatJitType.asInt() == IntJitType.I4; DoubleJitType.asInt() == LongJitType.I8.
        assert_eq!(FloatJitType::F4.as_int(), AnySimpleJitType::Int(IntJitType::I4));
        assert_eq!(DoubleJitType::F8.as_int(), AnySimpleJitType::Long(LongJitType::I8));
        // Integer types return themselves.
        assert_eq!(IntJitType::I3.as_int(), AnySimpleJitType::Int(IntJitType::I3));
        assert_eq!(LongJitType::I7.as_int(), AnySimpleJitType::Long(LongJitType::I7));
    }

    #[test]
    fn simple_types_are_their_own_single_leg() {
        // Java: legTypesBE() == legTypesLE() == List.of(this).
        assert_eq!(IntJitType::I2.leg_types_be(), vec![AnySimpleJitType::Int(IntJitType::I2)]);
        assert_eq!(IntJitType::I2.leg_types_le_typed(), vec![IntJitType::I2]);
        assert_eq!(DoubleJitType::F8.leg_types_be_typed(), vec![DoubleJitType::F8]);
    }

    #[test]
    fn mp_int_legs_for_size_nine() {
        // Java: legsAlloc(9) == 3, partialSize(9) == 1, so BE == [I1, I4, I4] and LE is reversed.
        let t = MpIntJitType::for_size(9);
        assert_eq!(t.size(), 9);
        assert_eq!(t.pref(), 4);
        assert_eq!(t.nm(), "I");
        assert_eq!(t.legs_alloc(), 3);
        assert_eq!(t.legs_whole(), 2);
        assert_eq!(t.partial_size(), 1);
        assert_eq!(
            t.leg_types_be_typed(),
            vec![IntJitType::I1, IntJitType::I4, IntJitType::I4]
        );
        assert_eq!(
            t.leg_types_le_typed(),
            vec![IntJitType::I4, IntJitType::I4, IntJitType::I1]
        );
    }

    #[test]
    fn mp_int_legs_for_whole_size_twelve() {
        // Java: partialSize(12) == 0, so all three legs are I4 and BE == LE.
        let t = MpIntJitType::for_size(12);
        assert_eq!(t.legs_alloc(), 3);
        assert_eq!(t.legs_whole(), 3);
        assert_eq!(t.partial_size(), 0);
        assert_eq!(t.leg_types_be_typed(), vec![IntJitType::I4; 3]);
        assert_eq!(t.leg_types_le_typed(), vec![IntJitType::I4; 3]);
    }

    #[test]
    fn mp_int_ext_fills_every_leg() {
        // Java: MpIntJitType.ext() == forSize(legsAlloc() * Integer.BYTES).
        assert_eq!(
            MpIntJitType::for_size(9).ext(),
            AnyJitType::MpInt(MpIntJitType::for_size(12))
        );
        assert_eq!(
            MpIntJitType::for_size(12).ext(),
            AnyJitType::MpInt(MpIntJitType::for_size(12))
        );
    }

    #[test]
    fn mp_float_is_pref_five_and_extends_to_itself() {
        // Java: MpFloatJitType.pref() == 5, nm() == "F", ext() == this.
        let t = MpFloatJitType::for_size(10);
        assert_eq!(t.pref(), 5);
        assert_eq!(t.nm(), "F");
        assert_eq!(t.size(), 10);
        assert_eq!(t.ext(), AnyJitType::MpFloat(t));
    }

    #[test]
    #[should_panic(expected = "MpFloat")]
    fn mp_float_legs_are_unfinished() {
        // Java: Unfinished.TODO("MpFloat").
        MpFloatJitType::for_size(10).leg_types_be();
    }

    #[test]
    fn unify_returns_the_common_type_unchanged() {
        // Java: `if (a == b) return a;`
        let a = AnyJitType::Float(FloatJitType::F4);
        assert_eq!(unify(&a, &a), a);
    }

    #[test]
    fn unify_takes_the_greater_size_as_an_integer() {
        // Java: JitTypeBehavior.INTEGER.type(max(size, size)).
        let i2 = AnyJitType::Int(IntJitType::I2);
        let i6 = AnyJitType::Long(LongJitType::I6);
        assert_eq!(unify(&i2, &i6), AnyJitType::Long(LongJitType::I6));
        // A mix of integral and floating-point yields an integral type of the greater size.
        let f8 = AnyJitType::Double(DoubleJitType::F8);
        assert_eq!(unify(&i2, &f8), AnyJitType::Long(LongJitType::I8));
        // Sizes past 8 land in the multi-precision type.
        let i16 = AnyJitType::MpInt(MpIntJitType::for_size(16));
        assert_eq!(unify(&i2, &i16), AnyJitType::MpInt(MpIntJitType::for_size(16)));
    }

    #[test]
    fn unify_least_takes_the_lesser_size_as_an_integer() {
        let i2 = AnyJitType::Int(IntJitType::I2);
        let i6 = AnyJitType::Long(LongJitType::I6);
        assert_eq!(unify_least(&i2, &i6), AnyJitType::Int(IntJitType::I2));
        let f4 = AnyJitType::Float(FloatJitType::F4);
        assert_eq!(unify_least(&f4, &i6), AnyJitType::Int(IntJitType::I4));
    }

    #[test]
    fn compare_orders_by_behavior_then_size() {
        // Java: pref first (int < long < float < double < mpint < mpfloat), then size.
        assert_eq!(compare(&IntJitType::I4, &LongJitType::I5), Ordering::Less);
        assert_eq!(compare(&FloatJitType::F4, &DoubleJitType::F8), Ordering::Less);
        assert_eq!(compare(&MpIntJitType::for_size(9), &MpFloatJitType::for_size(9)), Ordering::Less);
        // Same behavior: the smaller size wins.
        assert_eq!(compare(&IntJitType::I1, &IntJitType::I4), Ordering::Less);
        assert_eq!(compare(&IntJitType::I4, &IntJitType::I1), Ordering::Greater);
        assert_eq!(compare(&IntJitType::I3, &IntJitType::I3), Ordering::Equal);
        // A 4-byte int is preferred over a 4-byte float, despite the equal size.
        assert_eq!(compare(&IntJitType::I4, &FloatJitType::F4), Ordering::Less);
    }

    #[test]
    fn for_java_type_maps_jvm_primitives() {
        // Java: boolean and byte -> I1, short -> I2, int -> I4, long -> I8, float -> F4,
        // double -> F8, anything else -> IllegalArgumentException.
        assert_eq!(for_java_type("Z"), Some(AnySimpleJitType::Int(IntJitType::I1)));
        assert_eq!(for_java_type("B"), Some(AnySimpleJitType::Int(IntJitType::I1)));
        assert_eq!(for_java_type("S"), Some(AnySimpleJitType::Int(IntJitType::I2)));
        assert_eq!(for_java_type("I"), Some(AnySimpleJitType::Int(IntJitType::I4)));
        assert_eq!(for_java_type("J"), Some(AnySimpleJitType::Long(LongJitType::I8)));
        assert_eq!(for_java_type("F"), Some(AnySimpleJitType::Float(FloatJitType::F4)));
        assert_eq!(for_java_type("D"), Some(AnySimpleJitType::Double(DoubleJitType::F8)));
        assert_eq!(for_java_type("C"), None);
        assert_eq!(for_java_type("V"), None);
        assert_eq!(for_java_type("Ljava/lang/Integer;"), None);
    }

    #[test]
    fn erased_type_delegates_to_its_variant() {
        let t = AnyJitType::MpInt(MpIntJitType::for_size(9));
        assert_eq!(t.pref(), 4);
        assert_eq!(t.nm(), "I");
        assert_eq!(t.size(), 9);
        assert_eq!(
            t.leg_types_le(),
            vec![
                AnySimpleJitType::Int(IntJitType::I4),
                AnySimpleJitType::Int(IntJitType::I4),
                AnySimpleJitType::Int(IntJitType::I1),
            ]
        );
    }

    #[test]
    fn erase_simple_wraps_each_concrete_type_in_its_matching_variant() {
        assert_eq!(IntJitType::I2.erase_simple(), AnySimpleJitType::Int(IntJitType::I2));
        assert_eq!(LongJitType::I6.erase_simple(), AnySimpleJitType::Long(LongJitType::I6));
        assert_eq!(FloatJitType::F4.erase_simple(), AnySimpleJitType::Float(FloatJitType::F4));
        assert_eq!(DoubleJitType::F8.erase_simple(), AnySimpleJitType::Double(DoubleJitType::F8));
    }

    #[test]
    fn erased_simple_type_extends_within_its_kind() {
        // Java's SimpleJitType.ext() narrows to the same kind of simple type.
        let t = AnySimpleJitType::Int(IntJitType::I1);
        assert_eq!(t.ext_simple(), AnySimpleJitType::Int(IntJitType::I4));
        assert_eq!(t.ext(), AnyJitType::Int(IntJitType::I4));
        let d = AnySimpleJitType::Double(DoubleJitType::F8);
        assert_eq!(d.ext_simple(), d);
    }
}
