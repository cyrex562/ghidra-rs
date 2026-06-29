//! A namespace for types describing JVM bytecode types used in JIT code generation.
//!
//! Corresponds to `ghidra.pcode.emu.jit.gen.util.Types`.
//!
//! In the original Java source this is an interface serving as a namespace; here it is a module
//! containing the trait hierarchy and concrete type structs. The ASM `Type` representation is
//! replaced by a JVM descriptor string. The Java `Class<?>` reflection field in `TRef` is
//! replaced by the JVM internal class name.

use once_cell::sync::Lazy;

// ── JVM NEWARRAY type codes (JVM spec §6.5 / ASM Opcodes) ────────────────────

/// NEWARRAY type code for `boolean` (`4`).
pub const NEWARRAY_BOOLEAN: i32 = 4;
/// NEWARRAY type code for `char` (`5`).
pub const NEWARRAY_CHAR: i32 = 5;
/// NEWARRAY type code for `float` (`6`).
pub const NEWARRAY_FLOAT: i32 = 6;
/// NEWARRAY type code for `double` (`7`).
pub const NEWARRAY_DOUBLE: i32 = 7;
/// NEWARRAY type code for `byte` (`8`).
pub const NEWARRAY_BYTE: i32 = 8;
/// NEWARRAY type code for `short` (`9`).
pub const NEWARRAY_SHORT: i32 = 9;
/// NEWARRAY type code for `int` (`10`).
pub const NEWARRAY_INT: i32 = 10;
/// NEWARRAY type code for `long` (`11`).
pub const NEWARRAY_LONG: i32 = 11;

// ── Trait hierarchy ───────────────────────────────────────────────────────────

/// Types that may appear as a method return type, including `void`.
///
/// Corresponds to `Types.SType`.
pub trait SType {
    /// JVM type descriptor for this type (e.g., `"V"` for void, `"I"` for int,
    /// `"Ljava/lang/String;"` for `String`).
    fn descriptor(&self) -> &str;
}

/// Types that may be ascribed to a variable — all types except `void`.
///
/// Corresponds to `Types.SNonVoid`.
pub trait SNonVoid: SType {}

/// Primitive Java types, associated with their JVM NEWARRAY type code.
///
/// Corresponds to `Types.SPrim<A>`. The array-type parameter `A` is not carried in Rust
/// since Java array classes have no Rust equivalent.
pub trait SPrim: SNonVoid {
    /// The NEWARRAY type code for this primitive (e.g., [`NEWARRAY_INT`]).
    fn t(&self) -> i32;
}

/// JVM bytecode-level types — types that may appear in local-variable slots or on the operand
/// stack — plus `void`.
///
/// Corresponds to `Types.BType`.
pub trait BType: SType {
    /// The JVM internal name of this type.
    ///
    /// For object types the leading `L` and trailing `;` are stripped from the descriptor
    /// (e.g., `"Ljava/lang/String;"` → `"java/lang/String"`). For all other forms the
    /// descriptor is returned unchanged.
    fn internal_name(&self) -> &str {
        self.descriptor()
    }
}

/// JVM bytecode non-void types — types that can be stored in a local variable or pushed onto
/// the operand stack.
///
/// Corresponds to `Types.BNonVoid`.
pub trait BNonVoid: BType + SNonVoid {
    /// Number of JVM stack slots (or consecutive local-variable indices) occupied by this type.
    fn slots(&self) -> u32;
}

/// JVM bytecode primitive types: `int`, `float`, `long`, and `double`.
///
/// Corresponds to `Types.BPrim<A>`. The array-type parameter is elided for the same reason
/// as in [`SPrim`].
pub trait BPrim: BNonVoid + SPrim {}

/// Category-1 JVM types (one stack slot): reference types, `int`, and `float`.
///
/// Corresponds to `Types.TCat1`.
pub trait TCat1: BNonVoid {}

/// Category-2 JVM types (two stack slots): `long` and `double`.
///
/// Corresponds to `Types.TCat2`.
pub trait TCat2: BNonVoid {}

// ── Concrete primitive and void types ─────────────────────────────────────────

/// The `void` type.
///
/// Corresponds to `Types.TVoid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TVoid;

impl SType for TVoid {
    fn descriptor(&self) -> &str { "V" }
}
impl BType for TVoid {}

/// Singleton constant for `void`. Corresponds to `Types.T_VOID`.
pub const T_VOID: TVoid = TVoid;

/// The `boolean` type.
///
/// Corresponds to `Types.TBool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TBool;

impl SType for TBool {
    fn descriptor(&self) -> &str { "Z" }
}
impl SNonVoid for TBool {}
impl SPrim for TBool {
    fn t(&self) -> i32 { NEWARRAY_BOOLEAN }
}

/// Singleton constant for `boolean`. Corresponds to `Types.T_BOOL`.
pub const T_BOOL: TBool = TBool;

/// The `byte` type.
///
/// Corresponds to `Types.TByte`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TByte;

impl SType for TByte {
    fn descriptor(&self) -> &str { "B" }
}
impl SNonVoid for TByte {}
impl SPrim for TByte {
    fn t(&self) -> i32 { NEWARRAY_BYTE }
}

/// Singleton constant for `byte`. Corresponds to `Types.T_BYTE`.
pub const T_BYTE: TByte = TByte;

/// The `char` type.
///
/// Corresponds to `Types.TChar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TChar;

impl SType for TChar {
    fn descriptor(&self) -> &str { "C" }
}
impl SNonVoid for TChar {}
impl SPrim for TChar {
    fn t(&self) -> i32 { NEWARRAY_CHAR }
}

/// Singleton constant for `char`. Corresponds to `Types.T_CHAR`.
pub const T_CHAR: TChar = TChar;

/// The `short` type.
///
/// Corresponds to `Types.TShort`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TShort;

impl SType for TShort {
    fn descriptor(&self) -> &str { "S" }
}
impl SNonVoid for TShort {}
impl SPrim for TShort {
    fn t(&self) -> i32 { NEWARRAY_SHORT }
}

/// Singleton constant for `short`. Corresponds to `Types.T_SHORT`.
pub const T_SHORT: TShort = TShort;

/// The `int` type — category-1 bytecode primitive.
///
/// Corresponds to `Types.TInt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TInt;

impl SType for TInt {
    fn descriptor(&self) -> &str { "I" }
}
impl SNonVoid for TInt {}
impl SPrim for TInt {
    fn t(&self) -> i32 { NEWARRAY_INT }
}
impl BType for TInt {}
impl BNonVoid for TInt {
    fn slots(&self) -> u32 { 1 }
}
impl BPrim for TInt {}
impl TCat1 for TInt {}

/// Singleton constant for `int`. Corresponds to `Types.T_INT`.
pub const T_INT: TInt = TInt;

/// The `float` type — category-1 bytecode primitive.
///
/// Corresponds to `Types.TFloat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TFloat;

impl SType for TFloat {
    fn descriptor(&self) -> &str { "F" }
}
impl SNonVoid for TFloat {}
impl SPrim for TFloat {
    fn t(&self) -> i32 { NEWARRAY_FLOAT }
}
impl BType for TFloat {}
impl BNonVoid for TFloat {
    fn slots(&self) -> u32 { 1 }
}
impl BPrim for TFloat {}
impl TCat1 for TFloat {}

/// Singleton constant for `float`. Corresponds to `Types.T_FLOAT`.
pub const T_FLOAT: TFloat = TFloat;

/// The `long` type — category-2 bytecode primitive.
///
/// Corresponds to `Types.TLong`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TLong;

impl SType for TLong {
    fn descriptor(&self) -> &str { "J" }
}
impl SNonVoid for TLong {}
impl SPrim for TLong {
    fn t(&self) -> i32 { NEWARRAY_LONG }
}
impl BType for TLong {}
impl BNonVoid for TLong {
    fn slots(&self) -> u32 { 2 }
}
impl BPrim for TLong {}
impl TCat2 for TLong {}

/// Singleton constant for `long`. Corresponds to `Types.T_LONG`.
pub const T_LONG: TLong = TLong;

/// The `double` type — category-2 bytecode primitive.
///
/// Corresponds to `Types.TDouble`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TDouble;

impl SType for TDouble {
    fn descriptor(&self) -> &str { "D" }
}
impl SNonVoid for TDouble {}
impl SPrim for TDouble {
    fn t(&self) -> i32 { NEWARRAY_DOUBLE }
}
impl BType for TDouble {}
impl BNonVoid for TDouble {
    fn slots(&self) -> u32 { 2 }
}
impl BPrim for TDouble {}
impl TCat2 for TDouble {}

/// Singleton constant for `double`. Corresponds to `Types.T_DOUBLE`.
pub const T_DOUBLE: TDouble = TDouble;

// ── Reference type ────────────────────────────────────────────────────────────

/// A reference type (object or array) in the JVM type system.
///
/// Corresponds to `Types.TRef<T>`. The Java source stores a `Class<? super T>` for
/// reflection and an ASM `Type` for codegen. In Rust there is no Java reflection; instead
/// `cls_name` holds the JVM internal name of the class or super-type and `descriptor` holds
/// the full JVM descriptor used in generated bytecode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TRef {
    /// JVM internal name of the class or its super-type for generated extensions
    /// (e.g., `"java/lang/String"`, or `"[I"` for an `int[]`).
    pub cls_name: String,
    /// JVM type descriptor (e.g., `"Ljava/lang/String;"` or `"[Z"`).
    pub descriptor: String,
}

impl TRef {
    /// Creates a [`TRef`] for a concrete class identified by its JVM internal name.
    ///
    /// The descriptor is derived as `"L{internal_name};"`.
    /// Corresponds to `TRef.of(Class)` / `Types.refOf(Class)`.
    pub fn of_class(internal_name: &str) -> Self {
        Self {
            cls_name: internal_name.to_string(),
            descriptor: format!("L{};", internal_name),
        }
    }

    /// Creates a [`TRef`] for an array type from the JVM descriptor of the element type.
    ///
    /// For example, `TRef::of_array("I")` produces a `TRef` for `int[]` with descriptor `"[I"`.
    /// Corresponds to `Types.refOf(boolean[].class)` etc.
    pub fn of_array(element_descriptor: &str) -> Self {
        let descriptor = format!("[{}", element_descriptor);
        Self {
            cls_name: descriptor.clone(),
            descriptor,
        }
    }

    /// Creates a [`TRef`] for a generated type that extends a known super-type.
    ///
    /// `super_cls_name` is the JVM internal name of the super-type and `descriptor` is the
    /// full JVM descriptor of the generated type.
    /// Corresponds to `TRef.ofExtends(Class, String)` / `Types.refExtends(Class, String)`.
    pub fn of_extends(super_cls_name: &str, descriptor: &str) -> Self {
        Self {
            cls_name: super_cls_name.to_string(),
            descriptor: descriptor.to_string(),
        }
    }

    /// Creates a [`TRef`] for a type that extends the class described by `super_tref`.
    ///
    /// Corresponds to `Types.refExtends(TRef<ST>, String)` and
    /// `Types.refExtends(TRef<ST>, Class<?>)` (both overloads pass the descriptor explicitly
    /// in Rust since there is no Java reflection).
    pub fn extends_from(super_tref: &TRef, descriptor: &str) -> Self {
        Self::of_extends(&super_tref.cls_name, descriptor)
    }
}

impl SType for TRef {
    fn descriptor(&self) -> &str { &self.descriptor }
}
impl SNonVoid for TRef {}
impl BType for TRef {
    fn internal_name(&self) -> &str {
        let d = &self.descriptor;
        if d.starts_with('L') && d.ends_with(';') {
            &d[1..d.len() - 1]
        } else {
            d
        }
    }
}
impl BNonVoid for TRef {
    fn slots(&self) -> u32 { 1 }
}
impl TCat1 for TRef {}

// ── Well-known array-type reference constants ─────────────────────────────────

/// The `boolean[]` type. Corresponds to `Types.T_BOOL_ARR`.
pub static T_BOOL_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("Z"));
/// The `byte[]` type. Corresponds to `Types.T_BYTE_ARR`.
pub static T_BYTE_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("B"));
/// The `char[]` type. Corresponds to `Types.T_CHAR_ARR`.
pub static T_CHAR_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("C"));
/// The `short[]` type. Corresponds to `Types.T_SHORT_ARR`.
pub static T_SHORT_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("S"));
/// The `int[]` type. Corresponds to `Types.T_INT_ARR`.
pub static T_INT_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("I"));
/// The `long[]` type. Corresponds to `Types.T_LONG_ARR`.
pub static T_LONG_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("J"));
/// The `float[]` type. Corresponds to `Types.T_FLOAT_ARR`.
pub static T_FLOAT_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("F"));
/// The `double[]` type. Corresponds to `Types.T_DOUBLE_ARR`.
pub static T_DOUBLE_ARR: Lazy<TRef> = Lazy::new(|| TRef::of_array("D"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn void_descriptor() {
        assert_eq!(T_VOID.descriptor(), "V");
    }

    #[test]
    fn primitive_descriptors() {
        assert_eq!(T_BOOL.descriptor(), "Z");
        assert_eq!(T_BYTE.descriptor(), "B");
        assert_eq!(T_CHAR.descriptor(), "C");
        assert_eq!(T_SHORT.descriptor(), "S");
        assert_eq!(T_INT.descriptor(), "I");
        assert_eq!(T_FLOAT.descriptor(), "F");
        assert_eq!(T_LONG.descriptor(), "J");
        assert_eq!(T_DOUBLE.descriptor(), "D");
    }

    #[test]
    fn newarray_type_codes() {
        assert_eq!(T_BOOL.t(), NEWARRAY_BOOLEAN);
        assert_eq!(T_BYTE.t(), NEWARRAY_BYTE);
        assert_eq!(T_CHAR.t(), NEWARRAY_CHAR);
        assert_eq!(T_SHORT.t(), NEWARRAY_SHORT);
        assert_eq!(T_INT.t(), NEWARRAY_INT);
        assert_eq!(T_FLOAT.t(), NEWARRAY_FLOAT);
        assert_eq!(T_LONG.t(), NEWARRAY_LONG);
        assert_eq!(T_DOUBLE.t(), NEWARRAY_DOUBLE);
    }

    #[test]
    fn cat1_slots() {
        assert_eq!(T_INT.slots(), 1);
        assert_eq!(T_FLOAT.slots(), 1);
    }

    #[test]
    fn cat2_slots() {
        assert_eq!(T_LONG.slots(), 2);
        assert_eq!(T_DOUBLE.slots(), 2);
    }

    #[test]
    fn tref_of_class_descriptor_and_internal_name() {
        let r = TRef::of_class("java/lang/String");
        assert_eq!(r.descriptor(), "Ljava/lang/String;");
        assert_eq!(r.internal_name(), "java/lang/String");
    }

    #[test]
    fn tref_of_array_descriptor_and_internal_name() {
        let r = TRef::of_array("I");
        assert_eq!(r.descriptor(), "[I");
        assert_eq!(r.internal_name(), "[I");
    }

    #[test]
    fn tref_of_extends() {
        let r = TRef::of_extends("java/lang/Object", "Lcom/example/Gen;");
        assert_eq!(r.cls_name, "java/lang/Object");
        assert_eq!(r.descriptor(), "Lcom/example/Gen;");
        assert_eq!(r.internal_name(), "com/example/Gen");
    }

    #[test]
    fn tref_extends_from() {
        let super_ref = TRef::of_class("ghidra/pcode/emu/jit/gen/JitCompiledPassage");
        let generated = TRef::extends_from(&super_ref, "Lcom/example/CompiledPassage;");
        assert_eq!(generated.cls_name, "ghidra/pcode/emu/jit/gen/JitCompiledPassage");
        assert_eq!(generated.descriptor(), "Lcom/example/CompiledPassage;");
    }

    #[test]
    fn tref_slots_is_one() {
        let r = TRef::of_class("java/lang/Object");
        assert_eq!(r.slots(), 1);
    }

    #[test]
    fn array_type_constants_descriptors() {
        assert_eq!(T_BOOL_ARR.descriptor(), "[Z");
        assert_eq!(T_BYTE_ARR.descriptor(), "[B");
        assert_eq!(T_CHAR_ARR.descriptor(), "[C");
        assert_eq!(T_SHORT_ARR.descriptor(), "[S");
        assert_eq!(T_INT_ARR.descriptor(), "[I");
        assert_eq!(T_LONG_ARR.descriptor(), "[J");
        assert_eq!(T_FLOAT_ARR.descriptor(), "[F");
        assert_eq!(T_DOUBLE_ARR.descriptor(), "[D");
    }

    #[test]
    fn tref_satisfies_cat1_bound() {
        fn slots_of_cat1<T: TCat1>(t: &T) -> u32 { t.slots() }
        let r = TRef::of_class("java/lang/Object");
        assert_eq!(slots_of_cat1(&r), 1);
    }

    #[test]
    fn int_float_satisfy_bprim_bound() {
        fn slots_via_bprim<T: BPrim>(t: &T) -> u32 { t.slots() }
        assert_eq!(slots_via_bprim(&T_INT), 1);
        assert_eq!(slots_via_bprim(&T_FLOAT), 1);
        assert_eq!(slots_via_bprim(&T_LONG), 2);
        assert_eq!(slots_via_bprim(&T_DOUBLE), 2);
    }

    #[test]
    fn void_is_btype_not_snon_void() {
        fn accepts_btype<T: BType>(t: &T) -> &str { t.descriptor() }
        assert_eq!(accepts_btype(&T_VOID), "V");
    }
}
