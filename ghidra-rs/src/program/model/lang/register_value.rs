//! Port of `ghidra.program.model.lang.RegisterValue`.
//!
//! The crate's single register-value type: every processor-context, program-context, trace and
//! emulator API passes these by value (`RegisterValue`, `Option<RegisterValue>`) or reference.
//!
//! ## Storage format
//!
//! Mirrors Java's documented layout exactly: `bytes` is `2 * base_register_byte_size` long,
//! big-endian, with the mask stored in the first half and the value in the second half (see the
//! class doc comment on `RegisterValue.java`). All arithmetic here reimplements Java's byte-level
//! algorithms (`combineValues`, `clearBitValues`, `hasValue`, `hasAnyValue`,
//! `getUnsignedValueIgnoreMask`) using `u128` shifts over the mask/value halves instead of Java's
//! manual per-byte bit masking -- behaviorally identical, since both approaches just extract/set
//! the `[start_bit, end_bit]` window (relative to the base register's LSB) of a big-endian byte
//! string, but far simpler to read and verify. Registers whose base is wider than 16 bytes (128
//! bits) cannot be represented by this port (Java's `BigInteger` accessors become `u128`/`i128`).

use crate::program::model::lang::register::RegisterRef;

/// A register value that keeps track of which bits are actually set (via an associated mask).
///
/// Port of `ghidra.program.model.lang.RegisterValue`.
#[derive(Clone, Debug)]
pub struct RegisterValue {
    register: RegisterRef,
    /// `2 * base_register_byte_size` bytes: mask half followed by value half, both big-endian.
    bytes: Vec<u8>,
    /// Least-significant bit of `register` within its base register (`register.getLeastSignificantBitInBaseRegister()`).
    start_bit: i32,
    /// Most-significant bit of `register` within its base register (`start_bit + bit_length - 1`).
    end_bit: i32,
}

fn bytes_to_u128_be(bytes: &[u8]) -> u128 {
    let mut v: u128 = 0;
    for &b in bytes {
        v = (v << 8) | b as u128;
    }
    v
}

fn u128_to_bytes_be(mut v: u128, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in (0..len).rev() {
        out[i] = (v & 0xFF) as u8;
        v >>= 8;
    }
    out
}

/// Mask with the low `bits` bits set (all 1s if `bits >= 128`).
fn low_bits_mask(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

impl RegisterValue {
    /// Registers wider than this many bytes cannot be represented (see module docs).
    pub const MAX_BASE_REGISTER_BYTES: usize = 16;

    fn base_byte_size(register: &RegisterRef) -> usize {
        let n = register.get_base_register().base_mask().len();
        assert!(
            n <= Self::MAX_BASE_REGISTER_BYTES,
            "RegisterValue: base register '{}' is {n} bytes, exceeding the {}-byte limit imposed \
             by this crate's u128-based RegisterValue seam trait (get_unsigned_value_ignore_mask)",
            register.get_base_register().name(),
            Self::MAX_BASE_REGISTER_BYTES
        );
        n
    }

    fn bit_range(register: &RegisterRef) -> (i32, i32) {
        let reg = register;
        let start = reg.least_significant_bit_in_base_register();
        let end = start + reg.bit_length() - 1;
        (start, end)
    }

    /// Creates a new `RegisterValue` for a register that has no value (all mask bits off).
    ///
    /// Port of `RegisterValue(Register)`.
    pub fn new(register: RegisterRef) -> Self {
        let n = Self::base_byte_size(&register);
        let (start_bit, end_bit) = Self::bit_range(&register);
        Self { register, bytes: vec![0u8; n * 2], start_bit, end_bit }
    }

    /// Constructs a new `RegisterValue` for the given register and value. All mask bits for the
    /// given register are set to "valid".
    ///
    /// Port of `RegisterValue(Register, BigInteger)`.
    pub fn with_value(register: RegisterRef, value: u128) -> Self {
        let n = Self::base_byte_size(&register);
        let (start_bit, end_bit) = Self::bit_range(&register);
        let bit_length = end_bit - start_bit + 1;

        let masked_value = value & low_bits_mask(bit_length as u32);
        // Shift into position within the base register's bit range. `start_bit` plus
        // `bit_length` is guaranteed (by construction of a valid Register) to fit within
        // `n * 8` bits, so this shift cannot lose value bits that survive the final
        // register-mask AND below.
        let shifted = if start_bit >= 128 { 0 } else { masked_value << start_bit };
        let value_bytes = u128_to_bytes_be(shifted, n);

        let register_mask = register.base_mask();
        let mut bytes = vec![0u8; n * 2];
        for i in 0..n {
            bytes[i] = register_mask[i];
            bytes[n + i] = value_bytes[i] & register_mask[i];
        }
        Self { register, bytes, start_bit, end_bit }
    }

    /// Constructs a new `RegisterValue` for `register` using a specified value and mask, where
    /// the set bits of `mask` (relative to `register`'s least significant bit) identify which value
    /// bits are valid.
    ///
    /// Port of `RegisterValue(Register, BigInteger, BigInteger)`: like Java, the mask is shifted
    /// into position and copied over the mask half as-is (bits above the base register are
    /// dropped), and the value half is then limited to the masked bits.
    pub fn with_value_and_mask(register: RegisterRef, value: u128, mask: u128) -> Self {
        let mut result = Self::with_value(register, value);
        let n = result.n();
        let shifted_mask = if result.start_bit >= 128 { 0 } else { mask << result.start_bit };
        let mask_bytes = u128_to_bytes_be(shifted_mask, n);
        for i in 0..n {
            result.bytes[i] = mask_bytes[i];
            result.bytes[n + i] &= mask_bytes[i];
        }
        result
    }

    /// Constructs a new `RegisterValue` object for the given register and the mask/value byte
    /// array (mask/value halves, both sized to the register's *base* register byte length).
    ///
    /// Port of `RegisterValue(Register, byte[])`, minus Java's `adjustBytes` resizing step: that
    /// step exists to reinterpret bytes captured under a *different*-sized base register (e.g.
    /// across a language upgrade), which this crate's `RangeMapAdapter::set_language` already
    /// leaves as a documented no-op (see `database_range_map_adapter.rs`); every real caller in
    /// this port always supplies bytes already sized to `register`'s current base register, so
    /// that resize path is dead code here. Falls back to zero-padding/truncating (rather than
    /// Java's context-aware left/right justification) if `bytes` is the wrong length, to keep this
    /// a total function; that fallback path is not exercised by any real caller in this crate.
    pub fn from_bytes(register: RegisterRef, bytes: &[u8]) -> Self {
        let n = Self::base_byte_size(&register);
        let (start_bit, end_bit) = Self::bit_range(&register);

        let mut adjusted = vec![0u8; 2 * n];
        if bytes.len() == 2 * n {
            adjusted.copy_from_slice(bytes);
        } else {
            // Not exercised by any real caller in this port; see doc comment above.
            let old_n = bytes.len() / 2;
            let keep = old_n.min(n);
            adjusted[n - keep..n].copy_from_slice(&bytes[old_n - keep..old_n]);
            adjusted[2 * n - keep..].copy_from_slice(&bytes[bytes.len() - keep..]);
        }

        let register_mask = register.base_mask();
        for i in 0..n {
            adjusted[i] &= register_mask[i];
            adjusted[n + i] &= register_mask[i];
        }

        Self { register, bytes: adjusted, start_bit, end_bit }
    }

    fn check_base_register(&self, other: &RegisterRef) {
        let self_base = self.register.get_base_register();
        let other_base = other.get_base_register();
        assert!(
            same_register(&self_base, &other_base),
            "Register '{}' does not share common base register '{}'",
            other.name(),
            self_base.name()
        );
    }

    /// Returns the register used in this register value object.
    ///
    /// Port of `RegisterValue.getRegister()`.
    pub fn register(&self) -> RegisterRef {
        self.register.clone()
    }

    /// Returns the mask/value bytes for this register value.
    ///
    /// Port of `RegisterValue.toBytes()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Returns this register value in terms of the base register.
    ///
    /// Port of `RegisterValue.getBaseRegisterValue()`.
    pub fn base_register_value(&self) -> RegisterValue {
        Self::from_bytes(self.register.get_base_register(), &self.bytes)
    }

    fn n(&self) -> usize {
        self.bytes.len() / 2
    }

    fn mask_int(&self) -> u128 {
        bytes_to_u128_be(&self.bytes[0..self.n()])
    }

    fn value_int(&self) -> u128 {
        bytes_to_u128_be(&self.bytes[self.n()..])
    }

    /// Creates a new `RegisterValue`, combining `self` and `other_value`, where `other_value`'s
    /// value bits take precedence wherever `other_value`'s mask is "on". The mask bits are OR'd
    /// together.
    ///
    /// Port of `RegisterValue.combineValues(RegisterValue)`.
    pub fn combine_values(&self, other_value: &RegisterValue) -> RegisterValue {
        self.check_base_register(&other_value.register);
        let base_register = self.register.get_base_register();
        let result_register =
            if reg_eq(&self.register, &other_value.register) { self.register.clone() } else { base_register };

        let n = self.n();
        let mut result_bytes = vec![0u8; other_value.bytes.len()];
        for i in 0..n {
            let mask = other_value.bytes[i];
            let clear_mask = !mask;
            result_bytes[n + i] = (other_value.bytes[n + i] & mask) | (self.bytes[n + i] & clear_mask);
            result_bytes[i] = self.bytes[i] | other_value.bytes[i];
        }
        Self::from_bytes(result_register, &result_bytes)
    }

    /// Clears the value bits corresponding to the "on" bits in the given mask (a base-register-
    /// sized byte mask, e.g. from [`RegisterRef::base_mask`]).
    ///
    /// Port of `RegisterValue.clearBitValues(byte[])`.
    pub fn clear_bit_values(&self, mask: &[u8]) -> RegisterValue {
        assert_eq!(mask.len(), self.n(), "Mask length must be the same length as this object's mask");
        let n = self.n();
        let mut result_bytes = vec![0u8; self.bytes.len()];
        for i in 0..n {
            let clear_mask = !mask[i];
            result_bytes[n + i] = self.bytes[n + i] & clear_mask;
            result_bytes[i] = self.bytes[i] & clear_mask;
        }
        Self::from_bytes(self.register.clone(), &result_bytes)
    }

    /// Returns the value mask (relative to the base register) that indicates which bits have a
    /// valid value.
    ///
    /// Port of `RegisterValue.getBaseValueMask()`.
    pub fn base_value_mask(&self) -> Vec<u8> {
        let mask = self.register.base_mask();
        let mut out = vec![0u8; mask.len()];
        for i in 0..mask.len() {
            out[i] = mask[i] & self.bytes[i];
        }
        out
    }

    /// Returns the value mask that indicates which bits relative to this value's register (bit 0
    /// being its least significant bit) have a valid value.
    ///
    /// Port of `RegisterValue.getValueMask()`.
    pub fn value_mask(&self) -> u128 {
        let base_mask = bytes_to_u128_be(&self.base_value_mask());
        if self.start_bit >= 128 { 0 } else { base_mask >> self.start_bit }
    }

    /// Assigns `value` to the portion of this register value that `sub_register` covers: only
    /// the bits `value` actually has are applied.
    ///
    /// Port of `RegisterValue.assign(Register, RegisterValue)`.
    ///
    /// # Panics
    /// If `sub_register` does not share this value's base register (Java's
    /// `IllegalArgumentException`).
    pub fn assign(&self, sub_register: &RegisterRef, value: &RegisterValue) -> RegisterValue {
        self.check_base_register(sub_register);
        let other = Self::with_value_and_mask(
            sub_register.clone(),
            value.unsigned_value_ignore_mask(),
            value.value_mask(),
        );
        self.combine_values(&other)
    }

    /// Assigns the fully-known `value` to the portion of this register value that `sub_register`
    /// covers.
    ///
    /// Port of `RegisterValue.assign(Register, BigInteger)`.
    ///
    /// # Panics
    /// If `sub_register` does not share this value's base register.
    pub fn assign_value(&self, sub_register: &RegisterRef, value: u128) -> RegisterValue {
        self.check_base_register(sub_register);
        self.combine_values(&Self::with_value(sub_register.clone(), value))
    }

    /// Tests if this `RegisterValue` contains valid value bits for the entire register (i.e.
    /// [`RegisterValue::unsigned_value`] would return `Some`).
    ///
    /// Port of `RegisterValue.hasValue()`.
    pub fn has_value(&self) -> bool {
        let bit_length = (self.end_bit - self.start_bit + 1) as u32;
        let sub_mask = if self.start_bit >= 128 { 0 } else { (self.mask_int() >> self.start_bit) & low_bits_mask(bit_length) };
        sub_mask == low_bits_mask(bit_length)
    }

    /// Returns true if this value's mask has any bits set anywhere in the base register (not
    /// scoped to this value's own register's bit range).
    ///
    /// Port of `RegisterValue.hasAnyValue()`.
    pub fn has_any_value(&self) -> bool {
        self.mask_int() != 0
    }

    /// Returns the unsigned value for this register regardless of the mask bits. Bits that have
    /// an "off" mask bit have the value 0.
    ///
    /// Port of `RegisterValue.getUnsignedValueIgnoreMask()`.
    pub fn unsigned_value_ignore_mask(&self) -> u128 {
        let bit_length = (self.end_bit - self.start_bit + 1) as u32;
        if self.start_bit >= 128 {
            return 0;
        }
        (self.value_int() >> self.start_bit) & low_bits_mask(bit_length)
    }

    /// Returns the unsigned value for this register if all the appropriate mask bits are "on",
    /// otherwise `None`.
    ///
    /// Port of `RegisterValue.getUnsignedValue()`.
    pub fn unsigned_value(&self) -> Option<u128> {
        if self.has_value() { Some(self.unsigned_value_ignore_mask()) } else { None }
    }

    /// Returns the signed (two's-complement, sign-extended over this register's bit length)
    /// value for this register regardless of the mask bits.
    ///
    /// Port of `RegisterValue.getSignedValueIgnoreMask()`.
    pub fn signed_value_ignore_mask(&self) -> i128 {
        let bit_length = (self.end_bit - self.start_bit + 1) as u32;
        let raw = self.unsigned_value_ignore_mask();
        if bit_length == 0 {
            return 0;
        }
        if bit_length >= 128 {
            // The full 128-bit pattern; reinterpreting as `i128` is exactly two's-complement
            // sign extension for a value that already occupies every bit.
            return raw as i128;
        }
        let sign_bit = 1u128 << (bit_length - 1);
        if raw & sign_bit != 0 {
            (raw as i128) - (1i128 << bit_length)
        } else {
            raw as i128
        }
    }

    /// Returns the signed value for this register if all the appropriate mask bits are "on",
    /// otherwise `None`.
    ///
    /// Port of `RegisterValue.getSignedValue()`.
    pub fn signed_value(&self) -> Option<i128> {
        if self.has_value() { Some(self.signed_value_ignore_mask()) } else { None }
    }

    /// Returns a new `RegisterValue` restricted to `new_register` (which must share the same
    /// base register as `self`).
    ///
    /// Port of `RegisterValue.getRegisterValue(Register)`.
    pub fn get_register_value(&self, new_register: &RegisterRef) -> RegisterValue {
        if reg_eq(&self.register, new_register) {
            return self.clone();
        }
        self.check_base_register(new_register);
        Self::from_bytes(new_register.clone(), &self.bytes)
    }
}

/// Reference-identity-like equality for registers: pointer identity, falling back to name
/// equality. Java compares by object identity (`register == other.register`); this crate's
/// `Register`s constructed from the same `Language` are expected to be the same underlying
/// definition, so name equality is the faithful analog here when the `Rc` pointers themselves
/// differ (e.g. a register reached via two different traversal paths).
fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    crate::program::model::lang::Register::same(a, b) || a.name() == b.name()
}

fn reg_eq(a: &RegisterRef, b: &RegisterRef) -> bool {
    same_register(a, b)
}

/// Port of `RegisterValue.equals(Object)`: the same register (Java's `==` on `Register`, whose
/// analog here is [`same_register`]) and the same mask/value bytes.
impl PartialEq for RegisterValue {
    fn eq(&self, other: &Self) -> bool {
        same_register(&self.register, &other.register) && self.bytes == other.bytes
    }
}

impl Eq for RegisterValue {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn base_register(name: &str, num_bytes: i32) -> RegisterRef {
        let space = space();
        Register::new(name, "", Address::new(space, 0), num_bytes, false, 0)
    }

    /// Attaches a single byte-aligned child register (`byte_offset` bytes above the base
    /// register's own address) to `parent`. Note: each call replaces `parent`'s full child list
    /// (see `Register::set_child_registers`), so tests that need multiple children on the same
    /// parent must use [`child_registers`] instead of calling this more than once per parent.
    fn child_register(parent: &mut RegisterRef, name: &str, byte_offset: i64, num_bytes: i32) -> RegisterRef {
        let space = space();
        let child = Register::new(name, "", Address::new(space, byte_offset), num_bytes, false, 0);
        let mut linked = crate::program::model::lang::register::test_support::linked(&[parent, &child], &[(0, &[1])]);
        let child = linked.pop().unwrap();
        *parent = linked.pop().unwrap();
        child
    }

    /// Attaches multiple byte-aligned child registers to `parent` in one call.
    fn child_registers(parent: &mut RegisterRef, specs: &[(&str, i64, i32)]) -> Vec<RegisterRef> {
        let space = space();
        let children: Vec<RegisterRef> = specs
            .iter()
            .map(|(name, byte_offset, num_bytes)| {
                Register::new(*name, "", Address::new(space.clone(), *byte_offset), *num_bytes, false, 0)
            })
            .collect();
        let mut all: Vec<&RegisterRef> = vec![parent];
        all.extend(children.iter());
        let child_indices: Vec<usize> = (1..all.len()).collect();
        let mut linked = crate::program::model::lang::register::test_support::linked(&all, &[(0, &child_indices)]);
        let children = linked.split_off(1);
        *parent = linked.pop().unwrap();
        children
    }

    #[test]
    fn new_value_has_no_value_and_no_any_value() {
        let reg = base_register("r0", 4);
        let value = RegisterValue::new(reg);
        assert!(!value.has_value());
        assert!(!value.has_any_value());
        assert_eq!(value.unsigned_value(), None);
    }

    #[test]
    fn with_value_round_trips_through_unsigned_value() {
        let reg = base_register("r0", 4);
        let value = RegisterValue::with_value(reg, 0xDEADBEEFu128);
        assert!(value.has_value());
        assert!(value.has_any_value());
        assert_eq!(value.unsigned_value(), Some(0xDEADBEEF));
        assert_eq!(value.unsigned_value_ignore_mask(), 0xDEADBEEF);
    }

    #[test]
    fn signed_value_sign_extends_negative_numbers() {
        let reg = base_register("r0", 4);
        // 0xFFFFFFFF as an unsigned 32-bit value is -1 when interpreted as signed.
        let value = RegisterValue::with_value(reg.clone(), 0xFFFF_FFFFu128);
        assert_eq!(value.signed_value(), Some(-1));

        let positive = RegisterValue::with_value(reg, 0x7FFF_FFFFu128);
        assert_eq!(positive.signed_value(), Some(0x7FFF_FFFF));
    }

    #[test]
    fn to_bytes_has_mask_half_and_value_half() {
        let reg = base_register("r0", 2);
        let value = RegisterValue::with_value(reg, 0x1234);
        let bytes = value.to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes[0..2], &[0xFF, 0xFF]);
        assert_eq!(&bytes[2..4], &[0x12, 0x34]);
    }

    #[test]
    fn combine_values_prefers_other_where_masked_on() {
        let mut reg = base_register("r0", 4);
        let base_val = RegisterValue::with_value(reg.clone(), 0x1111_1111);

        // A partial value: only the low byte known, via a child register (byte offset 0 is the
        // least-significant byte under this crate's little-endian `set_base_register_info`
        // convention, see `child_register`'s doc comment).
        let low_byte = child_register(&mut reg, "r0l", 0, 1);
        let partial = RegisterValue::with_value(low_byte, 0xAB);

        let combined = base_val.combine_values(&partial);
        // Low byte comes from `partial` (0xAB); rest is preserved from `base_val`.
        assert_eq!(combined.unsigned_value(), Some(0x1111_11AB));
    }

    #[test]
    fn clear_bit_values_removes_masked_bits() {
        let mut reg = base_register("r0", 4);
        let value = RegisterValue::with_value(reg.clone(), 0xFFFF_FFFF);
        let low_byte_mask = child_register(&mut reg, "r0l", 0, 1).base_mask();

        let cleared = value.clear_bit_values(&low_byte_mask);
        assert!(!cleared.has_value()); // no longer fully specified
        assert_eq!(cleared.unsigned_value_ignore_mask(), 0xFFFF_FF00);
    }

    #[test]
    fn sub_register_composition_and_decomposition() {
        let mut reg = base_register("eax", 4);
        let children = child_registers(&mut reg, &[("al", 0, 1), ("ah", 1, 1)]);
        let al = children[0].clone();
        let ah = children[1].clone();

        let al_value = RegisterValue::with_value(al.clone(), 0x11);
        let ah_value = RegisterValue::with_value(ah.clone(), 0x22);

        let combined = al_value.combine_values(&ah_value);
        // Neither al nor ah covers all of eax, so the combination is still partial...
        assert!(!combined.has_value());
        // ...but decomposing back down to al/ah recovers each byte exactly.
        let al_back = combined.get_register_value(&al);
        let ah_back = combined.get_register_value(&ah);
        assert_eq!(al_back.unsigned_value(), Some(0x11));
        assert_eq!(ah_back.unsigned_value(), Some(0x22));
    }

    #[test]
    fn get_register_value_widens_to_full_register_view() {
        let mut reg = base_register("eax", 4);
        let al = child_register(&mut reg, "al", 0, 1);

        let al_value = RegisterValue::with_value(al.clone(), 0x7F);
        let as_eax = al_value.get_register_value(&reg);
        assert!(!as_eax.has_value()); // only the al byte is known
        assert_eq!(as_eax.unsigned_value_ignore_mask(), 0x7F);
    }

    /// A partially-known value (only `al` of `eax`) is not equal to the fully-known value with
    /// the same value bits: equality is Java's -- same register, same mask/value bytes.
    #[test]
    fn equality_compares_the_mask_as_well_as_the_value() {
        let mut reg = base_register("eax", 4);
        let al = child_register(&mut reg, "al", 0, 1);
        let partial = RegisterValue::with_value(al, 0x7F).get_register_value(&reg);
        assert!(partial.has_any_value() && !partial.has_value());

        let copy = RegisterValue::from_bytes(reg.clone(), &partial.to_bytes());
        assert_eq!(copy, partial);
        assert_eq!(copy.base_value_mask(), partial.base_value_mask());
        assert_ne!(copy, RegisterValue::with_value(reg, 0x7F));
    }

    #[test]
    fn with_value_and_mask_keeps_only_masked_value_bits() {
        let reg = base_register("r0", 4);
        let value = RegisterValue::with_value_and_mask(reg, 0x1234_5678, 0x0000_FFFF);
        assert!(!value.has_value());
        assert!(value.has_any_value());
        assert_eq!(value.unsigned_value_ignore_mask(), 0x5678);
        assert_eq!(value.value_mask(), 0xFFFF);
        assert_eq!(value.to_bytes(), vec![0, 0, 0xFF, 0xFF, 0, 0, 0x56, 0x78]);
    }

    #[test]
    fn value_mask_is_relative_to_the_value_register() {
        let mut reg = base_register("eax", 4);
        let ah = child_register(&mut reg, "ah", 1, 1);
        let ah_value = RegisterValue::with_value(ah, 0x22);
        // Relative to `ah` itself: all 8 of its bits are known.
        assert_eq!(ah_value.value_mask(), 0xFF);
        // Relative to the base register, the known bits sit at bits 8..16.
        assert_eq!(ah_value.base_register_value().value_mask(), 0xFF00);
    }

    /// Java's `assign(Register, RegisterValue)` applies only the bits the assigned value has.
    #[test]
    fn assign_applies_only_known_bits_of_the_sub_value() {
        let mut reg = base_register("eax", 4);
        let children = child_registers(&mut reg, &[("al", 0, 1), ("ah", 1, 1)]);
        let (al, ah) = (children[0].clone(), children[1].clone());
        let whole = RegisterValue::with_value(reg.clone(), 0x1111_1111);

        let assigned = whole.assign(&al, &RegisterValue::with_value(al.clone(), 0xAB));
        assert_eq!(assigned.unsigned_value(), Some(0x1111_11AB));

        // An empty value assigns nothing.
        let unchanged = whole.assign(&ah, &RegisterValue::new(ah.clone()));
        assert_eq!(unchanged.unsigned_value(), Some(0x1111_1111));

        let by_int = RegisterValue::new(reg).assign_value(&ah, 0x7F);
        assert_eq!(by_int.get_register_value(&ah).unsigned_value(), Some(0x7F));
        assert_eq!(by_int.get_register_value(&al).unsigned_value(), None);
    }

    #[test]
    fn base_register_value_reflects_full_bit_range() {
        let mut reg = base_register("eax", 4);
        let al = child_register(&mut reg, "al", 0, 1);
        let al_value = RegisterValue::with_value(al, 0x42);

        let base_value = al_value.base_register_value();
        assert_eq!(base_value.unsigned_value_ignore_mask(), 0x42);
        assert!(!base_value.has_value());
    }
}
