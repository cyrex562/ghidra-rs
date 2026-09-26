use super::binary_field::format_hex_preview;
use super::buffer::Buffer;
use super::fixed_field::FixedField;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::field::FieldType;
use std::cmp::Ordering;

/// An unsigned 10-byte fixed-length field value. The most-significant byte corresponds to
/// index 0.
///
/// Port of `db.FixedField10`, `FixedField`'s only concrete subclass in the real `db` package (see
/// the scope note on [`FixedField`]). Like its siblings in this file family, it is ported as an
/// object-safe trait (a cycle cut-point): `FixedField10: FixedField` (which itself requires
/// [`super::binary_field::BinaryField`]).
///
/// # Representation
/// Java stores the value as `long hi8` (the first/most-significant 8 bytes) plus `short lo2`
/// (the last 2 bytes) -- both ordinary *signed* Java primitives, even though the field's overall
/// value is documented as unsigned. `compareTo` explicitly reinterprets both as unsigned
/// (`Long.compareUnsigned`/`Short.compareUnsigned`), while `hashCode`'s `result = prime * result
/// + lo2` relies on ordinary Java short-to-int promotion, which *sign-extends*. This port keeps
/// the exact same signed `i64`/`i16` representation (rather than switching to `u64`/`u16`, which
/// would look tidier but would silently change [`Self::field_hash_fixed10`]'s bit pattern for any
/// value whose `lo2` has its high bit set) specifically so [`Self::field_hash_fixed10`] can
/// reproduce that sign-extension quirk bit-for-bit; see the test
/// `test_hash_code_sign_extends_lo2_unlike_unsigned_compare`.
///
/// # Method-name suffixing
/// Following the convention established by [`FixedField`] itself (see its doc comment's
/// "Method-name shadowing caveat"), every method this trait adds beyond what it inherits from
/// [`FixedField`]/[`super::binary_field::BinaryField`] is suffixed `_fixed10` to avoid
/// same-name-different-signature ambiguity for a type implementing all three traits at once.
/// [`super::binary_field::BinaryField::get_binary_data`]/`set_binary_data` are *not* redeclared
/// here: both are already abstract (no default body) on `BinaryField`, so any concrete
/// implementor of this trait must supply them directly regardless -- there is nothing for this
/// trait to add. [`Self::binary_data_fixed10`] is provided as a ready-made, allocating helper
/// that a `get_binary_data`/`set_binary_data` implementation can delegate to, sidestepping the
/// awkward fact that Java's `getBinaryData()` lazily *mutates* a cached `data` byte-array field
/// from within what Rust would need to be a `&self` method (this port's implementors are
/// expected to instead keep their own cached byte array in sync eagerly, e.g. on construction and
/// on every mutation -- an internal strategy change with no externally observable effect, per
/// this crate's house rule on the owned-vs-borrowed self-reference problem).
pub trait FixedField10: FixedField {
    /// The most-significant 8 bytes of this field's value, as a raw (signed-typed, semantically
    /// unsigned) `i64`. Mirrors the private `FixedField10.hi8` field.
    fn get_hi8(&self) -> i64;

    /// The least-significant 2 bytes of this field's value, as a raw (signed-typed, semantically
    /// unsigned) `i16`. Mirrors the private `FixedField10.lo2` field.
    fn get_lo2(&self) -> i16;

    /// Directly (infallibly) overwrite this field's `hi8`/`lo2` primitive storage, without
    /// touching null-state or immutability bookkeeping (callers -- i.e. the default methods on
    /// this trait -- are responsible for performing those checks first). Mirrors the handful of
    /// places Java's `FixedField10` assigns `this.hi8`/`this.lo2` directly (the package-private
    /// `FixedField10(long, short, boolean)` constructor, `updatePrimitiveValue(byte[])`, and
    /// `setNull()`'s reset to zero).
    fn set_raw_fixed10(&mut self, hi8: i64, lo2: i16);

    /// Constructs a new, zero-valued, mutable `FixedField10`. Mirrors `FixedField10.newField()`
    /// (`abstract` at the [`FixedField`] level; narrowed to `FixedField10` here).
    fn new_fixed10(&self) -> Box<dyn FixedField10>;

    /// Returns the minimum representable `FixedField10` value (zero). Mirrors
    /// `FixedField10.getMinValue()`/`FixedField10.MIN_VALUE` (`abstract` at the [`FixedField`]
    /// level; narrowed to `FixedField10` here). Java also exposes this as a shared `MIN_VALUE`/
    /// `ZERO_VALUE`/`INSTANCE` static singleton, which is deferred to whichever concrete
    /// implementor eventually replaces the placeholder use of this trait, since a trait cannot
    /// hold `Self`-typed constants while remaining object-safe.
    fn min_value_fixed10(&self) -> Box<dyn FixedField10>;

    /// Returns the maximum representable `FixedField10` value (all bits set). Mirrors
    /// `FixedField10.getMaxValue()`/`FixedField10.MAX_VALUE`.
    fn max_value_fixed10(&self) -> Box<dyn FixedField10>;

    /// Constructs a copy of this field, detached from any underlying buffer, preserving its
    /// null-state. Mirrors `FixedField10.copyField()`.
    ///
    /// Provided as a default built on [`Self::new_fixed10`] plus the null-state/raw-value
    /// accessors, since (unlike [`Self::new_fixed10`]/min/max, which must construct a fresh
    /// instance of the implementor's own concrete type) the copying *logic* itself is fully
    /// generic.
    fn copy_fixed10(&self) -> Box<dyn FixedField10> {
        let mut copy = self.new_fixed10();
        if self.is_fixed_null() {
            // `set_fixed_null()` on a freshly-constructed, mutable field cannot fail.
            copy.set_fixed_null().expect("freshly constructed FixedField10 must be mutable");
        } else {
            copy.set_raw_fixed10(self.get_hi8(), self.get_lo2());
        }
        copy
    }

    /// The `Field` type tag for a 10-byte fixed field (`FIXED_10_TYPE`). Mirrors
    /// `FixedField10.getFieldType()`.
    fn field_type_fixed10(&self) -> FieldType {
        FieldType::Fixed(10)
    }

    /// Encoded length in bytes: always 10. Mirrors `FixedField10.length()`.
    fn length_fixed10(&self) -> usize {
        10
    }

    /// Length in bytes of the encoded value at `offset` within `buf`: always 10, without
    /// inspecting `buf`. Mirrors `FixedField10.readLength(Buffer, int)`.
    fn read_length_fixed10(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        10
    }

    /// This field's value as a 10-byte big-endian array (most-significant byte first). Mirrors
    /// `FixedField10.getBinaryData()`, computed fresh from [`Self::get_hi8`]/[`Self::get_lo2`]
    /// rather than lazily cached (see this trait's doc comment).
    fn binary_data_fixed10(&self) -> Vec<u8> {
        let mut data = vec![0u8; 10];
        data[0..8].copy_from_slice(&self.get_hi8().to_be_bytes());
        data[8..10].copy_from_slice(&self.get_lo2().to_be_bytes());
        data
    }

    /// Sets this field's value from a 10-byte array, or clears it to a null state if `data` is
    /// `None`. Mirrors `FixedField10.setBinaryData(byte[])`.
    ///
    /// A ready-made helper a concrete
    /// [`BinaryField::set_binary_data`](super::binary_field::BinaryField::set_binary_data)
    /// implementation can delegate to.
    ///
    /// # Errors
    /// Returns an error if the field is immutable, or (mirroring Java's
    /// `IllegalArgumentException` -- pragmatically substituted with
    /// [`IllegalFieldAccessException`] for consistency with every other fallible method in this
    /// field-trait family, exactly as [`FixedField::truncate_fixed`] already documents doing for
    /// its own Java `UnsupportedOperationException`) if `data` is `Some` with a length other
    /// than 10.
    fn set_binary_data_fixed10(
        &mut self,
        data: Option<&[u8]>,
    ) -> Result<(), IllegalFieldAccessException> {
        match data {
            None => self.set_null_fixed10(),
            Some(d) => {
                if d.len() != 10 {
                    return Err(IllegalFieldAccessException::with_message(
                        "Invalid FixedField10 data length",
                    ));
                }
                self.updating_value()?;
                let mut hi8_bytes = [0u8; 8];
                hi8_bytes.copy_from_slice(&d[0..8]);
                let mut lo2_bytes = [0u8; 2];
                lo2_bytes.copy_from_slice(&d[8..10]);
                self.set_raw_fixed10(i64::from_be_bytes(hi8_bytes), i16::from_be_bytes(lo2_bytes));
                Ok(())
            }
        }
    }

    /// Sets this field to a null state, also resetting its raw storage to zero. Mirrors
    /// `FixedField10.setNull()` (which further extends the inherited `FixedField.setNull()` by
    /// also clearing `data`/`hi8`/`lo2`, unlike plain [`FixedField::set_fixed_null`], which only
    /// touches the null-state flag).
    fn set_null_fixed10(&mut self) -> Result<(), IllegalFieldAccessException> {
        self.set_fixed_null()?;
        self.set_raw_fixed10(0, 0);
        Ok(())
    }

    /// Writes this field's 10-byte value into `buf` at `offset` (with **no** length prefix,
    /// unlike [`super::binary_field::BinaryField::write`]'s default). Returns the next available
    /// offset, or -1 if the buffer is full. Mirrors `FixedField10.write(Buffer, int)`.
    fn write_fixed10(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        let next = buf.put_long(offset, self.get_hi8());
        if next < 0 {
            return next;
        }
        buf.put_short(next as usize, self.get_lo2())
    }

    /// Reads a 10-byte value from `buf` at `offset` into this field, clearing any null state.
    /// Returns the offset immediately following the read value. Mirrors
    /// `FixedField10.read(Buffer, int)`.
    fn read_fixed10(
        &mut self,
        buf: &dyn Buffer,
        offset: usize,
    ) -> Result<usize, IllegalFieldAccessException> {
        self.updating_value()?;
        let hi8 = buf.get_long(offset);
        let lo2 = buf.get_short(offset + 8);
        self.set_raw_fixed10(hi8, lo2);
        Ok(offset + 10)
    }

    /// Compares this field's value to `other`'s, treating both `hi8` and `lo2` as unsigned.
    /// Mirrors `FixedField10.compareTo(Field)` (`Long.compareUnsigned`/`Short.compareUnsigned`).
    ///
    /// This is mathematically equivalent to (but avoids materializing byte arrays for) a plain
    /// unsigned lexicographic byte comparison of the two 10-byte values -- see the test
    /// `test_compare_to_fixed10_matches_lexicographic_byte_order`.
    fn compare_to_fixed10(&self, other: &dyn FixedField10) -> Ordering {
        match (self.get_hi8() as u64).cmp(&(other.get_hi8() as u64)) {
            Ordering::Equal => (self.get_lo2() as u16).cmp(&(other.get_lo2() as u16)),
            ord => ord,
        }
    }

    /// Compares this field's value to the 10-byte value encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors the package-private `FixedField10.compareTo(DataBuffer,
    /// int)`.
    fn compare_buffer_fixed10(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_hi8 = buffer.get_long(offset) as u64;
        match (self.get_hi8() as u64).cmp(&other_hi8) {
            Ordering::Equal => {
                let other_lo2 = buffer.get_short(offset + 8) as u16;
                (self.get_lo2() as u16).cmp(&other_lo2)
            }
            ord => ord,
        }
    }

    /// Whether `other` has the same `hi8`/`lo2` value as this instance. Mirrors
    /// `FixedField10.equals(Object)`.
    fn fields_equal_fixed10(&self, other: &dyn FixedField10) -> bool {
        self.get_hi8() == other.get_hi8() && self.get_lo2() == other.get_lo2()
    }

    /// Deterministic hash over this field's `hi8`/`lo2` value. Mirrors
    /// `FixedField10.hashCode()` bit-for-bit, **including** its sign-extension quirk: see this
    /// trait's own doc comment and the test
    /// `test_hash_code_sign_extends_lo2_unlike_unsigned_compare`.
    fn field_hash_fixed10(&self) -> i32 {
        let hi8 = self.get_hi8();
        // `hi8 >>> 32` in Java: an *unsigned* right shift, reproduced here by shifting the
        // reinterpreted-unsigned bit pattern before casting back.
        let shifted = ((hi8 as u64) >> 32) as i64;
        let result = (hi8 ^ shifted) as i32;
        // `result = prime * result + lo2`: plain Java short-to-int promotion sign-extends `lo2`
        // (unlike this trait's own unsigned-comparison methods above). `i16 as i32` in Rust also
        // sign-extends, so this is a direct, faithful translation -- not a coincidence to "fix".
        result.wrapping_mul(31).wrapping_add(self.get_lo2() as i32)
    }

    /// Human-readable value form: `"{<hex preview>}"`. Mirrors `FixedField10.getValueAsString()`.
    fn value_as_string_fixed10(&self) -> String {
        format!("{{{}}}", format_hex_preview(&self.binary_data_fixed10()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::binary_field::BinaryField;
    use super::super::buffer::DataBuffer;

    struct MockFixedField10 {
        hi8: i64,
        lo2: i16,
        fixed_null: bool,
        immutable: bool,
        cached_data: Vec<u8>,
    }

    impl MockFixedField10 {
        fn new(hi8: i64, lo2: i16) -> Self {
            let mut f = Self { hi8, lo2, fixed_null: false, immutable: false, cached_data: Vec::new() };
            f.cached_data = f.binary_data_fixed10();
            f
        }

        fn zero() -> Self {
            Self::new(0, 0)
        }

        fn immutable(hi8: i64, lo2: i16) -> Self {
            let mut f = Self::new(hi8, lo2);
            f.immutable = true;
            f
        }

        /// Mirrors the `FixedField10(byte[] data)` constructor: a `None`/null `data` argument
        /// means a zero value that does *not* affect the null-state -- see the doc comment on
        /// [`FixedField`]'s `set_fixed_null` and the quirk test below.
        fn from_data_ctor(data: Option<[u8; 10]>) -> Self {
            match data {
                None => Self::zero(),
                Some(d) => {
                    let mut f = Self::zero();
                    BinaryField::set_binary_data(&mut f, Some(&d)).unwrap();
                    f
                }
            }
        }

        fn sync_cache(&mut self) {
            self.cached_data = self.binary_data_fixed10();
        }
    }

    impl BinaryField for MockFixedField10 {
        fn get_binary_data(&self) -> Option<&[u8]> {
            Some(&self.cached_data)
        }

        fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
            self.set_binary_data_fixed10(data)?;
            self.sync_cache();
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn BinaryField> {
            let mut copy = MockFixedField10::new(self.hi8, self.lo2);
            copy.fixed_null = self.fixed_null;
            copy.sync_cache();
            Box::new(copy)
        }

        fn new_field(&self) -> Box<dyn BinaryField> {
            Box::new(MockFixedField10::zero())
        }
    }

    impl FixedField for MockFixedField10 {
        fn is_fixed_null(&self) -> bool {
            self.fixed_null
        }

        fn set_fixed_null(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.fixed_null = true;
            Ok(())
        }

        fn updating_value(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.fixed_null = false;
            Ok(())
        }

        fn copy_fixed_field(&self) -> Box<dyn FixedField> {
            let mut copy = MockFixedField10::new(self.hi8, self.lo2);
            copy.fixed_null = self.fixed_null;
            copy.sync_cache();
            Box::new(copy)
        }

        fn new_fixed_field(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField10::zero())
        }

        fn get_fixed_min_value(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField10::immutable(0, 0))
        }

        fn get_fixed_max_value(&self) -> Box<dyn FixedField> {
            Box::new(MockFixedField10::immutable(-1, -1))
        }
    }

    impl FixedField10 for MockFixedField10 {
        fn get_hi8(&self) -> i64 {
            self.hi8
        }

        fn get_lo2(&self) -> i16 {
            self.lo2
        }

        fn set_raw_fixed10(&mut self, hi8: i64, lo2: i16) {
            self.hi8 = hi8;
            self.lo2 = lo2;
            self.sync_cache();
        }

        fn new_fixed10(&self) -> Box<dyn FixedField10> {
            Box::new(MockFixedField10::zero())
        }

        fn min_value_fixed10(&self) -> Box<dyn FixedField10> {
            Box::new(MockFixedField10::immutable(0, 0))
        }

        fn max_value_fixed10(&self) -> Box<dyn FixedField10> {
            Box::new(MockFixedField10::immutable(-1, -1))
        }
    }

    #[test]
    fn test_length_and_field_type_always_10() {
        let f: Box<dyn FixedField10> = Box::new(MockFixedField10::zero());
        assert_eq!(f.length_fixed10(), 10);
        assert_eq!(f.field_type_fixed10(), FieldType::Fixed(10));
        assert!(!f.is_fixed_variable_length());
    }

    #[test]
    fn test_write_read_round_trip_no_length_prefix() {
        let original: Box<dyn FixedField10> = Box::new(MockFixedField10::new(0x0102030405060708, 0x090A));
        let mut buf = DataBuffer::new(0, 10);
        let end = original.write_fixed10(&mut buf, 0);
        // Exactly 10 bytes written -- no 4-byte length prefix, unlike BinaryField's default.
        assert_eq!(end, 10);

        let mut decoded = MockFixedField10::zero();
        let next = decoded.read_fixed10(&buf, 0).unwrap();
        assert_eq!(next, 10);
        assert_eq!(decoded.get_hi8(), 0x0102030405060708);
        assert_eq!(decoded.get_lo2(), 0x090A);
        assert!(original.fields_equal_fixed10(&decoded));
    }

    #[test]
    fn test_compare_to_fixed10_matches_lexicographic_byte_order() {
        // hi8 = -1 (all bits set) is a *larger* unsigned value than hi8 = 1, even though it is
        // the smaller value when compared as signed i64.
        let big_unsigned: Box<dyn FixedField10> = Box::new(MockFixedField10::new(-1, 0));
        let small_unsigned: Box<dyn FixedField10> = Box::new(MockFixedField10::new(1, 0));
        assert_eq!(big_unsigned.compare_to_fixed10(small_unsigned.as_ref()), Ordering::Greater);

        // Cross-check against a plain lexicographic byte comparison of the two 10-byte values,
        // which the doc comment claims is mathematically equivalent.
        let a_bytes = big_unsigned.binary_data_fixed10();
        let b_bytes = small_unsigned.binary_data_fixed10();
        assert_eq!(a_bytes.cmp(&b_bytes), Ordering::Greater);
    }

    #[test]
    fn test_compare_buffer_fixed10_matches_compare_to_fixed10() {
        let field: Box<dyn FixedField10> = Box::new(MockFixedField10::new(-5, 7));
        let other: Box<dyn FixedField10> = Box::new(MockFixedField10::new(-5, 7));
        let mut buf = DataBuffer::new(0, 10);
        other.write_fixed10(&mut buf, 0);

        assert_eq!(field.compare_buffer_fixed10(&buf, 0), Ordering::Equal);
        assert_eq!(field.compare_to_fixed10(other.as_ref()), Ordering::Equal);
    }

    /// Demonstrates the sign-extension quirk documented on this trait: `hashCode()` promotes
    /// `lo2` (a signed Java `short`) to `int` with sign extension, even though every comparison
    /// method in this same class treats `lo2` as unsigned. With `hi8 = 0` and `lo2 = -1` (bit
    /// pattern `0xFFFF`, i.e. unsigned value 65535), Java computes:
    /// `result = (int)(0 ^ 0) = 0; result = 31*0 + (-1) = -1`. An "unsigned-consistent" hash
    /// would instead add 65535, giving 65535 -- not -1. This is a real quirk of the actual Java
    /// source (`FixedField10.hashCode()`), faithfully reproduced rather than "fixed".
    #[test]
    fn test_hash_code_sign_extends_lo2_unlike_unsigned_compare() {
        let field: Box<dyn FixedField10> = Box::new(MockFixedField10::new(0, -1));
        assert_eq!(field.field_hash_fixed10(), -1);
    }

    #[test]
    fn test_copy_fixed10_preserves_value_and_null_state() {
        let original: Box<dyn FixedField10> = Box::new(MockFixedField10::new(42, 7));
        let copy = original.copy_fixed10();
        assert!(original.fields_equal_fixed10(copy.as_ref()));
        assert!(!copy.is_fixed_null());

        let mut null_field = MockFixedField10::new(1, 2);
        null_field.set_fixed_null().unwrap();
        let null_copy = FixedField10::copy_fixed10(&null_field);
        assert!(null_copy.is_fixed_null());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn FixedField10> = Box::new(MockFixedField10::zero());
        let min = field.min_value_fixed10();
        let max = field.max_value_fixed10();
        assert_eq!(min.get_hi8(), 0);
        assert_eq!(min.get_lo2(), 0);
        assert_eq!(max.get_hi8(), -1);
        assert_eq!(max.get_lo2(), -1);
        assert_eq!(min.compare_to_fixed10(max.as_ref()), Ordering::Less);
    }

    #[test]
    fn test_set_binary_data_wrong_length_rejected() {
        let mut field = MockFixedField10::zero();
        assert!(BinaryField::set_binary_data(&mut field, Some(&[1, 2, 3])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null_and_zeroes_value() {
        let mut field = MockFixedField10::new(99, 1);
        BinaryField::set_binary_data(&mut field, None).unwrap();
        assert!(field.is_fixed_null());
        assert_eq!(field.get_hi8(), 0);
        assert_eq!(field.get_lo2(), 0);
    }

    /// Demonstrates the documented asymmetry between the `FixedField10(byte[] data)` constructor
    /// (a `null` `data` argument yields a zero value that does *not* set the null-state -- see
    /// the Java doc comment: "A null corresponds to zero value and does not affect the
    /// null-state") and calling `setBinaryData(null)` post-construction (which routes through the
    /// overridden `setNull()`, and *does* set the null-state). Both end up with the same
    /// zero-valued `hi8`/`lo2`, but only one is flagged null.
    #[test]
    fn test_constructor_null_data_vs_set_binary_data_null_quirk() {
        let ctor_null = MockFixedField10::from_data_ctor(None);
        assert!(!ctor_null.is_fixed_null());
        assert_eq!(ctor_null.get_hi8(), 0);
        assert_eq!(ctor_null.get_lo2(), 0);

        let mut via_setter = MockFixedField10::new(5, 5);
        BinaryField::set_binary_data(&mut via_setter, None).unwrap();
        assert!(via_setter.is_fixed_null());
        assert_eq!(via_setter.get_hi8(), 0);
        assert_eq!(via_setter.get_lo2(), 0);
    }

    #[test]
    fn test_value_as_string() {
        let field = MockFixedField10::new(0, 0x0102);
        let s = field.value_as_string_fixed10();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert!(s.contains("01 02"));
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field = MockFixedField10::immutable(1, 1);
        assert!(field.set_null_fixed10().is_err());
        assert!(field.read_fixed10(&DataBuffer::new(0, 10), 0).is_err());
    }
}
