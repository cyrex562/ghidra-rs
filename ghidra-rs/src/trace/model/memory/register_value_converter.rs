//! Port of `ghidra.trace.model.memory.RegisterValueConverter`.
//!
//! Converts a raw [`TraceObjectValue`] (whatever primitive/`byte[]`/`Address` a debug-target
//! object reported for a register) into a numeric value and, from there, into big- or
//! little-endian bytes -- lazily and memoized, exactly like the Java class.
//!
//! # `BigInteger` -> `i128`
//!
//! Java's arbitrary-precision `BigInteger` is modeled as `i128` here, matching the convention
//! already established by [`crate::pcode::utils::utils::bytes_to_big_integer`]/
//! [`big_integer_to_bytes`](crate::pcode::utils::utils::big_integer_to_bytes) (which this port
//! reuses directly). `i128` comfortably covers every real register width Ghidra models (up to
//! 128-bit vector registers); values that would need Java's true unbounded precision are out of
//! scope for this crate's `BigInteger` substitute in general, not just for this class.
//!
//! # Untyped error messages
//!
//! Java's `"Cannot convert register value: (" + val.getClass() + ") '" + val + "'"` needs a
//! Java-style class name and a `toString()` of an arbitrary boxed value. [`dyn Any`] exposes
//! neither, so [`convert_value_to_big_integer`]'s error message for the unsupported-type case is
//! a fixed string instead of Java's fully-interpolated one; every other error message matches
//! Java exactly.

use std::any::Any;

use crate::pcode::utils::utils::{big_integer_to_bytes, bytes_to_big_integer};
use crate::program::model::address::Address;
use crate::trace::model::memory::register_value_exception::RegisterValueException;
use crate::trace::model::memory::trace_register::KEY_BITLENGTH;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Port of `ghidra.trace.model.memory.RegisterValueConverter`.
pub struct RegisterValueConverter {
    register_value: Box<dyn TraceObjectValue>,
    value: Option<i128>,
    bit_length: i32,
    be: Option<Vec<u8>>,
    le: Option<Vec<u8>>,
}

impl RegisterValueConverter {
    /// `RegisterValueConverter(TraceObjectValue)`.
    pub fn new(register_value: Box<dyn TraceObjectValue>) -> Self {
        Self { register_value, value: None, bit_length: -1, be: None, le: None }
    }

    /// `RegisterValueConverter.convertValueToBigInteger(Object)`.
    pub fn convert_value_to_big_integer(val: &dyn Any) -> Result<i128, RegisterValueException> {
        if let Some(s) = val.downcast_ref::<String>() {
            return i128::from_str_radix(s, 16).map_err(|_| {
                RegisterValueException::new(format!(
                    "Invalid register value {s}. Must be hex digits only."
                ))
            });
        }
        if let Some(bytes) = val.downcast_ref::<Vec<u8>>() {
            // NOTE: Reg object values are always big endian, and Java's `new BigInteger(1, arr)`
            // always treats them as non-negative regardless of the high bit -- see the
            // `byte_array_is_always_unsigned_big_endian` test below.
            return Ok(bytes_to_big_integer(bytes, bytes.len(), true, false));
        }
        if let Some(b) = val.downcast_ref::<i8>() {
            return Ok(*b as i128);
        }
        if let Some(s) = val.downcast_ref::<i16>() {
            return Ok(*s as i128);
        }
        if let Some(i) = val.downcast_ref::<i32>() {
            return Ok(*i as i128);
        }
        if let Some(l) = val.downcast_ref::<i64>() {
            return Ok(*l as i128);
        }
        if let Some(a) = val.downcast_ref::<Address>() {
            return Ok(a.offset() as i128);
        }
        Err(RegisterValueException::new(
            "Cannot convert register value: unsupported value type",
        ))
    }

    /// `RegisterValueConverter.convertRegisterValueToBigInteger()`.
    fn convert_register_value_to_big_integer(&self) -> Result<i128, RegisterValueException> {
        Self::convert_value_to_big_integer(self.register_value.get_value().as_ref())
    }

    /// `RegisterValueConverter.getRegisterValueBitLength()`.
    ///
    /// # Panics
    /// Panics if the register value has no parent, or if its parent has no `_length` value --
    /// mirroring the `NullPointerException` Java raises calling `getParent()`/`.getValue(...)`
    /// on a `null` in `registerValue.getParent().getValue(minSnap, KEY_BITLENGTH)`.
    fn get_register_value_bit_length(&self) -> Result<i32, RegisterValueException> {
        let parent = self.register_value.get_parent().expect(
            "RegisterValueConverter: register value has no parent (mirrors Java NullPointerException)",
        );
        let snap = self.register_value.get_min_snap();
        let bit_length_value = parent.get_value(snap, KEY_BITLENGTH).expect(
            "RegisterValueConverter: parent has no _length value (mirrors Java NullPointerException)",
        );
        let obj_bit_length = bit_length_value.get_value();
        if let Some(b) = obj_bit_length.downcast_ref::<i8>() {
            return Ok(*b as i32);
        }
        if let Some(s) = obj_bit_length.downcast_ref::<i16>() {
            return Ok(*s as i32);
        }
        if let Some(i) = obj_bit_length.downcast_ref::<i32>() {
            return Ok(*i);
        }
        if let Some(l) = obj_bit_length.downcast_ref::<i64>() {
            return Ok(*l as i32);
        }
        Err(RegisterValueException::new("Register length is not numeric"))
    }

    /// `RegisterValueConverter.getValue()`. Memoized after the first successful call.
    pub fn get_value(&mut self) -> Result<i128, RegisterValueException> {
        if let Some(v) = self.value {
            return Ok(v);
        }
        let v = self.convert_register_value_to_big_integer()?;
        self.value = Some(v);
        Ok(v)
    }

    /// `RegisterValueConverter.getBitLength()`. Memoized after the first successful call.
    fn get_bit_length(&mut self) -> Result<i32, RegisterValueException> {
        if self.bit_length != -1 {
            return Ok(self.bit_length);
        }
        let bl = self.get_register_value_bit_length()?;
        self.bit_length = bl;
        Ok(bl)
    }

    /// `RegisterValueConverter.getByteLength()`.
    fn get_byte_length(&mut self) -> Result<i32, RegisterValueException> {
        Ok((self.get_bit_length()? + 7) / 8)
    }

    /// `RegisterValueConverter.getBytesBigEndian()`. Memoized after the first successful call.
    pub fn get_bytes_big_endian(&mut self) -> Result<Vec<u8>, RegisterValueException> {
        if let Some(be) = &self.be {
            return Ok(be.clone());
        }
        let value = self.get_value()?;
        let len = self.get_byte_length()? as usize;
        let bytes = big_integer_to_bytes(value, len, true);
        self.be = Some(bytes.clone());
        Ok(bytes)
    }

    /// `RegisterValueConverter.getBytesLittleEndian()`. Memoized after the first successful call.
    pub fn get_bytes_little_endian(&mut self) -> Result<Vec<u8>, RegisterValueException> {
        if let Some(le) = &self.le {
            return Ok(le.clone());
        }
        let value = self.get_value()?;
        let len = self.get_byte_length()? as usize;
        let bytes = big_integer_to_bytes(value, len, false);
        self.le = Some(bytes.clone());
        Ok(bytes)
    }

    /// `RegisterValueConverter.getBytes(boolean)`.
    pub fn get_bytes(&mut self, is_big_endian: bool) -> Result<Vec<u8>, RegisterValueException> {
        if is_big_endian {
            self.get_bytes_big_endian()
        } else {
            self.get_bytes_little_endian()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
    use crate::trace::model::target::path::key_path::KeyPath;
    use crate::trace::model::target::trace_object::{ConflictResolution, TraceObject};
    use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
    use crate::trace::model::target::trace_object_value::TruncateOrDelete;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    // ---- convert_value_to_big_integer: no TraceObjectValue needed at all ----

    #[test]
    fn converts_hex_string() {
        let val: Box<dyn Any> = Box::new("1234".to_string());
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(val.as_ref()).unwrap(), 0x1234);
    }

    #[test]
    fn rejects_non_hex_string() {
        let val: Box<dyn Any> = Box::new("zzzz".to_string());
        let err = RegisterValueConverter::convert_value_to_big_integer(val.as_ref()).unwrap_err();
        assert!(err.message().contains("Must be hex digits only"));
    }

    #[test]
    fn byte_array_is_always_unsigned_big_endian() {
        // Java: `new BigInteger(1, arr)` -- the `1` signum forces the result non-negative no
        // matter the byte pattern, even though the high bit is set here. If this were signed
        // big-endian interpretation instead, [0xFF, 0xFF] would be -1, not 65535.
        let val: Box<dyn Any> = Box::new(vec![0xFFu8, 0xFF]);
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(val.as_ref()).unwrap(), 65535);
    }

    #[test]
    fn converts_numeric_boxed_types() {
        let b: Box<dyn Any> = Box::new(-5i8);
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(b.as_ref()).unwrap(), -5);
        let s: Box<dyn Any> = Box::new(1000i16);
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(s.as_ref()).unwrap(), 1000);
        let i: Box<dyn Any> = Box::new(-70000i32);
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(i.as_ref()).unwrap(), -70000);
        let l: Box<dyn Any> = Box::new(9_000_000_000i64);
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(l.as_ref()).unwrap(), 9_000_000_000);
    }

    #[test]
    fn converts_address_via_its_offset() {
        let addr: Box<dyn Any> = Box::new(make_address(0x4000));
        assert_eq!(RegisterValueConverter::convert_value_to_big_integer(addr.as_ref()).unwrap(), 0x4000);
    }

    #[test]
    fn rejects_unsupported_type() {
        let val: Box<dyn Any> = Box::new(true);
        assert!(RegisterValueConverter::convert_value_to_big_integer(val.as_ref()).is_err());
    }

    // ---- Full instance behavior needs a minimal TraceObject/TraceObjectValue mock. ----

    /// Clones the small set of `Any` payloads these tests actually box (mirrors what a real
    /// debug-target model would hand back on every `getValue()` call, rather than caching an
    /// owned value across calls the way a raw `Box<dyn Any>` field can't be cloned generically).
    fn clone_any(value: &(dyn Any + Send + Sync)) -> Box<dyn Any + Send + Sync> {
        if let Some(s) = value.downcast_ref::<String>() {
            return Box::new(s.clone());
        }
        if let Some(b) = value.downcast_ref::<Vec<u8>>() {
            return Box::new(b.clone());
        }
        if let Some(v) = value.downcast_ref::<i8>() {
            return Box::new(*v);
        }
        if let Some(v) = value.downcast_ref::<i16>() {
            return Box::new(*v);
        }
        if let Some(v) = value.downcast_ref::<i32>() {
            return Box::new(*v);
        }
        if let Some(v) = value.downcast_ref::<i64>() {
            return Box::new(*v);
        }
        if let Some(v) = value.downcast_ref::<Address>() {
            return Box::new(v.clone());
        }
        panic!("clone_any: unsupported test payload type");
    }

    /// A mock `TraceObject` standing in for a register's parent object, whose only job in these
    /// tests is to answer `getValue(minSnap, KEY_BITLENGTH)`.
    struct MockObject {
        bit_length_value: Box<dyn Any + Send + Sync>,
        get_value_calls: Arc<AtomicI32>,
    }

    impl MockObject {
        fn duplicate(&self) -> Self {
            Self {
                bit_length_value: clone_any(self.bit_length_value.as_ref()),
                get_value_calls: self.get_value_calls.clone(),
            }
        }
    }

    impl TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            unimplemented!("not exercised by these tests")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_key(&self) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn get_root(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by these tests")
        }
        fn get_canonical_path(&self) -> KeyPath {
            unimplemented!("not exercised by these tests")
        }
        fn get_life(&self) -> Box<dyn crate::trace::seam_stubs::LifeSet> {
            unimplemented!("not exercised by these tests")
        }
        fn is_alive(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn is_alive_span(&self, _span: Lifespan) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn insert(
            &mut self,
            _lifespan: Lifespan,
            _resolution: ConflictResolution,
        ) -> Box<dyn TraceObjectValPath> {
            unimplemented!("not exercised by these tests")
        }
        fn remove(&mut self, _span: Lifespan) {
            unimplemented!("not exercised by these tests")
        }
        fn remove_tree(&mut self, _span: Lifespan) {
            unimplemented!("not exercised by these tests")
        }
        fn get_canonical_parent(&self, _snap: i64) -> Option<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_canonical_parents(&self, _lifespan: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn is_root(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_paths(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_interfaces(
            &self,
        ) -> Vec<crate::trace::model::target::info::trace_object_info::TraceObjectInfo> {
            unimplemented!("not exercised by these tests")
        }
        fn query_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
        ) -> Option<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_parents(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_values(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_values_by_key(&self, _span: Lifespan, _key: &str) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_ordered_values(
            &self,
            _span: Lifespan,
            _key: &str,
            _forward: bool,
        ) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_elements(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_attributes(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_value(&self, _snap: i64, key: &str) -> Option<Box<dyn TraceObjectValue>> {
            assert_eq!(key, KEY_BITLENGTH);
            self.get_value_calls.fetch_add(1, Ordering::SeqCst);
            Some(Box::new(MockValue {
                value: clone_any(self.bit_length_value.as_ref()),
                parent: None,
                min_snap: 0,
                value_calls: Arc::new(AtomicI32::new(0)),
            }))
        }
        fn get_ancestors_root(
            &self,
            _span: Lifespan,
            _root_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_ancestors(
            &self,
            _span: Lifespan,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_successors(
            &self,
            _span: Lifespan,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_ordered_successors(
            &self,
            _span: Lifespan,
            _relative_path: &KeyPath,
            _forward: bool,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_canonical_successors(
            &self,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_value_with_resolution(
            &mut self,
            _lifespan: Lifespan,
            _key: &str,
            _value: Option<crate::trace::model::target::trace_object::ObjectValue>,
            _resolution: ConflictResolution,
        ) -> Result<Option<Box<dyn TraceObjectValue>>, DuplicateKeyException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_schema(&self) -> Box<dyn crate::trace::model::target::schema::trace_object_schema::TraceObjectSchema> {
            unimplemented!("not exercised by these tests")
        }
        fn find_ancestors_interface(
            &self,
            _span: Lifespan,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn query_ancestors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: Lifespan,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by these tests")
        }
        fn find_canonical_ancestors_interface(
            &self,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn TraceObject>> {
            unimplemented!("not exercised by these tests")
        }
        fn query_canonical_ancestors_interface<
            I: crate::trace::model::target::iface::TraceObjectInterface,
        >(
            &self,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by these tests")
        }
        fn find_successors_interface(
            &self,
            _span: Lifespan,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
            _require_canonical: bool,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            unimplemented!("not exercised by these tests")
        }
        fn query_successors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: Lifespan,
            _require_canonical: bool,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by these tests")
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A mock `TraceObjectValue` standing in for the register value itself (and, when nested via
    /// `parent`, for the parent's `_length` attribute value).
    struct MockValue {
        value: Box<dyn Any + Send + Sync>,
        parent: Option<MockObject>,
        min_snap: i64,
        value_calls: Arc<AtomicI32>,
    }

    impl TraceObjectValue for MockValue {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
            self.parent.as_ref().map(|p| Box::new(p.duplicate()) as Box<dyn TraceObject>)
        }
        fn get_entry_key(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_canonical_path(&self) -> KeyPath {
            unimplemented!("not exercised by these tests")
        }
        fn get_value(&self) -> Box<dyn Any + Send + Sync> {
            self.value_calls.fetch_add(1, Ordering::SeqCst);
            clone_any(self.value.as_ref())
        }
        fn get_child(&self) -> Box<dyn TraceObject> {
            panic!("value is not an object")
        }
        fn is_object(&self) -> bool {
            false
        }
        fn is_canonical(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_lifespan(&mut self, _lifespan: Lifespan) {
            unimplemented!("not exercised by these tests")
        }
        fn set_lifespan_with_resolution(
            &mut self,
            _span: Lifespan,
            _resolution: ConflictResolution,
        ) -> Result<(), DuplicateKeyException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by these tests")
        }
        fn set_min_snap(&mut self, _min_snap: i64) {
            unimplemented!("not exercised by these tests")
        }
        fn get_min_snap(&self) -> i64 {
            self.min_snap
        }
        fn set_max_snap(&mut self, _max_snap: i64) {
            unimplemented!("not exercised by these tests")
        }
        fn get_max_snap(&self) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by these tests")
        }
        fn is_deleted(&self) -> bool {
            false
        }
        fn truncate_or_delete(&mut self, _span: Lifespan) -> TruncateOrDelete {
            unimplemented!("not exercised by these tests")
        }
    }

    fn make_converter(
        payload: Box<dyn Any + Send + Sync>,
        bit_length: i32,
        get_value_calls: Arc<AtomicI32>,
    ) -> RegisterValueConverter {
        let value = MockValue {
            value: payload,
            parent: Some(MockObject { bit_length_value: Box::new(bit_length), get_value_calls }),
            min_snap: 7,
            value_calls: Arc::new(AtomicI32::new(0)),
        };
        RegisterValueConverter::new(Box::new(value))
    }

    #[test]
    fn full_round_trip_single_byte() {
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("FF".to_string()), 8, calls);
        assert_eq!(converter.get_value().unwrap(), 0xFF);
        assert_eq!(converter.get_bytes_big_endian().unwrap(), vec![0xFF]);
        assert_eq!(converter.get_bytes_little_endian().unwrap(), vec![0xFF]);
    }

    #[test]
    fn full_round_trip_two_bytes_big_vs_little_endian_differ() {
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("1234".to_string()), 16, calls);
        assert_eq!(converter.get_bytes_big_endian().unwrap(), vec![0x12, 0x34]);
        assert_eq!(converter.get_bytes_little_endian().unwrap(), vec![0x34, 0x12]);
    }

    #[test]
    fn get_bytes_dispatches_on_endianness_flag() {
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("1234".to_string()), 16, calls);
        assert_eq!(converter.get_bytes(true).unwrap(), vec![0x12, 0x34]);
        assert_eq!(converter.get_bytes(false).unwrap(), vec![0x34, 0x12]);
    }

    #[test]
    fn byte_length_rounds_up_from_bit_length() {
        // 12 bits -> ceil(12/8) = 2 bytes, exactly like TraceRegister::byte_length.
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("A".to_string()), 12, calls);
        assert_eq!(converter.get_bytes_big_endian().unwrap().len(), 2);
    }

    #[test]
    fn bit_length_is_memoized_after_first_lookup() {
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("FF".to_string()), 8, calls.clone());
        converter.get_bytes_big_endian().unwrap();
        converter.get_bytes_little_endian().unwrap();
        // Both getBytes* calls above go through get_byte_length -> get_bit_length, but the
        // underlying parent.getValue(KEY_BITLENGTH) lookup must only happen once, thanks to
        // getBitLength's `-1` sentinel memoization.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn value_is_memoized_after_first_lookup() {
        let calls = Arc::new(AtomicI32::new(0));
        let mut converter = make_converter(Box::new("2A".to_string()), 8, calls);
        let first = converter.get_value().unwrap();
        let second = converter.get_value().unwrap();
        assert_eq!(first, 0x2A);
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_non_numeric_bit_length_payload() {
        let calls = Arc::new(AtomicI32::new(0));
        let value = MockValue {
            value: Box::new("FF".to_string()),
            parent: Some(MockObject {
                bit_length_value: Box::new("not a number".to_string()),
                get_value_calls: calls,
            }),
            min_snap: 0,
            value_calls: Arc::new(AtomicI32::new(0)),
        };
        let mut converter = RegisterValueConverter::new(Box::new(value));
        let err = converter.get_bytes_big_endian().unwrap_err();
        assert!(err.message().contains("not numeric"));
    }

    #[test]
    fn panics_when_register_value_has_no_parent() {
        // Mirrors Java's NullPointerException: registerValue.getParent() is null in Java, so
        // getParent().getValue(...) would NPE immediately. get_bit_length (invoked here via
        // get_bytes_big_endian) is exactly the call that must panic -- scope catch_unwind tightly
        // around it rather than trusting a loose #[should_panic] on a multi-step test.
        let value = MockValue {
            value: Box::new("FF".to_string()),
            parent: None,
            min_snap: 0,
            value_calls: Arc::new(AtomicI32::new(0)),
        };
        let mut converter = RegisterValueConverter::new(Box::new(value));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| converter.get_bytes_big_endian()));
        assert!(result.is_err());
    }
}
