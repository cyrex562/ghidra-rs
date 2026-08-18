//! Port of `ghidra.app.plugin.core.debug.service.tracermi.ValueDecoder`.
//!
//! Decodes Trace RMI wire values (`Addr`, `AddrRange`, `ObjSpec`, `ObjDesc`, `Value`, all
//! placeholders in [`seam_stubs`](crate::app::seam_stubs) for the not-yet-ported `trace-rmi.proto`
//! messages) into this crate's [`Address`]/[`AddressRange`] model. Java's default methods raise
//! `IllegalStateException` when a "required" conversion needs live trace context (supplied by
//! `TraceRmiHandler`, which is not yet ported and sits on this type's forward-reference cycle);
//! those defaults are mirrored here as panics, matching this crate's convention for unchecked
//! `IllegalStateException`s (see e.g. `RangeMapAdapter::check_writable_state`).

use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::app::seam_stubs::{Addr, AddrRange as WireAddrRange, NumericUtilities, ObjDesc, ObjSpec, Value};
use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};

/// Decodes wire-level Trace RMI values into program model types.
///
/// Corresponds to `ghidra.app.plugin.core.debug.service.tracermi.ValueDecoder`.
pub trait ValueDecoder {
    /// Corresponds to `ValueDecoder.toAddress(Addr, boolean)`.
    ///
    /// # Panics
    /// The default implementation panics if `required` is `true`, mirroring
    /// `IllegalStateException("Address requires a trace for context")`.
    fn to_address(&self, addr: &Addr, required: bool) -> Option<Address> {
        let _ = addr;
        if required {
            panic!("Address requires a trace for context");
        }
        None
    }

    /// Corresponds to `ValueDecoder.toRange(AddrRange, boolean)`.
    ///
    /// # Panics
    /// The default implementation panics if `required` is `true`, mirroring
    /// `IllegalStateException("AddressRange requires a trace for context")`.
    fn to_range(&self, range: &WireAddrRange, required: bool) -> Option<AddressRange> {
        let _ = range;
        if required {
            panic!("AddressRange requires a trace for context");
        }
        None
    }

    /// Corresponds to `ValueDecoder.getObject(ObjSpec, boolean)`. Named `_by_spec` since Rust
    /// traits cannot overload on parameter type the way Java's `getObject` does.
    ///
    /// # Panics
    /// The default implementation panics if `required` is `true`, mirroring
    /// `IllegalStateException("TraceObject requires a trace for context")`.
    fn get_object_by_spec(&self, spec: &ObjSpec, required: bool) -> Option<Box<dyn Any>> {
        let _ = spec;
        if required {
            panic!("TraceObject requires a trace for context");
        }
        None
    }

    /// Corresponds to `ValueDecoder.getObject(ObjDesc, boolean)`. Named `_by_desc` since Rust
    /// traits cannot overload on parameter type the way Java's `getObject` does.
    ///
    /// # Panics
    /// The default implementation panics if `required` is `true`, mirroring
    /// `IllegalStateException("TraceObject requires a trace for context")`.
    fn get_object_by_desc(&self, desc: &ObjDesc, required: bool) -> Option<Box<dyn Any>> {
        let _ = desc;
        if required {
            panic!("TraceObject requires a trace for context");
        }
        None
    }

    /// Corresponds to `ValueDecoder.toValue(Value)`.
    ///
    /// # Panics
    /// Panics on an unset `oneof` (mirrors Java's `default -> throw new AssertionError(...)`),
    /// or if a nested `required` conversion panics (see [`to_address`](Self::to_address),
    /// [`to_range`](Self::to_range)).
    fn to_value(&self, value: &Value) -> Option<Box<dyn Any>> {
        match value {
            Value::NotSet => panic!("Unrecognized value: not set"),
            Value::NullValue => None,
            Value::BoolValue(b) => Some(Box::new(*b)),
            Value::ByteValue(b) => Some(Box::new(*b)),
            Value::CharValue(c) => Some(Box::new(*c)),
            Value::ShortValue(s) => Some(Box::new(*s)),
            Value::IntValue(i) => Some(Box::new(*i)),
            Value::LongValue(l) => Some(Box::new(*l)),
            Value::StringValue(s) => Some(Box::new(s.clone())),
            Value::BoolArrValue(v) => Some(Box::new(v.clone())),
            Value::BytesValue(v) => Some(Box::new(v.clone())),
            Value::CharArrValue(s) => Some(Box::new(s.clone())),
            Value::ShortArrValue(v) => Some(Box::new(v.clone())),
            Value::IntArrValue(v) => Some(Box::new(v.clone())),
            Value::LongArrValue(v) => Some(Box::new(v.clone())),
            Value::StringArrValue(v) => Some(Box::new(v.clone())),
            Value::AddressValue(addr) => {
                Some(Box::new(self.to_address(addr, true).expect(
                    "to_address(_, required=true) must return Some or panic",
                )))
            }
            Value::RangeValue(range) => Some(Box::new(self.to_range(range, true).expect(
                "to_range(_, required=true) must return Some or panic",
            ))),
            Value::ChildSpec(spec) => self.get_object_by_spec(spec, true),
            Value::ChildDesc(desc) => self.get_object_by_desc(desc, true),
        }
    }
}

/// The default decoder: every conversion that needs trace context returns `None` (or panics if
/// `required`), matching `ValueDecoder.DEFAULT`.
///
/// Corresponds to the anonymous `ValueDecoder.DEFAULT` instance.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultValueDecoder;

impl ValueDecoder for DefaultValueDecoder {}

/// A decoder that renders values for display without any trace context, fabricating a
/// throwaway [`AddressSpace`] per space name and describing objects/child references as
/// placeholder strings instead of resolving them.
///
/// Corresponds to the anonymous `ValueDecoder.DISPLAY` instance.
#[derive(Debug, Default)]
pub struct DisplayValueDecoder {
    spaces: Mutex<HashMap<String, std::sync::Arc<AddressSpace>>>,
}

impl DisplayValueDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Corresponds to the private `DISPLAY.getSpace(String)` helper: returns the cached RAM
    /// address space for `space`, creating a 64-bit one on first use.
    fn get_space(&self, space: &str) -> std::sync::Arc<AddressSpace> {
        let mut spaces = self.spaces.lock().unwrap();
        spaces
            .entry(space.to_string())
            .or_insert_with(|| AddressSpace::new(space, 64, 1, AddressSpaceType::Ram, 0))
            .clone()
    }
}

impl ValueDecoder for DisplayValueDecoder {
    fn to_address(&self, addr: &Addr, _required: bool) -> Option<Address> {
        let space = self.get_space(&addr.space);
        Some(space.address(addr.offset as i64))
    }

    fn to_range(&self, range: &WireAddrRange, _required: bool) -> Option<AddressRange> {
        let space = self.get_space(&range.space);
        let min = space.address(range.offset as i64);
        let max = space.address((range.offset + range.extend) as i64);
        Some(AddressRange::new(min, max))
    }

    fn get_object_by_desc(&self, desc: &ObjDesc, _required: bool) -> Option<Box<dyn Any>> {
        Some(Box::new(format!(
            "<Object id={} path={}>",
            desc.id, desc.path
        )))
    }

    fn get_object_by_spec(&self, spec: &ObjSpec, _required: bool) -> Option<Box<dyn Any>> {
        let rendered = match spec {
            ObjSpec::NotSet => "<ERROR: No key>".to_string(),
            ObjSpec::Id(id) => format!("<Object id={id}>"),
            ObjSpec::Path(path) => format!("<Object path={path}>"),
        };
        Some(Box::new(rendered))
    }

    fn to_value(&self, value: &Value) -> Option<Box<dyn Any>> {
        let obj = ValueDecoder::to_value(&DefaultValueDecoderShim(self), value);
        if let Some(bytes) = obj.as_ref().and_then(|o| o.downcast_ref::<Vec<u8>>()) {
            return Some(Box::new(NumericUtilities::convert_bytes_to_string(bytes, ":")));
        }
        obj
    }
}

/// Delegates the default-trait-method dispatch that `DisplayValueDecoder::to_value` needs
/// (`ValueDecoder.super.toValue(value)` in Java) back through the wrapped decoder's own
/// overrides, since Rust has no `super` call for default trait methods.
struct DefaultValueDecoderShim<'a>(&'a DisplayValueDecoder);

impl ValueDecoder for DefaultValueDecoderShim<'_> {
    fn to_address(&self, addr: &Addr, required: bool) -> Option<Address> {
        self.0.to_address(addr, required)
    }

    fn to_range(&self, range: &WireAddrRange, required: bool) -> Option<AddressRange> {
        self.0.to_range(range, required)
    }

    fn get_object_by_spec(&self, spec: &ObjSpec, required: bool) -> Option<Box<dyn Any>> {
        self.0.get_object_by_spec(spec, required)
    }

    fn get_object_by_desc(&self, desc: &ObjDesc, required: bool) -> Option<Box<dyn Any>> {
        self.0.get_object_by_desc(desc, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_decoder_to_address_not_required_returns_none() {
        let addr = Addr { space: "ram".to_string(), offset: 0x1000 };
        assert!(DefaultValueDecoder.to_address(&addr, false).is_none());
    }

    #[test]
    #[should_panic(expected = "Address requires a trace for context")]
    fn default_decoder_to_address_required_panics() {
        let addr = Addr { space: "ram".to_string(), offset: 0x1000 };
        DefaultValueDecoder.to_address(&addr, true);
    }

    #[test]
    fn default_decoder_to_value_primitives_match_java_switch() {
        let d = DefaultValueDecoder;
        assert!(ValueDecoder::to_value(&d, &Value::NullValue).is_none());
        assert_eq!(
            *ValueDecoder::to_value(&d, &Value::IntValue(42))
                .unwrap()
                .downcast::<i32>()
                .unwrap(),
            42
        );
        assert_eq!(
            *ValueDecoder::to_value(&d, &Value::StringValue("hi".to_string()))
                .unwrap()
                .downcast::<String>()
                .unwrap(),
            "hi".to_string()
        );
    }

    #[test]
    fn display_decoder_to_address_resolves_offset_in_named_space() {
        let d = DisplayValueDecoder::new();
        let addr = Addr { space: "ram".to_string(), offset: 0x1000 };
        let resolved = d.to_address(&addr, false).unwrap();
        assert_eq!(resolved.offset(), 0x1000);
        assert_eq!(resolved.space().name(), "ram");
    }

    #[test]
    fn display_decoder_caches_space_by_name() {
        let d = DisplayValueDecoder::new();
        let a1 = d.to_address(&Addr { space: "ram".to_string(), offset: 0 }, false).unwrap();
        let a2 = d.to_address(&Addr { space: "ram".to_string(), offset: 4 }, false).unwrap();
        assert!(a1.same_address_space(&a2));
    }

    #[test]
    fn display_decoder_to_range_uses_offset_plus_extend_as_max() {
        let d = DisplayValueDecoder::new();
        let range = WireAddrRange { space: "ram".to_string(), offset: 0x100, extend: 0x10 };
        let resolved = d.to_range(&range, false).unwrap();
        assert_eq!(resolved.min_address().offset(), 0x100);
        assert_eq!(resolved.max_address().offset(), 0x110);
    }

    #[test]
    fn display_decoder_get_object_by_desc_formats_id_and_path() {
        let d = DisplayValueDecoder::new();
        let desc = ObjDesc { id: 7, path: "Processes[0]".to_string() };
        let obj = d.get_object_by_desc(&desc, false).unwrap();
        assert_eq!(
            *obj.downcast::<String>().unwrap(),
            "<Object id=7 path=Processes[0]>".to_string()
        );
    }

    #[test]
    fn display_decoder_get_object_by_spec_covers_all_key_cases() {
        let d = DisplayValueDecoder::new();
        assert_eq!(
            *d.get_object_by_spec(&ObjSpec::NotSet, false)
                .unwrap()
                .downcast::<String>()
                .unwrap(),
            "<ERROR: No key>".to_string()
        );
        assert_eq!(
            *d.get_object_by_spec(&ObjSpec::Id(5), false)
                .unwrap()
                .downcast::<String>()
                .unwrap(),
            "<Object id=5>".to_string()
        );
        assert_eq!(
            *d.get_object_by_spec(&ObjSpec::Path("Threads[1]".to_string()), false)
                .unwrap()
                .downcast::<String>()
                .unwrap(),
            "<Object path=Threads[1]>".to_string()
        );
    }

    /// Java: `NumericUtilities.convertBytesToString(byte[]{0xDE,0xAD,0xBE,0xEF}, ":")` ==
    /// `"de:ad:be:ef"`.
    #[test]
    fn display_decoder_to_value_renders_bytes_as_colon_separated_hex() {
        let d = DisplayValueDecoder::new();
        let value = Value::BytesValue(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let obj = d.to_value(&value).unwrap();
        assert_eq!(
            *obj.downcast::<String>().unwrap(),
            "de:ad:be:ef".to_string()
        );
    }

    #[test]
    fn display_decoder_to_value_non_bytes_passes_through_default_conversion() {
        let d = DisplayValueDecoder::new();
        let obj = d.to_value(&Value::IntValue(7)).unwrap();
        assert_eq!(*obj.downcast::<i32>().unwrap(), 7);
    }
}
