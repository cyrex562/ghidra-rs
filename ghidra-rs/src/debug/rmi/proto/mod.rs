//! Generated protobuf messages for the Trace RMI protocol (`trace-rmi.proto`, package
//! `ghidra.rmi.trace`).
//!
//! Java equivalent: the `protoc`-generated outer class `ghidra.rmi.trace.TraceRmi`. Each Java
//! nested message class (`TraceRmi.RootMessage`, `TraceRmi.Value`, ...) is a `prost` struct of
//! the same name here; each `oneof` is a Rust enum in a snake_case submodule named after its
//! message (e.g. `Value.getValueCase()` is a match on [`value::Value`], and
//! `RootMessage.getMsgCase()` a match on [`root_message::Msg`]). Protobuf enums
//! ([`Resolution`], [`ValueKinds`], [`MemoryState`]) are `i32`-backed Rust enums, stored in
//! messages as `i32` per `prost` convention.
//!
//! The code in `ghidra.rmi.trace.rs` is **generated** and checked in, so building this crate
//! needs neither `protoc` nor a build script. Do not edit it by hand. To regenerate after
//! changing the `.proto`, run from the repository root:
//!
//! ```text
//! scripts/protogen/regen.sh
//! ```
//!
//! That compiles the `.proto` with `protox` (a pure-Rust protobuf compiler) and feeds the result
//! to `prost-build`, writing `ghidra.rmi.trace.rs` into this directory.

#![allow(clippy::all, missing_docs)]

include!("ghidra.rmi.trace.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// The generated code must produce the standard protobuf wire format that Java's
    /// `RootMessage.writeTo` emits and `RootMessage.parseFrom` accepts. Expected bytes are the
    /// hand-computed encoding of `RootMessage{request_start_tx{oid{id:1}, undoable:true,
    /// description:"x", txid{id:2}}}`: field 10 as a length-delimited record (tag `0x52`) whose
    /// body carries fields 1-4 in declaration order.
    #[test]
    fn start_tx_encodes_to_standard_wire_format() {
        let msg = RootMessage {
            msg: Some(root_message::Msg::RequestStartTx(RequestStartTx {
                oid: Some(DomObjId { id: 1 }),
                undoable: true,
                description: "x".to_string(),
                txid: Some(TxId { id: 2 }),
            })),
        };
        let bytes = msg.encode_to_vec();
        assert_eq!(
            bytes,
            vec![
                0x52, 0x0d, 0x0a, 0x02, 0x08, 0x01, 0x10, 0x01, 0x1a, 0x01, 0x78, 0x22, 0x02,
                0x08, 0x02
            ]
        );
        assert_eq!(RootMessage::decode(bytes.as_slice()).unwrap(), msg);
    }

    #[test]
    fn value_oneof_round_trips_every_nested_message_kind() {
        let values = vec![
            value::Value::NullValue(Null {}),
            value::Value::CharValue(0x41),
            value::Value::ShortArrValue(ShortArr { arr: vec![-1, 2] }),
            value::Value::StringArrValue(StringArr { arr: vec!["a".into(), "b".into()] }),
            value::Value::AddressValue(Addr { space: "ram".into(), offset: 0xdead_beef }),
            value::Value::RangeValue(AddrRange { space: "ram".into(), offset: 0x100, extend: 0xf }),
            value::Value::ChildSpec(ObjSpec {
                key: Some(obj_spec::Key::Path(ObjPath { path: "Processes[1]".into() })),
            }),
            value::Value::ChildDesc(ObjDesc {
                id: 7,
                path: Some(ObjPath { path: "Processes[1].Threads[2]".into() }),
            }),
        ];
        for v in values {
            let msg = Value { value: Some(v) };
            let decoded = Value::decode(msg.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    /// Protobuf enums are carried as `i32` on the wire; the Java constants' numbers are fixed by
    /// the `.proto` (`CR_ADJUST = 2`, `VK_BOTH = 2`, `MS_ERROR = 2`).
    #[test]
    fn enums_keep_proto_numbers_and_names() {
        assert_eq!(Resolution::CrAdjust as i32, 2);
        assert_eq!(Resolution::CrTruncate.as_str_name(), "CR_TRUNCATE");
        assert_eq!(ValueKinds::from_str_name("VK_ATTRIBUTES"), Some(ValueKinds::VkAttributes));
        assert_eq!(MemoryState::try_from(2), Ok(MemoryState::MsError));
    }

    /// `XRequestInvokeMethod.oid` is `optional` in the `.proto`; absence must survive a trip.
    #[test]
    fn optional_oid_absence_round_trips() {
        let req = XRequestInvokeMethod { oid: None, name: "refresh".into(), arguments: vec![] };
        let decoded = XRequestInvokeMethod::decode(req.encode_to_vec().as_slice()).unwrap();
        assert!(decoded.oid.is_none());
        assert_eq!(decoded.name, "refresh");
    }
}
