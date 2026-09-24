//! Generated protobuf messages for the ISF protocol (`isf.proto`, package
//! `ghidra.dbg.isf.protocol`).
//!
//! Java equivalent: the `protoc`-generated outer class `ghidra.dbg.isf.protocol.Isf`. Each Java
//! nested message class is a `prost` struct of the same name here; each `oneof` is a Rust enum
//! in a snake_case submodule named after its message.
//!
//! The code in `ghidra.dbg.isf.protocol.rs` is **generated** and checked in, so building this
//! crate needs neither `protoc` nor a build script. Do not edit it by hand. To regenerate after
//! changing the `.proto`, run from the repository root:
//!
//! ```text
//! scripts/protogen/regen.sh
//! ```

#![allow(clippy::all, missing_docs)]

include!("ghidra.dbg.isf.protocol.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn ping_round_trips_through_root_message() {
        let msg = RootMessage {
            sequence: 42,
            msg: Some(root_message::Msg::PingRequest(PingRequest { content: "hi".into() })),
        };
        let decoded = RootMessage::decode(msg.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn error_code_numbers_match_proto() {
        assert_eq!(ErrorCode::EcBadRequest as i32, 1);
        assert_eq!(ErrorCode::EcNotSupported.as_str_name(), "EC_NOT_SUPPORTED");
    }
}
