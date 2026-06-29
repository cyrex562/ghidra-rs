/// Method handle type code constants for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.MethodHandleType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodHandleType;

impl MethodHandleType {
    /// A setter for a given static field.
    pub const K_STATIC_PUT: i16 = 0x0000;
    /// A getter for a given static field.
    pub const K_STATIC_GET: i16 = 0x0001;
    /// A setter for a given instance field.
    pub const K_INSTANCE_PUT: i16 = 0x0002;
    /// A getter for a given instance field.
    pub const K_INSTANCE_GET: i16 = 0x0003;
    /// An invoker for a given static method.
    pub const K_INVOKE_STATIC: i16 = 0x0004;
    /// An invoker for a given instance method (any non-static method except `<init>`).
    pub const K_INVOKE_INSTANCE: i16 = 0x0005;
    /// An invoker for a given constructor.
    pub const K_INVOKE_CONSTRUCTOR: i16 = 0x0006;
    /// An invoker for a direct (special) method.
    pub const K_INVOKE_DIRECT: i16 = 0x0007;
    /// An invoker for an interface method.
    pub const K_INVOKE_INTERFACE: i16 = 0x0008;
    pub const K_LAST: i16 = Self::K_INVOKE_INTERFACE;

    /// Returns the field name for the given type code, or `"MethodHandleType:<type>"` if unknown.
    ///
    /// Replicates the reflection-based `toString(short)` from the Java source, preserving
    /// declaration order.
    pub fn to_string(type_: i16) -> String {
        const TYPES: &[(&str, i16)] = &[
            ("kStaticPut", MethodHandleType::K_STATIC_PUT),
            ("kStaticGet", MethodHandleType::K_STATIC_GET),
            ("kInstancePut", MethodHandleType::K_INSTANCE_PUT),
            ("kInstanceGet", MethodHandleType::K_INSTANCE_GET),
            ("kInvokeStatic", MethodHandleType::K_INVOKE_STATIC),
            ("kInvokeInstance", MethodHandleType::K_INVOKE_INSTANCE),
            ("kInvokeConstructor", MethodHandleType::K_INVOKE_CONSTRUCTOR),
            ("kInvokeDirect", MethodHandleType::K_INVOKE_DIRECT),
            ("kInvokeInterface", MethodHandleType::K_INVOKE_INTERFACE),
            ("kLast", MethodHandleType::K_LAST),
        ];
        for &(name, value) in TYPES {
            if value == type_ {
                return name.to_string();
            }
        }
        format!("MethodHandleType:{}", type_)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(MethodHandleType::K_STATIC_PUT, 0x0000);
        assert_eq!(MethodHandleType::K_STATIC_GET, 0x0001);
        assert_eq!(MethodHandleType::K_INSTANCE_PUT, 0x0002);
        assert_eq!(MethodHandleType::K_INSTANCE_GET, 0x0003);
        assert_eq!(MethodHandleType::K_INVOKE_STATIC, 0x0004);
        assert_eq!(MethodHandleType::K_INVOKE_INSTANCE, 0x0005);
        assert_eq!(MethodHandleType::K_INVOKE_CONSTRUCTOR, 0x0006);
        assert_eq!(MethodHandleType::K_INVOKE_DIRECT, 0x0007);
        assert_eq!(MethodHandleType::K_INVOKE_INTERFACE, 0x0008);
        assert_eq!(MethodHandleType::K_LAST, MethodHandleType::K_INVOKE_INTERFACE);
    }

    #[test]
    fn to_string_known_types() {
        assert_eq!(MethodHandleType::to_string(0x0000), "kStaticPut");
        assert_eq!(MethodHandleType::to_string(0x0001), "kStaticGet");
        assert_eq!(MethodHandleType::to_string(0x0002), "kInstancePut");
        assert_eq!(MethodHandleType::to_string(0x0003), "kInstanceGet");
        assert_eq!(MethodHandleType::to_string(0x0004), "kInvokeStatic");
        assert_eq!(MethodHandleType::to_string(0x0005), "kInvokeInstance");
        assert_eq!(MethodHandleType::to_string(0x0006), "kInvokeConstructor");
        assert_eq!(MethodHandleType::to_string(0x0007), "kInvokeDirect");
        assert_eq!(MethodHandleType::to_string(0x0008), "kInvokeInterface");
    }

    #[test]
    fn to_string_unknown_type() {
        assert_eq!(MethodHandleType::to_string(0x0009), "MethodHandleType:9");
        assert_eq!(MethodHandleType::to_string(-1), "MethodHandleType:-1");
    }
}
