/// Enumeration of message types for logging and notifications.
///
/// Port of `ghidra.util.MessageType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Informational message.
    Info,
    /// Alert-level message requiring attention.
    Alert,
    /// Warning-level message.
    Warning,
    /// Error-level message.
    Error,
}

impl MessageType {
    /// Returns the variant whose ordinal equals `value`, or `None` if out of range.
    ///
    /// Ordinals: `Info` = 0, `Alert` = 1, `Warning` = 2, `Error` = 3.
    pub fn parse(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Info),
            1 => Some(Self::Alert),
            2 => Some(Self::Warning),
            3 => Some(Self::Error),
            _ => None,
        }
    }

    /// Returns the ordinal index of this variant (mirrors Java's `Enum.ordinal()`).
    pub fn ordinal(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_ordinals() {
        assert_eq!(MessageType::parse(0), Some(MessageType::Info));
        assert_eq!(MessageType::parse(1), Some(MessageType::Alert));
        assert_eq!(MessageType::parse(2), Some(MessageType::Warning));
        assert_eq!(MessageType::parse(3), Some(MessageType::Error));
    }

    #[test]
    fn parse_out_of_range() {
        assert_eq!(MessageType::parse(4), None);
        assert_eq!(MessageType::parse(-1), None);
        assert_eq!(MessageType::parse(i32::MAX), None);
    }

    #[test]
    fn ordinal_roundtrip() {
        for (expected_ordinal, msg_type) in [
            (0, MessageType::Info),
            (1, MessageType::Alert),
            (2, MessageType::Warning),
            (3, MessageType::Error),
        ] {
            assert_eq!(msg_type.ordinal(), expected_ordinal);
            assert_eq!(MessageType::parse(expected_ordinal), Some(msg_type));
        }
    }

    #[test]
    fn derives() {
        let a = MessageType::Warning;
        let b = a;
        assert_eq!(a, b);
        let _ = format!("{:?}", a);
    }
}
