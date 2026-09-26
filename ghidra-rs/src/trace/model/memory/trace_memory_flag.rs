/// A flag representing a memory access type in a trace.
///
/// Mirrors `ghidra.trace.model.memory.TraceMemoryFlag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryFlag {
    Execute,
    Write,
    Read,
    Volatile,
}

impl TraceMemoryFlag {
    /// Returns the bit value for this flag.
    pub fn bits(self) -> u8 {
        match self {
            TraceMemoryFlag::Execute => 0x1,
            TraceMemoryFlag::Write => 0x2,
            TraceMemoryFlag::Read => 0x4,
            TraceMemoryFlag::Volatile => 0x8,
        }
    }

    /// Constructs a set of flags from a bitmask.
    ///
    /// Mirrors Java's `fromBits(int mask)`.
    pub fn from_bits(mask: u8) -> Vec<TraceMemoryFlag> {
        let mut flags = Vec::new();
        if (mask & Self::Execute.bits()) != 0 {
            flags.push(Self::Execute);
        }
        if (mask & Self::Write.bits()) != 0 {
            flags.push(Self::Write);
        }
        if (mask & Self::Read.bits()) != 0 {
            flags.push(Self::Read);
        }
        if (mask & Self::Volatile.bits()) != 0 {
            flags.push(Self::Volatile);
        }
        flags
    }

    /// Converts a collection of flags to a bitmask.
    ///
    /// Mirrors Java's `toBits(Collection<TraceMemoryFlag> flags)`.
    pub fn to_bits(flags: &[TraceMemoryFlag]) -> u8 {
        let mut bits: u8 = 0;
        for flag in flags {
            bits |= flag.bits();
        }
        bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_bits() {
        assert_eq!(TraceMemoryFlag::Execute.bits(), 0x1);
    }

    #[test]
    fn write_bits() {
        assert_eq!(TraceMemoryFlag::Write.bits(), 0x2);
    }

    #[test]
    fn read_bits() {
        assert_eq!(TraceMemoryFlag::Read.bits(), 0x4);
    }

    #[test]
    fn volatile_bits() {
        assert_eq!(TraceMemoryFlag::Volatile.bits(), 0x8);
    }

    #[test]
    fn from_bits_empty() {
        assert_eq!(TraceMemoryFlag::from_bits(0), vec![]);
    }

    #[test]
    fn from_bits_single_execute() {
        assert_eq!(
            TraceMemoryFlag::from_bits(0x1),
            vec![TraceMemoryFlag::Execute]
        );
    }

    #[test]
    fn from_bits_single_write() {
        assert_eq!(
            TraceMemoryFlag::from_bits(0x2),
            vec![TraceMemoryFlag::Write]
        );
    }

    #[test]
    fn from_bits_single_read() {
        assert_eq!(
            TraceMemoryFlag::from_bits(0x4),
            vec![TraceMemoryFlag::Read]
        );
    }

    #[test]
    fn from_bits_single_volatile() {
        assert_eq!(
            TraceMemoryFlag::from_bits(0x8),
            vec![TraceMemoryFlag::Volatile]
        );
    }

    #[test]
    fn from_bits_multiple() {
        let result = TraceMemoryFlag::from_bits(0x7);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&TraceMemoryFlag::Execute));
        assert!(result.contains(&TraceMemoryFlag::Write));
        assert!(result.contains(&TraceMemoryFlag::Read));
    }

    #[test]
    fn from_bits_all() {
        let result = TraceMemoryFlag::from_bits(0xF);
        assert_eq!(result.len(), 4);
        assert!(result.contains(&TraceMemoryFlag::Execute));
        assert!(result.contains(&TraceMemoryFlag::Write));
        assert!(result.contains(&TraceMemoryFlag::Read));
        assert!(result.contains(&TraceMemoryFlag::Volatile));
    }

    #[test]
    fn to_bits_empty() {
        assert_eq!(TraceMemoryFlag::to_bits(&[]), 0);
    }

    #[test]
    fn to_bits_single_execute() {
        assert_eq!(TraceMemoryFlag::to_bits(&[TraceMemoryFlag::Execute]), 0x1);
    }

    #[test]
    fn to_bits_single_write() {
        assert_eq!(TraceMemoryFlag::to_bits(&[TraceMemoryFlag::Write]), 0x2);
    }

    #[test]
    fn to_bits_single_read() {
        assert_eq!(TraceMemoryFlag::to_bits(&[TraceMemoryFlag::Read]), 0x4);
    }

    #[test]
    fn to_bits_single_volatile() {
        assert_eq!(TraceMemoryFlag::to_bits(&[TraceMemoryFlag::Volatile]), 0x8);
    }

    #[test]
    fn to_bits_multiple() {
        let flags = vec![
            TraceMemoryFlag::Execute,
            TraceMemoryFlag::Write,
            TraceMemoryFlag::Read,
        ];
        assert_eq!(TraceMemoryFlag::to_bits(&flags), 0x7);
    }

    #[test]
    fn to_bits_all() {
        let flags = vec![
            TraceMemoryFlag::Execute,
            TraceMemoryFlag::Write,
            TraceMemoryFlag::Read,
            TraceMemoryFlag::Volatile,
        ];
        assert_eq!(TraceMemoryFlag::to_bits(&flags), 0xF);
    }

    #[test]
    fn roundtrip_empty() {
        let mask = 0u8;
        let flags = TraceMemoryFlag::from_bits(mask);
        let bits = TraceMemoryFlag::to_bits(&flags);
        assert_eq!(bits, mask);
    }

    #[test]
    fn roundtrip_all() {
        let mask = 0xFu8;
        let flags = TraceMemoryFlag::from_bits(mask);
        let bits = TraceMemoryFlag::to_bits(&flags);
        assert_eq!(bits, mask);
    }

    #[test]
    fn roundtrip_partial() {
        let mask = 0x5u8;
        let flags = TraceMemoryFlag::from_bits(mask);
        let bits = TraceMemoryFlag::to_bits(&flags);
        assert_eq!(bits, mask);
    }

    #[test]
    fn from_bits_ignores_high_bits() {
        let result = TraceMemoryFlag::from_bits(0xFF);
        assert_eq!(result.len(), 4);
    }
}
