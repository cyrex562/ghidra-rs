use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::entry_point::EntryPoint;
use std::io;

/// Marker denoting an unused entry table bundle.
pub const UNUSED: i8 = 0x00;
/// Segment is moveable.
pub const MOVEABLE: i8 = 0xffu8 as i8;
/// Refers to a constant defined in module.
pub const CONSTANT: i8 = 0xfeu8 as i8;

/// Represents a new-executable (NE) entry table bundle.
///
/// Mirrors `EntryTableBundle` from the original Ghidra Java source.
pub struct EntryTableBundle {
    count: i8,
    r#type: i8,
    /// `None` mirrors the Java `null` left in place when the bundle is unused (`count == 0`) or
    /// the type byte itself is unused (`type == 0`).
    entry_points: Option<Vec<EntryPoint>>,
}

impl EntryTableBundle {
    /// Constructs a new entry table bundle by reading it from `reader`.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let count = reader.read_next_byte()? as i8;
        if count == 0 {
            // do not read anymore data...
            return Ok(EntryTableBundle {
                count,
                r#type: 0,
                entry_points: None,
            });
        }

        let r#type = reader.read_next_byte()? as i8;
        if r#type == 0 {
            // unused bundle...
            return Ok(EntryTableBundle {
                count,
                r#type,
                entry_points: None,
            });
        }

        let count_int = count as u8 as usize;
        let is_moveable = r#type == MOVEABLE;

        let mut entry_points = Vec::with_capacity(count_int);
        for _ in 0..count_int {
            entry_points.push(EntryPoint::new(reader, is_moveable)?);
        }

        Ok(EntryTableBundle {
            count,
            r#type,
            entry_points: Some(entry_points),
        })
    }

    /// Returns true if this bundle is moveable.
    pub fn is_moveable(&self) -> bool {
        self.r#type == MOVEABLE
    }

    /// Returns true if this bundle is constant.
    pub fn is_constant(&self) -> bool {
        self.r#type == CONSTANT
    }

    /// Returns the number of entries in bundle.
    pub fn get_count(&self) -> i8 {
        self.count
    }

    /// Returns the type of the bundle. For example, MOVEABLE, CONSTANT, or segment index.
    pub fn get_type(&self) -> i8 {
        self.r#type
    }

    /// Returns the entry points in this bundle, or `None` if the bundle is unused.
    pub fn get_entry_points(&self) -> Option<&[EntryPoint]> {
        self.entry_points.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn unused_bundle_stops_after_count_byte() {
        let data = vec![0x00u8];
        let mut reader = BinaryReader::from_bytes(data, true);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 0);
        assert_eq!(bundle.get_type(), 0);
        assert!(bundle.get_entry_points().is_none());
        assert!(!bundle.is_moveable());
        assert!(!bundle.is_constant());
    }

    #[test]
    fn unused_type_stops_after_type_byte() {
        let data = vec![0x02u8, 0x00u8];
        let mut reader = BinaryReader::from_bytes(data, true);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 2);
        assert_eq!(bundle.get_type(), 0);
        assert!(bundle.get_entry_points().is_none());
    }

    #[test]
    fn reads_constant_bundle_entry_points() {
        // count = 2, type = CONSTANT (0xfe); non-moveable entries only have flagword + offset.
        let data = vec![
            0x02, 0xfe, // count, type
            0x01, 0x10, 0x00, // entry 1: flagword=1, offset=0x0010
            0x02, 0x20, 0x00, // entry 2: flagword=2, offset=0x0020
        ];
        let mut reader = BinaryReader::from_bytes(data, true);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert_eq!(bundle.get_count(), 2);
        assert_eq!(bundle.get_type(), CONSTANT);
        assert!(bundle.is_constant());
        assert!(!bundle.is_moveable());

        let entries = bundle.get_entry_points().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get_flagword(), 1);
        assert_eq!(entries[0].get_offset(), 0x0010);
        assert_eq!(entries[1].get_flagword(), 2);
        assert_eq!(entries[1].get_offset(), 0x0020);
    }

    #[test]
    fn reads_moveable_bundle_entry_points() {
        // count = 1, type = MOVEABLE (0xff); moveable entries also read instruction + segment.
        let data = vec![
            0x01, 0xff, // count, type
            0x03, 0xAA, 0xBB, 0x05, 0x30, 0x00, // flagword, instruction, segment, offset
        ];
        let mut reader = BinaryReader::from_bytes(data, true);

        let bundle = EntryTableBundle::new(&mut reader).unwrap();

        assert!(bundle.is_moveable());
        let entries = bundle.get_entry_points().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].get_flagword(), 3);
        assert_eq!(entries[0].get_instruction(), i16::from_le_bytes([0xAA, 0xBB]));
        assert_eq!(entries[0].get_segment(), 5);
        assert_eq!(entries[0].get_offset(), 0x0030);
    }
}
