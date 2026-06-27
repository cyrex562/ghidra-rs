/// Maximum permitted data byte count in a single Intel HEX record.
pub const MAX_RECORD_LENGTH: u8 = 255;

pub const DATA_RECORD_TYPE: u8 = 0x00;
pub const END_OF_FILE_RECORD_TYPE: u8 = 0x01;
pub const EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE: u8 = 0x02;
pub const START_SEGMENT_ADDRESS_RECORD: u8 = 0x03;
pub const EXTENDED_LINEAR_ADDRESS_RECORD_TYPE: u8 = 0x04;
pub const START_LINEAR_ADDRESS_RECORD_TYPE: u8 = 0x05;

/// A single Intel HEX record.
///
/// The format is `:LLAAAATT[DD...]CC` where `LL` is the byte count, `AAAA` is the 16-bit
/// load offset, `TT` is the record type, `DD` is zero or more data bytes, and `CC` is the
/// two's-complement checksum.
#[derive(Debug, Clone)]
pub struct IntelHexRecord {
    record_length: u8,
    load_offset: u16,
    record_type: u8,
    data: Vec<u8>,
    /// The checksum value read from the source (may differ from the computed value).
    checksum: u8,
    actual_checksum: u8,
}

impl IntelHexRecord {
    /// Creates a record with an explicit checksum, intended for use when parsing.
    ///
    /// Returns `Err` if any field fails its validity constraints.
    pub fn new_with_checksum(
        record_length: u8,
        load_offset: u16,
        record_type: u8,
        data: &[u8],
        checksum: u8,
    ) -> Result<Self, String> {
        let actual_checksum =
            Self::compute_checksum(record_length, load_offset, record_type, data);
        let record = Self {
            record_length,
            load_offset,
            record_type,
            data: data.to_vec(),
            checksum,
            actual_checksum,
        };
        record.check_validity()?;
        Ok(record)
    }

    /// Creates a record and computes its checksum automatically, intended for use when writing.
    pub fn new(
        record_length: u8,
        load_offset: u16,
        record_type: u8,
        data: &[u8],
    ) -> Result<Self, String> {
        let checksum = Self::compute_checksum(record_length, load_offset, record_type, data);
        Self::new_with_checksum(record_length, load_offset, record_type, data, checksum)
    }

    fn check_validity(&self) -> Result<(), String> {
        self.check_record_length()?;
        self.check_record_type()?;
        Ok(())
    }

    fn check_record_length(&self) -> Result<(), String> {
        if self.record_length as usize != self.data.len() {
            return Err("recordLength != data.length".to_string());
        }
        Ok(())
    }

    fn check_record_type(&self) -> Result<(), String> {
        match self.record_type {
            DATA_RECORD_TYPE => {}
            END_OF_FILE_RECORD_TYPE => {
                if self.record_length != 0 {
                    return Err(format!(
                        "bad length ({}) for End Of File Record",
                        self.record_length
                    ));
                }
                if self.load_offset != 0 {
                    return Err(format!(
                        "bad load offset ({}) for End Of File Record",
                        self.load_offset
                    ));
                }
            }
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE => {
                if self.record_length != 2 {
                    return Err(format!(
                        "bad length ({}) for Extended Segment Address Record",
                        self.record_length
                    ));
                }
                if self.load_offset != 0 {
                    return Err(format!(
                        "bad load offset ({}) for Extended Segment Address Record",
                        self.load_offset
                    ));
                }
            }
            START_SEGMENT_ADDRESS_RECORD => {
                if self.record_length != 4 {
                    return Err(format!(
                        "bad length ({}) for Start Segment Address Record",
                        self.record_length
                    ));
                }
                if self.load_offset != 0 {
                    return Err(format!(
                        "bad load offset ({}) for Start Segment Address Record",
                        self.load_offset
                    ));
                }
            }
            EXTENDED_LINEAR_ADDRESS_RECORD_TYPE => {
                if self.record_length != 2 {
                    return Err(format!(
                        "bad length ({}) for Extended Linear Address Record",
                        self.record_length
                    ));
                }
                if self.load_offset != 0 {
                    return Err(format!(
                        "bad load offset ({}) for Extended Linear Address Record",
                        self.load_offset
                    ));
                }
            }
            START_LINEAR_ADDRESS_RECORD_TYPE => {
                if self.record_length != 4 {
                    return Err(format!(
                        "bad length ({}) for Start Linear Address Record",
                        self.record_length
                    ));
                }
                if self.load_offset != 0 {
                    return Err(format!(
                        "bad load offset ({}) for Start Linear Address Record",
                        self.load_offset
                    ));
                }
            }
            t => return Err(format!("illegal record type - {}", t)),
        }
        Ok(())
    }

    fn compute_checksum(record_length: u8, load_offset: u16, record_type: u8, data: &[u8]) -> u8 {
        let mut accum: u32 = 0;
        accum += record_length as u32;
        accum += (load_offset & 0xff) as u32;
        accum += ((load_offset >> 8) & 0xff) as u32;
        accum += record_type as u32;
        for &b in data {
            accum += b as u32;
        }
        ((0x100u32 - (accum & 0xff)) & 0xff) as u8
    }

    /// Returns the byte count (number of data bytes in this record).
    pub fn record_length(&self) -> u8 {
        self.record_length
    }

    /// Returns the 16-bit load offset (base address for data records).
    pub fn load_offset(&self) -> u16 {
        self.load_offset
    }

    /// Returns the record type identifier.
    pub fn record_type(&self) -> u8 {
        self.record_type
    }

    /// Returns a copy of the data bytes.
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Returns the data bytes formatted as an uppercase hex string.
    pub fn data_string(&self) -> String {
        self.data.iter().map(|b| format!("{:02X}", b)).collect()
    }

    /// Returns the checksum that was supplied at construction time (may differ from computed).
    pub fn reported_checksum(&self) -> u8 {
        self.checksum
    }

    /// Returns the checksum computed from the record's fields.
    pub fn actual_checksum(&self) -> u8 {
        self.actual_checksum
    }

    /// Returns `true` when the reported checksum matches the computed checksum.
    pub fn is_reported_checksum_correct(&self) -> bool {
        self.checksum == self.actual_checksum
    }

    /// Returns the record serialized in Intel HEX text format (`:LLAAAATT[DD...]CC`).
    pub fn format(&self) -> String {
        let mut s = format!(
            ":{:02X}{:04X}{:02X}",
            self.record_length, self.load_offset, self.record_type
        );
        for &b in &self.data {
            s.push_str(&format!("{:02X}", b));
        }
        s.push_str(&format!("{:02X}", self.actual_checksum));
        s
    }
}

impl PartialEq for IntelHexRecord {
    fn eq(&self, other: &Self) -> bool {
        self.actual_checksum == other.actual_checksum
            && self.checksum == other.checksum
            && self.data == other.data
            && self.load_offset == other.load_offset
            && self.record_length == other.record_length
            && self.record_type == other.record_type
    }
}

impl Eq for IntelHexRecord {}

impl std::hash::Hash for IntelHexRecord {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.actual_checksum.hash(state);
        self.checksum.hash(state);
        self.data.hash(state);
        self.load_offset.hash(state);
        self.record_length.hash(state);
        self.record_type.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_record_type_high() {
        assert!(IntelHexRecord::new_with_checksum(0, 0, 6, &[], 0).is_err());
    }

    #[test]
    fn invalid_record_type_wraps_to_high() {
        // u8 255 is not a valid record type (matches Java's -1 cast to unsigned)
        assert!(IntelHexRecord::new_with_checksum(0, 0, 255, &[], 0).is_err());
    }

    #[test]
    fn record_length_mismatch() {
        assert!(IntelHexRecord::new_with_checksum(15, 0, 0, &[], 0).is_err());
    }

    #[test]
    fn valid_eof_record() {
        // EOF record: length=0, offset=0, type=1, no data; checksum = 0xFF
        IntelHexRecord::new_with_checksum(0, 0, END_OF_FILE_RECORD_TYPE, &[], 0xff).unwrap();
    }

    #[test]
    fn valid_data_record() {
        // From Java test: length=3, offset=0x0030, type=0, data=[0x02,0x33,0x7a], checksum=0x1e
        IntelHexRecord::new_with_checksum(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a], 0x1e)
            .unwrap();
    }

    #[test]
    fn checksum_correct() {
        let r = IntelHexRecord::new_with_checksum(
            3,
            0x0030,
            DATA_RECORD_TYPE,
            &[0x02, 0x33, 0x7a],
            0x1e,
        )
        .unwrap();
        assert!(r.is_reported_checksum_correct());
    }

    #[test]
    fn checksum_incorrect() {
        let r =
            IntelHexRecord::new_with_checksum(1, 0, DATA_RECORD_TYPE, &[4], 37).unwrap();
        assert!(!r.is_reported_checksum_correct());
    }

    #[test]
    fn auto_checksum_correct() {
        let r =
            IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        assert!(r.is_reported_checksum_correct());
        assert_eq!(r.actual_checksum(), 0x1e);
    }

    #[test]
    fn data_string() {
        let r = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        assert_eq!(r.data_string(), "02337A");
    }

    #[test]
    fn format_output() {
        let r = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        assert_eq!(r.format(), ":0300300002337A1E");
    }

    #[test]
    fn eof_bad_length() {
        assert!(IntelHexRecord::new_with_checksum(1, 0, END_OF_FILE_RECORD_TYPE, &[0], 0).is_err());
    }

    #[test]
    fn eof_bad_offset() {
        assert!(
            IntelHexRecord::new_with_checksum(0, 1, END_OF_FILE_RECORD_TYPE, &[], 0).is_err()
        );
    }

    #[test]
    fn extended_segment_address_bad_length() {
        assert!(IntelHexRecord::new_with_checksum(
            1,
            0,
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE,
            &[0],
            0
        )
        .is_err());
    }

    #[test]
    fn extended_segment_address_bad_offset() {
        assert!(IntelHexRecord::new_with_checksum(
            2,
            1,
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE,
            &[0, 0],
            0
        )
        .is_err());
    }

    #[test]
    fn start_segment_address_bad_length() {
        assert!(IntelHexRecord::new_with_checksum(
            2,
            0,
            START_SEGMENT_ADDRESS_RECORD,
            &[0, 0],
            0
        )
        .is_err());
    }

    #[test]
    fn extended_linear_address_valid() {
        IntelHexRecord::new(2, 0, EXTENDED_LINEAR_ADDRESS_RECORD_TYPE, &[0x00, 0x01]).unwrap();
    }

    #[test]
    fn start_linear_address_valid() {
        IntelHexRecord::new(4, 0, START_LINEAR_ADDRESS_RECORD_TYPE, &[0x00, 0x00, 0x00, 0x01])
            .unwrap();
    }

    #[test]
    fn equality() {
        let a = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        let b = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_data() {
        let a = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a]).unwrap();
        let b = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7b]).unwrap();
        assert_ne!(a, b);
    }
}
