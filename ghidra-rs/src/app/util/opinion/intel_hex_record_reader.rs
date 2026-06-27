use super::intel_hex_record::IntelHexRecord;

const RECORD_MARK_START: usize = 0;
const RECORD_MARK_END: usize = 1;
const RECORD_LENGTH_START: usize = 1;
const RECORD_LENGTH_END: usize = 3;
const LOAD_OFFSET_START: usize = 3;
const LOAD_OFFSET_END: usize = 7;
const RECORD_TYPE_START: usize = 7;
const RECORD_TYPE_END: usize = 9;
const DATA_START: usize = 9;
const CHECKSUM_LENGTH: usize = 2;

/// Parses a single Intel HEX record line into an [`IntelHexRecord`].
///
/// The line may contain whitespace; it is stripped before parsing.  Returns
/// `Err` with a human-readable message if the line is malformed.
pub fn read_record(line: &str) -> Result<IntelHexRecord, String> {
    let line: String = line.chars().filter(|c| !c.is_whitespace()).collect();

    if line.len() < DATA_START + CHECKSUM_LENGTH {
        return Err("line too short to contain record".to_string());
    }

    let record_mark = &line[RECORD_MARK_START..RECORD_MARK_END];
    if record_mark != ":" {
        return Err("line does not start with record mark (:)".to_string());
    }

    let record_length_str = &line[RECORD_LENGTH_START..RECORD_LENGTH_END];
    let record_length = u8::from_str_radix(record_length_str, 16)
        .map_err(|e| format!("error parsing record length: {}", e))?;

    let load_offset_str = &line[LOAD_OFFSET_START..LOAD_OFFSET_END];
    let load_offset = u16::from_str_radix(load_offset_str, 16)
        .map_err(|e| format!("error parsing load offset: {}", e))?;

    let record_type_str = &line[RECORD_TYPE_START..RECORD_TYPE_END];
    let record_type = u8::from_str_radix(record_type_str, 16)
        .map_err(|e| format!("error parsing record type: {}", e))?;

    let data_end = DATA_START + record_length as usize * 2;
    let checksum_start = data_end;
    let checksum_end = checksum_start + CHECKSUM_LENGTH;

    if line.len() != checksum_end {
        return Err(format!(
            "line invalid length to contain record with record length {}",
            record_length
        ));
    }

    let data = convert_data(&line[DATA_START..data_end])?;

    let checksum_str = &line[checksum_start..checksum_end];
    let checksum = u8::from_str_radix(checksum_str, 16)
        .map_err(|e| format!("error parsing checksum: {}", e))?;

    IntelHexRecord::new_with_checksum(record_length, load_offset, record_type, &data, checksum)
}

fn convert_data(data_string: &str) -> Result<Vec<u8>, String> {
    if data_string.len() % 2 == 1 {
        return Err("internal error - data string of odd length".to_string());
    }
    let mut result = Vec::with_capacity(data_string.len() / 2);
    for chunk in data_string.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).unwrap();
        let b = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("error parsing data byte: {}", e))?;
        result.push(b);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::opinion::intel_hex_record::{
        DATA_RECORD_TYPE, END_OF_FILE_RECORD_TYPE, EXTENDED_LINEAR_ADDRESS_RECORD_TYPE,
    };

    #[test]
    fn basic_data_record() {
        let raw = IntelHexRecord::new_with_checksum(3, 0x0030, DATA_RECORD_TYPE, &[0x02, 0x33, 0x7a], 0x1e).unwrap();
        let parsed = read_record(":0300300002337A1E").unwrap();
        assert_eq!(raw, parsed);
    }

    #[test]
    fn lowercase_hex_accepted() {
        let parsed = read_record(":0300300002337a1e").unwrap();
        assert_eq!(parsed.record_length(), 3);
        assert_eq!(parsed.load_offset(), 0x0030);
    }

    #[test]
    fn whitespace_stripped() {
        let parsed = read_record("  :0300300002337A1E  ").unwrap();
        assert_eq!(parsed.record_length(), 3);
    }

    #[test]
    fn eof_record() {
        let parsed = read_record(":00000001FF").unwrap();
        assert_eq!(parsed.record_type(), END_OF_FILE_RECORD_TYPE);
        assert_eq!(parsed.record_length(), 0);
    }

    #[test]
    fn extended_linear_address_record() {
        let parsed = read_record(":02000004FFFFFC").unwrap();
        assert_eq!(parsed.record_type(), EXTENDED_LINEAR_ADDRESS_RECORD_TYPE);
        assert_eq!(parsed.record_length(), 2);
    }

    #[test]
    fn line_too_short() {
        assert!(read_record(":0300300002337A").is_err());
        let err = read_record(":030030").unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn missing_record_mark() {
        let err = read_record("0300300002337A1E00").unwrap_err();
        assert!(err.contains("record mark"));
    }

    #[test]
    fn invalid_record_length_hex() {
        let err = read_record(":GG00300002337A1E").unwrap_err();
        assert!(err.contains("record length"));
    }

    #[test]
    fn invalid_load_offset_hex() {
        let err = read_record(":03ZZZZ0002337A1E").unwrap_err();
        assert!(err.contains("load offset"));
    }

    #[test]
    fn invalid_record_type_hex() {
        let err = read_record(":030030ZZ02337A1E").unwrap_err();
        assert!(err.contains("record type"));
    }

    #[test]
    fn line_length_mismatch() {
        // record length says 3 bytes but line has 4 data bytes
        let err = read_record(":030030000102030405").unwrap_err();
        assert!(err.contains("invalid length"));
    }

    #[test]
    fn invalid_checksum_hex() {
        let err = read_record(":030030000203ZZ").unwrap_err();
        assert!(err.contains("checksum"));
    }

    #[test]
    fn invalid_data_hex() {
        let err = read_record(":030030000203ZZ1E").unwrap_err();
        // data byte error comes before checksum parsing
        assert!(err.contains("data") || err.contains("checksum"));
    }
}
