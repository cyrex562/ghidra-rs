/// macOS Apple Single/Double Header entry descriptor IDs.
///
/// Mirrors Ghidra's `EntryDescriptorID`.
pub const ENTRY_DATA_FORK: u32 = 0x1;
pub const ENTRY_RESOURCE_FORK: u32 = 0x2;
pub const ENTRY_REAL_NAME: u32 = 0x3;
pub const ENTRY_COMMENT: u32 = 0x4;
pub const ENTRY_ICON_BW: u32 = 0x5;
pub const ENTRY_ICON_COLOR: u32 = 0x6;
pub const ENTRY_FILE_DATE_INFO: u32 = 0x7;
pub const ENTRY_FINDER_INFO: u32 = 0x8;
pub const ENTRY_MAC_FILE_INFO: u32 = 0x9;
pub const ENTRY_PRODOS_FILE_INFO: u32 = 0xa;
pub const ENTRY_MSDOS_FILE_INFO: u32 = 0xb;
pub const ENTRY_SHORT_NAME: u32 = 0xc;
pub const ENTRY_AFP_FILE_INFO: u32 = 0xd;
pub const ENTRY_DIRECTORY_ID: u32 = 0xe;

/// Converts an entry ID to its constant name.
///
/// Returns the symbolic name (without the "ENTRY_" prefix) if the ID matches
/// a known constant, otherwise returns a formatted string like "Unrecognized entry id: 0x...".
pub fn convert_entry_id_to_name(entry_id: u32) -> String {
    match entry_id {
        ENTRY_DATA_FORK => "DATA_FORK".to_string(),
        ENTRY_RESOURCE_FORK => "RESOURCE_FORK".to_string(),
        ENTRY_REAL_NAME => "REAL_NAME".to_string(),
        ENTRY_COMMENT => "COMMENT".to_string(),
        ENTRY_ICON_BW => "ICON_BW".to_string(),
        ENTRY_ICON_COLOR => "ICON_COLOR".to_string(),
        ENTRY_FILE_DATE_INFO => "FILE_DATE_INFO".to_string(),
        ENTRY_FINDER_INFO => "FINDER_INFO".to_string(),
        ENTRY_MAC_FILE_INFO => "MAC_FILE_INFO".to_string(),
        ENTRY_PRODOS_FILE_INFO => "PRODOS_FILE_INFO".to_string(),
        ENTRY_MSDOS_FILE_INFO => "MSDOS_FILE_INFO".to_string(),
        ENTRY_SHORT_NAME => "SHORT_NAME".to_string(),
        ENTRY_AFP_FILE_INFO => "AFP_FILE_INFO".to_string(),
        ENTRY_DIRECTORY_ID => "DIRECTORY_ID".to_string(),
        _ => format!("Unrecognized entry id: 0x{:x}", entry_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_fork_constant() {
        assert_eq!(ENTRY_DATA_FORK, 0x1);
    }

    #[test]
    fn resource_fork_constant() {
        assert_eq!(ENTRY_RESOURCE_FORK, 0x2);
    }

    #[test]
    fn real_name_constant() {
        assert_eq!(ENTRY_REAL_NAME, 0x3);
    }

    #[test]
    fn comment_constant() {
        assert_eq!(ENTRY_COMMENT, 0x4);
    }

    #[test]
    fn icon_bw_constant() {
        assert_eq!(ENTRY_ICON_BW, 0x5);
    }

    #[test]
    fn icon_color_constant() {
        assert_eq!(ENTRY_ICON_COLOR, 0x6);
    }

    #[test]
    fn file_date_info_constant() {
        assert_eq!(ENTRY_FILE_DATE_INFO, 0x7);
    }

    #[test]
    fn finder_info_constant() {
        assert_eq!(ENTRY_FINDER_INFO, 0x8);
    }

    #[test]
    fn mac_file_info_constant() {
        assert_eq!(ENTRY_MAC_FILE_INFO, 0x9);
    }

    #[test]
    fn prodos_file_info_constant() {
        assert_eq!(ENTRY_PRODOS_FILE_INFO, 0xa);
    }

    #[test]
    fn msdos_file_info_constant() {
        assert_eq!(ENTRY_MSDOS_FILE_INFO, 0xb);
    }

    #[test]
    fn short_name_constant() {
        assert_eq!(ENTRY_SHORT_NAME, 0xc);
    }

    #[test]
    fn afp_file_info_constant() {
        assert_eq!(ENTRY_AFP_FILE_INFO, 0xd);
    }

    #[test]
    fn directory_id_constant() {
        assert_eq!(ENTRY_DIRECTORY_ID, 0xe);
    }

    #[test]
    fn convert_data_fork() {
        assert_eq!(convert_entry_id_to_name(ENTRY_DATA_FORK), "DATA_FORK");
    }

    #[test]
    fn convert_resource_fork() {
        assert_eq!(convert_entry_id_to_name(ENTRY_RESOURCE_FORK), "RESOURCE_FORK");
    }

    #[test]
    fn convert_real_name() {
        assert_eq!(convert_entry_id_to_name(ENTRY_REAL_NAME), "REAL_NAME");
    }

    #[test]
    fn convert_comment() {
        assert_eq!(convert_entry_id_to_name(ENTRY_COMMENT), "COMMENT");
    }

    #[test]
    fn convert_icon_bw() {
        assert_eq!(convert_entry_id_to_name(ENTRY_ICON_BW), "ICON_BW");
    }

    #[test]
    fn convert_icon_color() {
        assert_eq!(convert_entry_id_to_name(ENTRY_ICON_COLOR), "ICON_COLOR");
    }

    #[test]
    fn convert_file_date_info() {
        assert_eq!(convert_entry_id_to_name(ENTRY_FILE_DATE_INFO), "FILE_DATE_INFO");
    }

    #[test]
    fn convert_finder_info() {
        assert_eq!(convert_entry_id_to_name(ENTRY_FINDER_INFO), "FINDER_INFO");
    }

    #[test]
    fn convert_mac_file_info() {
        assert_eq!(convert_entry_id_to_name(ENTRY_MAC_FILE_INFO), "MAC_FILE_INFO");
    }

    #[test]
    fn convert_prodos_file_info() {
        assert_eq!(
            convert_entry_id_to_name(ENTRY_PRODOS_FILE_INFO),
            "PRODOS_FILE_INFO"
        );
    }

    #[test]
    fn convert_msdos_file_info() {
        assert_eq!(
            convert_entry_id_to_name(ENTRY_MSDOS_FILE_INFO),
            "MSDOS_FILE_INFO"
        );
    }

    #[test]
    fn convert_short_name() {
        assert_eq!(convert_entry_id_to_name(ENTRY_SHORT_NAME), "SHORT_NAME");
    }

    #[test]
    fn convert_afp_file_info() {
        assert_eq!(convert_entry_id_to_name(ENTRY_AFP_FILE_INFO), "AFP_FILE_INFO");
    }

    #[test]
    fn convert_directory_id() {
        assert_eq!(convert_entry_id_to_name(ENTRY_DIRECTORY_ID), "DIRECTORY_ID");
    }

    #[test]
    fn convert_unrecognized_id() {
        let result = convert_entry_id_to_name(0xff);
        assert_eq!(result, "Unrecognized entry id: 0xff");
    }

    #[test]
    fn convert_unrecognized_id_zero() {
        let result = convert_entry_id_to_name(0x0);
        assert_eq!(result, "Unrecognized entry id: 0x0");
    }
}
