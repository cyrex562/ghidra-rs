/// Categories of file attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileAttributeTypeGroup {
    GeneralInfo,
    SizeInfo,
    DateInfo,
    OwnershipInfo,
    PermissionInfo,
    EncryptionInfo,
    MiscInfo,
    AdditionalInfo,
}

impl FileAttributeTypeGroup {
    /// Returns the descriptive name of the group.
    pub fn descriptive_name(self) -> &'static str {
        match self {
            FileAttributeTypeGroup::GeneralInfo => "General",
            FileAttributeTypeGroup::SizeInfo => "Size Info",
            FileAttributeTypeGroup::DateInfo => "Date Info",
            FileAttributeTypeGroup::OwnershipInfo => "Ownership Info",
            FileAttributeTypeGroup::PermissionInfo => "Permission Info",
            FileAttributeTypeGroup::EncryptionInfo => "Encryption Info",
            FileAttributeTypeGroup::MiscInfo => "Misc",
            FileAttributeTypeGroup::AdditionalInfo => "Additional Info",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileAttributeTypeGroup;

    #[test]
    fn descriptive_names_match_java_source() {
        assert_eq!(FileAttributeTypeGroup::GeneralInfo.descriptive_name(), "General");
        assert_eq!(FileAttributeTypeGroup::SizeInfo.descriptive_name(), "Size Info");
        assert_eq!(FileAttributeTypeGroup::DateInfo.descriptive_name(), "Date Info");
        assert_eq!(FileAttributeTypeGroup::OwnershipInfo.descriptive_name(), "Ownership Info");
        assert_eq!(FileAttributeTypeGroup::PermissionInfo.descriptive_name(), "Permission Info");
        assert_eq!(FileAttributeTypeGroup::EncryptionInfo.descriptive_name(), "Encryption Info");
        assert_eq!(FileAttributeTypeGroup::MiscInfo.descriptive_name(), "Misc");
        assert_eq!(FileAttributeTypeGroup::AdditionalInfo.descriptive_name(), "Additional Info");
    }

    #[test]
    fn variants_are_distinct() {
        let variants = [
            FileAttributeTypeGroup::GeneralInfo,
            FileAttributeTypeGroup::SizeInfo,
            FileAttributeTypeGroup::DateInfo,
            FileAttributeTypeGroup::OwnershipInfo,
            FileAttributeTypeGroup::PermissionInfo,
            FileAttributeTypeGroup::EncryptionInfo,
            FileAttributeTypeGroup::MiscInfo,
            FileAttributeTypeGroup::AdditionalInfo,
        ];
        for (i, &a) in variants.iter().enumerate() {
            for &b in variants[..i].iter() {
                assert_ne!(a, b, "enum variants must be distinct");
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let g = FileAttributeTypeGroup::GeneralInfo;
        let g2 = g;
        assert_eq!(g, g2);
        let g3 = g.clone();
        assert_eq!(g, g3);
    }
}
