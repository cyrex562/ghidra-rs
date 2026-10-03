use crate::filesystem::gfilesystem::fileinfo::file_attribute_type_group::FileAttributeTypeGroup;
use crate::filesystem::seam_stubs::FileAttributeTypeLike;

/// The Rust equivalent of a Java `Class<?>` value-type marker for a
/// [`FileAttributeType`]'s expected value.
///
/// Mirrors the small closed set of classes actually used as `valueType` arguments in the Java
/// enum's constructor calls (`FSRL.class`, `String.class`, `FileType.class`, `Long.class`,
/// `Date.class`, `Boolean.class`, `Object.class`). Represented as an enum rather than
/// `std::any::TypeId` because `FSRL` is ported as the [`Fsrl`](crate::filesystem::gfilesystem::fsrl::Fsrl)
/// trait, not a concrete type, so there is no single Rust type a `TypeId` could name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileAttributeValueType {
    Fsrl,
    Str,
    FileType,
    Long,
    Date,
    Boolean,
    Object,
}

/// Well known types of file attributes.
///
/// Uncommon information about a file should be added to the `FileAttributes` collection
/// as an [`FileAttributeType::UnknownAttribute`] with a custom display name.
///
/// When adding new attribute types to this enum, add them adjacent to other types of the same
/// [`FileAttributeTypeGroup`] category. The enum ordinal controls display ordering.
///
/// Mirrors `ghidra.formats.gfilesystem.fileinfo.FileAttributeType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileAttributeType {
    FsrlAttr,
    NameAttr,
    /// The directory containing the file.
    PathAttr,
    FileTypeAttr,
    ProjectFileAttr,

    SizeAttr,
    CompressedSizeAttr,

    CreateDateAttr,
    ModifiedDateAttr,
    AccessedDateAttr,

    UserNameAttr,
    UserIdAttr,
    GroupNameAttr,
    GroupIdAttr,

    UnixAclAttr,

    IsEncryptedAttr,
    HasGoodPasswordAttr,

    SymlinkDestAttr,
    CommentAttr,
    /// No leading '.'.
    FilenameExtOverride,

    UnknownAttribute,
}

impl FileAttributeType {
    /// Returns the display name of this attribute type.
    ///
    /// Mirrors `getDisplayName()`.
    pub fn display_name(self) -> &'static str {
        match self {
            FileAttributeType::FsrlAttr => "FSRL",
            FileAttributeType::NameAttr => "Name",
            FileAttributeType::PathAttr => "Path",
            FileAttributeType::FileTypeAttr => "File type",
            FileAttributeType::ProjectFileAttr => "Project file",

            FileAttributeType::SizeAttr => "Size",
            FileAttributeType::CompressedSizeAttr => "Compressed size",

            FileAttributeType::CreateDateAttr => "Create date",
            FileAttributeType::ModifiedDateAttr => "Last modified date",
            FileAttributeType::AccessedDateAttr => "Last accessed date",

            FileAttributeType::UserNameAttr => "User",
            FileAttributeType::UserIdAttr => "UserId",
            FileAttributeType::GroupNameAttr => "Group",
            FileAttributeType::GroupIdAttr => "GroupId",

            FileAttributeType::UnixAclAttr => "Unix acl",

            FileAttributeType::IsEncryptedAttr => "Is encrypted?",
            FileAttributeType::HasGoodPasswordAttr => "Password available?",

            FileAttributeType::SymlinkDestAttr => "Symbolic link destination",
            FileAttributeType::CommentAttr => "Comment",
            FileAttributeType::FilenameExtOverride => "Extension override",

            FileAttributeType::UnknownAttribute => "Other attribute",
        }
    }

    /// Returns the [`FileAttributeTypeGroup`] this attribute belongs in.
    ///
    /// Mirrors `getGroup()`.
    pub fn group(self) -> FileAttributeTypeGroup {
        match self {
            FileAttributeType::FsrlAttr
            | FileAttributeType::NameAttr
            | FileAttributeType::PathAttr
            | FileAttributeType::FileTypeAttr
            | FileAttributeType::ProjectFileAttr => FileAttributeTypeGroup::GeneralInfo,

            FileAttributeType::SizeAttr | FileAttributeType::CompressedSizeAttr => {
                FileAttributeTypeGroup::SizeInfo
            }

            FileAttributeType::CreateDateAttr
            | FileAttributeType::ModifiedDateAttr
            | FileAttributeType::AccessedDateAttr => FileAttributeTypeGroup::DateInfo,

            FileAttributeType::UserNameAttr
            | FileAttributeType::UserIdAttr
            | FileAttributeType::GroupNameAttr
            | FileAttributeType::GroupIdAttr => FileAttributeTypeGroup::OwnershipInfo,

            FileAttributeType::UnixAclAttr => FileAttributeTypeGroup::PermissionInfo,

            FileAttributeType::IsEncryptedAttr | FileAttributeType::HasGoodPasswordAttr => {
                FileAttributeTypeGroup::EncryptionInfo
            }

            FileAttributeType::SymlinkDestAttr
            | FileAttributeType::CommentAttr
            | FileAttributeType::FilenameExtOverride => FileAttributeTypeGroup::MiscInfo,

            FileAttributeType::UnknownAttribute => FileAttributeTypeGroup::AdditionalInfo,
        }
    }

    /// Returns the class the value should match.
    ///
    /// Mirrors `getValueType()`.
    pub fn value_type(self) -> FileAttributeValueType {
        match self {
            FileAttributeType::FsrlAttr => FileAttributeValueType::Fsrl,
            FileAttributeType::NameAttr => FileAttributeValueType::Str,
            FileAttributeType::PathAttr => FileAttributeValueType::Str,
            FileAttributeType::FileTypeAttr => FileAttributeValueType::FileType,
            FileAttributeType::ProjectFileAttr => FileAttributeValueType::Str,

            FileAttributeType::SizeAttr => FileAttributeValueType::Long,
            FileAttributeType::CompressedSizeAttr => FileAttributeValueType::Long,

            FileAttributeType::CreateDateAttr => FileAttributeValueType::Date,
            FileAttributeType::ModifiedDateAttr => FileAttributeValueType::Date,
            FileAttributeType::AccessedDateAttr => FileAttributeValueType::Date,

            FileAttributeType::UserNameAttr => FileAttributeValueType::Str,
            FileAttributeType::UserIdAttr => FileAttributeValueType::Long,
            FileAttributeType::GroupNameAttr => FileAttributeValueType::Str,
            FileAttributeType::GroupIdAttr => FileAttributeValueType::Long,

            FileAttributeType::UnixAclAttr => FileAttributeValueType::Long,

            FileAttributeType::IsEncryptedAttr => FileAttributeValueType::Boolean,
            FileAttributeType::HasGoodPasswordAttr => FileAttributeValueType::Boolean,

            FileAttributeType::SymlinkDestAttr => FileAttributeValueType::Str,
            FileAttributeType::CommentAttr => FileAttributeValueType::Str,
            FileAttributeType::FilenameExtOverride => FileAttributeValueType::Str,

            FileAttributeType::UnknownAttribute => FileAttributeValueType::Object,
        }
    }
}

impl FileAttributeTypeLike for FileAttributeType {
    fn display_name(&self) -> &str {
        FileAttributeType::display_name(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_match_java_source() {
        assert_eq!(FileAttributeType::FsrlAttr.display_name(), "FSRL");
        assert_eq!(FileAttributeType::NameAttr.display_name(), "Name");
        assert_eq!(FileAttributeType::PathAttr.display_name(), "Path");
        assert_eq!(FileAttributeType::FileTypeAttr.display_name(), "File type");
        assert_eq!(FileAttributeType::ProjectFileAttr.display_name(), "Project file");
        assert_eq!(FileAttributeType::SizeAttr.display_name(), "Size");
        assert_eq!(
            FileAttributeType::CompressedSizeAttr.display_name(),
            "Compressed size"
        );
        assert_eq!(FileAttributeType::CreateDateAttr.display_name(), "Create date");
        assert_eq!(
            FileAttributeType::ModifiedDateAttr.display_name(),
            "Last modified date"
        );
        assert_eq!(
            FileAttributeType::AccessedDateAttr.display_name(),
            "Last accessed date"
        );
        assert_eq!(FileAttributeType::UserNameAttr.display_name(), "User");
        assert_eq!(FileAttributeType::UserIdAttr.display_name(), "UserId");
        assert_eq!(FileAttributeType::GroupNameAttr.display_name(), "Group");
        assert_eq!(FileAttributeType::GroupIdAttr.display_name(), "GroupId");
        assert_eq!(FileAttributeType::UnixAclAttr.display_name(), "Unix acl");
        assert_eq!(
            FileAttributeType::IsEncryptedAttr.display_name(),
            "Is encrypted?"
        );
        assert_eq!(
            FileAttributeType::HasGoodPasswordAttr.display_name(),
            "Password available?"
        );
        assert_eq!(
            FileAttributeType::SymlinkDestAttr.display_name(),
            "Symbolic link destination"
        );
        assert_eq!(FileAttributeType::CommentAttr.display_name(), "Comment");
        assert_eq!(
            FileAttributeType::FilenameExtOverride.display_name(),
            "Extension override"
        );
        assert_eq!(
            FileAttributeType::UnknownAttribute.display_name(),
            "Other attribute"
        );
    }

    #[test]
    fn groups_match_java_source() {
        assert_eq!(FileAttributeType::FsrlAttr.group(), FileAttributeTypeGroup::GeneralInfo);
        assert_eq!(FileAttributeType::ProjectFileAttr.group(), FileAttributeTypeGroup::GeneralInfo);
        assert_eq!(FileAttributeType::SizeAttr.group(), FileAttributeTypeGroup::SizeInfo);
        assert_eq!(
            FileAttributeType::CompressedSizeAttr.group(),
            FileAttributeTypeGroup::SizeInfo
        );
        assert_eq!(FileAttributeType::CreateDateAttr.group(), FileAttributeTypeGroup::DateInfo);
        assert_eq!(FileAttributeType::UserNameAttr.group(), FileAttributeTypeGroup::OwnershipInfo);
        assert_eq!(FileAttributeType::UnixAclAttr.group(), FileAttributeTypeGroup::PermissionInfo);
        assert_eq!(
            FileAttributeType::IsEncryptedAttr.group(),
            FileAttributeTypeGroup::EncryptionInfo
        );
        assert_eq!(FileAttributeType::CommentAttr.group(), FileAttributeTypeGroup::MiscInfo);
        assert_eq!(
            FileAttributeType::UnknownAttribute.group(),
            FileAttributeTypeGroup::AdditionalInfo
        );
    }

    #[test]
    fn value_types_match_java_source() {
        assert_eq!(FileAttributeType::FsrlAttr.value_type(), FileAttributeValueType::Fsrl);
        assert_eq!(FileAttributeType::NameAttr.value_type(), FileAttributeValueType::Str);
        assert_eq!(FileAttributeType::FileTypeAttr.value_type(), FileAttributeValueType::FileType);
        assert_eq!(FileAttributeType::SizeAttr.value_type(), FileAttributeValueType::Long);
        assert_eq!(FileAttributeType::CreateDateAttr.value_type(), FileAttributeValueType::Date);
        assert_eq!(
            FileAttributeType::IsEncryptedAttr.value_type(),
            FileAttributeValueType::Boolean
        );
        assert_eq!(
            FileAttributeType::UnknownAttribute.value_type(),
            FileAttributeValueType::Object
        );
    }

    #[test]
    fn implements_file_attribute_type_like_seam() {
        let attr: &dyn FileAttributeTypeLike = &FileAttributeType::SizeAttr;
        assert_eq!(attr.display_name(), "Size");
    }

    #[test]
    fn variants_are_distinct() {
        let variants = [
            FileAttributeType::FsrlAttr,
            FileAttributeType::NameAttr,
            FileAttributeType::PathAttr,
            FileAttributeType::FileTypeAttr,
            FileAttributeType::ProjectFileAttr,
            FileAttributeType::SizeAttr,
            FileAttributeType::CompressedSizeAttr,
            FileAttributeType::CreateDateAttr,
            FileAttributeType::ModifiedDateAttr,
            FileAttributeType::AccessedDateAttr,
            FileAttributeType::UserNameAttr,
            FileAttributeType::UserIdAttr,
            FileAttributeType::GroupNameAttr,
            FileAttributeType::GroupIdAttr,
            FileAttributeType::UnixAclAttr,
            FileAttributeType::IsEncryptedAttr,
            FileAttributeType::HasGoodPasswordAttr,
            FileAttributeType::SymlinkDestAttr,
            FileAttributeType::CommentAttr,
            FileAttributeType::FilenameExtOverride,
            FileAttributeType::UnknownAttribute,
        ];
        for (i, &a) in variants.iter().enumerate() {
            for &b in variants[..i].iter() {
                assert_ne!(a, b, "enum variants must be distinct");
            }
        }
    }
}
