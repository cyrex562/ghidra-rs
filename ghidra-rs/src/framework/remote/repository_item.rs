//! Port of `ghidra.framework.remote.RepositoryItem`.
//!
//! Provides status information for a repository folder item.
//!
//! ## Serialization not literally ported
//!
//! The Java class implements `Serializable` via a custom `writeObject`/`readObject` pair
//! (an expandable wire schema: `serialVersionUID == 2` covers the original field set, and a
//! trailing `SERIALIZATION_SCHEMA_VERSION` byte plus `textData` string were appended later
//! without bumping `serialVersionUID`, so old clients can still read the head of the stream
//! from a new server and vice versa). Following the precedent set by the sibling port
//! [`ItemCheckoutStatus`](crate::framework::store::ItemCheckoutStatus) (which documents rather
//! than literally re-implements its own `writeObject`/`readObject`), this port carries the
//! constructor and getters but does not implement a byte-stream reader/writer: nothing in this
//! crate currently deserializes the Java RMI wire form directly, so there is no forcing need for
//! one yet.
//!
//! One quirk worth flagging in `readObject` (source lines 122-165) for whoever eventually adds
//! real wire deserialization: the null-collapsing logic is *not* symmetric across the nullable
//! string fields. `fileID` and `contentType` are nulled out only on a strict empty-string check
//! (`if (fileID.length() == 0) fileID = null;`), but `textData` is nulled out via
//! `StringUtils.isBlank(textData)`, which is also `true` for a string of only whitespace. So a
//! deserialized item with `fileID == " "` keeps the single space, while one with
//! `textData == " "` collapses to `null`.
//!
//! `writeObject`'s companion encoding of the *outgoing* direction is symmetric with itself
//! though: both `fileID` and `contentType` (like `textData`) are written as `""` when `null`
//! (`fileID != null ? fileID : ""`), so the asymmetry is purely a read-side thing.

use crate::framework::store::file_system::SEPARATOR;

/// Port of `RepositoryItem.serialVersionUID`.
pub const SERIAL_VERSION_UID: i64 = 2;

/// Port of `RepositoryItem.SERIALIZATION_SCHEMA_VERSION` (private in Java; kept private here
/// too, retained for documentation parity with the wire-format notes above).
#[allow(dead_code)]
const SERIALIZATION_SCHEMA_VERSION: u8 = 1;

/// Port of `RepositoryItem.FILE`: a `DataFileItem` (not yet supported, per the Java comment).
pub const FILE: i32 = 1;
/// Port of `RepositoryItem.DATABASE`: a `DatabaseItem`.
pub const DATABASE: i32 = 2;
/// Port of `RepositoryItem.TEXT_DATA_FILE`: a `TextDataItem`.
pub const TEXT_DATA_FILE: i32 = 3;

/// Status information for a repository folder item.
///
/// Port of `ghidra.framework.remote.RepositoryItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryItem {
    folder_path: String,
    item_name: String,
    file_id: Option<String>,
    item_type: i32,
    content_type: Option<String>,
    version: i32,
    version_time: i64,
    text_data: Option<String>,
}

impl RepositoryItem {
    /// Port of the public constructor:
    /// `RepositoryItem(String folderPath, String itemName, String fileID, int itemType, String
    /// contentType, int version, long versionTime, String textData)`.
    ///
    /// * `folder_path` - path of folder containing item.
    /// * `item_name` - name of item.
    /// * `file_id` - unique file ID.
    /// * `item_type` - type of item ([`FILE`] or [`DATABASE`]).
    /// * `content_type` - content type associated with item.
    /// * `version` - repository item version or `-1` if versioning not supported.
    /// * `version_time` - version creation time.
    /// * `text_data` - related text data (may be `None`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        folder_path: impl Into<String>,
        item_name: impl Into<String>,
        file_id: Option<String>,
        item_type: i32,
        content_type: Option<String>,
        version: i32,
        version_time: i64,
        text_data: Option<String>,
    ) -> Self {
        Self {
            folder_path: folder_path.into(),
            item_name: item_name.into(),
            file_id,
            item_type,
            content_type,
            version,
            version_time,
            text_data,
        }
    }

    /// Port of the protected default constructor ("Default constructor needed for
    /// de-serialization"). Produces an item with Java's default field values: empty strings for
    /// the (non-nullable in this port) `folder_path`/`item_name`, `None` for the nullable string
    /// fields, and `0` for the numeric fields.
    pub fn empty() -> Self {
        Self {
            folder_path: String::new(),
            item_name: String::new(),
            file_id: None,
            item_type: 0,
            content_type: None,
            version: 0,
            version_time: 0,
            text_data: None,
        }
    }

    /// Returns the item name. Port of `getName()`.
    pub fn get_name(&self) -> &str {
        &self.item_name
    }

    /// Returns the folder item path within the repository. Port of `getPathName()`.
    pub fn get_path_name(&self) -> String {
        format!("{}{}{}", self.folder_path, SEPARATOR, self.item_name)
    }

    /// Returns path of the parent folder containing this item. Port of `getParentPath()`.
    pub fn get_parent_path(&self) -> &str {
        &self.folder_path
    }

    /// Returns type of item. Port of `getItemType()`.
    pub fn get_item_type(&self) -> i32 {
        self.item_type
    }

    /// Returns content class. Port of `getContentType()`.
    pub fn get_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Port of `getFileID()`.
    pub fn get_file_id(&self) -> Option<&str> {
        self.file_id.as_deref()
    }

    /// Returns the current version of the item or `-1` if versioning not supported. Port of
    /// `getVersion()`.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Returns the time (UTC milliseconds) when the current version was created. Port of
    /// `getVersionTime()`.
    pub fn get_version_time(&self) -> i64 {
        self.version_time
    }

    /// Get related text data, or `None`. Port of `getTextData()`.
    pub fn get_text_data(&self) -> Option<&str> {
        self.text_data.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RepositoryItem {
        RepositoryItem::new(
            "/a/b",
            "myItem",
            Some("file-123".to_string()),
            DATABASE,
            Some("Program".to_string()),
            3,
            1_700_000_000_000,
            Some("some text".to_string()),
        )
    }

    #[test]
    fn getters_return_constructor_values() {
        let item = sample();
        assert_eq!(item.get_name(), "myItem");
        assert_eq!(item.get_parent_path(), "/a/b");
        assert_eq!(item.get_item_type(), DATABASE);
        assert_eq!(item.get_content_type(), Some("Program"));
        assert_eq!(item.get_file_id(), Some("file-123"));
        assert_eq!(item.get_version(), 3);
        assert_eq!(item.get_version_time(), 1_700_000_000_000);
        assert_eq!(item.get_text_data(), Some("some text"));
    }

    /// `getPathName()` joins folder path and item name with `FileSystem.SEPARATOR` ("/"), with
    /// no de-duplication of a trailing slash on `folderPath` -- matching Java's plain `+`
    /// concatenation (`folderPath + FileSystem.SEPARATOR + itemName`).
    #[test]
    fn get_path_name_joins_folder_and_item_name() {
        let item = RepositoryItem::new(
            "/a/b",
            "myItem",
            None,
            FILE,
            None,
            -1,
            0,
            None,
        );
        assert_eq!(item.get_path_name(), "/a/b/myItem");
    }

    #[test]
    fn get_path_name_root_folder() {
        let item = RepositoryItem::new("/", "root_item", None, FILE, None, -1, 0, None);
        assert_eq!(item.get_path_name(), "//root_item");
    }

    #[test]
    fn nullable_fields_default_to_none() {
        let item = RepositoryItem::new("/a", "b", None, TEXT_DATA_FILE, None, -1, 0, None);
        assert_eq!(item.get_file_id(), None);
        assert_eq!(item.get_content_type(), None);
        assert_eq!(item.get_text_data(), None);
    }

    #[test]
    fn version_minus_one_means_versioning_unsupported() {
        let item = RepositoryItem::new("/a", "b", None, FILE, None, -1, 0, None);
        assert_eq!(item.get_version(), -1);
    }

    #[test]
    fn empty_constructor_matches_java_defaults() {
        let item = RepositoryItem::empty();
        assert_eq!(item.get_name(), "");
        assert_eq!(item.get_parent_path(), "");
        assert_eq!(item.get_item_type(), 0);
        assert_eq!(item.get_content_type(), None);
        assert_eq!(item.get_file_id(), None);
        assert_eq!(item.get_version(), 0);
        assert_eq!(item.get_version_time(), 0);
        assert_eq!(item.get_text_data(), None);
    }

    #[test]
    fn item_type_constants_match_java_values() {
        assert_eq!(FILE, 1);
        assert_eq!(DATABASE, 2);
        assert_eq!(TEXT_DATA_FILE, 3);
    }

    #[test]
    fn equal_items_compare_equal() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn items_with_different_names_are_not_equal() {
        let a = sample();
        let mut b = sample();
        b = RepositoryItem::new(
            "/a/b",
            "otherItem",
            b.file_id.clone(),
            b.item_type,
            b.content_type.clone(),
            b.version,
            b.version_time,
            b.text_data.clone(),
        );
        assert_ne!(a, b);
    }
}
