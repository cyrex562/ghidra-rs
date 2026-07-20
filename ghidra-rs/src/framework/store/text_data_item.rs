use crate::framework::seam_stubs::FolderItem;

/// Corresponds to a file which contains text data only and relies only on property file storage
/// (i.e., no separate database or data file).
///
/// Mirrors `ghidra.framework.store.TextDataItem`, which extends `FolderItem`.
pub trait TextDataItem: FolderItem {
    /// Get the text data that was stored with this item.
    fn get_text_data(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTextDataItem {
        text: String,
    }

    impl FolderItem for MockTextDataItem {}

    impl TextDataItem for MockTextDataItem {
        fn get_text_data(&self) -> String {
            self.text.clone()
        }
    }

    #[test]
    fn test_text_data_item_object_safety_and_dispatch() {
        let item: Box<dyn TextDataItem> = Box::new(MockTextDataItem {
            text: "hello world".to_string(),
        });

        assert_eq!(item.get_text_data(), "hello world");
    }
}
