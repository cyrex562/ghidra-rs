/// Holds a list item and the rendering metadata needed to display it correctly.
///
/// Corresponds to `docking.widgets.searchlist.SearchListEntry`.
///
/// `T` is the type of list items. `category` is the group label, `show_category`
/// is `true` only for the first item in a category (triggering the header to be
/// drawn), and `draw_separator` is `true` for the last item in a non-final
/// category (triggering a divider line below the entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchListEntry<T> {
    pub value: T,
    pub category: String,
    pub show_category: bool,
    pub draw_separator: bool,
}

impl<T> SearchListEntry<T> {
    pub fn new(value: T, category: impl Into<String>, show_category: bool, draw_separator: bool) -> Self {
        Self {
            value,
            category: category.into(),
            show_category,
            draw_separator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_roundtrip() {
        let entry = SearchListEntry::new(42u32, "Numbers", true, false);
        assert_eq!(entry.value, 42);
        assert_eq!(entry.category, "Numbers");
        assert!(entry.show_category);
        assert!(!entry.draw_separator);
    }

    #[test]
    fn draw_separator_set() {
        let entry = SearchListEntry::new("hello", "Strings", false, true);
        assert!(!entry.show_category);
        assert!(entry.draw_separator);
    }

    #[test]
    fn category_owned_string() {
        let cat = String::from("MyCategory");
        let entry = SearchListEntry::new(0i32, cat.clone(), true, true);
        assert_eq!(entry.category, cat);
    }

    #[test]
    fn clone_produces_equal_entry() {
        let entry = SearchListEntry::new(7u8, "A", true, false);
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn first_item_in_category_shows_header() {
        let first = SearchListEntry::new("item", "Cat", true, false);
        let second = SearchListEntry::new("item2", "Cat", false, true);
        assert!(first.show_category);
        assert!(!second.show_category);
    }

    #[test]
    fn last_item_in_non_final_category_draws_separator() {
        let last_in_cat = SearchListEntry::new("z", "Cat", false, true);
        assert!(last_in_cat.draw_separator);
    }
}
