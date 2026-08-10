//! Provider of highlight objects for listing fields.
//!
//! Port of `ghidra.app.util.ListingHighlightProvider`. This is a genuine open extension
//! point (four in-repo implementors), so it is ported as a trait.

use crate::app::seam_stubs::Highlight;
use crate::app::util::viewer::field::listing_field::ListingField;

/// A provider of highlight objects appropriate for listing fields.
///
/// `ListingHighlightProvider` implementations highlight specific portions of text in a listing
/// field based on the context (e.g., current selection, cursor position, matching syntax elements).
pub trait ListingHighlightProvider {
    /// Returns an empty array of highlights.
    const NO_HIGHLIGHTS: &'static [&'static dyn Highlight] = &[];

    /// Get the highlights appropriate for the given text.
    ///
    /// # Arguments
    ///
    /// * `text` - the entire text contained in the field, regardless of layout
    /// * `field` - the field being rendered. From this field you can get the field factory and
    ///   the proxy object, which is usually a `CodeUnit`.
    /// * `cursor_text_offset` - the cursor position within the given text or -1 if no cursor in
    ///   this field
    ///
    /// # Returns
    ///
    /// An array of highlight objects that indicate the location within the text string to
    /// be highlighted.
    fn create_highlights(
        &self,
        text: &str,
        field: &dyn ListingField,
        cursor_text_offset: i32,
    ) -> Vec<Box<dyn Highlight>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{Field, FieldFactory, FieldLocation, ProxyObj};

    struct MockHighlight {
        start: i32,
        end: i32,
    }

    impl Highlight for MockHighlight {
        fn get_start(&self) -> i32 {
            self.start
        }

        fn get_end(&self) -> i32 {
            self.end
        }

        fn length(&self) -> i32 {
            self.end - self.start
        }

        fn get_color(&self) -> Box<dyn crate::app::seam_stubs::Color> {
            Box::new(MockColor)
        }

        fn set_offset(&self, _new_offset: i32) {}

        fn to_string(&self) -> String {
            format!("Highlight[{}, {})", self.start, self.end)
        }
    }

    struct MockColor;

    impl crate::app::seam_stubs::Color for MockColor {}

    struct MockListingHighlightProvider;

    impl ListingHighlightProvider for MockListingHighlightProvider {
        fn create_highlights(
            &self,
            _text: &str,
            _field: &dyn ListingField,
            _cursor_text_offset: i32,
        ) -> Vec<Box<dyn Highlight>> {
            vec![Box::new(MockHighlight { start: 0, end: 5 })]
        }
    }

    struct MockFieldFactory;

    impl FieldFactory for MockFieldFactory {
        fn services_changed(&self) {}
        fn new_instance(
            &self,
            _format_model: &dyn std::any::Any,
            _highlight_provider: &dyn std::any::Any,
            _options: &dyn std::any::Any,
            _field_options: &dyn std::any::Any,
        ) -> Box<dyn FieldFactory> {
            Box::new(MockFieldFactory)
        }
        fn display_options_changed(
            &self,
            _options: &dyn std::any::Any,
            _option_name: &str,
            _old_value: &dyn std::any::Any,
            _new_value: &dyn std::any::Any,
        ) {
        }
        fn field_options_changed(
            &self,
            _options: &dyn std::any::Any,
            _option_name: &str,
            _old_value: &dyn std::any::Any,
            _new_value: &dyn std::any::Any,
        ) {
        }
        fn get_field_name(&self) -> String {
            "MockField".to_string()
        }
        fn get_start_x(&self) -> i32 {
            0
        }
        fn set_start_x(&self, _x: i32) {}
        fn get_width(&self) -> i32 {
            100
        }
        fn set_width(&self, _w: i32) {}
        fn get_field_model(&self) -> Box<dyn std::any::Any> {
            Box::new("mock_model")
        }
        fn is_enabled(&self) -> bool {
            true
        }
        fn set_enabled(&self, _state: bool) {}
        fn supports_location(
            &self,
            _listing_field: &dyn std::any::Any,
            _location: &dyn std::any::Any,
        ) -> bool {
            true
        }
        fn get_field(&self, _obj: &dyn ProxyObj, _var_width: i32) -> Box<dyn std::any::Any> {
            Box::new("mock_field")
        }
        fn get_field_location(
            &self,
            _bf: &dyn std::any::Any,
            _index: &dyn std::any::Any,
            _field_num: i32,
            _loc: &dyn std::any::Any,
        ) -> Box<dyn FieldLocation> {
            Box::new(MockFieldLocation)
        }
        fn get_program_location(
            &self,
            _row: i32,
            _col: i32,
            _bf: &dyn std::any::Any,
        ) -> Box<dyn std::any::Any> {
            Box::new("mock_location")
        }
        fn accepts_type(
            &self,
            _category: i32,
            _proxy_object_class: &dyn crate::app::seam_stubs::Class,
        ) -> bool {
            true
        }
        fn get_field_text(&self) -> String {
            "MockFieldText".to_string()
        }
        fn get_metrics(&self) -> Box<dyn std::any::Any> {
            Box::new("mock_metrics")
        }
    }

    struct MockProxyObj;

    impl ProxyObj for MockProxyObj {
        fn get_listing_layout_model(
            &self,
        ) -> Box<dyn crate::app::util::viewer::listingpanel::listing_model::ListingModel> {
            unimplemented!("mock")
        }
        fn get_object(&self) -> Box<dyn std::any::Any> {
            Box::new("mock_object")
        }
        fn contains(&self, _a: &dyn std::any::Any) -> bool {
            true
        }
    }

    struct MockFieldLocation;

    impl FieldLocation for MockFieldLocation {
        fn get_index(&self) -> Box<dyn std::any::Any> {
            Box::new(0i32)
        }
        fn get_field_num(&self) -> i32 {
            0
        }
        fn get_row(&self) -> i32 {
            0
        }
        fn get_col(&self) -> i32 {
            0
        }
        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            true
        }
        fn compare_to(&self, _o: &dyn FieldLocation) -> i32 {
            0
        }
        fn hash_code(&self) -> i32 {
            42
        }
        fn to_string(&self) -> String {
            "MockFieldLocation".to_string()
        }
        fn get_element(&self, _name: &str) -> Box<dyn std::any::Any> {
            Box::new("mock_element")
        }
        fn set(&self, _loc: &dyn FieldLocation) {}
        fn set_index(&self, _index: &dyn std::any::Any) {}
    }

    struct MockField;

    impl Field for MockField {
        fn get_width(&self) -> i32 {
            100
        }
        fn get_preferred_width(&self) -> i32 {
            100
        }
        fn get_height(&self) -> i32 {
            20
        }
        fn get_height_above(&self) -> i32 {
            10
        }
        fn get_height_below(&self) -> i32 {
            10
        }
        fn get_start_x(&self) -> i32 {
            0
        }
        fn paint(
            &self,
            _c: &dyn std::any::Any,
            _g: &dyn std::any::Any,
            _context: &dyn std::any::Any,
            _clip: &dyn std::any::Any,
            _color_manager: &dyn std::any::Any,
            _cursor_loc: &dyn std::any::Any,
            _row_height: i32,
        ) {
        }
        fn contains(&self, _x: i32, _y: i32) -> bool {
            true
        }
        fn get_num_data_rows(&self) -> i32 {
            1
        }
        fn get_num_rows(&self) -> i32 {
            1
        }
        fn get_num_cols(&self, _row: i32) -> i32 {
            10
        }
        fn get_x(&self, _row: i32, _col: i32) -> i32 {
            0
        }
        fn get_y(&self, _row: i32) -> i32 {
            0
        }
        fn get_row(&self, _y: i32) -> i32 {
            0
        }
        fn get_col(&self, _row: i32, _x: i32) -> i32 {
            0
        }
        fn is_valid(&self, _row: i32, _col: i32) -> bool {
            true
        }
        fn get_cursor_bounds(&self, _row: i32, _col: i32) -> Box<dyn std::any::Any> {
            Box::new("mock")
        }
        fn get_scrollable_unit_increment(
            &self,
            _top_of_screen: i32,
            _direction: i32,
            _max: i32,
        ) -> i32 {
            10
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn row_height_changed(&self, _height_above: i32, _height_below: i32) {}
        fn get_text(&self) -> String {
            "MockField".to_string()
        }
        fn get_text_with_line_separators(&self) -> String {
            "MockField".to_string()
        }
        fn text_offset_to_screen_location(&self, _text_offset: i32) -> Box<dyn std::any::Any> {
            Box::new("mock")
        }
        fn screen_location_to_text_offset(&self, _row: i32, _col: i32) -> i32 {
            0
        }
    }

    struct MockListingField;

    impl Field for MockListingField {
        fn get_width(&self) -> i32 {
            100
        }
        fn get_preferred_width(&self) -> i32 {
            100
        }
        fn get_height(&self) -> i32 {
            20
        }
        fn get_height_above(&self) -> i32 {
            10
        }
        fn get_height_below(&self) -> i32 {
            10
        }
        fn get_start_x(&self) -> i32 {
            0
        }
        fn paint(
            &self,
            _c: &dyn std::any::Any,
            _g: &dyn std::any::Any,
            _context: &dyn std::any::Any,
            _clip: &dyn std::any::Any,
            _color_manager: &dyn std::any::Any,
            _cursor_loc: &dyn std::any::Any,
            _row_height: i32,
        ) {
        }
        fn contains(&self, _x: i32, _y: i32) -> bool {
            true
        }
        fn get_num_data_rows(&self) -> i32 {
            1
        }
        fn get_num_rows(&self) -> i32 {
            1
        }
        fn get_num_cols(&self, _row: i32) -> i32 {
            10
        }
        fn get_x(&self, _row: i32, _col: i32) -> i32 {
            0
        }
        fn get_y(&self, _row: i32) -> i32 {
            0
        }
        fn get_row(&self, _y: i32) -> i32 {
            0
        }
        fn get_col(&self, _row: i32, _x: i32) -> i32 {
            0
        }
        fn is_valid(&self, _row: i32, _col: i32) -> bool {
            true
        }
        fn get_cursor_bounds(&self, _row: i32, _col: i32) -> Box<dyn std::any::Any> {
            Box::new("mock")
        }
        fn get_scrollable_unit_increment(
            &self,
            _top_of_screen: i32,
            _direction: i32,
            _max: i32,
        ) -> i32 {
            10
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn row_height_changed(&self, _height_above: i32, _height_below: i32) {}
        fn get_text(&self) -> String {
            "MockListingField".to_string()
        }
        fn get_text_with_line_separators(&self) -> String {
            "MockListingField".to_string()
        }
        fn text_offset_to_screen_location(&self, _text_offset: i32) -> Box<dyn std::any::Any> {
            Box::new("mock")
        }
        fn screen_location_to_text_offset(&self, _row: i32, _col: i32) -> i32 {
            0
        }
    }

    impl ListingField for MockListingField {
        fn get_field_factory(&self) -> Box<dyn FieldFactory> {
            Box::new(MockFieldFactory)
        }

        fn get_proxy(&self) -> Box<dyn ProxyObj> {
            Box::new(MockProxyObj)
        }

        fn get_clicked_object(&self, _field_location: &dyn FieldLocation) -> Box<dyn std::any::Any> {
            Box::new("clicked_object")
        }
    }

    #[test]
    fn test_listing_highlight_provider_creates_highlights() {
        let provider = MockListingHighlightProvider;
        let field = MockListingField;
        let text = "example text";

        let highlights = provider.create_highlights(text, &field, 5);

        assert_eq!(highlights.len(), 1);
        assert_eq!(highlights[0].get_start(), 0);
        assert_eq!(highlights[0].get_end(), 5);
        assert_eq!(highlights[0].length(), 5);
    }

    #[test]
    fn test_highlight_span_methods() {
        let highlight = MockHighlight { start: 2, end: 7 };

        assert_eq!(highlight.get_start(), 2);
        assert_eq!(highlight.get_end(), 7);
        assert_eq!(highlight.length(), 5);
    }

    #[test]
    fn test_highlight_to_string() {
        let highlight = MockHighlight { start: 10, end: 15 };
        let s = highlight.to_string();
        assert!(s.contains("10"));
        assert!(s.contains("15"));
    }
}
