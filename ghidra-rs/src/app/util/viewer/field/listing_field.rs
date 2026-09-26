//! A field that extends `Field` to add listing-specific information.
//!
//! Port of `ghidra.app.util.viewer.field.ListingField`. This is a genuine open extension
//! point (four in-repo implementors), so it is ported as a trait.
//!
//! `ListingField` extends the `Field` interface to add information that the browser needs from
//! the fields, such as the factory that created them and the proxy object they represent.

use crate::app::seam_stubs::{Field, FieldFactory, FieldLocation, ProxyObj};

/// A field that extends `Field` to add listing-specific information.
///
/// Port of `ghidra.app.util.viewer.field.ListingField`.
pub trait ListingField: Field {
    /// Returns the `FieldFactory` that generated this field.
    fn get_field_factory(&self) -> Box<dyn FieldFactory>;

    /// Returns the object that the field factory used to generate the information in this field.
    fn get_proxy(&self) -> Box<dyn ProxyObj>;

    /// Returns the object that was clicked on a field for the given field location.
    /// This may be the field itself or a lower-level entity, such as a `FieldElement`.
    fn get_clicked_object(&self, field_location: &dyn FieldLocation) -> Box<dyn std::any::Any>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of FieldFactory for testing.
    struct MockFieldFactory;

    impl FieldFactory for MockFieldFactory {
        fn services_changed(&self) {}
        fn new_instance(&self, _format_model: &dyn std::any::Any, _highlight_provider: &dyn std::any::Any, _options: &dyn std::any::Any, _field_options: &dyn std::any::Any) -> Box<dyn FieldFactory> {
            Box::new(MockFieldFactory)
        }
        fn display_options_changed(&self, _options: &dyn std::any::Any, _option_name: &str, _old_value: &dyn std::any::Any, _new_value: &dyn std::any::Any) {}
        fn field_options_changed(&self, _options: &dyn std::any::Any, _option_name: &str, _old_value: &dyn std::any::Any, _new_value: &dyn std::any::Any) {}
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
        fn supports_location(&self, _listing_field: &dyn std::any::Any, _location: &dyn std::any::Any) -> bool {
            true
        }
        fn get_field(&self, _obj: &dyn ProxyObj, _var_width: i32) -> Box<dyn std::any::Any> {
            Box::new("mock_field")
        }
        fn get_field_location(&self, _bf: &dyn std::any::Any, _index: &dyn std::any::Any, _field_num: i32, _loc: &dyn std::any::Any) -> Box<dyn FieldLocation> {
            Box::new(MockFieldLocation)
        }
        fn get_program_location(&self, _row: i32, _col: i32, _bf: &dyn std::any::Any) -> Box<dyn std::any::Any> {
            Box::new("mock_location")
        }
        fn accepts_type(&self, _category: i32, _proxy_object_class: &dyn crate::app::seam_stubs::Class) -> bool {
            true
        }
        fn get_field_text(&self) -> String {
            "MockFieldText".to_string()
        }
        fn get_metrics(&self) -> Box<dyn std::any::Any> {
            Box::new("mock_metrics")
        }
    }

    /// Mock implementation of ProxyObj for testing.
    struct MockProxyObj;

    impl ProxyObj for MockProxyObj {
        fn get_listing_layout_model(&self) -> Box<dyn crate::app::util::viewer::listingpanel::listing_model::ListingModel> {
            unimplemented!("mock")
        }
        fn get_object(&self) -> Box<dyn std::any::Any> {
            Box::new("mock_object")
        }
        fn contains(&self, _a: &dyn std::any::Any) -> bool {
            true
        }
    }

    /// Mock implementation of FieldLocation for testing.
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

    /// Mock implementation of Field for testing.
    struct MockField;

    impl Field for MockField {
        fn get_width(&self) -> i32 { 100 }
        fn get_preferred_width(&self) -> i32 { 100 }
        fn get_height(&self) -> i32 { 20 }
        fn get_height_above(&self) -> i32 { 10 }
        fn get_height_below(&self) -> i32 { 10 }
        fn get_start_x(&self) -> i32 { 0 }
        fn paint(&self, _c: &dyn std::any::Any, _g: &dyn std::any::Any, _context: &dyn std::any::Any, _clip: &dyn std::any::Any, _color_manager: &dyn std::any::Any, _cursor_loc: &dyn std::any::Any, _row_height: i32) {}
        fn contains(&self, _x: i32, _y: i32) -> bool { true }
        fn get_num_data_rows(&self) -> i32 { 1 }
        fn get_num_rows(&self) -> i32 { 1 }
        fn get_num_cols(&self, _row: i32) -> i32 { 10 }
        fn get_x(&self, _row: i32, _col: i32) -> i32 { 0 }
        fn get_y(&self, _row: i32) -> i32 { 0 }
        fn get_row(&self, _y: i32) -> i32 { 0 }
        fn get_col(&self, _row: i32, _x: i32) -> i32 { 0 }
        fn is_valid(&self, _row: i32, _col: i32) -> bool { true }
        fn get_cursor_bounds(&self, _row: i32, _col: i32) -> Box<dyn std::any::Any> { Box::new("mock") }
        fn get_scrollable_unit_increment(&self, _top_of_screen: i32, _direction: i32, _max: i32) -> i32 { 10 }
        fn is_primary(&self) -> bool { true }
        fn row_height_changed(&self, _height_above: i32, _height_below: i32) {}
        fn get_text(&self) -> String { "MockField".to_string() }
        fn get_text_with_line_separators(&self) -> String { "MockField".to_string() }
        fn text_offset_to_screen_location(&self, _text_offset: i32) -> Box<dyn std::any::Any> { Box::new("mock") }
        fn screen_location_to_text_offset(&self, _row: i32, _col: i32) -> i32 { 0 }
    }

    /// Mock implementation of ListingField for testing.
    struct MockListingField;

    impl Field for MockListingField {
        fn get_width(&self) -> i32 { 100 }
        fn get_preferred_width(&self) -> i32 { 100 }
        fn get_height(&self) -> i32 { 20 }
        fn get_height_above(&self) -> i32 { 10 }
        fn get_height_below(&self) -> i32 { 10 }
        fn get_start_x(&self) -> i32 { 0 }
        fn paint(&self, _c: &dyn std::any::Any, _g: &dyn std::any::Any, _context: &dyn std::any::Any, _clip: &dyn std::any::Any, _color_manager: &dyn std::any::Any, _cursor_loc: &dyn std::any::Any, _row_height: i32) {}
        fn contains(&self, _x: i32, _y: i32) -> bool { true }
        fn get_num_data_rows(&self) -> i32 { 1 }
        fn get_num_rows(&self) -> i32 { 1 }
        fn get_num_cols(&self, _row: i32) -> i32 { 10 }
        fn get_x(&self, _row: i32, _col: i32) -> i32 { 0 }
        fn get_y(&self, _row: i32) -> i32 { 0 }
        fn get_row(&self, _y: i32) -> i32 { 0 }
        fn get_col(&self, _row: i32, _x: i32) -> i32 { 0 }
        fn is_valid(&self, _row: i32, _col: i32) -> bool { true }
        fn get_cursor_bounds(&self, _row: i32, _col: i32) -> Box<dyn std::any::Any> { Box::new("mock") }
        fn get_scrollable_unit_increment(&self, _top_of_screen: i32, _direction: i32, _max: i32) -> i32 { 10 }
        fn is_primary(&self) -> bool { true }
        fn row_height_changed(&self, _height_above: i32, _height_below: i32) {}
        fn get_text(&self) -> String { "MockListingField".to_string() }
        fn get_text_with_line_separators(&self) -> String { "MockListingField".to_string() }
        fn text_offset_to_screen_location(&self, _text_offset: i32) -> Box<dyn std::any::Any> { Box::new("mock") }
        fn screen_location_to_text_offset(&self, _row: i32, _col: i32) -> i32 { 0 }
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
    fn test_listing_field_trait_implementation() {
        let mock_field = MockListingField;

        let factory = mock_field.get_field_factory();
        assert_eq!(factory.get_field_name(), "MockField");

        let proxy = mock_field.get_proxy();
        let obj = proxy.get_object();
        assert_eq!(obj.downcast_ref::<&str>(), Some(&"mock_object"));

        let location = MockFieldLocation;
        let clicked = mock_field.get_clicked_object(&location);
        assert_eq!(clicked.downcast_ref::<&str>(), Some(&"clicked_object"));
    }

    #[test]
    fn test_listing_field_field_trait_methods() {
        let mock_field = MockListingField;

        assert_eq!(mock_field.get_width(), 100);
        assert_eq!(mock_field.get_preferred_width(), 100);
        assert_eq!(mock_field.get_height(), 20);
        assert_eq!(mock_field.get_height_above(), 10);
        assert_eq!(mock_field.get_height_below(), 10);
        assert_eq!(mock_field.get_start_x(), 0);
        assert!(mock_field.contains(50, 10));
        assert_eq!(mock_field.get_num_data_rows(), 1);
        assert_eq!(mock_field.get_num_rows(), 1);
        assert_eq!(mock_field.get_text(), "MockListingField");
    }
}
