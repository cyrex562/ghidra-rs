pub mod comparison_item;
pub mod comparison_item_layout;
pub mod coordinated_structure_line;
pub mod display_coordinator;

pub use comparison_item::{ComparisonItem, ItemApplyState, MAX_COLS};
pub use comparison_item_layout::{ColumnWidths, ComparisonItemLayout, HGAP};
pub use coordinated_structure_line::{
    CompareId, CoordinatedStructureLine, CoordinatedStructureModel,
};
pub use display_coordinator::{CoordinatedStructureDisplay, DisplayCoordinator};
