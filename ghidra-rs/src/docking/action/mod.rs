pub mod docking_action;
pub mod docking_action_if;
pub mod key_binding_data;
pub mod key_bindings_manager;
pub mod key_binding_type;
pub mod menu_data;
pub mod multi_action_docking_action_if;
pub mod tool_bar_data;
#[cfg(test)]
pub(crate) mod tests_support;
pub mod toggle_docking_action_if;

pub use key_binding_data::{KeyBindingData, KeyBindingError};
pub use key_binding_type::KeyBindingType;
pub use menu_data::{MenuData, MenuDataError, NO_SUBGROUP};
pub use tool_bar_data::ToolBarData;
pub use docking_action::{is_context_applicable, ActionChange, ActionId, ContextPredicate, DockingAction};
pub use docking_action_if::DockingActionIf;
pub use toggle_docking_action_if::{ToggleDockingActionIf, ToggleState};
pub use multi_action_docking_action_if::MultiActionDockingActionIf;
pub use key_bindings_manager::{DispatchResult, KeyBindingsManager};
