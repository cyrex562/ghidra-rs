//! Service for controlling the Watches window.
//!
//! Port of `ghidra.app.services.DebuggerWatchesService`.
//! The Java `@ServiceInfo` annotation (default provider
//! `ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesPlugin`) has no Rust equivalent and is omitted.

use crate::debug::api::watch::watch_row::WatchRow;

/// A service interface for controlling the Watches window.
///
/// Port of `ghidra.app.services.DebuggerWatchesService`.
pub trait DebuggerWatchesService {
    /// Add a watch.
    ///
    /// # Arguments
    ///
    /// * `expression` - the Sleigh expression
    ///
    /// # Returns
    ///
    /// The new row.
    ///
    /// Port of `DebuggerWatchesService.addWatch(String)`.
    fn add_watch(&mut self, expression: &str) -> Box<dyn WatchRow>;

    /// Remove a watch.
    ///
    /// # Arguments
    ///
    /// * `watch` - the row to remove
    ///
    /// Port of `DebuggerWatchesService.removeWatch(WatchRow)`.
    fn remove_watch(&mut self, watch: &dyn WatchRow);

    /// Get the current watches.
    ///
    /// # Returns
    ///
    /// The unmodifiable collection of watches.
    ///
    /// Port of `DebuggerWatchesService.getWatches()`.
    fn get_watches(&self) -> Vec<Box<dyn WatchRow>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressRange, AddressSetView};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::symbol::Symbol;

    #[derive(Default, Clone)]
    struct MockSettings;

    impl Settings for MockSettings {}

    #[derive(Default, Clone)]
    struct MockWatchRow {
        expression: String,
        settings: MockSettings,
    }

    impl WatchRow for MockWatchRow {
        fn get_expression(&self) -> String {
            self.expression.clone()
        }

        fn set_expression(&mut self, expression: &str) {
            self.expression = expression.to_string();
        }

        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_data_type(&mut self, _data_type: Option<Box<dyn DataType>>) {}

        fn get_settings(&mut self) -> &mut dyn Settings {
            &mut self.settings
        }

        fn settings_changed(&mut self) {}

        fn get_address(&self) -> Option<Address> {
            None
        }

        fn get_range(&self) -> Option<AddressRange> {
            None
        }

        fn get_reads(&self) -> Option<Box<dyn AddressSetView>> {
            None
        }

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_value(&self) -> Option<Vec<u8>> {
            None
        }

        fn get_raw_value_string(&self) -> Option<String> {
            None
        }

        fn get_value_length(&self) -> i32 {
            0
        }

        fn set_raw_value_string(&mut self, _value: &str) {}

        fn is_raw_value_editable(&self) -> bool {
            false
        }

        fn get_value_object(&self) -> Option<Box<dyn Any>> {
            None
        }

        fn get_value_string(&self) -> Option<String> {
            None
        }

        fn set_value_string(&mut self, _value: &str) {}

        fn is_value_editable(&self) -> bool {
            false
        }

        fn get_error(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
            None
        }

        fn get_error_message(&self) -> String {
            String::new()
        }

        fn is_known(&self) -> bool {
            false
        }

        fn is_changed(&self) -> bool {
            false
        }

        fn get_comment(&self) -> String {
            String::new()
        }

        fn set_comment(&mut self, _comment: &str) {}
    }

    struct MockDebuggerWatchesService {
        watches: Vec<Box<dyn WatchRow>>,
    }

    impl DebuggerWatchesService for MockDebuggerWatchesService {
        fn add_watch(&mut self, expression: &str) -> Box<dyn WatchRow> {
            let watch = Box::new(MockWatchRow {
                expression: expression.to_string(),
                ..Default::default()
            });
            self.watches.push(Box::new(MockWatchRow {
                expression: expression.to_string(),
                ..Default::default()
            }));
            watch
        }

        fn remove_watch(&mut self, watch: &dyn WatchRow) {
            self.watches.retain(|w| w.get_expression() != watch.get_expression());
        }

        fn get_watches(&self) -> Vec<Box<dyn WatchRow>> {
            self.watches
                .iter()
                .map(|w| {
                    Box::new(MockWatchRow {
                        expression: w.get_expression(),
                        ..Default::default()
                    }) as Box<dyn WatchRow>
                })
                .collect()
        }
    }

    #[test]
    fn add_watch_creates_and_returns_new_row() {
        let mut service = MockDebuggerWatchesService {
            watches: Vec::new(),
        };
        let row = service.add_watch("RAX");
        assert_eq!(row.get_expression(), "RAX");
    }

    #[test]
    fn add_watch_increases_watch_count() {
        let mut service = MockDebuggerWatchesService {
            watches: Vec::new(),
        };
        assert_eq!(service.get_watches().len(), 0);
        service.add_watch("RAX");
        assert_eq!(service.get_watches().len(), 1);
        service.add_watch("RBX");
        assert_eq!(service.get_watches().len(), 2);
    }

    #[test]
    fn get_watches_returns_current_watches() {
        let mut service = MockDebuggerWatchesService {
            watches: Vec::new(),
        };
        service.add_watch("RAX");
        service.add_watch("RBX");
        let watches = service.get_watches();
        assert_eq!(watches.len(), 2);
        assert_eq!(watches[0].get_expression(), "RAX");
        assert_eq!(watches[1].get_expression(), "RBX");
    }

    #[test]
    fn remove_watch_decreases_watch_count() {
        let mut service = MockDebuggerWatchesService {
            watches: Vec::new(),
        };
        let row1 = service.add_watch("RAX");
        service.add_watch("RBX");
        assert_eq!(service.get_watches().len(), 2);
        service.remove_watch(row1.as_ref());
        assert_eq!(service.get_watches().len(), 1);
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerWatchesService> = Box::new(MockDebuggerWatchesService {
            watches: Vec::new(),
        });
        let row = service.add_watch("RAX");
        assert_eq!(row.get_expression(), "RAX");
        let watches = service.get_watches();
        assert_eq!(watches.len(), 1);
    }
}
