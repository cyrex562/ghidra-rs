use std::io::Write;

use crate::util::task::TaskMonitor;
use crate::util::exception::CancelledException;
use crate::program::model::data::isf::{AbstractIsfWriterState, IsfWriterImpl};

/// Trait for types that implement extended SARIF export writer behavior.
///
/// Mirrors the abstract `AbstractExtWriter` from Ghidra's SARIF export module.
/// Implementations are similar to [`IsfWriterImpl`] but with `strict` mode disabled
/// to allow more flexible serialization. Concrete exporters (e.g., for bookmarks,
/// code blocks) implement this trait to generate SARIF-formatted output.
///
/// The main difference from [`IsfWriterImpl`] is that `strict` is set to `false`
/// by default, controlled via [`new_ext_writer_state`].
pub trait AbstractExtWriter: IsfWriterImpl {}

/// Creates a new writer state with non-strict mode enabled.
///
/// Initializes [`AbstractIsfWriterState`] with `strict = false`, matching the
/// behavior of the Java `AbstractExtWriter` constructor which sets `STRICT = false`.
/// This allows more flexible serialization during SARIF export.
///
/// # Arguments
///
/// * `base_writer` - Optional output writer for serialization.
///
/// # Returns
///
/// A new [`AbstractIsfWriterState`] with `strict` disabled.
pub fn new_ext_writer_state(base_writer: Option<Box<dyn Write>>) -> AbstractIsfWriterState {
    let mut state = AbstractIsfWriterState::new(base_writer);
    state.strict = false;
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TestExtWriter {
        state: AbstractIsfWriterState,
    }

    impl IsfWriterImpl for TestExtWriter {
        fn gen_root(&mut self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            self.state.root = json!({ "test": "ext_value" });
            Ok(())
        }

        fn state_mut(&mut self) -> &mut AbstractIsfWriterState {
            &mut self.state
        }
    }

    impl AbstractExtWriter for TestExtWriter {}

    #[test]
    fn creates_state_with_strict_false() {
        let state = new_ext_writer_state(None);
        assert!(!state.strict);
    }

    #[test]
    fn creates_state_with_empty_root() {
        let state = new_ext_writer_state(None);
        assert_eq!(state.root, json!({}));
    }

    #[test]
    fn creates_state_with_empty_objects_array() {
        let state = new_ext_writer_state(None);
        assert_eq!(state.objects, json!([]));
    }

    #[test]
    fn abstract_ext_writer_implements_isf_writer() {
        let mut writer = TestExtWriter {
            state: new_ext_writer_state(None),
        };
        let dummy_monitor = crate::util::task::DummyMonitor;
        let root = writer.get_root_object(&dummy_monitor).unwrap();
        assert_eq!(root, json!({ "test": "ext_value" }));
    }

    #[test]
    fn state_is_non_strict_by_default() {
        let mut writer = TestExtWriter {
            state: new_ext_writer_state(None),
        };
        assert!(!writer.state_mut().strict);
    }

    #[test]
    fn get_results_returns_empty_array_initially() {
        let mut writer = TestExtWriter {
            state: new_ext_writer_state(None),
        };
        let results = writer.get_results();
        assert_eq!(results, json!([]));
    }

    #[test]
    fn can_use_writer_methods_with_ext_writer_state() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = TestExtWriter {
            state: new_ext_writer_state(Some(Box::new(buffer))),
        };
        let obj = json!({ "key": "value" });
        assert!(writer.write(&obj).is_ok());
    }

    #[test]
    fn close_succeeds_with_ext_writer_state() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = TestExtWriter {
            state: new_ext_writer_state(Some(Box::new(buffer))),
        };
        assert!(writer.close().is_ok());
    }
}
