use std::io::Write;

use serde::{Serialize, Deserialize};
use serde_json::{Value as JsonValue, json};

use crate::util::task::TaskMonitor;
use crate::util::exception::CancelledException;

/// Trait for types that implement ISF writer behavior.
///
/// Mirrors the abstract `AbstractIsfWriter` from Ghidra's Debugger-isf module.
/// Implementations must define [`gen_root`](IsfWriterImpl::gen_root) to populate
/// the root object. Helper methods manage JSON serialization and I/O.
pub trait IsfWriterImpl: Sized {
    /// Generates the root object.
    ///
    /// Implementations populate the root object with appropriate data.
    /// Called by `get_root_object` before returning the root.
    fn gen_root(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;

    /// Returns a mutable reference to the writer state.
    ///
    /// Used internally by methods that need access to root, objects, and the
    /// output writer.
    fn state_mut(&mut self) -> &mut AbstractIsfWriterState;

    /// Gets the root object after calling `gen_root`.
    ///
    /// Mirrors `getRootObject(TaskMonitor)` from Java. Calls the implementation's
    /// [`gen_root`](IsfWriterImpl::gen_root) to populate the root, then returns it.
    fn get_root_object(&mut self, monitor: &dyn TaskMonitor) -> Result<JsonValue, CancelledException> {
        self.gen_root(monitor)?;
        let state = self.state_mut();
        Ok(state.root.clone())
    }

    /// Returns the results array.
    ///
    /// Mirrors `getResults()` from Java. Returns the accumulated objects array.
    fn get_results(&mut self) -> JsonValue {
        self.state_mut().objects.clone()
    }

    /// Serializes an object to JSON using serde.
    ///
    /// Mirrors `getTree(Object obj)` from Java. Converts the given object to a
    /// JSON tree representation.
    fn get_tree<T: Serialize>(&mut self, obj: &T) -> Result<JsonValue, serde_json::Error> {
        serde_json::to_value(obj)
    }

    /// Deserializes JSON to an object of the given type.
    ///
    /// Mirrors `getObject(JsonElement element, Class<?> clazz)` from Java.
    /// Converts a JSON value to the specified type using serde.
    fn get_object<T: for<'de> Deserialize<'de>>(
        &mut self,
        element: &JsonValue,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_value(element.clone())
    }

    /// Writes a JSON object to the output writer.
    ///
    /// Mirrors `write(JsonObject object)` from Java. Serializes the object to
    /// JSON and writes it to the configured writer.
    fn write(&mut self, object: &JsonValue) -> Result<(), std::io::Error> {
        let state = self.state_mut();
        if let Some(ref mut writer) = state.writer {
            let json_str = serde_json::to_string_pretty(object)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            writer.write_all(json_str.as_bytes())?;
        }
        Ok(())
    }

    /// Closes the output writer.
    ///
    /// Mirrors `close()` from Java. Flushes and closes the underlying writer
    /// if present. Safe to call multiple times.
    fn close(&mut self) -> Result<(), std::io::Error> {
        let state = self.state_mut();
        if let Some(ref mut writer) = state.writer {
            writer.flush()?;
        }
        state.writer = None;
        Ok(())
    }
}

/// Shared state for ISF writer implementations.
///
/// Holds the JSON root object, results array, and output writer.
pub struct AbstractIsfWriterState {
    pub writer: Option<Box<dyn Write>>,
    pub root: JsonValue,
    pub objects: JsonValue,
    pub strict: bool,
}

impl AbstractIsfWriterState {
    /// Creates a new writer state with optional output writer.
    ///
    /// Initializes `root` to an empty object and `objects` to an empty array.
    /// If `base_writer` is provided, it will be used for output; otherwise,
    /// serialization methods that use the writer will no-op.
    pub fn new(base_writer: Option<Box<dyn Write>>) -> Self {
        Self {
            writer: base_writer,
            root: json!({}),
            objects: json!([]),
            strict: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestWriter {
        state: AbstractIsfWriterState,
    }

    impl IsfWriterImpl for TestWriter {
        fn gen_root(&mut self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            self.state.root = json!({ "test": "value" });
            Ok(())
        }

        fn state_mut(&mut self) -> &mut AbstractIsfWriterState {
            &mut self.state
        }
    }

    #[test]
    fn creates_new_state_with_empty_root_and_objects() {
        let state = AbstractIsfWriterState::new(None);
        assert_eq!(state.root, json!({}));
        assert_eq!(state.objects, json!([]));
        assert!(state.strict);
    }

    #[test]
    fn implements_isf_writer_trait() {
        let mut writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        let dummy_monitor = crate::util::task::DummyMonitor;
        let root = writer.get_root_object(&dummy_monitor).unwrap();
        assert_eq!(root, json!({ "test": "value" }));
    }

    #[test]
    fn serializes_object_to_tree() {
        #[derive(Serialize)]
        struct TestObj {
            name: String,
            value: i32,
        }

        let writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        let obj = TestObj {
            name: "test".to_string(),
            value: 42,
        };
        let tree = writer.get_tree(&obj).unwrap();
        assert_eq!(tree["name"], "test");
        assert_eq!(tree["value"], 42);
    }

    #[test]
    fn deserializes_json_to_object() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct TestObj {
            name: String,
            value: i32,
        }

        let writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        let json = json!({ "name": "test", "value": 42 });
        let obj: TestObj = writer.get_object(&json).unwrap();
        assert_eq!(obj.name, "test");
        assert_eq!(obj.value, 42);
    }

    #[test]
    fn get_results_returns_objects_array() {
        let writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        let results = writer.get_results();
        assert_eq!(results, json!([]));
    }

    #[test]
    fn close_succeeds_without_writer() {
        let mut writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        writer.close().unwrap();
    }

    #[test]
    fn write_succeeds_without_writer() {
        let mut writer = TestWriter {
            state: AbstractIsfWriterState::new(None),
        };
        let obj = json!({ "test": "value" });
        writer.write(&obj).unwrap();
    }

    #[test]
    fn write_to_buffer_succeeds() {
        let buffer: Vec<u8> = Vec::new();
        let mut writer = TestWriter {
            state: AbstractIsfWriterState::new(Some(Box::new(buffer))),
        };
        let obj = json!({ "test": "value" });
        writer.write(&obj).unwrap();
    }
}
