//! Port of `ghidra.app.util.bin.format.golang.rtti.JsonPatchApplier`.

use std::io;
use std::path::Path;

use serde_json::{Map, Value};

use super::json_patch::{JsonPatch, PatchOp, PatchSection};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

const ROOT_ELEM_NAME: &str = "rootElement";

/// Error from applying a patch: an I/O (bad patch / mismatched json) error, or cancellation.
#[derive(Debug)]
pub enum JsonPatchError {
    /// Java `IOException`.
    Io(io::Error),
    /// Java `CancelledException`.
    Cancelled(CancelledException),
}

impl std::fmt::Display for JsonPatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonPatchError::Io(e) => write!(f, "{e}"),
            JsonPatchError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for JsonPatchError {}

impl From<io::Error> for JsonPatchError {
    fn from(e: io::Error) -> Self {
        JsonPatchError::Io(e)
    }
}

impl From<CancelledException> for JsonPatchError {
    fn from(e: CancelledException) -> Self {
        JsonPatchError::Cancelled(e)
    }
}

/// Simplistic implementation, applies a json diff (see <https://github.com/josephburnett/jd>)
/// to an in memory json element to create a new json value.
///
/// Does not use any context hints in the diff to correct for mismatches, hence should only be
/// used against the exact original value to produce the new value, useful for compressing json
/// files that are derived from each other.
pub struct JsonPatchApplier {
    /// `{ "rootElement": json }`, so a bare (non-container) value can be patched too.
    root_container: Value,
}

impl JsonPatchApplier {
    /// `JsonPatchApplier(JsonElement)`.
    pub fn new(json: Value) -> Self {
        let mut m = Map::new();
        m.insert(ROOT_ELEM_NAME.to_string(), json);
        JsonPatchApplier { root_container: Value::Object(m) }
    }

    /// `JsonPatchApplier(File)`: reads the json to patch from a file.
    ///
    /// # Errors
    /// Error reading or parsing the file.
    pub fn from_file(base_file: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(base_file)?;
        let json = serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(json))
    }

    /// `getJson()`: the (patched) json value, `None` if a patch removed it.
    pub fn get_json(&self) -> Option<&Value> {
        self.root_container.get(ROOT_ELEM_NAME)
    }

    /// Takes the (patched) json value out of this applier.
    pub fn into_json(self) -> Option<Value> {
        match self.root_container {
            Value::Object(mut m) => m.remove(ROOT_ELEM_NAME),
            _ => None,
        }
    }

    /// `apply(String, TaskMonitor)`.
    ///
    /// # Errors
    /// Bad patch text, a patch that doesn't fit the json, or cancellation.
    pub fn apply_str(&mut self, patch_string: &str, monitor: &dyn TaskMonitor) -> Result<(), JsonPatchError> {
        self.apply(&JsonPatch::read_str(patch_string)?, monitor)
    }

    /// `apply(JsonPatch, TaskMonitor)`.
    ///
    /// # Errors
    /// A patch section that doesn't fit the json, or cancellation.
    pub fn apply(&mut self, patch: &JsonPatch, monitor: &dyn TaskMonitor) -> Result<(), JsonPatchError> {
        for section in patch.get_sections() {
            // Java: monitor.increment() checks for cancellation and bumps progress
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            self.apply_section(section)?;
        }
        Ok(())
    }

    /// `writeJson(File)`.
    ///
    /// # Errors
    /// Error writing the file.
    pub fn write_json(&self, dest_file: &Path) -> io::Result<()> {
        let s = match self.get_json() {
            Some(v) => serde_json::to_string(v).map_err(io::Error::other)?,
            None => "null".to_string(),
        };
        std::fs::write(dest_file, s)
    }

    fn apply_section(&mut self, section: &PatchSection) -> io::Result<()> {
        let path = &section.path;
        let lines = &section.lines;

        // special case to handle bare values without container
        let target_id =
            path.last().cloned().unwrap_or_else(|| Value::String(ROOT_ELEM_NAME.to_string()));
        let parent = find_parent(&mut self.root_container, path)?;

        match (&target_id, parent) {
            (Value::String(target_name), Value::Object(parent_obj)) => {
                let mut i = 0;
                if lines.first().map(|l| l.operation) == Some(PatchOp::Remove) {
                    parent_obj.remove(target_name);
                    i += 1;
                }
                if let Some(line) = lines.get(i) {
                    if line.operation == PatchOp::Add {
                        parent_obj.insert(target_name.clone(), line.value.clone().unwrap_or(Value::Null));
                    }
                }
                Ok(())
            }
            (Value::Number(n), Value::Array(parent_array)) => {
                let mut target_index = n
                    .as_i64()
                    .or_else(|| n.as_f64().map(|f| f as i64))
                    .ok_or_else(|| io::Error::other(format!("bad array index {n}")))?
                    as usize;
                let mut i = 0;
                while i < lines.len() && lines[i].operation == PatchOp::Remove {
                    if target_index >= parent_array.len() {
                        return Err(io::Error::other(format!(
                            "Index {target_index} out of bounds for length {}",
                            parent_array.len()
                        )));
                    }
                    parent_array.remove(target_index);
                    i += 1;
                }
                while i < lines.len() && lines[i].operation == PatchOp::Add {
                    if target_index > parent_array.len() {
                        return Err(io::Error::other(format!(
                            "Index: {target_index}, Size: {}",
                            parent_array.len()
                        )));
                    }
                    parent_array.insert(target_index, lines[i].value.clone().unwrap_or(Value::Null));
                    target_index += 1;
                    i += 1;
                }
                Ok(())
            }
            _ => Err(io::Error::other("unsupported section")),
        }
    }
}

/// Java `findParent(JsonArray)`: the container of the element named by `path`.
///
/// Handles the corner case of a bare value that is not inside a json container by returning the
/// artificial root container when the path is empty.
fn find_parent<'a>(root_container: &'a mut Value, path: &[Value]) -> io::Result<&'a mut Value> {
    if path.is_empty() {
        return Ok(root_container);
    }
    // skip the root container since there is a path
    let mut current = root_container
        .get_mut(ROOT_ELEM_NAME)
        .ok_or_else(|| io::Error::other("missing rootContainer element"))?;
    for (i, path_elem) in path[..path.len() - 1].iter().enumerate() {
        let next = match path_elem {
            Value::String(s) => match current {
                Value::Object(o) => o.get_mut(s),
                _ => return Err(io::Error::other("invalid json diff data")),
            },
            Value::Number(n) => match current {
                Value::Array(a) => {
                    let index = n.as_i64().unwrap_or(-1);
                    let len = a.len();
                    if index < 0 || index as usize >= len {
                        return Err(io::Error::other(format!("Index {index} out of bounds for length {len}")));
                    }
                    a.get_mut(index as usize)
                }
                _ => return Err(io::Error::other("invalid json diff data")),
            },
            _ => None,
        };
        current = next.ok_or_else(|| {
            io::Error::other(format!("Could not find next element in path: {}, {i}", Value::Array(path.to_vec())))
        })?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    //! Port of `JsonPatchApplierTest`.
    use super::*;
    use crate::util::task::DummyMonitor;

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn apply(json: &str, patch: &str) -> Option<Value> {
        let mut jpa = JsonPatchApplier::new(parse(json));
        jpa.apply_str(patch, &DummyMonitor).unwrap();
        jpa.get_json().cloned()
    }

    const B_C_Z_D_PATCH: &str = r#"@ ["b",1]
  0
- 1
- 1
+ 1.5
  2
@ ["b",3]
  2
+ 2
+ 2
+ 2
+ 2.5
  3
@ ["b",8]
  3
+ 55
+ 66
]
@ ["c",1]
  55
- 66
- 77
+ 99
+ 99
]"#;

    #[test]
    fn test() {
        let patch = format!("{B_C_Z_D_PATCH}\n@ [\"z\"]\n- {{}}\n@ [\"d\"]\n+ {{\"cc\":\"cee\"}}");
        let result = apply(r#"{"a":"a value","b":[0,1,1,2,3],"c":[55,66,77],"z":{}}"#, &patch);
        let expected =
            parse(r#"{"a":"a value","b":[0,1.5,2,2,2,2,2.5,3,55,66],"c":[55,99,99],"d":{"cc":"cee"}}"#);
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_empty_patch() {
        assert_eq!(apply(r#"{"a":"a value"}"#, ""), Some(parse(r#"{"a":"a value"}"#)));
    }

    #[test]
    fn test_end_of_array_additions() {
        let patch = "@ [1]\n  5\n+ 5.5\n  6\n@ [4]\n  7.5\n+ \"string\"\n]";
        assert_eq!(apply("[5,6,7.5]", patch), Some(parse(r#"[5,5.5,6,7.5,"string"]"#)));
    }

    #[test]
    fn test_bare_value() {
        let patch = "@ []\n- 5.5\n+ \"string value\"\n";
        assert_eq!(apply("5.5", patch), Some(parse("\"string value\"")));
    }

    #[test]
    fn test_bare_value_delete() {
        assert_eq!(apply("5.5", "@ []\n- 5.5\n"), None);
    }

    #[test]
    fn test_array_mods() {
        let patch = format!(
            "{B_C_Z_D_PATCH}\n@ [\"name\",\"subname\",\"blah\"]\n- \"1\"\n+ \"2\"\n@ [\"name\",\"subname\",\"test\"]\n+ 44\n@ [\"z\"]\n- {{}}\n@ [\"d\"]\n+ {{\"cc\":\"cee\"}}"
        );
        let result = apply(
            r#"{"a":"a value","b":[0,1,1,2,3],"c":[55,66,77],"z":{},"name":{"subname":{"blah":"1"}}}"#,
            &patch,
        );
        let expected = parse(
            r#"{"a":"a value","b":[0,1.5,2,2,2,2,2.5,3,55,66],"c":[55,99,99],"d":{"cc":"cee"},"name":{"subname":{"blah":"2","test":44}}}"#,
        );
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn bad_paths_are_errors() {
        let mut jpa = JsonPatchApplier::new(parse(r#"{"a":1}"#));
        assert!(jpa.apply_str("@ [\"x\",\"y\"]\n+ 1", &DummyMonitor).is_err());
        assert!(jpa.apply_str("@ [\"a\",0,1]\n+ 1", &DummyMonitor).is_err());
        assert!(jpa.apply_str("@ [0]\n+ 1", &DummyMonitor).is_err());
    }
}
