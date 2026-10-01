//! Port of `ghidra.app.util.bin.format.golang.rtti.JsonPatch`.

use std::io;
use std::path::Path;

use serde_json::{json, Map, Value};

/// Represents a sequence of operations that describe how a json file has changed.
///
/// This implementation currently only supports reading jd (<https://github.com/josephburnett/jd>)
/// native format diffs.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonPatch {
    sections: Vec<PatchSection>,
}

/// One kind of patch line (`JsonPatch.PatchOp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    /// `+ value`
    Add,
    /// `- value`
    Remove,
    /// A context line (never produced by the parsers).
    Context,
}

impl PatchOp {
    /// `fromChar(char)`: `+` / `-`, else `None`.
    pub fn from_char(ch: char) -> Option<PatchOp> {
        match ch {
            '+' => Some(PatchOp::Add),
            '-' => Some(PatchOp::Remove),
            _ => None,
        }
    }

    /// `getOpChar()`.
    pub fn get_op_char(&self) -> &'static str {
        match self {
            PatchOp::Add => "+",
            PatchOp::Remove => "-",
            PatchOp::Context => "??",
        }
    }
}

/// A run of patch lines that apply to the json element named by `path` (`JsonPatch.PatchSection`).
#[derive(Debug, Clone, PartialEq)]
pub struct PatchSection {
    /// Path (object keys / array indexes) of the changed element.
    pub path: Vec<Value>,
    /// The add / remove operations.
    pub lines: Vec<PatchLine>,
}

impl PatchSection {
    /// `toJson()`: `{ "path": [...], "elements": [ { "op": "+/-", "value": jsonvalue }, * ] }`.
    pub fn to_json(&self) -> Value {
        json!({
            "path": Value::Array(self.path.clone()),
            "elements": Value::Array(self.lines.iter().map(PatchLine::to_json).collect()),
        })
    }
}

/// One add / remove operation (`JsonPatch.PatchLine`); `value` is `None` for a remove.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchLine {
    /// The operation.
    pub operation: PatchOp,
    /// The added value (`None` for removals).
    pub value: Option<Value>,
}

impl PatchLine {
    /// `toJson()`: `{ "op": "+/-", "value": jsonvalue }`.
    pub fn to_json(&self) -> Value {
        let mut result = Map::new();
        result.insert("op".to_string(), Value::String(self.operation.get_op_char().to_string()));
        if let Some(v) = &self.value {
            result.insert("value".to_string(), v.clone());
        }
        Value::Object(result)
    }
}

impl JsonPatch {
    /// Creates a new instance (`JsonPatch(List<PatchSection>)`).
    pub fn new(sections: Vec<PatchSection>) -> Self {
        JsonPatch { sections }
    }

    /// Creates a new instance using the contents in the supplied string (`read(String)`).
    ///
    /// # Errors
    /// A section that doesn't start with `@ `, or bad json.
    pub fn read_str(patch_string: &str) -> io::Result<JsonPatch> {
        let lines: Vec<&str> = patch_string.lines().collect();
        Self::read_lines(&lines)
    }

    /// Creates a new instance using the contents of the supplied file (`read(File)`).
    ///
    /// # Errors
    /// Error reading the file, or bad patch contents.
    pub fn read_file(patch_file: &Path) -> io::Result<JsonPatch> {
        let s = std::fs::read_to_string(patch_file)?;
        Self::read_str(&s)
    }

    /// Creates a new instance using the supplied text lines (`read(ListIterator<String>)`).
    ///
    /// # Errors
    /// A section that doesn't start with `@ `, or bad json.
    pub fn read_lines(lines: &[&str]) -> io::Result<JsonPatch> {
        let mut sections = Vec::new();
        let mut pos = 0;
        while pos < lines.len() {
            match read_patch_section(lines, &mut pos)? {
                Some(section) => sections.push(section),
                None => break,
            }
        }
        Ok(JsonPatch::new(sections))
    }

    /// Creates a new instance using the contents of a json array, allowing a json patch to be
    /// stored in a json document (`read(JsonArray)`).
    ///
    /// # Errors
    /// An element that is not a `{ "path": [...], "elements": [...] }` object, or a bad element.
    pub fn read_json(patch_section_elements: &[Value]) -> io::Result<JsonPatch> {
        let mut sections = Vec::new();
        for elem in patch_section_elements {
            let obj = elem.as_object().ok_or_else(|| io::Error::other(format!("Not a JSON Object: {elem}")))?;
            sections.push(read_patch_section_json(obj)?);
        }
        Ok(JsonPatch::new(sections))
    }

    /// `getSectionCount()`.
    pub fn get_section_count(&self) -> usize {
        self.sections.len()
    }

    /// `getSections()`.
    pub fn get_sections(&self) -> &[PatchSection] {
        &self.sections
    }

    /// Converts this patch to a json array (`toJson()`).
    pub fn to_json(&self) -> Value {
        Value::Array(self.sections.iter().map(PatchSection::to_json).collect())
    }
}

fn read_patch_section_json(obj: &Map<String, Value>) -> io::Result<PatchSection> {
    let path = obj.get("path").and_then(Value::as_array);
    let elements = obj.get("elements").and_then(Value::as_array);
    let (Some(path), Some(elements)) = (path, elements) else {
        return Err(io::Error::other("bad patch section"));
    };
    let mut lines = Vec::new();
    for e in elements {
        let o = e.as_object().ok_or_else(|| io::Error::other(format!("Not a JSON Object: {e}")))?;
        lines.push(line_from_json(o)?);
    }
    Ok(PatchSection { path: path.clone(), lines })
}

fn line_from_json(obj: &Map<String, Value>) -> io::Result<PatchLine> {
    // Java: prim.getAsCharacter() is the first char of the primitive's string form
    let op = match obj.get("op") {
        Some(Value::String(s)) => s.chars().next().and_then(PatchOp::from_char),
        Some(v @ (Value::Number(_) | Value::Bool(_))) => v.to_string().chars().next().and_then(PatchOp::from_char),
        _ => None,
    };
    let value = obj.get("value").cloned();
    match op {
        None => Err(io::Error::other(format!("bad patch element: {}", Value::Object(obj.clone())))),
        Some(PatchOp::Add) if value.is_none() => {
            Err(io::Error::other(format!("bad patch element: {}", Value::Object(obj.clone()))))
        }
        Some(op) => Ok(PatchLine { operation: op, value }),
    }
}

fn parse_json(s: &str) -> io::Result<Value> {
    serde_json::from_str(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn read_patch_section(lines: &[&str], pos: &mut usize) -> io::Result<Option<PatchSection>> {
    let Some(line) = lines.get(*pos) else {
        return Ok(None);
    };
    *pos += 1;
    let Some(path_str) = line.strip_prefix("@ ") else {
        return Err(io::Error::other(format!("bad start of patch section: {line}")));
    };
    let path_elem = parse_json(path_str)?;

    let mut patch_lines = Vec::new();
    while let Some(line) = lines.get(*pos) {
        *pos += 1;
        if line.chars().count() < 3 {
            // probably a context line, just skip it
            continue;
        }
        let op_char = line.chars().next().unwrap_or(' ');
        if op_char == '+' || op_char == '-' {
            let patch_op = PatchOp::from_char(op_char).expect("+ or -");
            let val = if patch_op == PatchOp::Add { Some(parse_json(&line[2..])?) } else { None };
            patch_lines.push(PatchLine { operation: patch_op, value: val });
        }
        else if op_char == '@' {
            *pos -= 1;
            break;
        }
    }
    let path = match path_elem {
        Value::Array(a) => a,
        other => return Err(io::Error::other(format!("Not a JSON Array: {other}"))),
    };
    Ok(Some(PatchSection { path, lines: patch_lines }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_jd_sections() {
        let patch = JsonPatch::read_str(
            "@ [\"b\",1]\n  0\n- 1\n- 1\n+ 1.5\n  2\n@ [\"z\"]\n- {}\n@ [\"d\"]\n+ {\"cc\":\"cee\"}",
        )
        .unwrap();
        assert_eq!(patch.get_section_count(), 3);
        let s0 = &patch.get_sections()[0];
        assert_eq!(s0.path, vec![json!("b"), json!(1)]);
        assert_eq!(
            s0.lines,
            vec![
                PatchLine { operation: PatchOp::Remove, value: None },
                PatchLine { operation: PatchOp::Remove, value: None },
                PatchLine { operation: PatchOp::Add, value: Some(json!(1.5)) },
            ]
        );
        assert_eq!(patch.get_sections()[2].lines[0].value, Some(json!({"cc": "cee"})));
    }

    #[test]
    fn json_round_trip() {
        let patch = JsonPatch::read_str("@ [\"a\"]\n- 1\n+ \"x\"").unwrap();
        let j = patch.to_json();
        assert_eq!(
            j,
            json!([{"path": ["a"], "elements": [{"op": "-"}, {"op": "+", "value": "x"}]}])
        );
        let back = JsonPatch::read_json(j.as_array().unwrap()).unwrap();
        assert_eq!(back, patch);
    }

    #[test]
    fn bad_input() {
        assert!(JsonPatch::read_str("+ 1").is_err());
        assert!(JsonPatch::read_json(&[json!({"path": ["a"]})]).is_err());
        assert!(JsonPatch::read_json(&[json!({"path": [], "elements": [{"op": "+"}]})]).is_err());
        assert_eq!(JsonPatch::read_str("").unwrap().get_section_count(), 0);
    }
}
