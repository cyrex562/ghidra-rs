//! Port of `generic.theme.AbstractThemeReader`: the shared machinery for reading theme
//! data organized in `[Section]`s of `key = value` lines, and for turning a section's
//! entries into a [`GThemeValueMap`].
//!
//! Java dispatches sections to abstract `processXxxSection` methods; here
//! [`AbstractThemeReader::read`] hands each section to a [`ThemeSectionProcessor`]. Java
//! keeps section entries in a `HashMap`; entries here keep file order, so values and errors
//! are processed deterministically.

use std::collections::HashMap;

use super::color_value::ColorValue;
use super::font_value::FontValue;
use super::g_theme_value_map::GThemeValueMap;
use super::icon_value::IconValue;
use super::java_property_value::JavaPropertyValue;

/// Name of the implicit section holding lines before the first section header.
pub const NO_SECTION: &str = "No Section";
/// Name of the standard defaults section.
pub const DEFAULTS: &str = "Defaults";
/// Name of the dark defaults section.
pub const DARK_DEFAULTS: &str = "Dark Defaults";
/// `GTheme.JAVA_ICON`: an icon value meaning "keep the look and feel's own icon".
pub const JAVA_ICON: &str = "<JAVA ICON>";

/// The values found in one `[section name]` of a theme file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    name: String,
    start_line_number: usize,
    entries: Vec<(String, String, usize)>,
    index: HashMap<String, usize>,
}

impl Section {
    /// A new, empty section starting at `line_number`.
    pub fn new(name: impl Into<String>, line_number: usize) -> Self {
        Self {
            name: name.into(),
            start_line_number: line_number,
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// `getName()`
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `getLineNumber()`: the line where this section began (0 for [`NO_SECTION`]).
    pub fn line_number(&self) -> usize {
        self.start_line_number
    }

    /// `getValue(key)`
    pub fn value(&self, key: &str) -> Option<&str> {
        self.index.get(key).map(|&i| self.entries[i].1.as_str())
    }

    /// `getLineNumber(key)`: the line the key was read from.
    pub fn key_line_number(&self, key: &str) -> Option<usize> {
        self.index.get(key).map(|&i| self.entries[i].2)
    }

    /// `getKeys()`, in file order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _, _)| k.as_str())
    }

    /// `(key, value, line number)` entries, in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str, usize)> {
        self.entries
            .iter()
            .map(|(k, v, l)| (k.as_str(), v.as_str(), *l))
    }

    /// `isEmpty()`
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `remove(key)`
    pub fn remove(&mut self, key: &str) {
        if let Some(i) = self.index.remove(key) {
            self.entries.remove(i);
            for slot in self.index.values_mut() {
                if *slot > i {
                    *slot -= 1;
                }
            }
        }
    }

    /// `add(line, lineNumber)`: parses `key = value`, reporting malformed lines through
    /// `reader`.
    fn add(&mut self, reader: &mut AbstractThemeReader, line: &str, line_number: usize) {
        let Some(split) = line.find('=') else {
            reader.error(
                Some(line_number),
                &format!("Missing required \"=\" for propery line: \"{line}\""),
            );
            return;
        };
        let key = line[..split].trim();
        let value = line[split + 1..].trim();
        if key.is_empty() {
            reader.error(
                Some(line_number),
                &format!("Missing key for propery line: \"{line}\""),
            );
            return;
        }
        if value.is_empty() {
            reader.error(
                Some(line_number),
                &format!("Missing value for propery line: \"{line}\""),
            );
            return;
        }
        if self.index.contains_key(key) {
            reader.error(
                Some(line_number),
                &format!("Duplicate key found in this file!: \"{key}\""),
            );
            return;
        }
        self.index.insert(key.to_string(), self.entries.len());
        self.entries
            .push((key.to_string(), value.to_string(), line_number));
    }
}

/// What a concrete reader does with each kind of section (Java's abstract
/// `processNoSection` / `processDefaultSection` / `processDarkDefaultSection` /
/// `processCustomSection`).
pub trait ThemeSectionProcessor {
    /// Lines before the first section header.
    fn process_no_section(&mut self, reader: &mut AbstractThemeReader, section: &Section);
    /// The `[Defaults]` section.
    fn process_default_section(&mut self, reader: &mut AbstractThemeReader, section: &Section);
    /// The `[Dark Defaults]` section.
    fn process_dark_default_section(&mut self, reader: &mut AbstractThemeReader, section: &Section);
    /// Any other section (look-and-feel specific values).
    fn process_custom_section(&mut self, reader: &mut AbstractThemeReader, section: &Section);
}

/// The source name and collected errors of a theme read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbstractThemeReader {
    source: String,
    errors: Vec<String>,
}

impl AbstractThemeReader {
    /// A reader whose error messages name `source`.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            errors: Vec::new(),
        }
    }

    /// The source name used in error messages.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// `getErrors()`
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// `read(reader)`: splits `text` into sections and dispatches each to `processor`.
    pub fn read(&mut self, text: &str, processor: &mut impl ThemeSectionProcessor) {
        for section in self.read_sections(text) {
            match section.name() {
                NO_SECTION => processor.process_no_section(self, &section),
                DEFAULTS => processor.process_default_section(self, &section),
                DARK_DEFAULTS => processor.process_dark_default_section(self, &section),
                _ => processor.process_custom_section(self, &section),
            }
        }
    }

    /// `readSections`: strips comments (`//` to end of line; whole lines starting `#`),
    /// skips blank lines, and groups `key = value` lines under `[section]` headers.
    pub fn read_sections(&mut self, text: &str) -> Vec<Section> {
        let mut sections = vec![Section::new(NO_SECTION, 0)];
        for (i, raw_line) in text.lines().enumerate() {
            let line_number = i + 1;
            let line = remove_comments(raw_line);
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                sections.push(Section::new(&line[1..line.len() - 1], line_number));
            } else {
                let current = sections.last_mut().expect("NO_SECTION is always present");
                current.add(self, line, line_number);
            }
        }
        sections
    }

    /// `processValues(valueMap, section)`: parses each entry by its key's kind and adds
    /// it to `value_map`, reporting parse failures and duplicate ids.
    pub fn process_values(&mut self, value_map: &mut GThemeValueMap, section: &Section) {
        for (key, value, line) in section.entries() {
            if ColorValue::is_color_key(key) {
                match ColorValue::parse(key, value) {
                    Ok(v) => {
                        let old = value_map.add_color(v);
                        self.report_duplicate_key(old.as_ref().map(ColorValue::id), line);
                    }
                    Err(_) => {
                        self.error(Some(line), &format!("Could not parse Color value: {value}"))
                    }
                }
            } else if FontValue::is_font_key(key) {
                match FontValue::parse(key, value) {
                    Ok(Some(v)) => {
                        let old = value_map.add_font(v);
                        self.report_duplicate_key(old.as_ref().map(FontValue::id), line);
                    }
                    Ok(None) => {
                        self.error(Some(line), &format!("Could not parse Font value: {value}"))
                    }
                    Err(e) => self.error(
                        Some(line),
                        &format!("Could not parse Font value: {value}because {e}"),
                    ),
                }
            } else if IconValue::is_icon_key(key) {
                if value == JAVA_ICON {
                    continue;
                }
                match IconValue::parse(key, value) {
                    Ok(Some(v)) => {
                        let old = value_map.add_icon(v);
                        self.report_duplicate_key(old.as_ref().map(IconValue::id), line);
                    }
                    Ok(None) => {
                        self.error(Some(line), &format!("Could not parse Icon value: {value}"))
                    }
                    Err(e) => self.error(
                        Some(line),
                        &format!("Could not parse Icon value: \"{value}\" because: {e}"),
                    ),
                }
            } else if JavaPropertyValue::is_boolean_key(key) {
                self.add_property(
                    value_map,
                    JavaPropertyValue::parse_boolean(key, value),
                    "boolean",
                    value,
                    line,
                );
            } else if JavaPropertyValue::is_string_key(key) {
                self.add_property(
                    value_map,
                    JavaPropertyValue::parse_string(key, value),
                    "String",
                    value,
                    line,
                );
            } else {
                self.error(
                    Some(line),
                    &format!("Can't process property: {key} = {value}"),
                );
            }
        }
    }

    fn add_property<E>(
        &mut self,
        value_map: &mut GThemeValueMap,
        parsed: Result<JavaPropertyValue, E>,
        kind: &str,
        value: &str,
        line: usize,
    ) {
        match parsed {
            Ok(v) => {
                let old = value_map.add_property(v);
                self.report_duplicate_key(old.as_ref().map(JavaPropertyValue::id), line);
            }
            Err(_) => self.error(
                Some(line),
                &format!("Could not parse {kind} property value: {value}"),
            ),
        }
    }

    fn report_duplicate_key(&mut self, old_id: Option<&str>, line: usize) {
        if let Some(id) = old_id {
            self.error(Some(line), &format!("Duplicate id found: \"{id}\""));
        }
    }

    /// `error(lineNumber, message)`: records a formatted error. `None` stands for Java's
    /// negative line number (no location).
    pub fn error(&mut self, line_number: Option<usize>, message: &str) {
        let mut msg = format!("Error parsing theme file \"{}\"", self.source);
        if let Some(line) = line_number {
            msg.push_str(&format!(" at line: {line}"));
        }
        msg.push_str(". ");
        msg.push_str(message);
        self.errors.push(msg);
    }
}

fn remove_comments(line: &str) -> &str {
    let line = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    let line = line.trim();
    if line.starts_with('#') {
        return "";
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_comments_and_line_numbers() {
        let mut reader = AbstractThemeReader::new("test");
        let sections = reader.read_sections(
            "# header comment\n\n[Defaults]\n  icon.a = a.png // trailing\n#icon.b = b.png\n[Dark Defaults]\nicon.a=b.png\n",
        );
        assert!(reader.errors().is_empty());
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].name(), NO_SECTION);
        assert!(sections[0].is_empty());
        assert_eq!(sections[1].name(), "Defaults");
        assert_eq!(sections[1].line_number(), 3);
        assert_eq!(sections[1].value("icon.a"), Some("a.png"));
        assert_eq!(sections[1].key_line_number("icon.a"), Some(4));
        assert_eq!(sections[1].value("icon.b"), None);
        assert_eq!(sections[2].value("icon.a"), Some("b.png"));
        assert_eq!(sections[2].key_line_number("icon.a"), Some(7));
    }

    #[test]
    fn malformed_lines_are_reported() {
        let mut reader = AbstractThemeReader::new("test");
        let sections = reader.read_sections("[Defaults]\nnoequals\n = v\nk =  \nk = 1\nk = 2\n");
        assert_eq!(sections[1].keys().collect::<Vec<_>>(), ["k"]);
        assert_eq!(sections[1].value("k"), Some("1"));
        assert_eq!(
            reader.errors(),
            [
                "Error parsing theme file \"test\" at line: 2. Missing required \"=\" for propery line: \"noequals\"",
                "Error parsing theme file \"test\" at line: 3. Missing key for propery line: \"= v\"",
                "Error parsing theme file \"test\" at line: 4. Missing value for propery line: \"k =\"",
                "Error parsing theme file \"test\" at line: 6. Duplicate key found in this file!: \"k\"",
            ]
        );
    }

    #[test]
    fn error_without_line_number() {
        let mut reader = AbstractThemeReader::new("src");
        reader.error(None, "boom");
        assert_eq!(reader.errors(), ["Error parsing theme file \"src\". boom"]);
    }
}
