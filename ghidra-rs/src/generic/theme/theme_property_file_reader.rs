//! Port of `generic.theme.ThemePropertyFileReader`: reads one `*.theme.properties` file
//! into its `[Defaults]`, `[Dark Defaults]` and look-and-feel specific value maps.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use super::abstract_theme_reader::{AbstractThemeReader, Section, ThemeSectionProcessor};
use super::g_theme_value_map::GThemeValueMap;
use super::laf_type::LafType;

/// The parsed contents of one theme properties file.
#[derive(Debug, Clone, Default)]
pub struct ThemePropertyFileReader {
    reader: AbstractThemeReader,
    defaults: GThemeValueMap,
    dark_defaults: GThemeValueMap,
    custom_sections: HashMap<LafType, GThemeValueMap>,
    default_section_processed: bool,
}

impl ThemePropertyFileReader {
    /// `ThemePropertyFileReader(ResourceFile)`: reads the file at `path`; error messages
    /// name its absolute path.
    pub fn from_path(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let source = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        Ok(Self::from_text(source.display().to_string(), &text))
    }

    /// `ThemePropertyFileReader(String source, Reader reader)`: parses `text`.
    pub fn from_text(source: impl Into<String>, text: &str) -> Self {
        let mut reader = AbstractThemeReader::new(source);
        let mut this = Self::default();
        reader.read(text, &mut this);
        this.reader = reader;
        this
    }

    /// `getErrors()`
    pub fn errors(&self) -> &[String] {
        self.reader.errors()
    }

    /// `getDefaultValues()`
    pub fn default_values(&self) -> &GThemeValueMap {
        &self.defaults
    }

    /// `getDarkDefaultValues()`
    pub fn dark_default_values(&self) -> &GThemeValueMap {
        &self.dark_defaults
    }

    /// `getLookAndFeelSections()`
    pub fn look_and_feel_sections(&self) -> &HashMap<LafType, GThemeValueMap> {
        &self.custom_sections
    }

    /// Reports ids defined in section `name` but not in `[Defaults]` (external ids are
    /// exempt). Ids are checked in sorted order for deterministic errors.
    fn validate(&self, reader: &mut AbstractThemeReader, name: &str, values: &GThemeValueMap) {
        let mut colors: Vec<_> = values
            .colors()
            .filter(|v| !self.defaults.contains_color(v.id()) && !v.is_external())
            .map(|v| v.id())
            .collect();
        colors.sort_unstable();
        for id in colors {
            report_missing_defaults_error(reader, "Color", name, id);
        }
        let mut fonts: Vec<_> = values
            .fonts()
            .filter(|v| !self.defaults.contains_font(v.id()) && !v.is_external())
            .map(|v| v.id())
            .collect();
        fonts.sort_unstable();
        for id in fonts {
            report_missing_defaults_error(reader, "Font", name, id);
        }
        let mut icons: Vec<_> = values
            .icons()
            .filter(|v| !self.defaults.contains_icon(v.id()) && !v.is_external())
            .map(|v| v.id())
            .collect();
        icons.sort_unstable();
        for id in icons {
            report_missing_defaults_error(reader, "Icon", name, id);
        }
    }
}

fn report_missing_defaults_error(
    reader: &mut AbstractThemeReader,
    kind: &str,
    name: &str,
    id: &str,
) {
    reader.error(
        None,
        &format!(
            "{kind} id found in \"{name}\" section, but not defined in \"Defaults\" section: {id}"
        ),
    );
}

impl ThemeSectionProcessor for ThemePropertyFileReader {
    fn process_no_section(&mut self, reader: &mut AbstractThemeReader, section: &Section) {
        if !section.is_empty() {
            reader.error(
                Some(section.line_number()),
                "Theme properties file has values defined outside of a defined section",
            );
        }
    }

    fn process_default_section(&mut self, reader: &mut AbstractThemeReader, section: &Section) {
        self.default_section_processed = true;
        reader.process_values(&mut self.defaults, section);
    }

    fn process_dark_default_section(
        &mut self,
        reader: &mut AbstractThemeReader,
        section: &Section,
    ) {
        if !self.default_section_processed {
            reader.error(
                Some(section.line_number()),
                "Defaults section must be defined before Dark Defaults section!",
            );
            return;
        }
        let mut dark = std::mem::take(&mut self.dark_defaults);
        reader.process_values(&mut dark, section);
        self.validate(reader, "Dark Defaults", &dark);
        self.dark_defaults = dark;
    }

    fn process_custom_section(&mut self, reader: &mut AbstractThemeReader, section: &Section) {
        let name = section.name();
        let Some(laf_type) = LafType::from_name(name) else {
            reader.error(
                Some(section.line_number()),
                &format!("Unknown Look and Feel section found: {name}"),
            );
            return;
        };
        if !self.default_section_processed {
            reader.error(
                Some(section.line_number()),
                &format!("Defaults section must be defined before {name} section!"),
            );
            return;
        }
        let mut custom = GThemeValueMap::new();
        reader.process_values(&mut custom, section);
        self.validate(reader, name, &custom);
        self.custom_sections.insert(laf_type, custom);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::theme::icon_value::IconSpec;
    use crate::generic::theme::java_property_value::PropertyValue;

    fn read(text: &str) -> ThemePropertyFileReader {
        ThemePropertyFileReader::from_text("test", text)
    }

    fn icon(values: &GThemeValueMap, id: &str) -> crate::generic::theme::icon_value::ResolvedIcon {
        values.get_resolved_icon(id).unwrap().unwrap()
    }

    // Derived from ThemePropertyFileReaderTest.testDefaults. Colors and fonts are held as raw
    // text until WebColors / a Font value type are ported, so those assertions check the text.
    #[test]
    fn defaults() {
        let reader = read(
            &[
                "[Defaults]",
                "  color.b.1    = white",
                "  color.b.2    = #ff0000",
                "  color.b.3    = 0x008000",
                "  color.b.4    = 0xff000080",
                "  color.b.5 \t= rgb(0,0,255)",
                "  color.b.6 \t= rgba(255,0,0,0.5)",
                "  color.b.7    = color.b.1",
                "  font.a.8     = dialog-PLAIN-14",
                "  font.a.9     = font.a.8",
                "  font.a.b     = (font.a.8[20][BOLD])",
                "  icon.a.10     = core.png",
                "  icon.a.11     = icon.a.10",
                "  icon.a.12    = icon.a.10[size(17,21)]",
                "  icon.a.13    = core.png[size(17,21)]",
                "  icon.a.14    = icon.a.10{core.png[size(4,4)][move(8, 8)]}",
                "  [laf.font]PasswordField.font = font.a.8",
                "  [laf.font]TextArea.font = dialog-PLAIN-14",
                "  [laf.color]TextArea.background = color.b.1",
                "  [laf.string]Fake.title = This is my title",
                "  [laf.string]OtherFake.title = [laf.string]Fake.title",
                "  [laf.boolean]PopupMenu.consumeEventOnClose = false",
                "",
            ]
            .join("\n"),
        );
        assert!(reader.errors().is_empty(), "{:?}", reader.errors());
        let values = reader.default_values();
        assert_eq!(values.size(), 21);
        assert_eq!(
            values.get_resolved_color("color.b.7").unwrap().unwrap(),
            "white"
        );
        assert_eq!(
            values.get_resolved_color("color.b.6").unwrap().unwrap(),
            "rgba(255,0,0,0.5)"
        );
        assert_eq!(
            values.get_resolved_font("font.a.9").unwrap().unwrap(),
            "dialog-PLAIN-14"
        );
        assert_eq!(
            values.get_resolved_font("font.a.b").unwrap().unwrap(),
            "dialog-PLAIN-14"
        );
        assert_eq!(
            values.get_font("font.a.b").unwrap().modifier_text(),
            Some("[20][BOLD]")
        );
        let core = IconSpec::Resource("core.png".into());
        assert_eq!(icon(values, "icon.a.10").base, core);
        assert_eq!(icon(values, "icon.a.11").base, core);
        let i12 = icon(values, "icon.a.12");
        assert_eq!(
            (i12.base.clone(), i12.modifiers[0].size),
            (core.clone(), Some((17, 21)))
        );
        let i13 = icon(values, "icon.a.13");
        assert_eq!(
            (i13.base.clone(), i13.modifiers[0].size),
            (core.clone(), Some((17, 21)))
        );
        let i14 = icon(values, "icon.a.14");
        assert_eq!(i14.modifiers[0].overlays.len(), 1);
        assert_eq!(
            values
                .get_resolved_font("laf.font.PasswordField.font")
                .unwrap()
                .unwrap(),
            "dialog-PLAIN-14"
        );
        assert_eq!(
            values
                .get_resolved_font("laf.font.TextArea.font")
                .unwrap()
                .unwrap(),
            "dialog-PLAIN-14"
        );
        assert_eq!(
            values
                .get_resolved_property("OtherFake.title")
                .unwrap()
                .unwrap(),
            &PropertyValue::String("This is my title".into())
        );
        assert_eq!(
            values
                .get_resolved_property("PopupMenu.consumeEventOnClose")
                .unwrap()
                .unwrap(),
            &PropertyValue::Boolean(false)
        );
    }

    #[test]
    fn both_defaults_and_dark_defaults_in_same_file() {
        let reader = read(
            "[Defaults]\n  color.b.1 = white\n  color.b.2 = #ff0000\n[Dark Defaults]\n  color.b.1 = black\n  color.b.2 = #0000ff\n",
        );
        assert!(reader.errors().is_empty());
        assert_eq!(reader.default_values().size(), 2);
        assert_eq!(reader.dark_default_values().size(), 2);
        assert_eq!(
            reader
                .default_values()
                .get_resolved_color("color.b.1")
                .unwrap()
                .unwrap(),
            "white"
        );
        assert_eq!(
            reader
                .dark_default_values()
                .get_resolved_color("color.b.2")
                .unwrap()
                .unwrap(),
            "#0000ff"
        );
    }

    #[test]
    fn look_and_feel_values() {
        let reader = read(
            "[Defaults]\n  color.b.1 = white\n[Dark Defaults]\n  color.b.1 = black\n[Metal]\n  color.b.1 = red\n[Nimbus]\n  color.b.1 = green\n",
        );
        assert!(reader.errors().is_empty());
        let custom = reader.look_and_feel_sections();
        assert_eq!(custom.len(), 2);
        assert_eq!(
            custom[&LafType::Nimbus]
                .get_resolved_color("color.b.1")
                .unwrap()
                .unwrap(),
            "green"
        );
        assert_eq!(
            custom[&LafType::Metal]
                .get_resolved_color("color.b.1")
                .unwrap()
                .unwrap(),
            "red"
        );
    }

    #[test]
    fn unknown_look_and_feel_section() {
        let reader = read("[Defaults]\n[Bogus]\n  color.b.1 = red\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\" at line: 2. Unknown Look and Feel section found: Bogus"]
        );
    }

    #[test]
    fn parse_font_error() {
        let reader = read(
            "[Defaults]\n  font.b.1    =  Dialog-PLAIN-14\n  font.b.2    = Dialog-PLANE-13\n  font.b.3    = Dialog-BOLD-ITALIC\n",
        );
        assert_eq!(reader.errors().len(), 2);
    }

    #[test]
    fn parse_font_modifier_error() {
        let reader =
            read("[Defaults]\n  font.b.1    =  Dialog-PLAIN-14\n  font.b.2    = (font.b.1[)\n");
        assert_eq!(reader.errors().len(), 1);
    }

    #[test]
    fn icon_no_right_hand_value_error() {
        let reader = read("[Defaults]\n  icon.b.1    = core.png\n  icon.b.2    = \t\n");
        assert_eq!(reader.errors().len(), 1);
    }

    #[test]
    fn icon_modifier_error_is_reported() {
        let reader = read("[Defaults]\n  icon.b.1 = core.png[bogus]\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\" at line: 2. Could not parse Icon value: \"core.png[bogus]\" because: Invalid icon modifier: bogus"]
        );
    }

    #[test]
    fn java_icon_values_are_skipped() {
        let reader = read("[Defaults]\n  [laf.icon]Tree.icon = <JAVA ICON>\n");
        assert!(reader.errors().is_empty());
        assert!(reader.default_values().is_empty());
    }

    #[test]
    fn color_id_defined_in_non_defaults_section_only() {
        let reader = read("[Defaults]\n  color.foo = red\n[Dark Defaults]\n  color.bar = blue\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\". Color id found in \"Dark Defaults\" section, but not defined in \"Defaults\" section: color.bar"]
        );
    }

    #[test]
    fn font_id_defined_in_non_defaults_section_only() {
        let reader = read("[Defaults]\n[Dark Defaults]\n  font.bar = dialog-PLAIN-14\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\". Font id found in \"Dark Defaults\" section, but not defined in \"Defaults\" section: font.bar"]
        );
    }

    #[test]
    fn icon_id_defined_in_non_defaults_section_only() {
        let reader = read("[Defaults]\n[Dark Defaults]\n  icon.bar = core.png\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\". Icon id found in \"Dark Defaults\" section, but not defined in \"Defaults\" section: icon.bar"]
        );
    }

    #[test]
    fn external_ids_need_no_default() {
        let reader = read("[Defaults]\n[Dark Defaults]\n  [laf.icon]Tree.icon = core.png\n");
        assert!(reader.errors().is_empty());
    }

    #[test]
    fn default_section_must_be_first() {
        let reader = read("[Dark Defaults]\n  color.foo = red\n[Defaults]\n  color.bar = blue\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\" at line: 1. Defaults section must be defined before Dark Defaults section!"]
        );
    }

    #[test]
    fn values_outside_a_section() {
        let reader = read("icon.a = a.png\n[Defaults]\n");
        assert_eq!(
            reader.errors(),
            ["Error parsing theme file \"test\" at line: 0. Theme properties file has values defined outside of a defined section"]
        );
    }

    #[test]
    fn reads_real_gui_theme_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../orig_src/Ghidra/Framework/Gui/data/gui.theme.properties");
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let reader = ThemePropertyFileReader::from_path(&path).unwrap();
        assert!(reader.errors().is_empty(), "{:?}", reader.errors());
        assert_eq!(
            reader
                .default_values()
                .get_icon("icon.left")
                .unwrap()
                .raw_value(),
            Some(&IconSpec::Resource("left.png".into()))
        );
    }
}
