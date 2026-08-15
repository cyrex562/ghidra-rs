use std::fmt;

use crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId;
use crate::format::seam_stubs::{DIEAggregate, DWARFTag};

/// `DW_TAG_formal_parameter`, the only child tag `DWARFSourceInfo::create` looks under when
/// hunting for a `DW_AT_decl_line` attribute value.
const DW_TAG_FORMAL_PARAMETER: i32 = 0x5;

/// Represents the filename and line number info values from DWARF
/// [`DebugInfoEntry`](crate::format::dwarf::debug_info_entry::DebugInfoEntry)s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFSourceInfo {
    pub filename: String,
    pub line_num: i32,
}

impl DWARFSourceInfo {
    pub fn new(filename: String, line_num: i32) -> Self {
        DWARFSourceInfo { filename, line_num }
    }

    /// Creates a new [`DWARFSourceInfo`] instance from the supplied [`DIEAggregate`] if the info
    /// is present, otherwise returns `None`.
    ///
    /// Mirrors `DWARFSourceInfo.create(DIEAggregate)`.
    pub fn create(diea: &DIEAggregate) -> Option<DWARFSourceInfo> {
        let mut current = Some(diea);
        let mut file: Option<String> = None;
        while let Some(d) = current {
            if let Some(f) = d.get_source_file() {
                file = Some(f.to_string());
                break;
            }
            current = d.get_parent();
        }
        let file = file?;

        let decl_line_attr = diea.find_attribute_in_children(
            DWARFAttributeId::DwAtDeclLine,
            DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
        )?;

        let line_num = decl_line_attr.get_unsigned_value() as i32;
        Some(DWARFSourceInfo::new(file, line_num))
    }

    /// Creates a new [`DWARFSourceInfo`] instance from the supplied [`DIEAggregate`], falling
    /// back to the parent containing DIE record if the first record did not have any source
    /// info.
    ///
    /// Mirrors `DWARFSourceInfo.getSourceInfoWithFallbackToParent(DIEAggregate)`.
    pub fn get_source_info_with_fallback_to_parent(diea: &DIEAggregate) -> Option<DWARFSourceInfo> {
        Self::create(diea).or_else(|| diea.get_decl_parent().and_then(Self::create))
    }

    /// Returns the source file and line number info attached to the specified [`DIEAggregate`]
    /// formatted as [`Self::get_description_str`], or `None` if not present.
    ///
    /// Mirrors `DWARFSourceInfo.getDescriptionStr(DIEAggregate)`.
    pub fn get_description_str_for(diea: &DIEAggregate) -> Option<String> {
        Self::create(diea).map(|source_info| source_info.get_description_str())
    }

    /// Returns the source location info as a string formatted as "filename:linenum".
    ///
    /// Mirrors `DWARFSourceInfo.getDescriptionStr()`.
    pub fn get_description_str(&self) -> String {
        format!("{}:{}", self.filename, self.line_num)
    }
}

impl fmt::Display for DWARFSourceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DWARFSourceInfo [filename={}, lineNum={}]", self.filename, self.line_num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(source_file: Option<&str>) -> DIEAggregate {
        DIEAggregate {
            source_file: source_file.map(str::to_string),
            parent: None,
            decl_parent: None,
            children_numeric_attrs: Vec::new(),
        }
    }

    #[test]
    fn description_str_formats_filename_and_line() {
        let info = DWARFSourceInfo::new("foo.c".to_string(), 42);
        assert_eq!(info.get_description_str(), "foo.c:42");
    }

    #[test]
    fn display_matches_java_tostring() {
        let info = DWARFSourceInfo::new("foo.c".to_string(), 42);
        assert_eq!(info.to_string(), "DWARFSourceInfo [filename=foo.c, lineNum=42]");
    }

    #[test]
    fn create_finds_decl_line_among_formal_parameter_children() {
        let mut diea = leaf(Some("foo.c"));
        diea.children_numeric_attrs.push((
            DWARFAttributeId::DwAtDeclLine,
            DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
            crate::format::seam_stubs::DWARFNumericAttribute::new(42),
        ));

        let info = DWARFSourceInfo::create(&diea).expect("expected source info");
        assert_eq!(info.filename, "foo.c");
        assert_eq!(info.line_num, 42);
    }

    #[test]
    fn create_walks_up_parents_to_find_source_file() {
        let mut root = leaf(Some("foo.c"));
        root.children_numeric_attrs.push((
            DWARFAttributeId::DwAtDeclLine,
            DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
            crate::format::seam_stubs::DWARFNumericAttribute::new(7),
        ));
        let child = DIEAggregate {
            source_file: None,
            parent: Some(Box::new(root)),
            decl_parent: None,
            children_numeric_attrs: Vec::new(),
        };

        // findAttributeInChildren is called on the original DIEA (`child`), not the ancestor
        // whose getSourceFile() supplied the filename -- so with no matching attribute on
        // `child` itself, create() must return None even though a source file was found.
        assert!(DWARFSourceInfo::create(&child).is_none());
    }

    #[test]
    fn create_returns_none_when_no_source_file_present() {
        let diea = leaf(None);
        assert!(DWARFSourceInfo::create(&diea).is_none());
    }

    #[test]
    fn create_returns_none_when_no_decl_line_attribute_present() {
        let diea = leaf(Some("foo.c"));
        assert!(DWARFSourceInfo::create(&diea).is_none());
    }

    #[test]
    fn fallback_to_parent_used_when_first_diea_has_no_info() {
        let mut decl_parent = leaf(Some("foo.c"));
        decl_parent.children_numeric_attrs.push((
            DWARFAttributeId::DwAtDeclLine,
            DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
            crate::format::seam_stubs::DWARFNumericAttribute::new(9),
        ));
        let diea = DIEAggregate {
            source_file: None,
            parent: None,
            decl_parent: Some(Box::new(decl_parent)),
            children_numeric_attrs: Vec::new(),
        };

        let info = DWARFSourceInfo::get_source_info_with_fallback_to_parent(&diea)
            .expect("expected fallback source info");
        assert_eq!(info.filename, "foo.c");
        assert_eq!(info.line_num, 9);
    }

    #[test]
    fn description_str_for_wraps_create_and_format() {
        let mut diea = leaf(Some("bar.c"));
        diea.children_numeric_attrs.push((
            DWARFAttributeId::DwAtDeclLine,
            DWARFTag::of(DW_TAG_FORMAL_PARAMETER),
            crate::format::seam_stubs::DWARFNumericAttribute::new(3),
        ));
        assert_eq!(DWARFSourceInfo::get_description_str_for(&diea), Some("bar.c:3".to_string()));

        let empty = leaf(None);
        assert_eq!(DWARFSourceInfo::get_description_str_for(&empty), None);
    }
}
