use std::fmt;

use crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId;
use crate::format::dwarf::die_aggregate::DIEAggregate;
use crate::format::seam_stubs::{DWARFNumericAttribute, DWARFTag};

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
        let mut current = Some(diea.clone());
        let mut file: Option<String> = None;
        while let Some(d) = current {
            if let Some(f) = d.get_source_file() {
                file = Some(f);
                break;
            }
            current = d.get_parent();
        }
        let file = file?;

        let decl_line_attr = diea.find_attribute_in_children::<DWARFNumericAttribute>(
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
        Self::create(diea).or_else(|| diea.get_decl_parent().as_ref().and_then(Self::create))
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
    use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
    use crate::format::dwarf::die_aggregate::tests::{
        comp_unit, comp_unit_with_line, die, install, num, MockCompUnit, MockContainer,
        DW_TAG_SUBPROGRAM, DW_TAG_VARIABLE,
    };
    use std::sync::Arc;

    /// A subprogram DIE (index 0) declared in `source_file` at file index 1, with two children: a
    /// formal parameter (index 1) carrying `DW_AT_decl_line` = `decl_line`, and an attribute-less
    /// variable (index 2). Either attribute can be left off.
    fn subprogram_with_source_info(
        source_file: Option<&str>,
        decl_line: Option<i64>,
    ) -> Arc<MockCompUnit> {
        let cu = match source_file {
            Some(name) => comp_unit_with_line(name),
            None => comp_unit(),
        };
        let subprogram = die(
            &cu,
            0x10,
            0,
            DW_TAG_SUBPROGRAM,
            source_file
                .map(|_| vec![(DWARFAttributeId::DwAtDeclFile, DWARFForm::DwFormData1, num(1))])
                .unwrap_or_default(),
        );
        let param = die(
            &cu,
            0x20,
            1,
            DW_TAG_FORMAL_PARAMETER,
            decl_line
                .map(|line| {
                    vec![(DWARFAttributeId::DwAtDeclLine, DWARFForm::DwFormData1, num(line))]
                })
                .unwrap_or_default(),
        );
        let variable = die(&cu, 0x30, 2, DW_TAG_VARIABLE, vec![]);
        install(
            &cu,
            MockContainer {
                dies: vec![subprogram, param, variable],
                parents: vec![(1, 0), (2, 0)],
                children: vec![(0, 1), (0, 2)],
                ..MockContainer::default()
            },
        );
        cu
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
        let cu = subprogram_with_source_info(Some("foo.c"), Some(42));
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        let info = DWARFSourceInfo::create(&diea).expect("expected source info");

        assert_eq!(info.filename, "foo.c");
        assert_eq!(info.line_num, 42);
    }

    #[test]
    fn create_walks_up_parents_to_find_source_file() {
        let cu = subprogram_with_source_info(Some("foo.c"), Some(7));
        // The variable child itself has no DW_AT_decl_file; its parent (the subprogram) does.
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(2));
        assert_eq!(diea.get_source_file(), None);
        assert_eq!(
            diea.get_parent().and_then(|p| p.get_source_file()),
            Some("foo.c".to_string())
        );

        // findAttributeInChildren is called on the original DIEA (the variable), not the
        // ancestor whose getSourceFile() supplied the filename -- and the variable has neither
        // DW_AT_decl_line nor children, so create() must return None even though the walk up the
        // parent chain did find a source file.
        assert!(DWARFSourceInfo::create(&diea).is_none());
    }

    #[test]
    fn create_returns_none_when_no_source_file_present() {
        let cu = subprogram_with_source_info(None, Some(42));
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        assert!(DWARFSourceInfo::create(&diea).is_none());
    }

    #[test]
    fn create_returns_none_when_no_decl_line_attribute_present() {
        let cu = subprogram_with_source_info(Some("foo.c"), None);
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));

        assert!(DWARFSourceInfo::create(&diea).is_none());
    }

    #[test]
    fn fallback_to_parent_used_when_first_diea_has_no_info() {
        let cu = subprogram_with_source_info(Some("foo.c"), Some(9));
        // The variable has no source info of its own, but its decl parent (the subprogram) has.
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(2));

        assert!(DWARFSourceInfo::create(&diea).is_none());

        let info = DWARFSourceInfo::get_source_info_with_fallback_to_parent(&diea)
            .expect("expected fallback source info");
        assert_eq!(info.filename, "foo.c");
        assert_eq!(info.line_num, 9);
    }

    #[test]
    fn description_str_for_wraps_create_and_format() {
        let cu = subprogram_with_source_info(Some("bar.c"), Some(3));
        let diea = DIEAggregate::create_single(cu.container.get().unwrap().die_at(0));
        assert_eq!(DWARFSourceInfo::get_description_str_for(&diea), Some("bar.c:3".to_string()));

        let empty = subprogram_with_source_info(None, Some(3));
        let empty_diea = DIEAggregate::create_single(empty.container.get().unwrap().die_at(0));
        assert_eq!(DWARFSourceInfo::get_description_str_for(&empty_diea), None);
    }
}
