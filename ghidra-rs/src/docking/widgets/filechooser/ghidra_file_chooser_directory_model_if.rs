use super::GhidraFile;

/// Trait for the directory model backing a `GhidraFileChooser`.
///
/// Corresponds to `docking.widgets.filechooser.GhidraFileChooserDirectoryModelIf`.
pub trait GhidraFileChooserDirectoryModelIf {
    fn set_selected_file(&mut self, file: GhidraFile);
    fn get_selected_file(&self) -> Option<GhidraFile>;
    fn get_selected_rows(&self) -> Vec<i32>;
    fn get_file(&self, row: i32) -> Option<GhidraFile>;
    fn edit(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::MAIN_SEPARATOR;

    struct TestModel {
        selected: Option<GhidraFile>,
        files: Vec<GhidraFile>,
        edit_called: bool,
    }

    impl TestModel {
        fn new(files: Vec<GhidraFile>) -> Self {
            Self { selected: None, files, edit_called: false }
        }
    }

    impl GhidraFileChooserDirectoryModelIf for TestModel {
        fn set_selected_file(&mut self, file: GhidraFile) {
            self.selected = Some(file);
        }

        fn get_selected_file(&self) -> Option<GhidraFile> {
            self.selected.clone()
        }

        fn get_selected_rows(&self) -> Vec<i32> {
            match &self.selected {
                None => vec![],
                Some(sel) => self
                    .files
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| *f == sel)
                    .map(|(i, _)| i as i32)
                    .collect(),
            }
        }

        fn get_file(&self, row: i32) -> Option<GhidraFile> {
            let idx = usize::try_from(row).ok()?;
            self.files.get(idx).cloned()
        }

        fn edit(&mut self) {
            self.edit_called = true;
        }
    }

    fn make_file(path: &str) -> GhidraFile {
        GhidraFile::from_path(path, MAIN_SEPARATOR)
    }

    #[test]
    fn get_selected_file_initially_none() {
        let model = TestModel::new(vec![make_file("a.txt")]);
        assert!(model.get_selected_file().is_none());
    }

    #[test]
    fn set_and_get_selected_file() {
        let mut model = TestModel::new(vec![]);
        let f = make_file("dir/file.txt");
        model.set_selected_file(f.clone());
        assert_eq!(model.get_selected_file(), Some(f));
    }

    #[test]
    fn get_selected_rows_empty_when_no_selection() {
        let model = TestModel::new(vec![make_file("a.txt"), make_file("b.txt")]);
        assert!(model.get_selected_rows().is_empty());
    }

    #[test]
    fn get_selected_rows_returns_matching_indices() {
        let fa = make_file("a.txt");
        let fb = make_file("b.txt");
        let mut model = TestModel::new(vec![fa.clone(), fb.clone(), fa.clone()]);
        model.set_selected_file(fa);
        assert_eq!(model.get_selected_rows(), vec![0, 2]);
    }

    #[test]
    fn get_file_returns_correct_entry() {
        let files = vec![make_file("x.txt"), make_file("y.txt")];
        let model = TestModel::new(files.clone());
        assert_eq!(model.get_file(0), Some(files[0].clone()));
        assert_eq!(model.get_file(1), Some(files[1].clone()));
    }

    #[test]
    fn get_file_out_of_bounds_returns_none() {
        let model = TestModel::new(vec![make_file("a.txt")]);
        assert!(model.get_file(5).is_none());
    }

    #[test]
    fn get_file_negative_row_returns_none() {
        let model = TestModel::new(vec![make_file("a.txt")]);
        assert!(model.get_file(-1).is_none());
    }

    #[test]
    fn edit_sets_flag() {
        let mut model = TestModel::new(vec![]);
        assert!(!model.edit_called);
        model.edit();
        assert!(model.edit_called);
    }
}
