/// Types of ways to use a DataTreeDialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTreeDialogType {
    /// Dialog type for opening domain data files.
    Open,
    /// Dialog type for saving domain data files.
    Save,
    /// Dialog type for choosing a user folder.
    ChooseFolder,
    /// Dialog type for creating domain data files.
    Create,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let variants = [
            DataTreeDialogType::Open,
            DataTreeDialogType::Save,
            DataTreeDialogType::ChooseFolder,
            DataTreeDialogType::Create,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let a = DataTreeDialogType::Open;
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", DataTreeDialogType::Open), "Open");
        assert_eq!(format!("{:?}", DataTreeDialogType::Save), "Save");
        assert_eq!(format!("{:?}", DataTreeDialogType::ChooseFolder), "ChooseFolder");
        assert_eq!(format!("{:?}", DataTreeDialogType::Create), "Create");
    }
}
