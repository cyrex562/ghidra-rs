use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;
use crate::filesystem::seam_stubs::SelectFromListDialogLike;

/// A callback interface used to choose which filesystem implementation to use when
/// multiple filesystem types indicate that they can open a container file.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.FileSystemProbeConflictResolver`.
pub trait FileSystemProbeConflictResolver {
    /// Picks a single [`FileSystemInfoRec`] to use when mounting a filesystem.
    ///
    /// `factories` is a list of candidate [`FileSystemInfoRec`]s.
    /// Returns the chosen record, or `None`.
    fn resolve_fsir<'a>(
        &self,
        factories: &[&'a FileSystemInfoRec],
    ) -> Option<&'a FileSystemInfoRec> {
        match factories.len() {
            0 => None,
            1 => Some(factories[0]),
            _ => self.choose_fsir(factories),
        }
    }

    /// This method should be provided by the actual strategy implementation.
    ///
    /// This method will only be called if the list contains more than a single item.
    ///
    /// `factories` always has more than 1 element. Returns the chosen record, or `None`.
    fn choose_fsir<'a>(
        &self,
        factories: &[&'a FileSystemInfoRec],
    ) -> Option<&'a FileSystemInfoRec>;
}

/// Conflict handler that chooses the first filesystem in the list.
///
/// This is the Rust equivalent of `FileSystemProbeConflictResolver.CHOOSEFIRST`.
pub struct ChooseFirstResolver;

impl FileSystemProbeConflictResolver for ChooseFirstResolver {
    fn choose_fsir<'a>(
        &self,
        factories: &[&'a FileSystemInfoRec],
    ) -> Option<&'a FileSystemInfoRec> {
        factories.first().copied()
    }
}

/// Conflict handler that allows the user to pick the filesystem to use from a GUI list.
///
/// This is the Rust equivalent of `FileSystemProbeConflictResolver.GUI_PICKER`. The Java
/// version reaches directly for the static `SelectFromListDialog.selectFromList` utility;
/// here the dialog is an injected dependency (`D: SelectFromListDialogLike`) since Rust has
/// no static/singleton GUI utility to call into.
pub struct GuiPickerResolver<D> {
    dialog: D,
}

impl<D> GuiPickerResolver<D> {
    pub fn new(dialog: D) -> Self {
        Self { dialog }
    }
}

impl<D> FileSystemProbeConflictResolver for GuiPickerResolver<D>
where
    D: SelectFromListDialogLike,
{
    fn choose_fsir<'a>(
        &self,
        factories: &[&'a FileSystemInfoRec],
    ) -> Option<&'a FileSystemInfoRec> {
        self.dialog.select_from_list(
            factories,
            "Select filesystem",
            "Select a filesystem from list",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::rc::Rc;

    use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;

    struct DummyFactory;
    impl GFileSystemFactory for DummyFactory {}

    fn rec(
        fs_type: &'static str,
        description: &'static str,
        priority: i32,
        fs_class_name: &'static str,
    ) -> FileSystemInfoRec {
        FileSystemInfoRec::new(
            fs_type,
            description,
            priority,
            TypeId::of::<DummyFactory>(),
            fs_class_name,
            Rc::new(DummyFactory),
        )
    }

    /// Mock strategy that always picks the last element, proving the trait is object-safe
    /// and that `resolve_fsir`'s default routing to `choose_fsir` works for >1 candidates.
    struct ChooseLastResolver;

    impl FileSystemProbeConflictResolver for ChooseLastResolver {
        fn choose_fsir<'a>(
            &self,
            factories: &[&'a FileSystemInfoRec],
        ) -> Option<&'a FileSystemInfoRec> {
            factories.last().copied()
        }
    }

    #[test]
    fn resolve_fsir_returns_none_for_empty_list() {
        let resolver = ChooseFirstResolver;
        let factories: Vec<&FileSystemInfoRec> = vec![];
        assert!(resolver.resolve_fsir(&factories).is_none());
    }

    #[test]
    fn resolve_fsir_returns_sole_item_without_delegating() {
        let resolver = ChooseLastResolver;
        let rec = rec("zip", "Zip filesystem", 0, "ghidra.ZipGFileSystem");
        let factories: Vec<&FileSystemInfoRec> = vec![&rec];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "zip");
    }

    #[test]
    fn resolve_fsir_delegates_to_choose_fsir_for_multiple_items() {
        let resolver = ChooseLastResolver;
        let first = rec("first", "", 0, "First");
        let second = rec("second", "", 0, "Second");
        let factories: Vec<&FileSystemInfoRec> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "second");
    }

    #[test]
    fn choose_first_resolver_picks_first_of_many() {
        let resolver = ChooseFirstResolver;
        let first = rec("first", "", 0, "First");
        let second = rec("second", "", 0, "Second");
        let factories: Vec<&FileSystemInfoRec> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "first");
    }

    struct MockDialog;

    impl SelectFromListDialogLike for MockDialog {
        fn select_from_list<'a>(
            &self,
            choices: &[&'a FileSystemInfoRec],
            _title: &str,
            _message: &str,
        ) -> Option<&'a FileSystemInfoRec> {
            choices.iter().find(|c| c.get_type() == "second").copied()
        }
    }

    #[test]
    fn gui_picker_resolver_delegates_to_injected_dialog() {
        let resolver = GuiPickerResolver::new(MockDialog);
        let first = rec("first", "", 0, "First");
        let second = rec("second", "", 0, "Second");
        let factories: Vec<&FileSystemInfoRec> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "second");
    }

    #[test]
    fn boxed_dyn_resolver_is_accepted() {
        let resolver: Box<dyn FileSystemProbeConflictResolver> =
            Box::new(ChooseFirstResolver);
        let rec = rec("only", "", 0, "Only");
        let factories: Vec<&FileSystemInfoRec> = vec![&rec];
        assert_eq!(resolver.resolve_fsir(&factories).unwrap().get_type(), "only");
    }
}
