use crate::filesystem::gfilesystem::factory::file_system_info_rec::FileSystemInfoRec;
use crate::filesystem::seam_stubs::{GFileSystemLike, SelectFromListDialogLike};

/// A callback interface used to choose which filesystem implementation to use when
/// multiple filesystem types indicate that they can open a container file.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.FileSystemProbeConflictResolver`.
pub trait FileSystemProbeConflictResolver<FSTYPE: GFileSystemLike> {
    /// Picks a single [`FileSystemInfoRec`] to use when mounting a filesystem.
    ///
    /// `factories` is a list of candidate [`FileSystemInfoRec`]s.
    /// Returns the chosen record, or `None`.
    fn resolve_fsir<'a>(
        &self,
        factories: &[&'a dyn FileSystemInfoRec<FSTYPE>],
    ) -> Option<&'a dyn FileSystemInfoRec<FSTYPE>> {
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
        factories: &[&'a dyn FileSystemInfoRec<FSTYPE>],
    ) -> Option<&'a dyn FileSystemInfoRec<FSTYPE>>;
}

/// Conflict handler that chooses the first filesystem in the list.
///
/// This is the Rust equivalent of `FileSystemProbeConflictResolver.CHOOSEFIRST`.
pub struct ChooseFirstResolver;

impl<FSTYPE: GFileSystemLike> FileSystemProbeConflictResolver<FSTYPE> for ChooseFirstResolver {
    fn choose_fsir<'a>(
        &self,
        factories: &[&'a dyn FileSystemInfoRec<FSTYPE>],
    ) -> Option<&'a dyn FileSystemInfoRec<FSTYPE>> {
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

impl<FSTYPE, D> FileSystemProbeConflictResolver<FSTYPE> for GuiPickerResolver<D>
where
    FSTYPE: GFileSystemLike,
    D: SelectFromListDialogLike<FSTYPE>,
{
    fn choose_fsir<'a>(
        &self,
        factories: &[&'a dyn FileSystemInfoRec<FSTYPE>],
    ) -> Option<&'a dyn FileSystemInfoRec<FSTYPE>> {
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
    use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct DummyFactory;
    impl GFileSystemFactory<DummyFileSystem> for DummyFactory {}

    struct MockRec {
        fs_type: &'static str,
        description: &'static str,
        priority: i32,
        fs_class_name: &'static str,
        factory: DummyFactory,
    }

    impl FileSystemInfoRec<DummyFileSystem> for MockRec {
        fn get_type(&self) -> &str {
            self.fs_type
        }

        fn get_description(&self) -> &str {
            self.description
        }

        fn get_priority(&self) -> i32 {
            self.priority
        }

        fn get_fs_class_name(&self) -> &str {
            self.fs_class_name
        }

        fn get_factory(&self) -> &dyn GFileSystemFactory<DummyFileSystem> {
            &self.factory
        }
    }

    /// Mock strategy that always picks the last element, proving the trait is object-safe
    /// and that `resolve_fsir`'s default routing to `choose_fsir` works for >1 candidates.
    struct ChooseLastResolver;

    impl FileSystemProbeConflictResolver<DummyFileSystem> for ChooseLastResolver {
        fn choose_fsir<'a>(
            &self,
            factories: &[&'a dyn FileSystemInfoRec<DummyFileSystem>],
        ) -> Option<&'a dyn FileSystemInfoRec<DummyFileSystem>> {
            factories.last().copied()
        }
    }

    #[test]
    fn resolve_fsir_returns_none_for_empty_list() {
        let resolver = ChooseFirstResolver;
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![];
        assert!(resolver.resolve_fsir(&factories).is_none());
    }

    #[test]
    fn resolve_fsir_returns_sole_item_without_delegating() {
        let resolver = ChooseLastResolver;
        let rec = MockRec {
            fs_type: "zip",
            description: "Zip filesystem",
            priority: 0,
            fs_class_name: "ghidra.ZipGFileSystem",
            factory: DummyFactory,
        };
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&rec];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "zip");
    }

    #[test]
    fn resolve_fsir_delegates_to_choose_fsir_for_multiple_items() {
        let resolver = ChooseLastResolver;
        let first = MockRec {
            fs_type: "first",
            description: "",
            priority: 0,
            fs_class_name: "First",
            factory: DummyFactory,
        };
        let second = MockRec {
            fs_type: "second",
            description: "",
            priority: 0,
            fs_class_name: "Second",
            factory: DummyFactory,
        };
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "second");
    }

    #[test]
    fn choose_first_resolver_picks_first_of_many() {
        let resolver = ChooseFirstResolver;
        let first = MockRec {
            fs_type: "first",
            description: "",
            priority: 0,
            fs_class_name: "First",
            factory: DummyFactory,
        };
        let second = MockRec {
            fs_type: "second",
            description: "",
            priority: 0,
            fs_class_name: "Second",
            factory: DummyFactory,
        };
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "first");
    }

    struct MockDialog;

    impl SelectFromListDialogLike<DummyFileSystem> for MockDialog {
        fn select_from_list<'a>(
            &self,
            choices: &[&'a dyn FileSystemInfoRec<DummyFileSystem>],
            _title: &str,
            _message: &str,
        ) -> Option<&'a dyn FileSystemInfoRec<DummyFileSystem>> {
            choices.iter().find(|c| c.get_type() == "second").copied()
        }
    }

    #[test]
    fn gui_picker_resolver_delegates_to_injected_dialog() {
        let resolver = GuiPickerResolver::new(MockDialog);
        let first = MockRec {
            fs_type: "first",
            description: "",
            priority: 0,
            fs_class_name: "First",
            factory: DummyFactory,
        };
        let second = MockRec {
            fs_type: "second",
            description: "",
            priority: 0,
            fs_class_name: "Second",
            factory: DummyFactory,
        };
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&first, &second];
        let chosen = resolver.resolve_fsir(&factories).expect("expected a match");
        assert_eq!(chosen.get_type(), "second");
    }

    #[test]
    fn boxed_dyn_resolver_is_accepted() {
        let resolver: Box<dyn FileSystemProbeConflictResolver<DummyFileSystem>> =
            Box::new(ChooseFirstResolver);
        let rec = MockRec {
            fs_type: "only",
            description: "",
            priority: 0,
            fs_class_name: "Only",
            factory: DummyFactory,
        };
        let factories: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&rec];
        assert_eq!(resolver.resolve_fsir(&factories).unwrap().get_type(), "only");
    }
}
