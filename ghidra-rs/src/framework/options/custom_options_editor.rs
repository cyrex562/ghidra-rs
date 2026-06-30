/// Marker trait for components that handle display editing of one or more
/// interrelated options.
///
/// Implementing this trait signals to the options framework that the component
/// wishes to own the presentation and editing of a named group of options.
/// This mirrors the Java `CustomOptionsEditor` interface from
/// `ghidra.framework.options`.
pub trait CustomOptionsEditor {
    /// Returns the names of the options that this editor is editing.
    ///
    /// Must not be empty.
    fn option_names(&self) -> Vec<String>;

    /// Returns the descriptions of the options that this editor is editing.
    ///
    /// Returns `None` when no descriptions are available, matching the Java
    /// contract that the return value "may be null".
    fn option_descriptions(&self) -> Option<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TwoOptionEditor {
        names: Vec<String>,
        descs: Option<Vec<String>>,
    }

    impl CustomOptionsEditor for TwoOptionEditor {
        fn option_names(&self) -> Vec<String> {
            self.names.clone()
        }

        fn option_descriptions(&self) -> Option<Vec<String>> {
            self.descs.clone()
        }
    }

    #[test]
    fn option_names_returns_all_names() {
        let editor = TwoOptionEditor {
            names: vec!["Alpha".into(), "Beta".into()],
            descs: None,
        };
        assert_eq!(editor.option_names(), vec!["Alpha", "Beta"]);
    }

    #[test]
    fn option_descriptions_none_when_not_provided() {
        let editor = TwoOptionEditor {
            names: vec!["Alpha".into()],
            descs: None,
        };
        assert!(editor.option_descriptions().is_none());
    }

    #[test]
    fn option_descriptions_some_when_provided() {
        let editor = TwoOptionEditor {
            names: vec!["Alpha".into(), "Beta".into()],
            descs: Some(vec!["Desc A".into(), "Desc B".into()]),
        };
        let descs = editor.option_descriptions().unwrap();
        assert_eq!(descs, vec!["Desc A", "Desc B"]);
    }

    #[test]
    fn names_and_descriptions_same_length() {
        let editor = TwoOptionEditor {
            names: vec!["X".into(), "Y".into(), "Z".into()],
            descs: Some(vec!["dx".into(), "dy".into(), "dz".into()]),
        };
        assert_eq!(editor.option_names().len(), editor.option_descriptions().unwrap().len());
    }
}
