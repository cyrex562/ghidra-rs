//! Port of `ghidra.app.util.bean.SelectLanguagePanelListener`.

use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::language_id::LanguageID;

/// Listener notified every time a language / compiler spec pair is selected in a language
/// selection panel.
///
/// Port of `ghidra.app.util.bean.SelectLanguagePanelListener`. The Java contract notes that
/// "the language could be null" (the selection was cleared), so both identifiers are passed as
/// `Option`s.
pub trait SelectLanguagePanelListener {
    /// Invoked every time a language is selected.
    ///
    /// `lang_id` is the selected language id and `compiler_spec_id` the selected compiler spec
    /// id; either is `None` when nothing is selected.
    fn select_id_validation(
        &self,
        lang_id: Option<&LanguageID>,
        compiler_spec_id: Option<&CompilerSpecID>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every selection it is told about, as a validating panel client would.
    #[derive(Default)]
    struct Recorder {
        seen: RefCell<Vec<(Option<String>, Option<String>)>>,
    }

    impl SelectLanguagePanelListener for Recorder {
        fn select_id_validation(
            &self,
            lang_id: Option<&LanguageID>,
            compiler_spec_id: Option<&CompilerSpecID>,
        ) {
            self.seen.borrow_mut().push((
                lang_id.map(|l| l.get_id_as_string().to_string()),
                compiler_spec_id.map(|c| c.get_id_as_string().to_string()),
            ));
        }
    }

    fn notify(listener: &impl SelectLanguagePanelListener) {
        let lang = LanguageID::new("x86:LE:64:default").unwrap();
        let cspec = CompilerSpecID::new(Some("gcc"));
        listener.select_id_validation(Some(&lang), Some(&cspec));
        // The Java contract allows a cleared selection (null language).
        listener.select_id_validation(None, None);
    }

    #[test]
    fn receives_selected_ids_and_cleared_selection() {
        let r = Recorder::default();
        notify(&r);
        assert_eq!(
            r.seen.into_inner(),
            vec![
                (Some("x86:LE:64:default".to_string()), Some("gcc".to_string())),
                (None, None),
            ]
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let r = Recorder::default();
        {
            let l: &dyn SelectLanguagePanelListener = &r;
            let lang = LanguageID::new("ARM:LE:32:v8").unwrap();
            l.select_id_validation(Some(&lang), None);
        }
        assert_eq!(r.seen.into_inner(), vec![(Some("ARM:LE:32:v8".to_string()), None)]);
    }
}
