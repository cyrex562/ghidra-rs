//! Port of `ghidra.app.util.opinion.LibraryExportedSymbol`.
//!
//! Represents a single exported symbol in a library (or DLL): a name and/or ordinal, its stack
//! purge value, whether the function never returns, and -- for a forwarded export (e.g.
//! `kernel32.HeapAlloc` re-exported from `kernelbase.dll`) -- the library/symbol it forwards to.
//!
//! # Departures from the Java class
//!
//! * Java's `getPurge()`/`hasNoReturn()` lazily resolve a forwarded entry via the static
//!   `LibraryLookupTable.getSymbolTable(String, int)`, which this crate ported as
//!   [`library_lookup_table::get_symbol_table`](crate::app::util::opinion::library_lookup_table::get_symbol_table)
//!   taking an explicit `&dyn Application` (Java's `Application` singleton was dropped when that
//!   type was ported; see that module's docs). The same explicit parameter is threaded through
//!   here.
//! * Java's `purge`/`noReturn` fields are mutated by `synchronized` instance methods, including
//!   through a shared `LibrarySymbolTable`-cached instance. Here they live behind a [`Mutex`] so
//!   [`purge`](Self::purge) and [`has_no_return`](Self::has_no_return) can take `&self` -- matching
//!   how a caller reaches a forwarded symbol through a `LibrarySymbolTable` it does not own
//!   exclusively -- rather than requiring `&mut self`.
//! * `LibrarySymbolTable` is not yet ported (see [`crate::app::seam_stubs`]); its stub was
//!   extended with the minimal `get_symbol(&self, &str) -> Option<&LibraryExportedSymbol>` this
//!   type's forward-resolution needs.

use std::sync::Mutex;

use crate::app::util::opinion::library_lookup_table;
use crate::framework::application::Application;

/// The purge/no-return memoization state, mutated by [`LibraryExportedSymbol::process_forwarded_entry`].
///
/// `purge == -1` means "not yet resolved"; `purge == -2` is a re-entrancy guard set while
/// resolution of a forwarded entry is in progress, mirroring the Java field's use as its own lock
/// flag before `synchronized` was layered on top.
#[derive(Debug, Clone, Copy)]
struct PurgeState {
    purge: i32,
    no_return: bool,
}

/// A single exported symbol in a library (or DLL).
///
/// Mirrors `ghidra.app.util.opinion.LibraryExportedSymbol`.
#[derive(Debug)]
pub struct LibraryExportedSymbol {
    library_name: String,
    memsize: i32,
    ordinal: i32,
    symbol_name: Option<String>,
    forward_library_name: Option<String>,
    forward_symbol_name: Option<String>,
    comment: Option<String>,
    purge_state: Mutex<PurgeState>,
}

impl LibraryExportedSymbol {
    /// Mirrors the constructor
    /// `LibraryExportedSymbol(String, int, int, String, String, String, int, boolean, String)`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        library_name: impl Into<String>,
        memsize: i32,
        ordinal: i32,
        symbol_name: Option<String>,
        forward_library_name: Option<String>,
        forward_symbol_name: Option<String>,
        purge: i32,
        no_return: bool,
        comment: Option<String>,
    ) -> Self {
        LibraryExportedSymbol {
            library_name: library_name.into(),
            memsize,
            ordinal,
            symbol_name,
            forward_library_name,
            forward_symbol_name,
            comment,
            purge_state: Mutex::new(PurgeState { purge, no_return }),
        }
    }

    /// Mirrors `getLibraryName()`: the name of the library containing this exported symbol, e.g.
    /// `"user32.dll"` or `"libc.so"`.
    pub fn library_name(&self) -> &str {
        &self.library_name
    }

    /// Mirrors `getOrdinal()`. A value of `-1` indicates that this symbol is only exported by
    /// name.
    pub fn ordinal(&self) -> i32 {
        self.ordinal
    }

    /// Mirrors `getName()`. `None` since some libraries only export by ordinal value.
    pub fn name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }

    /// Mirrors `setName(String)`.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.symbol_name = Some(name.into());
    }

    /// Mirrors `getPurge()`: the number of bytes purged from the stack when the related function
    /// returns, resolving a forwarded entry first if needed. `-1` if the purge value could not be
    /// resolved.
    pub fn purge(&self, app: &dyn Application) -> i32 {
        self.resolve_forward_if_needed(app);

        let mut state = self.purge_state.lock().expect("LibraryExportedSymbol purge mutex poisoned");
        if state.purge == -2 {
            state.purge = -1;
        }
        state.purge
    }

    /// Mirrors `hasNoReturn()`: whether the related function never returns, resolving a forwarded
    /// entry first if needed.
    pub fn has_no_return(&self, app: &dyn Application) -> bool {
        self.resolve_forward_if_needed(app);

        let mut state = self.purge_state.lock().expect("LibraryExportedSymbol purge mutex poisoned");
        if state.purge == -2 {
            state.purge = -1;
        }
        state.no_return
    }

    /// Runs [`Self::process_forwarded_entry`] if this is a forwarded entry whose purge value has
    /// not yet been resolved. Shared by [`Self::purge`] and [`Self::has_no_return`].
    fn resolve_forward_if_needed(&self, app: &dyn Application) {
        let needs_resolution = {
            let state = self.purge_state.lock().expect("LibraryExportedSymbol purge mutex poisoned");
            self.is_forward_entry() && state.purge == -1
        };
        if needs_resolution {
            self.process_forwarded_entry(app);
        }
    }

    /// Mirrors `processForwardedEntry()`: attempts to get the purge value and no-return flag from
    /// the forwarded entry. `-2` is written first as a re-entrancy guard, so a forwarding cycle
    /// resolves to "unable to resolve" (`-1`) rather than looping forever.
    fn process_forwarded_entry(&self, app: &dyn Application) {
        {
            let mut state =
                self.purge_state.lock().expect("LibraryExportedSymbol purge mutex poisoned");
            state.purge = -2;
        }

        let Some(forward_library_name) = self.forward_library_name.as_deref() else {
            return;
        };
        let Some(lib) =
            library_lookup_table::get_symbol_table(app, forward_library_name, self.memsize)
        else {
            return;
        };

        let Some(forward_symbol_name) = self.forward_symbol_name.as_deref() else {
            return;
        };
        let Some(lib_sym) = lib.get_symbol(forward_symbol_name) else {
            return;
        };

        let purge = lib_sym.purge(app);
        let no_return = if purge != -1 { Some(lib_sym.has_no_return(app)) } else { None };

        let mut state = self.purge_state.lock().expect("LibraryExportedSymbol purge mutex poisoned");
        state.purge = purge;
        if let Some(no_return) = no_return {
            state.no_return = no_return;
        }
    }

    /// Mirrors `getComment()`: the comment from the symbol file.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Mirrors `isFowardEntry()` (sic): whether this symbol is forwarded to another library.
    pub fn is_forward_entry(&self) -> bool {
        self.forward_library_name.is_some()
    }

    /// Mirrors `getFowardLibraryName()` (sic).
    pub fn forward_library_name(&self) -> Option<&str> {
        self.forward_library_name.as_deref()
    }

    /// Mirrors `getFowardSymbolName()` (sic).
    pub fn forward_symbol_name(&self) -> Option<&str> {
        self.forward_symbol_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::LibrarySymbolTable;
    use std::io;
    use std::path::PathBuf;

    /// `Application` with no user settings directory and no module data directory, so
    /// [`library_lookup_table::get_symbol_table`] always returns `None` -- enough to exercise the
    /// "can't resolve the forward" paths without needing real `.exports` files on disk.
    struct EmptyApplication;

    impl Application for EmptyApplication {
        fn application_layout(&self) -> Box<dyn crate::framework::seam_stubs::ApplicationLayoutLike> {
            unimplemented!("not exercised by these smoke tests")
        }

        fn current_platform(&self) -> Box<dyn crate::framework::platform::Platform> {
            unimplemented!("not exercised by these smoke tests")
        }

        fn user_settings_directory(&self) -> Option<PathBuf> {
            None
        }

        fn get_module_data_sub_directory(
            &self,
            module_name: &str,
            relative_path: &str,
        ) -> io::Result<crate::generic::jar::resource_file::ResourceFile> {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{relative_path} does not exist in module {module_name}"),
            ))
        }
    }

    fn plain_symbol(purge: i32, no_return: bool) -> LibraryExportedSymbol {
        LibraryExportedSymbol::new(
            "KERNEL32.DLL",
            32,
            -1,
            Some("HeapAlloc".to_string()),
            None,
            None,
            purge,
            no_return,
            Some("allocates from a heap".to_string()),
        )
    }

    #[test]
    fn accessors_match_constructor_arguments() {
        let sym = plain_symbol(4, false);

        assert_eq!(sym.library_name(), "KERNEL32.DLL");
        assert_eq!(sym.ordinal(), -1);
        assert_eq!(sym.name(), Some("HeapAlloc"));
        assert_eq!(sym.comment(), Some("allocates from a heap"));
        assert!(!sym.is_forward_entry());
        assert_eq!(sym.forward_library_name(), None);
        assert_eq!(sym.forward_symbol_name(), None);
    }

    #[test]
    fn set_name_overwrites_symbol_name() {
        let mut sym = plain_symbol(0, false);
        sym.set_name("VirtualAlloc");
        assert_eq!(sym.name(), Some("VirtualAlloc"));
    }

    #[test]
    fn non_forwarded_entry_returns_purge_and_no_return_directly() {
        let app = EmptyApplication;
        let sym = plain_symbol(4, true);

        // Not a forward entry, so getPurge()/hasNoReturn() never touch LibraryLookupTable.
        assert_eq!(sym.purge(&app), 4);
        assert!(sym.has_no_return(&app));
    }

    #[test]
    fn purge_of_minus_two_normalizes_to_minus_one() {
        // Java: "-2 purge value is used to prevent infinite loops in recursion" and is
        // normalized back to -1 (unresolved) by both getPurge() and hasNoReturn().
        let app = EmptyApplication;
        let sym = plain_symbol(-2, false);

        assert_eq!(sym.purge(&app), -1);
    }

    #[test]
    fn unresolvable_forward_leaves_purge_at_minus_one() {
        // is_forward_entry() is true and purge starts at -1, so getPurge() attempts
        // processForwardedEntry(); with no real LibraryLookupTable data behind EmptyApplication,
        // getSymbolTable returns None and purge is left at -2, normalized to -1.
        let app = EmptyApplication;
        let sym = LibraryExportedSymbol::new(
            "USER32.DLL",
            32,
            -1,
            Some("MessageBoxForward".to_string()),
            Some("KERNELBASE.DLL".to_string()),
            Some("HeapAlloc".to_string()),
            -1,
            false,
            None,
        );

        assert!(sym.is_forward_entry());
        assert_eq!(sym.forward_library_name(), Some("KERNELBASE.DLL"));
        assert_eq!(sym.forward_symbol_name(), Some("HeapAlloc"));
        assert_eq!(sym.purge(&app), -1);
        assert!(!sym.has_no_return(&app));
    }

    #[test]
    fn library_symbol_table_get_symbol_finds_by_name() {
        let mut table = LibrarySymbolTable::new("KERNEL32.DLL", 32);
        table.insert_symbol(plain_symbol(4, false));

        assert_eq!(table.get_symbol("HeapAlloc").unwrap().library_name(), "KERNEL32.DLL");
        assert!(table.get_symbol("NoSuchSymbol").is_none());
    }
}
