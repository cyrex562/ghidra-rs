use std::collections::HashSet;

use super::{EmuUnixFile, EmuUnixUser};
use crate::pcode::seam_stubs::EmuIOException;

/// Open flags as defined by the simulator.
///
/// See a UNIX manual for the exact meaning of each.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenFlag {
    ORdonly,
    OWronly,
    ORdwr,
    OCreat,
    OTrunc,
    OAppend,
}

impl OpenFlag {
    /// Construct a set of flags.
    ///
    /// # Panics
    ///
    /// If the flags contain both [`OpenFlag::ORdonly`] and [`OpenFlag::OWronly`], as Java throws
    /// `IllegalArgumentException`.
    pub fn set(flags: impl IntoIterator<Item = OpenFlag>) -> HashSet<OpenFlag> {
        let flags: HashSet<OpenFlag> = flags.into_iter().collect();
        if flags.contains(&OpenFlag::ORdonly) && flags.contains(&OpenFlag::OWronly) {
            panic!("Cannot be read only and write only");
        }
        flags
    }

    /// Check if the given flags indicate open for reading.
    pub fn is_read(flags: &HashSet<OpenFlag>) -> bool {
        flags.contains(&OpenFlag::ORdonly) || flags.contains(&OpenFlag::ORdwr)
    }

    /// Check if the given flags indicate open for writing.
    pub fn is_write(flags: &HashSet<OpenFlag>) -> bool {
        flags.contains(&OpenFlag::OWronly) || flags.contains(&OpenFlag::ORdwr)
    }
}

/// A simulated UNIX file system, storing files with values of type `T`.
///
/// Corresponds to `ghidra.pcode.emu.unix.EmuUnixFileSystem`.
pub trait EmuUnixFileSystem<T> {
    /// Construct a new file (without adding it to the file system).
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if the file cannot be constructed.
    fn new_file(&self, pathname: &str, mode: i32) -> Result<Box<dyn EmuUnixFile<T>>, EmuIOException>;

    /// Get the named file, creating it if it doesn't already exist.
    ///
    /// This is accessed by the emulator user, not the target program.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn create_or_get_file(
        &mut self,
        pathname: &str,
        mode: i32,
    ) -> Result<Box<dyn EmuUnixFile<T>>, EmuIOException>;

    /// Get the named file, or `None` if it doesn't exist.
    ///
    /// This is accessed by the emulator user, not the target program.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn get_file(&self, pathname: &str) -> Result<Option<Box<dyn EmuUnixFile<T>>>, EmuIOException>;

    /// Place the given file at the given location.
    ///
    /// This is accessed by the emulator user, not the target program. If the file already
    /// exists, it is replaced silently.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn put_file(&mut self, pathname: &str, file: Box<dyn EmuUnixFile<T>>) -> Result<(), EmuIOException>;

    /// Remove the file at the given location.
    ///
    /// If the file does not exist, this has no effect.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred.
    fn unlink(&mut self, pathname: &str, user: &EmuUnixUser) -> Result<(), EmuIOException>;

    /// Open the requested file according to the given flags and user.
    ///
    /// This is generally accessed by the target program via a file descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`EmuIOException`] if an error occurred, e.g., file not found, or access denied.
    fn open(
        &mut self,
        pathname: &str,
        flags: &HashSet<OpenFlag>,
        user: &EmuUnixUser,
        mode: i32,
    ) -> Result<Box<dyn EmuUnixFile<T>>, EmuIOException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::unix::{EmuUnixFileStat, MODE_R, MODE_W};
    use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
    use std::collections::HashMap;

    /// A minimal in-memory file, sufficient only to exercise the file system trait.
    struct MockFile {
        pathname: String,
        data: Vec<u8>,
        stat: EmuUnixFileStat,
    }

    impl EmuUnixFile<i64> for MockFile {
        fn pathname(&self) -> &str {
            &self.pathname
        }

        fn read(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, offset: i64, buf: i64) -> i64 {
            let start = offset as usize;
            let want = buf as usize;
            self.data.len().saturating_sub(start).min(want) as i64
        }

        fn write(&mut self, _arithmetic: &dyn PcodeArithmetic<i64>, _offset: i64, buf: i64) -> i64 {
            buf
        }

        fn truncate(&mut self) {
            self.data.clear();
        }

        fn stat(&self) -> EmuUnixFileStat {
            self.stat
        }
    }

    /// A minimal in-memory file system, used only to prove the trait's shape is implementable
    /// and behaves like Java's contract (create-or-get, put/unlink, open with flags).
    #[derive(Default)]
    struct MockFileSystem {
        files: HashMap<String, (Vec<u8>, EmuUnixFileStat)>,
    }

    impl EmuUnixFileSystem<i64> for MockFileSystem {
        fn new_file(&self, pathname: &str, mode: i32) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            Ok(Box::new(MockFile {
                pathname: pathname.to_string(),
                data: Vec::new(),
                stat: EmuUnixFileStat {
                    st_mode: mode,
                    ..Default::default()
                },
            }))
        }

        fn create_or_get_file(
            &mut self,
            pathname: &str,
            mode: i32,
        ) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            let entry = self.files.entry(pathname.to_string()).or_insert_with(|| {
                (
                    Vec::new(),
                    EmuUnixFileStat {
                        st_mode: mode,
                        ..Default::default()
                    },
                )
            });
            Ok(Box::new(MockFile {
                pathname: pathname.to_string(),
                data: entry.0.clone(),
                stat: entry.1,
            }))
        }

        fn get_file(&self, pathname: &str) -> Result<Option<Box<dyn EmuUnixFile<i64>>>, EmuIOException> {
            Ok(self.files.get(pathname).map(|(data, stat)| {
                Box::new(MockFile {
                    pathname: pathname.to_string(),
                    data: data.clone(),
                    stat: *stat,
                }) as Box<dyn EmuUnixFile<i64>>
            }))
        }

        fn put_file(&mut self, pathname: &str, file: Box<dyn EmuUnixFile<i64>>) -> Result<(), EmuIOException> {
            self.files
                .insert(pathname.to_string(), (Vec::new(), file.stat()));
            Ok(())
        }

        fn unlink(&mut self, pathname: &str, _user: &EmuUnixUser) -> Result<(), EmuIOException> {
            self.files.remove(pathname);
            Ok(())
        }

        fn open(
            &mut self,
            pathname: &str,
            flags: &HashSet<OpenFlag>,
            user: &EmuUnixUser,
            mode: i32,
        ) -> Result<Box<dyn EmuUnixFile<i64>>, EmuIOException> {
            if !self.files.contains_key(pathname) {
                if !flags.contains(&OpenFlag::OCreat) {
                    return Err(EmuIOException::new(format!("No such file: {pathname}")));
                }
                self.create_or_get_file(pathname, mode)?;
            }
            let (data, stat) = self.files.get(pathname).unwrap();
            if OpenFlag::is_read(flags) && !stat.has_permissions(MODE_R, user) {
                return Err(EmuIOException::new(format!("{pathname} cannot be read.")));
            }
            if OpenFlag::is_write(flags) && !stat.has_permissions(MODE_W, user) {
                return Err(EmuIOException::new(format!("{pathname} cannot be written.")));
            }
            Ok(Box::new(MockFile {
                pathname: pathname.to_string(),
                data: data.clone(),
                stat: *stat,
            }))
        }
    }

    #[test]
    fn open_flag_set_rejects_read_only_and_write_only() {
        let result = std::panic::catch_unwind(|| {
            OpenFlag::set([OpenFlag::ORdonly, OpenFlag::OWronly])
        });
        assert!(result.is_err());
    }

    #[test]
    fn open_flag_is_read_matches_java_semantics() {
        let rdonly = OpenFlag::set([OpenFlag::ORdonly]);
        let rdwr = OpenFlag::set([OpenFlag::ORdwr]);
        let wronly = OpenFlag::set([OpenFlag::OWronly]);
        assert!(OpenFlag::is_read(&rdonly));
        assert!(OpenFlag::is_read(&rdwr));
        assert!(!OpenFlag::is_read(&wronly));
    }

    #[test]
    fn open_flag_is_write_matches_java_semantics() {
        let wronly = OpenFlag::set([OpenFlag::OWronly]);
        let rdwr = OpenFlag::set([OpenFlag::ORdwr]);
        let rdonly = OpenFlag::set([OpenFlag::ORdonly]);
        assert!(OpenFlag::is_write(&wronly));
        assert!(OpenFlag::is_write(&rdwr));
        assert!(!OpenFlag::is_write(&rdonly));
    }

    #[test]
    fn create_or_get_file_then_get_file_round_trips() {
        let mut fs = MockFileSystem::default();
        fs.create_or_get_file("/tmp/a", MODE_R | MODE_W).unwrap();
        let file = fs.get_file("/tmp/a").unwrap();
        assert!(file.is_some());
        assert_eq!(file.unwrap().pathname(), "/tmp/a");
    }

    #[test]
    fn get_file_returns_none_for_missing_pathname() {
        let fs = MockFileSystem::default();
        assert!(fs.get_file("/nope").unwrap().is_none());
    }

    #[test]
    fn unlink_removes_file() {
        let mut fs = MockFileSystem::default();
        fs.create_or_get_file("/tmp/a", MODE_R).unwrap();
        fs.unlink("/tmp/a", &EmuUnixUser::DEFAULT_USER).unwrap();
        assert!(fs.get_file("/tmp/a").unwrap().is_none());
    }

    #[test]
    fn open_without_creat_fails_on_missing_file() {
        let mut fs = MockFileSystem::default();
        let flags = OpenFlag::set([OpenFlag::ORdonly]);
        let result = fs.open("/missing", &flags, &EmuUnixUser::DEFAULT_USER, 0);
        match result {
            Err(err) => assert_eq!(err.message(), "No such file: /missing"),
            Ok(_) => panic!("expected EmuIOException"),
        }
    }

    #[test]
    fn open_with_creat_creates_missing_file() {
        let mut fs = MockFileSystem::default();
        let flags = OpenFlag::set([OpenFlag::ORdonly, OpenFlag::OCreat]);
        let file = fs
            .open("/new", &flags, &EmuUnixUser::DEFAULT_USER, MODE_R)
            .unwrap();
        assert_eq!(file.pathname(), "/new");
    }
}
