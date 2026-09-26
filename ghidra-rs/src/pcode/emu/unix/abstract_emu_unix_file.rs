//! Port of `ghidra.pcode.emu.unix.AbstractEmuUnixFile`.

use super::{EmuUnixFile, EmuUnixFileStat};
use crate::pcode::emu::sys::emu_file_contents::EmuFileContents;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::util::math_utilities::MathUtilities;

/// The abstract operations of an [`AbstractEmuUnixFileBase`]: the factory methods Java's
/// constructor calls virtually.
///
/// Java's `AbstractEmuUnixFile<T>` is an abstract class carrying both state (`pathname`, `stat`,
/// `contents`) and behaviour. Per the crate's shape rules the state and the concrete methods live
/// in [`AbstractEmuUnixFileBase`], and this trait declares only what a concrete file type must (or
/// may) supply. Both factories are associated functions rather than methods because Java invokes
/// them from the constructor, before any instance exists.
///
/// Corresponds to `ghidra.pcode.emu.unix.AbstractEmuUnixFile`.
pub trait AbstractEmuUnixFile<T> {
    /// The content store backing files of this kind.
    type Contents: EmuFileContents<T>;

    /// A factory method for the file's `stat` structure.
    ///
    /// Java: `protected EmuUnixFileStat createStat()`, which returns a fresh (all-zero) stat.
    fn create_stat() -> EmuUnixFileStat {
        EmuUnixFileStat::default()
    }

    /// A factory method for the file's default contents.
    ///
    /// Java: `protected abstract EmuFileContents<T> createDefaultContents()`.
    fn create_default_contents() -> Self::Contents;
}

/// The shared state and concrete behaviour of an abstract simulated UNIX file.
///
/// A file keeps its original pathname, a `stat` structure (whose `st_size` tracks the file's
/// length), and a content store `C`. It implements [`EmuUnixFile`] by delegating reads, writes and
/// truncation to the content store while maintaining `st_size`.
///
/// Corresponds to the fields and non-abstract methods of `ghidra.pcode.emu.unix.AbstractEmuUnixFile`.
///
/// # Deviations from Java
///
/// * Java's `truncate()` is `synchronized`; here it takes `&mut self`, so exclusivity comes from
///   the borrow checker instead of a monitor.
/// * Java's arithmetic conversions throw the unchecked `ConcretionException` when an offset is not
///   concrete; the `Result`-less trait methods panic with that error's message instead.
#[derive(Debug)]
pub struct AbstractEmuUnixFileBase<C> {
    pathname: String,
    stat: EmuUnixFileStat,
    contents: C,
}

impl<C> AbstractEmuUnixFileBase<C> {
    /// Construct a new file, obtaining its `stat` and default contents from the factories of the
    /// concrete file kind `F`.
    ///
    /// Java notes that a file can technically be hard-linked to several pathnames, but for
    /// simplicity (and diagnostics) the file knows its own original name.
    ///
    /// Java: `AbstractEmuUnixFile(String pathname, int mode)`.
    pub fn new<T, F>(pathname: impl Into<String>, mode: i32) -> Self
    where
        C: EmuFileContents<T>,
        F: AbstractEmuUnixFile<T, Contents = C>,
    {
        let mut stat = F::create_stat();
        stat.st_mode = mode;
        Self { pathname: pathname.into(), stat, contents: F::create_default_contents() }
    }

    /// Mutable access to the file's `stat` structure.
    ///
    /// Java's `getStat()` hands out the (mutable) stat object itself; the read-only view is
    /// [`EmuUnixFile::stat`].
    pub fn stat_mut(&mut self) -> &mut EmuUnixFileStat {
        &mut self.stat
    }

    /// The file's content store (Java's `protected contents` field).
    pub fn contents(&self) -> &C {
        &self.contents
    }

    /// Mutable access to the file's content store.
    pub fn contents_mut(&mut self) -> &mut C {
        &mut self.contents
    }

    /// Replace the file's content store (Java's `contents` field is non-final).
    pub fn set_contents(&mut self, contents: C) {
        self.contents = contents;
    }

}

/// Java: `arithmetic.toLong(offset, Purpose.OTHER)`, whose failure is an unchecked exception.
fn concrete_offset<T>(arithmetic: &dyn PcodeArithmetic<T>, offset: &T) -> i64 {
    arithmetic
        .to_long(offset, Purpose::Other)
        .unwrap_or_else(|e| panic!("{e}"))
}

impl<T, C: EmuFileContents<T>> EmuUnixFile<T> for AbstractEmuUnixFileBase<C> {
    fn pathname(&self) -> &str {
        &self.pathname
    }

    /// Java: `read(PcodeArithmetic, T offset, T buf)`; copies at most `buf`'s capacity, bounded by
    /// `st_size`, into `buf` and returns the count sized like `offset`.
    ///
    /// # Panics
    ///
    /// Panics if `offset` cannot be made concrete by `arithmetic`.
    fn read(&mut self, arithmetic: &dyn PcodeArithmetic<T>, offset: T, buf: &mut T) -> T {
        let off = concrete_offset(arithmetic, &offset);
        let len = self.contents.read(off, buf, self.stat.st_size);
        arithmetic.from_const_u64(len as u64, arithmetic.size_of(&offset) as i32)
    }

    fn write(&mut self, arithmetic: &dyn PcodeArithmetic<T>, offset: T, buf: T) -> T {
        let off = concrete_offset(arithmetic, &offset);
        let len = self.contents.write(off, &buf, self.stat.st_size);
        self.stat.st_size = MathUtilities::unsigned_max_i64(self.stat.st_size, off + len);
        arithmetic.from_const_u64(len as u64, arithmetic.size_of(&offset) as i32)
    }

    fn truncate(&mut self) {
        self.stat.st_size = 0;
        self.contents.truncate();
    }

    fn stat(&self) -> EmuUnixFileStat {
        self.stat
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::sys::BytesEmuFileContents;
    use crate::pcode::emu::unix::{EmuUnixUser, MODE_R, MODE_W};
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;

    /// Minimal little-endian arithmetic over `byte[]`, implementing only what `PcodeArithmetic`
    /// leaves abstract (mirroring the fixtures in `abstract_pcode_machine`).
    struct BytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for BytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            in1.clone()
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &Vec<u8>,
            _sizein2: i32,
            _in2: &Vec<u8>,
        ) -> Vec<u8> {
            in1.clone()
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }
        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }
        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }
        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    /// Mirrors Java's `BytesEmuUnixFileSystem.BytesEmuUnixFile`: default stat, byte contents.
    struct BytesFile;

    impl AbstractEmuUnixFile<Vec<u8>> for BytesFile {
        type Contents = BytesEmuFileContents;

        fn create_default_contents() -> BytesEmuFileContents {
            BytesEmuFileContents::new()
        }
    }

    /// A file kind overriding `createStat`, to prove the constructor consults the factory.
    struct PresetStatFile;

    impl AbstractEmuUnixFile<Vec<u8>> for PresetStatFile {
        type Contents = BytesEmuFileContents;

        fn create_stat() -> EmuUnixFileStat {
            EmuUnixFileStat { st_uid: 42, st_mode: 0o777, ..Default::default() }
        }

        fn create_default_contents() -> BytesEmuFileContents {
            BytesEmuFileContents::new()
        }
    }

    fn new_file(mode: i32) -> AbstractEmuUnixFileBase<BytesEmuFileContents> {
        AbstractEmuUnixFileBase::new::<Vec<u8>, BytesFile>("/tmp/f", mode)
    }

    /// A 4-byte little-endian offset, as `arithmetic.fromConst(off, 4)` would produce.
    fn off4(v: u32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    #[test]
    fn constructor_sets_pathname_and_mode_on_a_fresh_stat() {
        let file = new_file(MODE_R | MODE_W);
        assert_eq!(EmuUnixFile::<Vec<u8>>::pathname(&file), "/tmp/f");
        let stat = EmuUnixFile::<Vec<u8>>::stat(&file);
        assert_eq!(stat.st_mode, MODE_R | MODE_W);
        assert_eq!(stat.st_size, 0);
    }

    #[test]
    fn constructor_overwrites_mode_of_the_factory_stat_but_keeps_its_other_fields() {
        let file = AbstractEmuUnixFileBase::new::<Vec<u8>, PresetStatFile>("/x", MODE_R);
        let stat = EmuUnixFile::<Vec<u8>>::stat(&file);
        assert_eq!(stat.st_mode, MODE_R);
        assert_eq!(stat.st_uid, 42);
    }

    #[test]
    fn write_returns_length_sized_like_offset_and_grows_st_size() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_R | MODE_W);
        let len = file.write(&arith, off4(0), vec![1, 2, 3, 4, 5]);
        assert_eq!(len, off4(5));
        assert_eq!(EmuUnixFile::<Vec<u8>>::stat(&file).st_size, 5);
    }

    #[test]
    fn write_before_end_does_not_shrink_st_size() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_W);
        file.write(&arith, off4(0), vec![0; 10]);
        file.write(&arith, off4(2), vec![7, 7]);
        assert_eq!(EmuUnixFile::<Vec<u8>>::stat(&file).st_size, 10);
    }

    #[test]
    fn write_past_end_extends_st_size_to_offset_plus_length() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_W);
        file.write(&arith, off4(0), vec![1, 2]);
        file.write(&arith, off4(8), vec![3, 4, 5]);
        assert_eq!(EmuUnixFile::<Vec<u8>>::stat(&file).st_size, 11);
    }

    #[test]
    fn read_copies_contents_up_to_file_size_into_the_callers_buffer() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_R | MODE_W);
        file.write(&arith, off4(0), vec![10, 20, 30, 40]);

        let mut buf = vec![0u8; 8];
        let len = file.read(&arith, off4(1), &mut buf);
        // min(buf.length, st_size - offset) = min(8, 3)
        assert_eq!(len, off4(3));
        assert_eq!(buf, vec![20, 30, 40, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn read_is_bounded_by_the_buffer_capacity() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_R | MODE_W);
        file.write(&arith, off4(0), vec![1, 2, 3, 4]);
        let mut buf = vec![0u8; 2];
        let len = file.read(&arith, off4(0), &mut buf);
        assert_eq!(len, off4(2));
        assert_eq!(buf, vec![1, 2]);
    }

    #[test]
    fn truncate_resets_st_size_to_zero() {
        let arith = BytesArithmetic;
        let mut file = new_file(MODE_R | MODE_W);
        file.write(&arith, off4(0), vec![1, 2, 3]);
        EmuUnixFile::<Vec<u8>>::truncate(&mut file);
        assert_eq!(EmuUnixFile::<Vec<u8>>::stat(&file).st_size, 0);

        let mut buf = vec![0u8; 4];
        assert_eq!(file.read(&arith, off4(0), &mut buf), off4(0));
    }

    #[test]
    fn permission_checks_use_the_constructed_mode() {
        let file = new_file(MODE_R);
        let user = EmuUnixUser::DEFAULT_USER;
        assert!(EmuUnixFile::<Vec<u8>>::is_readable(&file, &user));
        assert!(!EmuUnixFile::<Vec<u8>>::is_writable(&file, &user));
        let err = EmuUnixFile::<Vec<u8>>::check_writable(&file, &user).unwrap_err();
        assert_eq!(err.message(), "The file /tmp/f cannot be written.");
    }

    #[test]
    fn stat_mut_changes_are_visible_through_stat() {
        let mut file = new_file(MODE_R);
        file.stat_mut().st_uid = 7;
        assert_eq!(EmuUnixFile::<Vec<u8>>::stat(&file).st_uid, 7);
    }
}
