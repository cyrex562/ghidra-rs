//! Port of `ghidra.pcode.emu.sys.PairedEmuFileContents`.
//!
//! The analog of `PairedPcodeExecutorStatePiece` for simulated file contents: composes two
//! delegate [`EmuFileContents`] ("left" and "right") into a single one storing pairs of values.
//! Java's `org.apache.commons.lang3.tuple.Pair<L, R>` maps to a plain Rust tuple `(L, R)`
//! throughout this port (see
//! [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece)'s own
//! docs for the same convention).

use crate::pcode::emu::sys::emu_file_contents::EmuFileContents;

/// A paired file contents, combining a "left" and "right" [`EmuFileContents`] into a single one
/// over `(L, R)` pairs.
///
/// Port of `ghidra.pcode.emu.sys.PairedEmuFileContents<L, R>`.
pub struct PairedEmuFileContents<L, R> {
    left: Box<dyn EmuFileContents<L>>,
    right: Box<dyn EmuFileContents<R>>,
}

impl<L, R> PairedEmuFileContents<L, R> {
    /// Create a paired file contents.
    ///
    /// Port of `PairedEmuFileContents(EmuFileContents<L>, EmuFileContents<R>)`.
    pub fn new(left: Box<dyn EmuFileContents<L>>, right: Box<dyn EmuFileContents<R>>) -> Self {
        PairedEmuFileContents { left, right }
    }
}

impl<L, R> EmuFileContents<(L, R)> for PairedEmuFileContents<L, R> {
    /// Port of `read(long offset, Pair<L, R> buf, long fileSize)`.
    ///
    /// Reads into both the left and right halves of `buf`, but -- faithfully reproduced quirk --
    /// only the left delegate's return value is returned; the right delegate's return value is
    /// discarded, matching Java's `long result = left.read(...); right.read(...); return
    /// result;`.
    fn read(&self, offset: i64, buf: &mut (L, R), file_size: i64) -> i64 {
        let result = self.left.read(offset, &mut buf.0, file_size);
        self.right.read(offset, &mut buf.1, file_size);
        result
    }

    /// Port of `write(long offset, Pair<L, R> buf, long curSize)`. Same left-result-only quirk as
    /// [`Self::read`]: the right delegate's return value is discarded.
    fn write(&mut self, offset: i64, buf: &(L, R), cur_size: i64) -> i64 {
        let result = self.left.write(offset, &buf.0, cur_size);
        self.right.write(offset, &buf.1, cur_size);
        result
    }

    /// Port of `truncate()`.
    fn truncate(&mut self) {
        self.left.truncate();
        self.right.truncate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::sys::bytes_emu_file_contents::BytesEmuFileContents;

    /// A trivial `EmuFileContents<u32>` fake that always claims to have read/written a fixed,
    /// caller-configured count, letting tests distinguish left's vs. right's return value. The
    /// last-seen offset is recorded through a shared `Rc<Cell<_>>` so a test can still observe it
    /// after the fake has been moved into a `Box` owned by [`PairedEmuFileContents`].
    struct FixedCountFileContents {
        return_count: i64,
        last_offset: std::rc::Rc<std::cell::Cell<i64>>,
    }

    impl FixedCountFileContents {
        fn new(return_count: i64, last_offset: std::rc::Rc<std::cell::Cell<i64>>) -> Self {
            Self { return_count, last_offset }
        }
    }

    impl EmuFileContents<u32> for FixedCountFileContents {
        fn read(&self, offset: i64, buf: &mut u32, _file_size: i64) -> i64 {
            self.last_offset.set(offset);
            *buf = 0xAAAA_AAAA;
            self.return_count
        }
        fn write(&mut self, offset: i64, buf: &u32, _cur_size: i64) -> i64 {
            self.last_offset.set(offset);
            let _ = buf;
            self.return_count
        }
        fn truncate(&mut self) {}
    }

    #[test]
    fn read_returns_only_the_left_delegates_count() {
        // Faithful quirk: even though both delegates are read, only the left's return value
        // propagates.
        let discard = std::rc::Rc::new(std::cell::Cell::new(-1));
        let left = Box::new(FixedCountFileContents::new(4, discard.clone()));
        let right = Box::new(FixedCountFileContents::new(999, discard));
        let paired = PairedEmuFileContents::new(left, right);

        let mut buf: (u32, u32) = (0, 0);
        let read = paired.read(0, &mut buf, 8);
        assert_eq!(read, 4);
        assert_eq!(buf, (0xAAAA_AAAA, 0xAAAA_AAAA));
    }

    #[test]
    fn write_returns_only_the_left_delegates_count() {
        let discard = std::rc::Rc::new(std::cell::Cell::new(-1));
        let left = Box::new(FixedCountFileContents::new(4, discard.clone()));
        let right = Box::new(FixedCountFileContents::new(999, discard));
        let mut paired = PairedEmuFileContents::new(left, right);

        let buf: (u32, u32) = (1, 2);
        let written = paired.write(0, &buf, 0);
        assert_eq!(written, 4);
    }

    #[test]
    fn both_delegates_receive_the_same_offset() {
        let left_offset = std::rc::Rc::new(std::cell::Cell::new(-1));
        let right_offset = std::rc::Rc::new(std::cell::Cell::new(-1));
        let left = Box::new(FixedCountFileContents::new(1, left_offset.clone()));
        let right = Box::new(FixedCountFileContents::new(1, right_offset.clone()));
        let paired = PairedEmuFileContents::new(left, right);

        let mut buf: (u32, u32) = (0, 0);
        paired.read(16, &mut buf, 32);
        assert_eq!(left_offset.get(), 16);
        assert_eq!(right_offset.get(), 16);
    }

    #[test]
    fn truncate_truncates_both_delegates() {
        let left: Box<dyn EmuFileContents<Vec<u8>>> = Box::new(BytesEmuFileContents::new());
        let right: Box<dyn EmuFileContents<Vec<u8>>> = Box::new(BytesEmuFileContents::new());
        let mut paired = PairedEmuFileContents::new(left, right);

        // BytesEmuFileContents grows by doubling its capacity *at most once* per write (a
        // faithfully preserved Java quirk documented on `BytesEmuFileContents::write`); stay
        // within what a single doubling from its 1024-byte initial capacity can hold so this
        // test only exercises truncate(), not that unrelated quirk.
        let big = vec![7u8; 1200];
        paired.write(0, &(big.clone(), big.clone()), 0);
        // Should not panic, and should leave both sides usable afterward.
        paired.truncate();

        let mut dst: (Vec<u8>, Vec<u8>) = (vec![0u8; 4], vec![0u8; 4]);
        let read = paired.read(0, &mut dst, 4);
        assert_eq!(read, 4);
    }

    #[test]
    fn real_bytes_backed_pair_round_trips_through_both_sides() {
        let left: Box<dyn EmuFileContents<Vec<u8>>> = Box::new(BytesEmuFileContents::new());
        let right: Box<dyn EmuFileContents<Vec<u8>>> = Box::new(BytesEmuFileContents::new());
        let mut paired = PairedEmuFileContents::new(left, right);

        let src = (vec![1u8, 2, 3, 4], vec![9u8, 8, 7, 6]);
        let written = paired.write(0, &src, 0);
        assert_eq!(written, 4);

        let mut dst: (Vec<u8>, Vec<u8>) = (vec![0u8; 4], vec![0u8; 4]);
        let read = paired.read(0, &mut dst, 4);
        assert_eq!(read, 4);
        assert_eq!(dst, src);
    }
}
