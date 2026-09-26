//! A small, read-only cpio archive reader standing in for Apache commons-compress's
//! `CpioArchiveInputStream` / `CpioArchiveEntry`, which `CpioFileSystem` is written against.
//!
//! Supports the four formats commons-compress reads: "new" ASCII (`070701`, a.k.a. newc),
//! "new" ASCII with CRC (`070702`), "old" ASCII (`070707`, a.k.a. odc) and "old" binary (magic
//! `070707` octal as a 16-bit word, either byte order). Behaviour follows commons-compress:
//! the `TRAILER!!!` entry ends the archive, mode 0 is only allowed on the trailer, unknown file
//! types are rejected, entries of the CRC format are checksummed once their data has been
//! passed over, and running out of input is reported as [`io::ErrorKind::UnexpectedEof`]
//! (Java's `EOFException`).
//!
//! Unlike the stream, the reader works over a random-access [`ByteProvider`] and records each
//! entry's data offset, so an entry's contents can be addressed without re-reading the archive.

use std::io;

use crate::app::util::bin::byte_provider::ByteProvider;

/// `CpioConstants.FORMAT_NEW`.
pub const FORMAT_NEW: u16 = 1;
/// `CpioConstants.FORMAT_NEW_CRC`.
pub const FORMAT_NEW_CRC: u16 = 2;
/// `CpioConstants.FORMAT_OLD_ASCII`.
pub const FORMAT_OLD_ASCII: u16 = 4;
/// `CpioConstants.FORMAT_OLD_BINARY`.
pub const FORMAT_OLD_BINARY: u16 = 8;

/// `CpioConstants.S_IFMT`: mask for the file type bits of a mode.
pub const S_IFMT: u64 = 0o170000;
/// `CpioConstants.C_ISSOCK`.
pub const C_ISSOCK: u64 = 0o140000;
/// `CpioConstants.C_ISLNK`.
pub const C_ISLNK: u64 = 0o120000;
/// `CpioConstants.C_ISNWK`.
pub const C_ISNWK: u64 = 0o110000;
/// `CpioConstants.C_ISREG`.
pub const C_ISREG: u64 = 0o100000;
/// `CpioConstants.C_ISBLK`.
pub const C_ISBLK: u64 = 0o060000;
/// `CpioConstants.C_ISDIR`.
pub const C_ISDIR: u64 = 0o040000;
/// `CpioConstants.C_ISCHR`.
pub const C_ISCHR: u64 = 0o020000;
/// `CpioConstants.C_ISFIFO`.
pub const C_ISFIFO: u64 = 0o010000;

/// `CpioConstants.CPIO_TRAILER`.
pub const CPIO_TRAILER: &str = "TRAILER!!!";

const MAGIC_NEW: &[u8] = b"070701";
const MAGIC_NEW_CRC: &[u8] = b"070702";
const MAGIC_OLD_ASCII: &[u8] = b"070707";
const MAGIC_OLD_BINARY: u64 = 0o070707;

/// Checks if `signature` (of which the first `length` bytes are valid) is the start of a cpio
/// archive: the binary magic in either byte order, or an ASCII `07070[127]` magic.
///
/// Mirrors commons-compress `CpioArchiveInputStream.matches(byte[], int)`.
pub fn matches(signature: &[u8], length: usize) -> bool {
    if length < 6 || signature.len() < 6 {
        return false;
    }
    // Check binary values
    if signature[0] == 0x71 && signature[1] == 0xc7 {
        return true;
    }
    if signature[1] == 0x71 && signature[0] == 0xc7 {
        return true;
    }
    // Check Ascii (String) values
    // 3037 3037 30nn
    if signature[..5] != *b"07070" {
        return false;
    }
    // Check last byte
    matches!(signature[5], b'1' | b'2' | b'7')
}

/// One member of a cpio archive. Mirrors commons-compress `CpioArchiveEntry`.
///
/// Equality compares names only, as `CpioArchiveEntry.equals` does.
#[derive(Debug, Clone)]
pub struct CpioArchiveEntry {
    format: u16,
    name: String,
    inode: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    nlink: u64,
    mtime: u64,
    size: u64,
    chksum: u64,
    dev_maj: u64,
    dev_min: u64,
    rdev_maj: u64,
    rdev_min: u64,
    device: u64,
    rdev: u64,
    data_offset: u64,
}

impl PartialEq for CpioArchiveEntry {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl CpioArchiveEntry {
    fn new(format: u16) -> Self {
        CpioArchiveEntry {
            format,
            name: String::new(),
            inode: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            mtime: 0,
            size: 0,
            chksum: 0,
            dev_maj: 0,
            dev_min: 0,
            rdev_maj: 0,
            rdev_min: 0,
            device: 0,
            rdev: 0,
            data_offset: 0,
        }
    }

    /// Mirrors `setMode(long)`: rejects modes whose file type is not a known cpio type.
    fn set_mode(&mut self, mode: u64) -> io::Result<()> {
        let masked = mode & S_IFMT;
        match masked {
            C_ISDIR | C_ISLNK | C_ISREG | C_ISFIFO | C_ISCHR | C_ISBLK | C_ISSOCK | C_ISNWK => {
                self.mode = mode;
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown mode. Full: {mode:x} Masked: {masked:x}"),
            )),
        }
    }

    fn is_new_format(&self) -> bool {
        self.format & (FORMAT_NEW | FORMAT_NEW_CRC) != 0
    }

    fn unsupported(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, what.to_owned())
    }

    /// Header alignment of this entry's format (`getAlignmentBoundary()`).
    fn alignment(&self) -> u64 {
        match self.format {
            FORMAT_NEW | FORMAT_NEW_CRC => 4,
            FORMAT_OLD_BINARY => 2,
            _ => 0,
        }
    }

    /// Fixed header size of this entry's format (`getHeaderSize()`).
    fn header_size(&self) -> u64 {
        match self.format {
            FORMAT_NEW | FORMAT_NEW_CRC => 110,
            FORMAT_OLD_ASCII => 76,
            _ => 26,
        }
    }

    fn pad_to_alignment(&self, size: u64) -> u64 {
        let align = self.alignment();
        if align == 0 {
            return 0;
        }
        let remain = size % align;
        if remain > 0 { align - remain } else { 0 }
    }

    /// The archive format ([`FORMAT_NEW`], ...). Mirrors `getFormat()`.
    pub fn format(&self) -> u16 {
        self.format
    }

    /// The entry's path within the archive. Mirrors `getName()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mirrors `getInode()`.
    pub fn inode(&self) -> u64 {
        self.inode
    }

    /// The mode (file type and permission bits). Mirrors `getMode()`.
    pub fn mode(&self) -> u64 {
        self.mode
    }

    /// Mirrors `getUID()`.
    pub fn uid(&self) -> u64 {
        self.uid
    }

    /// Mirrors `getGID()`.
    pub fn gid(&self) -> u64 {
        self.gid
    }

    /// Mirrors `getNumberOfLinks()`.
    pub fn nlink(&self) -> u64 {
        self.nlink
    }

    /// Modification time in seconds since the epoch. Mirrors `getTime()`.
    pub fn time(&self) -> u64 {
        self.mtime
    }

    /// Modification time in epoch milliseconds, i.e. `getLastModifiedDate().getTime()`.
    pub fn last_modified_millis(&self) -> i64 {
        (self.mtime as i64).wrapping_mul(1000)
    }

    /// Size of the entry's data in bytes. Mirrors `getSize()`.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Offset of the entry's data within the archive.
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }

    /// Mirrors `getChksum()`; only the new formats carry one.
    ///
    /// # Errors
    /// `Unsupported` for the old formats (Java's `UnsupportedOperationException`).
    pub fn chksum(&self) -> io::Result<u64> {
        if self.is_new_format() { Ok(self.chksum) } else { Err(Self::unsupported("checksum")) }
    }

    /// Mirrors `getDevice()`; only the old formats carry one.
    ///
    /// # Errors
    /// `Unsupported` for the new formats.
    pub fn device(&self) -> io::Result<u64> {
        if self.is_new_format() { Err(Self::unsupported("device")) } else { Ok(self.device) }
    }

    /// Mirrors `getRemoteDevice()`; only the old formats carry one.
    ///
    /// # Errors
    /// `Unsupported` for the new formats.
    pub fn remote_device(&self) -> io::Result<u64> {
        if self.is_new_format() { Err(Self::unsupported("remote device")) } else { Ok(self.rdev) }
    }

    /// Mirrors `getDeviceMaj()`/`getDeviceMin()`/`getRemoteDeviceMaj()`/`getRemoteDeviceMin()`
    /// as a `(dev_maj, dev_min, rdev_maj, rdev_min)` tuple; only the new formats carry them.
    ///
    /// # Errors
    /// `Unsupported` for the old formats.
    pub fn device_numbers(&self) -> io::Result<(u64, u64, u64, u64)> {
        if self.is_new_format() {
            Ok((self.dev_maj, self.dev_min, self.rdev_maj, self.rdev_min))
        } else {
            Err(Self::unsupported("device numbers"))
        }
    }

    fn file_type(&self) -> u64 {
        self.mode & S_IFMT
    }

    /// Mirrors `isDirectory()`.
    pub fn is_directory(&self) -> bool {
        self.file_type() == C_ISDIR
    }

    /// Mirrors `isRegularFile()`.
    pub fn is_regular_file(&self) -> bool {
        self.file_type() == C_ISREG
    }

    /// Mirrors `isSymbolicLink()`.
    pub fn is_symbolic_link(&self) -> bool {
        self.file_type() == C_ISLNK
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected end of cpio archive")
}

/// Sequential reader over the entries of a cpio archive held in a [`ByteProvider`].
///
/// Mirrors commons-compress `CpioArchiveInputStream.getNextEntry()`.
pub struct CpioArchiveReader<'a> {
    provider: &'a dyn ByteProvider,
    pos: u64,
    /// The entry whose data has not been passed over yet.
    pending: Option<CpioArchiveEntry>,
    finished: bool,
}

impl<'a> CpioArchiveReader<'a> {
    /// Starts reading the archive at offset 0 of `provider`.
    pub fn new(provider: &'a dyn ByteProvider) -> Self {
        CpioArchiveReader { provider, pos: 0, pending: None, finished: false }
    }

    fn read(&mut self, len: u64) -> io::Result<Vec<u8>> {
        if self.pos.checked_add(len).is_none_or(|end| end > self.provider.length()) {
            return Err(eof());
        }
        let bytes = self.provider.read_bytes(self.pos, len)?;
        self.pos += len;
        Ok(bytes)
    }

    fn skip(&mut self, len: u64) -> io::Result<()> {
        if self.pos.checked_add(len).is_none_or(|end| end > self.provider.length()) {
            return Err(eof());
        }
        self.pos += len;
        Ok(())
    }

    fn read_ascii(&mut self, len: u64, radix: u32) -> io::Result<u64> {
        let bytes = self.read(len)?;
        let text = String::from_utf8_lossy(&bytes);
        u64::from_str_radix(&text, radix).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("For input string: \"{text}\": {e}"))
        })
    }

    /// `CpioUtil.byteArray2long(bytes, swapHalfWord)`.
    fn binary_long(bytes: &[u8], swap_half_word: bool) -> u64 {
        let mut tmp = bytes.to_vec();
        if swap_half_word {
            for pair in tmp.chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
        }
        tmp.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    }

    fn read_binary(&mut self, len: u64, swap: bool) -> io::Result<u64> {
        let bytes = self.read(len)?;
        Ok(Self::binary_long(&bytes, swap))
    }

    fn read_c_string(&mut self, len: u64) -> io::Result<String> {
        let bytes = self.read(len)?;
        let body = &bytes[..bytes.len().saturating_sub(1)];
        Ok(String::from_utf8_lossy(body).into_owned())
    }

    /// Passes over the pending entry's data and padding, verifying the checksum of CRC-format
    /// entries. Mirrors `closeEntry()` plus the end-of-entry handling in `read()`.
    fn close_entry(&mut self) -> io::Result<()> {
        let Some(entry) = self.pending.take() else { return Ok(()) };
        if entry.format == FORMAT_NEW_CRC {
            let data = self.read(entry.size)?;
            let crc = data.iter().fold(0u64, |acc, &b| (acc + u64::from(b)) & 0xFFFF_FFFF);
            self.skip(entry.pad_to_alignment(entry.size))?;
            if crc != entry.chksum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("CRC Error. Occurred at byte: {}", self.pos),
                ));
            }
        } else {
            self.skip(entry.size)?;
            self.skip(entry.pad_to_alignment(entry.size))?;
        }
        Ok(())
    }

    /// The next entry, or `None` once the trailer has been reached.
    ///
    /// # Errors
    /// `UnexpectedEof` when the archive is truncated; `InvalidData` for an unknown magic, an
    /// unknown file type, mode 0 on a non-trailer entry or a CRC mismatch.
    pub fn next_entry(&mut self) -> io::Result<Option<CpioArchiveEntry>> {
        self.close_entry()?;
        if self.finished {
            return Ok(None);
        }
        let magic2 = self.read(2)?;
        let entry = if Self::binary_long(&magic2, false) == MAGIC_OLD_BINARY {
            self.read_old_binary_entry(false)?
        } else if Self::binary_long(&magic2, true) == MAGIC_OLD_BINARY {
            self.read_old_binary_entry(true)?
        } else {
            let mut magic = magic2;
            magic.extend(self.read(4)?);
            match magic.as_slice() {
                MAGIC_NEW => self.read_new_entry(false)?,
                MAGIC_NEW_CRC => self.read_new_entry(true)?,
                MAGIC_OLD_ASCII => self.read_old_ascii_entry()?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Unknown magic [{}]. Occurred at byte: {}",
                            String::from_utf8_lossy(&magic),
                            self.pos
                        ),
                    ))
                }
            }
        };
        if entry.name == CPIO_TRAILER {
            self.finished = true;
            return Ok(None);
        }
        self.pending = Some(entry.clone());
        Ok(Some(entry))
    }

    fn set_mode_and_check(&mut self, entry: &mut CpioArchiveEntry, mode: u64) -> io::Result<()> {
        if mode & S_IFMT != 0 {
            entry.set_mode(mode)?;
        }
        Ok(())
    }

    fn finish_name(&mut self, entry: &mut CpioArchiveEntry, namesize: u64) -> io::Result<()> {
        entry.name = self.read_c_string(namesize)?;
        if entry.file_type() == 0 && entry.name != CPIO_TRAILER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Mode 0 only allowed in the trailer. Found entry name: {} Occurred at byte: {}",
                    entry.name, self.pos
                ),
            ));
        }
        let header_and_name = entry.header_size() + namesize;
        self.skip(entry.pad_to_alignment(header_and_name))?;
        entry.data_offset = self.pos;
        Ok(())
    }

    fn read_new_entry(&mut self, has_crc: bool) -> io::Result<CpioArchiveEntry> {
        let mut e = CpioArchiveEntry::new(if has_crc { FORMAT_NEW_CRC } else { FORMAT_NEW });
        e.inode = self.read_ascii(8, 16)?;
        let mode = self.read_ascii(8, 16)?;
        self.set_mode_and_check(&mut e, mode)?;
        e.uid = self.read_ascii(8, 16)?;
        e.gid = self.read_ascii(8, 16)?;
        e.nlink = self.read_ascii(8, 16)?;
        e.mtime = self.read_ascii(8, 16)?;
        e.size = self.read_ascii(8, 16)?;
        e.dev_maj = self.read_ascii(8, 16)?;
        e.dev_min = self.read_ascii(8, 16)?;
        e.rdev_maj = self.read_ascii(8, 16)?;
        e.rdev_min = self.read_ascii(8, 16)?;
        let namesize = self.read_ascii(8, 16)?;
        e.chksum = self.read_ascii(8, 16)?;
        self.finish_name(&mut e, namesize)?;
        Ok(e)
    }

    fn read_old_ascii_entry(&mut self) -> io::Result<CpioArchiveEntry> {
        let mut e = CpioArchiveEntry::new(FORMAT_OLD_ASCII);
        e.device = self.read_ascii(6, 8)?;
        e.inode = self.read_ascii(6, 8)?;
        let mode = self.read_ascii(6, 8)?;
        self.set_mode_and_check(&mut e, mode)?;
        e.uid = self.read_ascii(6, 8)?;
        e.gid = self.read_ascii(6, 8)?;
        e.nlink = self.read_ascii(6, 8)?;
        e.rdev = self.read_ascii(6, 8)?;
        e.mtime = self.read_ascii(11, 8)?;
        let namesize = self.read_ascii(6, 8)?;
        e.size = self.read_ascii(11, 8)?;
        self.finish_name(&mut e, namesize)?;
        Ok(e)
    }

    fn read_old_binary_entry(&mut self, swap: bool) -> io::Result<CpioArchiveEntry> {
        let mut e = CpioArchiveEntry::new(FORMAT_OLD_BINARY);
        e.device = self.read_binary(2, swap)?;
        e.inode = self.read_binary(2, swap)?;
        let mode = self.read_binary(2, swap)?;
        self.set_mode_and_check(&mut e, mode)?;
        e.uid = self.read_binary(2, swap)?;
        e.gid = self.read_binary(2, swap)?;
        e.nlink = self.read_binary(2, swap)?;
        e.rdev = self.read_binary(2, swap)?;
        e.mtime = self.read_binary(4, swap)?;
        let namesize = self.read_binary(2, swap)?;
        e.size = self.read_binary(4, swap)?;
        self.finish_name(&mut e, namesize)?;
        Ok(e)
    }

    /// Reads the data of the entry most recently returned by [`next_entry`](Self::next_entry)
    /// (Java's `readAllBytes()` on the stream positioned at that entry).
    ///
    /// # Errors
    /// `UnexpectedEof` if the data is truncated; `InvalidData` on a CRC mismatch.
    pub fn read_entry_data(&mut self) -> io::Result<Vec<u8>> {
        let Some(entry) = self.pending.clone() else { return Ok(Vec::new()) };
        let data = self.provider.read_bytes(entry.data_offset, entry.size);
        if entry.data_offset + entry.size > self.provider.length() {
            return Err(eof());
        }
        let data = data?;
        self.close_entry()?;
        Ok(data)
    }
}

/// Builders for synthetic archives, shared with the filesystem tests.
#[cfg(test)]
pub(crate) mod test_archives {
    use super::*;

    /// One newc (or crc, when `crc` is set) member.
    pub fn newc_member(name: &str, mode: u64, data: &[u8], crc: bool) -> Vec<u8> {
        let namesize = name.len() + 1;
        let chksum: u64 =
            if crc { data.iter().map(|&b| u64::from(b)).sum::<u64>() & 0xFFFF_FFFF } else { 0 };
        let mut out = Vec::new();
        out.extend_from_slice(if crc { b"070702" } else { b"070701" });
        for v in [7u64, mode, 1000, 100, 1, 1_600_000_000, data.len() as u64, 8, 1, 0, 0] {
            out.extend(format!("{v:08X}").bytes());
        }
        out.extend(format!("{namesize:08X}").bytes());
        out.extend(format!("{chksum:08X}").bytes());
        out.extend(name.bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// A complete newc archive of `(name, mode, data)` members plus the trailer.
    pub fn newc_archive(members: &[(&str, u64, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, mode, data) in members {
            out.extend(newc_member(name, *mode, data, false));
        }
        out.extend(newc_member(CPIO_TRAILER, 0, &[], false));
        out
    }

    /// One odc member.
    pub fn odc_member(name: &str, mode: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"070707");
        for v in [0o12u64, 0o34, mode, 0o1750, 0o144, 1, 0o5] {
            out.extend(format!("{v:06o}").bytes());
        }
        out.extend(format!("{:011o}", 1_600_000_000u64).bytes());
        out.extend(format!("{:06o}", name.len() + 1).bytes());
        out.extend(format!("{:011o}", data.len()).bytes());
        out.extend(name.bytes());
        out.push(0);
        out.extend_from_slice(data);
        out
    }

    /// One old-binary member in little- (`le`) or big-endian word order.
    pub fn binary_member(name: &str, mode: u64, data: &[u8], le: bool) -> Vec<u8> {
        let word = |v: u64| {
            let w = v as u16;
            if le { w.to_le_bytes() } else { w.to_be_bytes() }
        };
        let mut out = Vec::new();
        for v in [MAGIC_OLD_BINARY, 3, 9, mode, 1000, 100, 1, 4] {
            out.extend(word(v));
        }
        let mtime = 0x5F5E_1000u64;
        out.extend(word(mtime >> 16));
        out.extend(word(mtime & 0xFFFF));
        out.extend(word(name.len() as u64 + 1));
        out.extend(word(data.len() as u64 >> 16));
        out.extend(word(data.len() as u64 & 0xFFFF));
        out.extend(name.bytes());
        out.push(0);
        if out.len() % 2 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        if out.len() % 2 != 0 {
            out.push(0);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_archives::*;
    use super::*;
    use crate::filesystem::gfilesystem::abstract_single_payload_file_system::test_support::MemProvider;

    fn entries(bytes: Vec<u8>) -> io::Result<Vec<(CpioArchiveEntry, Vec<u8>)>> {
        let p = MemProvider::new(bytes, None);
        let mut r = CpioArchiveReader::new(&p);
        let mut out = Vec::new();
        while let Some(e) = r.next_entry()? {
            let data = r.read_entry_data()?;
            out.push((e, data));
        }
        Ok(out)
    }

    #[test]
    fn matches_signatures_like_commons_compress() {
        assert!(matches(b"070701xx", 8));
        assert!(matches(b"070702", 6));
        assert!(matches(b"070707", 6));
        assert!(!matches(b"070703", 6));
        assert!(!matches(b"07070", 5), "too short");
        assert!(!matches(b"070701", 5), "length limits the check");
        // Binary magic 0o070707 == 0x71C7, either byte order.
        assert!(matches(&[0x71, 0xc7, 0, 0, 0, 0], 6));
        assert!(matches(&[0xc7, 0x71, 0, 0, 0, 0], 6));
        assert!(matches(&newc_archive(&[("a", C_ISREG, b"x")]), 6));
        assert!(matches(&binary_member("a", C_ISREG, b"x", true), 6));
        assert!(matches(&binary_member("a", C_ISREG, b"x", false), 6));
        assert!(!matches(b"PK\x03\x04\0\0", 6));
    }

    #[test]
    fn reads_newc_entries_until_trailer() {
        let bytes = newc_archive(&[
            ("dir", C_ISDIR | 0o755, b""),
            ("dir/hello.txt", C_ISREG | 0o644, b"hello"),
            ("link", C_ISLNK | 0o777, b"dir/hello.txt"),
        ]);
        let es = entries(bytes).unwrap();
        assert_eq!(es.len(), 3);
        let (dir, _) = &es[0];
        assert!(dir.is_directory());
        assert_eq!(dir.format(), FORMAT_NEW);
        let (file, data) = &es[1];
        assert!(file.is_regular_file());
        assert_eq!(file.name(), "dir/hello.txt");
        assert_eq!(data, b"hello");
        assert_eq!(file.size(), 5);
        assert_eq!(file.uid(), 1000);
        assert_eq!(file.gid(), 100);
        assert_eq!(file.inode(), 7);
        assert_eq!(file.last_modified_millis(), 1_600_000_000_000);
        assert_eq!(file.device_numbers().unwrap(), (8, 1, 0, 0));
        assert!(file.device().is_err());
        assert_eq!(file.chksum().unwrap(), 0);
        let (link, target) = &es[2];
        assert!(link.is_symbolic_link());
        assert_eq!(target, b"dir/hello.txt");
    }

    #[test]
    fn skipping_data_without_reading_it() {
        let bytes = newc_archive(&[("a", C_ISREG, b"12345"), ("b", C_ISREG, b"xy")]);
        let p = MemProvider::new(bytes, None);
        let mut r = CpioArchiveReader::new(&p);
        let a = r.next_entry().unwrap().unwrap();
        let b = r.next_entry().unwrap().unwrap();
        assert_eq!((a.name(), b.name()), ("a", "b"));
        assert_eq!(p.read_bytes(b.data_offset(), b.size()).unwrap(), b"xy");
        assert!(r.next_entry().unwrap().is_none());
        assert!(r.next_entry().unwrap().is_none());
    }

    #[test]
    fn crc_format_is_verified() {
        let mut bytes = newc_member("f", C_ISREG, b"abc", true);
        bytes.extend(newc_member(CPIO_TRAILER, 0, &[], false));
        let es = entries(bytes.clone()).unwrap();
        assert_eq!(es[0].0.format(), FORMAT_NEW_CRC);
        assert_eq!(es[0].0.chksum().unwrap(), 97 + 98 + 99);
        // corrupt the data
        let data_at = es[0].0.data_offset() as usize;
        bytes[data_at] = b'z';
        let err = entries(bytes).unwrap_err();
        assert!(err.to_string().starts_with("CRC Error."), "{err}");
    }

    #[test]
    fn reads_odc_entries() {
        let mut bytes = odc_member("x/y", C_ISREG | 0o600, b"data!");
        bytes.extend(odc_member(CPIO_TRAILER, 0, b""));
        let es = entries(bytes).unwrap();
        assert_eq!(es.len(), 1);
        let (e, data) = &es[0];
        assert_eq!(e.format(), FORMAT_OLD_ASCII);
        assert_eq!(e.name(), "x/y");
        assert_eq!(data, b"data!");
        assert_eq!(e.device().unwrap(), 0o12);
        assert_eq!(e.remote_device().unwrap(), 0o5);
        assert_eq!(e.uid(), 0o1750);
        assert!(e.chksum().is_err());
        assert_eq!(e.time(), 1_600_000_000);
    }

    #[test]
    fn reads_old_binary_both_byte_orders() {
        for le in [true, false] {
            let mut bytes = binary_member("odd", C_ISREG, b"abc", le);
            bytes.extend(binary_member(CPIO_TRAILER, 0, b"", le));
            let es = entries(bytes).unwrap();
            assert_eq!(es.len(), 1, "le={le}");
            let (e, data) = &es[0];
            assert_eq!(e.format(), FORMAT_OLD_BINARY);
            assert_eq!(e.name(), "odd");
            assert_eq!(data, b"abc");
            assert_eq!(e.time(), 0x5F5E_1000);
            assert_eq!(e.device().unwrap(), 3);
            assert_eq!(e.inode(), 9);
        }
    }

    #[test]
    fn errors_match_commons_compress() {
        let err = entries(b"123456789".to_vec()).unwrap_err();
        assert!(err.to_string().starts_with("Unknown magic [123456]"), "{err}");

        let mut bytes = newc_member("zero", 0, b"", false);
        bytes.extend(newc_member(CPIO_TRAILER, 0, &[], false));
        let err = entries(bytes).unwrap_err();
        assert!(err.to_string().starts_with("Mode 0 only allowed in the trailer. Found entry name: zero"));

        let bytes = newc_archive(&[("bad", 0o070000, b"")]);
        let err = entries(bytes).unwrap_err();
        assert_eq!(err.to_string(), "Unknown mode. Full: 7000 Masked: 7000");

        let mut truncated = newc_archive(&[("a", C_ISREG, b"12345678")]);
        truncated.truncate(118);
        assert_eq!(entries(truncated).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn entries_compare_by_name() {
        let es = entries(newc_archive(&[("a", C_ISREG, b"1"), ("a", C_ISDIR, b"")])).unwrap();
        assert_eq!(es[0].0, es[1].0);
    }
}
