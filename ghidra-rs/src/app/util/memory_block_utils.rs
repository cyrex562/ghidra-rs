//! Port of `ghidra.app.util.MemoryBlockUtils`: convenience functions loaders use to create memory
//! blocks and file bytes in a [`Program`].
//!
//! Java's class is a holder of statics, so this is a plain module of free functions. Each
//! function goes through the program's [`Memory`](crate::program::model::mem::Memory) seam
//! ([`Program::get_memory_mut`]), so it works against any memory implementing the block-creation
//! methods -- in particular the real database-backed
//! [`MemoryMapDB`](crate::program::database::mem::MemoryMapDB) of a
//! [`ProgramDB`](crate::program::database::program_db::ProgramDB).
//!
//! # Return values
//!
//! Java returns `null` when it logged and swallowed a failure; that is `None` here. Exceptions
//! Java lets escape (its declared `AddressOverflowException` plus unchecked ones such as
//! `IllegalArgumentException`) come back as `Err`, so a caller can tell "logged and skipped"
//! apart from "the load must stop", as Java's callers can.
//!
//! # Divergences
//!
//! * `adjustFragment` (rename the program-tree fragment holding a new block after the block) is
//!   not applied: the ported [`Listing`](crate::program::model::listing::Listing) hands
//!   fragments out as shared `Arc`s whose `set_name` needs `&mut`, and `ProgramDB` has no
//!   program tree yet. See [`adjust_fragment`].

use std::io::{self, Read};
use std::sync::Arc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::importer::message_log::MessageLog;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::memory::CreateBlockError;
use crate::program::model::mem::memory_block::EXTERNAL_BLOCK_NAME;
use crate::program::model::mem::MemoryBlockHandle;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// The failure Java's `createInitializedBlock` overloads let escape (they log and return `null`
/// for everything else).
pub type BlockResult = Result<Option<MemoryBlockHandle>, CreateBlockError>;

fn no_memory() -> CreateBlockError {
    CreateBlockError::IllegalState("program has no memory".to_string())
}

/// Port of `createUninitializedBlock(Program, boolean, String, Address, long, String, String,
/// boolean, boolean, boolean, MessageLog)`: creates an uninitialized block and sets its
/// attributes. Every failure is logged and yields `None`, as in Java.
#[allow(clippy::too_many_arguments)]
pub fn create_uninitialized_block(
    program: &dyn Program,
    is_overlay: bool,
    name: &str,
    start: &Address,
    length: i64,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    log: &MessageLog,
) -> Option<MemoryBlockHandle> {
    let result = match program.get_memory_mut() {
        Some(mut memory) => memory.create_uninitialized_block(name, start, length, is_overlay),
        None => Err(no_memory()),
    };
    finish_logged(program, result, name, comment, source, r, w, x, log)
}

/// Port of `createInitializedBlock(Program, boolean, String, Address, long, String, String,
/// boolean, boolean, boolean, MessageLog)`: creates a zero-filled initialized block. Every
/// failure is logged and yields `None`, as in Java.
#[allow(clippy::too_many_arguments)]
pub fn create_zeroed_initialized_block(
    program: &dyn Program,
    is_overlay: bool,
    name: &str,
    start: &Address,
    length: i64,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    log: &MessageLog,
) -> Option<MemoryBlockHandle> {
    let result = match program.get_memory_mut() {
        Some(mut memory) => memory.create_initialized_block_from_stream(
            name,
            start,
            None,
            length,
            Some(&DummyMonitor),
            is_overlay,
        ),
        None => Err(no_memory()),
    };
    finish_logged(program, result, name, comment, source, r, w, x, log)
}

/// Shared tail of the two "log everything" creators: Java's `catch (LockException)` /
/// `catch (Exception)` messages, then `setBlockAttributes` + `adjustFragment`.
#[allow(clippy::too_many_arguments)]
fn finish_logged(
    program: &dyn Program,
    result: Result<MemoryBlockHandle, CreateBlockError>,
    name: &str,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    log: &MessageLog,
) -> Option<MemoryBlockHandle> {
    match result {
        Ok(block) => {
            set_block_attributes(&block, comment, source, r, w, x);
            let start = block.read().unwrap().get_start();
            adjust_fragment(program, &start, name);
            Some(block)
        }
        Err(CreateBlockError::Lock(_)) => {
            log.append_msg("Failed to create memory block: exclusive lock/checkout required");
            None
        }
        Err(e) => {
            log.append_msg(format!("Failed to create '{name}' memory block: {e}"));
            None
        }
    }
}

/// Port of `createInitializedBlock(Program, boolean, String, Address, FileBytes, long, long,
/// String, String, boolean, boolean, boolean, MessageLog)`: creates a block backed by `length`
/// bytes of `file_bytes` at `offset`.
///
/// If the block conflicts with an existing one, Java retries it in a new overlay space and logs
/// that it did; overlay creation is not ported (`MemoryMapDB` rejects it), so the retry's
/// failure is what comes back.
///
/// # Errors
/// Whatever Java lets escape: the conflict retry's failure (Java wraps it in a
/// `RuntimeException`), an address overflow, or an invalid argument / file-bytes range.
#[allow(clippy::too_many_arguments)]
pub fn create_initialized_block(
    program: &dyn Program,
    is_overlay: bool,
    name: &str,
    start: &Address,
    file_bytes: &Arc<dyn FileBytes>,
    offset: i64,
    length: i64,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    log: &MessageLog,
) -> BlockResult {
    if !program.has_exclusive_access() {
        log.append_msg("Failed to create memory block: exclusive access/checkout required");
        return Ok(None);
    }
    let block = {
        let mut memory = program.get_memory_mut().ok_or_else(no_memory)?;
        match memory.create_initialized_block_from_file_bytes(
            name,
            start,
            Arc::clone(file_bytes),
            offset,
            length,
            is_overlay,
        ) {
            Err(CreateBlockError::Conflict(_)) => {
                let block = memory.create_initialized_block_from_file_bytes(
                    name,
                    start,
                    Arc::clone(file_bytes),
                    offset,
                    length,
                    true,
                )?;
                log.append_msg(format!(
                    "Conflict attempting to create memory block: {name} at address {start} Created block in new overlay instead"
                ));
                block
            }
            other => other?,
        }
    };
    set_block_attributes(&block, comment, source, r, w, x);
    let block_start = block.read().unwrap().get_start();
    adjust_fragment(program, &block_start, name);
    Ok(Some(block))
}

/// Port of `createInitializedBlock(Program, boolean, String, Address, InputStream, long, String,
/// String, boolean, boolean, boolean, MessageLog, TaskMonitor)`: creates a block whose bytes are
/// read from `data_input`. A cancelled `monitor` yields `Ok(None)`, as Java's `null`.
///
/// # Errors
/// As for [`create_initialized_block`].
#[allow(clippy::too_many_arguments)]
pub fn create_initialized_block_from_stream(
    program: &dyn Program,
    is_overlay: bool,
    name: &str,
    start: &Address,
    data_input: &mut dyn Read,
    data_length: i64,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    log: &MessageLog,
    monitor: &dyn TaskMonitor,
) -> BlockResult {
    if !program.has_exclusive_access() {
        log.append_msg("Failed to create memory block: exclusive access/checkout required");
        return Ok(None);
    }
    let created = {
        let mut memory = program.get_memory_mut().ok_or_else(no_memory)?;
        match memory.create_initialized_block_from_stream(
            name,
            start,
            Some(&mut *data_input),
            data_length,
            Some(monitor),
            is_overlay,
        ) {
            Err(CreateBlockError::Conflict(_)) => {
                let retried = memory.create_initialized_block_from_stream(
                    name,
                    start,
                    Some(&mut *data_input),
                    data_length,
                    Some(monitor),
                    true,
                );
                if retried.is_ok() {
                    log.append_msg(format!(
                        "Conflict attempting to create memory block: {name} at address {start} Created block in new overlay instead"
                    ));
                }
                retried
            }
            other => other,
        }
    };
    let block = match created {
        Ok(block) => block,
        Err(CreateBlockError::Cancelled(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    set_block_attributes(&block, comment, source, r, w, x);
    let (block_start, block_name) = {
        let b = block.read().unwrap();
        (b.get_start(), b.get_name().to_string())
    };
    adjust_fragment(program, &block_start, &block_name);
    Ok(Some(block))
}

/// Port of `createBitMappedBlock(Program, String, Address, Address, int, String, String,
/// boolean, boolean, boolean, boolean, MessageLog)`: a block whose bytes are the bits of the bytes
/// at `base`. Every failure is logged and yields `None`, as in Java.
#[allow(clippy::too_many_arguments)]
pub fn create_bit_mapped_block(
    program: &dyn Program,
    name: &str,
    start: &Address,
    base: &Address,
    length: i32,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    overlay: bool,
    log: &MessageLog,
) -> Option<MemoryBlockHandle> {
    let result = match program.get_memory_mut() {
        Some(mut memory) => memory.create_bit_mapped_block(name, start, base, length as i64, overlay),
        None => Err(no_memory()),
    };
    match result {
        Ok(block) => {
            set_block_attributes(&block, comment, source, r, w, x);
            adjust_fragment(program, start, name);
            Some(block)
        }
        Err(CreateBlockError::Lock(_)) => {
            log.append_msg(format!(
                "Failed to create '{name}'bit mapped memory block: exclusive lock/checkout required"
            ));
            None
        }
        Err(e) => {
            log.append_msg(format!("Failed to create '{name}' mapped memory block: {e}"));
            None
        }
    }
}

/// Port of `createByteMappedBlock(Program, String, Address, Address, int, String, String,
/// boolean, boolean, boolean, boolean, MessageLog)`: a 1:1 byte-mapped block over the bytes at
/// `base`. Every failure is logged and yields `None`, as in Java.
#[allow(clippy::too_many_arguments)]
pub fn create_byte_mapped_block(
    program: &dyn Program,
    name: &str,
    start: &Address,
    base: &Address,
    length: i32,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
    overlay: bool,
    log: &MessageLog,
) -> Option<MemoryBlockHandle> {
    let result = match program.get_memory_mut() {
        Some(mut memory) => {
            memory.create_byte_mapped_block(name, start, base, length as i64, None, overlay)
        }
        None => Err(no_memory()),
    };
    match result {
        Ok(block) => {
            set_block_attributes(&block, comment, source, r, w, x);
            adjust_fragment(program, start, name);
            Some(block)
        }
        Err(CreateBlockError::Lock(_)) => {
            log.append_msg(format!(
                "Failed to create '{name}' byte mapped memory block: exclusive lock/checkout required"
            ));
            None
        }
        Err(e) => {
            log.append_msg(format!("Failed to create '{name}' mapped memory block: {e}"));
            None
        }
    }
}

/// Port of `addExternalBlock(Program, long, MessageLog)`: appends `size` bytes to the
/// `EXTERNAL` block (creating it, uninitialized, writable and artificial, at
/// [`get_next_available_address`] if there is none) and returns the address of the new piece.
///
/// # Errors
/// Whatever creating or joining the block fails with (Java's `throws Exception`).
pub fn add_external_block(program: &dyn Program, size: i64, log: &MessageLog) -> Result<Address, CreateBlockError> {
    let _ = log;
    let existing = program.get_memory().and_then(|m| {
        m.get_block_handles()
            .into_iter()
            .find(|b| b.read().unwrap().get_name() == EXTERNAL_BLOCK_NAME)
    });
    match existing {
        Some(external_block) => {
            let ret = external_block.read().unwrap().get_end().add(1)?;
            let mut mem = program.get_memory_mut().ok_or_else(no_memory)?;
            let new_block = mem.create_block(&external_block, EXTERNAL_BLOCK_NAME, &ret, size)?;
            mem.join(&external_block, &new_block)?;
            Ok(ret)
        }
        None => {
            let ret = get_next_available_address(program)?;
            let external_block = program
                .get_memory_mut()
                .ok_or_else(no_memory)?
                .create_uninitialized_block(EXTERNAL_BLOCK_NAME, &ret, size, false)?;
            let mut b = external_block.write().unwrap();
            b.set_write(true);
            b.set_artificial(true);
            b.set_comment(Some(
                "NOTE: This block is artificial and is used to make relocations work correctly",
            ));
            Ok(ret)
        }
    }
}

/// Port of `adjustFragment(Program, Address, String)`: Java renames the fragment containing
/// `address` in every program tree to `name`.
///
/// Not applied (see the module docs): the ported `Listing` hands fragments out as shared `Arc`s
/// and has no `&self` rename, and `ProgramDB` has no program tree for a fragment to live in, so
/// there is never a fragment this could rename yet. Kept as the single place to apply it once
/// the program tree is ported.
pub fn adjust_fragment(program: &dyn Program, address: &Address, name: &str) {
    let _ = (program, address, name);
}

/// Port of `createFileBytes(Program, ByteProvider, TaskMonitor)`: stores every byte of
/// `provider` as the program's original file bytes.
///
/// # Errors
/// An IO error reading `provider` or storing the bytes, or [`CreateBlockError::Cancelled`].
pub fn create_file_bytes(
    program: &dyn Program,
    provider: &dyn ByteProvider,
    monitor: &dyn TaskMonitor,
) -> Result<Arc<dyn FileBytes>, CreateBlockError> {
    create_file_bytes_range(program, provider, 0, provider.length() as i64, monitor)
}

/// Port of `createFileBytes(Program, ByteProvider, long, long, TaskMonitor)`: stores `length`
/// bytes of `provider` starting at `offset`. Java passes `provider.getName()` straight through;
/// a provider with no name stores an empty file name here.
///
/// # Errors
/// As for [`create_file_bytes`].
pub fn create_file_bytes_range(
    program: &dyn Program,
    provider: &dyn ByteProvider,
    offset: i64,
    length: i64,
    monitor: &dyn TaskMonitor,
) -> Result<Arc<dyn FileBytes>, CreateBlockError> {
    let mut fis = provider.get_input_stream(offset as u64)?;
    let name = provider.get_name().unwrap_or_default();
    let mut memory = program.get_memory_mut().ok_or_else(no_memory)?;
    memory.create_file_bytes(&name, offset, length, &mut fis, monitor)
}

/// Port of `getNextAvailableAddress(Program)`: the first 0x1000-aligned address past the end of
/// the highest non-overlay block, or `0x1000` in the default space if there are no blocks.
///
/// # Errors
/// `NotFound` if the program has no address factory / default space (Java would throw a
/// `NullPointerException`); an address overflow past the end of the space.
pub fn get_next_available_address(program: &dyn Program) -> io::Result<Address> {
    let mut max_address: Option<Address> = None;
    if let Some(memory) = program.get_memory() {
        for block in memory.get_block_handles() {
            let b = block.read().unwrap();
            if b.is_overlay() {
                continue;
            }
            let end = b.get_end();
            if max_address.as_ref().is_none_or(|max| end > *max) {
                max_address = Some(end);
            }
        }
    }
    let Some(max_address) = max_address else {
        let space = program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default address space"))?;
        return Ok(space.address(0x1000));
    };
    let max_addr = max_address.offset();
    let remainder = max_addr % 0x1000;
    max_address
        .space()
        .checked_address(max_addr + 0x1000 - remainder)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Port of the private `setBlockAttributes(MemoryBlock, String, String, boolean, boolean,
/// boolean)`.
fn set_block_attributes(
    block: &MemoryBlockHandle,
    comment: Option<&str>,
    source: Option<&str>,
    r: bool,
    w: bool,
    x: bool,
) {
    let mut b = block.write().unwrap();
    b.set_comment(comment);
    b.set_source_name(source);
    b.set_read(r);
    b.set_write(w);
    b.set_execute(x);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::program::database::program_db::ProgramDB;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::pcode::PackedDecode;

    /// A minimal `SleighLanguage` (one 32-bit little-endian `ram` space, no instructions) --
    /// the same packed `.sla` fixture `ProgramDB`'s own tests decode, parameterized on the space
    /// size in bytes and endianness so ELF64/ELF32 programs can be built.
    pub(crate) fn test_language(space_bytes: u8, big_endian: bool) -> Arc<SleighLanguage> {
        let mut data = vec![];
        // <sleigh version="4" bigendian=...>
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3]);
        data.push(if big_endian { 0x11 } else { 0x10 });
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size=N index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, space_bytes, 0xC9, 0x21, 1,
            0xE0, 0xAA, 0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0"> <scope id="0" parent="0"/> </symbol_table>
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);
        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap())
    }

    fn program() -> (ProgramDB, Arc<crate::program::model::address::AddressSpace>) {
        let language = test_language(4, false);
        let space = language.get_address_factory().get_default_address_space().unwrap();
        (ProgramDB::new("p".into(), language).unwrap(), space)
    }

    struct BytesProvider(Vec<u8>);
    impl ByteProvider for BytesProvider {
        fn get_file(&self) -> Option<std::path::PathBuf> {
            None
        }
        fn get_name(&self) -> Option<String> {
            Some("image.bin".into())
        }
        fn get_absolute_path(&self) -> Option<String> {
            None
        }
        fn length(&self) -> u64 {
            self.0.len() as u64
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            Ok(self.0[index as usize])
        }
        fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
            Ok(self.0[index as usize..(index + length) as usize].to_vec())
        }
    }

    #[test]
    fn file_bytes_block_gets_bytes_and_attributes() {
        let (program, space) = program();
        let provider = BytesProvider((0u8..64).collect());
        let fb = create_file_bytes(&program, &provider, &DummyMonitor).unwrap();
        assert_eq!(fb.get_filename(), "image.bin");
        assert_eq!(fb.get_size(), 64);
        let log = MessageLog::new();
        let block = create_initialized_block(
            &program,
            false,
            ".text",
            &space.address(0x1000),
            &fb,
            16,
            8,
            Some("code"),
            Some("Elf Loader"),
            true,
            false,
            true,
            &log,
        )
        .unwrap()
        .unwrap();
        let b = block.read().unwrap();
        assert_eq!(b.get_name(), ".text");
        assert_eq!(b.get_size(), 8);
        assert!(b.is_read() && !b.is_write() && b.is_execute());
        assert_eq!(b.get_comment(), Some("code"));
        assert_eq!(b.get_source_name(), Some("Elf Loader"));
        let mut out = [0u8; 8];
        assert_eq!(b.get_bytes(&space.address(0x1000), &mut out), 8);
        assert_eq!(out, [16, 17, 18, 19, 20, 21, 22, 23]);
    }

    #[test]
    fn uninitialized_and_zeroed_blocks() {
        let (program, space) = program();
        let log = MessageLog::new();
        let bss = create_uninitialized_block(
            &program, false, ".bss", &space.address(0x2000), 0x100, None, None, true, true, false,
            &log,
        )
        .unwrap();
        assert!(!bss.read().unwrap().is_initialized());
        assert!(bss.read().unwrap().is_write());
        let zero = create_zeroed_initialized_block(
            &program, false, "zero", &space.address(0x3000), 4, None, None, true, false, false,
            &log,
        )
        .unwrap();
        assert_eq!(zero.read().unwrap().get_byte(&space.address(0x3002)).unwrap(), 0);
        assert_eq!(Program::get_memory(&program).unwrap().get_block_handles().len(), 2);
    }

    #[test]
    fn conflicting_uninitialized_block_is_logged_and_none() {
        let (program, space) = program();
        let log = MessageLog::new();
        create_uninitialized_block(
            &program, false, "a", &space.address(0x2000), 0x100, None, None, true, true, false,
            &log,
        )
        .unwrap();
        let again = create_uninitialized_block(
            &program, false, "b", &space.address(0x2080), 0x100, None, None, true, true, false,
            &log,
        );
        assert!(again.is_none());
        assert!(log.to_string().contains("Failed to create 'b' memory block: Part of range"));
    }

    #[test]
    fn stream_block_reads_input() {
        let (program, space) = program();
        let log = MessageLog::new();
        let mut input: &[u8] = &[9, 8, 7];
        let block = create_initialized_block_from_stream(
            &program,
            false,
            "s",
            &space.address(0x10),
            &mut input,
            5,
            None,
            None,
            true,
            true,
            true,
            &log,
            &DummyMonitor,
        )
        .unwrap()
        .unwrap();
        let mut out = [0xFFu8; 5];
        assert_eq!(block.read().unwrap().get_bytes(&space.address(0x10), &mut out), 5);
        assert_eq!(out, [9, 8, 7, 0, 0]);
    }

    #[test]
    fn next_available_address_matches_java() {
        let (program, space) = program();
        assert_eq!(get_next_available_address(&program).unwrap(), space.address(0x1000));
        let log = MessageLog::new();
        create_uninitialized_block(
            &program, false, "a", &space.address(0x4000), 0x234, None, None, true, true, false,
            &log,
        )
        .unwrap();
        // max end 0x4233 -> 0x4233 + 0x1000 - 0x233
        assert_eq!(get_next_available_address(&program).unwrap(), space.address(0x5000));
    }

    #[test]
    fn external_block_is_created_then_extended() {
        let (program, space) = program();
        let log = MessageLog::new();
        create_uninitialized_block(
            &program, false, ".text", &space.address(0x1000), 0x234, None, None, true, false, true,
            &log,
        )
        .unwrap();
        let first = add_external_block(&program, 0x10, &log).unwrap();
        assert_eq!(first, space.address(0x2000));
        let second = add_external_block(&program, 0x8, &log).unwrap();
        assert_eq!(second, space.address(0x2010));
        let memory = Program::get_memory(&program).unwrap();
        let ext = memory.get_block_handle(&space.address(0x2000)).unwrap();
        let b = ext.read().unwrap();
        assert_eq!(b.get_name(), EXTERNAL_BLOCK_NAME);
        assert_eq!(b.get_size(), 0x18);
        assert!(b.is_write() && b.is_artificial() && !b.is_initialized());
        assert_eq!(
            b.get_comment(),
            Some("NOTE: This block is artificial and is used to make relocations work correctly")
        );
        assert_eq!(memory.get_block_handles().len(), 2);
    }

    #[test]
    fn mapped_blocks_get_attributes_and_log_failures() {
        let (program, space) = program();
        let log = MessageLog::new();
        create_zeroed_initialized_block(
            &program, false, "src", &space.address(0x10), 4, None, None, true, true, false, &log,
        )
        .unwrap();
        let bits = create_bit_mapped_block(
            &program, "bits", &space.address(0x100), &space.address(0x10), 32, Some("c"), None,
            true, false, false, false, &log,
        )
        .unwrap();
        assert_eq!(bits.read().unwrap().get_comment(), Some("c"));
        let bytes = create_byte_mapped_block(
            &program, "bytes", &space.address(0x200), &space.address(0x10), 4, None, None, true,
            true, false, false, &log,
        )
        .unwrap();
        assert!(bytes.read().unwrap().is_write());
        assert!(create_byte_mapped_block(
            &program, "dup", &space.address(0x200), &space.address(0x10), 4, None, None, true,
            true, false, false, &log,
        )
        .is_none());
        assert!(log.to_string().contains("Failed to create 'dup' mapped memory block: Part of range"));
    }

}
