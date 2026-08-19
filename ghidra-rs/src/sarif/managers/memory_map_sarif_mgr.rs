//! Port of `sarif.managers.MemoryMapSarifMgr`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read as _, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::listing::Program;
use crate::program::model::mem::{Memory, MemoryBlock};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use crate::sarif::managers::memory_map_bytes_file::MemoryMapBytesFile;
use crate::sarif::seam_stubs::{
    MemoryBlockUtils, MessageLog, ProgramSarifMgr, SarifMemoryMapWriter, SarifMgr, SarifProgramOptions,
    SarifUtils, SarifWriterTask, TaskLauncher,
};

/// Everything [`MemoryMapSarifMgr::process_memory_block`] can fail with -- both propagated to
/// [`MemoryMapSarifMgr::read`], which logs and returns `false` for either.
///
/// Java's `processMemoryBlock` also lets an uncaught `RuntimeException` ("Unexpected number of
/// ranges for block @ ...") escape when `SarifUtils.getLocations` does not resolve to exactly one
/// range; `read`'s own `catch (FileNotFoundException | AddressOverflowException e)` does not catch
/// it, so in Java it crashes the whole read pipeline. [`SarifUtils::get_locations`] is a
/// placeholder pending its own port and never resolves a location, so that branch fires on every
/// call; rather than reproduce a crash that would fire unconditionally, [`UnexpectedRangeCount`]
/// folds it into the same log-and-return-`false` handling as the other two -- the precedent
/// [`ExternalLibSarifMgr::process_external_location`](crate::sarif::managers::ExternalLibSarifMgr)
/// sets for a different permanently-blocked (there, NPE-shaped) path.
///
/// [`UnexpectedRangeCount`]: ProcessMemoryBlockError::UnexpectedRangeCount
#[derive(Error, Debug)]
enum ProcessMemoryBlockError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error("Unexpected number of ranges for block @ {address}: {count}")]
    UnexpectedRangeCount { address: String, count: usize },
    #[error(transparent)]
    FileNotFound(#[from] std::io::Error),
}

/// What [`MemoryMapSarifMgr::set_data`] can fail with.
#[derive(Debug)]
enum SetDataError {
    /// `RandomAccessFile(File, String)` throwing `FileNotFoundException`: opening the backing file
    /// failed. The only `setData` failure `processMemoryBlock`'s inner
    /// `catch (FileNotFoundException e) { throw e; }` re-throws; every other failure is logged and
    /// swallowed there instead.
    FileNotFound(std::io::Error),
    /// The `directory`/`fileName` pair fails Java's `FileUtilities.isPathContainedWithin` check
    /// (a bare `RuntimeException`), or a seek/read after the file was opened fails (an
    /// `IOException`); both are swallowed by `processMemoryBlock`'s generic `catch (Exception e)`.
    Other(String),
}

/// Everything [`MemoryMapSarifMgr::write`] can fail with, combining `write`'s own
/// `IOException`/`CancelledException`.
#[derive(Error, Debug)]
pub enum MemoryMapWriteError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Reads and writes `MEMORY_MAP` entries -- memory blocks, and optionally their byte contents --
/// between a [`Program`]'s [`Memory`] and SARIF.
///
/// Port of `sarif.managers.MemoryMapSarifMgr`, which extends the abstract `SarifMgr`; that base
/// class is modeled here via composition (see [`SarifMgr`]) rather than inheritance, which Rust
/// does not have. Unlike Java, which caches nothing beyond `programMgr`, this keeps the whole
/// `Program` handle and re-fetches its `Memory`/`AddressFactory` on each use, matching the
/// convention set by [`ExternalLibSarifMgr`](crate::sarif::managers::ExternalLibSarifMgr) and
/// [`MarkupSarifMgr`](crate::sarif::managers::MarkupSarifMgr).
///
/// Java's `bf` field only exists to let `write`'s `finally` block close the bytes file created
/// earlier in the same call; since Rust ownership makes that unnecessary (the file can simply be
/// a local closed before `write` returns), it is not carried as a struct field here.
pub struct MemoryMapSarifMgr {
    base: SarifMgr,
    log: MessageLog,
    program: Arc<dyn Program>,
    program_mgr: ProgramSarifMgr,
}

impl MemoryMapSarifMgr {
    /// `MemoryMapSarifMgr.KEY`.
    pub const KEY: &'static str = "MEMORY_MAP";
    /// `MemoryMapSarifMgr.SUBKEY`.
    pub const SUBKEY: &'static str = "MemorySection";

    /// `MemoryMapSarifMgr(ProgramSarifMgr programMgr, Program program, MessageLog log)`.
    pub fn new(program_mgr: ProgramSarifMgr, program: Arc<dyn Program>, log: MessageLog) -> Self {
        Self {
            base: SarifMgr::new(Self::KEY),
            log,
            program,
            program_mgr,
        }
    }

    /// `SarifMgr.getKey()`, inherited from the base class.
    pub fn get_key(&self) -> &str {
        self.base.get_key()
    }

    // ------------------------------------------------------------------
    // SARIF READ CURRENT DTD
    // ------------------------------------------------------------------

    /// `MemoryMapSarifMgr.read`.
    pub fn read(
        &mut self,
        result: &HashMap<String, Value>,
        _options: Option<&SarifProgramOptions>,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        let directory = self.program_mgr.get_directory().to_string();
        match self.process_memory_block(result, &directory, monitor) {
            Ok(()) => true,
            Err(e) => {
                self.log.append_exception(&e);
                false
            }
        }
    }

    /// `MemoryMapSarifMgr.processMemoryBlock`.
    fn process_memory_block(
        &mut self,
        result: &HashMap<String, Value>,
        directory: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ProcessMemoryBlockError> {
        let name = result.get("name").and_then(Value::as_str).unwrap_or_default();
        let set = SarifUtils::get_locations(result, self.program.as_ref(), None)?;
        let min_address = set.min_address();
        if set.num_address_ranges() != 1 {
            return Err(ProcessMemoryBlockError::UnexpectedRangeCount {
                address: min_address.map(|a| a.to_string()).unwrap_or_else(|| "<none>".to_string()),
                count: set.num_address_ranges(),
            });
        }
        let block_address = min_address.expect("exactly one address range implies a minimum address");
        let max_address = set.max_address().expect("exactly one address range implies a maximum address");
        let length = (max_address.subtract(&block_address) as i32) + 1;

        let permissions = result.get("kind").and_then(Value::as_str).unwrap_or("r");
        let r = permissions.contains('r');
        let w = permissions.contains('w');
        let x = permissions.contains('x');

        let is_volatile = result.get("isVolatile").and_then(Value::as_bool).unwrap_or(false);
        let is_artificial = result.get("isArtificial").and_then(Value::as_bool).unwrap_or(false);

        let comment = result.get("comment").and_then(Value::as_str);
        let block_type = result.get("type").and_then(Value::as_str).unwrap_or_default();
        // `location == position of the bytes w/i file (file::pos)`.
        let loc = result.get("location").and_then(Value::as_str);

        let mut block: Option<Arc<dyn MemoryBlock>> = None;
        match block_type {
            "DEFAULT" => match loc {
                None => {
                    block = MemoryBlockUtils::create_uninitialized_block(
                        self.program.as_ref(),
                        false,
                        name,
                        &block_address,
                        length as i64,
                        comment,
                        None,
                        r,
                        w,
                        x,
                        &self.log,
                    );
                }
                Some(loc) => {
                    let mut split = loc.splitn(2, ':');
                    let file_name = split.next().unwrap_or_default();
                    let file_offset: i32 = split.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                    match self.set_data(directory, file_name, file_offset, length) {
                        Ok(bytes) => {
                            block = MemoryBlockUtils::create_initialized_block(
                                self.program.as_ref(),
                                false,
                                name,
                                &block_address,
                                &bytes,
                                comment,
                                None,
                                r,
                                w,
                                x,
                                &self.log,
                                monitor,
                            );
                        }
                        Err(SetDataError::FileNotFound(e)) => return Err(ProcessMemoryBlockError::FileNotFound(e)),
                        Err(SetDataError::Other(msg)) => self.log.append_msg(msg),
                    }
                }
            },
            "BIT_MAPPED" => {
                let source_addr = loc.and_then(|l| self.address(l));
                block = MemoryBlockUtils::create_bit_mapped_block(
                    self.program.as_ref(),
                    name,
                    &block_address,
                    source_addr.as_ref(),
                    length,
                    comment,
                    comment,
                    r,
                    w,
                    x,
                    false,
                    &self.log,
                );
            }
            "BYTE_MAPPED" => {
                let source_addr = loc.and_then(|l| self.address(l));
                block = MemoryBlockUtils::create_byte_mapped_block(
                    self.program.as_ref(),
                    name,
                    &block_address,
                    source_addr.as_ref(),
                    length,
                    comment,
                    comment,
                    r,
                    w,
                    x,
                    false,
                    &self.log,
                );
            }
            other => {
                self.log.append_msg(format!("Unexpected type value - {other}"));
            }
        }

        if let Some(block) = block.as_mut().and_then(Arc::get_mut) {
            block.set_volatile(is_volatile);
            block.set_artificial(is_artificial);
        }

        Ok(())
    }

    /// `factory.getAddress(String)`, where `factory` is the base class's cached
    /// `program.getAddressFactory()`; re-fetched here since this field-less port keeps only the
    /// whole `Program` handle.
    fn address(&self, addr_string: &str) -> Option<Address> {
        self.program.get_address_factory()?.get_address(addr_string)
    }

    /// `MemoryMapSarifMgr.setData`.
    fn set_data(&self, directory: &str, file_name: &str, file_offset: i32, length: i32) -> Result<Vec<u8>, SetDataError> {
        let length = length.max(0) as usize;
        let mut bytes = vec![0xffu8; length];

        let dir = Path::new(directory);
        let f = normalize_lexically(&dir.join(file_name));
        if !f.starts_with(normalize_lexically(dir)) {
            return Err(SetDataError::Other(format!("{file_name} not found within {directory}")));
        }

        let mut file = File::open(&f).map_err(SetDataError::FileNotFound)?;
        let mut pos = 0usize;
        while pos < length {
            let read_len = (512 * 1024).min(length - pos);
            file.seek(SeekFrom::Start(file_offset as u64 + pos as u64))
                .map_err(|e| SetDataError::Other(e.to_string()))?;
            let n = file
                .read(&mut bytes[pos..pos + read_len])
                .map_err(|e| SetDataError::Other(e.to_string()))?;
            if n == 0 {
                break;
            }
            pos += n;
        }
        Ok(bytes)
    }

    // ------------------------------------------------------------------
    // SARIF WRITE CURRENT DTD
    // ------------------------------------------------------------------

    /// `MemoryMapSarifMgr.write`.
    pub fn write(
        &mut self,
        results: &mut Vec<Value>,
        addrs: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
        is_write_contents: bool,
        file_path: &str,
    ) -> Result<(), MemoryMapWriteError> {
        monitor.set_message("Writing MEMORY MAP ...");

        let memory_handle = self.program.get_memory();
        let mut request: Vec<(AddressRange, Arc<dyn MemoryBlock>)> = Vec::new();
        if let Some(memory) = memory_handle.as_deref() {
            for range in addrs.address_ranges() {
                monitor.check_cancelled()?;
                let rb = RangeBlock::new(memory, &range);
                request.extend(rb.into_pairs());
            }
        }

        if is_write_contents {
            let memory: &dyn Memory = memory_handle
                .as_deref()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "program has no memory"))?;
            let mut bf = MemoryMapBytesFile::new(memory, file_path)?;
            Self::write_as_sarif(request, Some(&mut bf), true, results, monitor);
            bf.close()?;
        } else {
            Self::write_as_sarif(request, None, false, results, monitor);
        }

        Ok(())
    }

    /// `MemoryMapSarifMgr.writeAsSARIF`.
    pub fn write_as_sarif(
        request: Vec<(AddressRange, Arc<dyn MemoryBlock>)>,
        bytes: Option<&mut MemoryMapBytesFile>,
        is_write_contents: bool,
        results: &mut Vec<Value>,
        monitor: &dyn TaskMonitor,
    ) {
        // `bytesFile` is not stored on the placeholder writer: `SarifWriterTask::run` does not
        // read it back yet (see `SarifMemoryMapWriter`'s doc comment), and the caller already
        // keeps the real handle alive across this call to flush/close it afterward.
        let _ = bytes;
        let writer = SarifMemoryMapWriter::new(request, is_write_contents);
        let task = SarifWriterTask::new(Self::SUBKEY, writer);
        TaskLauncher::launch(&task, monitor, results);
    }
}

/// Resolves `.`/`..` components without touching the filesystem, mirroring the effect of Java's
/// `File.getCanonicalFile()` well enough for [`MemoryMapSarifMgr::set_data`]'s containment check
/// -- unlike `Path::starts_with`, which compares components lexically and so would treat
/// `dir.join("../outside.bin")` as starting with `dir` (its first two components still match).
fn normalize_lexically(path: &Path) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

/// `sarif.managers.RangeBlock`: splits an [`AddressRange`] into the sub-ranges covered by each
/// [`MemoryBlock`] it overlaps, pairing each sub-range with its owning block.
struct RangeBlock {
    range_list: Vec<AddressRange>,
    block_list: Vec<Arc<dyn MemoryBlock>>,
}

impl RangeBlock {
    /// `RangeBlock(AddressFactory af, Memory memory, AddressRange range)`. `af` goes unused in
    /// Java too, so it is not part of this port's signature.
    fn new(memory: &dyn Memory, range: &AddressRange) -> Self {
        let mut range_list = Vec::new();
        let mut block_list = Vec::new();
        let mut set = AddressSet::from_range(range.clone());
        while !set.is_empty() {
            let min = set.min_address().expect("non-empty set has a minimum address");
            // Java dereferences `memory.getBlock(...)` unconditionally here, so a `null` block
            // (an address claimed by `range` but not actually backed by any block) would throw
            // an uncaught `NullPointerException`. Stopping instead avoids fabricating a panic for
            // a `Memory` implementation that has not filled in `get_block`.
            let Some(block) = memory.get_block(&min) else {
                break;
            };
            set.delete_range(&block.get_start(), &block.get_end());
            let block_range = AddressRange::new(block.get_start(), block.get_end());
            if let Some(intersection) = range.intersect(&block_range) {
                range_list.push(intersection);
                block_list.push(block);
            }
        }
        Self { range_list, block_list }
    }

    /// `RangeBlock.getRanges()`/`RangeBlock.getBlocks()`, zipped back into the `Pair`s Java builds
    /// from them at the call site.
    fn into_pairs(self) -> Vec<(AddressRange, Arc<dyn MemoryBlock>)> {
        self.range_list.into_iter().zip(self.block_list).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{MemoryAccessException, MemoryBlockType};
    use crate::util::task::DummyMonitor;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn empty_mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    #[test]
    fn key_and_subkey_match_java() {
        assert_eq!(MemoryMapSarifMgr::KEY, "MEMORY_MAP");
        assert_eq!(MemoryMapSarifMgr::SUBKEY, "MemorySection");
    }

    #[test]
    fn get_key_returns_memory_map() {
        let mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        assert_eq!(mgr.get_key(), "MEMORY_MAP");
    }

    #[test]
    fn read_logs_and_returns_false_while_sarif_utils_is_unported() {
        // `SarifUtils::get_locations` is a placeholder pending its own port: it never resolves a
        // location, so `set.getNumAddressRanges() != 1` (0 != 1) fires on every call. Java's
        // equivalent is an uncaught `RuntimeException` that crashes the whole read pipeline; this
        // port folds it into `read`'s existing log-and-return-`false` path instead (see
        // `ProcessMemoryBlockError`'s doc comment) so the manager stays callable.
        let mut mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        let result: HashMap<String, Value> = [("name".to_string(), Value::String("ram".to_string()))].into();

        assert!(!mgr.read(&result, None, &DummyMonitor));
        let messages = mgr.log.messages();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Unexpected number of ranges"), "{}", messages[0]);
    }

    #[test]
    fn set_data_reads_the_requested_slice_of_the_backing_file() {
        let dir = std::env::temp_dir().join(format!("memory_map_sarif_mgr_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("blob.bin");
        std::fs::write(&file_path, (0u8..20).collect::<Vec<u8>>()).unwrap();

        let mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        let bytes = mgr.set_data(dir.to_str().unwrap(), "blob.bin", 4, 6).unwrap();
        assert_eq!(bytes, vec![4, 5, 6, 7, 8, 9]);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_data_rejects_a_file_name_that_escapes_the_directory() {
        let dir = std::env::temp_dir().join(format!("memory_map_sarif_mgr_test_escape_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        let err = mgr.set_data(dir.to_str().unwrap(), "../outside.bin", 0, 4).unwrap_err();
        assert!(matches!(err, SetDataError::Other(msg) if msg.contains("not found within")));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_data_reports_a_missing_file_as_file_not_found() {
        let dir = std::env::temp_dir().join(format!("memory_map_sarif_mgr_test_missing_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        let err = mgr.set_data(dir.to_str().unwrap(), "nope.bin", 0, 4).unwrap_err();
        assert!(matches!(err, SetDataError::FileNotFound(_)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    struct FakeBlock {
        name: &'static str,
        start: Address,
        end: Address,
    }

    impl MemoryBlock for FakeBlock {
        fn get_name(&self) -> &str {
            self.name
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            self.end.clone()
        }
        fn get_size(&self) -> u64 {
            (self.end.subtract(&self.start) + 1) as u64
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn get_type(&self) -> MemoryBlockType {
            MemoryBlockType::Default
        }
    }

    struct FakeMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks.iter().find(|b| b.contains(addr)).cloned()
        }
    }

    #[test]
    fn range_block_splits_a_range_across_the_blocks_it_overlaps() {
        // Two adjoining blocks (0x1000..=0x100f and 0x1010..=0x101f) covering a single requested
        // range (0x1000..=0x101f): the split should produce one sub-range per block.
        let block_a: Arc<dyn MemoryBlock> = Arc::new(FakeBlock {
            name: "a",
            start: addr(0x1000),
            end: addr(0x100f),
        });
        let block_b: Arc<dyn MemoryBlock> = Arc::new(FakeBlock {
            name: "b",
            start: addr(0x1010),
            end: addr(0x101f),
        });
        let memory = FakeMemory {
            blocks: vec![block_a, block_b],
        };
        let range = AddressRange::new(addr(0x1000), addr(0x101f));

        let rb = RangeBlock::new(&memory, &range);
        let pairs = rb.into_pairs();

        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, AddressRange::new(addr(0x1000), addr(0x100f)));
        assert_eq!(pairs[0].1.get_name(), "a");
        assert_eq!(pairs[1].0, AddressRange::new(addr(0x1010), addr(0x101f)));
        assert_eq!(pairs[1].1.get_name(), "b");
    }

    #[test]
    fn range_block_stops_when_a_gap_has_no_backing_block() {
        // A single block only covers half the requested range; the other half has no block, so
        // Rust stops (rather than reproducing Java's NullPointerException).
        let block_a: Arc<dyn MemoryBlock> = Arc::new(FakeBlock {
            name: "a",
            start: addr(0x2000),
            end: addr(0x200f),
        });
        let memory = FakeMemory { blocks: vec![block_a] };
        let range = AddressRange::new(addr(0x2000), addr(0x201f));

        let rb = RangeBlock::new(&memory, &range);
        let pairs = rb.into_pairs();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, AddressRange::new(addr(0x2000), addr(0x200f)));
    }

    #[test]
    fn write_with_no_memory_produces_an_empty_request_and_no_results() {
        let mut mgr = MemoryMapSarifMgr::new(ProgramSarifMgr::new("."), empty_mock_program(), MessageLog::new());
        let addrs = AddressSet::from_range(AddressRange::new(addr(0), addr(0xff)));
        let mut results = Vec::new();

        assert!(mgr.write(&mut results, &addrs, &DummyMonitor, false, "unused").is_ok());
        assert!(results.is_empty());
    }

    #[test]
    fn write_as_sarif_with_empty_request_leaves_results_empty() {
        let mut results = Vec::new();
        MemoryMapSarifMgr::write_as_sarif(Vec::new(), None, false, &mut results, &DummyMonitor);
        assert!(results.is_empty());
    }

    #[test]
    fn set_volatile_default_discards_the_request() {
        // Sanity check for the `MemoryBlock::set_volatile` default grown alongside this port:
        // matches `is_volatile`'s constant `false`, the same relationship `set_artificial` has to
        // `is_artificial`.
        let mut block = FakeBlock {
            name: "a",
            start: addr(0),
            end: addr(0xf),
        };
        block.set_volatile(true);
        assert!(!block.is_volatile());
    }
}
