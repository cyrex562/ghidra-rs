//! Port of `ghidra.app.util.opinion.DyldCacheUtils`.
//!
//! Utilities for working with DYLD shared caches, including [`SplitDyldCache`], which gathers a
//! cache together with its sub-caches (`dyld_shared_cache_arm64e.01`, ...) and `.symbols` file.
//!
//! Java's `SplitDyldCache` asks the process-wide `FileSystemService.getInstance()` for the
//! sibling sub-cache files. In this crate the [`FileSystemService`] is a value its owner
//! constructs (see its module docs), so [`SplitDyldCache::new`] takes the service to use.

use std::collections::{HashMap, HashSet};
use std::io;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::importer::message_log::MessageLog;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::format::macho::dyld::dyld_architecture::DyldArchitecture;
use crate::format::macho::dyld::dyld_cache_header::DyldCacheHeader;
use crate::format::macho::dyld::dyld_cache_image::DyldCacheImage;
use crate::format::macho::dyld::dyld_cache_image_info::DyldCacheImageInfo;
use crate::format::macho::dyld::dyld_cache_local_symbols_info::DyldCacheLocalSymbolsInfo;
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::program::model::listing::program::Program;
use crate::util::exception::CancelledException;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;

/// Java's `String.trim()`.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// Java: `isDyldCache(Program)`. True if the program's memory starts with a DYLD cache magic.
pub fn is_dyld_cache_program(program: &dyn Program) -> bool {
    let len = DyldArchitecture::DYLD_V1_SIGNATURE_LEN;
    let Some(memory) = program.get_memory() else {
        return false;
    };
    let size: u64 = memory.get_blocks().iter().map(|b| b.get_size()).sum();
    if size < len as u64 {
        return false;
    }
    let Some(address) = program.get_min_address() else {
        return false;
    };
    let mut bytes = vec![0u8; len];
    if memory.get_bytes(&address, &mut bytes) < len {
        return false;
    }
    is_dyld_cache(java_trim(&String::from_utf8_lossy(&bytes)))
}

/// Java: `isDyldCache(ByteProvider)`. True if the provider starts with a DYLD cache magic.
pub fn is_dyld_cache_provider(provider: &dyn ByteProvider) -> bool {
    match provider.read_bytes(0, DyldArchitecture::DYLD_V1_SIGNATURE_LEN as u64) {
        Ok(bytes) => is_dyld_cache(java_trim(&String::from_utf8_lossy(&bytes))),
        Err(_) => false,
    }
}

/// Java: `isDyldCache(String)`. True if `signature` is a known DYLD cache magic.
pub fn is_dyld_cache(signature: &str) -> bool {
    DyldArchitecture::ARCHITECTURES.iter().any(|a| a.signature() == signature)
}

/// A DYLD cache image and the index of the split-cache file that holds it.
///
/// Port of the record `DyldCacheUtils.DyldCacheImageRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldCacheImageRecord {
    /// Java: `image()`.
    pub image: DyldCacheImageInfo,
    /// Java: `splitCacheIndex()`.
    pub split_cache_index: usize,
}

/// Java: `getImageRecords(List<DyldCacheHeader>)`: every distinct image across `headers`, paired
/// with the split-cache file whose mappings contain it.
pub fn get_image_records(headers: &[DyldCacheHeader]) -> Vec<DyldCacheImageRecord> {
    let mut addrs = HashSet::new();
    let mut image_records = Vec::new();
    for header in headers {
        for image in header.get_image_infos() {
            if addrs.contains(&image.address()) {
                continue;
            }
            for (i, h) in headers.iter().enumerate() {
                if h.get_mapping_infos().iter().any(|m| m.contains(image.address() as i64, true)) {
                    image_records.push(DyldCacheImageRecord { image: image.clone(), split_cache_index: i });
                    addrs.insert(image.address());
                }
            }
        }
    }
    image_records
}

/// A DYLD cache that may be split across several files.
///
/// Port of `DyldCacheUtils.SplitDyldCache`. Java implements `Closeable` to close the sub-cache
/// providers it opened; here they are released when this value is dropped.
pub struct SplitDyldCache {
    providers: Vec<Rc<dyn ByteProvider>>,
    headers: Vec<DyldCacheHeader>,
    names: Vec<String>,
}

impl SplitDyldCache {
    /// Java: `SplitDyldCache(ByteProvider, boolean, MessageLog, TaskMonitor)`. Parses the base
    /// cache and, when it names sub-caches or a symbols file, every `<name>.*` sibling file (other
    /// than `.map` files) that is a DYLD cache, found through `fs_service`.
    ///
    /// # Errors
    /// I/O errors, a referenced sub-cache or symbols file that was not found, or cancellation.
    pub fn new(
        base_provider: Rc<dyn ByteProvider>,
        should_process_local_symbols: bool,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
        fs_service: &FileSystemService,
    ) -> Result<Self, SplitDyldCacheError> {
        let base_name = base_provider.get_name().unwrap_or_default();
        monitor.set_message(&format!("Parsing {base_name} headers..."));
        let mut cache = SplitDyldCache { providers: Vec::new(), headers: Vec::new(), names: Vec::new() };
        cache.providers.push(Rc::clone(&base_provider));
        let mut base_header = DyldCacheHeader::new(&BinaryReader::new(Rc::clone(&base_provider), true))?;
        base_header.parse_from_file(should_process_local_symbols, log, monitor)?;
        let no_subcaches = base_header.get_subcache_entries().is_empty();
        let symbol_file_uuid = base_header.get_symbol_file_uuid().map(<[u8]>::to_vec);
        let subcache_entries = base_header.get_subcache_entries().to_vec();
        cache.headers.push(base_header);
        cache.names.push(base_name.clone());
        if no_subcaches && symbol_file_uuid.is_none() {
            return Ok(cache);
        }

        let mut uuid_to_file_map: HashMap<String, Fsrl> = HashMap::new();
        for split_fsrl in find_split_dyld_cache_files(base_provider.get_fsrl(), fs_service, monitor)? {
            let split_name = split_fsrl.name().unwrap_or_default();
            monitor.set_message(&format!("Parsing {split_name} headers..."));
            let split_provider: Rc<dyn ByteProvider> =
                Rc::from(fs_service.get_byte_provider(&split_fsrl, false, monitor).map_err(fs_error)?);
            if !is_dyld_cache_provider(split_provider.as_ref()) {
                continue;
            }
            cache.providers.push(Rc::clone(&split_provider));
            let mut split_header = DyldCacheHeader::new(&BinaryReader::new(split_provider, true))?;
            split_header.parse_from_file(should_process_local_symbols, log, monitor)?;
            let uuid = NumericUtilities::convert_bytes_to_string(split_header.get_uuid().unwrap_or(&[]), "");
            cache.headers.push(split_header);
            cache.names.push(split_name);
            uuid_to_file_map.insert(uuid, split_fsrl);
        }

        for subcache_entry in &subcache_entries {
            let uuid = subcache_entry.get_uuid();
            let Some(fsrl) = uuid_to_file_map.get(&uuid) else {
                let extension = match subcache_entry.get_cache_extension() {
                    Some(ext) => format!("{base_name}{ext} - "),
                    None => String::new(),
                };
                return Err(SplitDyldCacheError::Io(io::Error::other(format!(
                    "Missing subcache: {extension}{uuid}"
                ))));
            };
            log.append_msg(&format!("Including subcache: {} - {uuid}", fsrl.name().unwrap_or_default()));
        }

        if let Some(symbol_uuid) = symbol_file_uuid {
            let symbol_uuid = NumericUtilities::convert_bytes_to_string(&symbol_uuid, "");
            let Some(symbol_fsrl) = uuid_to_file_map.get(&symbol_uuid) else {
                return Err(SplitDyldCacheError::Io(io::Error::other(format!(
                    "Missing symbols subcache: {base_name}.symbols - {symbol_uuid}"
                ))));
            };
            log.append_msg(&format!(
                "Including symbols subcache: {} - {symbol_uuid}",
                symbol_fsrl.name().unwrap_or_default()
            ));
        }
        Ok(cache)
    }

    /// Java: `SplitDyldCache(List<ByteProvider>, List<DyldCacheHeader>, List<String>, MessageLog,
    /// TaskMonitor)`: a split cache from already-parsed parts.
    pub fn from_parts(
        providers: Vec<Rc<dyn ByteProvider>>,
        headers: Vec<DyldCacheHeader>,
        names: Vec<String>,
    ) -> Self {
        SplitDyldCache { providers, headers, names }
    }

    /// Java: `getProvider(int)`.
    pub fn get_provider(&self, i: usize) -> &Rc<dyn ByteProvider> {
        &self.providers[i]
    }

    /// Java: `getDyldCacheHeader(int)`.
    pub fn get_dyld_cache_header(&self, i: usize) -> &DyldCacheHeader {
        &self.headers[i]
    }

    /// Mutable access to the `i`th header (Java mutates the same object through
    /// `getDyldCacheHeader`, e.g. `setFileBlock`/`parseFromMemory`).
    pub fn get_dyld_cache_header_mut(&mut self, i: usize) -> &mut DyldCacheHeader {
        &mut self.headers[i]
    }

    /// Java: `getName(int)`.
    pub fn get_name(&self, i: usize) -> &str {
        &self.names[i]
    }

    /// Java: `size()`, the number of cache files.
    pub fn size(&self) -> usize {
        self.providers.len()
    }

    /// Java: `getBaseAddress()`, the base cache's base address.
    pub fn get_base_address(&self) -> i64 {
        self.headers[0].get_base_address()
    }

    /// Java: `getLocalSymbolInfo()`: any file's local symbols info.
    pub fn get_local_symbol_info(&self) -> Option<&DyldCacheLocalSymbolsInfo> {
        self.headers.iter().find_map(DyldCacheHeader::get_local_symbols_info)
    }

    /// Java: `getImageRecords()`.
    pub fn get_image_records(&self) -> Vec<DyldCacheImageRecord> {
        get_image_records(&self.headers)
    }

    /// Java: `getMacho(DyldCacheImageRecord)`: the (unparsed) Mach-O header of a cached image.
    ///
    /// # Errors
    /// If the image's bytes are not a Mach-O header.
    pub fn get_macho(&self, image_record: &DyldCacheImageRecord) -> Result<MachHeader, MachException> {
        let i = image_record.split_cache_index;
        let offset = (image_record.image.address() as i64).wrapping_sub(self.headers[i].get_base_address());
        MachHeader::with_start_index_relative(Rc::clone(&self.providers[i]), offset as u64, false)
    }
}

/// Why [`SplitDyldCache::new`] failed (Java: `IOException`, `CancelledException`).
#[derive(Debug, thiserror::Error)]
pub enum SplitDyldCacheError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

fn fs_error(e: impl std::fmt::Display) -> SplitDyldCacheError {
    SplitDyldCacheError::Io(io::Error::other(e.to_string()))
}

/// Java: the private `findSplitDyldCacheFiles(FSRL, TaskMonitor)`: the sibling files named
/// `<base>.*` (except `*.map`), sorted by name.
fn find_split_dyld_cache_files(
    base_fsrl: Option<&Fsrl>,
    fs_service: &FileSystemService,
    monitor: &dyn TaskMonitor,
) -> Result<Vec<Fsrl>, SplitDyldCacheError> {
    let Some(base_fsrl) = base_fsrl else {
        return Ok(Vec::new());
    };
    let fs_ref = fs_service.get_filesystem(&base_fsrl.fs(), monitor).map_err(fs_error)?;
    let fs = fs_ref.get_filesystem();
    let base_file = fs
        .lookup(base_fsrl.path())?
        .ok_or_else(|| io::Error::other(format!("File not found: {base_fsrl}")))?;
    let base_name = base_file.get_name().to_string();
    // Java: fs.getListing(baseFile.getParentFile()).
    let path = base_file.get_path();
    let parent_path = match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    };
    let parent = fs.lookup(Some(parent_path))?;
    let mut ret: Vec<Fsrl> = fs
        .get_listing(parent.as_deref())?
        .iter()
        .filter(|f| f.get_name().starts_with(&format!("{base_name}.")))
        .filter(|f| !f.get_name().to_lowercase().ends_with(".map"))
        .map(|f| f.get_fsrl().clone())
        .collect();
    ret.sort_by(|a, b| a.name().cmp(&b.name()));
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::util::task::DummyMonitor;

    /// A minimal cache: header ending at 0x48 (through slide info), two mappings, one image at
    /// 0x7fff_2000_1000 (old-style image table at 0xa8).
    fn cache(magic: &str) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name(magic, 16).u32(0x48).u32(2).u32(0xa8).u32(1).u64(0);
        b.u64(0).u64(0).u64(0).u64(0);
        assert_eq!(b.len(), 0x48);
        b.u64(0x7fff_2000_0000).u64(0x2000).u64(0).u32(5).u32(5);
        b.u64(0x7fff_4000_0000).u64(0x1000).u64(0x2000).u32(3).u32(3);
        b.pad_to(0xa8).u64(0x7fff_2000_1000).u64(0).u64(0).u32(0xc8).u32(0);
        b.name("/usr/lib/libB.dylib", 32);
        b.pad_to(0x3000);
        b.buf
    }

    /// A cache header extending through `symbolFileUUID` (mapping table at 0x1a0) naming one
    /// subcache with `sub_uuid`.
    fn base_cache(sub_uuid: [u8; 16]) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name("dyld_v1  x86_64", 16).u32(0x1a0).u32(1).u32(0).u32(0).u64(0);
        b.pad_to(0x188).u32(0x200).u32(1).raw(&[0u8; 16]);
        assert_eq!(b.len(), 0x1a0);
        b.u64(0x1_8000_0000).u64(0x1000).u64(0).u32(1).u32(1);
        b.pad_to(0x200).raw(&sub_uuid).u64(0x4000).u8(0);
        b.pad_to(0x400);
        b.buf
    }

    /// A sub-cache file whose header carries `uuid` (mapping table at 0x68).
    fn sub_cache(uuid: [u8; 16]) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name("dyld_v1  x86_64", 16).u32(0x68).u32(1).u32(0).u32(0).u64(0);
        b.u64(0).u64(0).u64(0).u64(0).u64(0).u64(0).raw(&uuid);
        b.u64(0x1_8000_4000).u64(0x1000).u64(0).u32(1).u32(1);
        b.pad_to(0x200);
        b.buf
    }

    fn split_from_dir(sub_uuid: [u8; 16]) -> (Result<SplitDyldCache, SplitDyldCacheError>, MessageLog) {
        use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cache"), base_cache(sub_uuid)).unwrap();
        std::fs::write(dir.path().join("cache.01"), sub_cache([0x42; 16])).unwrap();
        std::fs::write(dir.path().join("cache.02"), b"not a cache").unwrap();
        std::fs::write(dir.path().join("cache.map"), sub_cache([0x42; 16])).unwrap();
        let svc = FileSystemService::new(&dir.path().join("fscache"), FileSystemFactoryMgr::new()).unwrap();
        let fsrl = svc.get_local_fsrl(&dir.path().join("cache"));
        let base: Rc<dyn ByteProvider> = Rc::from(svc.get_byte_provider(&fsrl, false, &DummyMonitor).unwrap());
        let log = MessageLog::new();
        let result = SplitDyldCache::new(base, false, &log, &DummyMonitor, &svc);
        (result, log)
    }

    #[test]
    fn finds_and_verifies_sub_caches() {
        let (split, log) = split_from_dir([0x42; 16]);
        let split = split.unwrap();
        assert_eq!(split.size(), 2);
        assert_eq!(split.get_name(0), "cache");
        assert_eq!(split.get_name(1), "cache.01");
        assert_eq!(split.get_dyld_cache_header(1).get_mapping_infos()[0].get_address(), 0x1_8000_4000);
        assert_eq!(log.messages(), [format!("Including subcache: cache.01 - {}", "42".repeat(16))]);

        let (missing, _) = split_from_dir([0x77; 16]);
        let Err(err) = missing else { panic!("expected a missing-subcache error") };
        assert_eq!(err.to_string(), format!("Missing subcache: {}", "77".repeat(16)));
    }

    #[test]
    fn signature_checks() {
        assert!(is_dyld_cache("dyld_v1  x86_64"));
        assert!(!is_dyld_cache("dyld_v1   bogus"));
        assert!(is_dyld_cache_provider(provider(cache("dyld_v1  x86_64")).as_ref()));
        assert!(!is_dyld_cache_provider(provider(vec![0; 4]).as_ref()));
    }

    #[test]
    fn image_records_and_macho_lookup() {
        let p = provider(cache("dyld_v1  x86_64"));
        let mut h = DyldCacheHeader::new(&BinaryReader::new(Rc::clone(&p), true)).unwrap();
        h.parse_from_file(false, &MessageLog::new(), &DummyMonitor).unwrap();
        let split = SplitDyldCache::from_parts(vec![p], vec![h], vec!["cache".into()]);
        assert_eq!(split.size(), 1);
        assert_eq!(split.get_base_address(), 0x7fff_2000_0000);
        assert!(split.get_local_symbol_info().is_none());
        let records = split.get_image_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].split_cache_index, 0);
        assert_eq!(records[0].image.get_path(), "/usr/lib/libB.dylib");
        // The image's bytes (offset 0x1000) are zero, so they are not a Mach-O header.
        assert!(split.get_macho(&records[0]).is_err());
    }
}
