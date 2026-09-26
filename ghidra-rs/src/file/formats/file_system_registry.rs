//! Explicit registration of this module's filesystems with a
//! [`FileSystemFactoryMgr`](crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr).
//!
//! Java discovers every `GFileSystem` class (and its `@FileSystemInfo` factory) by scanning the
//! classpath; Rust has no classpath, so the filesystems ported here are listed explicitly.
//! Filesystems whose factories are still unported are not listed.

use std::rc::Rc;

use crate::filesystem::gfilesystem::abstract_single_payload_file_system::SinglePayloadFileSystem;
use crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr;

use super::complzss::comp_lzss_file_system::CompLzssFileSystem;
use super::complzss::comp_lzss_file_system_factory::CompLzssFileSystemFactory;
use super::cpio::cpio_file_system::CpioFileSystem;
use super::cpio::cpio_file_system_factory::CpioFileSystemFactory;
use super::gzip::g_zip_file_system::GZipFileSystem;
use super::gzip::g_zip_file_system_factory::GZipFileSystemFactory;

/// Registers every filesystem in `crate::file::formats` that has a ported factory.
pub fn register_file_system_factories(mgr: &mut FileSystemFactoryMgr) {
    mgr.register::<CompLzssFileSystem>(&CompLzssFileSystem::INFO, Rc::new(CompLzssFileSystemFactory));
    mgr.register::<CpioFileSystem>(&CpioFileSystem::INFO, Rc::new(CpioFileSystemFactory));
    mgr.register::<GZipFileSystem>(&GZipFileSystem::INFO, Rc::new(GZipFileSystemFactory));
}

/// A [`FileSystemFactoryMgr`] with every ported filesystem registered.
pub fn default_factory_mgr() -> FileSystemFactoryMgr {
    let mut mgr = FileSystemFactoryMgr::new();
    register_file_system_factories(&mut mgr);
    mgr
}

#[cfg(test)]
mod tests {
    //! End-to-end tests of the filesystem service over real container files.

    use std::cell::Cell;
    use std::io::{Read, Write};
    use std::path::Path;

    use flate2::{Compression, GzBuilder};

    use super::*;
    use crate::app::util::bin::byte_provider::ByteProvider;
    use crate::filesystem::gfilesystem::annotations::file_system_info::PRIORITY_LOWEST;
    use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::filesystem::gfilesystem::g_file_system::{AnyGFileSystem, GFileSystemError};
    use crate::util::task::DummyMonitor;

    const PAYLOAD: &[u8] = b"The quick brown fox jumps over the lazy dog.\n0123456789\n";

    fn write_gzip(path: &Path, name: Option<&str>, payload: &[u8]) {
        let f = std::fs::File::create(path).unwrap();
        let mut b = GzBuilder::new().mtime(1_600_000_000);
        if let Some(n) = name {
            b = b.filename(n);
        }
        let mut enc = b.write(f, Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap();
    }

    fn service(dir: &Path) -> FileSystemService {
        FileSystemService::new(&dir.join("fscache"), default_factory_mgr()).unwrap()
    }

    #[test]
    fn registry_lists_ported_filesystems() {
        let mgr = default_factory_mgr();
        assert_eq!(mgr.get_file_system_type::<GZipFileSystem>().as_deref(), Some("gzip"));
        let names = mgr.get_all_filesystem_names();
        assert!(names.contains(&"GZIP".to_string()));
        assert_eq!(mgr.get_file_system_type::<CpioFileSystem>().as_deref(), Some("cpio"));
        assert!(names.contains(&"CPIO".to_string()));
    }

    /// A container as `CompLzssFileSystemFactory` accepts it: an `LzssCompressionHeader` whose
    /// first two ints are `"lzss"`, `"comp"` (Java's probe order), then the LZSS stream.
    fn lzss_container_bytes(payload: &[u8]) -> Vec<u8> {
        use crate::file::formats::lzss::lzss_constants::PADDING_LENGTH;
        let mut compressed = Vec::new();
        crate::file::formats::lzss::lzss_codec::compress(&mut compressed, &mut &payload[..]).unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(b"lzsscomp");
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        b.extend(std::iter::repeat_n(0u8, PADDING_LENGTH));
        b.extend_from_slice(&compressed);
        b
    }

    #[test]
    fn lzss_payload_by_fsrl_string_is_decompressed_through_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("kernelcache");
        let payload: Vec<u8> = PAYLOAD.iter().copied().cycle().take(5000).collect();
        std::fs::write(&container, lzss_container_bytes(&payload)).unwrap();
        let svc = service(dir.path());

        let fsrl =
            Fsrl::from_string(&format!("file://{}|lzss:///lzss_decompressed", container.display())).unwrap();
        let bp = svc.get_byte_provider(&fsrl, false, &DummyMonitor).unwrap();
        assert_eq!(bp.length(), payload.len() as u64);
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), payload);
        assert!(bp.get_fsrl().unwrap().md5().is_some());
        drop(bp);

        let local = svc.get_local_fsrl(&container);
        let fs_ref = svc
            .probe_file_for_filesystem(&local, &DummyMonitor, None, PRIORITY_LOWEST)
            .unwrap()
            .expect("lzss recognized");
        let fs = std::rc::Rc::clone(fs_ref.get_filesystem());
        assert_eq!(fs.get_type(), "lzss");
        assert_eq!(fs.get_description(), "LZSS Compression");
        let listing = fs.get_listing(None).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "lzss_decompressed");
        assert!(svc.has_derived_file(&svc.get_fully_qualified_fsrl(&local, &DummyMonitor).unwrap(), "decompressed lzss", &DummyMonitor).unwrap());
        svc.release_file_system_immediate(Some(fs_ref));
        assert!(fs.is_closed());
    }

    #[test]
    fn apple_comp_lzss_order_is_not_probed_like_java() {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("apple.lzss");
        let mut bytes = lzss_container_bytes(PAYLOAD);
        bytes[..8].copy_from_slice(b"complzss");
        std::fs::write(&container, bytes).unwrap();
        let svc = service(dir.path());
        let local = svc.get_local_fsrl(&container);
        assert!(!svc.is_file_filesystem_container(&local, &DummyMonitor).unwrap());
    }

    fn cpio_archive_bytes() -> Vec<u8> {
        use crate::file::formats::cpio::cpio_archive::test_archives::newc_archive;
        use crate::file::formats::cpio::cpio_archive::{C_ISDIR, C_ISLNK, C_ISREG};
        newc_archive(&[
            ("bin", C_ISDIR | 0o755, b""),
            ("bin/busybox", C_ISREG | 0o755, PAYLOAD),
            ("bin/sh", C_ISLNK | 0o777, b"busybox"),
            ("etc/motd", C_ISREG | 0o644, b"welcome\n"),
        ])
    }

    #[test]
    fn cpio_member_by_fsrl_string_reads_through_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("initrd.cpio");
        std::fs::write(&archive, cpio_archive_bytes()).unwrap();
        let svc = service(dir.path());

        let fsrl = Fsrl::from_string(&format!("file://{}|cpio:///bin/busybox", archive.display())).unwrap();
        let bp = svc.get_byte_provider(&fsrl, false, &DummyMonitor).unwrap();
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), PAYLOAD);
        let got = bp.get_fsrl().unwrap();
        assert_eq!(got.path(), Some("/bin/busybox"));
        assert!(got.md5().is_some());
        drop(bp);

        // Symlinks resolve through the mounted filesystem.
        let sh = Fsrl::from_string(&format!("file://{}|cpio:///bin/sh", archive.display())).unwrap();
        let refd = svc.get_refd_file(&sh, &DummyMonitor).unwrap();
        let fs = std::rc::Rc::clone(refd.fs_ref.get_filesystem());
        assert_eq!(fs.get_type(), "cpio");
        assert_eq!(fs.get_description(), "CPIO");
        let bp = fs.get_byte_provider(&*refd.file, &DummyMonitor).unwrap().unwrap();
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), PAYLOAD);
        drop(bp);
        assert_eq!(svc.get_mounted_filesystems().len(), 1);

        // Listing through the erased view.
        let root = fs.lookup(None).unwrap().unwrap();
        let names: Vec<String> =
            fs.get_listing(Some(&*root)).unwrap().iter().map(|f| f.get_name().to_string()).collect();
        assert_eq!(names, ["bin", "etc"]);

        refd.close().unwrap();
        svc.close_unused_file_systems();
        assert!(fs.is_closed());
        assert!(fs.get_ref_manager().is_closed());
        assert!(svc.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn cpio_container_is_probed_and_directories_have_no_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("root.cpio");
        std::fs::write(&archive, cpio_archive_bytes()).unwrap();
        let svc = service(dir.path());
        let container = svc.get_local_fsrl(&archive);
        assert!(svc.is_file_filesystem_container(&container, &DummyMonitor).unwrap());
        let fs_ref = svc
            .probe_file_for_filesystem(&container, &DummyMonitor, None, PRIORITY_LOWEST)
            .unwrap()
            .expect("cpio recognized");
        let fs = std::rc::Rc::clone(fs_ref.get_filesystem());
        // root + bin + busybox + sh + etc (auto-created) + motd
        assert_eq!(fs.get_file_count(), 6);
        let motd = fs.lookup(Some("/etc/motd")).unwrap().unwrap();
        let bp = fs.get_byte_provider(&*motd, &DummyMonitor).unwrap().unwrap();
        assert_eq!(bp.read_bytes(0, 8).unwrap(), b"welcome\n");
        let bin = fs.lookup(Some("/bin")).unwrap().unwrap();
        assert!(fs.get_byte_provider(&*bin, &DummyMonitor).is_err(), "not a regular file");
        drop(bp);
        svc.release_file_system_immediate(Some(fs_ref));
        assert!(fs.is_closed());
    }

    #[test]
    fn byte_provider_by_nested_fsrl_string_reads_decompressed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("x.gz");
        write_gzip(&gz, Some("hello.txt"), PAYLOAD);
        let svc = service(dir.path());
        let fsrl = Fsrl::from_string(&format!("file://{}|gzip:///hello.txt", gz.display())).unwrap();
        let bp = svc.get_byte_provider(&fsrl, false, &DummyMonitor).unwrap();
        assert_eq!(bp.read_bytes(0, bp.length()).unwrap(), PAYLOAD);
        // The returned FSRL is fully qualified with the payload's MD5.
        let expected_md5 = crate::filesystem::gfilesystem::fs_utilities::get_md5_of_stream(
            &mut &PAYLOAD[..],
            "",
            PAYLOAD.len() as i64,
            &DummyMonitor,
        )
        .unwrap();
        assert_eq!(bp.get_fsrl().unwrap().md5(), Some(expected_md5.as_str()));
        // The gzip filesystem stays mounted in the cache.
        assert_eq!(svc.get_mounted_filesystems().len(), 1);
        assert!(svc.is_filesystem_mounted_at(&svc.get_local_fsrl(&gz)));
    }

    #[test]
    fn probe_mount_list_read_and_close_after_last_ref() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("archive.gz");
        write_gzip(&gz, None, PAYLOAD);
        let svc = service(dir.path());
        let container = svc.get_local_fsrl(&gz);
        assert!(svc.is_file_filesystem_container(&container, &DummyMonitor).unwrap());

        let fs_ref = svc
            .probe_file_for_filesystem(&container, &DummyMonitor, None, PRIORITY_LOWEST)
            .unwrap()
            .expect("gzip recognized");
        let fs = std::rc::Rc::clone(fs_ref.get_filesystem());
        assert_eq!(fs.get_type(), "gzip");
        assert_eq!(fs.get_name(), "archive.gz");
        let root = fs.lookup(None).unwrap().unwrap();
        let listing = fs.get_listing(Some(&*root)).unwrap();
        // No name in the header: the container name minus ".gz".
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].get_name(), "archive");
        assert_eq!(listing[0].get_length(), PAYLOAD.len() as i64);
        let bp = fs.get_byte_provider(&*listing[0], &DummyMonitor).unwrap().unwrap();
        assert_eq!(bp.read_bytes(0, PAYLOAD.len() as u64).unwrap(), PAYLOAD);
        drop(bp);

        // A second probe finds the mounted instance.
        let again = svc
            .probe_file_for_filesystem(&container, &DummyMonitor, None, PRIORITY_LOWEST)
            .unwrap()
            .unwrap();
        assert!(std::rc::Rc::ptr_eq(again.get_filesystem(), &fs));

        // While refs are held the filesystem survives cache cleanup...
        svc.close_unused_file_systems();
        assert!(!fs.is_closed());
        // ...and once the last outside ref is gone it is closed and evicted.
        drop(again);
        svc.release_file_system_immediate(Some(fs_ref));
        assert!(fs.is_closed());
        assert!(svc.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn close_unused_closes_filesystems_no_one_references() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("y.gz");
        write_gzip(&gz, Some("y.bin"), PAYLOAD);
        let svc = service(dir.path());
        let refd = svc
            .get_refd_file(&Fsrl::from_string(&format!("file://{}|gzip:///y.bin", gz.display())).unwrap(), &DummyMonitor)
            .unwrap();
        assert_eq!(refd.file.get_name(), "y.bin");
        let fs = std::rc::Rc::clone(refd.fs_ref.get_filesystem());
        svc.close_unused_file_systems();
        assert!(!fs.is_closed(), "the RefdFile pins it");
        refd.close().unwrap();
        svc.close_unused_file_systems();
        assert!(fs.is_closed());
    }

    #[test]
    fn derived_provider_reuses_md5_keyed_cache_entry() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let container = Fsrl::from_string("file:///c.bin?MD5=0123456789abcdef0123456789abcdef").unwrap();
        let calls = Cell::new(0);
        let mut producer = || -> Result<Box<dyn Read>, GFileSystemError> {
            calls.set(calls.get() + 1);
            Ok(Box::new(std::io::Cursor::new(b"derived bytes".to_vec())))
        };
        let a = svc
            .get_derived_byte_provider(&container, None, "derived", -1, &mut producer, &DummyMonitor)
            .unwrap();
        let b = svc
            .get_derived_byte_provider(&container, None, "derived", -1, &mut producer, &DummyMonitor)
            .unwrap();
        assert_eq!(calls.get(), 1, "second request served from the cache");
        assert_eq!(a.get_fsrl(), b.get_fsrl());
        let md5 = a.get_fsrl().unwrap().md5().unwrap().to_string();
        assert_eq!(a.get_fsrl().unwrap().to_string(), format!("cache:///{md5}?MD5={md5}"));
        assert_eq!(b.read_bytes(0, 13).unwrap(), b"derived bytes");
        assert!(svc.has_derived_file(&container, "derived", &DummyMonitor).unwrap());
        assert!(!svc.has_derived_file(&container, "other", &DummyMonitor).unwrap());
        // A container FSRL without an MD5 is rejected.
        let bad = Fsrl::from_string("file:///c.bin").unwrap();
        assert!(svc.get_derived_byte_provider(&bad, None, "d", -1, &mut producer, &DummyMonitor).is_err());

        // The push flavor shares the cache.
        let mut pusher = |os: &mut dyn Write| -> Result<(), GFileSystemError> {
            os.write_all(b"pushed")?;
            Ok(())
        };
        let derived_fsrl = Fsrl::from_string("file:///c.bin|x:///p").unwrap();
        let p = svc
            .get_derived_byte_provider_push(&container, Some(&derived_fsrl), "pushed", 6, &mut pusher, &DummyMonitor)
            .unwrap();
        assert_eq!(p.read_bytes(0, 6).unwrap(), b"pushed");
        assert_eq!(p.get_fsrl().unwrap().path(), Some("/p"));
        assert!(p.get_fsrl().unwrap().md5().is_some());
    }

    #[test]
    fn gzip_payload_is_cached_across_remounts() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("z.gz");
        write_gzip(&gz, Some("z.txt"), PAYLOAD);
        let svc = service(dir.path());
        let fsrl = Fsrl::from_string(&format!("file://{}|gzip:///z.txt", gz.display())).unwrap();
        let fq = svc.get_fully_qualified_fsrl(&fsrl, &DummyMonitor).unwrap();
        assert!(fq.md5().is_some());
        assert!(fq.fs().container().unwrap().md5().is_some(), "container re-homed to its fully qualified FSRL");
        svc.clear();
        assert!(svc.get_mounted_filesystems().is_empty());
        // With the MD5 known, the bytes come straight from the file cache.
        let bp = svc.get_byte_provider(&fq, false, &DummyMonitor).unwrap();
        assert_eq!(bp.read_bytes(0, PAYLOAD.len() as u64).unwrap(), PAYLOAD);
        assert!(svc.get_mounted_filesystems().is_empty());
    }

    #[test]
    fn mount_specific_and_open_container_are_unmanaged() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("s.gz");
        write_gzip(&gz, Some("s.txt"), PAYLOAD);
        let svc = service(dir.path());
        let container = svc.get_local_fsrl(&gz);
        let fs = svc
            .mount_specific_file_system::<GZipFileSystem>(&container, &DummyMonitor)
            .unwrap()
            .unwrap();
        let payload = fs.get_payload_file().unwrap();
        assert_eq!(crate::filesystem::gfilesystem::g_file::GFile::get_name(payload), "s.txt");
        assert!(svc.get_mounted_filesystems().is_empty());
        let opened = svc.open_file_system_container(&container, &DummyMonitor).unwrap().unwrap();
        assert_eq!(opened.get_description(), "GZIP");
        opened.close().unwrap();
        // Not a registered type: None.
        let none = svc
            .mount_specific_file_system::<crate::filesystem::gfilesystem::local_file_system::LocalFileSystem>(
                &container,
                &DummyMonitor,
            )
            .unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn non_container_probes_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("plain.txt");
        std::fs::write(&f, b"just text").unwrap();
        let svc = service(dir.path());
        let container = svc.get_local_fsrl(&f);
        assert!(!svc.is_file_filesystem_container(&container, &DummyMonitor).unwrap());
        assert!(svc
            .probe_file_for_filesystem(&container, &DummyMonitor, None, PRIORITY_LOWEST)
            .unwrap()
            .is_none());
        // Local files come back through the root filesystem with a hashed FSRL.
        let bp = svc.get_byte_provider(&container, true, &DummyMonitor).unwrap();
        assert_eq!(bp.read_bytes(0, 9).unwrap(), b"just text");
        assert_eq!(svc.get_file_if_available(&*bp), Some(f.clone()));
        assert!(bp.get_fsrl().unwrap().md5().is_some());
        // A stale MD5 is detected.
        let stale = container.with_md5(Some("00000000000000000000000000000000"));
        assert!(svc.get_byte_provider(&stale, false, &DummyMonitor).is_err());
    }

    #[test]
    fn named_temp_file_and_push_file_to_cache() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        let mut b = svc.create_temp_file(-1).unwrap();
        b.write_all(b"temp!").unwrap();
        let fce = b.finish().unwrap();
        let named = svc.get_named_temp_file(&fce, "n.bin").unwrap();
        assert_eq!(named.get_fsrl().unwrap().to_string(), format!("tmp:///n.bin?MD5={}", fce.get_md5()));
        assert_eq!(named.read_bytes(0, 5).unwrap(), b"temp!");

        let plain = dir.path().join("give.txt");
        std::fs::write(&plain, b"given").unwrap();
        let fsrl = svc.get_local_fsrl(&plain);
        let pushed = svc.push_file_to_cache(&plain, &fsrl, &DummyMonitor).unwrap();
        assert!(!plain.exists());
        assert_eq!(pushed.read_bytes(0, 5).unwrap(), b"given");
        svc.release_file_cache(pushed.get_fsrl().unwrap());
    }
}
