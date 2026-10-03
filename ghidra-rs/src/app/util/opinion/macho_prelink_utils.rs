//! Partial port of `ghidra.app.util.opinion.MachoPrelinkUtils`: only the two byte-provider
//! predicates, `isMachoPrelink` and `isMachoFileset`.
//!
//! The rest of the class (`parsePrelinkXml`, `findPrelinkMachoHeaderOffsets`, `getMachoLoadSpec`,
//! `matchPrelinkToMachoHeaderOffsets`) stays parked in `DESCENT_PARKED.tsv`: it needs
//! `MachoLoader`. The class's manifest row therefore stays TODO.
//!
//! Java constructs `MachHeader`s directly over the probed provider. This crate's [`MachHeader`]
//! owns an `Rc<dyn ByteProvider>`, while probes only borrow a `&dyn ByteProvider`, so these
//! predicates parse a copy of the provider's header-plus-load-commands region (`sizeofcmds`
//! bytes after the header), which is all either check reads.

use std::rc::Rc;

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::format::macho::commands::load_command_types::LC_FILESET_ENTRY;
use crate::format::macho::mach_constants::{MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64};
use crate::format::macho::mach_header::MachHeader;

/// A copy of `provider`'s Mach-O header and load commands, or `None` if it does not start with
/// a Mach-O magic.
fn header_region(provider: &dyn ByteProvider) -> Option<Rc<dyn ByteProvider>> {
    let head = provider.read_bytes(0, 0x20.min(provider.length())).ok()?;
    if head.len() < 0x1c {
        return None;
    }
    let magic_be = u32::from_be_bytes(head[0..4].try_into().ok()?);
    let (little, is64) = match magic_be {
        MH_MAGIC => (false, false),
        MH_MAGIC_64 => (false, true),
        MH_CIGAM => (true, false),
        MH_CIGAM_64 => (true, true),
        _ => return None,
    };
    let raw = head[0x14..0x18].try_into().ok()?;
    let size_of_cmds = if little { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) } as u64;
    let header_size = if is64 { 0x20 } else { 0x1c };
    let len = (header_size + size_of_cmds).min(provider.length());
    let bytes = provider.read_bytes(0, len).ok()?;
    Some(Rc::new(ByteArrayProvider::new(bytes)))
}

/// Java `isMachoPrelink(ByteProvider, TaskMonitor)`: a Mach-O with a `__PRELINK*` segment and no
/// `LC_FILESET_ENTRY` load commands.
pub fn is_macho_prelink(provider: &dyn ByteProvider) -> bool {
    let Some(region) = header_region(provider) else {
        return false;
    };
    let check = || -> Result<bool, crate::format::macho::mach_exception::MachException> {
        let mut header = MachHeader::new(Rc::clone(&region))?;
        let has_prelink_segment = MachHeader::new(Rc::clone(&region))?
            .parse_segments()?
            .iter()
            .any(|s| s.get_segment_name().starts_with("__PRELINK"));
        let has_file_set = header.parse_and_check(LC_FILESET_ENTRY)?;
        Ok(has_prelink_segment && !has_file_set)
    };
    check().unwrap_or(false)
}

/// Java `isMachoFileset(ByteProvider)`: a Mach-O with at least one `LC_FILESET_ENTRY` load
/// command.
pub fn is_macho_fileset(provider: &dyn ByteProvider) -> bool {
    let Some(region) = header_region(provider) else {
        return false;
    };
    MachHeader::new(region)
        .and_then(|mut h| h.parse_and_check(LC_FILESET_ENTRY))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_SEGMENT_64;
    use crate::format::macho::mach_header::test_support::Bytes;

    fn macho(commands: &[(u32, &str)]) -> Vec<u8> {
        let mut b = Bytes::new(true);
        let sizeofcmds: u32 = commands.iter().map(|(c, _)| if *c == LC_SEGMENT_64 { 72 } else { 32 }).sum();
        b.u32(MH_MAGIC_64).u32(0x0100_000c).u32(0).u32(0xc).u32(commands.len() as u32).u32(sizeofcmds).u32(0).u32(0);
        for (cmd, name) in commands {
            if *cmd == LC_SEGMENT_64 {
                b.u32(LC_SEGMENT_64).u32(72).name(name, 16).u64(0).u64(0).u64(0).u64(0).u32(0).u32(0).u32(0).u32(0);
            } else {
                // fileset_entry_command: vmaddr, fileoff, entry_id offset, reserved, then id
                b.u32(*cmd).u32(32).u64(0).u64(0).u32(24).u32(0);
                b.name(name, 0);
            }
        }
        b.pad_to(0x200);
        b.buf
    }

    #[test]
    fn fileset_and_prelink_predicates() {
        let fileset = ByteArrayProvider::new(macho(&[(LC_SEGMENT_64, "__TEXT"), (LC_FILESET_ENTRY, "")]));
        assert!(is_macho_fileset(&fileset));
        assert!(!is_macho_prelink(&fileset));

        let prelink = ByteArrayProvider::new(macho(&[(LC_SEGMENT_64, "__PRELINK_TEXT")]));
        assert!(is_macho_prelink(&prelink));
        assert!(!is_macho_fileset(&prelink));

        let plain = ByteArrayProvider::new(macho(&[(LC_SEGMENT_64, "__TEXT")]));
        assert!(!is_macho_prelink(&plain));
        assert!(!is_macho_fileset(&plain));

        assert!(!is_macho_fileset(&ByteArrayProvider::new(vec![0u8; 64])));
        assert!(!is_macho_prelink(&ByteArrayProvider::new(vec![0xcf, 0xfa])));
    }
}
