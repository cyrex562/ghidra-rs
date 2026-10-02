//! `BinaryLoader` tests over a real `ProgramDB`.

use std::sync::Arc;

use super::*;
use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::memory_block_utils::tests::test_language;
use crate::app::util::opinion::abstract_program_loader::{ANCHOR_LABELS_OPTION_NAME, APPLY_LABELS_OPTION_NAME};
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::AddressSpace;
use crate::util::task::DummyMonitor;

fn program() -> (ProgramDB, Arc<AddressSpace>) {
    let language = test_language(4, false);
    let space = language
        .get_address_factory()
        .get_default_address_space_arc();
    (ProgramDB::new("raw".into(), language).unwrap(), space)
}

trait DefaultSpace {
    fn get_default_address_space_arc(&self) -> Arc<AddressSpace>;
}

impl DefaultSpace for Arc<crate::program::model::address::DefaultAddressFactory> {
    fn get_default_address_space_arc(&self) -> Arc<AddressSpace> {
        use crate::program::model::address::factory::AddressFactory as _;
        self.get_default_address_space().unwrap()
    }
}

fn opt_hex(name: &str, v: i64) -> Box<dyn Option> {
    new_hex_long(name).value(Box::new(HexLong::new(v))).build()
}

#[test]
fn loader_identity_matches_java() {
    let l = BinaryLoader::new();
    assert_eq!(l.get_name(), "Raw Binary");
    assert_eq!(l.get_tier(), LoaderTier::UntargetedLoader);
    assert_eq!(l.get_tier_priority(), 100);
    assert!(l.supports_load_into_program());
    assert!(l.should_apply_processor_labels_by_default());
}

#[test]
fn default_options_match_java() {
    let (program, space) = program();
    let provider = ByteArrayProvider::new(vec![0u8; 0x30]);
    let options = BinaryLoader.get_default_options(&provider, Some(&program), false);
    let names: Vec<String> = options.iter().map(|o| o.get_name()).collect();
    assert_eq!(
        names,
        vec![
            OPTION_NAME_BLOCK_NAME,
            OPTION_NAME_BASE_ADDR,
            OPTION_NAME_FILE_OFFSET,
            OPTION_NAME_LEN,
            APPLY_LABELS_OPTION_NAME,
            ANCHOR_LABELS_OPTION_NAME
        ]
    );
    assert_eq!(options[1].get_value().downcast_ref::<std::option::Option<Address>>(), Some(&Some(space.address(0))));
    assert_eq!(options[3].get_value().downcast_ref::<HexLong>(), Some(&HexLong::new(0x30)));
    assert_eq!(options[0].get_arg(), "-loader-blockName");
    // processor labels applied by default for raw binaries
    assert_eq!(options[4].get_value().downcast_ref::<bool>(), Some(&true));
    let into = BinaryLoader.get_default_options(&provider, Some(&program), true);
    assert_eq!(into[0].get_name(), OPTION_NAME_IS_OVERLAY);
    assert_eq!(BinaryLoader.validate_options(&provider, &options, None), None);
}

#[test]
fn validate_options_reports_java_messages() {
    let (program, space) = program();
    let provider = ByteArrayProvider::new(vec![0u8; 0x30]);
    let base = |a: std::option::Option<Address>| new_address(OPTION_NAME_BASE_ADDR).value(Box::new(a)).build();
    assert_eq!(
        BinaryLoader.validate_options(&provider, &[base(None)], None).as_deref(),
        Some("Invalid base address")
    );
    let opts = vec![base(Some(space.address(0x1000))), opt_hex(OPTION_NAME_FILE_OFFSET, 0x30)];
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, None).as_deref(),
        Some("File Offset must be greater than or equal to 0 and less than file length 48 (0x30)")
    );
    let opts = vec![base(Some(space.address(0x1000))), opt_hex(OPTION_NAME_LEN, 0x31)];
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, None).as_deref(),
        Some("Length must be greater than or equal to 0 and less than or equal to file length 48 (0x30)")
    );
    let opts = vec![
        base(Some(space.address(0x1000))),
        opt_hex(OPTION_NAME_FILE_OFFSET, 0x10),
        opt_hex(OPTION_NAME_LEN, 0x30),
    ];
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, None).as_deref(),
        Some("File Offset + Length (0x40) too large; set length to 0x20")
    );
    // 32-bit space: base near the top limits the length
    let opts = vec![base(Some(space.address(0xffff_fff0))), opt_hex(OPTION_NAME_LEN, 0x20)];
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, None).as_deref(),
        Some("Length must not exceed maximum allowed size of 16 (0x10) bytes")
    );
    let opts = vec![base(Some(space.address(0))), new_string(OPTION_NAME_IS_OVERLAY).value(Box::new("x".to_string())).build()];
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, None).as_deref(),
        Some("Overlay must be a boolean")
    );
    // conflict with existing memory
    let opts = vec![base(Some(space.address(0))), opt_hex(OPTION_NAME_LEN, 0x10)];
    BinaryLoader
        .load_program_into(&program, &provider, &opts, &MessageLog::new(), &DummyMonitor)
        .unwrap();
    assert_eq!(
        BinaryLoader.validate_options(&provider, &opts, Some(&program)).as_deref(),
        Some("Memory Conflict: Use <Options...> to change the base address!")
    );
}

#[test]
fn load_into_creates_one_block_named_after_the_space() {
    let (program, space) = program();
    let bytes: Vec<u8> = (0..0x40u8).collect();
    let provider = ByteArrayProvider::new(bytes);
    let opts = vec![
        new_address(OPTION_NAME_BASE_ADDR).value(Box::new(space.address(0x8000))).build(),
        opt_hex(OPTION_NAME_FILE_OFFSET, 0x10),
        opt_hex(OPTION_NAME_LEN, 0x20),
    ];
    BinaryLoader
        .load_program_into(&program, &provider, &opts, &MessageLog::new(), &DummyMonitor)
        .unwrap();
    let memory = Program::get_memory(&program).unwrap();
    let blocks = memory.get_block_handles();
    assert_eq!(blocks.len(), 1);
    let b = blocks[0].read().unwrap();
    assert_eq!(b.get_name(), "ram");
    assert_eq!(b.get_start(), space.address(0x8000));
    assert_eq!(b.get_size(), 0x20);
    assert!(b.is_read() && b.is_write() && b.is_execute());
    assert_eq!(b.get_source_name(), Some("Binary Loader"));
    drop(b);
    assert_eq!(memory.get_byte(&space.address(0x8000)).unwrap(), 0x10);
    assert_eq!(memory.get_byte(&space.address(0x801f)).unwrap(), 0x2f);
    let fb = memory.get_all_file_bytes();
    assert_eq!(fb[0].get_file_offset(), 0x10);
    assert_eq!(fb[0].get_size(), 0x20);

    // a second load over it conflicts
    let err = BinaryLoader
        .load_program_into(&program, &provider, &opts, &MessageLog::new(), &DummyMonitor)
        .unwrap_err();
    assert!(err.to_string().contains("conflicts with existing memory blocks"), "{err}");
}

#[test]
fn defaults_load_whole_file_at_zero_and_named_block() {
    let (program, space) = program();
    let provider = ByteArrayProvider::new(vec![7u8; 0x10]);
    let opts = vec![new_string(OPTION_NAME_BLOCK_NAME).value(Box::new("rom".to_string())).build()];
    BinaryLoader
        .load_program_into(&program, &provider, &opts, &MessageLog::new(), &DummyMonitor)
        .unwrap();
    let memory = Program::get_memory(&program).unwrap();
    let b = memory.get_block_handle(&space.address(0)).unwrap();
    assert_eq!(b.read().unwrap().get_name(), "rom");
    assert_eq!(b.read().unwrap().get_size(), 0x10);
    assert_eq!(BinaryLoader.generate_block_name(&program, true, &space), "ov1");
}

#[test]
fn parse_long_accepts_hex_strings_and_hexlongs() {
    let s = new_string("x").value(Box::new("0x1F".to_string())).build();
    assert_eq!(parse_long(s.as_ref()).unwrap(), Some(0x1f));
    let h = opt_hex("x", 0x40);
    assert_eq!(parse_long(h.as_ref()).unwrap(), Some(0x40));
    let bad = new_string("x").value(Box::new("zz".to_string())).build();
    assert!(parse_long(bad.as_ref()).is_err());
}
