//! Port of `ghidra.app.util.bin.format.macho.commands.LoadCommand`.
//!
//! Represents a `load_command` structure. See
//! <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>.
//!
//! Java's `LoadCommand` is an abstract class carrying three instance fields (`startIndex`, `cmd`,
//! `cmdsize`) plus a mix of abstract and concrete/overridable behaviour, with ~29 in-repo
//! subclasses. That shared state is split into [`LoadCommandBase`]; the trait [`LoadCommand`]
//! declares the abstract members and provides the concrete ones (as default methods) via
//! [`LoadCommand::base`].

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::StructConverter;
use crate::format::macho::commands::load_command_types::get_load_command_name;
use crate::format::macho::commands::segment_names;
use crate::format::seam_stubs::{FlatProgramAPI, MachHeader, MessageLog, SegmentCommand};
use crate::program::model::address::Address;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_fragment::ProgramFragment;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The shared state every [`LoadCommand`] implementor carries.
///
/// Java: the private `startIndex`/`cmd`/`cmdsize` fields on the abstract `LoadCommand` class.
pub struct LoadCommandBase {
    start_index: u64,
    cmd: i32,
    cmdsize: i32,
}

impl LoadCommandBase {
    /// Java: `LoadCommand(BinaryReader reader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let start_index = reader.get_pointer_index();
        let cmd = reader.read_next_int()?;
        let cmdsize = reader.read_next_int()?;
        Ok(LoadCommandBase { start_index, cmd, cmdsize })
    }

    /// Java: `getStartIndex()`.
    pub fn get_start_index(&self) -> u64 {
        self.start_index
    }

    /// Java: `getCommandType()`.
    pub fn get_command_type(&self) -> i32 {
        self.cmd
    }

    /// Java: `getCommandSize()`.
    pub fn get_command_size(&self) -> i32 {
        self.cmdsize
    }
}

/// Port of the abstract `ghidra.app.util.bin.format.macho.commands.LoadCommand` class.
pub trait LoadCommand: StructConverter + Send + Sync {
    /// Accessor to the shared state every load command carries.
    fn base(&self) -> &LoadCommandBase;

    /// Java: `getStartIndex()`.
    fn get_start_index(&self) -> u64 {
        self.base().get_start_index()
    }

    /// Java: `getCommandType()`.
    fn get_command_type(&self) -> i32 {
        self.base().get_command_type()
    }

    /// Java: `getCommandSize()`.
    fn get_command_size(&self) -> i32 {
        self.base().get_command_size()
    }

    /// Java: `getCommandName()` (abstract).
    fn get_command_name(&self) -> String;

    /// Java: `getLinkerDataOffset()`. Not all load commands with data have linker data (typically
    /// in the `__LINKEDIT` segment); defaults to 0, overridable.
    fn get_linker_data_offset(&self) -> i64 {
        0
    }

    /// Java: `getLinkerDataSize()`. Defaults to 0, overridable.
    fn get_linker_data_size(&self) -> i64 {
        0
    }

    /// Java: `markup(Program, MachHeader, String, TaskMonitor, MessageLog)`. Marks up this load
    /// command's data with data structures and comments, assuming the program was imported as a
    /// Mach-O. Default is no markup, overridable.
    fn markup(
        &self,
        program: &mut dyn Program,
        header: &dyn MachHeader,
        source: Option<&str>,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
    ) -> Result<(), CancelledException> {
        let _ = (program, header, source, monitor, log);
        Ok(())
    }

    /// Java: `markupPlateComment(Program, Address, String, String)`. Creates a plate comment at
    /// the given address based on this load command's name.
    fn markup_plate_comment(
        &self,
        program: &mut dyn Program,
        address: Option<&Address>,
        source: Option<&str>,
        additional_description: Option<&str>,
    ) {
        let Some(address) = address else {
            return;
        };
        let comment = self.get_contextual_name(source, additional_description);
        if let Some(listing) = program.get_listing() {
            listing.set_comment(address, CommentType::Plate, Some(comment));
        }
    }

    /// Java: `getContextualName(String, String)`. The name of this load command, including
    /// contextual information.
    fn get_contextual_name(
        &self,
        source: Option<&str>,
        additional_description: Option<&str>,
    ) -> String {
        let mut markup_name = get_load_command_name(self.get_command_type() as u32);
        if let Some(desc) = additional_description {
            if !desc.trim().is_empty() {
                markup_name.push_str(&format!(" ({desc})"));
            }
        }
        if let Some(src) = source {
            if !src.trim().is_empty() {
                markup_name.push_str(&format!(" - {src}"));
            }
        }
        markup_name
    }

    /// Java: `fileOffsetToAddress(Program, MachHeader, long, long)`. Converts the given Mach-O
    /// file offset to an address, or `None` if there is no corresponding address.
    fn file_offset_to_address(
        &self,
        program: &dyn Program,
        header: &dyn MachHeader,
        file_offset: i64,
        size: i64,
    ) -> Option<Address> {
        if file_offset == 0 || size == 0 {
            return None;
        }
        let space = program.get_address_factory()?.get_default_address_space()?;
        let mut segment = if self.get_linker_data_offset() != 0 {
            header.get_segment(segment_names::LINKEDIT)
        } else {
            None
        };
        if segment.is_none() {
            segment = self.get_containing_segment(header, file_offset);
        }
        segment.map(|seg| {
            space.address(seg.get_v_maddress() + (file_offset - seg.get_file_offset()))
        })
    }

    /// Java: `checkCount(long)`. Checks that the given count value isn't larger than
    /// `Integer.MAX_VALUE`.
    fn check_count(&self, count: i64) -> io::Result<i64> {
        if count > i32::MAX as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Count value {count:#x} in {} is greater than Integer.MAX_VALUE",
                    self.get_command_name()
                ),
            ));
        }
        Ok(count)
    }

    /// Java: `getContainingSegment(MachHeader, long)`. The segment that contains the given file
    /// offset, or `None` if one was not found.
    fn get_containing_segment(
        &self,
        header: &dyn MachHeader,
        file_offset: i64,
    ) -> Option<Box<dyn SegmentCommand>> {
        header.get_all_segments().into_iter().find(|segment| {
            file_offset >= segment.get_file_offset()
                && file_offset < segment.get_file_offset() + segment.get_file_size()
        })
    }

    /// Java: `markupRawBinary(MachHeader, FlatProgramAPI, Address, ProgramModule, TaskMonitor,
    /// MessageLog)`. Marks up this load command with data structures and comments, assuming the
    /// program was imported as a Raw Binary. Legacy code to support Raw Binary markup.
    fn markup_raw_binary(
        &self,
        header: &dyn MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
    ) {
        let _ = header;
        self.update_monitor(monitor);
        let result: Result<(), String> = (|| {
            self.create_fragment(api, base_address, parent_module).map_err(|e| e.to_string())?;
            let addr = base_address.space().address(self.get_start_index() as i64);
            let data_type = self.to_data_type().map_err(|e| e.to_string())?;
            api.create_data(&addr, data_type).map_err(|e| e.to_string())?;
            self.create_plate_comment(api, &addr);
            Ok(())
        })();
        if let Err(message) = result {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }
    }

    /// Java: `createFragment(FlatProgramAPI, Address, ProgramModule)`.
    fn create_fragment(
        &self,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        module: &mut dyn ProgramModule,
    ) -> io::Result<Box<dyn ProgramFragment>> {
        let start = base_address.space().address(self.get_start_index() as i64);
        api.create_fragment(
            module,
            &get_load_command_name(self.get_command_type() as u32),
            &start,
            self.get_command_size() as i64,
        )
    }

    /// Java: `createPlateComment(FlatProgramAPI, Address)`.
    fn create_plate_comment(&self, api: &dyn FlatProgramAPI, addr: &Address) {
        api.set_plate_comment(addr, &get_load_command_name(self.get_command_type() as u32));
    }

    /// Java: `updateMonitor(TaskMonitor)`.
    fn update_monitor(&self, monitor: &dyn TaskMonitor) {
        monitor.set_message(&format!("Processing {}...", self.get_command_name()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::macho::commands::load_command_types::LC_SEGMENT;
    use crate::program::model::data::data_type::DataType;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }

        fn is_little_endian(&self) -> bool {
            self.little_endian
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct DummyDataType;
    impl DataType for DummyDataType {}

    struct TestLoadCommand {
        base: LoadCommandBase,
    }

    impl StructConverter for TestLoadCommand {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn DataType>, crate::app::util::bin::struct_converter::ToDataTypeError>
        {
            Ok(Box::new(DummyDataType))
        }
    }

    impl LoadCommand for TestLoadCommand {
        fn base(&self) -> &LoadCommandBase {
            &self.base
        }

        fn get_command_name(&self) -> String {
            get_load_command_name(self.get_command_type() as u32)
        }
    }

    fn command_bytes(cmd: u32, cmdsize: i32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(cmd as i32).to_le_bytes());
        v.extend_from_slice(&cmdsize.to_le_bytes());
        v
    }

    #[test]
    fn constructor_reads_start_index_cmd_and_cmdsize() {
        let mut reader = TestReader::new(command_bytes(LC_SEGMENT, 56));
        let cmd = TestLoadCommand { base: LoadCommandBase::new(&mut reader).unwrap() };
        assert_eq!(cmd.get_start_index(), 0);
        assert_eq!(cmd.get_command_type(), LC_SEGMENT as i32);
        assert_eq!(cmd.get_command_size(), 56);
    }

    #[test]
    fn constructor_captures_start_index_mid_stream() {
        let mut bytes = vec![0u8; 4];
        bytes.extend(command_bytes(LC_SEGMENT, 56));
        let mut reader = TestReader::new(bytes);
        reader.set_pointer_index(4);
        let cmd = TestLoadCommand { base: LoadCommandBase::new(&mut reader).unwrap() };
        assert_eq!(cmd.get_start_index(), 4);
    }

    #[test]
    fn default_linker_data_offset_and_size_are_zero() {
        let cmd = TestLoadCommand { base: LoadCommandBase { start_index: 0, cmd: 0, cmdsize: 0 } };
        assert_eq!(cmd.get_linker_data_offset(), 0);
        assert_eq!(cmd.get_linker_data_size(), 0);
    }

    #[test]
    fn contextual_name_matches_java_formatting() {
        let cmd = TestLoadCommand {
            base: LoadCommandBase { start_index: 0, cmd: LC_SEGMENT as i32, cmdsize: 0 },
        };
        assert_eq!(cmd.get_contextual_name(None, None), "LC_SEGMENT");
        assert_eq!(cmd.get_contextual_name(Some("foo.dylib"), None), "LC_SEGMENT - foo.dylib");
        assert_eq!(cmd.get_contextual_name(None, Some("extra")), "LC_SEGMENT (extra)");
        assert_eq!(
            cmd.get_contextual_name(Some("foo.dylib"), Some("extra")),
            "LC_SEGMENT (extra) - foo.dylib"
        );
        // Blank strings are treated like "not present", mirroring Java's `isBlank()` checks.
        assert_eq!(cmd.get_contextual_name(Some("  "), Some("  ")), "LC_SEGMENT");
    }

    #[test]
    fn check_count_rejects_values_over_i32_max() {
        let cmd = TestLoadCommand { base: LoadCommandBase { start_index: 0, cmd: 0, cmdsize: 0 } };
        assert_eq!(cmd.check_count(42).unwrap(), 42);
        assert!(cmd.check_count(i32::MAX as i64 + 1).is_err());
    }

    struct MockSegment {
        v_maddress: i64,
        file_offset: i64,
        file_size: i64,
    }

    impl SegmentCommand for MockSegment {
        fn get_v_maddress(&self) -> i64 {
            self.v_maddress
        }
        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }
        fn get_file_size(&self) -> i64 {
            self.file_size
        }
    }

    struct MockMachHeader {
        segments: Vec<(i64, i64, i64)>,
    }

    impl MachHeader for MockMachHeader {
        fn get_segment(&self, _segment_name: &str) -> Option<Box<dyn SegmentCommand>> {
            None
        }
        fn get_all_segments(&self) -> Vec<Box<dyn SegmentCommand>> {
            self.segments
                .iter()
                .map(|&(v_maddress, file_offset, file_size)| {
                    Box::new(MockSegment { v_maddress, file_offset, file_size })
                        as Box<dyn SegmentCommand>
                })
                .collect()
        }
    }

    #[test]
    fn containing_segment_finds_the_segment_holding_the_offset() {
        let header = MockMachHeader {
            segments: vec![(0x1000, 0, 0x100), (0x2000, 0x100, 0x200)],
        };
        let cmd = TestLoadCommand { base: LoadCommandBase { start_index: 0, cmd: 0, cmdsize: 0 } };

        let found = cmd.get_containing_segment(&header, 0x150).unwrap();
        assert_eq!(found.get_v_maddress(), 0x2000);

        assert!(cmd.get_containing_segment(&header, 0x9999).is_none());
    }
}
