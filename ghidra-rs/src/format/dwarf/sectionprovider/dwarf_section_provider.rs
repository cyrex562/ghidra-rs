use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Mirrors `ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProvider`.
///
/// A `DWARFSectionProvider` is responsible for allowing access to DWARF section data of
/// a Ghidra program.
///
/// Implementors of this trait are responsible for closing any [`ByteProvider`] that has been
/// returned via [`get_section_as_byte_provider`](Self::get_section_as_byte_provider) when the
/// section provider instance itself is closed.
pub trait DWARFSectionProvider: Send + Sync {
    /// Returns true if all of the specified section names are present.
    ///
    /// # Arguments
    /// * `section_names` - slice of section names to test
    ///
    /// # Returns
    /// true if all are present, false if not present
    fn has_section(&self, section_names: &[&str]) -> bool;

    /// Returns a `ByteProvider` for the specified section.
    ///
    /// # Arguments
    /// * `section_name` - name of the section
    /// * `monitor` - [`TaskMonitor`] to use when performing long operations
    ///
    /// # Returns
    /// A `ByteProvider` for the section, which will be closed by the section provider when
    /// itself is closed, or an IO error if the section cannot be read.
    fn get_section_as_byte_provider(
        &self,
        section_name: &str,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<Box<dyn ByteProvider>>;

    /// Closes the section provider and any resources it holds.
    fn close(&mut self) -> std::io::Result<()>;

    /// Decorates the specified program with any information that is unique to this section provider.
    ///
    /// # Arguments
    /// * `program` - [`Program`] with an active transaction
    ///
    /// The default implementation does nothing.
    fn update_program_info(&self, _program: &dyn Program) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockByteProvider {
        data: Vec<u8>,
    }

    impl ByteProvider for MockByteProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.data.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            if index >= self.data.len() as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "index out of bounds",
                ));
            }
            Ok(self.data[index as usize])
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            if index + length as u64 > self.data.len() as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "range out of bounds",
                ));
            }
            Ok(self.data[index as usize..(index as usize + length)].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "not supported",
            ))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "not supported",
            ))
        }

        fn get_fsrl(&self) -> Option<&dyn crate::filesystem::gfilesystem::fsrl::Fsrl> {
            None
        }

        fn get_file(&self) -> Option<std::path::PathBuf> {
            None
        }
    }

    struct MockTaskMonitor;

    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }

        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }

        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }

        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }

        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }

        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }

        fn clear_cancelled(&self) {}
    }

    struct MockSectionProvider {
        has_debug_info: bool,
    }

    impl DWARFSectionProvider for MockSectionProvider {
        fn has_section(&self, section_names: &[&str]) -> bool {
            for name in section_names {
                if *name == "debug_info" && !self.has_debug_info {
                    return false;
                }
            }
            true
        }

        fn get_section_as_byte_provider(
            &self,
            _section_name: &str,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<Box<dyn ByteProvider>> {
            Ok(Box::new(MockByteProvider {
                data: vec![0x11, 0x22, 0x33],
            }))
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn has_section_returns_true_when_section_present() {
        let provider = MockSectionProvider {
            has_debug_info: true,
        };
        assert!(provider.has_section(&["debug_info"]));
    }

    #[test]
    fn has_section_returns_false_when_section_missing() {
        let provider = MockSectionProvider {
            has_debug_info: false,
        };
        assert!(!provider.has_section(&["debug_info"]));
    }

    #[test]
    fn has_section_checks_all_sections() {
        let provider = MockSectionProvider {
            has_debug_info: true,
        };
        assert!(provider.has_section(&["debug_info", "debug_abbrev"]));
    }

    #[test]
    fn get_section_as_byte_provider_returns_data() {
        let provider = MockSectionProvider {
            has_debug_info: true,
        };
        let monitor = MockTaskMonitor;
        let mut byte_provider = provider
            .get_section_as_byte_provider("debug_info", &monitor)
            .expect("should return provider");
        let len = byte_provider.length().expect("should get length");
        assert_eq!(len, 3);
    }

}
