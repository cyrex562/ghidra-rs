//! Port of `ghidra.app.util.opinion.AbstractProgramLoader` -- the parts concrete loaders inherit
//! that are reachable without the project/`Loaded`/`LoadResults` import pipeline.
//!
//! Java's abstract class has no instance state, so (per `shape_rules`) it is a trait whose
//! provided methods are the inherited behaviour: the processor-label options every program
//! loader offers ([`get_default_options`](AbstractProgramLoader::get_default_options) /
//! [`validate_options`](AbstractProgramLoader::validate_options)) and
//! [`generate_block_name`](AbstractProgramLoader::generate_block_name). The abstract
//! `loadProgramInto(Program, ImporterSettings)` is the required
//! [`load_program_into`](AbstractProgramLoader::load_program_into), with the `ImporterSettings`
//! fields it reads passed explicitly (the convention `ElfLoader` set: the ported
//! `ImporterSettings` carries opaque option placeholders).
//!
//! # Not yet ported
//!
//! `load`/`loadInto` (transactions, `LoadResults`), `createProgram` (needs a language service
//! that hands out the concrete `SleighLanguage` a `ProgramDB` is built on, plus program
//! properties `ProgramDB` cannot store yet), `setProgramProperties`, `createDefaultMemoryBlocks`,
//! `applyProcessorLabels`, `markAsFunction` and the MD5/SHA-256 helpers. The manifest row stays
//! TODO until they land.

use std::io;

use crate::app::seam_stubs::{new_boolean, Option};
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::importer::message_log::MessageLog;
use crate::app::util::opinion::loader::{COMMAND_LINE_ARG_PREFIX, LoadIntoError};
use crate::program::model::address::AddressSpace;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// `AbstractProgramLoader.APPLY_LABELS_OPTION_NAME`.
pub const APPLY_LABELS_OPTION_NAME: &str = "Apply Processor Defined Labels";
/// `AbstractProgramLoader.ANCHOR_LABELS_OPTION_NAME`.
pub const ANCHOR_LABELS_OPTION_NAME: &str = "Anchor Processor Defined Labels";

/// `ghidra.app.util.opinion.AbstractProgramLoader`. See the module docs.
pub trait AbstractProgramLoader {
    /// `loadProgramInto(Program, ImporterSettings)`: loads the provider's bytes into an existing
    /// program.
    ///
    /// # Errors
    /// Java's `IOException`/`LoadException`/`CancelledException`.
    fn load_program_into(
        &self,
        program: &dyn Program,
        provider: &dyn ByteProvider,
        options: &[Box<dyn Option>],
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), LoadIntoError>;

    /// `shouldApplyProcessorLabelsByDefault()`: most loaders do not apply processor labels by
    /// default.
    fn should_apply_processor_labels_by_default(&self) -> bool {
        false
    }

    /// `getDefaultOptions(ByteProvider, LoadSpec, DomainObject, boolean, boolean)`: the
    /// processor-label options. (Java's builder `description` text is not modeled by the option
    /// placeholder.)
    fn get_default_options(&self) -> Vec<Box<dyn Option>> {
        vec![
            new_boolean(APPLY_LABELS_OPTION_NAME)
                .value(Box::new(self.should_apply_processor_labels_by_default()))
                .command_line_argument(format!("{COMMAND_LINE_ARG_PREFIX}-applyLabels"))
                .build(),
            new_boolean(ANCHOR_LABELS_OPTION_NAME)
                .value(Box::new(true))
                .command_line_argument("-anchorLabels".to_string())
                .build(),
        ]
    }

    /// `validateOptions(ByteProvider, LoadSpec, List<Option>, Program)`: the processor-label
    /// options must be booleans. `None` means valid (Java's `null`).
    fn validate_options(&self, options: &[Box<dyn Option>]) -> std::option::Option<String> {
        for option in options {
            let name = option.get_name();
            if (name == APPLY_LABELS_OPTION_NAME || name == ANCHOR_LABELS_OPTION_NAME)
                && !option.get_value().is::<bool>()
            {
                return Some(format!("Invalid type for option: {name} - {}", value_class(option.as_ref())));
            }
        }
        None
    }

    /// `generateBlockName(Program, boolean, AddressSpace)`: the space name, or the first free
    /// `ovN` name for an overlay.
    fn generate_block_name(&self, program: &dyn Program, is_overlay: bool, space: &AddressSpace) -> String {
        if !is_overlay {
            return space.name().to_string();
        }
        let factory = program.get_address_factory();
        for count in 1..=1000 {
            let lname = format!("ov{count}");
            if factory.as_ref().and_then(|f| f.get_address_space_by_name(&lname)).is_none() {
                return lname;
            }
        }
        // CAN'T HAPPEN
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        format!("ov{millis}")
    }
}

/// Java's `option.getValueClass()` as it prints, for the value types the option placeholder
/// carries.
pub(crate) fn value_class(option: &dyn Option) -> &'static str {
    let value = option.get_value();
    if value.is::<bool>() {
        "class java.lang.Boolean"
    } else if value.is::<String>() {
        "class java.lang.String"
    } else if value.is::<i32>() {
        "class java.lang.Integer"
    } else if value.is::<crate::app::util::hex_long::HexLong>() {
        "class ghidra.app.util.importer.HexLong"
    } else {
        "class ghidra.program.model.address.Address"
    }
}

/// Wraps a message as the IO error a `loadProgramInto` raises.
pub(crate) fn io_error(msg: impl Into<String>) -> LoadIntoError {
    LoadIntoError::Io(io::Error::other(msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::new_string;

    struct Plain;
    impl AbstractProgramLoader for Plain {
        fn load_program_into(
            &self,
            _program: &dyn Program,
            _provider: &dyn ByteProvider,
            _options: &[Box<dyn Option>],
            _log: &MessageLog,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), LoadIntoError> {
            Ok(())
        }
    }

    #[test]
    fn label_options_default_and_validate() {
        let options = Plain.get_default_options();
        assert_eq!(options[0].get_name(), APPLY_LABELS_OPTION_NAME);
        assert_eq!(options[0].get_value().downcast_ref::<bool>(), Some(&false));
        assert_eq!(options[0].get_arg(), "-loader-applyLabels");
        assert_eq!(options[1].get_name(), ANCHOR_LABELS_OPTION_NAME);
        assert_eq!(options[1].get_value().downcast_ref::<bool>(), Some(&true));
        assert_eq!(options[1].get_arg(), "-anchorLabels");
        assert_eq!(Plain.validate_options(&options), None);
        let bad = vec![new_string(APPLY_LABELS_OPTION_NAME).value(Box::new("yes".to_string())).build()];
        assert_eq!(
            Plain.validate_options(&bad).as_deref(),
            Some("Invalid type for option: Apply Processor Defined Labels - class java.lang.String")
        );
    }
}
