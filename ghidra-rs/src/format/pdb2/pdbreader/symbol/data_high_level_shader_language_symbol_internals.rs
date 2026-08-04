//! Internals of the High Level Shader Language symbol.
//!
//! Corresponds to the Java abstract class
//! `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.DataHighLevelShaderLanguageSymbolInternals`.
//!
//! Note: we have guessed that HLSL means High Level Shader Language.
//! <P>
//! Note: we do not necessarily understand each of these symbol type classes.
//!
//! Ported as a trait (rather than a struct extending a concrete `AbstractSymbolInternals` parsing
//! pipeline) because this type was selected as a dependency-cycle cut-point: callers such as
//! `AbstractDataHighLevelShaderLanguageMsSymbol`, `AbstractGlobalDataHLSLMsSymbol`, and
//! `AbstractLocalDataHLSLMsSymbol` (not yet ported) can depend on
//! `dyn DataHighLevelShaderLanguageSymbolInternals` instead of a concrete class, so their crates
//! don't need to see `AbstractSymbolInternals`/`AbstractPdb`/`PdbByteReader`'s full parsing
//! machinery.

use crate::format::seam_stubs::{AbstractPdb, HlslRegisterType, RecordNumber};

/// The various flavors of Internals of the High Level Shader Language symbol.
///
/// Corresponds to the Java abstract class's common fields/accessors
/// (`typeRecordNumber`, `dataOffset`, `registerType`, `name`).
pub trait DataHighLevelShaderLanguageSymbolInternals {
    /// Returns the type record number.
    fn type_record_number(&self) -> RecordNumber;

    /// Returns the data offset.
    fn data_offset(&self) -> i64;

    /// Returns the register type.
    fn register_type(&self) -> &dyn HlslRegisterType;

    /// Returns the name.
    fn name(&self) -> &str;

    /// Emits string output of this class into `builder`, matching the Java override of
    /// `AbstractSymbolInternals.emit(StringBuilder)`. Left abstract (no default), matching Java
    /// where each nested subclass (`...32`, `...32Extended`) overrides this differently.
    fn emit(&self, builder: &mut String, pdb: &dyn AbstractPdb);
}

/// This class represents Internals and Internal 32 of the High Level Shader Language symbol.
///
/// Corresponds to the Java nested static class
/// `DataHighLevelShaderLanguageSymbolInternals.DataHighLevelShaderLanguageSymbolInternals32`.
pub trait DataHighLevelShaderLanguageSymbolInternals32: DataHighLevelShaderLanguageSymbolInternals {
    /// Return the data slot.
    fn data_slot(&self) -> i64;

    /// Return the texture slot start.
    fn texture_slot_start(&self) -> i64;

    /// Return the sampler slot start.
    fn sampler_slot_start(&self) -> i64;

    /// Return the UAV slot start.
    fn uav_slot_start(&self) -> i64;
}

/// This class represents Extended Internals 32 of the High Level Shader Language symbol.
///
/// Corresponds to the Java nested static class
/// `DataHighLevelShaderLanguageSymbolInternals.DataHighLevelShaderLanguageSymbolInternals32Extended`.
pub trait DataHighLevelShaderLanguageSymbolInternals32Extended:
    DataHighLevelShaderLanguageSymbolInternals
{
    /// Return the register index.
    fn register_index(&self) -> i64;

    /// Return the bind space.
    fn bind_space(&self) -> i64;

    /// Return the bind slot.
    fn bind_slot(&self) -> i64;
}

/// Formats the `emit` body for the `...32` flavor, matching Java's
/// `DataHighLevelShaderLanguageSymbolInternals32.emit(StringBuilder)`. Exposed as a free function
/// (rather than a trait default) so it stays reusable regardless of which concrete `emit`
/// signature a caller settles on, and so its formatting logic is independently testable.
pub fn emit_32(
    internals: &dyn DataHighLevelShaderLanguageSymbolInternals32,
    builder: &mut String,
    pdb: &dyn AbstractPdb,
) {
    builder.push_str(&format!(
        ": Type: {}. {}\n",
        pdb.get_type_record(internals.type_record_number()).to_display_string(),
        internals.register_type().label()
    ));
    builder.push_str(&format!(
        "   base data: slot = {} offset = {}, texture slot = {}, sampler slot = {}, UAV slot = {}\n",
        internals.data_slot(),
        internals.data_offset(),
        internals.texture_slot_start(),
        internals.sampler_slot_start(),
        internals.uav_slot_start()
    ));
}

/// Formats the `emit` body for the `...32Extended` flavor, matching Java's
/// `DataHighLevelShaderLanguageSymbolInternals32Extended.emit(StringBuilder)`.
pub fn emit_32_extended(
    internals: &dyn DataHighLevelShaderLanguageSymbolInternals32Extended,
    builder: &mut String,
    pdb: &dyn AbstractPdb,
) {
    builder.push_str(&format!(
        ": Type: {}. {}\n",
        pdb.get_type_record(internals.type_record_number()).to_display_string(),
        internals.register_type().label()
    ));
    builder.push_str(&format!(
        "   register index = {}, base data offset start = {}, bind space = {}, bind slot = {}\n",
        internals.register_index(),
        internals.data_offset(),
        internals.bind_space(),
        internals.bind_slot()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
    use crate::format::seam_stubs::{AbstractMsType, PdbReaderOptions};
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset;

    #[derive(Debug)]
    struct MockRegisterType(&'static str);
    impl HlslRegisterType for MockRegisterType {
        fn label(&self) -> &str {
            self.0
        }
    }

    struct MockParentType(&'static str);
    impl AbstractParsableItem for MockParentType {
        fn emit(&self, builder: &mut String) {
            builder.push_str(self.0);
        }
    }
    impl AbstractMsType for MockParentType {}

    struct MockPdb {
        options: PdbReaderOptions,
        type_name: &'static str,
    }
    impl AbstractPdb for MockPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            &self.options
        }

        fn get_type_record(&self, _record_number: RecordNumber) -> Box<dyn AbstractMsType> {
            Box::new(MockParentType(self.type_name))
        }
    }

    fn mock_pdb(type_name: &'static str) -> MockPdb {
        MockPdb {
            options: PdbReaderOptions {
                one_byte_charset: PdbCharset::OneByte,
                two_byte_charset: PdbCharset::Utf16Le,
            },
            type_name,
        }
    }

    struct Mock32 {
        type_record_number: RecordNumber,
        data_offset: i64,
        register_type: MockRegisterType,
        name: String,
        data_slot: i64,
        texture_slot_start: i64,
        sampler_slot_start: i64,
        uav_slot_start: i64,
    }

    impl DataHighLevelShaderLanguageSymbolInternals for Mock32 {
        fn type_record_number(&self) -> RecordNumber {
            self.type_record_number
        }

        fn data_offset(&self) -> i64 {
            self.data_offset
        }

        fn register_type(&self) -> &dyn HlslRegisterType {
            &self.register_type
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, builder: &mut String, pdb: &dyn AbstractPdb) {
            emit_32(self, builder, pdb);
        }
    }

    impl DataHighLevelShaderLanguageSymbolInternals32 for Mock32 {
        fn data_slot(&self) -> i64 {
            self.data_slot
        }

        fn texture_slot_start(&self) -> i64 {
            self.texture_slot_start
        }

        fn sampler_slot_start(&self) -> i64 {
            self.sampler_slot_start
        }

        fn uav_slot_start(&self) -> i64 {
            self.uav_slot_start
        }
    }

    struct Mock32Extended {
        type_record_number: RecordNumber,
        data_offset: i64,
        register_type: MockRegisterType,
        name: String,
        register_index: i64,
        bind_space: i64,
        bind_slot: i64,
    }

    impl DataHighLevelShaderLanguageSymbolInternals for Mock32Extended {
        fn type_record_number(&self) -> RecordNumber {
            self.type_record_number
        }

        fn data_offset(&self) -> i64 {
            self.data_offset
        }

        fn register_type(&self) -> &dyn HlslRegisterType {
            &self.register_type
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, builder: &mut String, pdb: &dyn AbstractPdb) {
            emit_32_extended(self, builder, pdb);
        }
    }

    impl DataHighLevelShaderLanguageSymbolInternals32Extended for Mock32Extended {
        fn register_index(&self) -> i64 {
            self.register_index
        }

        fn bind_space(&self) -> i64 {
            self.bind_space
        }

        fn bind_slot(&self) -> i64 {
            self.bind_slot
        }
    }

    #[test]
    fn accessors_match_java_fields() {
        let internals = Mock32 {
            type_record_number: RecordNumber { number: 7 },
            data_offset: 16,
            register_type: MockRegisterType("SAMPLER"),
            name: "myVar".to_string(),
            data_slot: 1,
            texture_slot_start: 2,
            sampler_slot_start: 3,
            uav_slot_start: 4,
        };
        assert_eq!(internals.type_record_number(), RecordNumber { number: 7 });
        assert_eq!(internals.data_offset(), 16);
        assert_eq!(internals.register_type().label(), "SAMPLER");
        assert_eq!(internals.name(), "myVar");
        assert_eq!(internals.data_slot(), 1);
        assert_eq!(internals.texture_slot_start(), 2);
        assert_eq!(internals.sampler_slot_start(), 3);
        assert_eq!(internals.uav_slot_start(), 4);
    }

    #[test]
    fn emit_32_matches_java_format() {
        let internals = Mock32 {
            type_record_number: RecordNumber { number: 7 },
            data_offset: 16,
            register_type: MockRegisterType("SAMPLER"),
            name: "myVar".to_string(),
            data_slot: 1,
            texture_slot_start: 2,
            sampler_slot_start: 3,
            uav_slot_start: 4,
        };
        let pdb = mock_pdb("T_INT4");
        let mut builder = String::new();
        internals.emit(&mut builder, &pdb);
        assert_eq!(
            builder,
            ": Type: T_INT4. SAMPLER\n   base data: slot = 1 offset = 16, texture slot = 2, sampler slot = 3, UAV slot = 4\n"
        );
    }

    #[test]
    fn emit_32_extended_matches_java_format() {
        let internals = Mock32Extended {
            type_record_number: RecordNumber { number: 9 },
            data_offset: 20,
            register_type: MockRegisterType("RESOURCE"),
            name: "myTex".to_string(),
            register_index: 5,
            bind_space: 6,
            bind_slot: 7,
        };
        let pdb = mock_pdb("T_PTR");
        let mut builder = String::new();
        internals.emit(&mut builder, &pdb);
        assert_eq!(
            builder,
            ": Type: T_PTR. RESOURCE\n   register index = 5, base data offset start = 20, bind space = 6, bind slot = 7\n"
        );
    }

    #[test]
    fn is_object_safe() {
        let base: Box<dyn DataHighLevelShaderLanguageSymbolInternals> = Box::new(Mock32 {
            type_record_number: RecordNumber::no_type(),
            data_offset: 0,
            register_type: MockRegisterType("TEMP"),
            name: "x".to_string(),
            data_slot: 0,
            texture_slot_start: 0,
            sampler_slot_start: 0,
            uav_slot_start: 0,
        });
        assert_eq!(base.name(), "x");

        let ext: Box<dyn DataHighLevelShaderLanguageSymbolInternals32Extended> =
            Box::new(Mock32Extended {
                type_record_number: RecordNumber::no_type(),
                data_offset: 0,
                register_type: MockRegisterType("NULL"),
                name: "y".to_string(),
                register_index: 0,
                bind_space: 0,
                bind_slot: 0,
            });
        assert_eq!(ext.bind_slot(), 0);
        assert_eq!(ext.name(), "y");
    }
}
