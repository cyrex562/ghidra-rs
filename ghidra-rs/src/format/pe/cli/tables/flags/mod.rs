//! Port of `ghidra.app.util.bin.format.pe.cli.tables.flags`.

pub mod cli_flags;

pub use cli_flags::{
    cli_enum_assembly_flags, cli_enum_assembly_hash_algorithm, cli_enum_event_attributes,
    cli_enum_field_attributes, cli_enum_file_attributes, cli_enum_generic_param_attributes,
    cli_enum_manifest_resource_attributes, cli_enum_method_attributes,
    cli_enum_method_impl_attributes, cli_enum_method_semantics_attributes,
    cli_enum_p_invoke_attributes, cli_enum_param_attributes, cli_enum_property_attributes,
    cli_enum_type_attributes, PATH,
};
