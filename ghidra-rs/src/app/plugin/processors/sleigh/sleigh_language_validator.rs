//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageValidator`: validates the SLEIGH
//! XML configuration files (`.cspec`, `.pspec` and `.ldefs`) against their RELAX NG schemas.
//!
//! # Divergences from the Java
//! * **Schema engine.** Java compiles the `.rxg` schemas with the Sun Multi-Schema Validator;
//!   this port uses the crate's own RELAX NG validator ([`RelaxNgSchema`]), which supports the
//!   schema subset Ghidra's language schemas use. Error messages therefore differ from MSV's in
//!   wording (the location and the offending element/attribute are reported).
//! * **Schema location.** Java's static initializer finds `languages/*.rxg` through
//!   `Application.getModuleDataFile`; this crate has no initialized `Application` singleton, so
//!   the schemas of the `SoftwareModeling` module are compiled into the binary, and
//!   [`SleighLanguageValidator::with_schema_file`] validates against a schema read from disk.

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::sleigh::manual::exists_and_is_case_dependent;
use crate::util::msg::Msg;
use crate::util::xml::relax_ng::{RelaxNgError, RelaxNgSchema, SchemaResolver};

/// Verifier type for `.cspec` files. Port of `SleighLanguageValidator.CSPEC_TYPE`.
pub const CSPEC_TYPE: i32 = 1;
/// Verifier type for `.pspec` files. Port of `SleighLanguageValidator.PSPEC_TYPE`.
pub const PSPEC_TYPE: i32 = 2;
/// Verifier type for `.ldefs` files. Port of `SleighLanguageValidator.LDEFS_TYPE`.
pub const LDEFS_TYPE: i32 = 3;
/// Verifier type for compiler-spec tags verified on their own (see
/// [`SleighLanguageValidator::verify_document`]). Port of `SleighLanguageValidator.CSPECTAG_TYPE`.
pub const CSPECTAG_TYPE: i32 = 4;

const LANGUAGE_TYPESTRING: &str = "language definitions";
const COMPILER_TYPESTRING: &str = "compiler specification";
const PROCESSOR_TYPESTRING: &str = "processor specification";

const LDEFS_SCHEMA_NAME: &str = "language_definitions.rxg";
const PSPEC_SCHEMA_NAME: &str = "processor_spec.rxg";
const CSPEC_SCHEMA_NAME: &str = "compiler_spec.rxg";

/// The `SoftwareModeling` module's `data/languages` schemas, by file name.
const EMBEDDED_SCHEMAS: &[(&str, &str)] = &[
    (
        LDEFS_SCHEMA_NAME,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../orig_src/Ghidra/Framework/SoftwareModeling/data/languages/language_definitions.rxg"
        )),
    ),
    (
        PSPEC_SCHEMA_NAME,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../orig_src/Ghidra/Framework/SoftwareModeling/data/languages/processor_spec.rxg"
        )),
    ),
    (
        CSPEC_SCHEMA_NAME,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../orig_src/Ghidra/Framework/SoftwareModeling/data/languages/compiler_spec.rxg"
        )),
    ),
    (
        "language_common.rxg",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../orig_src/Ghidra/Framework/SoftwareModeling/data/languages/language_common.rxg"
        )),
    ),
];

/// Resolves includes among the embedded schemas.
struct EmbeddedResolver;

impl SchemaResolver for EmbeddedResolver {
    fn resolve(&self, _base: &str, href: &str) -> Option<(String, Vec<u8>)> {
        EMBEDDED_SCHEMAS
            .iter()
            .find(|(name, _)| *name == href)
            .map(|(name, text)| (name.to_string(), text.as_bytes().to_vec()))
    }
}

/// Resolves includes relative to the including schema file's directory.
struct FileResolver;

impl SchemaResolver for FileResolver {
    fn resolve(&self, base: &str, href: &str) -> Option<(String, Vec<u8>)> {
        let path = Path::new(base).parent().unwrap_or_else(|| Path::new("")).join(href);
        let text = std::fs::read(&path).ok()?;
        Some((path.to_string_lossy().into_owned(), text))
    }
}

/// The compiled embedded schema `name`, compiled once per process.
fn embedded_schema(name: &'static str) -> Result<Arc<RelaxNgSchema>, RelaxNgError> {
    static LDEFS: OnceLock<Result<Arc<RelaxNgSchema>, RelaxNgError>> = OnceLock::new();
    static PSPEC: OnceLock<Result<Arc<RelaxNgSchema>, RelaxNgError>> = OnceLock::new();
    static CSPEC: OnceLock<Result<Arc<RelaxNgSchema>, RelaxNgError>> = OnceLock::new();
    let cell = match name {
        LDEFS_SCHEMA_NAME => &LDEFS,
        PSPEC_SCHEMA_NAME => &PSPEC,
        _ => &CSPEC,
    };
    cell.get_or_init(|| {
        let (_, text) = EMBEDDED_SCHEMAS.iter().find(|(n, _)| *n == name).expect("embedded schema exists");
        RelaxNgSchema::compile(name, text.as_bytes(), &EmbeddedResolver).map(Arc::new)
    })
    .clone()
}

/// The embedded schema for a verifier type, or `None` for an unknown type.
fn schema_name_for_type(verifier_type: i32) -> Option<&'static str> {
    match verifier_type {
        CSPEC_TYPE | CSPECTAG_TYPE => Some(CSPEC_SCHEMA_NAME),
        PSPEC_TYPE => Some(PSPEC_SCHEMA_NAME),
        LDEFS_TYPE => Some(LDEFS_SCHEMA_NAME),
        _ => None,
    }
}

/// Validates SLEIGH related XML configuration files: `.cspec`, `.pspec` and `.ldefs`.
///
/// A file can be verified with one of the static-style functions
/// ([`validate_cspec_file`](Self::validate_cspec_file),
/// [`validate_ldefs_file`](Self::validate_ldefs_file),
/// [`validate_pspec_file`](Self::validate_pspec_file)), or a validator can be built once and
/// run on multiple files.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageValidator`.
#[derive(Debug, Clone)]
pub struct SleighLanguageValidator {
    verifier_type: i32,
    verifier: Arc<RelaxNgSchema>,
}

impl SleighLanguageValidator {
    /// A validator for files of the given type ([`CSPEC_TYPE`], [`PSPEC_TYPE`], [`LDEFS_TYPE`] or
    /// [`CSPECTAG_TYPE`]).
    ///
    /// Port of `SleighLanguageValidator(int)`.
    ///
    /// # Errors
    /// `Bad verifier type` for an unknown type; `Error creating verifier` if the schema does not
    /// compile.
    pub fn new(verifier_type: i32) -> Result<Self, SleighException> {
        let name = schema_name_for_type(verifier_type)
            .ok_or_else(|| SleighException::with_message("Bad verifier type"))?;
        let verifier = embedded_schema(name).map_err(|e| SleighException::with_cause("Error creating verifier", e))?;
        Ok(SleighLanguageValidator { verifier_type, verifier })
    }

    /// A validator of the given type using the schema in `schema_file` (Java's `getVerifier` on
    /// the file `Application.getModuleDataFile` found). Includes resolve relative to the file.
    ///
    /// # Errors
    /// `Bad verifier type` for an unknown type; `Error creating verifier` if the schema cannot be
    /// read or does not compile.
    pub fn with_schema_file(verifier_type: i32, schema_file: &ResourceFile) -> Result<Self, SleighException> {
        if schema_name_for_type(verifier_type).is_none() {
            return Err(SleighException::with_message("Bad verifier type"));
        }
        let verifier = Self::get_verifier(schema_file)?;
        Ok(SleighLanguageValidator { verifier_type, verifier })
    }

    /// Port of the private static `getVerifier(ResourceFile)`.
    fn get_verifier(schema_file: &ResourceFile) -> Result<Arc<RelaxNgSchema>, SleighException> {
        let text = read_all(schema_file)
            .map_err(|e| SleighException::with_cause("Error creating verifier", RelaxNgError::new(e.to_string())))?;
        RelaxNgSchema::compile(&schema_file.absolute_path(), &text, &FileResolver)
            .map(Arc::new)
            .map_err(|e| SleighException::with_cause("Error creating verifier", e))
    }

    /// Port of the private `getTypeString()`.
    fn get_type_string(&self) -> &'static str {
        match self.verifier_type {
            PSPEC_TYPE => PROCESSOR_TYPESTRING,
            LDEFS_TYPE => LANGUAGE_TYPESTRING,
            _ => COMPILER_TYPESTRING,
        }
    }

    /// Verify the given file against this validator.
    ///
    /// Port of `verify(ResourceFile)`.
    ///
    /// # Errors
    /// A [`SleighException`] explaining why the file does not validate (its cause carries the
    /// location and violation).
    pub fn verify(&self, spec_file: &ResourceFile) -> Result<(), SleighException> {
        verify_file(&self.verifier, spec_file, self.get_type_string())
    }

    /// Verify an XML document (the body of a `<compiler_spec>`, such as a single `<prototype>` or
    /// `<callfixup>` tag) against this validator. Only supported for [`CSPECTAG_TYPE`].
    ///
    /// Port of `verify(String, String)`.
    ///
    /// # Errors
    /// If this is not a [`CSPECTAG_TYPE`] validator, or the document does not validate; error
    /// line numbers are relative to `document`.
    pub fn verify_document(&self, title: &str, document: &str) -> Result<(), SleighException> {
        if self.verifier_type != CSPECTAG_TYPE {
            return Err(SleighException::with_message("Only cspec tag verification is supported"));
        }
        let mut buffer = String::new();
        buffer.push_str("<compiler_spec>\n");
        buffer.push_str("<default_proto>\n");
        buffer.push_str("<prototype name=\"a\" extrapop=\"0\" stackshift=\"0\">\n");
        buffer.push_str("<input/><output/>\n");
        buffer.push_str("</prototype>\n");
        buffer.push_str("</default_proto>\n");
        buffer.push_str(document);
        buffer.push_str("</compiler_spec>\n");
        self.verifier.validate(buffer.as_bytes()).map_err(|e| {
            let e = report_error(title, 6, e);
            SleighException::with_cause(format!("Invalid {}: {title}", self.get_type_string()), e)
        })
    }

    /// Port of the static `validateLdefsFile(ResourceFile)`.
    ///
    /// # Errors
    /// As [`verify`](Self::verify).
    pub fn validate_ldefs_file(ldefs_file: &ResourceFile) -> Result<(), SleighException> {
        validate_sleigh_file(LDEFS_SCHEMA_NAME, ldefs_file, LANGUAGE_TYPESTRING)
    }

    /// Port of the static `validatePspecFile(ResourceFile)`.
    ///
    /// # Errors
    /// As [`verify`](Self::verify).
    pub fn validate_pspec_file(pspec_file: &ResourceFile) -> Result<(), SleighException> {
        validate_sleigh_file(PSPEC_SCHEMA_NAME, pspec_file, PROCESSOR_TYPESTRING)
    }

    /// Port of the static `validateCspecFile(ResourceFile)`.
    ///
    /// # Errors
    /// As [`verify`](Self::verify).
    pub fn validate_cspec_file(cspec_file: &ResourceFile) -> Result<(), SleighException> {
        validate_sleigh_file(CSPEC_SCHEMA_NAME, cspec_file, COMPILER_TYPESTRING)
    }
}

fn read_all(file: &ResourceFile) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.get_input_stream()?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Port of the private static `validateSleighFile(ResourceFile, ResourceFile, String)`.
fn validate_sleigh_file(schema_name: &'static str, file_to_validate: &ResourceFile, type_string: &str) -> Result<(), SleighException> {
    check_case_dependent(file_to_validate)?;
    let verifier = embedded_schema(schema_name).map_err(|e| SleighException::with_cause("Error creating verifier", e))?;
    verify_file(&verifier, file_to_validate, type_string)
}

fn check_case_dependent(file: &ResourceFile) -> Result<(), SleighException> {
    let result = exists_and_is_case_dependent(file);
    if !result.is_ok() {
        return Err(SleighException::with_message(format!(
            "{} is not properly case dependent: {}",
            file.absolute_path(),
            result.message()
        )));
    }
    Ok(())
}

/// The shared body of `verify(ResourceFile)` and `validateSleighFile`.
fn verify_file(verifier: &RelaxNgSchema, spec_file: &ResourceFile, type_string: &str) -> Result<(), SleighException> {
    check_case_dependent(spec_file)?;
    let invalid = || format!("Invalid {type_string} file: {}", spec_file.absolute_path());
    let bytes = read_all(spec_file)
        .map_err(|e| SleighException::with_cause(invalid(), RelaxNgError::new(e.to_string())))?;
    verifier.validate(&bytes).map_err(|e| {
        let e = report_error(&spec_file.absolute_path(), 0, e);
        SleighException::with_cause(invalid(), e)
    })
}

/// Port of the private `VerifierErrorHandler.error`: logs the failure (line numbers made
/// relative to `line_number_base`) and passes it on.
fn report_error(document_title: &str, line_number_base: i32, mut e: RelaxNgError) -> RelaxNgError {
    if e.line > 0 {
        e.line -= line_number_base;
    }
    Msg::error(
        "SleighLanguageValidator",
        &format!("Error validating {document_title}  at {}:{}: {}", e.line, e.column, e.message),
    );
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::path::PathBuf;

    fn processors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../orig_src/Ghidra/Processors")
    }

    /// Every file with `extension` under the processors' `data/languages` directories.
    fn language_files(extension: &str) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for processor in std::fs::read_dir(processors_dir()).unwrap() {
            let dir = processor.unwrap().path().join("data/languages");
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            let mut stack: Vec<PathBuf> = entries.map(|e| e.unwrap().path()).collect();
            while let Some(path) = stack.pop() {
                if path.is_dir() {
                    stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
                } else if path.extension().is_some_and(|e| e == extension) {
                    files.push(path);
                }
            }
        }
        files.sort();
        files
    }

    fn cause(e: &SleighException) -> String {
        e.source().map(|c| c.to_string()).unwrap_or_default()
    }

    /// Ghidra's build validates every shipped spec file; all of them must pass here too.
    fn all_valid(extension: &str, validate: fn(&ResourceFile) -> Result<(), SleighException>) {
        let files = language_files(extension);
        assert!(files.len() > 10, "found only {} .{extension} files", files.len());
        let failures: Vec<String> = files
            .iter()
            .filter_map(|f| validate(&ResourceFile::new(f.clone())).err().map(|e| format!("{e}: {}", cause(&e))))
            .collect();
        assert!(failures.is_empty(), "{} of {} failed:\n{}", failures.len(), files.len(), failures.join("\n"));
    }

    #[test]
    fn every_processor_cspec_validates() {
        all_valid("cspec", SleighLanguageValidator::validate_cspec_file);
    }

    #[test]
    fn every_processor_pspec_validates() {
        all_valid("pspec", SleighLanguageValidator::validate_pspec_file);
    }

    #[test]
    fn every_processor_ldefs_validates() {
        all_valid("ldefs", SleighLanguageValidator::validate_ldefs_file);
    }

    fn temp_file(dir: &tempfile::TempDir, name: &str, text: &str) -> ResourceFile {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        ResourceFile::new(path)
    }

    #[test]
    fn a_real_cspec_with_a_renamed_element_fails() {
        let text = std::fs::read_to_string(processors_dir().join("x86/data/languages/x86-64-gcc.cspec")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file = temp_file(&dir, "x86-64-gcc.cspec", &text.replace("<stackpointer ", "<stackpointr "));
        let err = SleighLanguageValidator::validate_cspec_file(&file).unwrap_err();
        assert!(cause(&err).contains("element \"stackpointr\" not allowed here"), "{}", cause(&err));
    }

    #[test]
    fn invalid_cspec_reports_the_file_and_the_violation() {
        let dir = tempfile::tempdir().unwrap();
        let file = temp_file(
            &dir,
            "bad.cspec",
            "<compiler_spec>\n  <default_proto>\n    <prototype name=\"p\" extrapop=\"0\" stackshift=\"0\" bogus=\"1\">\n<input/><output/></prototype>\n  </default_proto>\n</compiler_spec>\n",
        );
        let err = SleighLanguageValidator::validate_cspec_file(&file).unwrap_err();
        assert_eq!(err.to_string(), format!("Invalid compiler specification file: {}", file.absolute_path()));
        let cause = cause(&err);
        assert!(cause.starts_with("3:") && cause.contains("attribute \"bogus\""), "{cause}");

        // A validator instance verifies the same way.
        let validator = SleighLanguageValidator::new(CSPEC_TYPE).unwrap();
        assert!(validator.verify(&file).is_err());
    }

    #[test]
    fn missing_or_wrong_type_files_fail() {
        let dir = tempfile::tempdir().unwrap();
        let missing = ResourceFile::new(dir.path().join("missing.pspec"));
        let err = SleighLanguageValidator::validate_pspec_file(&missing).unwrap_err();
        assert!(err.to_string().contains("is not properly case dependent"), "{err}");

        // A .cspec is not a valid processor specification.
        let cspec = temp_file(
            &dir,
            "x.pspec",
            "<compiler_spec><default_proto><prototype name=\"a\" extrapop=\"0\" stackshift=\"0\"><input/><output/></prototype></default_proto></compiler_spec>",
        );
        let err = SleighLanguageValidator::new(PSPEC_TYPE).unwrap().verify(&cspec).unwrap_err();
        assert!(err.to_string().starts_with("Invalid processor specification file: "), "{err}");
    }

    #[test]
    fn bad_verifier_type() {
        assert_eq!(SleighLanguageValidator::new(9).unwrap_err().to_string(), "Bad verifier type");
    }

    #[test]
    fn cspec_tag_documents() {
        let validator = SleighLanguageValidator::new(CSPECTAG_TYPE).unwrap();
        let fixup = "<callfixup name=\"f\">\n  <pcode>\n    <body><![CDATA[ x = 1; ]]></body>\n  </pcode>\n</callfixup>\n";
        validator.verify_document("fixup", fixup).unwrap();

        let bad = "<callfixup name=\"f\">\n  <pcode>\n    <nobody/>\n  </pcode>\n</callfixup>\n";
        let err = validator.verify_document("bad fixup", bad).unwrap_err();
        assert_eq!(err.to_string(), "Invalid compiler specification: bad fixup");
        // The line is relative to the tag document (line 3), not the wrapping template.
        assert!(cause(&err).starts_with("3:"), "{}", cause(&err));

        let err = SleighLanguageValidator::new(CSPEC_TYPE).unwrap().verify_document("t", fixup).unwrap_err();
        assert_eq!(err.to_string(), "Only cspec tag verification is supported");
    }

    #[test]
    fn schema_files_on_disk_compile_with_relative_includes() {
        let schema = ResourceFile::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../orig_src/Ghidra/Framework/SoftwareModeling/data/languages/compiler_spec.rxg"),
        );
        let validator = SleighLanguageValidator::with_schema_file(CSPEC_TYPE, &schema).unwrap();
        let x86 = processors_dir().join("x86/data/languages/x86-64-gcc.cspec");
        validator.verify(&ResourceFile::new(x86)).unwrap();

        let missing = ResourceFile::new(PathBuf::from("/nonexistent/compiler_spec.rxg"));
        let err = SleighLanguageValidator::with_schema_file(CSPEC_TYPE, &missing).unwrap_err();
        assert_eq!(err.to_string(), "Error creating verifier");
    }
}
