//! Port of `ghidra.app.script.JavaScriptProvider`, the provider for Ghidra Scripts written in
//! Java.
//!
//! Java loads a script's compiled class by activating its containing OSGi bundle and reflecting
//! into the classes the JVM's OSGi framework loaded from it, then instantiates the script class
//! via `Class.getDeclaredConstructor().newInstance()`. Neither dynamic OSGi class loading nor
//! reflective instantiation has an in-process Rust equivalent, so [`JavaScriptProvider::load_class`]
//! and [`JavaScriptProvider::get_script_instance`] keep the parts that have meaning without a JVM
//! (locating the source bundle, resolving the target class name) and report the missing pieces as
//! errors rather than silently doing nothing -- the same tradeoff
//! [`ResourceFileJavaFileManager`](crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager)
//! makes for the JDK compiler it would otherwise delegate to.

use std::io::Write as _;
use std::sync::Arc;
use std::sync::OnceLock;

use crate::app::seam_stubs::{BundleHost, GhidraSourceBundle};
use crate::generic::jar::resource_file::ResourceFile;
use crate::script::ghidra_script_load_exception::GhidraScriptLoadException;
use crate::script::ghidra_script_util;
use crate::script::seam_stubs::{GhidraScript, GhidraScriptProvider};
use crate::util::msg::Msg;
use crate::util::task::DummyMonitor;

/// Originator passed to [`Msg`], standing in for Java's `this` in `Msg.error(this, ...)`.
const ORIGINATOR: &str = "JavaScriptProvider";

fn block_comment_start() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"/\*").unwrap())
}

fn block_comment_end() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\*/").unwrap())
}

/// The provider for Ghidra Scripts written in Java.
pub struct JavaScriptProvider {
    bundle_host: Option<Arc<BundleHost>>,
}

impl Default for JavaScriptProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaScriptProvider {
    /// Create a new [`JavaScriptProvider`] associated with the current bundle host used by
    /// scripting.
    pub fn new() -> Self {
        Self { bundle_host: ghidra_script_util::get_bundle_host() }
    }

    /// Get the [`GhidraSourceBundle`] containing the given source file, assuming it already
    /// exists.
    pub fn get_bundle_for_source(&self, source_file: &ResourceFile) -> Option<GhidraSourceBundle> {
        let source_dir = ghidra_script_util::find_source_directory_containing(source_file)?;
        self.bundle_host.as_ref()?.get_existing_ghidra_bundle(&source_dir)
    }

    /// Returns a description for this type of script.
    pub fn get_description(&self) -> &'static str {
        "Java"
    }

    /// Deletes the script file and unloads the script from the script manager.
    pub fn delete_script(&self, source_file: &ResourceFile) -> bool {
        if let Some(bundle) = self.get_bundle_for_source(source_file) {
            if let Some(osgi_bundle) = bundle.os_gi_bundle() {
                if let Some(host) = &self.bundle_host {
                    if let Err(e) = host.deactivate_synchronously(&osgi_bundle) {
                        Msg::error_with_error(
                            ORIGINATOR,
                            &"Error while deactivating bundle for delete",
                            &e,
                        );
                        return false;
                    }
                }
            }
        }
        base_delete_script(source_file)
    }

    /// Returns a [`GhidraScript`] instance for the specified source file.
    pub fn get_script_instance(
        &self,
        source_file: &ResourceFile,
        writer: &mut dyn std::io::Write,
    ) -> Result<Box<dyn GhidraScript>, GhidraScriptLoadException> {
        // Java wraps this in a try-with-resources `OSGiParallelLock`, a lock file guarding the
        // shared OSGi directory across concurrent Ghidra instances. `ghidra_script_util` does not
        // reproduce that lock either (see its `initialize` doc comment); this does not either.
        self.load_class(source_file, writer)?;
        Err(GhidraScriptLoadException::new(
            "Reflective script instantiation is not yet ported: it requires OSGi dynamic class \
             loading, which has no in-process Rust equivalent yet",
        ))
    }

    /// Activate and build the [`GhidraSourceBundle`] containing `source_file`, then resolve the
    /// script's compiled class name from its class loader.
    ///
    /// Returns the resolved class name on success, mirroring the useful half of Java's
    /// `Class<?> loadClass(ResourceFile, PrintWriter)`; actually loading that class requires OSGi
    /// dynamic class loading, which is not ported (see the module docs).
    pub fn load_class(
        &self,
        source_file: &ResourceFile,
        writer: &mut dyn std::io::Write,
    ) -> Result<String, GhidraScriptLoadException> {
        let bundle = self.get_bundle_for_source(source_file).ok_or_else(|| {
            GhidraScriptLoadException::new(format!(
                "Failed to find source bundle containing script: {}",
                source_file.absolute_path()
            ))
        })?;

        if let Some(host) = &self.bundle_host {
            host.activate_all(&[&bundle], &DummyMonitor, writer);
        }

        let classname = bundle.class_name_for_script(source_file).map_err(|e| {
            GhidraScriptLoadException::with_cause(
                format!(
                    "The class could not be found. It must be the public class of the .java \
                     file: {e}"
                ),
                e,
            )
        })?;

        if bundle.os_gi_bundle().is_none() {
            return Err(GhidraScriptLoadException::new(format!(
                "Failed to get OSGi bundle containing script: {}",
                source_file.absolute_path()
            )));
        }

        Ok(classname)
    }

    /// Creates a new script using the specified file.
    pub fn create_new_script(
        &self,
        new_script: &ResourceFile,
        category: Option<&str>,
    ) -> std::io::Result<()> {
        let script_name = new_script.name();
        let class_name = match script_name.rfind('.') {
            Some(dotpos) => script_name[..dotpos].to_string(),
            None => script_name,
        };

        let mut writer = new_script.get_output_stream()?;

        self.write_header(writer.as_mut(), category)?;

        writeln!(writer, "import ghidra.app.script.GhidraScript;")?;
        // Java also imports every currently loaded `ghidra.program.model.*` package here, found
        // via `Package.getPackages()` -- a JVM reflection facility over loaded classes with no
        // Rust equivalent. Omitted, matching `ResourceFileJavaFileManager`'s precedent for
        // JVM-only reflection this crate cannot reproduce.
        writeln!(writer)?;

        writeln!(writer, "public class {class_name} extends GhidraScript {{")?;
        writeln!(writer)?;
        writeln!(writer, "    public void run() throws Exception {{")?;

        self.write_body(writer.as_mut())?;

        writeln!(writer, "    }}")?;
        writeln!(writer)?;
        write!(writer, "}}")?;
        Ok(())
    }

    /// Writes the script header. Include a place holder for each meta-data item.
    ///
    /// Inlined from `GhidraScriptProvider.writeHeader`: that base class is only ported as the
    /// minimal seam trait in [`seam_stubs`](crate::script::seam_stubs) (see its doc comment), so
    /// its one concrete behavior a `JavaScriptProvider` needs is reproduced directly here rather
    /// than through `super`.
    fn write_header(&self, writer: &mut dyn std::io::Write, category: Option<&str>) -> std::io::Result<()> {
        let category = category.unwrap_or("_NEW_");
        writeln!(writer, "{}TODO write a description for this script", self.get_comment_character())?;

        for metadata_item in ["@author", "@category", "@keybinding", "@menupath", "@toolbar", "@runtime"] {
            write!(writer, "{}{metadata_item} ", self.get_comment_character())?;
            if metadata_item == "@category" {
                write!(writer, "{category}")?;
            } else if metadata_item == "@runtime" {
                write!(writer, "{}", GhidraScriptProvider::get_runtime_environment_name(self).unwrap_or_default())?;
            }
            writeln!(writer)?;
        }

        writeln!(writer)
    }

    /// Writes the script body template.
    fn write_body(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(writer, "{}TODO Add User Code Here", self.get_comment_character())
    }

    /// Returns a Pattern that matches block comment openings: `/\*`.
    pub fn get_block_comment_start(&self) -> &'static regex::Regex {
        block_comment_start()
    }

    /// Returns a Pattern that matches block comment closings: `\*/`.
    pub fn get_block_comment_end(&self) -> &'static regex::Regex {
        block_comment_end()
    }

    /// Returns the comment character: `//`.
    pub fn get_comment_character(&self) -> &'static str {
        "//"
    }

    /// The start of a certification header line for Java source files.
    pub fn get_certify_header_start(&self) -> &'static str {
        "/* ###"
    }

    /// The end of a certification header line for Java source files.
    pub fn get_certify_header_end(&self) -> &'static str {
        "*/"
    }

    /// The prefix for each certification header body line for Java source files.
    pub fn get_certification_body_prefix(&self) -> &'static str {
        "*"
    }
}

impl GhidraScriptProvider for JavaScriptProvider {
    fn get_extension(&self) -> String {
        ".java".to_string()
    }

    fn get_runtime_environment_name(&self) -> Option<String> {
        Some("Java".to_string())
    }

    /// Fix script name for search in script directories, such as Java package parts in the name
    /// and inner class names.
    ///
    /// This method can handle names with `$` (inner classes) and names with `.` characters for
    /// package separators.
    fn fixup_name(&self, script_name: &str) -> String {
        let base = &script_name[..script_name.len().saturating_sub(".java".len())];
        let mut path = base.replace('.', "/");
        if let Some(inner_class_index) = path.find('$') {
            path.truncate(inner_class_index);
        }
        format!("{path}.java")
    }
}

/// Mirrors `GhidraScriptProvider.deleteScript`'s base implementation, which `JavaScriptProvider`
/// calls via `super.deleteScript(sourceFile)`.
fn base_delete_script(source_file: &ResourceFile) -> bool {
    !source_file.exists() || std::fs::remove_file(source_file.absolute_path()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn get_extension_is_dot_java() {
        let provider = JavaScriptProvider::new();
        assert_eq!(GhidraScriptProvider::get_extension(&provider), ".java");
    }

    #[test]
    fn get_description_and_runtime_are_java() {
        let provider = JavaScriptProvider::new();
        assert_eq!(provider.get_description(), "Java");
        assert_eq!(GhidraScriptProvider::get_runtime_environment_name(&provider), Some("Java".to_string()));
    }

    #[test]
    fn get_comment_character_is_double_slash() {
        let provider = JavaScriptProvider::new();
        assert_eq!(provider.get_comment_character(), "//");
    }

    #[test]
    fn block_comment_patterns_match_java_delimiters() {
        let provider = JavaScriptProvider::new();
        assert!(provider.get_block_comment_start().is_match("/*"));
        assert!(provider.get_block_comment_end().is_match("*/"));
        assert!(!provider.get_block_comment_start().is_match("//"));
    }

    #[test]
    fn fixup_name_strips_extension_and_converts_package_dots_to_slashes() {
        let provider = JavaScriptProvider::new();
        assert_eq!(provider.fixup_name("com.example.MyScript.java"), "com/example/MyScript.java");
    }

    #[test]
    fn fixup_name_truncates_at_inner_class_separator() {
        let provider = JavaScriptProvider::new();
        assert_eq!(provider.fixup_name("com.example.MyScript$Inner.java"), "com/example/MyScript.java");
    }

    #[test]
    fn fixup_name_handles_a_bare_script_name() {
        let provider = JavaScriptProvider::new();
        assert_eq!(provider.fixup_name("MyScript.java"), "MyScript.java");
    }

    #[test]
    fn delete_script_deletes_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MyScript.java");
        std::fs::write(&path, b"// script").unwrap();
        let source_file = ResourceFile::new(path.clone());

        let provider = JavaScriptProvider::new();
        assert!(provider.delete_script(&source_file));
        assert!(!path.exists());
    }

    #[test]
    fn delete_script_reports_success_for_an_already_missing_file() {
        let source_file = ResourceFile::new(PathBuf::from("/nonexistent/MyScript.java"));
        let provider = JavaScriptProvider::new();
        assert!(provider.delete_script(&source_file));
    }

    #[test]
    fn get_bundle_for_source_is_none_without_a_matching_script_directory() {
        let source_file = ResourceFile::new(PathBuf::from("/nonexistent/MyScript.java"));
        let provider = JavaScriptProvider::new();
        assert!(provider.get_bundle_for_source(&source_file).is_none());
    }

    #[test]
    fn load_class_fails_when_no_source_bundle_is_found() {
        let source_file = ResourceFile::new(PathBuf::from("/nonexistent/MyScript.java"));
        let provider = JavaScriptProvider::new();
        let mut sink = Vec::new();
        let err = provider.load_class(&source_file, &mut sink).unwrap_err();
        assert!(err.message().contains("Failed to find source bundle"));
    }

    #[test]
    fn create_new_script_writes_a_class_skeleton() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MyNewScript.java");
        let new_script = ResourceFile::new(path.clone());

        let provider = JavaScriptProvider::new();
        provider.create_new_script(&new_script, Some("Examples")).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("@category Examples"));
        assert!(contents.contains("@runtime Java"));
        assert!(contents.contains("import ghidra.app.script.GhidraScript;"));
        assert!(contents.contains("public class MyNewScript extends GhidraScript {"));
        assert!(contents.contains("public void run() throws Exception {"));
        assert!(contents.contains("//TODO Add User Code Here"));
    }
}
