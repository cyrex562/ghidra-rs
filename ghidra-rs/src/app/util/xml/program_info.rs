//! Values pulled from the PROGRAM, INFO_SOURCE, and LANGUAGE tags inside a
//! Ghidra program XML file.
//!
//! Java peer: `ghidra.app.util.xml.ProgramInfo`

use std::fmt;

use crate::program::model::lang::{CompilerSpecID, LanguageID};

/// This class stores values pulled from the PROGRAM, INFO_SOURCE, and LANGUAGE
/// tag inside a ghidra program XML file.
///
/// Please see PROGRAM.DTD
#[derive(Debug, Default, Clone)]
pub struct ProgramInfo {
    /// The family name of the program's processor (eg, "Intel").
    pub family: Option<String>,
    /// The program's processor (eg, Processor.PROCESSOR_X86).
    pub processor_name: Option<String>,
    /// The program's language id, e.g. "x86:LE:32:default".
    pub language_id: Option<LanguageID>,
    /// The program's compilerSpec id, e.g. "gcc".
    pub compiler_spec_id: Option<CompilerSpecID>,
    /// The preferred name of the Program when loaded back into Ghidra.
    pub program_name: Option<String>,
    /// The timestamp of when the XML file was created.
    pub timestamp: Option<String>,
    /// The ID of the user that created the XML file.
    pub user: Option<String>,
    /// The tool that generated the XML file (eg, "Ghidra", etc.).
    tool: Option<String>,
    /// This is the name of the tool normalized into known categories
    /// ("IDA-PRO" or "GHIDRA") if appropriate.
    normalized_external_tool_name: Option<String>,
    /// The XML version.
    #[deprecated(note = "since version 2.1")]
    pub version: Option<String>,
    /// The size of the addressing (eg, "32 bit").
    #[deprecated(note = "since version 2.1")]
    pub address_model: Option<String>,
    /// The endianness (eg, big or little).
    pub endian: Option<String>,
    /// The absolute path of where the original executable was imported.
    pub exe_path: Option<String>,
    /// The format of the original executable (eg, PE or ELF).
    pub exe_format: Option<String>,
    /// The image base of the program.
    pub image_base: Option<String>,
}

impl ProgramInfo {
    /// Creates a new, empty `ProgramInfo`.
    #[allow(deprecated)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the XmlMgr should process stack frames and references.
    pub fn should_process_stack(&self) -> bool {
        true
    }

    /// Returns true if the tool was IDA-PRO.
    fn is_ida_pro(&self) -> bool {
        self.normalized_external_tool_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("IDA-PRO"))
    }

    #[allow(dead_code)]
    fn is_ghidra(&self) -> bool {
        self.normalized_external_tool_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("GHIDRA"))
    }

    fn translate_compiler(&self, compiler: &str) -> String {
        if self.is_ida_pro() {
            return Self::translate_ida_compiler_name(compiler);
        }
        compiler.to_string()
    }

    /// Sets the compiler spec ID, translating IDA-PRO compiler names first if needed.
    pub fn set_compiler_spec_id(&mut self, compiler: Option<&str>) {
        self.compiler_spec_id = compiler.map(|compiler| {
            let translated = self.translate_compiler(compiler);
            CompilerSpecID::new(Some(&translated))
        });
    }

    fn translate_ida_compiler_name(compiler: &str) -> String {
        if compiler == "Visual C++" {
            return "windows".to_string();
        }
        compiler.to_string()
    }

    /// Returns the tool field. This is the name of the tool exactly as written
    /// in the XML being imported.
    pub fn tool(&self) -> Option<&str> {
        self.tool.as_deref()
    }

    /// Sets the tool field.
    ///
    /// Also sets `normalized_external_tool_name` to a normalized tool name
    /// ("IDA-PRO" or "GHIDRA") if appropriate, or just the value of `tool`.
    pub fn set_tool(&mut self, tool: Option<String>) {
        self.normalized_external_tool_name = tool.clone();

        if let Some(tool) = &tool {
            let upper = tool.to_uppercase();
            if upper.starts_with("IDA-PRO") {
                self.normalized_external_tool_name = Some("IDA-PRO".to_string());
            } else if upper.starts_with("GHIDRA") {
                // null, not external
                self.normalized_external_tool_name = None;
            }
        }

        self.tool = tool;
    }

    /// Returns the normalized external tool name field. This is the name of
    /// the tool normalized into known categories ("IDA-PRO" or "GHIDRA") if
    /// appropriate.
    pub fn normalized_external_tool_name(&self) -> Option<&str> {
        self.normalized_external_tool_name.as_deref()
    }
}

impl fmt::Display for ProgramInfo {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "processor={}\nfamily={}\ncompiler={}\naddress model={}\nendian={}\nprogram={}",
            self.processor_name.as_deref().unwrap_or("null"),
            self.family.as_deref().unwrap_or("null"),
            self.compiler_spec_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "null".to_string()),
            self.address_model.as_deref().unwrap_or("null"),
            self.endian.as_deref().unwrap_or("null"),
            self.program_name.as_deref().unwrap_or("null"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_process_stack_is_always_true() {
        let info = ProgramInfo::new();
        assert!(info.should_process_stack());
    }

    #[test]
    fn set_tool_ida_pro_normalizes() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("IDA-PRO 7.0".to_string()));
        assert_eq!(info.tool(), Some("IDA-PRO 7.0"));
        assert_eq!(info.normalized_external_tool_name(), Some("IDA-PRO"));
        assert!(info.is_ida_pro());
    }

    #[test]
    fn set_tool_ghidra_normalizes_to_none() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("Ghidra 10.0".to_string()));
        assert_eq!(info.tool(), Some("Ghidra 10.0"));
        assert_eq!(info.normalized_external_tool_name(), None);
        // A "Ghidra" tool normalizes to None, so is_ghidra() (which inspects the
        // normalized name, matching Java's ProgramInfo.isGhidra) is false.
        assert!(!info.is_ghidra());
    }

    #[test]
    fn set_tool_other_keeps_value() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("Some Other Tool".to_string()));
        assert_eq!(
            info.normalized_external_tool_name(),
            Some("Some Other Tool")
        );
        assert!(!info.is_ida_pro());
        assert!(!info.is_ghidra());
    }

    #[test]
    fn set_tool_none_clears_fields() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("Ghidra".to_string()));
        info.set_tool(None);
        assert_eq!(info.tool(), None);
        assert_eq!(info.normalized_external_tool_name(), None);
    }

    #[test]
    fn set_compiler_spec_id_plain() {
        let mut info = ProgramInfo::new();
        info.set_compiler_spec_id(Some("gcc"));
        assert_eq!(
            info.compiler_spec_id.as_ref().unwrap().get_id_as_string(),
            "gcc"
        );
    }

    #[test]
    fn set_compiler_spec_id_none_clears() {
        let mut info = ProgramInfo::new();
        info.set_compiler_spec_id(Some("gcc"));
        info.set_compiler_spec_id(None);
        assert!(info.compiler_spec_id.is_none());
    }

    #[test]
    fn set_compiler_spec_id_translates_ida_visual_cpp() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("IDA-PRO".to_string()));
        info.set_compiler_spec_id(Some("Visual C++"));
        assert_eq!(
            info.compiler_spec_id.as_ref().unwrap().get_id_as_string(),
            "windows"
        );
    }

    #[test]
    fn set_compiler_spec_id_does_not_translate_when_not_ida() {
        let mut info = ProgramInfo::new();
        info.set_tool(Some("Ghidra".to_string()));
        info.set_compiler_spec_id(Some("Visual C++"));
        assert_eq!(
            info.compiler_spec_id.as_ref().unwrap().get_id_as_string(),
            "Visual C++"
        );
    }

    #[test]
    fn display_formats_fields() {
        let mut info = ProgramInfo::new();
        info.processor_name = Some("x86".to_string());
        info.family = Some("Intel".to_string());
        info.set_compiler_spec_id(Some("gcc"));
        #[allow(deprecated)]
        {
            info.address_model = Some("32 bit".to_string());
        }
        info.endian = Some("little".to_string());
        info.program_name = Some("test.exe".to_string());

        let s = info.to_string();
        assert!(s.contains("processor=x86"));
        assert!(s.contains("family=Intel"));
        assert!(s.contains("compiler=gcc"));
        assert!(s.contains("address model=32 bit"));
        assert!(s.contains("endian=little"));
        assert!(s.contains("program=test.exe"));
    }

    #[test]
    fn default_is_empty() {
        let info = ProgramInfo::new();
        assert!(info.family.is_none());
        assert!(info.tool().is_none());
        assert!(info.compiler_spec_id.is_none());
    }
}
