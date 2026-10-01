//! Port of `ghidra.app.util.bin.format.golang.GoRegisterInfoManager`.

use std::collections::HashMap;
use std::io::{self, Read};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use super::go_register_info::{GoRegisterInfo, RegType};
use super::go_ver::GoVer;
use super::go_ver_set::GoVerSet;
use crate::format::dwarf::dwarf_util::get_language_external_file;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::util::msg::Msg;

const REGISTER_INFO_EXTERNAL_NAME: &str = "Golang.register.info.file";

/// Reads the Go register info file a language names in its ldefs.
///
/// XML config file format:
/// ```text
/// <golang>
///     <register_info versions="-1.2,1.3.3-1.4.2,1.8-"> // or "all"
///         <int_registers list="RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11"/>
///         <float_registers list="XMM0,XMM1,...,XMM14"/>
///         <stack initialoffset="8" maxalign="8"/>
///         <current_goroutine register="R14"/>
///         <zero_register register="XMM15" builtin="true|false"/>
///         <duffzero dest="RDI" zero_arg="XMM0" zero_type="float|int"/>
///         <closurecontext register="RDX" />
///     </register_info>
///     <register_info versions="1.2">
///         ...
///     </register_info>
/// </golang>
/// ```
#[derive(Debug, Default)]
pub struct GoRegisterInfoManager {
    _private: (),
}

static INSTANCE: GoRegisterInfoManager = GoRegisterInfoManager { _private: () };

impl GoRegisterInfoManager {
    /// `getInstance()`: the shared manager.
    pub fn get_instance() -> &'static GoRegisterInfoManager {
        &INSTANCE
    }

    /// Returns a [`GoRegisterInfo`] instance for the specified language
    /// (`getRegisterInfoForLang(Language, GoVer)`).
    ///
    /// If the language didn't define Go register info, a generic/empty instance will be
    /// returned that forces all parameters to be stack allocated.
    pub fn get_register_info_for_lang(&self, lang: &dyn Language, go_ver: GoVer) -> GoRegisterInfo {
        let register_infos = self.load_register_info(lang);
        if let Some(ri) = register_infos.into_iter().find(|ri| ri.get_valid_versions().contains(go_ver)) {
            return ri;
        }
        let go_size = lang.get_instruction_alignment();
        Msg::warn(
            "GoRegisterInfoManager",
            &format!(
                "Missing Go register info for: {}, defaulting to abi0, size={go_size}",
                lang.get_language_id()
            ),
        );
        self.get_default(lang)
    }

    fn load_register_info(&self, lang: &dyn Language) -> Vec<GoRegisterInfo> {
        let result = (|| -> io::Result<Option<Vec<GoRegisterInfo>>> {
            let Some(f) = get_language_external_file(lang, REGISTER_INFO_EXTERNAL_NAME)? else {
                return Ok(None);
            };
            let mut xml = String::new();
            f.get_input_stream()
                .and_then(|mut is| is.read_to_string(&mut xml))
                .map_err(|e| {
                    io::Error::other(format!("Failed to read Go register info file {}: {e}", f.absolute_path()))
                })?;
            Ok(Some(self.read_from_str(&xml, &|name| lang.get_register_by_name(name)).map_err(|e| {
                Msg::error(
                    "GoRegisterInfo",
                    &format!("Bad Go register info file {}: {e}", f.absolute_path()),
                );
                io::Error::other(format!("Failed to read Go register info file {}", f.absolute_path()))
            })?))
        })();
        match result {
            Ok(Some(infos)) => infos,
            Ok(None) => {
                Msg::warn(
                    "GoRegisterInfoManager",
                    &format!("Missing Go register info file for: {}", lang.get_language_id()),
                );
                Vec::new()
            }
            Err(e) => {
                Msg::warn("GoRegisterInfoManager", &format!("Failed to read Go register info file: {e}"));
                Vec::new()
            }
        }
    }

    /// Parses a register info XML document (`readFrom(Element, Language)`), resolving register
    /// names with `lookup_register` (Java's `lang.getRegister(name)`).
    ///
    /// # Errors
    /// Malformed XML, a missing required element/attribute, an out of range number, or an
    /// unknown register name.
    pub fn read_from_str(
        &self,
        xml: &str,
        lookup_register: &dyn Fn(&str) -> Option<Register>,
    ) -> io::Result<Vec<GoRegisterInfo>> {
        let mut result = Vec::new();
        for elem in parse_register_info_elements(xml)? {
            result.push(read_reg_info_element(&elem, lookup_register)?);
        }
        Ok(result)
    }

    fn get_default(&self, lang: &dyn Language) -> GoRegisterInfo {
        let go_size = lang.get_instruction_alignment();
        GoRegisterInfo::new(
            Vec::new(),
            Vec::new(),
            go_size,
            go_size,
            None,
            None,
            false,
            None,
            None,
            Some(RegType::Int),
            None,
            GoVerSet::all(),
        )
    }
}

/// A `<register_info>` element: its own attributes and the attributes of each child element.
#[derive(Default)]
struct RegInfoElement {
    attrs: HashMap<String, String>,
    children: HashMap<String, HashMap<String, String>>,
}

fn element_attrs(e: &BytesStart<'_>) -> io::Result<HashMap<String, String>> {
    let mut attrs = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|e| io::Error::other(format!("Bad XML attribute: {e}")))?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let raw = String::from_utf8_lossy(&attr.value).to_string();
        let value = quick_xml::escape::unescape(&raw)
            .map_err(|e| io::Error::other(format!("Bad XML attribute value: {e}")))?
            .to_string();
        attrs.insert(key, value);
    }
    Ok(attrs)
}

/// Collects the `<register_info>` children of the root element (JDOM's
/// `rootElem.getChildren("register_info")`), keeping the first of each named grandchild
/// (`getChild(name)`).
fn parse_register_info_elements(xml: &str) -> io::Result<Vec<RegInfoElement>> {
    let mut reader = Reader::from_str(xml);
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<RegInfoElement> = None;
    loop {
        let event = reader.read_event().map_err(|e| io::Error::other(format!("Bad XML: {e}")))?;
        match event {
            Event::Start(e) => {
                depth += 1;
                handle_open(&e, depth, &mut current)?;
            }
            Event::Empty(e) => {
                handle_open(&e, depth + 1, &mut current)?;
                if depth + 1 == 2 {
                    if let Some(ri) = current.take() {
                        result.push(ri);
                    }
                }
            }
            Event::End(_) => {
                if depth == 2 {
                    if let Some(ri) = current.take() {
                        result.push(ri);
                    }
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(result)
}

fn handle_open(e: &BytesStart<'_>, depth: usize, current: &mut Option<RegInfoElement>) -> io::Result<()> {
    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
    if depth == 2 && name == "register_info" {
        *current = Some(RegInfoElement { attrs: element_attrs(e)?, children: HashMap::new() });
    }
    else if depth == 3 {
        if let Some(ri) = current.as_mut() {
            if !ri.children.contains_key(&name) {
                ri.children.insert(name, element_attrs(e)?);
            }
        }
    }
    Ok(())
}

fn read_reg_info_element(
    elem: &RegInfoElement,
    lookup_register: &dyn Fn(&str) -> Option<Register>,
) -> io::Result<GoRegisterInfo> {
    let versions = elem
        .attrs
        .get("versions")
        .ok_or_else(|| io::Error::other("Missing required attribute: versions"))?;
    let valid_go_versions = GoVerSet::parse(versions)?;

    let child = |name: &str| elem.children.get(name);
    let (
        Some(int_regs_elem),
        Some(float_regs_elem),
        Some(stack_elem),
        Some(go_routine_elem),
        Some(zero_reg_elem),
        Some(duff_zero_elem),
        Some(closure_context_elem),
    ) = (
        child("int_registers"),
        child("float_registers"),
        child("stack"),
        child("current_goroutine"),
        child("zero_register"),
        child("duffzero"),
        child("closurecontext"),
    )
    else {
        return Err(io::Error::other("Bad format"));
    };
    let attr = |m: &HashMap<String, String>, n: &str| m.get(n).cloned();

    let int_regs = parse_reg_list_str(attr(int_regs_elem, "list"), lookup_register)?;
    let float_regs = parse_reg_list_str(attr(float_regs_elem, "list"), lookup_register)?;

    let stack_initial_offset = parse_bounded_int_attr(stack_elem, "initialoffset", 0, i32::MAX)?;
    let max_align = parse_bounded_int_attr(stack_elem, "maxalign", 1, i32::MAX)?;

    let current_go_routine_reg = parse_reg_str(attr(go_routine_elem, "register"), lookup_register)?;
    let zero_reg = parse_reg_str(attr(zero_reg_elem, "register"), lookup_register)?;
    let zero_reg_is_builtin = parse_optional_boolean_attr(zero_reg_elem, "builtin", false)?;

    let duffzero_dest = parse_reg_str(attr(duff_zero_elem, "dest"), lookup_register)?;
    let duffzero_zero = parse_reg_str(attr(duff_zero_elem, "zero_arg"), lookup_register)?;
    let duffzero_zero_type = parse_reg_type_str(attr(duff_zero_elem, "zero_type").as_deref());

    let closure_context_reg = parse_reg_str(attr(closure_context_elem, "register"), lookup_register)?;

    Ok(GoRegisterInfo::new(
        int_regs,
        float_regs,
        stack_initial_offset,
        max_align,
        current_go_routine_reg,
        zero_reg,
        zero_reg_is_builtin,
        duffzero_dest,
        duffzero_zero,
        Some(duffzero_zero_type),
        closure_context_reg,
        valid_go_versions,
    ))
}

fn parse_reg_list_str(
    s: Option<String>,
    lookup_register: &dyn Fn(&str) -> Option<Register>,
) -> io::Result<Vec<Register>> {
    // Java: s.split(",") on a null attribute throws a NullPointerException
    let s = s.ok_or_else(|| io::Error::other("Missing register list attribute"))?;
    let mut result = Vec::new();
    for reg_name in s.split(',') {
        let reg_name = reg_name.trim();
        if reg_name.is_empty() {
            continue;
        }
        if let Some(register) = parse_reg_str(Some(reg_name.to_string()), lookup_register)? {
            result.push(register);
        }
    }
    Ok(result)
}

fn parse_reg_str(
    reg_name: Option<String>,
    lookup_register: &dyn Fn(&str) -> Option<Register>,
) -> io::Result<Option<Register>> {
    let Some(reg_name) = reg_name.filter(|n| !n.trim().is_empty()) else {
        return Ok(None);
    };
    match lookup_register(&reg_name) {
        Some(r) => Ok(Some(r)),
        None => Err(io::Error::other(format!("Unknown register: {reg_name}"))),
    }
}

fn parse_reg_type_str(s: Option<&str>) -> RegType {
    match s.unwrap_or("int").to_lowercase().as_str() {
        "float" => RegType::Float,
        _ => RegType::Int,
    }
}

/// `XmlUtilities.parseLong(String)`: decimal, or hex with a `0x` prefix, optionally negative.
fn parse_xml_long(s: &str) -> Option<i64> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let val = match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()? as i64,
        None => s.parse::<i64>().ok()?,
    };
    Some(if neg { -val } else { val })
}

/// `XmlUtilities.parseBoundedIntAttr(Element, String, int, int)`.
fn parse_bounded_int_attr(attrs: &HashMap<String, String>, name: &str, min: i32, max: i32) -> io::Result<i32> {
    let bad = |msg: String| io::Error::new(io::ErrorKind::InvalidData, format!("Attribute '{name}' bad value: {msg}"));
    let s = attrs.get(name).ok_or_else(|| bad("missing".to_string()))?;
    let v = parse_xml_long(s).ok_or_else(|| bad(format!("For input string: \"{s}\"")))?;
    if v < min as i64 || v > max as i64 {
        return Err(bad(format!("Integer value {v} out of range: [{min}..{max}]")));
    }
    Ok(v as i32)
}

/// `XmlUtilities.parseOptionalBooleanAttr(Element, String, boolean)`: `y`/`n`/`true`/`false`.
fn parse_optional_boolean_attr(attrs: &HashMap<String, String>, name: &str, default: bool) -> io::Result<bool> {
    match attrs.get(name) {
        None => Ok(default),
        Some(v) if v.eq_ignore_ascii_case("y") || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("n") || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(v) => Err(io::Error::other(format!("Attribute '{name}' bad boolean value: '{v}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    /// `x86-64-golang.register.info`, verbatim.
    const X86_64_GOLANG_REGISTER_INFO: &str = r#"<golang>
	<!-- see https://github.com/golang/go/blob/master/src/internal/abi/abi_amd64.go -->
	<register_info versions="1.17-"> <!-- "all", or comma list of versions or ranges of versions -->
		<int_registers list="RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11"/>
		<float_registers list="XMM0,XMM1,XMM2,XMM3,XMM4,XMM5,XMM6,XMM7,XMM8,XMM9,XMM10,XMM11,XMM12,XMM13,XMM14"/>
		<stack initialoffset="8" maxalign="8"/>
		<current_goroutine register="R14"/>
		<zero_register register="XMM15"/>
		<duffzero dest="RDI" />
		<closurecontext register="RDX"/>
	</register_info>
	<register_info versions="-1.16">
		<int_registers list=""/>
		<float_registers list=""/>
		<stack initialoffset="8" maxalign="8"/>
		<current_goroutine register=""/>
		<zero_register register=""/>
		<duffzero dest="RDI" zero_arg="XMM0" zero_type="float"/>
		<closurecontext register="RDX"/>
	</register_info>
</golang>"#;

    fn lookup(name: &str) -> Option<Register> {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        let known = [
            "RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "R8", "R9", "R10", "R11", "R14", "XMM0", "XMM1", "XMM2",
            "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14",
            "XMM15",
        ];
        let idx = known.iter().position(|k| *k == name)?;
        let size = if name.starts_with("XMM") { 16 } else { 8 };
        Some(Register::new(name, name, Address::new(space, idx as i64 * 0x20), size, false, 0))
    }

    #[test]
    fn reads_x86_64_register_info() {
        let infos = GoRegisterInfoManager::get_instance()
            .read_from_str(X86_64_GOLANG_REGISTER_INFO, &lookup)
            .unwrap();
        assert_eq!(infos.len(), 2);

        let abi_internal = &infos[0];
        assert!(abi_internal.get_valid_versions().contains(GoVer::new(1, 17, 0)));
        assert!(abi_internal.get_valid_versions().contains(GoVer::new(1, 22, 0)));
        assert!(!abi_internal.get_valid_versions().contains(GoVer::new(1, 16, 0)));
        let int_names: Vec<&str> = abi_internal.get_int_registers().iter().map(|r| r.name()).collect();
        assert_eq!(int_names, ["RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"]);
        assert_eq!(abi_internal.get_float_registers().len(), 15);
        assert_eq!(abi_internal.get_stack_initial_offset(), 8);
        assert_eq!(abi_internal.get_max_align(), 8);
        assert_eq!(abi_internal.get_current_goroutine_register().unwrap().name(), "R14");
        assert_eq!(abi_internal.get_zero_register().unwrap().name(), "XMM15");
        assert!(!abi_internal.is_zero_register_is_builtin());
        assert_eq!(abi_internal.get_closure_context_register().unwrap().name(), "RDX");
        assert!(abi_internal.has_abi_internal_param_registers());

        let abi0 = &infos[1];
        assert!(abi0.get_valid_versions().contains(GoVer::new(1, 16, 0)));
        assert!(!abi0.get_valid_versions().contains(GoVer::new(1, 17, 0)));
        assert!(abi0.get_int_registers().is_empty());
        assert!(abi0.get_float_registers().is_empty());
        assert!(abi0.get_current_goroutine_register().is_none());
        assert!(abi0.get_zero_register().is_none());
        assert!(!abi0.has_abi_internal_param_registers());
    }

    #[test]
    fn rejects_unknown_register_and_bad_format() {
        let bad_reg = X86_64_GOLANG_REGISTER_INFO.replace("R14", "R99");
        let err = GoRegisterInfoManager::get_instance().read_from_str(&bad_reg, &lookup).unwrap_err();
        assert!(err.to_string().contains("Unknown register: R99"));

        let missing = X86_64_GOLANG_REGISTER_INFO.replace("<closurecontext register=\"RDX\"/>", "");
        let err = GoRegisterInfoManager::get_instance().read_from_str(&missing, &lookup).unwrap_err();
        assert_eq!(err.to_string(), "Bad format");

        let bad_align = X86_64_GOLANG_REGISTER_INFO.replacen("maxalign=\"8\"", "maxalign=\"0\"", 1);
        assert!(GoRegisterInfoManager::get_instance().read_from_str(&bad_align, &lookup).is_err());
    }

    #[test]
    fn attribute_helpers() {
        let attrs: HashMap<String, String> =
            [("a".to_string(), "0x10".to_string()), ("b".to_string(), "Y".to_string())].into();
        assert_eq!(parse_bounded_int_attr(&attrs, "a", 0, 100).unwrap(), 16);
        assert!(parse_optional_boolean_attr(&attrs, "b", false).unwrap());
        assert!(parse_optional_boolean_attr(&attrs, "c", true).unwrap());
        assert_eq!(parse_reg_type_str(Some("FLOAT")), RegType::Float);
        assert_eq!(parse_reg_type_str(None), RegType::Int);
        assert_eq!(parse_xml_long("-12"), Some(-12));
    }
}
