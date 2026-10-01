//! Port of `ghidra.app.util.bin.format.macho.prelink.MachoPrelinkParser`.
//!
//! Parses the XML property list stored in a kernelcache's `__PRELINK_INFO,__info` section into
//! one [`MachoPrelinkMap`] per prelinked kext.
//!
//! Java builds a JDOM document with `XmlUtilities.createSecureSAXBuilder`; this port builds the
//! same minimal element tree (name, attributes, element children, text) from the crate's SAX
//! layer, [`sax_parser`](crate::util::xml::sax_parser), with `<!DOCTYPE>` disallowed as in the
//! secure builder (the parser strips the plist's doctype first, as Java does).

use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::prelink::macho_prelink_constants as constants;
use crate::format::macho::prelink::macho_prelink_map::MachoPrelinkMap;
use crate::format::macho::prelink::no_pre_link_section_exception::NoPreLinkSectionException;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;
use crate::util::xml::sax_parser::{self, SaxConfig, SaxContentHandler, SaxError, SaxLocation};

const TAG_DATA: &str = "data";
const TAG_FALSE: &str = "false";
const TAG_TRUE: &str = "true";
const TAG_INTEGER: &str = "integer";
const TAG_STRING: &str = "string";
const TAG_KEY: &str = "key";
const TAG_DICT: &str = "dict";
const TAG_ARRAY: &str = "array";

/// Why [`MachoPrelinkParser::parse`] failed (Java: `IOException`, `JDOMException`,
/// `NoPreLinkSectionException`).
#[derive(Debug)]
pub enum MachoPrelinkError {
    /// Reading the section bytes failed.
    Io(std::io::Error),
    /// The plist is not well-formed XML (Java: `JDOMException`).
    Xml(String),
    /// No `__info` section in a prelink segment.
    NoPreLinkSection(NoPreLinkSectionException),
    /// An integer `IDREF` named no earlier `ID` (Java: `NullPointerException` unboxing it).
    MissingIntegerIdRef(String),
}

impl fmt::Display for MachoPrelinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachoPrelinkError::Io(e) => write!(f, "{e}"),
            MachoPrelinkError::Xml(m) => f.write_str(m),
            MachoPrelinkError::NoPreLinkSection(e) => write!(f, "{e}"),
            MachoPrelinkError::MissingIntegerIdRef(id) => write!(f, "no integer with ID {id}"),
        }
    }
}

impl std::error::Error for MachoPrelinkError {}

impl From<std::io::Error> for MachoPrelinkError {
    fn from(e: std::io::Error) -> Self {
        MachoPrelinkError::Io(e)
    }
}

/// The parts of a JDOM `Element` the parser reads.
#[derive(Debug, Default)]
struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
    /// Text and child-element content in document order, for [`Element::value`].
    content: Vec<Content>,
}

#[derive(Debug)]
enum Content {
    Text(String),
    Child(usize),
}

impl Element {
    /// JDOM `getValue()`: the concatenated text of this element and all its descendants.
    fn value(&self) -> String {
        let mut out = String::new();
        self.collect_value(&mut out);
        out
    }

    fn collect_value(&self, out: &mut String) {
        for c in &self.content {
            match c {
                Content::Text(t) => out.push_str(t),
                Content::Child(i) => self.children[*i].collect_value(out),
            }
        }
    }

    /// JDOM `getAttributeValue(String)`.
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// Builds the [`Element`] tree from SAX events.
#[derive(Default)]
struct TreeBuilder {
    stack: Vec<Element>,
    root: Option<Element>,
}

impl SaxContentHandler for TreeBuilder {
    fn start_element(
        &mut self,
        name: &str,
        attributes: Vec<(String, String)>,
        _location: SaxLocation,
    ) -> Result<(), SaxError> {
        self.stack.push(Element { name: name.to_string(), attributes, ..Default::default() });
        Ok(())
    }

    fn end_element(&mut self, _name: &str, _location: SaxLocation) -> Result<(), SaxError> {
        let element = self.stack.pop().expect("balanced elements");
        match self.stack.last_mut() {
            Some(parent) => {
                parent.content.push(Content::Child(parent.children.len()));
                parent.children.push(element);
            }
            None => self.root = Some(element),
        }
        Ok(())
    }

    fn characters(&mut self, text: &str) -> Result<(), SaxError> {
        if let Some(e) = self.stack.last_mut() {
            e.content.push(Content::Text(text.to_string()));
        }
        Ok(())
    }

    fn processing_instruction(&mut self, _target: &str, _data: &str) -> Result<(), SaxError> {
        Ok(())
    }
}

/// Parses the prelink plist of a kernelcache.
///
/// Port of `ghidra.app.util.bin.format.macho.prelink.MachoPrelinkParser`.
pub struct MachoPrelinkParser<'h> {
    id_to_strings: HashMap<String, String>,
    id_to_integers: HashMap<String, i64>,
    main_header: &'h MachHeader,
    provider: Rc<dyn ByteProvider>,
}

impl<'h> MachoPrelinkParser<'h> {
    /// Java: `MachoPrelinkParser(MachHeader, ByteProvider)`. `main_header` must already be
    /// parsed.
    pub fn new(main_header: &'h MachHeader, provider: Rc<dyn ByteProvider>) -> Self {
        MachoPrelinkParser {
            id_to_strings: HashMap::new(),
            id_to_integers: HashMap::new(),
            main_header,
            provider,
        }
    }

    /// Java: `parse(TaskMonitor)`. One map per prelinked kext's info dictionary.
    pub fn parse(&mut self, monitor: &dyn TaskMonitor) -> Result<Vec<MachoPrelinkMap>, MachoPrelinkError> {
        let input = self.find_prelink_input_stream()?;
        monitor.set_message("Parsing prelink plist...");
        let mut builder = TreeBuilder::default();
        sax_parser::parse(&input, SaxConfig { allow_doctype: false }, &mut builder)
            .map_err(|e| MachoPrelinkError::Xml(e.to_string()))?;
        let root = builder.root.ok_or_else(|| MachoPrelinkError::Xml("no root element".into()))?;

        let mut list = Vec::new();
        if root.name == TAG_ARRAY {
            // iOS version before 4.x
            self.process(&root.children, &mut list, monitor)?;
        } else {
            let mut iter = root.children.iter();
            while let Some(element) = iter.next() {
                if monitor.is_cancelled() {
                    break;
                }
                if element.name == TAG_DICT {
                    self.process_top_dict(monitor, &mut list, element)?;
                } else if element.name == TAG_KEY {
                    self.process_key(monitor, &mut list, &mut iter, element)?;
                }
            }
        }
        Ok(list)
    }

    fn process_top_dict(
        &mut self,
        monitor: &dyn TaskMonitor,
        list: &mut Vec<MachoPrelinkMap>,
        dict_root: &Element,
    ) -> Result<(), MachoPrelinkError> {
        let mut iter = dict_root.children.iter();
        while let Some(element) = iter.next() {
            if monitor.is_cancelled() {
                break;
            }
            if element.name == TAG_KEY {
                self.process_key(monitor, list, &mut iter, element)?;
            }
        }
        Ok(())
    }

    fn process_key<'e>(
        &mut self,
        monitor: &dyn TaskMonitor,
        list: &mut Vec<MachoPrelinkMap>,
        iter: &mut impl Iterator<Item = &'e Element>,
        element: &Element,
    ) -> Result<(), MachoPrelinkError> {
        let value = element.value();
        if value == constants::K_PRELINK_PERSONALITIES_KEY {
            // Java reads (and ignores) the personalities array.
            iter.next();
        } else if value == constants::K_PRELINK_INFO_DICTIONARY_KEY {
            if let Some(array) = iter.next() {
                self.process(&array.children, list, monitor)?;
            }
        }
        Ok(())
    }

    fn process(
        &mut self,
        children: &[Element],
        list: &mut Vec<MachoPrelinkMap>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MachoPrelinkError> {
        monitor.set_message("Processing prelink information...");
        for element in children {
            if monitor.is_cancelled() {
                break;
            }
            if element.name == TAG_DICT {
                let map = self.process_element(element, monitor)?;
                list.push(map);
            }
        }
        Ok(())
    }

    fn process_element(
        &mut self,
        parent: &Element,
        monitor: &dyn TaskMonitor,
    ) -> Result<MachoPrelinkMap, MachoPrelinkError> {
        let mut map = MachoPrelinkMap::new();
        let mut iter = parent.children.iter();
        while let Some(element) = iter.next() {
            if monitor.is_cancelled() {
                break;
            }
            if element.name == TAG_KEY {
                if let Some(value_element) = iter.next() {
                    self.process_value(element, value_element, &mut map, monitor)?;
                }
            }
        }
        Ok(map)
    }

    fn process_value(
        &mut self,
        key_element: &Element,
        value_element: &Element,
        map: &mut MachoPrelinkMap,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, MachoPrelinkError> {
        let key = key_element.value();
        Ok(match value_element.name.as_str() {
            TAG_STRING => self.process_string(map, &key, value_element),
            TAG_INTEGER => self.process_integer(map, &key, value_element)?,
            TAG_TRUE => {
                map.put_bool(key, true);
                "true".to_string()
            }
            TAG_FALSE => {
                map.put_bool(key, false);
                "false".to_string()
            }
            TAG_DATA => {
                let v = value_element.value();
                map.put_string(key, v.clone());
                v
            }
            TAG_DICT => {
                let dict = self.process_element(value_element, monitor)?;
                let s = dict.to_string();
                map.put_map(key, dict);
                s
            }
            TAG_ARRAY => {
                let s = self.process_array(value_element, map, monitor)?;
                map.put_string(key, s.clone());
                s
            }
            other => {
                println!("Unhandled value type: {other}");
                value_element.value()
            }
        })
    }

    fn process_string(&mut self, map: &mut MachoPrelinkMap, key: &str, value_element: &Element) -> String {
        let value = value_element.value();
        if let Some(id) = value_element.attribute("ID") {
            self.id_to_strings.insert(id.to_string(), value.clone());
        }
        map.put_string(key, value.clone());
        if let Some(idref) = value_element.attribute("IDREF") {
            match self.id_to_strings.get(idref) {
                Some(s) => map.put_string(key, s.clone()),
                None => map.put_null(key),
            }
        }
        value
    }

    fn process_integer(
        &mut self,
        map: &mut MachoPrelinkMap,
        key: &str,
        value_element: &Element,
    ) -> Result<String, MachoPrelinkError> {
        let value = value_element.value();
        let numeric_value = NumericUtilities::parse_hex_long(&value).unwrap_or(-1);
        if let Some(id) = value_element.attribute("ID") {
            self.id_to_integers.insert(id.to_string(), numeric_value);
        }
        map.put_long(key, numeric_value);
        if let Some(idref) = value_element.attribute("IDREF") {
            let v = *self
                .id_to_integers
                .get(idref)
                .ok_or_else(|| MachoPrelinkError::MissingIntegerIdRef(idref.to_string()))?;
            map.put_long(key, v);
        }
        Ok(value)
    }

    /// Java: `processArray`. Each child is processed both as an element (result discarded) and
    /// as a value keyed by the array element's own text, exactly as Java does.
    fn process_array(
        &mut self,
        array: &Element,
        map: &mut MachoPrelinkMap,
        monitor: &dyn TaskMonitor,
    ) -> Result<String, MachoPrelinkError> {
        let mut buffer = String::new();
        let mut iter = array.children.iter().peekable();
        while let Some(child) = iter.next() {
            if monitor.is_cancelled() {
                break;
            }
            self.process_element(child, monitor)?;
            let value = self.process_value(array, child, map, monitor)?;
            buffer.push_str(&value);
            if iter.peek().is_some() {
                buffer.push(',');
            }
        }
        Ok(buffer)
    }

    /// Java: the private `findPrelinkInputStream()`: the (repaired) plist bytes of the last
    /// non-empty `__info` section in a `__PRELINK`/`__PRELINK_INFO` segment.
    fn find_prelink_input_stream(&self) -> Result<Vec<u8>, MachoPrelinkError> {
        let mut found = None;
        for segment in self.main_header.get_load_commands_of::<SegmentCommand>() {
            let name = segment.get_segment_name();
            if name != constants::K_PRELINK_SEGMENT_IOS_1X && name != constants::K_PRELINK_INFO_SEGMENT {
                continue;
            }
            let Some(section) = segment.get_section_by_name(constants::K_PRELINK_INFO_SECTION) else {
                continue;
            };
            if section.get_size() <= 0 {
                continue;
            }
            let bytes = self
                .provider
                .read_bytes(section.get_offset() as i64 as u64, (section.get_size() - 1) as u64)?;
            found = Some(repair_plist(&String::from_utf8_lossy(&bytes)).into_bytes());
        }
        found.ok_or_else(|| {
            MachoPrelinkError::NoPreLinkSection(NoPreLinkSectionException::new(
                "Unable to locate __info section in __PRELINK segment inside mach-o header for COMPLZSS file system.",
            ))
        })
    }
}

/// The work-arounds `findPrelinkInputStream` applies to the plist text: malformed endings found
/// in 3.0 and 4.2.x firmwares, and removal of the `<!DOCTYPE>`.
fn repair_plist(string: &str) -> String {
    let mut trimmed = java_trim(string).to_string();
    if trimmed.ends_with("</>Apple") {
        trimmed = format!("{}</array>", &trimmed[..trimmed.len() - 8]);
    }
    if trimmed.ends_with("</4.2</shoneOS<") {
        trimmed = format!("{}</array></dict>", &trimmed[..trimmed.len() - 15]);
    }
    if let Some(doctype) = trimmed.find("<!DOCTYPE") {
        if let Some(end) = trimmed[doctype..].find('>') {
            trimmed = format!("{}{}", &trimmed[..doctype], &trimmed[doctype + end + 1..]);
        }
    }
    trimmed
}

/// Java's `String.trim()`: strips leading/trailing characters `<= ' '` (including NULs, which
/// pad the end of the `__info` section).
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_SEGMENT_64;
    use crate::format::macho::cpu_types::CPU_TYPE_ARM_64;
    use crate::format::macho::mach_constants::MH_CIGAM_64;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::format::macho::section::test_support::section_bytes;
    use crate::util::task::DummyMonitor;

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>_PrelinkInfoDictionary</key><array>
 <dict>
  <key>_PrelinkBundlePath</key><string ID="1">/System/Library/Extensions/A.kext</string>
  <key>_PrelinkExecutableLoadAddr</key><integer size="64" ID="2">0xfffffff007004000</integer>
  <key>_PrelinkKmodInfo</key><integer size="64">0xfffffff0070a0000</integer>
  <key>OSBundleRequired</key><true/>
  <key>CFBundleIdentifier</key><string>com.apple.a</string>
 </dict>
 <dict>
  <key>_PrelinkBundlePath</key><string IDREF="1"/>
  <key>_PrelinkExecutableLoadAddr</key><integer IDREF="2"/>
  <key>ModuleIndex</key><integer>0x5</integer>
 </dict>
</array>
<key>_PrelinkPersonalities</key><array/>
</dict></plist>"#;

    /// A kernelcache-like image with the plist in `__PRELINK_INFO,__info`.
    fn image(plist: &str) -> Vec<u8> {
        let info_off = 0x200u32;
        let mut info = plist.as_bytes().to_vec();
        info.extend([0u8; 16]);
        let mut b = Bytes::new(true);
        b.u32(MH_CIGAM_64.swap_bytes()).u32(CPU_TYPE_ARM_64 as u32).u32(0).u32(2).u32(1);
        b.u32(72 + 80).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72 + 80).name("__PRELINK_INFO", 16).u64(0).u64(0).u64(info_off as u64);
        b.u64(info.len() as u64).u32(1).u32(1).u32(1).u32(0);
        b.raw(&section_bytes(false, true, "__info", "__PRELINK_INFO", 0, info.len() as u64, info_off, 0, 0, 0));
        b.pad_to(info_off as usize).raw(&info);
        b.buf
    }

    #[test]
    fn parses_info_dictionaries_with_id_refs() {
        let p = provider(image(PLIST));
        let mut h = MachHeader::new(Rc::clone(&p)).unwrap();
        h.parse().unwrap();
        let maps = MachoPrelinkParser::new(&h, p).parse(&DummyMonitor).unwrap();
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].get_prelink_bundle_path(), Some("/System/Library/Extensions/A.kext"));
        assert_eq!(maps[0].get_prelink_executable_load_addr() as u64, 0xffff_fff0_0700_4000);
        assert_eq!(maps[0].get_prelink_kmod_info() as u64, 0xffff_fff0_070a_0000);
        assert_eq!(maps[1].get_prelink_bundle_path(), Some("/System/Library/Extensions/A.kext"));
        assert_eq!(maps[1].get_prelink_executable_load_addr() as u64, 0xffff_fff0_0700_4000);
        assert_eq!(maps[1].get_prelink_module_index(), 5);
        assert_eq!(maps[1].get_prelink_kmod_info(), -1);
    }

    #[test]
    fn pre_4x_root_array() {
        let plist = "<array><dict><key>_PrelinkBundlePath</key><string>/x</string></dict>\
                     <string>ignored</string></array>";
        let p = provider(image(plist));
        let mut h = MachHeader::new(Rc::clone(&p)).unwrap();
        h.parse().unwrap();
        let maps = MachoPrelinkParser::new(&h, p).parse(&DummyMonitor).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].get_prelink_bundle_path(), Some("/x"));
    }

    #[test]
    fn missing_info_section_is_reported() {
        let bytes = MachHeader::create(
            crate::format::macho::mach_constants::MH_MAGIC_64, CPU_TYPE_ARM_64, 0, 2, 0, 0, 0, 0,
        )
        .unwrap();
        let p = provider(bytes);
        let mut h = MachHeader::new(Rc::clone(&p)).unwrap();
        h.parse().unwrap();
        let err = MachoPrelinkParser::new(&h, p).parse(&DummyMonitor).unwrap_err();
        assert!(matches!(err, MachoPrelinkError::NoPreLinkSection(_)));
    }

    #[test]
    fn repairs_malformed_firmware_endings() {
        assert_eq!(repair_plist("<array>x</>Apple\0\0"), "<array>x</array>");
        assert_eq!(repair_plist("<dict><array>x</4.2</shoneOS<"), "<dict><array>x</array></dict>");
        assert_eq!(repair_plist("<?xml?><!DOCTYPE plist x><a/>"), "<?xml?><a/>");
    }
}
