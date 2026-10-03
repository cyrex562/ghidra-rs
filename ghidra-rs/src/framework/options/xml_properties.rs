//! Port of `ghidra.framework.options.XmlProperties`.

use std::io;
use std::path::Path;

use crate::framework::options::g_properties::GProperties;
use crate::util::xml::element::Element;

/// `XmlProperties.getXmlElement(File)`: the root element of the XML file.
pub(crate) fn read_xml_file(file: &Path) -> io::Result<Element> {
    let bytes = std::fs::read(file)?;
    Element::parse_bytes(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Port of `ghidra.framework.options.XmlProperties`: a [`GProperties`] read from a file written
/// by [`GProperties::save_to_xml_file`].
pub struct XmlProperties;

impl XmlProperties {
    /// `new XmlProperties(File)`.
    pub fn from_file(file: &Path) -> io::Result<GProperties> {
        Ok(GProperties::from_xml(&read_xml_file(file)?))
    }
}
