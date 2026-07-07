use std::io::{self, Write};

use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// An empty slot in the open-addressed hash table.
const EMPTY: i32 = -1;

/// A single hash/count entry in the [`IdfLookup`] hash table.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdfEntry {
    pub hash: i32,
    pub count: i32,
}

/// Open-addressed hash table mapping a feature hash to its inverse document
/// frequency (IDF) count.
///
/// Port of `generic.lsh.vector.IDFLookup`.
#[derive(Default)]
pub struct IdfLookup {
    /// Number of entries in the table, as given at construction time (via [`Self::set`] /
    /// [`Self::restore_xml`]).
    size: usize,
    mask: i32,
    hashtable: Vec<IdfEntry>,
}

impl IdfLookup {
    /// Creates a new, empty `IdfLookup`.
    pub fn new() -> Self {
        Self { size: 0, mask: 0, hashtable: Vec::new() }
    }

    fn initialize_table(&mut self) {
        let mut mask: i64 = 1;
        while (mask as usize) < self.size {
            mask <<= 1;
        }
        mask <<= 1;

        self.hashtable = vec![IdfEntry { hash: 0, count: EMPTY }; mask as usize];
        self.mask = (mask - 1) as i32;
    }

    /// Returns `true` if the table has not been initialized (holds no entries).
    pub fn empty(&self) -> bool {
        self.hashtable.is_empty()
    }

    /// Returns the count associated with the given hash, or `0` if not present.
    pub fn get_count(&self, hash: i32) -> i32 {
        if self.mask == 0 {
            return 0;
        }
        let mut val = (hash & self.mask) as usize;
        let mut entry = &self.hashtable[val];
        while entry.count != EMPTY {
            if entry.hash == hash {
                return entry.count;
            }
            val = ((val as i32 + 1) & self.mask) as usize;
            entry = &self.hashtable[val];
        }
        0
    }

    /// Returns the capacity of the hash table (one less than a power of two).
    pub fn get_capacity(&self) -> i32 {
        self.mask
    }

    /// Returns the raw hash stored at the given slot.
    pub fn get_raw_hash(&self, pos: usize) -> i32 {
        self.hashtable[pos].hash
    }

    /// Returns the raw count stored at the given slot.
    pub fn get_raw_count(&self, pos: usize) -> i32 {
        self.hashtable[pos].count
    }

    fn insert_hash(&mut self, hash: i32, count: i32) {
        let mut val = (hash & self.mask) as usize;
        loop {
            if self.hashtable[val].count == EMPTY {
                break;
            }
            val = ((val as i32 + 1) & self.mask) as usize;
        }
        self.hashtable[val] = IdfEntry { hash, count };
    }

    /// Serializes this object as XML to a `Writer`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        if self.empty() {
            write!(fwrite, "<idflookup/>\n")?;
            return Ok(());
        }

        let mut buf = String::new();
        buf.push_str("<idflookup");
        spec_xml_utils::encode_signed_integer_attribute(&mut buf, "size", self.size as i64);
        buf.push_str(">\n");
        let sz = (self.mask + 1) as usize;
        for entry in &self.hashtable[..sz] {
            if entry.count == EMPTY {
                continue;
            }
            buf.push_str("<hash");
            spec_xml_utils::encode_signed_integer_attribute(&mut buf, "count", entry.count as i64);
            buf.push('>');
            buf.push_str(&spec_xml_utils::encode_unsigned_integer(entry.hash as i64));
            buf.push_str("</hash>\n");
        }
        buf.push_str("</idflookup>\n");
        write!(fwrite, "{}", buf)
    }

    /// Builds (deserializes) this object from an XML stream.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<(), crate::util::xml::xml_exception::XmlException> {
        let el = parser.start(&["idflookup"])?;
        let Some(size_attr) = el.get_attribute("size") else {
            return Ok(()); // Empty table
        };
        self.size = spec_xml_utils::decode_int(Some(&size_attr)) as usize;
        self.initialize_table();
        while parser.peek().is_start() {
            let subel = parser.start(&["hash"])?;
            let count = spec_xml_utils::decode_int(subel.get_attribute("count").as_deref());
            let hash = spec_xml_utils::decode_int(Some(parser.end()?.get_text()));
            self.insert_hash(hash, count);
        }

        parser.end_matching(&el)?;
        Ok(())
    }

    /// Collapses this `IdfLookup` into an array of hash/count pairs, suitable for storage.
    pub fn to_array(&self) -> Vec<i32> {
        let count = self.hashtable.iter().filter(|e| e.count != EMPTY).count();
        let mut res = Vec::with_capacity(count * 2);
        for entry in &self.hashtable {
            if entry.count == EMPTY {
                continue;
            }
            res.push(entry.hash);
            res.push(entry.count);
        }
        res
    }

    /// Sets this table from an array of hash/count pairs. Every even index is a hash, every
    /// odd index is a count.
    pub fn set(&mut self, hash_count_pair: &[i32]) {
        self.size = hash_count_pair.len() / 2;
        self.initialize_table();
        for pair in hash_count_pair.chunks_exact(2) {
            self.insert_hash(pair[0], pair[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use crate::util::xml::xml_exception::XmlException;

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl VecParser {
        fn new(elements: Vec<XmlElementImpl>) -> Self {
            Self { elements, pos: 0 }
        }
    }

    impl XmlPullParser for VecParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "vec"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn get_line_number(&self) -> i32 {
            0
        }

        fn get_column_number(&self) -> i32 {
            0
        }

        fn is_pulling_content(&self) -> bool {
            false
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn get_current_level(&self) -> i32 {
            0
        }

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> XmlElementImpl {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> XmlElementImpl {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }

        fn start(&mut self, names: &[&str]) -> Result<XmlElementImpl, XmlException> {
            let elem = self.next();
            if !elem.is_start() {
                return Err(XmlException::with_message("expected start element"));
            }
            if !names.is_empty() && !names.iter().any(|n| *n == elem.get_name()) {
                return Err(XmlException::with_message("unexpected start element name"));
            }
            Ok(elem)
        }

        fn end(&mut self) -> Result<XmlElementImpl, XmlException> {
            let elem = self.next();
            if !elem.is_end() {
                return Err(XmlException::with_message("expected end element"));
            }
            Ok(elem)
        }

        fn end_matching(&mut self, element: &XmlElementImpl) -> Result<XmlElementImpl, XmlException> {
            let elem = self.end()?;
            if elem.get_name() != element.get_name() {
                return Err(XmlException::with_message("mismatched end element"));
            }
            Ok(elem)
        }

        fn soft_start(&mut self, names: &[&str]) -> Option<XmlElementImpl> {
            if !self.has_next() {
                return None;
            }
            let elem = self.peek();
            if !elem.is_start() {
                return None;
            }
            if !names.is_empty() && !names.iter().any(|n| *n == elem.get_name()) {
                return None;
            }
            Some(self.next())
        }

        fn discard_sub_tree(&mut self) -> i32 {
            0
        }

        fn discard_sub_tree_named(&mut self, _name: &str) -> Result<i32, XmlException> {
            Ok(0)
        }

        fn discard_sub_tree_element(&mut self, _element: &XmlElementImpl) -> i32 {
            0
        }

        fn dispose(&mut self) {}
    }

    #[test]
    fn new_table_is_empty() {
        let lookup = IdfLookup::new();
        assert!(lookup.empty());
        assert_eq!(lookup.get_count(42), 0);
        assert_eq!(lookup.get_capacity(), 0);
    }

    #[test]
    fn set_and_get_count_round_trips() {
        let mut lookup = IdfLookup::new();
        lookup.set(&[10, 100, 20, 200, 30, 300]);
        assert!(!lookup.empty());
        assert_eq!(lookup.get_count(10), 100);
        assert_eq!(lookup.get_count(20), 200);
        assert_eq!(lookup.get_count(30), 300);
        assert_eq!(lookup.get_count(999), 0);
    }

    #[test]
    fn to_array_then_set_round_trips() {
        let mut lookup = IdfLookup::new();
        lookup.set(&[1, 11, 2, 22, 3, 33, 4, 44]);
        let array = lookup.to_array();
        assert_eq!(array.len(), 8);

        let mut restored = IdfLookup::new();
        restored.set(&array);
        for pair in array.chunks_exact(2) {
            assert_eq!(restored.get_count(pair[0]), pair[1]);
        }
    }

    #[test]
    fn handles_hash_collisions_via_linear_probing() {
        // With size 3, initialize_table finds mask = 7 (capacity 8).
        // Choose two hashes that collide modulo 8.
        let mut lookup = IdfLookup::new();
        lookup.set(&[1, 111, 9, 999, 17, 1717]);
        assert_eq!(lookup.get_capacity(), 7);
        assert_eq!(lookup.get_count(1), 111);
        assert_eq!(lookup.get_count(9), 999);
        assert_eq!(lookup.get_count(17), 1717);
    }

    #[test]
    fn save_xml_empty_table() {
        let lookup = IdfLookup::new();
        let mut buf = Vec::new();
        lookup.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<idflookup/>\n");
    }

    #[test]
    fn save_xml_nonempty_table_contains_entries() {
        let mut lookup = IdfLookup::new();
        lookup.set(&[5, 50]);
        let mut buf = Vec::new();
        lookup.save_xml(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("<idflookup size=\"1\">\n"));
        assert!(text.contains("<hash count=\"50\">0x5</hash>"));
        assert!(text.ends_with("</idflookup>\n"));
    }

    #[test]
    fn restore_xml_empty_table_without_size_attribute() {
        let elements = vec![
            XmlElementImpl::new(true, false, "idflookup", 0, Vec::new(), None, 0, 0).unwrap(),
            XmlElementImpl::new(false, true, "idflookup", 0, Vec::new(), Some(String::new()), 0, 0)
                .unwrap(),
        ];
        let mut parser = VecParser::new(elements);
        let mut lookup = IdfLookup::new();
        lookup.restore_xml(&mut parser).unwrap();
        assert!(lookup.empty());
    }

    #[test]
    fn restore_xml_round_trips_saved_table() {
        let mut original = IdfLookup::new();
        original.set(&[7, 70, 8, 80]);
        let mut buf = Vec::new();
        original.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();

        let elements = parse_simple_xml(&xml);
        let mut parser = VecParser::new(elements);
        let mut restored = IdfLookup::new();
        restored.restore_xml(&mut parser).unwrap();

        assert_eq!(restored.get_count(7), 70);
        assert_eq!(restored.get_count(8), 80);
    }

    /// Minimal hand-rolled parser for the small, well-formed XML this module emits;
    /// only used to build fixtures for `restore_xml` tests.
    fn parse_simple_xml(xml: &str) -> Vec<XmlElementImpl> {
        let mut elements = Vec::new();
        for line in xml.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("<idflookup") {
                let rest = rest.trim_end_matches('>');
                let mut attrs = Vec::new();
                if let Some(size_pos) = rest.find("size=\"") {
                    let after = &rest[size_pos + 6..];
                    let end = after.find('"').unwrap();
                    attrs.push(("size".to_string(), after[..end].to_string()));
                }
                elements.push(
                    XmlElementImpl::new(true, false, "idflookup", 0, attrs, None, 0, 0).unwrap(),
                );
            } else if line.starts_with("<hash") {
                let count_pos = line.find("count=\"").unwrap();
                let after = &line[count_pos + 7..];
                let end = after.find('"').unwrap();
                let count = after[..end].to_string();
                let gt = line.find('>').unwrap();
                let close = line.find("</hash>").unwrap();
                let text = line[gt + 1..close].to_string();
                elements.push(
                    XmlElementImpl::new(
                        true,
                        false,
                        "hash",
                        1,
                        vec![("count".to_string(), count)],
                        None,
                        0,
                        0,
                    )
                    .unwrap(),
                );
                elements.push(
                    XmlElementImpl::new(false, true, "hash", 1, Vec::new(), Some(text), 0, 0)
                        .unwrap(),
                );
            } else if line == "</idflookup>" {
                elements.push(
                    XmlElementImpl::new(
                        false,
                        true,
                        "idflookup",
                        0,
                        Vec::new(),
                        Some(String::new()),
                        0,
                        0,
                    )
                    .unwrap(),
                );
            }
        }
        elements
    }
}
