use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::sync::Arc;

use crate::feature::bsim::query::LshException;
use crate::feature::bsim::query::description::{DescriptionManager, RowKey};
use crate::feature::seam_stubs::{CallgraphEntry, ExecutableRecord, SignatureRecord};
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A function within an executable, as described by a BSim database.
///
/// Port of `ghidra.features.bsim.query.description.FunctionDescription`.
///
/// A description is identified by its executable, its name (unique within that executable) and
/// its address; those three fields are immutable and are exactly what equality, ordering and
/// hashing are computed from. The executable record is shared with every other function of the
/// same executable, so it is held by [`Arc`]; likewise a signature is shared by all the
/// functions that hash to it (which is what `SignatureRecord::get_count` counts).
///
/// Divergence: Java stores the table id as a `RowKey` object. The ported [`RowKey`] trait
/// requires `Ord`, so it is not object safe and cannot be stored as `dyn RowKey`; since
/// `RowKey::get_long` is the whole of its ported surface and every caller immediately reduces
/// the key to that long, the id is stored here as an [`i64`]. [`set_id`](Self::set_id) takes
/// any `RowKey` implementation.
#[derive(Debug, Clone)]
pub struct FunctionDescription {
    exerec: Arc<ExecutableRecord>,
    /// Name of the function (unique within the executable).
    function_name: String,
    /// Address offset of this function within its executable, or `-1` for a library function.
    address: i64,
    sigrec: Option<Arc<SignatureRecord>>,
    /// Java models "no callgraph" as a null list; an empty vector is equivalent here.
    callrec: Vec<CallgraphEntry>,
    /// Table id of this description, if it has been stored.
    id: Option<i64>,
    /// Vector id of the signature associated with this function.
    vectorid: i64,
    /// 1-bit attributes of the function.
    flags: i32,
}

/// The fields of a [`FunctionDescription`] that need to be written back to the database.
///
/// Port of the Java nested class `FunctionDescription.Update`. `update` borrows the (already
/// reconciled) description the record refers to, matching the Java field that points at the
/// live object.
#[derive(Debug, Default, Clone, Copy)]
pub struct Update<'a> {
    pub update: Option<&'a FunctionDescription>,
    /// Do we update the function name?
    pub function_name: bool,
    /// Do we update the flags?
    pub flags: bool,
}

impl FunctionDescription {
    /// Java: `FunctionDescription(ExecutableRecord ex, String name, long addr)`.
    pub fn new(ex: Arc<ExecutableRecord>, name: impl Into<String>, addr: i64) -> Self {
        Self {
            exerec: ex,
            function_name: name.into(),
            address: addr,
            sigrec: None,
            callrec: Vec::new(),
            id: None,
            vectorid: 0,
            flags: 0,
        }
    }

    /// Java: package-private `setId(RowKey)`.
    pub(crate) fn set_id(&mut self, id: &impl RowKey) {
        self.id = Some(id.get_long());
    }

    /// Java: package-private `setVectorId(long)`.
    pub(crate) fn set_vector_id(&mut self, i: i64) {
        self.vectorid = i;
    }

    /// Java: package-private `setFlags(int)`.
    pub(crate) fn set_flags(&mut self, fl: i32) {
        self.flags = fl;
    }

    /// Java: package-private `insertCall(FunctionDescription fd, int lhash)`.
    pub(crate) fn insert_call(&mut self, fd: Arc<FunctionDescription>, lhash: i32) {
        self.callrec.push(CallgraphEntry::new(fd, lhash));
    }

    pub fn set_signature_record(&mut self, srec: Arc<SignatureRecord>) {
        self.sigrec = Some(srec);
    }

    pub fn get_function_name(&self) -> &str {
        &self.function_name
    }

    /// The executable this function belongs to. Returned as the [`Arc`] itself so callers can
    /// compare identity, as the Java does with `!=` on the record.
    pub fn get_executable_record(&self) -> &Arc<ExecutableRecord> {
        &self.exerec
    }

    pub fn get_signature_record(&self) -> Option<&Arc<SignatureRecord>> {
        self.sigrec.as_ref()
    }

    /// Java: `getCallgraphRecord()`, which returns null when no call has been inserted; the
    /// empty slice plays that role here.
    pub fn get_callgraph_record(&self) -> &[CallgraphEntry] {
        &self.callrec
    }

    /// The table id of this description, or `None` if it has not been stored.
    ///
    /// Java returns the `RowKey` itself; see the type-level note on why this is the key's long.
    pub fn get_id(&self) -> Option<i64> {
        self.id
    }

    pub fn get_vector_id(&self) -> i64 {
        self.vectorid
    }

    pub fn get_address(&self) -> i64 {
        self.address
    }

    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Java: `sortCallgraph()`. Sorts the call records and removes duplicate calls to the same
    /// function; as in Java, duplicates are recognised by *identity* of the callee, not by its
    /// value.
    pub fn sort_callgraph(&mut self) {
        if self.callrec.len() < 2 {
            return; // Nothing to do
        }
        self.callrec.sort();
        self.callrec.dedup_by(|a, b| {
            Arc::ptr_eq(a.get_function_description(), b.get_function_description())
        });
    }

    /// Java: `printRaw()`.
    pub fn print_raw(&self) -> String {
        format!("{} {}", self.function_name, self.exerec.print_raw())
    }

    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<fdesc name=\"")?;
        spec_xml_utils::xml_escape_writer(fwrite, &self.function_name)?;
        if self.address != -1 {
            write!(fwrite, "\" addr=\"0x{:x}", self.address as u64)?;
        }
        if let Some(sigrec) = &self.sigrec {
            if sigrec.get_count() > 0 {
                write!(
                    fwrite,
                    "\" sigdup=\"{}",
                    spec_xml_utils::encode_unsigned_integer(sigrec.get_count() as i64)
                )?;
            }
        }
        write!(fwrite, "\">\n")?;
        if let Some(sigrec) = &self.sigrec {
            sigrec.save_xml(fwrite)?;
        }
        for element in &self.callrec {
            element.save_xml(self, fwrite)?;
        }
        if self.flags != 0 {
            write!(
                fwrite,
                "<flags>{}</flags>\n",
                spec_xml_utils::encode_unsigned_integer(self.flags as i64)
            )?;
        }
        write!(fwrite, "</fdesc>\n")
    }

    /// Update the boolean fields in `res` to true, for every field in `self` that needs to be
    /// updated from `from_db`.
    ///
    /// Java: `diffForUpdate(Update res, FunctionDescription fromDB)`. As in Java this also
    /// reconciles `self` with the database record: bits 1 and 2 of the database flags are kept,
    /// and the database's table id is adopted.
    ///
    /// Returns true if one or more updates is necessary.
    pub fn diff_for_update<'a>(
        &'a mut self,
        res: &mut Update<'a>,
        from_db: &FunctionDescription,
    ) -> bool {
        let name_differs = self.function_name != from_db.function_name;
        // keep bits 1 and 2 of database flags
        self.flags = (0xffff_fff9_u32 as i32 & self.flags) | (from_db.flags & 6);
        let flags_differ = self.flags != from_db.flags;
        self.id = from_db.id;
        res.function_name = name_differs;
        res.flags = flags_differ;
        res.update = Some(self);
        name_differs || flags_differ
    }

    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory, DescriptionManager, ExecutableRecord)`.
    ///
    /// Crate-visible (rather than `pub`) to match [`CategoryRecord::restore_xml`], since the
    /// [`XmlPullParser`] seam it parses from is itself crate-visible.
    ///
    /// [`CategoryRecord::restore_xml`]: super::CategoryRecord
    pub(crate) fn restore_xml<P: XmlPullParser>(
        parser: &mut P,
        vector_factory: &LSHVectorFactory,
        man: &mut DescriptionManager,
        erec: Arc<ExecutableRecord>,
    ) -> Result<FunctionDescription, LshException> {
        let el = parser.start(&["fdesc"]).map_err(|e| LshException::new(e.to_string()))?;
        let fname = el.get_attribute("name").unwrap_or_default();
        // Default value if no attribute present
        let address = match el.get_attribute("addr") {
            Some(addr_string) => spec_xml_utils::decode_long(Some(&addr_string)),
            None => -1,
        };
        let count = spec_xml_utils::decode_int(el.get_attribute("sigdup").as_deref());

        let mut fdesc = man.new_function_description(&fname, address, erec);
        if parser.peek().is_start() {
            if parser.peek().get_name() == "lshcosine" {
                SignatureRecord::restore_xml(parser, vector_factory, man, &mut fdesc, count)?;
            }
            while parser.peek().is_start() {
                if parser.peek().get_name() == "flags" {
                    parser.start(&[]).map_err(|e| LshException::new(e.to_string()))?;
                    let text = parser
                        .end()
                        .map_err(|e| LshException::new(e.to_string()))?
                        .get_text()
                        .to_string();
                    fdesc.flags = spec_xml_utils::decode_int(Some(&text));
                } else {
                    // Assume it is a callgraph entry
                    CallgraphEntry::restore_xml(parser, man, &mut fdesc)?;
                }
            }
        }
        parser.end().map_err(|e| LshException::new(e.to_string()))?;
        Ok(fdesc)
    }

    /// Create a map from addresses to functions. Library functions (address `-1`) are skipped.
    ///
    /// Java: `createAddressToFunctionMap(Iterator<FunctionDescription>)`.
    pub fn create_address_to_function_map<'a, I>(funcs: I) -> BTreeMap<i64, &'a FunctionDescription>
    where
        I: IntoIterator<Item = &'a FunctionDescription>,
    {
        let mut addrmap = BTreeMap::new();
        for func in funcs {
            let addr = func.get_address();
            if addr == -1 {
                continue;
            }
            addrmap.insert(addr, func);
        }
        addrmap
    }

    /// Match new functions to old functions via the address, test if there is an update between
    /// the two functions, generate an update record if there is, return the list of updates.
    ///
    /// Java: `generateUpdates(Iterator, Map, List)`. `funcs` are the NEW functions (reconciled
    /// in place against the old ones), `addr_map` maps address to OLD function, and
    /// `bad_list` collects the new functions that could not be mapped to an old one.
    pub fn generate_updates<'a, I>(
        funcs: I,
        addr_map: &BTreeMap<i64, &FunctionDescription>,
        bad_list: &mut Vec<&'a FunctionDescription>,
    ) -> Vec<Update<'a>>
    where
        I: IntoIterator<Item = &'a mut FunctionDescription>,
    {
        let mut update_list = Vec::new();
        for newfunc in funcs {
            let addr = newfunc.get_address();
            if addr == -1 {
                continue;
            }
            let Some(oldfunc) = addr_map.get(&addr).copied() else {
                // Keep track of functions with update info which we couldn't find
                bad_list.push(newfunc);
                continue;
            };
            let mut curupdate = Update::default();
            // Check if there is any change in metadata
            if newfunc.diff_for_update(&mut curupdate, oldfunc) {
                update_list.push(curupdate);
            }
        }
        update_list
    }
}

impl PartialEq for FunctionDescription {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for FunctionDescription {}

impl Hash for FunctionDescription {
    /// Consistent with [`PartialEq`]: only the executable, name and address take part.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.exerec.hash(state);
        self.function_name.hash(state);
        self.address.hash(state);
    }
}

impl PartialOrd for FunctionDescription {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionDescription {
    /// Java: `compareTo`, which orders by executable, then function name, then address compared
    /// as *unsigned* (so a library function's `-1` sorts last).
    fn cmp(&self, other: &Self) -> Ordering {
        self.exerec
            .cmp(&other.exerec)
            .then_with(|| self.function_name.cmp(&other.function_name))
            .then_with(|| (self.address as u64).cmp(&(other.address as u64)))
    }
}

impl fmt::Display for FunctionDescription {
    /// Java: `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FunctionDescription {} ({})", self.function_name, self.exerec.get_name_exec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::client::row_key_sql::RowKeySQL;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use crate::util::xml::xml_exception::XmlException;
    use std::collections::hash_map::DefaultHasher;

    fn exe(md5: &str) -> Arc<ExecutableRecord> {
        Arc::new(ExecutableRecord::new(md5, "a.exe", "x86:LE:32:default", "gcc"))
    }

    fn func(exerec: &Arc<ExecutableRecord>, name: &str, addr: i64) -> FunctionDescription {
        FunctionDescription::new(Arc::clone(exerec), name, addr)
    }

    fn hash_of(fd: &FunctionDescription) -> u64 {
        let mut hasher = DefaultHasher::new();
        fd.hash(&mut hasher);
        hasher.finish()
    }

    fn xml(fd: &FunctionDescription) -> String {
        let mut buf = Vec::new();
        fd.save_xml(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // --- construction / accessors ---

    #[test]
    fn test_new_matches_java_defaults() {
        let fd = func(&exe("aa"), "main", 0x1000);
        assert_eq!(fd.get_function_name(), "main");
        assert_eq!(fd.get_address(), 0x1000);
        assert_eq!(fd.get_flags(), 0);
        assert_eq!(fd.get_vector_id(), 0);
        assert_eq!(fd.get_id(), None);
        assert!(fd.get_signature_record().is_none());
        assert!(fd.get_callgraph_record().is_empty());
        assert_eq!(fd.get_executable_record().get_name_exec(), "a.exe");
    }

    #[test]
    fn test_setters() {
        let mut fd = func(&exe("aa"), "main", 0x1000);
        fd.set_id(&RowKeySQL::new(77));
        fd.set_vector_id(1234);
        fd.set_flags(6);
        fd.set_signature_record(Arc::new(SignatureRecord::new(3)));
        assert_eq!(fd.get_id(), Some(77));
        assert_eq!(fd.get_vector_id(), 1234);
        assert_eq!(fd.get_flags(), 6);
        assert_eq!(fd.get_signature_record().unwrap().get_count(), 3);
    }

    #[test]
    fn test_to_string_matches_java() {
        let fd = func(&exe("aa"), "main", 0x1000);
        assert_eq!(fd.to_string(), "FunctionDescription main (a.exe)");
    }

    #[test]
    fn test_print_raw_matches_java() {
        let fd = func(&exe("abc123"), "main", 0x1000);
        assert_eq!(fd.print_raw(), "main abc123 a.exe x86:LE:32:default gcc");
    }

    // --- ordering / equality / hashing ---

    #[test]
    fn test_compare_executable_dominates() {
        let a = func(&exe("aaa"), "zzz", 0x2000);
        let b = func(&exe("bbb"), "aaa", 0x1000);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_ne!(a, b);
    }

    #[test]
    fn test_compare_name_when_same_executable() {
        let e = exe("aaa");
        let a = func(&e, "alpha", 0x2000);
        let b = func(&e, "beta", 0x1000);
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn test_compare_address_is_unsigned() {
        let e = exe("aaa");
        let a = func(&e, "f", 1);
        // -1 is a library function; Long.compareUnsigned puts it after every real address.
        let b = func(&e, "f", -1);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn test_equal_ignores_mutable_state() {
        let e = exe("aaa");
        let a = func(&e, "f", 0x10);
        let mut b = func(&e, "f", 0x10);
        b.set_flags(3);
        b.set_vector_id(9);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn test_equal_across_distinct_records_with_same_md5() {
        let a = func(&exe("aaa"), "f", 0x10);
        let b = func(&exe("aaa"), "f", 0x10);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn test_not_equal_on_address() {
        let e = exe("aaa");
        assert_ne!(func(&e, "f", 0x10), func(&e, "f", 0x11));
    }

    // --- callgraph ---

    #[test]
    fn test_sort_callgraph_sorts_and_dedups_by_identity() {
        let e = exe("aaa");
        let alpha = Arc::new(func(&e, "alpha", 0x10));
        let beta = Arc::new(func(&e, "beta", 0x20));
        let mut caller = func(&e, "caller", 0x100);
        caller.insert_call(Arc::clone(&beta), 1);
        caller.insert_call(Arc::clone(&alpha), 2);
        caller.insert_call(Arc::clone(&beta), 3);
        caller.sort_callgraph();

        let names: Vec<&str> = caller
            .get_callgraph_record()
            .iter()
            .map(|c| c.get_function_description().get_function_name())
            .collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        // The surviving beta entry is the first of the sorted run, i.e. local hash 1.
        assert_eq!(caller.get_callgraph_record()[1].get_local_hash(), 1);
    }

    #[test]
    fn test_sort_callgraph_keeps_distinct_objects_that_compare_equal() {
        let e = exe("aaa");
        // Java dedups on pointer identity, so two equal-but-distinct callees both survive.
        let one = Arc::new(func(&e, "callee", 0x10));
        let two = Arc::new(func(&e, "callee", 0x10));
        assert_eq!(*one, *two);
        let mut caller = func(&e, "caller", 0x100);
        caller.insert_call(one, 1);
        caller.insert_call(two, 2);
        caller.sort_callgraph();
        assert_eq!(caller.get_callgraph_record().len(), 2);
    }

    #[test]
    fn test_sort_callgraph_noop_for_short_lists() {
        let e = exe("aaa");
        let mut caller = func(&e, "caller", 0x100);
        caller.sort_callgraph();
        assert!(caller.get_callgraph_record().is_empty());
        caller.insert_call(Arc::new(func(&e, "callee", 0x10)), 7);
        caller.sort_callgraph();
        assert_eq!(caller.get_callgraph_record().len(), 1);
    }

    // --- save_xml ---

    #[test]
    fn test_save_xml_minimal() {
        let fd = func(&exe("aaa"), "main", 0x1000);
        assert_eq!(xml(&fd), "<fdesc name=\"main\" addr=\"0x1000\">\n</fdesc>\n");
    }

    #[test]
    fn test_save_xml_library_function_omits_address() {
        let fd = func(&exe("aaa"), "printf", -1);
        assert_eq!(xml(&fd), "<fdesc name=\"printf\">\n</fdesc>\n");
    }

    #[test]
    fn test_save_xml_escapes_name() {
        let fd = func(&exe("aaa"), "op<&>", 0x20);
        assert_eq!(xml(&fd), "<fdesc name=\"op&lt;&amp;&gt;\" addr=\"0x20\">\n</fdesc>\n");
    }

    #[test]
    fn test_save_xml_writes_sigdup_only_when_count_positive() {
        let mut fd = func(&exe("aaa"), "main", 0x1000);
        fd.set_signature_record(Arc::new(SignatureRecord::new(0)));
        assert_eq!(xml(&fd), "<fdesc name=\"main\" addr=\"0x1000\">\n</fdesc>\n");
        fd.set_signature_record(Arc::new(SignatureRecord::new(18)));
        assert_eq!(
            xml(&fd),
            "<fdesc name=\"main\" addr=\"0x1000\" sigdup=\"0x12\">\n</fdesc>\n"
        );
    }

    #[test]
    fn test_save_xml_writes_flags_element() {
        let mut fd = func(&exe("aaa"), "main", 0x1000);
        fd.set_flags(6);
        assert_eq!(
            xml(&fd),
            "<fdesc name=\"main\" addr=\"0x1000\">\n<flags>0x6</flags>\n</fdesc>\n"
        );
    }

    #[test]
    fn test_save_xml_writes_intra_executable_call() {
        let e = exe("aaa");
        let callee = Arc::new(func(&e, "callee", 0x20));
        let mut caller = func(&e, "caller", 0x10);
        caller.insert_call(callee, 5);
        assert_eq!(
            xml(&caller),
            "<fdesc name=\"caller\" addr=\"0x10\">\n<call dest=\"callee\" addr=\"0x20\" local=\"0x5\"/>\n</fdesc>\n"
        );
    }

    // --- diff_for_update / generate_updates ---

    #[test]
    fn test_diff_for_update_reports_name_change_and_adopts_db_id() {
        let e = exe("aaa");
        let mut newfunc = func(&e, "FUN_1000", 0x1000);
        let mut oldfunc = func(&e, "main", 0x1000);
        oldfunc.set_id(&RowKeySQL::new(42));

        let mut res = Update::default();
        assert!(newfunc.diff_for_update(&mut res, &oldfunc));
        assert!(res.function_name);
        assert!(!res.flags);
        assert_eq!(res.update.unwrap().get_function_name(), "FUN_1000");
        assert_eq!(res.update.unwrap().get_id(), Some(42));
    }

    #[test]
    fn test_diff_for_update_keeps_database_bits_1_and_2() {
        let e = exe("aaa");
        // 0b110: bit 0 is clear, bits 1 and 2 are ours to lose.
        let mut newfunc = func(&e, "main", 0x1000);
        newfunc.set_flags(6);
        let mut oldfunc = func(&e, "main", 0x1000);
        oldfunc.set_flags(4);

        let mut res = Update::default();
        // (0xfffffff9 & 6) | (4 & 6) == 0 | 4 == 4, which now matches the database.
        assert!(!newfunc.diff_for_update(&mut res, &oldfunc));
        assert!(!res.function_name);
        assert!(!res.flags);
        assert_eq!(newfunc.get_flags(), 4);
    }

    #[test]
    fn test_diff_for_update_reports_flag_change_outside_database_bits() {
        let e = exe("aaa");
        let mut newfunc = func(&e, "main", 0x1000);
        newfunc.set_flags(1); // bit 0 is not a database bit, so it survives the mask
        let mut oldfunc = func(&e, "main", 0x1000);
        oldfunc.set_flags(2);

        let mut res = Update::default();
        // (0xfffffff9 & 1) | (2 & 6) == 1 | 2 == 3 != 2
        assert!(newfunc.diff_for_update(&mut res, &oldfunc));
        assert!(!res.function_name);
        assert!(res.flags);
        assert_eq!(newfunc.get_flags(), 3);
    }

    #[test]
    fn test_create_address_to_function_map_skips_library_functions() {
        let e = exe("aaa");
        let funcs = vec![func(&e, "b", 0x20), func(&e, "lib", -1), func(&e, "a", 0x10)];
        let map = FunctionDescription::create_address_to_function_map(funcs.iter());
        assert_eq!(map.len(), 2);
        let names: Vec<&str> = map.values().map(|f| f.get_function_name()).collect();
        // TreeMap ordering: ascending address.
        assert_eq!(names, vec!["a", "b"]);
        assert!(map.get(&-1).is_none());
    }

    #[test]
    fn test_generate_updates_splits_updates_from_unmatched() {
        let e = exe("aaa");
        let mut old_matched = func(&e, "main", 0x10);
        old_matched.set_id(&RowKeySQL::new(5));
        let old_unchanged = func(&e, "helper", 0x20);
        let olds = vec![old_matched, old_unchanged];
        let addr_map = FunctionDescription::create_address_to_function_map(olds.iter());

        let mut news = vec![
            func(&e, "FUN_0010", 0x10), // renamed -> update
            func(&e, "helper", 0x20),   // identical -> no update
            func(&e, "brand_new", 0x30), // no old counterpart -> bad list
            func(&e, "lib", -1),        // library function -> skipped entirely
        ];
        let mut bad_list = Vec::new();
        let updates =
            FunctionDescription::generate_updates(news.iter_mut(), &addr_map, &mut bad_list);

        assert_eq!(updates.len(), 1);
        let rec = updates[0].update.unwrap();
        assert_eq!(rec.get_function_name(), "FUN_0010");
        assert_eq!(rec.get_id(), Some(5));
        assert!(updates[0].function_name);
        assert_eq!(bad_list.len(), 1);
        assert_eq!(bad_list[0].get_function_name(), "brand_new");
    }

    // --- restore_xml ---

    struct VecParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl XmlPullParser for VecParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "VecParser"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn is_pulling_content(&self) -> bool {
            true
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> Self::Element {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> Self::Element {
            let el = self.elements[self.pos].clone();
            self.pos += 1;
            el
        }

        fn end(&mut self) -> Result<Self::Element, XmlException> {
            let elem = self.next();
            if !elem.is_end() {
                return Err(XmlException::with_message("expected end element"));
            }
            Ok(elem)
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str, attrs: &[(&str, &str)]) -> XmlElementImpl {
        XmlElementImpl::new(
            true,
            false,
            name,
            0,
            attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            None,
            0,
            0,
        )
        .unwrap()
    }

    fn end(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn test_restore_xml_reads_attributes_and_flags() {
        let mut parser = VecParser {
            elements: vec![
                start("fdesc", &[("name", "main"), ("addr", "0x1000")]),
                start("flags", &[]),
                end("flags", "0x6"),
                end("fdesc", ""),
            ],
            pos: 0,
        };
        let mut man = DescriptionManager::new();
        let fdesc = FunctionDescription::restore_xml(
            &mut parser,
            &LSHVectorFactory::default(),
            &mut man,
            exe("aaa"),
        )
        .unwrap();
        assert_eq!(fdesc.get_function_name(), "main");
        assert_eq!(fdesc.get_address(), 0x1000);
        assert_eq!(fdesc.get_flags(), 6);
        assert!(!parser.has_next());
    }

    #[test]
    fn test_restore_xml_defaults_address_for_library_function() {
        let mut parser = VecParser {
            elements: vec![start("fdesc", &[("name", "printf")]), end("fdesc", "")],
            pos: 0,
        };
        let mut man = DescriptionManager::new();
        let fdesc = FunctionDescription::restore_xml(
            &mut parser,
            &LSHVectorFactory::default(),
            &mut man,
            exe("aaa"),
        )
        .unwrap();
        assert_eq!(fdesc.get_address(), -1);
        assert_eq!(fdesc.get_flags(), 0);
    }

    #[test]
    fn test_restore_xml_round_trips_save_xml() {
        let mut original = func(&exe("aaa"), "main", 0x1000);
        original.set_flags(6);
        let text = xml(&original);

        let mut parser = VecParser {
            elements: vec![
                start("fdesc", &[("name", "main"), ("addr", "0x1000")]),
                start("flags", &[]),
                end("flags", "0x6"),
                end("fdesc", ""),
            ],
            pos: 0,
        };
        let mut man = DescriptionManager::new();
        let restored = FunctionDescription::restore_xml(
            &mut parser,
            &LSHVectorFactory::default(),
            &mut man,
            exe("aaa"),
        )
        .unwrap();
        assert_eq!(restored, original);
        assert_eq!(xml(&restored), text);
    }

    #[test]
    fn test_restore_xml_rejects_wrong_element() {
        let mut parser =
            VecParser { elements: vec![start("exe", &[]), end("exe", "")], pos: 0 };
        let mut man = DescriptionManager::new();
        assert!(FunctionDescription::restore_xml(
            &mut parser,
            &LSHVectorFactory::default(),
            &mut man,
            exe("aaa")
        )
        .is_err());
    }
}
