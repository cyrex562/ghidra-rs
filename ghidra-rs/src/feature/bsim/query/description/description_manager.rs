use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::ops::Bound;
use std::sync::Arc;

use crate::feature::bsim::query::LshException;
use crate::feature::bsim::query::description::{
    CategoryRecord, FunctionDescription, RowKey,
};
use crate::feature::seam_stubs::{ExecutableRecord, SignatureRecord};
use crate::generic::lsh::vector::lsh_vector::LSHVector;
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::util::xml::spec_xml_utils;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Container for metadata about executables ([`ExecutableRecord`]), functions
/// ([`FunctionDescription`]) and their associated signatures ([`SignatureRecord`]).
///
/// Generally holds sets of functions that are either being inserted into or queried from a BSim
/// database.
///
/// Port of `ghidra.features.bsim.query.description.DescriptionManager`.
///
/// # Ownership divergences from the Java
///
/// Java hands out live references into the container and lets callers mutate them in place, so
/// `newFunctionDescription(..).setFlags(..)` is visible through the set. Rust cannot alias a
/// `BTreeSet` element mutably, so descriptions are handed out **by value**:
/// [`new_function_description`](Self::new_function_description) interns a description and returns
/// a copy of it, and a caller that mutates that copy stores it back with
/// [`insert_function`](Self::insert_function). Since the sort key (executable, name, address) is
/// immutable, storing back never moves the entry.
///
/// Executables are shared rather than copied -- every [`FunctionDescription`] holds the same
/// [`Arc<ExecutableRecord>`] the container holds -- so the executable mutators
/// ([`set_exe_row_id`](Self::set_exe_row_id), [`populate_executable_xref`](Self::populate_executable_xref),
/// ...) do reach every holder, exactly as the Java does. Those methods therefore take `&self`:
/// they mutate a shared record, not the container.
///
/// The executables are keyed by md5 (a [`BTreeMap`] rather than Java's `TreeSet`), which is the
/// same ordering the Java `TreeSet` uses and makes `findExecutable`'s `floor`-then-compare an
/// ordinary map lookup. Row ids are reduced to their `i64`, as they are on
/// [`FunctionDescription`], because the [`RowKey`] trait is not object safe.
#[derive(Debug, Default, Clone)]
pub struct DescriptionManager {
    /// Functions in this container (sorted by exe, name, address).
    funcrec: BTreeSet<FunctionDescription>,
    /// Executables in this container, keyed (and hence sorted) by md5.
    exerec: BTreeMap<String, Arc<ExecutableRecord>>,
    /// Alternate index into executables via row id. Java leaves this null until it is first
    /// populated; an empty map is indistinguishable from that through the public methods.
    row_cache: BTreeMap<i64, Arc<ExecutableRecord>>,
    /// Major version of the decompiler used to generate the signature records.
    major: i16,
    /// Minor version.
    minor: i16,
    /// Settings for signature generation (of functions in this container).
    settings: i32,
}

impl DescriptionManager {
    /// Versions the XML serialization of the objects put in a [`DescriptionManager`].
    pub const LAYOUT_VERSION: i32 = 5;

    pub fn new() -> Self {
        Self::default()
    }

    /// Set the version number of the decompiler used to generate signature records for this
    /// container.
    pub fn set_version(&mut self, maj: i16, min: i16) {
        self.major = maj;
        self.minor = min;
    }

    /// Establish the particular settings of the signature strategy used to generate the
    /// signature records for this container. `set` is the encoded bit-field of settings.
    pub fn set_settings(&mut self, set: i32) {
        self.settings = set;
    }

    /// The major version number of the decompiler used for signatures.
    pub fn get_major_version(&self) -> i16 {
        self.major
    }

    /// The minor version number of the decompiler used for signatures.
    pub fn get_minor_version(&self) -> i16 {
        self.minor
    }

    /// The settings of the signature strategy used for this container.
    pub fn get_settings(&self) -> i32 {
        self.settings
    }

    /// Set the categories associated with a particular executable, replacing any existing
    /// categories.
    pub fn set_exe_categories(&self, erec: &ExecutableRecord, cats: Option<Vec<CategoryRecord>>) {
        erec.set_category(cats);
    }

    /// Associate a database (row) id with a particular executable.
    pub fn set_exe_row_id(&self, erec: &ExecutableRecord, id: &impl RowKey) {
        erec.set_row_id(id.get_long());
    }

    /// Mark that an executable has (already) been stored in the database.
    pub fn set_exe_already_stored(&self, erec: &ExecutableRecord) {
        erec.set_already_stored();
    }

    /// Associate a signature's database id with a particular function.
    ///
    /// Java: the `setSignatureId(FunctionDescription, long)` overload.
    pub fn set_signature_id(&self, frec: &mut FunctionDescription, id: i64) {
        frec.set_vector_id(id);
    }

    /// Associate a database id with a particular signature record.
    ///
    /// Java: the `setSignatureId(SignatureRecord, long)` overload; Rust has no overloading, so
    /// the two carry different names.
    pub fn set_signature_record_id(&self, sigrec: &mut SignatureRecord, id: i64) {
        sigrec.set_vector_id(id);
    }

    /// Associate a database (row) id with a particular function.
    pub fn set_function_description_id(&self, fd: &mut FunctionDescription, id: &impl RowKey) {
        fd.set_id(id);
    }

    /// Associate function "tags" or attributes with a specific function. `fl` is the encoded
    /// bitfield of attributes.
    pub fn set_function_description_flags(&self, fd: &mut FunctionDescription, fl: i32) {
        fd.set_flags(fl);
    }

    /// The executables in this container, in md5 order.
    ///
    /// Java returns the `TreeSet` itself; an iterator over the same order is the read-only
    /// equivalent, and the mutators above are how the Java callers change a record.
    pub fn get_executable_record_set(&self) -> impl Iterator<Item = &Arc<ExecutableRecord>> {
        self.exerec.values()
    }

    /// Clear out all functions from the container, but leave the executables.
    pub fn clear_functions(&mut self) {
        self.funcrec.clear();
    }

    /// Reset to a completely empty container.
    pub fn clear(&mut self) {
        self.clear_functions();
        self.major = 0;
        self.minor = 0;
        self.settings = 0;
        self.exerec.clear();
        self.row_cache.clear();
    }

    /// The number of executables described by this container.
    pub fn num_executables(&self) -> usize {
        self.exerec.len()
    }

    /// The number of functions described by this container.
    pub fn num_functions(&self) -> usize {
        self.funcrec.len()
    }

    /// Allocate a new function in the container, or return the one that is already there.
    ///
    /// Java: `newFunctionDescription(String fnm, long address, ExecutableRecord erec)`. See the
    /// type-level note: the description comes back by value, so mutations to it must be stored
    /// back with [`insert_function`](Self::insert_function).
    pub fn new_function_description(
        &mut self,
        fnm: &str,
        address: i64,
        erec: Arc<ExecutableRecord>,
    ) -> FunctionDescription {
        let newfunc = FunctionDescription::new(erec, fnm, address);
        match self.funcrec.get(&newfunc) {
            Some(existing) => existing.clone(),
            None => {
                self.funcrec.insert(newfunc.clone());
                newfunc
            }
        }
    }

    /// Store a description back into the container, replacing any description with the same
    /// executable, name and address.
    ///
    /// This has no Java counterpart: Java mutates the interned object directly. It is the write
    /// half of [`new_function_description`](Self::new_function_description).
    pub fn insert_function(&mut self, fdesc: FunctionDescription) {
        self.funcrec.replace(fdesc);
    }

    /// Create a new executable record, uniquely identified by its md5 hash. `dt` is the date of
    /// ingest, in milliseconds since the epoch.
    ///
    /// If the executable is already in the container the existing record is returned instead.
    ///
    /// # Errors
    /// If the executable already exists with different metadata, or with a different database id.
    #[allow(clippy::too_many_arguments)]
    pub fn new_executable_record(
        &mut self,
        md5: &str,
        enm: &str,
        cnm: &str,
        arc: &str,
        dt: i64,
        repo: Option<&str>,
        path: Option<&str>,
        id: Option<i64>,
    ) -> Result<Arc<ExecutableRecord>, LshException> {
        let newexe = ExecutableRecord::new_full(md5, enm, cnm, arc, dt, id, repo, path);
        self.insert_executable(newexe, id)
    }

    /// Create a new "library" executable in the container. Functions in this container (will)
    /// have no body or address.
    ///
    /// # Errors
    /// If the library already exists with different metadata, or with a different database id.
    pub fn new_executable_library(
        &mut self,
        enm: &str,
        arc: &str,
        id: Option<i64>,
    ) -> Result<Arc<ExecutableRecord>, LshException> {
        let newexe = ExecutableRecord::new_library_with_id(enm, arc, id);
        self.insert_executable(newexe, id)
    }

    /// The duplicate-detection shared by the two executable factories: Java's
    /// `if (!exerec.add(newexe)) { ... }`.
    fn insert_executable(
        &mut self,
        newexe: ExecutableRecord,
        id: Option<i64>,
    ) -> Result<Arc<ExecutableRecord>, LshException> {
        if let Some(oldexe) = self.exerec.get(newexe.get_md5()) {
            if oldexe.compare_metadata(&newexe) != 0 {
                return Err(LshException::new("Duplicate md5 hash, different metadata"));
            }
            match (oldexe.get_row_id(), id) {
                (Some(old_id), Some(id)) if old_id != id => {
                    return Err(LshException::new("Overwriting existing executable id"));
                }
                _ => {}
            }
            return Ok(Arc::clone(oldexe));
        }
        let newexe = Arc::new(newexe);
        self.exerec.insert(newexe.get_md5().to_string(), Arc::clone(&newexe));
        Ok(newexe)
    }

    /// Transfer decompiler and signature settings from `op2` into this container.
    pub fn transfer_settings(&mut self, op2: &DescriptionManager) {
        self.major = op2.major;
        self.minor = op2.minor;
        self.settings = op2.settings;
    }

    /// Transfer an executable from another container into this container.
    ///
    /// # Errors
    /// If the executable already exists here with different metadata.
    pub fn transfer_executable(
        &mut self,
        erec: &ExecutableRecord,
    ) -> Result<Arc<ExecutableRecord>, LshException> {
        let id = erec.get_row_id();
        let res = if erec.is_library() {
            self.new_executable_library(erec.get_name_exec(), erec.get_architecture(), id)?
        } else {
            self.new_executable_record(
                erec.get_md5(),
                erec.get_name_exec(),
                erec.get_name_compiler(),
                erec.get_architecture(),
                erec.get_date(),
                erec.get_repository().as_deref(),
                erec.get_path().as_deref(),
                id,
            )?
        };
        res.clone_categories(erec);
        Ok(res)
    }

    /// Transfer a function from another container into this container, together with its
    /// executable. `transsig` selects whether the signature record is transferred as well.
    ///
    /// # Errors
    /// If the function's executable already exists here with different metadata.
    pub fn transfer_function(
        &mut self,
        fdesc: &FunctionDescription,
        transsig: bool,
    ) -> Result<FunctionDescription, LshException> {
        let erec = self.transfer_executable(fdesc.get_executable_record())?;
        let mut res =
            self.new_function_description(fdesc.get_function_name(), fdesc.get_address(), erec);
        res.set_vector_id(fdesc.get_vector_id());
        res.set_flags(fdesc.get_flags());
        if transsig {
            if let Some(srec) = fdesc.get_signature_record() {
                // As in Java, the cloned record starts with vector id 0, which attach_signature
                // then copies over the id set just above.
                let sigclone = self.new_signature_of_count(srec.get_count());
                self.attach_signature(&mut res, Arc::new(sigclone));
            }
        }
        self.insert_function(res.clone());
        Ok(res)
    }

    /// A map from database (row) id to function, for every function in this container that has
    /// an id.
    ///
    /// Java takes the map as an out-parameter and inserts every function, including those whose
    /// id is still null.
    pub fn generate_function_id_map(&self) -> BTreeMap<i64, &FunctionDescription> {
        self.funcrec.iter().filter_map(|func| func.get_id().map(|id| (id, func))).collect()
    }

    /// Generate a signature record for a specific feature vector. `count` is the number of
    /// functions sharing the vector.
    ///
    /// The placeholder [`SignatureRecord`] retains only the count, so the vector is inspected
    /// but not stored.
    pub fn new_signature<V: LSHVector + ?Sized>(&self, vec: &V, count: i32) -> SignatureRecord {
        let _ = vec;
        self.new_signature_of_count(count)
    }

    /// The part of [`new_signature`](Self::new_signature) that does not depend on the vector.
    fn new_signature_of_count(&self, count: i32) -> SignatureRecord {
        let mut srec = SignatureRecord::new(0);
        srec.set_count(count);
        srec
    }

    /// Parse a signature record from an XML stream, building the underlying feature vector with
    /// `vector_factory`.
    ///
    /// Java: the `newSignature(XmlPullParser, LSHVectorFactory, int)` overload. The
    /// [`LSHVectorFactory`] placeholder cannot build a vector yet, so the vector element is
    /// consumed and discarded, leaving the surrounding parse well formed.
    pub(crate) fn new_signature_from_xml<P: XmlPullParser>(
        &self,
        parser: &mut P,
        vector_factory: &LSHVectorFactory,
        count: i32,
    ) -> SignatureRecord {
        let _ = vector_factory;
        parser.discard_sub_tree();
        self.new_signature_of_count(count)
    }

    /// Associate a signature with a specific function.
    pub fn attach_signature(&self, fd: &mut FunctionDescription, srec: Arc<SignatureRecord>) {
        let vector_id = srec.get_vector_id();
        fd.set_signature_record(srec);
        self.set_signature_id(fd, vector_id);
    }

    /// Mark a parent/child relationship between two functions. `lhash` is a hash indicating
    /// where in `src` the call to `dest` is made.
    pub fn make_callgraph_link(
        &self,
        src: &mut FunctionDescription,
        dest: Arc<FunctionDescription>,
        lhash: i32,
    ) {
        src.insert_call(dest, lhash);
    }

    /// Look up an executable in the container via md5.
    ///
    /// # Errors
    /// If the executable cannot be found.
    pub fn find_executable(&self, md5: &str) -> Result<&Arc<ExecutableRecord>, LshException> {
        self.exerec.get(md5).ok_or_else(|| LshException::new("Unable to find executable"))
    }

    /// Search for an executable by name, and possibly other qualifying information. This is
    /// relatively inefficient as it just iterates through the list. An empty `arch` or `comp`
    /// is treated as absent, as Java's `StringUtils.isEmpty` does.
    ///
    /// Java: the `findExecutable(String, String, String)` overload.
    ///
    /// # Errors
    /// If a matching executable doesn't exist.
    pub fn find_executable_by_name(
        &self,
        name: &str,
        arch: Option<&str>,
        comp: Option<&str>,
    ) -> Result<&Arc<ExecutableRecord>, LshException> {
        let arch = arch.filter(|a| !a.is_empty());
        let comp = comp.filter(|c| !c.is_empty());
        self.exerec
            .values()
            .find(|erec| {
                erec.get_name_exec() == name
                    && arch.is_none_or(|arch| erec.get_architecture() == arch)
                    && comp.is_none_or(|comp| erec.get_name_compiler() == comp)
            })
            .ok_or_else(|| LshException::new("Unable to find executable"))
    }

    /// Find a function (within an executable) by its name and address (both must be provided).
    ///
    /// # Errors
    /// If a matching function does not exist.
    pub fn find_function(
        &self,
        fname: &str,
        address: i64,
        exe: &Arc<ExecutableRecord>,
    ) -> Result<&FunctionDescription, LshException> {
        self.contains_description(fname, address, exe)
            .ok_or_else(|| LshException::new("Unable to find FunctionDescription"))
    }

    /// Find a function within an executable by name. The name isn't guaranteed to be unique; if
    /// there is more than one, the first in address order is returned. If none are found,
    /// `None` is returned.
    pub fn find_function_by_name(
        &self,
        fname: &str,
        exe: &Arc<ExecutableRecord>,
    ) -> Option<&FunctionDescription> {
        let fdesc = FunctionDescription::new(Arc::clone(exe), fname, 0);
        let res = self.funcrec.range(fdesc..).next()?;
        if res.get_function_name() != fname || res.get_executable_record() != exe {
            return None;
        }
        Some(res)
    }

    /// Find a function (within an executable) by its name and address (both must be provided).
    /// If the function doesn't exist, `None` is returned.
    pub fn contains_description(
        &self,
        fname: &str,
        address: i64,
        exe: &Arc<ExecutableRecord>,
    ) -> Option<&FunctionDescription> {
        let fdesc = FunctionDescription::new(Arc::clone(exe), fname, address);
        self.funcrec.get(&fdesc)
    }

    /// Iterate over all functions belonging to a specific executable.
    ///
    /// Java returns null when there is no executable at or before `exe`; that becomes an empty
    /// iterator here.
    pub fn list_functions<'a>(
        &'a self,
        exe: &ExecutableRecord,
    ) -> Box<dyn Iterator<Item = &'a FunctionDescription> + 'a> {
        let md5 = exe.get_md5();
        // Java: exerec.floor(exe) and exerec.higher(exe)
        let Some(startexe) = self.exerec.range(..=md5.to_string()).next_back().map(|(_, v)| v)
        else {
            return Box::new(std::iter::empty());
        };
        let endexe = self
            .exerec
            .range((Bound::Excluded(md5.to_string()), Bound::Unbounded))
            .next()
            .map(|(_, v)| v);

        let startfunc = FunctionDescription::new(Arc::clone(startexe), "", 0);
        // Java: funcrec.ceiling(startfunc). No functions in exe or after it.
        if self.funcrec.range(startfunc.clone()..).next().is_none() {
            return Box::new(std::iter::empty());
        }
        let endfunc = endexe.and_then(|endexe| {
            let key = FunctionDescription::new(Arc::clone(endexe), "", 0);
            self.funcrec.range(key..).next()
        });
        match endfunc {
            // The executable is last, or the executables after it have no functions.
            None => Box::new(self.funcrec.range(startfunc..)),
            Some(endfunc) => Box::new(
                self.funcrec.range((Bound::Included(startfunc), Bound::Excluded(endfunc.clone()))),
            ),
        }
    }

    /// Iterate over all functions in the container.
    pub fn list_all_functions(&self) -> impl Iterator<Item = &FunctionDescription> {
        self.funcrec.iter()
    }

    /// Using the standard exe-md5, function name, address sorting, iterate over all functions
    /// starting with the first function *after* `func`.
    pub fn list_functions_after<'a>(
        &'a self,
        func: &'a FunctionDescription,
    ) -> impl Iterator<Item = &'a FunctionDescription> {
        self.funcrec.range((Bound::Excluded(func), Bound::Unbounded))
    }

    /// Create an internal map entry from a database (row) id to an executable.
    pub fn cache_executable_by_row(&mut self, erec: Arc<ExecutableRecord>, row_key: &impl RowKey) {
        self.row_cache.insert(row_key.get_long(), erec);
    }

    /// Look up an executable via database id. This uses an internal map which must have been
    /// explicitly populated via [`cache_executable_by_row`](Self::cache_executable_by_row).
    pub fn find_executable_by_row(&self, row_key: &impl RowKey) -> Option<&Arc<ExecutableRecord>> {
        self.row_cache.get(&row_key.get_long())
    }

    /// Assign an internal id to all executables for purposes of cross-referencing in XML.
    /// Indices are assigned in order starting at 1 (0 indicates an index has NOT been assigned).
    pub fn populate_executable_xref(&self) {
        let Some(first) = self.exerec.values().next() else {
            return;
        };
        if first.get_xref_index() == 1 {
            return; // Already been populated
        }
        for (xref_index, exe) in self.exerec.values().enumerate() {
            exe.set_xref_index(xref_index as i32 + 1);
        }
    }

    /// For every executable in this container that is also in `manage`, copy the xref index from
    /// the `manage` version; otherwise set the xref index to zero.
    pub fn match_and_set_xrefs(&self, manage: &DescriptionManager) {
        for (md5, current_record) in &self.exerec {
            // Java takes the floor and then checks the md5, which is this lookup.
            match manage.exerec.get(md5) {
                Some(matched) => current_record.set_xref_index(matched.get_xref_index()),
                // Mark as having no match in manage
                None => current_record.set_xref_index(0),
            }
        }
    }

    /// Assign an internal id to all executables and also create a map from id to executable. As
    /// with [`populate_executable_xref`](Self::populate_executable_xref), ids are assigned in
    /// order starting at 1.
    pub fn generate_executable_xref_map(&self) -> BTreeMap<i32, Arc<ExecutableRecord>> {
        self.exerec
            .values()
            .enumerate()
            .map(|(index, exe)| {
                let xref_index = index as i32 + 1;
                exe.set_xref_index(xref_index);
                (xref_index, Arc::clone(exe))
            })
            .collect()
    }

    /// Override the repository setting of every executable in this manager.
    pub fn override_repository(&self, repo: &str, path: &str) {
        for element in self.exerec.values() {
            element.set_repository(Some(repo), Some(path));
        }
    }

    /// Serialize the entire container to an XML stream.
    ///
    /// Executables with no functions are not written, as in Java. Java sorts each function's
    /// callgraph in place on the way out; here the sorted copy is what gets written, which
    /// produces the same bytes without mutating the container.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<description layout_version=\"{}\"", Self::LAYOUT_VERSION)?;
        if self.major != 0 {
            write!(fwrite, " major=\"{}\" minor=\"{}\"", self.major, self.minor)?;
        }
        if self.settings != 0 {
            write!(fwrite, " settings=\"0x{:x}\"", self.settings as u32)?;
        }
        write!(fwrite, ">\n")?;
        let mut curexe: Option<&Arc<ExecutableRecord>> = None;
        for fdesc in &self.funcrec {
            let exe = fdesc.get_executable_record();
            if curexe.is_none_or(|curexe| **exe != **curexe) {
                if curexe.is_some() {
                    write!(fwrite, "</execlist>\n")?;
                }
                curexe = Some(exe);
                write!(fwrite, "<execlist>\n")?;
                exe.save_xml(fwrite)?;
            }
            let mut sorted = fdesc.clone();
            sorted.sort_callgraph();
            sorted.save_xml(fwrite)?;
        }
        if curexe.is_some() {
            write!(fwrite, "</execlist>\n")?;
        }
        write!(fwrite, "</description>\n")
    }

    /// Reconstruct a container by deserializing an XML stream, building feature vectors with
    /// `vector_factory`.
    ///
    /// # Errors
    /// If there are inconsistencies in the XML, or its layout version is not
    /// [`LAYOUT_VERSION`](Self::LAYOUT_VERSION).
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        vector_factory: &LSHVectorFactory,
    ) -> Result<(), LshException> {
        use crate::util::xml::xml_exception::XmlException;
        let xml_err = |e: XmlException| LshException::new(e.to_string());

        self.major = 0;
        self.minor = 0;
        self.settings = 0;
        let mut layout_version = 0;
        let el = parser.start(&["description"]).map_err(xml_err)?;
        if el.has_attribute("layout_version") {
            layout_version =
                spec_xml_utils::decode_int(el.get_attribute("layout_version").as_deref());
        }
        if layout_version < Self::LAYOUT_VERSION {
            return Err(LshException::new("Old XML layout is no longer supported"));
        }
        if layout_version > Self::LAYOUT_VERSION {
            return Err(LshException::new("XML layout for newer version of BSIM"));
        }
        if el.has_attribute("major") {
            self.major = spec_xml_utils::decode_int(el.get_attribute("major").as_deref()) as i16;
            self.minor = spec_xml_utils::decode_int(el.get_attribute("minor").as_deref()) as i16;
        }
        if el.has_attribute("settings") {
            self.settings = spec_xml_utils::decode_int(el.get_attribute("settings").as_deref());
        }
        while parser.peek().is_start() {
            parser.start(&["execlist"]).map_err(xml_err)?;
            let erec = ExecutableRecord::restore_xml(parser, self)?;
            while parser.peek().is_start() {
                let fdesc = FunctionDescription::restore_xml(
                    parser,
                    vector_factory,
                    self,
                    Arc::clone(&erec),
                )?;
                self.insert_function(fdesc);
            }
            parser.end().map_err(xml_err)?;
        }
        parser.end().map_err(xml_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::client::row_key_sql::RowKeySQL;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use crate::util::xml::xml_exception::XmlException;

    const MD5_A: &str = "00000000000000000000000000000001";
    const MD5_B: &str = "00000000000000000000000000000002";

    fn manager_with_exe(md5: &str) -> (DescriptionManager, Arc<ExecutableRecord>) {
        let mut man = DescriptionManager::new();
        let exe = man
            .new_executable_record(md5, "a.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        (man, exe)
    }

    fn xml_of(man: &DescriptionManager) -> String {
        let mut buf = Vec::new();
        man.save_xml(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // --- versions / settings ---

    #[test]
    fn test_new_is_empty_and_unversioned() {
        let man = DescriptionManager::new();
        assert_eq!(man.num_executables(), 0);
        assert_eq!(man.num_functions(), 0);
        assert_eq!(man.get_major_version(), 0);
        assert_eq!(man.get_minor_version(), 0);
        assert_eq!(man.get_settings(), 0);
    }

    #[test]
    fn test_transfer_settings_copies_versions() {
        let mut src = DescriptionManager::new();
        src.set_version(7, 3);
        src.set_settings(0x21);
        let mut dst = DescriptionManager::new();
        dst.transfer_settings(&src);
        assert_eq!(dst.get_major_version(), 7);
        assert_eq!(dst.get_minor_version(), 3);
        assert_eq!(dst.get_settings(), 0x21);
    }

    // --- executables ---

    #[test]
    fn test_new_executable_record_interns_by_md5() {
        let (mut man, first) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_A, "a.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        assert_eq!(man.num_executables(), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn test_new_executable_record_rejects_conflicting_metadata() {
        let (mut man, _) = manager_with_exe(MD5_A);
        let err = man
            .new_executable_record(MD5_A, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap_err();
        assert_eq!(err.message(), "Duplicate md5 hash, different metadata");
    }

    #[test]
    fn test_new_executable_record_rejects_conflicting_row_id() {
        let mut man = DescriptionManager::new();
        man.new_executable_record(
            MD5_A,
            "a.exe",
            "gcc",
            "x86:LE:32:default",
            0,
            None,
            None,
            Some(11),
        )
        .unwrap();
        let err = man
            .new_executable_record(
                MD5_A,
                "a.exe",
                "gcc",
                "x86:LE:32:default",
                0,
                None,
                None,
                Some(12),
            )
            .unwrap_err();
        assert_eq!(err.message(), "Overwriting existing executable id");
    }

    #[test]
    fn test_new_executable_library_uses_placeholder_md5() {
        let mut man = DescriptionManager::new();
        let lib = man.new_executable_library("libc", "x86:LE:32:default", None).unwrap();
        assert!(lib.is_library());
        assert_eq!(
            lib.get_md5(),
            ExecutableRecord::calc_library_md5_placeholder("libc", "x86:LE:32:default")
        );
        // Java's placeholder hash is 32 characters and starts with the fixed prefix.
        assert_eq!(lib.get_md5().len(), 32);
        assert!(lib.get_md5().starts_with("bbbbbbbbaaaaaaaa"));
        // A different library gets a different placeholder.
        let other = man.new_executable_library("libm", "x86:LE:32:default", None).unwrap();
        assert_ne!(lib.get_md5(), other.get_md5());
        assert_eq!(man.num_executables(), 2);
    }

    #[test]
    fn test_find_executable_by_md5() {
        let (man, exe) = manager_with_exe(MD5_A);
        assert!(Arc::ptr_eq(man.find_executable(MD5_A).unwrap(), &exe));
        assert_eq!(man.find_executable(MD5_B).unwrap_err().message(), "Unable to find executable");
    }

    #[test]
    fn test_find_executable_by_name_filters_on_arch_and_compiler() {
        let (man, exe) = manager_with_exe(MD5_A);
        assert!(Arc::ptr_eq(man.find_executable_by_name("a.exe", None, None).unwrap(), &exe));
        // Empty strings are ignored, exactly like Java's StringUtils.isEmpty check.
        assert!(
            Arc::ptr_eq(man.find_executable_by_name("a.exe", Some(""), Some("")).unwrap(), &exe)
        );
        assert!(
            man.find_executable_by_name("a.exe", Some("x86:LE:32:default"), Some("gcc")).is_ok()
        );
        assert!(man.find_executable_by_name("a.exe", Some("ARM:LE:32:v8"), None).is_err());
        assert!(man.find_executable_by_name("a.exe", None, Some("clang")).is_err());
        assert!(man.find_executable_by_name("b.exe", None, None).is_err());
    }

    #[test]
    fn test_executable_mutators_reach_every_holder() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let func = man.new_function_description("main", 0x1000, Arc::clone(&exe));

        man.set_exe_row_id(&exe, &RowKeySQL::new(42));
        man.set_exe_already_stored(&exe);
        man.set_exe_categories(
            &exe,
            Some(vec![
                CategoryRecord::new("Origin", Some("vendor".to_string())),
                CategoryRecord::new("Compiler", Some("gcc".to_string())),
            ]),
        );
        man.populate_executable_xref();

        // The record the function points at is the record the container holds.
        let seen = func.get_executable_record();
        assert_eq!(seen.get_row_id(), Some(42));
        assert!(seen.is_already_stored());
        assert_eq!(seen.get_xref_index(), 1);
        // setCategory sorts by type, then category.
        let cats = seen.get_all_categories().unwrap();
        assert_eq!(cats.iter().map(|c| c.get_type()).collect::<Vec<_>>(), vec!["Compiler", "Origin"]);
    }

    #[test]
    fn test_populate_executable_xref_numbers_in_md5_order_and_is_idempotent() {
        let (mut man, _) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        man.populate_executable_xref();
        assert_eq!(man.find_executable(MD5_A).unwrap().get_xref_index(), 1);
        assert_eq!(second.get_xref_index(), 2);

        // A second call is a no-op because the first record already has index 1.
        second.set_xref_index(9);
        man.populate_executable_xref();
        assert_eq!(second.get_xref_index(), 9);
    }

    #[test]
    fn test_generate_executable_xref_map() {
        let (mut man, first) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        let map = man.generate_executable_xref_map();
        assert_eq!(map.len(), 2);
        assert!(Arc::ptr_eq(&map[&1], &first));
        assert!(Arc::ptr_eq(&map[&2], &second));
        assert_eq!(second.get_xref_index(), 2);
    }

    #[test]
    fn test_match_and_set_xrefs_zeroes_unmatched() {
        let (mut man, matched) = manager_with_exe(MD5_A);
        let unmatched = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        unmatched.set_xref_index(5);

        let (other, other_exe) = manager_with_exe(MD5_A);
        other_exe.set_xref_index(7);

        man.match_and_set_xrefs(&other);
        assert_eq!(matched.get_xref_index(), 7);
        assert_eq!(unmatched.get_xref_index(), 0);
    }

    #[test]
    fn test_override_repository_strips_slashes() {
        let (man, exe) = manager_with_exe(MD5_A);
        man.override_repository("ghidra://host/repo", "/some/path/");
        assert_eq!(exe.get_repository().as_deref(), Some("ghidra://host/repo"));
        assert_eq!(exe.get_path().as_deref(), Some("some/path"));
    }

    #[test]
    fn test_cache_and_find_executable_by_row() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        assert!(man.find_executable_by_row(&RowKeySQL::new(3)).is_none());
        man.cache_executable_by_row(Arc::clone(&exe), &RowKeySQL::new(3));
        assert!(Arc::ptr_eq(man.find_executable_by_row(&RowKeySQL::new(3)).unwrap(), &exe));
        assert!(man.find_executable_by_row(&RowKeySQL::new(4)).is_none());
    }

    // --- functions ---

    #[test]
    fn test_new_function_description_interns() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let first = man.new_function_description("main", 0x1000, Arc::clone(&exe));
        let second = man.new_function_description("main", 0x1000, Arc::clone(&exe));
        assert_eq!(man.num_functions(), 1);
        assert_eq!(first, second);
        man.new_function_description("main", 0x2000, Arc::clone(&exe));
        assert_eq!(man.num_functions(), 2);
    }

    #[test]
    fn test_insert_function_stores_mutations_back() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let mut func = man.new_function_description("main", 0x1000, Arc::clone(&exe));
        man.set_function_description_id(&mut func, &RowKeySQL::new(8));
        man.set_function_description_flags(&mut func, 6);
        man.set_signature_id(&mut func, 99);
        // Not stored back yet: the container still holds the pristine description.
        assert_eq!(man.find_function("main", 0x1000, &exe).unwrap().get_flags(), 0);
        man.insert_function(func);
        let stored = man.find_function("main", 0x1000, &exe).unwrap();
        assert_eq!(stored.get_flags(), 6);
        assert_eq!(stored.get_id(), Some(8));
        assert_eq!(stored.get_vector_id(), 99);
        assert_eq!(man.num_functions(), 1);
    }

    #[test]
    fn test_find_function_and_contains_description() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("main", 0x1000, Arc::clone(&exe));
        assert_eq!(man.find_function("main", 0x1000, &exe).unwrap().get_address(), 0x1000);
        assert!(man.contains_description("main", 0x2000, &exe).is_none());
        assert_eq!(
            man.find_function("main", 0x2000, &exe).unwrap_err().message(),
            "Unable to find FunctionDescription"
        );
    }

    #[test]
    fn test_find_function_by_name_returns_lowest_address() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("dup", 0x2000, Arc::clone(&exe));
        man.new_function_description("dup", 0x1000, Arc::clone(&exe));
        let found = man.find_function_by_name("dup", &exe).unwrap();
        assert_eq!(found.get_address(), 0x1000);
        assert!(man.find_function_by_name("absent", &exe).is_none());
    }

    #[test]
    fn test_find_function_by_name_rejects_other_executable() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let other = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        man.new_function_description("main", 0x1000, Arc::clone(&exe));
        assert!(man.find_function_by_name("main", &other).is_none());
    }

    #[test]
    fn test_generate_function_id_map_keys_on_row_id() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let mut with_id = man.new_function_description("main", 0x1000, Arc::clone(&exe));
        man.set_function_description_id(&mut with_id, &RowKeySQL::new(4));
        man.insert_function(with_id);
        man.new_function_description("helper", 0x2000, Arc::clone(&exe));

        let map = man.generate_function_id_map();
        assert_eq!(map.len(), 1);
        assert_eq!(map[&4].get_function_name(), "main");
    }

    #[test]
    fn test_list_functions_covers_only_the_requested_executable() {
        let (mut man, first) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        man.new_function_description("a1", 0x10, Arc::clone(&first));
        man.new_function_description("a2", 0x20, Arc::clone(&first));
        man.new_function_description("b1", 0x30, Arc::clone(&second));

        let names: Vec<&str> =
            man.list_functions(&first).map(|f| f.get_function_name()).collect();
        assert_eq!(names, vec!["a1", "a2"]);
        let names: Vec<&str> =
            man.list_functions(&second).map(|f| f.get_function_name()).collect();
        assert_eq!(names, vec!["b1"]);
    }

    #[test]
    fn test_list_functions_empty_for_executable_without_functions() {
        let (mut man, first) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        man.new_function_description("a1", 0x10, Arc::clone(&first));
        assert_eq!(man.list_functions(&second).count(), 0);
    }

    #[test]
    fn test_list_all_functions_and_after() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("beta", 0x20, Arc::clone(&exe));
        let alpha = man.new_function_description("alpha", 0x10, Arc::clone(&exe));
        man.new_function_description("gamma", 0x30, Arc::clone(&exe));

        let names: Vec<&str> =
            man.list_all_functions().map(|f| f.get_function_name()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
        let names: Vec<&str> =
            man.list_functions_after(&alpha).map(|f| f.get_function_name()).collect();
        assert_eq!(names, vec!["beta", "gamma"]);
    }

    #[test]
    fn test_clear_functions_keeps_executables() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("main", 0x1000, exe);
        man.set_version(3, 1);
        man.clear_functions();
        assert_eq!(man.num_functions(), 0);
        assert_eq!(man.num_executables(), 1);
        assert_eq!(man.get_major_version(), 3);
    }

    #[test]
    fn test_clear_resets_everything() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("main", 0x1000, Arc::clone(&exe));
        man.cache_executable_by_row(exe, &RowKeySQL::new(1));
        man.set_version(3, 1);
        man.set_settings(9);
        man.clear();
        assert_eq!(man.num_functions(), 0);
        assert_eq!(man.num_executables(), 0);
        assert_eq!(man.get_major_version(), 0);
        assert_eq!(man.get_minor_version(), 0);
        assert_eq!(man.get_settings(), 0);
        assert!(man.find_executable_by_row(&RowKeySQL::new(1)).is_none());
    }

    // --- signatures / callgraph ---

    #[test]
    fn test_attach_signature_copies_vector_id() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let mut func = man.new_function_description("main", 0x1000, exe);
        let mut srec = man.new_signature_of_count(4);
        man.set_signature_record_id(&mut srec, 77);
        man.attach_signature(&mut func, Arc::new(srec));
        assert_eq!(func.get_signature_record().unwrap().get_count(), 4);
        assert_eq!(func.get_vector_id(), 77);
    }

    #[test]
    fn test_make_callgraph_link() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        let callee = Arc::new(man.new_function_description("callee", 0x2000, Arc::clone(&exe)));
        let mut caller = man.new_function_description("caller", 0x1000, exe);
        man.make_callgraph_link(&mut caller, Arc::clone(&callee), 3);
        assert_eq!(caller.get_callgraph_record().len(), 1);
        assert_eq!(caller.get_callgraph_record()[0].get_local_hash(), 3);
        assert_eq!(
            caller.get_callgraph_record()[0].get_function_description().get_function_name(),
            "callee"
        );
    }

    // --- transfer ---

    #[test]
    fn test_transfer_executable_copies_metadata_and_categories() {
        let (mut src, exe) = manager_with_exe(MD5_A);
        src.set_exe_categories(&exe, Some(vec![CategoryRecord::new("Origin", Some("a".into()))]));
        exe.set_repository(Some("ghidra://host/repo"), Some("bin"));

        let mut dst = DescriptionManager::new();
        let moved = dst.transfer_executable(&exe).unwrap();
        assert!(!Arc::ptr_eq(&moved, &exe));
        assert_eq!(moved.get_md5(), MD5_A);
        assert_eq!(moved.get_name_exec(), "a.exe");
        assert_eq!(moved.get_repository().as_deref(), Some("ghidra://host/repo"));
        assert_eq!(moved.get_path().as_deref(), Some("bin"));
        assert_eq!(moved.get_all_categories().unwrap().len(), 1);
        assert_eq!(dst.num_executables(), 1);
    }

    #[test]
    fn test_transfer_executable_keeps_libraries_libraries() {
        let mut src = DescriptionManager::new();
        let lib = src.new_executable_library("libc", "x86:LE:32:default", None).unwrap();
        let mut dst = DescriptionManager::new();
        let moved = dst.transfer_executable(&lib).unwrap();
        assert!(moved.is_library());
        assert_eq!(moved.get_md5(), lib.get_md5());
    }

    #[test]
    fn test_transfer_function_with_and_without_signature() {
        let (mut src, exe) = manager_with_exe(MD5_A);
        let mut func = src.new_function_description("main", 0x1000, Arc::clone(&exe));
        src.set_function_description_flags(&mut func, 6);
        src.set_signature_id(&mut func, 55);
        let srec = src.new_signature_of_count(3);
        func.set_signature_record(Arc::new(srec));
        src.insert_function(func.clone());

        let mut dst = DescriptionManager::new();
        let moved = dst.transfer_function(&func, true).unwrap();
        assert_eq!(moved.get_function_name(), "main");
        assert_eq!(moved.get_flags(), 6);
        assert_eq!(moved.get_signature_record().unwrap().get_count(), 3);
        // Java: the cloned signature record has vector id 0, and attachSignature copies it over
        // the id that was set just before.
        assert_eq!(moved.get_vector_id(), 0);
        assert_eq!(dst.num_functions(), 1);
        assert_eq!(dst.find_function("main", 0x1000, moved.get_executable_record()).unwrap().get_flags(), 6);

        let mut dst = DescriptionManager::new();
        let moved = dst.transfer_function(&func, false).unwrap();
        assert!(moved.get_signature_record().is_none());
        assert_eq!(moved.get_vector_id(), 55);
    }

    // --- save_xml ---

    #[test]
    fn test_save_xml_empty_container() {
        let man = DescriptionManager::new();
        assert_eq!(xml_of(&man), "<description layout_version=\"5\">\n</description>\n");
    }

    #[test]
    fn test_save_xml_writes_versions_and_settings() {
        let mut man = DescriptionManager::new();
        man.set_version(7, 2);
        man.set_settings(0x1a);
        assert_eq!(
            xml_of(&man),
            "<description layout_version=\"5\" major=\"7\" minor=\"2\" settings=\"0x1a\">\n</description>\n"
        );
    }

    #[test]
    fn test_save_xml_groups_functions_under_their_executable() {
        let (mut man, exe) = manager_with_exe(MD5_A);
        man.new_function_description("main", 0x1000, Arc::clone(&exe));
        man.new_function_description("helper", 0x2000, exe);
        let text = xml_of(&man);
        assert_eq!(text.matches("<execlist>").count(), 1);
        assert_eq!(text.matches("</execlist>").count(), 1);
        assert!(text.contains(&format!("<md5>{MD5_A}</md5>")));
        // Functions come out in name order, between the exe record and the closing tag.
        let helper = text.find("name=\"helper\"").unwrap();
        let main = text.find("name=\"main\"").unwrap();
        let exe_end = text.find("</exe>").unwrap();
        assert!(exe_end < helper && helper < main);
        assert!(main < text.find("</execlist>").unwrap());
    }

    #[test]
    fn test_save_xml_starts_a_new_execlist_per_executable() {
        let (mut man, first) = manager_with_exe(MD5_A);
        let second = man
            .new_executable_record(MD5_B, "b.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
            .unwrap();
        man.new_function_description("a1", 0x10, first);
        man.new_function_description("b1", 0x20, second);
        let text = xml_of(&man);
        assert_eq!(text.matches("<execlist>").count(), 2);
        assert_eq!(text.matches("</execlist>").count(), 2);
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

    /// The element stream `save_xml` would produce for one executable holding one function.
    fn one_exe_one_function(description_attrs: &[(&str, &str)]) -> Vec<XmlElementImpl> {
        vec![
            start("description", description_attrs),
            start("execlist", &[]),
            start("exe", &[]),
            start("md5", &[]),
            end("md5", MD5_A),
            start("name", &[]),
            end("name", "a.exe"),
            start("arch", &[]),
            end("arch", "x86:LE:32:default"),
            start("compiler", &[]),
            end("compiler", "gcc"),
            start("date", &[("millis", "0x1f")]),
            end("date", "0x2"),
            start("path", &[]),
            end("path", "bin/a.exe"),
            start("category", &[("type", "Origin")]),
            end("category", "vendor"),
            end("exe", ""),
            start("fdesc", &[("name", "main"), ("addr", "0x1000")]),
            start("flags", &[]),
            end("flags", "0x6"),
            end("fdesc", ""),
            end("execlist", ""),
            end("description", ""),
        ]
    }

    #[test]
    fn test_restore_xml_reads_executable_and_functions() {
        let mut parser = VecParser {
            elements: one_exe_one_function(&[
                ("layout_version", "5"),
                ("major", "7"),
                ("minor", "2"),
                ("settings", "0x1a"),
            ]),
            pos: 0,
        };
        let mut man = DescriptionManager::new();
        man.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap();

        assert_eq!(man.get_major_version(), 7);
        assert_eq!(man.get_minor_version(), 2);
        assert_eq!(man.get_settings(), 0x1a);
        assert_eq!(man.num_executables(), 1);
        assert_eq!(man.num_functions(), 1);

        let exe = man.find_executable(MD5_A).unwrap();
        assert_eq!(exe.get_name_exec(), "a.exe");
        assert_eq!(exe.get_architecture(), "x86:LE:32:default");
        assert_eq!(exe.get_name_compiler(), "gcc");
        // <date millis="0x1f">0x2</date> is 2 seconds and 31 milliseconds.
        assert_eq!(exe.get_date(), 2_031);
        assert_eq!(exe.get_path().as_deref(), Some("bin/a.exe"));
        assert_eq!(exe.get_all_categories().unwrap().len(), 1);

        let func = man.find_function("main", 0x1000, exe).unwrap();
        assert_eq!(func.get_flags(), 6);
        assert!(!parser.has_next());
    }

    #[test]
    fn test_restore_xml_round_trips_save_xml() {
        let mut parser =
            VecParser { elements: one_exe_one_function(&[("layout_version", "5")]), pos: 0 };
        let mut man = DescriptionManager::new();
        man.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap();

        let text = xml_of(&man);
        let mut second = DescriptionManager::new();
        let mut parser =
            VecParser { elements: one_exe_one_function(&[("layout_version", "5")]), pos: 0 };
        second.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap();
        assert_eq!(xml_of(&second), text);
        assert!(text.contains("<date millis=\"0x1f\">0x2</date>"));
        assert!(text.contains("  <category type=\"Origin\">vendor</category>"));
    }

    #[test]
    fn test_restore_xml_rejects_old_layout() {
        let mut parser =
            VecParser { elements: one_exe_one_function(&[("layout_version", "4")]), pos: 0 };
        let mut man = DescriptionManager::new();
        let err = man.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap_err();
        assert_eq!(err.message(), "Old XML layout is no longer supported");
    }

    #[test]
    fn test_restore_xml_rejects_newer_layout() {
        let mut parser =
            VecParser { elements: one_exe_one_function(&[("layout_version", "6")]), pos: 0 };
        let mut man = DescriptionManager::new();
        let err = man.restore_xml(&mut parser, &LSHVectorFactory::default()).unwrap_err();
        assert_eq!(err.message(), "XML layout for newer version of BSIM");
    }

    #[test]
    fn test_restore_xml_missing_layout_version_is_too_old() {
        let mut parser = VecParser { elements: one_exe_one_function(&[]), pos: 0 };
        let mut man = DescriptionManager::new();
        // No attribute leaves layout_version at 0, which Java treats as an old layout.
        assert!(man.restore_xml(&mut parser, &LSHVectorFactory::default()).is_err());
    }
}
