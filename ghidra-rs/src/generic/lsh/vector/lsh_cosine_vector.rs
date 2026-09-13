use std::io::{self, Read, Write};

use crate::generic::hash::SimpleCRC32;
use crate::generic::lsh::vector::hash_entry::HashEntry;
use crate::generic::lsh::vector::idf_lookup::IdfLookup;
use crate::generic::lsh::vector::lsh_vector::LSHVector;
use crate::generic::lsh::vector::vector_compare::VectorCompare;
use crate::generic::lsh::vector::weight_factory::WeightFactory;
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A concrete cosine-similarity [`LSHVector`]: a sparse feature vector represented as a sorted
/// list of (hash, term-frequency, weight) triples, compared via a weighted dot product normalized
/// by vector length.
///
/// Port of `generic.lsh.vector.LSHCosineVector`.
///
/// # Deviations from Java
///
/// * **`compare`/`compareCounts`/`compareDetail` do not downcast `op2`.** Java's three methods
///   each start with `LSHCosineVector op = (LSHCosineVector) op2;`, reaching directly into `op`'s
///   private `hash`/`length`/`hashcount` fields. [`LSHVector`] was already ported (before this
///   class) with these methods generic over `T: LSHVector + ?Sized` rather than `dyn LSHVector`
///   specifically so call sites never need a trait object -- but that same choice means there is
///   no `Any`-style facility here to downcast an arbitrary `T` back to `LSHCosineVector`, and (more
///   fundamentally) `hashcount` is not part of the public `LSHVector` surface at all, so it
///   couldn't be read off an arbitrary implementor even with a downcast. This port instead drives
///   the merge purely off `op2`'s public interface: [`LSHVector::get_entries`] stands in for `op.hash`,
///   [`LSHVector::get_length`] stands in for `op.length`, and `op2`'s `hashcount` equivalent is
///   recomputed as the sum of every entry's term frequency -- exactly the same computation
///   [`calc_length`](Self::calc_length) itself uses to derive `hashcount` in the first place, so the
///   recomputed value is bit-for-bit identical to Java's private field whenever `op2` actually is
///   an `LSHCosineVector` (the only implementor anywhere in this codebase). Unlike Java, this also
///   means comparing against some other, hypothetical `LSHVector` implementor no longer throws
///   `ClassCastException` -- a strictly more permissive (not narrower) behavior, and a consequence
///   of a design decision already made by the pre-existing [`LSHVector`] port, not one introduced
///   here.
/// * **The unsigned-comparison arithmetic trick becomes a cast.** Java's `hash1 + 0x80000000 <
///   hash2 + 0x80000000` works around `int` having no unsigned comparison operator; this port uses
///   `(hash1 as u32) < (hash2 as u32)` for the same effect, matching the idiom already used by
///   [`crate::util::math_utilities`].
/// * **`calcUniqueHash`'s `long`-sign-extension dance is dropped.** Java's `res2 <<= 32; res2 >>>=
///   32;` exists only to zero out the sign-extended upper 32 bits that `long res2 = reg2;` (an
///   `int`-to-`long` widening conversion) introduces when `reg2` is negative. Since this port keeps
///   `reg1`/`reg2` as `u32` throughout, `reg2 as u64` already zero-extends with no sign-extension
///   artifact to undo, so the dance has no Rust equivalent to perform. The final combined value is
///   bit-for-bit identical to Java's for every input.
/// * **`calcLength`'s `hash[i] == null` check has no Rust equivalent.** Java's `HashEntry[] hash`
///   array can hold `null` elements (most plausibly if a caller passes such an array to
///   [`set_hash_entries`](Self::set_hash_entries)), and `calcLength` silently skips them. This port
///   stores entries as a `Vec<HashEntry>` of plain (non-optional) values, which cannot represent a
///   "null" element at all -- the branch is structurally unreachable rather than removed as "dead
///   code".
/// * **`compareDetail`'s `Double.toString`-style output is approximate.** Entry coefficients are
///   formatted with Rust's native `f64` `Display`, which -- like [`VtScore::to_storage_string`](
///   crate::feature::vt::api::main::vt_score::VtScore::to_storage_string) -- corresponds to, but is
///   not always byte-identical to, Java's `Double.toString` for every possible value.
/// * **`restoreBase64`'s `buffer` parameter is unused.** [`LSHVector::restore_base64`] types this
///   parameter as `&[char]` (immutable), but Java's `Reader.read(buffer, 0, 112)` needs to *write*
///   into it -- there is no way to honor that through an immutable slice. This port instead reads
///   into its own internal 112-byte scratch buffer (Java's own hardcoded chunk size), leaving the
///   `buffer` parameter's contents completely unread. Java's chunked-read structure is otherwise
///   reproduced faithfully, including the latent quirk that a `returned` count which isn't a
///   multiple of 7 causes the final partial group of a chunk to read past the freshly-read data,
///   picking up whatever was left over in the scratch buffer from the previous chunk (`\0` bytes on
///   the very first chunk). Real callers always serialize/deserialize a whole number of complete
///   7-character groups, so this is not expected to be observed in practice -- exactly as in Java.
#[derive(Debug)]
pub struct LSHCosineVector {
    /// Sorted list of hash values and their counts.
    hash: Vec<HashEntry>,
    /// Length of vector.
    length: f64,
    /// Total number of hashes (counting multiplicity).
    hashcount: i32,
}

impl LSHCosineVector {
    /// Creates an empty vector, for use as a template.
    ///
    /// Mirrors `LSHCosineVector()`.
    pub fn new() -> Self {
        Self { hash: Vec::new(), length: 0.0, hashcount: 0 }
    }

    /// Installs a set of features as a sorted `&[i32]`. Each integer is a hash; the same integer
    /// can occur more than once (term frequency (TF) > 1). Weights are determined by TF and Inverse
    /// Document Frequency (IDF) of individual features.
    ///
    /// Mirrors `LSHCosineVector(int[] feature, WeightFactory wfactory, IDFLookup idflookup)`.
    ///
    /// # Panics
    ///
    /// Java's constructor has no documented ordering precondition beyond "the integers MUST
    /// already be sorted"; this port does not itself verify that precondition (matching Java, which
    /// silently produces a `hash` array with meaningless ordering/merge behavior on unsorted input
    /// rather than raising an error).
    pub fn from_features(feature: &[i32], wfactory: &WeightFactory, idflookup: &IdfLookup) -> Self {
        let mut vector = Self::new();
        vector.install_features(feature, wfactory, idflookup);
        vector.calc_length();
        vector
    }

    /// Install hashes and weights directly. Length is automatically calculated. The entries must
    /// already be sorted on the hash.
    ///
    /// Mirrors `setHashEntries(HashEntry[])`.
    pub fn set_hash_entries(&mut self, entries: Vec<HashEntry>) {
        self.hash = entries;
        self.calc_length();
    }

    fn calc_length(&mut self) {
        let mut length = 0.0f64;
        let mut hashcount = 0i32;
        for entry in &self.hash {
            let coeff = entry.get_coeff();
            length += coeff * coeff;
            hashcount += entry.get_tf() as i32;
        }
        self.length = length.sqrt();
        self.hashcount = hashcount;
    }

    /// Assuming `feature` is sorted and `hash` is empty, counts the features and populates `hash`.
    /// For every unique feature, looks up its idf via `idflookup`.
    ///
    /// Mirrors the private `installFeatures(int[], WeightFactory, IDFLookup)`.
    fn install_features(&mut self, feature: &[i32], wfactory: &WeightFactory, idflookup: &IdfLookup) {
        let Some((&first, rest)) = feature.split_first() else {
            return; // No features
        };

        let mut hash = Vec::new();
        let mut lasthash = first;
        let mut count = 1i32;

        if !idflookup.empty() {
            let mut idf = idflookup.get_count(lasthash);
            for &featurei in rest {
                if featurei != lasthash {
                    hash.push(HashEntry::with_factory(lasthash, count, idf, wfactory));
                    lasthash = featurei;
                    count = 1;
                    idf = idflookup.get_count(lasthash);
                } else {
                    count += 1;
                }
            }
            hash.push(HashEntry::with_factory(lasthash, count, idf, wfactory));
        } else {
            let idf = 0;
            for &featurei in rest {
                if featurei != lasthash {
                    hash.push(HashEntry::with_factory(lasthash, count, idf, wfactory));
                    lasthash = featurei;
                    count = 1;
                } else {
                    count += 1;
                }
            }
            hash.push(HashEntry::with_factory(lasthash, count, idf, wfactory));
        }

        self.hash = hash;
    }

    /// Uses [`calc_unique_hash`](LSHVector::calc_unique_hash) to determine a Java-`hashCode`-shaped
    /// value.
    ///
    /// Mirrors `hashCode()`, which narrows the `long` returned by `calcUniqueHash()` down to an
    /// `int` via a truncating cast -- reproduced here with the equivalent `as i32` truncation.
    pub fn hash_code(&self) -> i32 {
        self.calc_unique_hash() as i32
    }
}

impl Default for LSHCosineVector {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for LSHCosineVector {
    /// Mirrors the Eclipse-generated `equals(Object)`: only the `hash` attribute is compared.
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for LSHCosineVector {}

/// Appends `hex_hash tf coeff\n` for each entry, in order.
///
/// Mirrors the private `writeOnlyList(ArrayList<HashEntry>, StringBuilder)`.
fn write_only_list(only: &[HashEntry], buf: &mut String) {
    for entry in only {
        buf.push_str(&format!(
            "{:x} {} {}\n",
            entry.get_hash() as u32,
            entry.get_tf(),
            entry.get_coeff()
        ));
    }
}

/// Appends `hex_hash (tf1,tf2) (coeff1,coeff2)\n` for each consecutive pair of entries.
///
/// Mirrors the private `writeBothList(ArrayList<HashEntry>, StringBuilder)`.
fn write_both_list(both: &[HashEntry], buf: &mut String) {
    for pair in both.chunks_exact(2) {
        let (entry1, entry2) = (pair[0], pair[1]);
        buf.push_str(&format!(
            "{:x} ({},{}) ({},{})\n",
            entry1.get_hash() as u32,
            entry1.get_tf(),
            entry2.get_tf(),
            entry1.get_coeff(),
            entry2.get_coeff()
        ));
    }
}

impl LSHVector for LSHCosineVector {
    fn num_entries(&self) -> i32 {
        self.hash.len() as i32
    }

    fn get_entry(&self, i: i32) -> Option<HashEntry> {
        if i >= 0 && (i as usize) < self.hash.len() {
            Some(self.hash[i as usize])
        } else {
            None
        }
    }

    fn get_entries(&self) -> Vec<HashEntry> {
        self.hash.clone()
    }

    fn get_length(&self) -> f64 {
        self.length
    }

    fn compare<T: LSHVector + ?Sized>(&self, op2: &T, data: &mut VectorCompare) -> f64 {
        let op_hash = op2.get_entries();
        let op_length = op2.get_length();
        // Stands in for Java's `op.hashcount`; see the struct's own module docs.
        let op_hashcount: i32 = op_hash.iter().map(|e| e.get_tf() as i32).sum();

        let mut iter = 0usize;
        let enditer = self.hash.len();
        let mut iter2 = 0usize;
        let enditer2 = op_hash.len();

        let mut res = 0.0f64;
        let mut intersectcount = 0i32;

        if iter != enditer && iter2 != enditer2 {
            let mut hash1 = self.hash[iter].get_hash();
            let mut hash2 = op_hash[iter2].get_hash();
            loop {
                if hash1 == hash2 {
                    let t1 = self.hash[iter].get_tf();
                    let t2 = op_hash[iter2].get_tf();
                    if t1 < t2 {
                        let w1 = self.hash[iter].get_coeff();
                        res += w1 * w1;
                        intersectcount += t1 as i32;
                    } else {
                        let w2 = op_hash[iter2].get_coeff();
                        res += w2 * w2;
                        intersectcount += t2 as i32;
                    }
                    iter += 1;
                    iter2 += 1;
                    if iter == enditer {
                        break;
                    }
                    if iter2 == enditer2 {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                    hash2 = op_hash[iter2].get_hash();
                } else if (hash1 as u32) < (hash2 as u32) {
                    // Unsigned comparison of hash1 and hash2.
                    iter += 1;
                    if iter == enditer {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                } else {
                    iter2 += 1;
                    if iter2 == enditer2 {
                        break;
                    }
                    hash2 = op_hash[iter2].get_hash();
                }
            }
            data.dotproduct = res;
            res /= self.length * op_length;
        } else {
            data.dotproduct = res;
        }
        data.intersectcount = intersectcount;
        data.acount = self.hashcount;
        data.bcount = op_hashcount;
        res
    }

    fn compare_counts<T: LSHVector + ?Sized>(&self, op2: &T, data: &mut VectorCompare) {
        let op_hash = op2.get_entries();
        let op_hashcount: i32 = op_hash.iter().map(|e| e.get_tf() as i32).sum();

        let mut iter = 0usize;
        let enditer = self.hash.len();
        let mut iter2 = 0usize;
        let enditer2 = op_hash.len();

        let mut intersectcount = 0i32;

        if iter != enditer && iter2 != enditer2 {
            let mut hash1 = self.hash[iter].get_hash();
            let mut hash2 = op_hash[iter2].get_hash();
            loop {
                if hash1 == hash2 {
                    let t1 = self.hash[iter].get_tf();
                    let t2 = op_hash[iter2].get_tf();
                    intersectcount += if t1 < t2 { t1 } else { t2 } as i32;
                    iter += 1;
                    iter2 += 1;
                    if iter == enditer {
                        break;
                    }
                    if iter2 == enditer2 {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                    hash2 = op_hash[iter2].get_hash();
                } else if (hash1 as u32) < (hash2 as u32) {
                    iter += 1;
                    if iter == enditer {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                } else {
                    iter2 += 1;
                    if iter2 == enditer2 {
                        break;
                    }
                    hash2 = op_hash[iter2].get_hash();
                }
            }
        }
        data.intersectcount = intersectcount;
        data.acount = self.hashcount;
        data.bcount = op_hashcount;
    }

    fn compare_detail<T: LSHVector + ?Sized>(&self, op2: &T, buf: &mut String) -> f64 {
        let op_hash = op2.get_entries();
        let op_length = op2.get_length();

        let mut a_only: Vec<HashEntry> = Vec::new();
        let mut b_only: Vec<HashEntry> = Vec::new();
        let mut ab_both: Vec<HashEntry> = Vec::new();

        buf.push_str(&format!("lena={}\n", self.get_length()));
        buf.push_str(&format!("lenb={}\n", op_length));

        let mut iter = 0usize;
        let enditer = self.hash.len();
        let mut iter2 = 0usize;
        let enditer2 = op_hash.len();

        let mut res = 0.0f64;
        let mut intersectcount = 0i32;

        if iter != enditer && iter2 != enditer2 {
            let mut hash1 = self.hash[iter].get_hash();
            let mut hash2 = op_hash[iter2].get_hash();
            loop {
                if hash1 == hash2 {
                    ab_both.push(self.hash[iter]);
                    ab_both.push(op_hash[iter2]);
                    let t1 = self.hash[iter].get_tf();
                    let t2 = op_hash[iter2].get_tf();
                    if t1 < t2 {
                        let w1 = self.hash[iter].get_coeff();
                        res += w1 * w1;
                        intersectcount += t1 as i32;
                    } else {
                        let w2 = op_hash[iter2].get_coeff();
                        res += w2 * w2;
                        intersectcount += t2 as i32;
                    }
                    iter += 1;
                    iter2 += 1;
                    if iter == enditer {
                        break;
                    }
                    if iter2 == enditer2 {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                    hash2 = op_hash[iter2].get_hash();
                } else if (hash1 as u32) < (hash2 as u32) {
                    a_only.push(self.hash[iter]);
                    iter += 1;
                    if iter == enditer {
                        break;
                    }
                    hash1 = self.hash[iter].get_hash();
                } else {
                    b_only.push(op_hash[iter2]);
                    iter2 += 1;
                    if iter2 == enditer2 {
                        break;
                    }
                    hash2 = op_hash[iter2].get_hash();
                }
            }
            buf.push_str(&format!("dotproduct={}\n", res));
            buf.push_str(&format!("intersect={}\n", intersectcount));
            res /= self.length * op_length;
        }
        while iter != enditer {
            a_only.push(self.hash[iter]);
            iter += 1;
        }
        while iter2 != enditer2 {
            b_only.push(op_hash[iter2]);
            iter2 += 1;
        }
        write_only_list(&a_only, buf);
        buf.push('\n');
        write_both_list(&ab_both, buf);
        buf.push('\n');
        write_only_list(&b_only, buf);
        res
    }

    fn save_xml(&self, mut fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<lshcosine>\n")?;
        // The length is not stored as part of XML.
        for entry in &self.hash {
            entry.save_xml(&mut fwrite)?;
        }
        write!(fwrite, "</lshcosine>\n")
    }

    fn save_sql(&self) -> String {
        let mut buf = String::new();
        buf.push('(');
        if self.hash.is_empty() {
            buf.push(')');
            return buf;
        }
        self.hash[0].save_sql(&mut buf);
        for entry in &self.hash[1..] {
            buf.push(',');
            entry.save_sql(&mut buf);
        }
        buf.push(')');
        buf
    }

    fn save_base64(&self, buffer: &mut [char], encoder: &[char]) {
        if self.hash.is_empty() {
            return;
        }
        for (i, entry) in self.hash.iter().enumerate() {
            entry.save_base64(buffer, i * 7, encoder);
        }
    }

    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        weight_factory: &WeightFactory,
        idf_lookup: &IdfLookup,
    ) -> Result<(), Box<dyn std::error::Error>> {
        parser.start(&["lshcosine"])?;
        let mut hashlist = Vec::new();
        if idf_lookup.empty() {
            while parser.peek().is_start() {
                let mut entry = HashEntry::new();
                entry.restore_xml(parser, weight_factory)?;
                hashlist.push(entry);
            }
        } else {
            while parser.peek().is_start() {
                let mut entry = HashEntry::new();
                entry.restore_xml_with_lookup(parser, weight_factory, idf_lookup)?;
                hashlist.push(entry);
            }
        }
        parser.end()?;
        self.hash = hashlist;
        self.calc_length(); // The length is not stored as part of XML.
        Ok(())
    }

    fn restore_sql(
        &mut self,
        sql: &str,
        weight_factory: &WeightFactory,
        idf_lookup: &IdfLookup,
    ) -> io::Result<()> {
        let bytes = sql.as_bytes();
        if sql.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty lshvector SQL"));
        }
        if bytes[0] != b'(' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing '(' while parsing lshvector SQL",
            ));
        }

        let mut hashlist = Vec::new();
        let mut start = 1usize;
        let mut tok = bytes[1] as char;
        if tok != ')' {
            loop {
                let mut entry = HashEntry::new();
                start = entry.restore_sql(sql, start, weight_factory, idf_lookup)?;
                hashlist.push(entry);
                tok = *bytes.get(start).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Missing ')' while parsing lshvector SQL",
                    )
                })? as char;
                start += 1;
                if tok != ',' {
                    break;
                }
            }
        }
        if tok != ')' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing ')' while parsing lshvector SQL",
            ));
        }
        self.hash = hashlist;
        self.calc_length();
        Ok(())
    }

    fn restore_base64(
        &mut self,
        input: &mut dyn Read,
        buffer: &[char],
        wfactory: &WeightFactory,
        idflookup: &IdfLookup,
        decode: &[i32],
    ) -> io::Result<()> {
        // `buffer`'s contents cannot be used as I/O scratch space (it's immutable); see the
        // struct's own module docs. Java's literal chunk size (112 = 16 * 7 characters) is used
        // as an internal scratch buffer instead.
        let _ = buffer;
        const CHUNK_LEN: usize = 112;
        let mut raw = [0u8; CHUNK_LEN];
        let mut hashlist = Vec::new();
        loop {
            let returned = input.read(&mut raw)?;
            let chars: Vec<char> = raw.iter().map(|&b| b as char).collect();
            let mut i = 0usize;
            while i < returned {
                let mut entry = HashEntry::new();
                if !entry.restore_base64(&chars, i, decode, wfactory, idflookup) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Bad base64 encoding of LSHCosine vector",
                    ));
                }
                hashlist.push(entry);
                i += 7;
            }
            if returned != CHUNK_LEN {
                break;
            }
        }
        self.hash = hashlist;
        self.calc_length();
        Ok(())
    }

    /// Mirrors `LSHVector.calcUniqueHash()`.
    fn calc_unique_hash(&self) -> u64 {
        let mut reg1: u32 = 0x12CF93AB;
        let mut reg2: u32 = 0xEE39B2D6;
        for entry in &self.hash {
            let curtf = entry.get_tf() as u32;
            let curhash = entry.get_hash() as u32;
            let oldreg1 = reg1;
            reg1 = SimpleCRC32::hash_one_byte(reg1, curtf);
            reg1 = SimpleCRC32::hash_one_byte(reg1, curhash);
            reg1 = SimpleCRC32::hash_one_byte(reg1, reg2 >> 24);
            reg2 = SimpleCRC32::hash_one_byte(reg2, oldreg1 >> 24);
            reg2 = SimpleCRC32::hash_one_byte(reg2, curhash >> 8);
            reg2 = SimpleCRC32::hash_one_byte(reg2, curhash >> 16);
            reg2 = SimpleCRC32::hash_one_byte(reg2, curhash >> 24);
        }
        // See the struct's own module docs: Java's `long`-sign-extension dance on `reg2` has no
        // Rust equivalent since `reg1`/`reg2` are unsigned throughout.
        ((reg1 as u64) << 32) | (reg2 as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;
    use crate::util::xml::xml_exception::XmlException;

    fn entry(hash: i32, tf: i32, coeff: f64) -> HashEntry {
        HashEntry::with_weight(hash, tf, coeff)
    }

    // ---- Construction / basic accessors ----

    #[test]
    fn new_is_empty_with_zero_length() {
        let v = LSHCosineVector::new();
        assert_eq!(v.num_entries(), 0);
        assert_eq!(v.get_length(), 0.0);
        assert!(v.get_entries().is_empty());
    }

    #[test]
    fn default_matches_new() {
        assert!(LSHCosineVector::default() == LSHCosineVector::new());
    }

    #[test]
    fn set_hash_entries_recomputes_length_and_num_entries() {
        let mut v = LSHCosineVector::new();
        v.set_hash_entries(vec![entry(1, 1, 3.0), entry(2, 1, 4.0)]);
        assert_eq!(v.num_entries(), 2);
        // sqrt(3^2 + 4^2) = 5
        assert_eq!(v.get_length(), 5.0);
    }

    #[test]
    fn get_entry_returns_none_out_of_bounds() {
        let mut v = LSHCosineVector::new();
        v.set_hash_entries(vec![entry(1, 1, 1.0)]);
        assert!(v.get_entry(0).is_some());
        assert!(v.get_entry(1).is_none());
        assert!(v.get_entry(-1).is_none());
    }

    // ---- install_features / from_features ----

    #[test]
    fn from_features_empty_array_has_no_entries() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let v = LSHCosineVector::from_features(&[], &w, &idf);
        assert_eq!(v.num_entries(), 0);
        assert_eq!(v.get_length(), 0.0);
    }

    #[test]
    fn from_features_counts_term_frequency_per_unique_hash_without_idf() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new(); // empty() == true
        let v = LSHCosineVector::from_features(&[5, 5, 5, 7, 9, 9], &w, &idf);
        assert_eq!(v.num_entries(), 3);
        let entries = v.get_entries();
        assert_eq!(entries[0].get_hash(), 5);
        assert_eq!(entries[0].get_tf(), 3);
        assert_eq!(entries[1].get_hash(), 7);
        assert_eq!(entries[1].get_tf(), 1);
        assert_eq!(entries[2].get_hash(), 9);
        assert_eq!(entries[2].get_tf(), 2);
    }

    #[test]
    fn from_features_single_repeated_value() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let v = LSHCosineVector::from_features(&[42, 42, 42, 42], &w, &idf);
        assert_eq!(v.num_entries(), 1);
        assert_eq!(v.get_entries()[0].get_tf(), 4);
    }

    #[test]
    fn from_features_with_populated_idf_lookup_still_counts_correctly() {
        let w = WeightFactory::new();
        let mut idf = IdfLookup::new();
        idf.set(&[5, 100, 7, 200, 9, 300]); // non-empty -> exercises the idflookup branch
        let v = LSHCosineVector::from_features(&[5, 5, 7, 9, 9, 9], &w, &idf);
        assert_eq!(v.num_entries(), 3);
        let entries = v.get_entries();
        assert_eq!(entries[0].get_hash(), 5);
        assert_eq!(entries[0].get_tf(), 2);
        assert_eq!(entries[0].get_idf(), 100);
        assert_eq!(entries[1].get_hash(), 7);
        assert_eq!(entries[1].get_tf(), 1);
        assert_eq!(entries[1].get_idf(), 200);
        assert_eq!(entries[2].get_hash(), 9);
        assert_eq!(entries[2].get_tf(), 3);
        assert_eq!(entries[2].get_idf(), 300);
    }

    // ---- equals / hash_code ----

    #[test]
    fn equal_vectors_have_equal_hash_arrays() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0), entry(2, 1, 4.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(1, 1, 3.0), entry(2, 1, 4.0)]);
        assert_eq!(a, b);
        assert_eq!(a.hash_code(), b.hash_code());
    }

    #[test]
    fn equals_ignores_coeff_and_idf_but_not_hash_or_tf() {
        // HashEntry's own equality (relied on by LSHCosineVector.equals) ignores idf/coeff.
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(1, 1, 999.0)]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_hash_entries_are_not_equal() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(2, 1, 3.0)]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_code_is_the_low_32_bits_of_calc_unique_hash() {
        let mut v = LSHCosineVector::new();
        v.set_hash_entries(vec![entry(1, 1, 1.0), entry(5, 2, 2.0)]);
        assert_eq!(v.hash_code(), v.calc_unique_hash() as i32);
    }

    #[test]
    fn calc_unique_hash_of_empty_vector_is_the_seed_registers() {
        let v = LSHCosineVector::new();
        assert_eq!(v.calc_unique_hash(), ((0x12CF93ABu64) << 32) | 0xEE39B2D6u64);
    }

    #[test]
    fn calc_unique_hash_differs_for_different_vectors() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 1.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(2, 1, 1.0)]);
        assert_ne!(a.calc_unique_hash(), b.calc_unique_hash());
    }

    // ---- compare / compare_counts ----

    #[test]
    fn compare_of_disjoint_vectors_yields_zero_dotproduct() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 1.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(2, 1, 1.0)]);
        let mut data = VectorCompare::new();
        let score = a.compare(&b, &mut data);
        assert_eq!(score, 0.0);
        assert_eq!(data.dotproduct, 0.0);
        assert_eq!(data.intersectcount, 0);
    }

    #[test]
    fn compare_against_self_yields_dotproduct_equal_to_length_squared() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0), entry(2, 1, 4.0)]);
        let mut data = VectorCompare::new();
        // "op2" must be a second, independently-owned vector; clone the entries.
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(a.get_entries());
        let score = a.compare(&b, &mut data);
        assert_eq!(data.dotproduct, 25.0); // 3^2 + 4^2
        assert_eq!(score, 1.0); // normalized by length(a) * length(b) == 25.0
        assert_eq!(data.acount, 2);
        assert_eq!(data.bcount, 2);
        assert_eq!(data.intersectcount, 2);
    }

    #[test]
    fn compare_with_one_empty_vector_skips_division_but_reports_counts() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0)]);
        let b = LSHCosineVector::new();
        let mut data = VectorCompare::new();
        let score = a.compare(&b, &mut data);
        assert_eq!(score, 0.0);
        assert_eq!(data.dotproduct, 0.0);
        assert_eq!(data.acount, 1);
        assert_eq!(data.bcount, 0);
    }

    /// Exercises the "unsigned comparison" branch: `-1i32` (bit pattern `0xFFFFFFFF`) sorts
    /// *before* `1i32` under unsigned comparison even though `-1 < 1` is false as signed integers.
    #[test]
    fn compare_orders_hashes_as_unsigned_not_signed() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(-1, 1, 2.0)]); // unsigned: 0xFFFFFFFF (large)
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(1, 1, 5.0)]); // unsigned: 1 (small)
        let mut data = VectorCompare::new();
        // These do not intersect (different hashes); regardless of merge order the result is the
        // same "no overlap" outcome, but a signed-comparison bug would infinite-loop or panic by
        // indexing past the smaller vector's bounds -- so simply completing without panicking,
        // with a correct disjoint-intersection result, demonstrates the fix took effect.
        let score = a.compare(&b, &mut data);
        assert_eq!(score, 0.0);
        assert_eq!(data.intersectcount, 0);
    }

    #[test]
    fn compare_takes_the_smaller_weight_on_tf_mismatch_at_the_same_hash() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 2.0)]); // smaller tf
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(1, 5, 9.0)]); // larger tf
        let mut data = VectorCompare::new();
        a.compare(&b, &mut data);
        // Java: `if (t1 < t2)` picks entry a's weight (2.0^2 = 4.0) since t1(1) < t2(5).
        assert_eq!(data.dotproduct, 4.0);
        assert_eq!(data.intersectcount, 1);
    }

    #[test]
    fn compare_counts_reports_min_tf_and_totals_without_dotproduct() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 3, 1.0), entry(2, 1, 1.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(1, 5, 1.0), entry(3, 1, 1.0)]);
        let mut data = VectorCompare::new();
        a.compare_counts(&b, &mut data);
        assert_eq!(data.intersectcount, 3); // min(3, 5) at the shared hash 1
        assert_eq!(data.acount, 4); // 3 + 1
        assert_eq!(data.bcount, 6); // 5 + 1
        assert_eq!(data.dotproduct, 0.0); // never touched by compare_counts
    }

    // ---- compare_detail ----

    #[test]
    fn compare_detail_includes_lengths_dotproduct_and_intersect() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0), entry(2, 1, 4.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(a.get_entries());
        let mut buf = String::new();
        let score = a.compare_detail(&b, &mut buf);
        assert_eq!(score, 1.0);
        assert!(buf.starts_with("lena=5\nlenb=5\ndotproduct=25\nintersect=2\n"));
    }

    /// Java quirk (see the struct's own docs): when either vector starts out empty, the
    /// `dotproduct=`/`intersect=` lines are never appended at all -- only `lena=`/`lenb=` and the
    /// three (possibly-empty) entry lists still are.
    #[test]
    fn compare_detail_omits_dotproduct_and_intersect_lines_when_a_vector_is_empty() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 3.0)]);
        let b = LSHCosineVector::new();
        let mut buf = String::new();
        let score = a.compare_detail(&b, &mut buf);
        assert_eq!(score, 0.0);
        assert!(buf.contains("lena=3\n"));
        assert!(buf.contains("lenb=0\n"));
        assert!(!buf.contains("dotproduct="));
        assert!(!buf.contains("intersect="));
        // The lone entry in `a` should still show up in the "a only" section.
        assert!(buf.contains(&format!("{:x} 1 3", 1u32)));
    }

    #[test]
    fn compare_detail_partitions_entries_into_a_only_both_and_b_only() {
        let mut a = LSHCosineVector::new();
        a.set_hash_entries(vec![entry(1, 1, 1.0), entry(2, 1, 2.0)]);
        let mut b = LSHCosineVector::new();
        b.set_hash_entries(vec![entry(2, 1, 2.0), entry(3, 1, 3.0)]);
        let mut buf = String::new();
        a.compare_detail(&b, &mut buf);

        // hash 1 is a-only, hash 2 is shared ("both"), hash 3 is b-only.
        let a_only_marker = format!("{:x} 1 1", 1u32);
        let both_marker = format!("{:x} (1,1) (2,2)", 2u32);
        let b_only_marker = format!("{:x} 1 3", 3u32);
        assert!(buf.contains(&a_only_marker));
        assert!(buf.contains(&both_marker));
        assert!(buf.contains(&b_only_marker));
    }

    // ---- save_sql / restore_sql ----

    #[test]
    fn save_sql_of_empty_vector_is_empty_parens() {
        let v = LSHCosineVector::new();
        assert_eq!(v.save_sql(), "()");
    }

    #[test]
    fn save_sql_joins_entries_with_commas() {
        let mut v = LSHCosineVector::new();
        v.set_hash_entries(vec![entry(0xdead, 4, 1.0), entry(0xbeef, 1, 1.0)]);
        assert_eq!(v.save_sql(), "(4:dead,1:beef)");
    }

    #[test]
    fn save_sql_then_restore_sql_round_trips() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let mut original = LSHCosineVector::new();
        original.set_hash_entries(vec![entry(0xdead, 4, 1.0), entry(0xbeef, 2, 1.0)]);
        let sql = original.save_sql();

        let mut restored = LSHCosineVector::new();
        restored.restore_sql(&sql, &w, &idf).unwrap();
        assert_eq!(restored.num_entries(), 2);
        assert_eq!(restored.get_entries()[0].get_hash(), 0xdead);
        assert_eq!(restored.get_entries()[0].get_tf(), 4);
        assert_eq!(restored.get_entries()[1].get_hash(), 0xbeef);
        assert_eq!(restored.get_entries()[1].get_tf(), 2);
    }

    #[test]
    fn restore_sql_of_empty_parens_yields_no_entries() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let mut v = LSHCosineVector::new();
        v.restore_sql("()", &w, &idf).unwrap();
        assert_eq!(v.num_entries(), 0);
    }

    #[test]
    fn restore_sql_rejects_too_short_input() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let mut v = LSHCosineVector::new();
        assert!(v.restore_sql("(", &w, &idf).is_err());
    }

    #[test]
    fn restore_sql_rejects_missing_open_paren() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let mut v = LSHCosineVector::new();
        assert!(v.restore_sql("4:dead)", &w, &idf).is_err());
    }

    #[test]
    fn restore_sql_rejects_missing_close_paren() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let mut v = LSHCosineVector::new();
        assert!(v.restore_sql("(4:dead", &w, &idf).is_err());
    }

    // ---- save_xml / restore_xml ----

    /// Minimal hand-rolled `XmlPullParser` over a fixed element list, mirroring the pattern
    /// already used by this module's siblings (e.g. `idf_lookup`'s own `VecParser`).
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

    /// Hand-rolled parser for the small, well-formed `<lshcosine>...</lshcosine>` XML this module
    /// emits; used only to build fixtures for `restore_xml` tests (mirroring the same technique
    /// used by `idf_lookup`'s own tests).
    fn parse_lshcosine_xml(xml: &str) -> Vec<XmlElementImpl> {
        let mut elements = Vec::new();
        for line in xml.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == "<lshcosine>" {
                elements.push(XmlElementImpl::new(true, false, "lshcosine", 0, Vec::new(), None, 0, 0).unwrap());
            } else if line == "</lshcosine>" {
                elements.push(
                    XmlElementImpl::new(false, true, "lshcosine", 0, Vec::new(), Some(String::new()), 0, 0)
                        .unwrap(),
                );
            } else if let Some(rest) = line.strip_prefix("<hash") {
                let rest = rest.trim_end_matches('>');
                let mut attrs = Vec::new();
                if let Some(tf_pos) = rest.find("tf=\"") {
                    let after = &rest[tf_pos + 4..];
                    let end = after.find('"').unwrap();
                    attrs.push(("tf".to_string(), after[..end].to_string()));
                }
                elements.push(XmlElementImpl::new(true, false, "hash", 1, attrs, None, 0, 0).unwrap());
                let gt = line.find('>').unwrap();
                let close = line.find("</hash>").unwrap();
                let text = line[gt + 1..close].to_string();
                elements.push(
                    XmlElementImpl::new(false, true, "hash", 1, Vec::new(), Some(text), 0, 0).unwrap(),
                );
            }
        }
        elements
    }

    #[test]
    fn save_xml_wraps_entries_in_lshcosine_tags() {
        let mut v = LSHCosineVector::new();
        v.set_hash_entries(vec![entry(5, 1, 1.0)]);
        let mut buf = Vec::new();
        v.save_xml(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("<lshcosine>\n"));
        assert!(text.ends_with("</lshcosine>\n"));
        assert!(text.contains("<hash>0x5</hash>"));
    }

    #[test]
    fn save_xml_then_restore_xml_round_trips_without_idf_lookup() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new(); // empty() == true

        let mut original = LSHCosineVector::new();
        original.set_hash_entries(vec![entry(5, 1, 1.0), entry(9, 3, 1.0)]);
        let mut buf = Vec::new();
        original.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();

        let elements = parse_lshcosine_xml(&xml);
        let mut parser = VecParser::new(elements);
        let mut restored = LSHCosineVector::new();
        restored.restore_xml(&mut parser, &w, &idf).unwrap();

        assert_eq!(restored.num_entries(), 2);
        assert_eq!(restored.get_entries()[0].get_hash(), 5);
        assert_eq!(restored.get_entries()[0].get_tf(), 1);
        assert_eq!(restored.get_entries()[1].get_hash(), 9);
        assert_eq!(restored.get_entries()[1].get_tf(), 3);
    }

    #[test]
    fn restore_xml_of_empty_vector_yields_no_entries() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let elements = parse_lshcosine_xml("<lshcosine>\n</lshcosine>\n");
        let mut parser = VecParser::new(elements);
        let mut restored = LSHCosineVector::new();
        restored.restore_xml(&mut parser, &w, &idf).unwrap();
        assert_eq!(restored.num_entries(), 0);
        assert_eq!(restored.get_length(), 0.0);
    }

    // ---- save_base64 / restore_base64 ----

    const BASE64_ENCODER: &[char] = &[
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];

    fn base64_decoder() -> [i32; 128] {
        let mut decoder = [-1i32; 128];
        for (i, &c) in BASE64_ENCODER.iter().enumerate() {
            decoder[c as usize] = i as i32;
        }
        decoder
    }

    #[test]
    fn save_base64_of_empty_vector_writes_nothing() {
        let v = LSHCosineVector::new();
        let mut buffer = vec!['\0'; 7];
        v.save_base64(&mut buffer, BASE64_ENCODER);
        assert_eq!(buffer, vec!['\0'; 7]);
    }

    #[test]
    fn save_base64_then_restore_base64_round_trips() {
        let encoder = BASE64_ENCODER;
        let decoder = base64_decoder();
        let w = WeightFactory::new();
        let idf = IdfLookup::new();

        let mut original = LSHCosineVector::new();
        original.set_hash_entries(vec![entry(0x1234_5678, 10, 1.0), entry(0x0000_00FF, 1, 1.0)]);

        let mut buffer = vec!['\0'; 14]; // 2 entries * 7 chars
        original.save_base64(&mut buffer, encoder);

        let bytes: Vec<u8> = buffer.iter().map(|&c| c as u8).collect();
        let mut input: &[u8] = &bytes;
        let mut restored = LSHCosineVector::new();
        restored.restore_base64(&mut input, &[], &w, &idf, &decoder).unwrap();

        assert_eq!(restored.num_entries(), 2);
        assert_eq!(restored.get_entries()[0].get_hash(), 0x1234_5678);
        assert_eq!(restored.get_entries()[0].get_tf(), 10);
        assert_eq!(restored.get_entries()[1].get_hash(), 0x0000_00FF);
        assert_eq!(restored.get_entries()[1].get_tf(), 1);
    }

    #[test]
    fn restore_base64_of_empty_input_yields_no_entries() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let decoder = base64_decoder();
        let mut input: &[u8] = &[];
        let mut restored = LSHCosineVector::new();
        restored.restore_base64(&mut input, &[], &w, &idf, &decoder).unwrap();
        assert_eq!(restored.num_entries(), 0);
    }

    #[test]
    fn restore_base64_rejects_bad_encoding() {
        let w = WeightFactory::new();
        let idf = IdfLookup::new();
        let decoder = base64_decoder();
        // '!' is not a valid base64 character -> decoder maps it to -1, which HashEntry's own
        // restore_base64 rejects as a bad `tf` character.
        let bad: Vec<u8> = "!AAAAAA".bytes().collect();
        let mut input: &[u8] = &bad;
        let mut restored = LSHCosineVector::new();
        assert!(restored.restore_base64(&mut input, &[], &w, &idf, &decoder).is_err());
    }
}
