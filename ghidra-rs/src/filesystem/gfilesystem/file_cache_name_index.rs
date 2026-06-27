use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

/// MD5 hex string length: 16 bytes × 2 hex chars per byte.
const MD5_HEXSTR_LEN: usize = 32;

/// Best-effort cache of MD5 values keyed by `{parentMD5}_{name}`.
///
/// Java used a soft-reference map; here a plain `HashMap` is used because Rust has no
/// built-in soft-reference mechanism.  Callers that need cache eviction should call
/// [`clear`](FileCacheNameIndex::clear) explicitly.
pub struct FileCacheNameIndex {
    map: Mutex<HashMap<String, String>>,
}

impl FileCacheNameIndex {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn clear(&self) {
        self.map.lock().unwrap().clear();
    }

    /// Stores `file_md5` under the key derived from `parent_md5` and `name`.
    ///
    /// Returns an error if `parent_md5` is not exactly 32 hex characters long.
    pub fn add(&self, parent_md5: &str, name: &str, file_md5: &str) -> io::Result<()> {
        if parent_md5.len() != MD5_HEXSTR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Bad MD5 for parent object: {parent_md5}, {name}, {file_md5}"),
            ));
        }
        let key = format!("{parent_md5}_{name}");
        self.map.lock().unwrap().insert(key, file_md5.to_owned());
        Ok(())
    }

    /// Retrieves the MD5 previously stored for `(parent_md5, name)`, or `None` if not cached.
    ///
    /// Returns an error if `parent_md5` is not exactly 32 hex characters long.
    pub fn get(&self, parent_md5: &str, name: &str) -> io::Result<Option<String>> {
        if parent_md5.len() != MD5_HEXSTR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Bad MD5 for parent object: {parent_md5}, {name}"),
            ));
        }
        let key = format!("{parent_md5}_{name}");
        Ok(self.map.lock().unwrap().get(&key).cloned())
    }
}

impl Default for FileCacheNameIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT: &str = "aabbccddeeff00112233445566778899";
    const FILE_MD5: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn add_and_get_roundtrip() {
        let cache = FileCacheNameIndex::new();
        cache.add(PARENT, "file.txt", FILE_MD5).unwrap();
        assert_eq!(cache.get(PARENT, "file.txt").unwrap(), Some(FILE_MD5.to_owned()));
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = FileCacheNameIndex::new();
        assert_eq!(cache.get(PARENT, "missing").unwrap(), None);
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = FileCacheNameIndex::new();
        cache.add(PARENT, "file.txt", FILE_MD5).unwrap();
        cache.clear();
        assert_eq!(cache.get(PARENT, "file.txt").unwrap(), None);
    }

    #[test]
    fn add_rejects_short_parent_md5() {
        let cache = FileCacheNameIndex::new();
        let err = cache.add("tooshort", "file.txt", FILE_MD5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn get_rejects_short_parent_md5() {
        let cache = FileCacheNameIndex::new();
        let err = cache.get("tooshort", "file.txt").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn same_name_different_parents_are_independent() {
        let cache = FileCacheNameIndex::new();
        let parent2 = "ffeeddccbbaa99887766554433221100";
        let md5b = "112233445566778899aabbccddeeff00";
        cache.add(PARENT, "file.txt", FILE_MD5).unwrap();
        cache.add(parent2, "file.txt", md5b).unwrap();
        assert_eq!(cache.get(PARENT, "file.txt").unwrap(), Some(FILE_MD5.to_owned()));
        assert_eq!(cache.get(parent2, "file.txt").unwrap(), Some(md5b.to_owned()));
    }

    #[test]
    fn add_overwrites_existing_entry() {
        let cache = FileCacheNameIndex::new();
        let new_md5 = "ffffffffffffffffffffffffffffffff";
        cache.add(PARENT, "file.txt", FILE_MD5).unwrap();
        cache.add(PARENT, "file.txt", new_md5).unwrap();
        assert_eq!(cache.get(PARENT, "file.txt").unwrap(), Some(new_md5.to_owned()));
    }
}
