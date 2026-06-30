use std::collections::HashMap;

const DESCRIPTION: &str = "Description";

/// A base class for objects that have a map of string key/value attribute pairs.
pub struct Attributed {
    attributes: HashMap<String, String>,
}

impl Attributed {
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// Returns an immutable reference to the attribute map.
    pub fn get_attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// Sets the attribute with the given key and value, returning the previous value if any.
    pub fn set_attribute(&mut self, key: String, value: String) -> Option<String> {
        self.attributes.insert(key, value)
    }

    /// Returns the value mapped to the given key, if present.
    pub fn get_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)
    }

    /// Removes the attribute with the given key, returning its previous value if any.
    pub fn remove_attribute(&mut self, key: &str) -> Option<String> {
        self.attributes.remove(key)
    }

    /// Returns `true` if an attribute with the given key exists.
    pub fn has_attribute(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Returns the number of attributes defined.
    pub fn size(&self) -> usize {
        self.attributes.len()
    }

    /// Returns `true` if there are no attributes.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Adds all key/value pairs from the given map as attributes.
    pub fn put_attributes(&mut self, map: HashMap<String, String>) {
        self.attributes.extend(map);
    }

    /// Removes all key/value mappings.
    pub fn clear(&mut self) {
        self.attributes.clear();
    }

    /// Returns an iterator over the attribute keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.attributes.keys()
    }

    /// Returns an iterator over the attribute values.
    pub fn values(&self) -> impl Iterator<Item = &String> {
        self.attributes.values()
    }

    /// Returns an iterator over the key/value entry pairs.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &String)> {
        self.attributes.iter()
    }

    /// Sets a description for this `Attributed` object, returning the previous description if any.
    pub fn set_description(&mut self, value: String) -> Option<String> {
        self.attributes.insert(DESCRIPTION.to_string(), value)
    }

    /// Returns the description of this `Attributed` object, if one has been set.
    pub fn get_description(&self) -> Option<&String> {
        self.get_attribute(DESCRIPTION)
    }
}

impl Default for Attributed {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let a = Attributed::new();
        assert!(a.is_empty());
        assert_eq!(a.size(), 0);
    }

    #[test]
    fn set_and_get_attribute() {
        let mut a = Attributed::new();
        let prev = a.set_attribute("key".to_string(), "value".to_string());
        assert!(prev.is_none());
        assert_eq!(a.get_attribute("key"), Some(&"value".to_string()));
    }

    #[test]
    fn set_attribute_returns_previous_value() {
        let mut a = Attributed::new();
        a.set_attribute("key".to_string(), "first".to_string());
        let prev = a.set_attribute("key".to_string(), "second".to_string());
        assert_eq!(prev, Some("first".to_string()));
        assert_eq!(a.get_attribute("key"), Some(&"second".to_string()));
    }

    #[test]
    fn get_attribute_missing_returns_none() {
        let a = Attributed::new();
        assert!(a.get_attribute("missing").is_none());
    }

    #[test]
    fn has_attribute() {
        let mut a = Attributed::new();
        assert!(!a.has_attribute("k"));
        a.set_attribute("k".to_string(), "v".to_string());
        assert!(a.has_attribute("k"));
    }

    #[test]
    fn remove_attribute() {
        let mut a = Attributed::new();
        a.set_attribute("k".to_string(), "v".to_string());
        let removed = a.remove_attribute("k");
        assert_eq!(removed, Some("v".to_string()));
        assert!(!a.has_attribute("k"));
    }

    #[test]
    fn remove_attribute_missing_returns_none() {
        let mut a = Attributed::new();
        assert!(a.remove_attribute("nope").is_none());
    }

    #[test]
    fn size_tracks_insertions_and_removals() {
        let mut a = Attributed::new();
        a.set_attribute("a".to_string(), "1".to_string());
        a.set_attribute("b".to_string(), "2".to_string());
        assert_eq!(a.size(), 2);
        a.remove_attribute("a");
        assert_eq!(a.size(), 1);
    }

    #[test]
    fn put_attributes_merges() {
        let mut a = Attributed::new();
        a.set_attribute("existing".to_string(), "old".to_string());
        let mut extra = HashMap::new();
        extra.insert("existing".to_string(), "new".to_string());
        extra.insert("fresh".to_string(), "val".to_string());
        a.put_attributes(extra);
        assert_eq!(a.get_attribute("existing"), Some(&"new".to_string()));
        assert_eq!(a.get_attribute("fresh"), Some(&"val".to_string()));
    }

    #[test]
    fn clear_removes_all() {
        let mut a = Attributed::new();
        a.set_attribute("k".to_string(), "v".to_string());
        a.clear();
        assert!(a.is_empty());
    }

    #[test]
    fn keys_and_values_iterate() {
        let mut a = Attributed::new();
        a.set_attribute("x".to_string(), "1".to_string());
        a.set_attribute("y".to_string(), "2".to_string());
        let mut keys: Vec<&String> = a.keys().collect();
        keys.sort();
        assert_eq!(keys, vec![&"x".to_string(), &"y".to_string()]);
        let mut vals: Vec<&String> = a.values().collect();
        vals.sort();
        assert_eq!(vals, vec![&"1".to_string(), &"2".to_string()]);
    }

    #[test]
    fn entries_iterate() {
        let mut a = Attributed::new();
        a.set_attribute("k".to_string(), "v".to_string());
        let entries: Vec<(&String, &String)> = a.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (&"k".to_string(), &"v".to_string()));
    }

    #[test]
    fn get_attributes_returns_all() {
        let mut a = Attributed::new();
        a.set_attribute("p".to_string(), "q".to_string());
        let map = a.get_attributes();
        assert_eq!(map.get("p"), Some(&"q".to_string()));
    }

    #[test]
    fn set_and_get_description() {
        let mut a = Attributed::new();
        assert!(a.get_description().is_none());
        let prev = a.set_description("My desc".to_string());
        assert!(prev.is_none());
        assert_eq!(a.get_description(), Some(&"My desc".to_string()));
    }

    #[test]
    fn set_description_returns_previous() {
        let mut a = Attributed::new();
        a.set_description("first".to_string());
        let prev = a.set_description("second".to_string());
        assert_eq!(prev, Some("first".to_string()));
    }

    #[test]
    fn description_stored_under_description_key() {
        let mut a = Attributed::new();
        a.set_description("hello".to_string());
        assert_eq!(a.get_attribute("Description"), Some(&"hello".to_string()));
    }

    #[test]
    fn default_equals_new() {
        let a: Attributed = Default::default();
        assert!(a.is_empty());
    }
}
