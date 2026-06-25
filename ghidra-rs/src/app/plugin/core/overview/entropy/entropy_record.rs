/// A record containing entropy information for various types found in a program.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyRecord {
    pub name: String,
    pub center: f64,
    pub width: f64,
}

impl EntropyRecord {
    /// Creates a new entropy record.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the entropy record
    /// * `center` - The center point of the entropy range
    /// * `width` - The width of the entropy range
    pub fn new<S: Into<String>>(name: S, center: f64, width: f64) -> Self {
        EntropyRecord { name: name.into(), center, width }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_record_creation_with_owned_string() {
        let record = EntropyRecord::new("x86".to_string(), 5.94, 0.4);
        assert_eq!(record.name, "x86");
        assert_eq!(record.center, 5.94);
        assert_eq!(record.width, 0.4);
    }

    #[test]
    fn test_entropy_record_creation_with_str_literal() {
        let record = EntropyRecord::new("arm", 5.1252, 0.51);
        assert_eq!(record.name, "arm");
        assert_eq!(record.center, 5.1252);
        assert_eq!(record.width, 0.51);
    }

    #[test]
    fn test_entropy_record_clone() {
        let record = EntropyRecord::new("x86", 5.94, 0.4);
        let cloned = record.clone();
        assert_eq!(record, cloned);
    }

    #[test]
    fn test_entropy_record_owned_string_format() {
        let name = format!("{}_{}", "test", "record");
        let record = EntropyRecord::new(name, 3.5, 0.2);
        assert_eq!(record.name, "test_record");
        assert_eq!(record.center, 3.5);
        assert_eq!(record.width, 0.2);
    }
}
