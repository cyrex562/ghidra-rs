use std::collections::HashMap;

use super::IsfObject;

/// Represents ISF Windows PE version metadata.
///
/// Mirrors `IsfWinPE` from Ghidra's `Debugger-isf` module. Fields are parsed
/// from the `"PE Property[ProductVersion]"` entry in the metadata map, which
/// is expected to hold a dot-separated string of the form
/// `major.minor.revision.build`.
pub struct IsfWinPE {
    pub build: Option<i32>,
    pub major: Option<i32>,
    pub minor: Option<i32>,
    pub revision: Option<i32>,
}

impl IsfWinPE {
    /// Creates a new `IsfWinPE` from the provided metadata map.
    ///
    /// Looks up `"PE Property[ProductVersion]"` and splits on `'.'`. If the
    /// value is absent or has fewer than four parts, the affected fields are
    /// `None`. Non-numeric parts also yield `None` for their field.
    pub fn new(meta_data: &HashMap<String, String>) -> Self {
        let (major, minor, revision, build) =
            if let Some(s) = meta_data.get("PE Property[ProductVersion]") {
                let quad: Vec<&str> = s.split('.').collect();
                if quad.len() >= 4 {
                    (
                        quad[0].parse().ok(),
                        quad[1].parse().ok(),
                        quad[2].parse().ok(),
                        quad[3].parse().ok(),
                    )
                } else {
                    (None, None, None, None)
                }
            } else {
                (None, None, None, None)
            };

        Self { build, major, minor, revision }
    }
}

impl IsfObject for IsfWinPE {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn fields_extracted_from_version_string() {
        let meta = make_map(&[("PE Property[ProductVersion]", "10.0.19041.1")]);
        let pe = IsfWinPE::new(&meta);
        assert_eq!(pe.major, Some(10));
        assert_eq!(pe.minor, Some(0));
        assert_eq!(pe.revision, Some(19041));
        assert_eq!(pe.build, Some(1));
    }

    #[test]
    fn missing_key_yields_all_none() {
        let meta = HashMap::new();
        let pe = IsfWinPE::new(&meta);
        assert_eq!(pe.major, None);
        assert_eq!(pe.minor, None);
        assert_eq!(pe.revision, None);
        assert_eq!(pe.build, None);
    }

    #[test]
    fn too_few_parts_yields_all_none() {
        let meta = make_map(&[("PE Property[ProductVersion]", "1.2.3")]);
        let pe = IsfWinPE::new(&meta);
        assert_eq!(pe.major, None);
        assert_eq!(pe.minor, None);
        assert_eq!(pe.revision, None);
        assert_eq!(pe.build, None);
    }

    #[test]
    fn non_numeric_part_yields_none_for_that_field() {
        let meta = make_map(&[("PE Property[ProductVersion]", "10.x.19041.1")]);
        let pe = IsfWinPE::new(&meta);
        assert_eq!(pe.major, Some(10));
        assert_eq!(pe.minor, None);
        assert_eq!(pe.revision, Some(19041));
        assert_eq!(pe.build, Some(1));
    }

    #[test]
    fn extra_parts_beyond_four_are_ignored() {
        let meta = make_map(&[("PE Property[ProductVersion]", "1.2.3.4.5")]);
        let pe = IsfWinPE::new(&meta);
        assert_eq!(pe.major, Some(1));
        assert_eq!(pe.minor, Some(2));
        assert_eq!(pe.revision, Some(3));
        assert_eq!(pe.build, Some(4));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = make_map(&[("PE Property[ProductVersion]", "6.1.7601.0")]);
        let pe = IsfWinPE::new(&meta);
        accepts_isf_object(&pe);
    }
}
