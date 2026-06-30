/// A named data-type organization entry capturing its byte-size and alignment.
///
/// Package-private helper used within the data-type subsystem to represent a
/// single named primitive together with its storage size and required alignment.
pub(crate) struct CustomOrganization {
    name: String,
    size: i32,
    alignment: i32,
}

impl CustomOrganization {
    pub(crate) fn new(name: impl Into<String>, size: i32, alignment: i32) -> Self {
        Self {
            name: name.into(),
            size,
            alignment,
        }
    }

    pub(crate) fn get_name(&self) -> &str {
        &self.name
    }

    pub(crate) fn get_size(&self) -> i32 {
        self.size
    }

    pub(crate) fn get_alignment(&self) -> i32 {
        self.alignment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_all_fields() {
        let org = CustomOrganization::new("int", 4, 4);
        assert_eq!(org.get_name(), "int");
        assert_eq!(org.get_size(), 4);
        assert_eq!(org.get_alignment(), 4);
    }

    #[test]
    fn size_and_alignment_can_differ() {
        let org = CustomOrganization::new("double", 8, 4);
        assert_eq!(org.get_size(), 8);
        assert_eq!(org.get_alignment(), 4);
    }

    #[test]
    fn name_accepts_string_literal() {
        let org = CustomOrganization::new("char", 1, 1);
        assert_eq!(org.get_name(), "char");
    }

    #[test]
    fn name_accepts_owned_string() {
        let name = String::from("long long");
        let org = CustomOrganization::new(name, 8, 8);
        assert_eq!(org.get_name(), "long long");
    }

    #[test]
    fn single_byte_type() {
        let org = CustomOrganization::new("byte", 1, 1);
        assert_eq!(org.get_size(), 1);
        assert_eq!(org.get_alignment(), 1);
    }
}
