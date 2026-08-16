use crate::format::seam_stubs::{MarkupSession, StructureContext};

/// Optional interface that structure mapped classes can implement that allows them to
/// control how their class is marked up.
///
/// This is the Rust equivalent of the Java `StructureMarkup<T>` interface from
/// `ghidra.app.util.bin.format.golang.structmapping`.
///
/// In Java only `getStructureContext()` is abstract; the remaining methods have default
/// implementations that this trait mirrors.
pub trait StructureMarkup<T> {
    /// Returns the structure context that describes how `self` was read from a program.
    fn structure_context(&self) -> &dyn StructureContext<T>;

    /// Returns the name of the instance, typically retrieved from data found inside the
    /// instance.
    ///
    /// Returns `Ok(None)` if this instance does not have a name.
    fn structure_name(&self) -> std::io::Result<Option<String>> {
        Ok(None)
    }

    /// Returns a string that can be used to place a label on the instance.
    ///
    /// The default implementation queries [`structure_name`](Self::structure_name); if it
    /// provides a value, this produces a string that looks like
    /// `"name___mappingstructname"`, where `mappingstructname` is the structure name from
    /// the structure context's mapping info.
    ///
    /// Returns `Ok(None)` if there is not a valid label for the instance.
    fn structure_label(&self) -> std::io::Result<Option<String>> {
        match self.structure_name()? {
            Some(name) => {
                let mapping_name = self.structure_context().get_mapping_info().structure_name();
                Ok(Some(format!("{}___{}", name, mapping_name)))
            }
            None => Ok(None),
        }
    }

    /// Returns the namespace that any labels should be placed in.
    ///
    /// Returns `Ok(None)` if there is no specific namespace for this instance.
    fn structure_namespace(&self) -> std::io::Result<Option<String>> {
        Ok(None)
    }

    /// Called to allow the implementor to perform custom markup of itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the markup operation fails or is cancelled.
    fn additional_markup(&self, _session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Returns a list of items that should be recursively marked up.
    fn external_instances_to_markup(&self) -> std::io::Result<Vec<Box<dyn std::any::Any>>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::StructureMappingInfo;
    use crate::program::model::address::Address;
    use std::any::Any;

    struct TestType;

    struct MockStructureMappingInfo {
        name: String,
    }

    impl StructureMappingInfo<TestType> for MockStructureMappingInfo {
        fn structure_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockStructureContext {
        mapping_name: String,
    }

    impl StructureContext<TestType> for MockStructureContext {
        fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<TestType>> {
            Box::new(MockStructureMappingInfo { name: self.mapping_name.clone() })
        }

        fn get_data_type_mapper(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_containing_field_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
            unimplemented!()
        }

        fn get_structure_address(&self) -> Address {
            unimplemented!()
        }

        fn get_field_address(&self, _field_offset: i64) -> Address {
            unimplemented!()
        }

        fn get_field_location(&self, _field_offset: i64) -> i64 {
            0
        }

        fn get_structure_start(&self) -> i64 {
            0
        }

        fn get_structure_end(&self) -> i64 {
            1000
        }

        fn get_structure_length(&self) -> i32 {
            1000
        }

        fn get_structure_instance(&self) -> &TestType {
            unimplemented!()
        }

        fn get_reader(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_field_reader(&self, _field_offset: i64) -> Box<dyn Any> {
            unimplemented!()
        }

        fn create_field_context(&self, _fmi: &dyn Any, _include_reader: bool) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_structure_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::structure::Structure>> {
            unimplemented!()
        }

        fn to_string(&self) -> String {
            "MockStructureContext".to_string()
        }
    }

    struct NamedGoType {
        name: Option<String>,
        context: MockStructureContext,
    }

    impl StructureMarkup<TestType> for NamedGoType {
        fn structure_context(&self) -> &dyn StructureContext<TestType> {
            &self.context
        }

        fn structure_name(&self) -> std::io::Result<Option<String>> {
            Ok(self.name.clone())
        }
    }

    struct DefaultGoType {
        context: MockStructureContext,
    }

    impl StructureMarkup<TestType> for DefaultGoType {
        fn structure_context(&self) -> &dyn StructureContext<TestType> {
            &self.context
        }
    }

    #[test]
    fn default_structure_name_is_none() {
        let t = DefaultGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        assert_eq!(t.structure_name().unwrap(), None);
    }

    #[test]
    fn default_structure_label_is_none_when_name_is_none() {
        let t = DefaultGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        assert_eq!(t.structure_label().unwrap(), None);
    }

    #[test]
    fn structure_label_combines_name_and_mapping_structure_name() {
        let t = NamedGoType {
            name: Some("runtime.foo".to_string()),
            context: MockStructureContext { mapping_name: "GoType".to_string() },
        };
        assert_eq!(t.structure_label().unwrap().as_deref(), Some("runtime.foo___GoType"));
    }

    #[test]
    fn default_structure_namespace_is_none() {
        let t = DefaultGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        assert_eq!(t.structure_namespace().unwrap(), None);
    }

    #[test]
    fn default_external_instances_to_markup_is_empty() {
        let t = DefaultGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        assert!(t.external_instances_to_markup().unwrap().is_empty());
    }

    struct RecordingMarkupSession {
        called: std::sync::Mutex<bool>,
    }

    impl MarkupSession for RecordingMarkupSession {
        fn get_program(&self) -> Box<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_mapping_context(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn get_markedup_addresses(&self) -> Box<dyn Any> {
            unimplemented!()
        }

        fn markup(&self, _obj: &dyn Any, _nested: bool) -> std::io::Result<()> {
            *self.called.lock().unwrap() = true;
            Ok(())
        }

        fn markup_address(&self, _addr: Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_address_if_undefined(&self, _addr: Address, _dt: &dyn Any) -> std::io::Result<()> {
            Ok(())
        }

        fn label_structure(&self, _obj: &dyn Any, _symbol_name: &str, _namespace_name: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn label_address(&self, _addr: Address, _symbol_name: &str) -> std::io::Result<()> {
            Ok(())
        }

        fn append_comment(
            &self,
            _field_context: &dyn Any,
            _comment_type: &dyn Any,
            _prefix: &str,
            _comment: &str,
            _sep: &str,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_structure(&self, _structure_context: &dyn Any, _nested: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn markup_array_element_references(
            &self,
            _array_addr: Address,
            _element_size: i32,
            _target_addrs: Vec<Address>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn create_function_if_missing(&self, _name: &str, _ns: &dyn Any, _addr: Address) -> Box<dyn Any> {
            unimplemented!()
        }

        fn add_reference(&self, _field_context: &dyn Any, _ref_dest: Address) {}

        fn log_warning_at(&self, _addr: Address, _msg: &str) {}
    }

    #[test]
    fn default_additional_markup_is_a_no_op() {
        let t = DefaultGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        let session = RecordingMarkupSession { called: std::sync::Mutex::new(false) };
        assert!(t.additional_markup(&session).is_ok());
        assert!(!*session.called.lock().unwrap());
    }

    struct MarkingUpGoType {
        context: MockStructureContext,
    }

    impl StructureMarkup<TestType> for MarkingUpGoType {
        fn structure_context(&self) -> &dyn StructureContext<TestType> {
            &self.context
        }

        fn additional_markup(&self, session: &dyn MarkupSession) -> Result<(), Box<dyn std::error::Error>> {
            session.markup(&0i32 as &dyn Any, false)?;
            Ok(())
        }
    }

    #[test]
    fn overridden_additional_markup_calls_session() {
        let t = MarkingUpGoType { context: MockStructureContext { mapping_name: "GoType".to_string() } };
        let session = RecordingMarkupSession { called: std::sync::Mutex::new(false) };
        assert!(t.additional_markup(&session).is_ok());
        assert!(*session.called.lock().unwrap());
    }
}
