//! Port of `ghidra.app.util.bin.format.golang.structmapping.StructureMarkup`.

use std::io;

use super::markup_session::MarkupSession;
use super::structure_context::StructureContext;
use super::structure_mapped::{MarkupItem, StructureMapped};

/// Optional interface that structure mapped types can implement that allows them to control how
/// their instances are marked up.
///
/// Port of the Java `StructureMarkup<T>` interface. A type opts in with
/// `#[structure_mapping(.., structure_markup)]`, which makes the derived descriptor call these
/// methods from [`MarkupSession::markup_structure`].
///
/// Java's only abstract method, `getStructureContext()`, is the instance's own
/// `#[context_field]` [`StructureContext`], which [`StructureMapped::structure_context`] already
/// returns; [`get_structure_context`](Self::get_structure_context) reaches it from there, so
/// implementors override only the defaults they need.
pub trait StructureMarkup: StructureMapped {
    /// `getStructureContext()`: the context that describes how `self` was read from a program.
    ///
    /// # Errors
    /// When the type declares no `StructureContext` context field.
    fn get_structure_context(&self) -> io::Result<&StructureContext<Self>> {
        StructureMapped::structure_context(self).ok_or_else(|| {
            io::Error::other(format!("No StructureContext for {}", Self::descriptor().type_name))
        })
    }

    /// `getStructureName()`: the name of the instance, typically retrieved from data found
    /// inside the instance; `None` if this instance does not have a name.
    fn structure_name(&self) -> io::Result<Option<String>> {
        Ok(None)
    }

    /// `getStructureLabel()`: a string that can be used to place a label on the instance.
    ///
    /// The default queries [`structure_name`](Self::structure_name); if it provides a value, the
    /// label looks like `"name___mappingstructname"`, where `mappingstructname` is the structure
    /// name from the structure context's mapping info. `None` if there is no valid label.
    fn structure_label(&self) -> io::Result<Option<String>> {
        match self.structure_name()? {
            Some(name) => {
                let ctx = self.get_structure_context()?;
                Ok(Some(format!("{}___{}", name, ctx.get_mapping_info().get_structure_name())))
            }
            None => Ok(None),
        }
    }

    /// `getStructureNamespace()`: the namespace that any labels should be placed in; `None` if
    /// there is no specific namespace for this instance.
    fn structure_namespace(&self) -> io::Result<Option<String>> {
        Ok(None)
    }

    /// `additionalMarkup(MarkupSession)`: called to allow the implementor to perform custom
    /// markup of itself.
    ///
    /// # Errors
    /// If the markup fails or the session's monitor is cancelled.
    fn additional_markup(&self, _session: &mut MarkupSession<'_>) -> io::Result<()> {
        Ok(())
    }

    /// `getExternalInstancesToMarkup()`: items that should be recursively marked up.
    fn external_instances_to_markup(&self) -> io::Result<Vec<Box<dyn MarkupItem + '_>>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::format::golang::structmapping::test_support::{byte_reader, simple, structure, test_mapper, TagContext};
    use crate::format::golang::structmapping::{DataTypeMapper, StructureMapped};
    use crate::program::model::data::data_type::DataType;

    #[derive(StructureMapped)]
    #[structure_mapping(structure_name = "GoThing", structure_markup)]
    struct NamedThing {
        #[context_field]
        context: StructureContext<NamedThing>,
        #[field_mapping]
        id: u8,
    }

    impl StructureMarkup for NamedThing {
        fn structure_name(&self) -> io::Result<Option<String>> {
            Ok((self.id != 0).then(|| format!("thing{}", self.id)))
        }

        fn structure_namespace(&self) -> io::Result<Option<String>> {
            Ok(Some("pkg".to_string()))
        }
    }

    #[derive(StructureMapped)]
    #[structure_mapping(structure_name = "GoThing", structure_markup)]
    struct DefaultThing {
        #[context_field]
        context: StructureContext<DefaultThing>,
        #[field_mapping]
        id: u8,
    }

    impl StructureMarkup for DefaultThing {}

    #[derive(StructureMapped)]
    #[structure_mapping(structure_name = "GoThing", structure_markup)]
    struct NoContextThing {
        #[field_mapping]
        id: u8,
    }

    impl StructureMarkup for NoContextThing {
        fn structure_name(&self) -> io::Result<Option<String>> {
            Ok(Some("x".to_string()))
        }
    }

    fn mapper() -> DataTypeMapper {
        let mut mapper = test_mapper(vec![Arc::new(|| {
            Box::new(structure("GoThing", vec![("id", simple("byte", 1))])) as Box<dyn DataType>
        })]);
        let ctx = TagContext(vec![]);
        mapper.register_structure::<NamedThing>(&ctx).unwrap();
        mapper.register_structure::<DefaultThing>(&ctx).unwrap();
        mapper.register_structure::<NoContextThing>(&ctx).unwrap();
        mapper
    }

    #[test]
    fn defaults_have_no_name_label_namespace_or_external_instances() {
        let mapper = mapper();
        let t: DefaultThing = mapper.read_structure(byte_reader(vec![5], true).as_mut()).unwrap();
        assert_eq!(t.structure_name().unwrap(), None);
        assert_eq!(t.structure_label().unwrap(), None);
        assert_eq!(t.structure_namespace().unwrap(), None);
        assert!(t.external_instances_to_markup().unwrap().is_empty());
        assert_eq!(t.get_structure_context().unwrap().get_structure_start(), 0);
    }

    #[test]
    fn structure_label_combines_name_and_mapping_structure_name() {
        let mapper = mapper();
        let t: NamedThing = mapper.read_structure(byte_reader(vec![7], true).as_mut()).unwrap();
        assert_eq!(t.structure_label().unwrap().as_deref(), Some("thing7___GoThing"));
        let t: NamedThing = mapper.read_structure(byte_reader(vec![0], true).as_mut()).unwrap();
        assert_eq!(t.structure_label().unwrap(), None, "no name, no label");
    }

    #[test]
    fn label_without_a_structure_context_is_an_error() {
        let mapper = mapper();
        let t: NoContextThing = mapper.read_structure(byte_reader(vec![1], true).as_mut()).unwrap();
        let err = t.structure_label().unwrap_err();
        assert_eq!(err.to_string(), "No StructureContext for NoContextThing");
    }

    #[test]
    fn derive_wires_the_hooks_into_the_descriptor() {
        let mapper = mapper();
        let t: NamedThing = mapper.read_structure(byte_reader(vec![3], true).as_mut()).unwrap();
        let hooks = NamedThing::descriptor().structure_markup.as_ref().unwrap();
        assert_eq!((hooks.structure_label)(&t).unwrap().as_deref(), Some("thing3___GoThing"));
        assert_eq!((hooks.structure_namespace)(&t).unwrap().as_deref(), Some("pkg"));
    }
}
