//! Port of `generic.lsh.vector.WeightedLSHCosineVectorFactory`.

use std::io;

use crate::generic::lsh::vector::lsh_cosine_vector::LSHCosineVector;
use crate::generic::lsh::vector::lsh_vector::LSHVector;
use crate::generic::lsh::vector::lsh_vector_factory::{LSHVectorFactory, LSHVectorFactoryBase};
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A concrete [`LSHVectorFactory`] that builds and restores [`LSHCosineVector`]s.
///
/// Port of `generic.lsh.vector.WeightedLSHCosineVectorFactory`, which `extends
/// LSHVectorFactory` and supplies its four abstract "build a vector" methods. Following this
/// crate's composition-over-inheritance convention (already established by
/// [`LSHVectorFactoryBase`]'s own docs), the inherited `weightFactory`/`idfLookup`/`settings`
/// state lives in a composed `base: LSHVectorFactoryBase` field, reached here via
/// [`LSHVectorFactoryBase::weight_factory`]/[`LSHVectorFactoryBase::idf_lookup`] -- the direct
/// Rust equivalent of Java reading its inherited `protected` fields.
#[derive(Default)]
pub struct WeightedLSHCosineVectorFactory {
    base: LSHVectorFactoryBase,
}

impl WeightedLSHCosineVectorFactory {
    /// Creates a new, unloaded factory (mirrors the implicit no-arg Java constructor).
    pub fn new() -> Self {
        Self::default()
    }
}

impl AsRef<LSHVectorFactoryBase> for WeightedLSHCosineVectorFactory {
    fn as_ref(&self) -> &LSHVectorFactoryBase {
        &self.base
    }
}

impl AsMut<LSHVectorFactoryBase> for WeightedLSHCosineVectorFactory {
    fn as_mut(&mut self) -> &mut LSHVectorFactoryBase {
        &mut self.base
    }
}

impl LSHVectorFactory for WeightedLSHCosineVectorFactory {
    type Vector = LSHCosineVector;

    /// Mirrors `buildZeroVector()`.
    fn build_zero_vector(&self) -> LSHCosineVector {
        LSHCosineVector::new()
    }

    /// Mirrors `buildVector(int[])`.
    ///
    /// # Panics
    ///
    /// Panics if this factory hasn't been loaded yet (reading `weightFactory`/`idfLookup`
    /// directly, unloaded, is a Java `NullPointerException`) -- see
    /// [`LSHVectorFactoryBase::weight_factory`]'s parity note.
    fn build_vector(&self, feature: &[i32]) -> LSHCosineVector {
        LSHCosineVector::from_features(feature, self.base.weight_factory(), self.base.idf_lookup())
    }

    /// Mirrors `restoreVectorFromXml(XmlPullParser)`.
    ///
    /// # Panics
    ///
    /// Java's method declares no checked exception, so a parse failure inside `restoreXml`
    /// would only ever surface as an unchecked exception there too; this port `.unwrap()`s the
    /// `Result` from [`LSHVector::restore_xml`] for the same reason, panicking on malformed
    /// input rather than returning a `Result` the trait's signature has no room for. Also
    /// panics under the same unloaded-factory condition as [`Self::build_vector`].
    fn restore_vector_from_xml<P: XmlPullParser>(&self, parser: &mut P) -> LSHCosineVector {
        let mut vector = LSHCosineVector::new();
        vector
            .restore_xml(parser, self.base.weight_factory(), self.base.idf_lookup())
            .expect("malformed LSHCosineVector XML (Java's restoreXml declares no checked exception either)");
        vector
    }

    /// Mirrors `restoreVectorFromSql(String)`.
    ///
    /// # Panics
    ///
    /// Panics under the same unloaded-factory condition as [`Self::build_vector`].
    fn restore_vector_from_sql(&self, sql: &str) -> io::Result<LSHCosineVector> {
        let mut vector = LSHCosineVector::new();
        vector.restore_sql(sql, self.base.weight_factory(), self.base.idf_lookup())?;
        Ok(vector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::lsh::vector::idf_lookup::IdfLookup;
    use crate::generic::lsh::vector::weight_factory::WeightFactory;

    fn loaded_factory() -> WeightedLSHCosineVectorFactory {
        let mut factory = WeightedLSHCosineVectorFactory::new();
        let mut wf = WeightFactory::new();
        wf.set(&vec![1.0; wf.get_size()]).unwrap();
        factory.set(wf, IdfLookup::new(), 0);
        factory
    }

    #[test]
    fn build_zero_vector_is_empty() {
        let factory = loaded_factory();
        let v = factory.build_zero_vector();
        assert_eq!(v.num_entries(), 0);
        assert_eq!(v.get_length(), 0.0);
    }

    #[test]
    fn build_vector_counts_term_frequency() {
        let factory = loaded_factory();
        let v = factory.build_vector(&[5, 5, 5, 7, 9, 9]);
        assert_eq!(v.num_entries(), 3);
        let entries = v.get_entries();
        assert_eq!(entries[0].get_hash(), 5);
        assert_eq!(entries[0].get_tf(), 3);
    }

    #[test]
    #[should_panic]
    fn build_vector_before_loading_panics() {
        let factory = WeightedLSHCosineVectorFactory::new();
        let _ = factory.build_vector(&[1, 2, 3]);
    }

    #[test]
    fn restore_vector_from_sql_round_trips_a_built_vector() {
        let factory = loaded_factory();
        let built = factory.build_vector(&[1, 1, 2]);
        let sql = built.save_sql();
        let restored = factory.restore_vector_from_sql(&sql).unwrap();
        assert_eq!(restored.num_entries(), built.num_entries());
        assert_eq!(restored.get_entries()[0].get_hash(), 1);
    }

    #[test]
    fn factory_default_is_not_loaded() {
        let factory = WeightedLSHCosineVectorFactory::default();
        assert!(!factory.is_loaded());
    }
}
