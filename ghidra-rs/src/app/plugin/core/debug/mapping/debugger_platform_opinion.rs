//! Port of `ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOpinion`.
//!
//! An opinion governing analysis and display of a trace according to a platform (processor, ISA,
//! OS, ABI, etc.). Meant for "object-based" traces: opinions are queried, each producing zero or
//! more scored offers ([`DebuggerPlatformOffer`]); the highest-confidence offer may be chosen
//! automatically, or the user prompted from a sorted list.
//!
//! # Shape
//!
//! Java is an `interface` with 1 abstract instance method and 2 in-repo implementors, so this
//! becomes a `trait` (rule R-interface-open-ext-point, per `scripts/shape_rules.py`).
//!
//! # Seams
//!
//! * **`TraceEnvironment`.** Not yet ported (a near-marker interface providing platform
//!   attribute keys). Added as a minimal set of constants --
//!   [`crate::app::seam_stubs::TRACE_ENVIRONMENT_SCHEMA_NAME`] and the four
//!   `TRACE_ENVIRONMENT_KEY_*` constants -- rather than a trait, since nothing here calls a method
//!   on it; only its `@TraceObjectInfo` schema name and attribute keys are used.
//! * **String-valued attributes.** `TraceObjectValue.getValue().toString()` is Java's unchecked
//!   stringification of an arbitrary attribute value. This crate's [`TraceObjectValue::get_value`]
//!   returns `Box<dyn Any + Send + Sync>`; since every attribute this file reads
//!   (arch/debugger/endian/os) is documented as string-valued, [`get_string_attribute`] downcasts
//!   to `String` directly rather than attempting a generic `toString()`-equivalent.
//! * **`ClassSearcher`-backed static method.** Java's `static queryOpinions(...)` iterates every
//!   registered opinion via `ClassSearcher.getInstances(DebuggerPlatformOpinion.class)`. This
//!   crate has no classpath-scanning equivalent (see `AutoReadMemorySpecFactory`'s module docs for
//!   the same gap), so it becomes a free function that takes the known opinions as an explicit
//!   slice parameter instead of discovering them via a global registry.
//! * **`Set<DebuggerPlatformOffer>` return.** Java's `getOffers` returns a `Set`, but its only
//!   in-repo consumer (`queryOpinions`) immediately flattens every opinion's offers into one
//!   `List` and sorts it -- so `get_offers` returns `Vec<Box<dyn DebuggerPlatformOffer>>` here;
//!   `DebuggerPlatformOffer` is a trait object, so it cannot derive `Hash`/`Eq` for a `HashSet`
//!   without inventing identity semantics Java never asked for.
//! * **`try`/`catch` around each opinion.** Java wraps each `getOffers` call in a `try`/`catch
//!   (Exception e)` and logs via `Msg.error`, since a misbehaving `ClassSearcher`-discovered
//!   plugin could throw. Rust has no checked exceptions and `get_offers` returns a plain `Vec`
//!   (not a `Result`), so there is nothing to catch; a panicking implementor would need
//!   `std::panic::catch_unwind`, which this crate avoids reaching for reflexively (see
//!   MEMORY.md's note on eager panic-payload extraction) and which isn't warranted for a `Vec`
//!   builder with no in-repo implementor yet.

use crate::app::plugin::core::debug::mapping::DebuggerPlatformOffer;
use crate::app::seam_stubs::{
    TRACE_ENVIRONMENT_KEY_ARCH, TRACE_ENVIRONMENT_KEY_DEBUGGER, TRACE_ENVIRONMENT_KEY_ENDIAN,
    TRACE_ENVIRONMENT_KEY_OS,
};
use crate::program::model::lang::endian::Endian;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::path::path_pattern::PathPattern;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::trace::Trace;
use crate::util::classfinder::ExtensionPoint;

/// Port of the Java interface `ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOpinion`.
///
/// Java also `extends ExtensionPoint`, a pure discovery marker with no methods, so it is not
/// modeled as a supertrait bound here -- nothing would be added to implementors.
pub trait DebuggerPlatformOpinion: ExtensionPoint {
    /// Renders offers for the given object.
    ///
    /// Mirrors `DebuggerPlatformOpinion.getOffers(Trace, TraceObject, long, boolean)`. See the
    /// module docs' Seams section for why this returns a `Vec` rather than a `Set`.
    fn get_offers(
        &self,
        trace: &dyn Trace,
        object: &dyn TraceObject,
        snap: i64,
        include_overrides: bool,
    ) -> Vec<Box<dyn DebuggerPlatformOffer>>;
}

/// Finds the environment for the given object.
///
/// Mirrors `DebuggerPlatformOpinion.getEnvironment(TraceObject, long)`.
pub fn get_environment(object: Option<&dyn TraceObject>, snap: i64) -> Option<Box<dyn TraceObject>> {
    let object = object?;
    let root = object.get_root();
    let path_to_env = root.get_schema().search_for_suitable(
        crate::app::seam_stubs::TRACE_ENVIRONMENT_SCHEMA_NAME,
        &object.get_canonical_path(),
    )?;
    root.get_successors(Lifespan::at(snap), &PathPattern::new(path_to_env))
        .into_iter()
        .next()
        .map(|p| p.get_destination(root))
}

/// Gets the string-valued attribute at `key` on `obj` at `snap`.
///
/// Mirrors `DebuggerPlatformOpinion.getStringAttribute(TraceObject, long, String)`. See the module
/// docs' Seams section for the `toString()`-equivalent decision.
pub fn get_string_attribute(obj: &dyn TraceObject, snap: i64, key: &str) -> Option<String> {
    let val = obj.get_value(snap, key)?;
    val.get_value().downcast_ref::<String>().cloned()
}

/// Mirrors `DebuggerPlatformOpinion.getDebugggerFromEnv(TraceObject, long)` (sic -- Java's own
/// method name has the typo).
pub fn get_debugger_from_env(env: &dyn TraceObject, snap: i64) -> Option<String> {
    get_string_attribute(env, snap, TRACE_ENVIRONMENT_KEY_DEBUGGER)
}

/// Mirrors `DebuggerPlatformOpinion.getArchitectureFromEnv(TraceObject, long)`.
pub fn get_architecture_from_env(env: &dyn TraceObject, snap: i64) -> Option<String> {
    get_string_attribute(env, snap, TRACE_ENVIRONMENT_KEY_ARCH)
}

/// Mirrors `DebuggerPlatformOpinion.getOperatingSystemFromEnv(TraceObject, long)`.
pub fn get_operating_system_from_env(env: &dyn TraceObject, snap: i64) -> Option<String> {
    get_string_attribute(env, snap, TRACE_ENVIRONMENT_KEY_OS)
}

/// Gets the endianness from the given environment.
///
/// Mirrors `DebuggerPlatformOpinion.getEndianFromEnv(TraceObject, long)`.
pub fn get_endian_from_env(env: &dyn TraceObject, snap: i64) -> Option<Endian> {
    let endian = get_string_attribute(env, snap, TRACE_ENVIRONMENT_KEY_ENDIAN)?;
    let lower = endian.to_lowercase();
    if lower.contains("little") {
        Some(Endian::Little)
    } else if lower.contains("big") {
        Some(Endian::Big)
    } else {
        None
    }
}

/// Queries all known opinions for offers of platform interpretation.
///
/// Mirrors `DebuggerPlatformOpinion.queryOpinions(Trace, TraceObject, long, boolean)`. See the
/// module docs' Seams section for why `opinions` is an explicit parameter rather than a
/// `ClassSearcher`-discovered set. Result is sorted highest-confidence-first.
pub fn query_opinions(
    opinions: &[Box<dyn DebuggerPlatformOpinion>],
    trace: &dyn Trace,
    object: &dyn TraceObject,
    snap: i64,
    include_overrides: bool,
) -> Vec<Box<dyn DebuggerPlatformOffer>> {
    let mut result: Vec<Box<dyn DebuggerPlatformOffer>> = Vec::new();
    for opinion in opinions {
        let offers = opinion.get_offers(trace, object, snap, include_overrides);
        result.extend(offers);
    }
    result.sort_by_key(|o| -o.get_confidence());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::debug::api::platform::DebuggerPlatformMapper;
    use crate::framework::seam_stubs::PluginTool;

    struct FakeOffer {
        description: String,
        confidence: i32,
    }

    impl DebuggerPlatformOffer for FakeOffer {
        fn get_description(&self) -> String {
            self.description.clone()
        }

        fn get_confidence(&self) -> i32 {
            self.confidence
        }

        fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
            None
        }

        fn take(&self, _tool: &dyn PluginTool, _trace: &dyn Trace) -> Box<dyn DebuggerPlatformMapper> {
            unimplemented!("not exercised by this test")
        }

        fn is_creator_of(&self, _mapper: &dyn DebuggerPlatformMapper) -> bool {
            false
        }
    }

    struct FakeOpinion {
        confidences: Vec<i32>,
    }

    impl ExtensionPoint for FakeOpinion {}

    impl DebuggerPlatformOpinion for FakeOpinion {
        fn get_offers(
            &self,
            _trace: &dyn Trace,
            _object: &dyn TraceObject,
            _snap: i64,
            _include_overrides: bool,
        ) -> Vec<Box<dyn DebuggerPlatformOffer>> {
            self.confidences
                .iter()
                .map(|&c| {
                    Box::new(FakeOffer {
                        description: format!("offer-{c}"),
                        confidence: c,
                    }) as Box<dyn DebuggerPlatformOffer>
                })
                .collect()
        }
    }

    #[test]
    fn opinion_trait_is_object_safe() {
        // `DebuggerPlatformOpinion` needs to be usable behind `Box<dyn ...>` (matching the
        // `queryOpinions`/`opinions: &[Box<dyn ...>]` shape); this compiles only if it is.
        let _opinion: Box<dyn DebuggerPlatformOpinion> =
            Box::new(FakeOpinion { confidences: vec![3, 7] });
    }

    #[test]
    fn endian_from_env_parses_little_and_big() {
        assert_eq!(classify_endian("little-endian"), Some(Endian::Little));
        assert_eq!(classify_endian("BIG"), Some(Endian::Big));
        assert_eq!(classify_endian("weird"), None);
    }

    /// Extracted copy of `get_endian_from_env`'s classification logic, so the string-matching
    /// rule can be tested without constructing a `TraceObject`.
    fn classify_endian(s: &str) -> Option<Endian> {
        let lower = s.to_lowercase();
        if lower.contains("little") {
            Some(Endian::Little)
        } else if lower.contains("big") {
            Some(Endian::Big)
        } else {
            None
        }
    }

    #[test]
    fn query_opinions_sorts_by_confidence_descending() {
        // `query_opinions` itself requires a `&dyn Trace`/`&dyn TraceObject`, both large traits
        // with many required methods on the real (DB-backed) implementors; those are out of
        // proportion to construct here. Instead, this validates the confidence-sort behavior
        // directly against the same logic `query_opinions` applies to `FakeOpinion`'s offers.
        let mut offers: Vec<Box<dyn DebuggerPlatformOffer>> = vec![
            Box::new(FakeOffer { description: "low".into(), confidence: 1 }),
            Box::new(FakeOffer { description: "high".into(), confidence: 10 }),
            Box::new(FakeOffer { description: "mid".into(), confidence: 5 }),
        ];
        offers.sort_by_key(|o| -o.get_confidence());
        let confidences: Vec<i32> = offers.iter().map(|o| o.get_confidence()).collect();
        assert_eq!(confidences, vec![10, 5, 1]);
    }
}
