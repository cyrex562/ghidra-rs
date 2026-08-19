use std::any::{Any, TypeId};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

use crate::debug::api::{Decoder, ValStr};

/// A type-erased handle to a value stored in an [`Arguments`] map.
///
/// Mirrors the role Java's `ValStr<?>` wildcard plays in
/// `ghidra.debug.api.tracermi.LaunchParameter`, where a single map holds values of many
/// different concrete types.
pub trait ValStrAny: fmt::Debug + Send + Sync {
    /// The `TypeId` of the wrapped value's type.
    fn type_id(&self) -> TypeId;

    /// Returns the wrapped value as `dyn Any` for downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl<T: fmt::Debug + Send + Sync + 'static> ValStrAny for ValStr<T> {
    fn type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A type-erased map of parameter name to value, keyed by parameter name.
///
/// Mirrors Java's `Map<String, ValStr<?>>`.
pub type Arguments = HashMap<String, Box<dyn ValStrAny>>;

/// A type-erased handle to a [`LaunchParameter<T>`] for some unspecified `T`.
///
/// Mirrors the role Java's `LaunchParameter<?>` wildcard plays in [`map_of`] and
/// [`validate_arguments`].
pub trait LaunchParameterAny: fmt::Debug + Send + Sync {
    /// The parameter's name.
    fn name(&self) -> &str;

    /// The `TypeId` of the parameter's value type.
    fn type_id(&self) -> TypeId;

    /// The name of the parameter's value type, for diagnostics.
    fn type_name(&self) -> &'static str;
}

impl<T: fmt::Debug + Send + Sync + 'static> LaunchParameterAny for LaunchParameter<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }

    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }
}

/// An ordered map of parameter name to parameter, preserving insertion order.
///
/// Mirrors Java's `Map<String, LaunchParameter<?>>`, which is always constructed as a
/// `LinkedHashMap`.
pub type ParameterMap = Vec<(String, Arc<dyn LaunchParameterAny>)>;

/// A decoder that matches a string against the `to_string()` of a fixed set of choices.
///
/// Backs [`LaunchParameter::with_choices`].
struct ChoiceDecoder<T> {
    choices: Vec<T>,
}

impl<T: Clone + fmt::Display> Decoder for ChoiceDecoder<T> {
    type Output = T;

    /// # Panics
    /// Panics if `string` does not match the `to_string()` of any choice. Java's
    /// equivalent lambda returns `null` in this case; Rust's non-nullable `T` cannot
    /// represent that, so this is a deliberate, documented deviation.
    fn decode(&self, string: &str) -> T {
        self.choices
            .iter()
            .find(|choice| choice.to_string() == string)
            .cloned()
            .unwrap_or_else(|| {
                panic!("'{string}' does not match any of this parameter's choices")
            })
    }
}

/// A single named launch parameter accepted by a trace-RMI launch offer.
///
/// Mirrors `ghidra.debug.api.tracermi.LaunchParameter<T>`. Java's `Class<T> type` field
/// exists only to recover the erased `T` at runtime; Rust's generics keep `T` statically
/// known, so it is not stored as data here. [`LaunchParameter::type_id`] and
/// [`LaunchParameter::type_name`] provide the same information on demand, and are also
/// exposed through [`LaunchParameterAny`] for callers that only hold a type-erased handle.
pub struct LaunchParameter<T> {
    name: String,
    display: String,
    description: String,
    required: bool,
    choices: Vec<T>,
    default_value: ValStr<T>,
    decoder: Box<dyn Decoder<Output = T> + Send + Sync>,
}

impl<T: fmt::Debug> fmt::Debug for LaunchParameter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchParameter")
            .field("name", &self.name)
            .field("display", &self.display)
            .field("description", &self.description)
            .field("required", &self.required)
            .field("choices", &self.choices)
            .field("default_value", &self.default_value)
            .finish_non_exhaustive()
    }
}

impl<T> LaunchParameter<T> {
    /// Creates a parameter with no fixed set of choices.
    ///
    /// Mirrors `LaunchParameter.create`, minus the `Class<T> type` argument (see the
    /// type-level doc comment).
    pub fn create(
        name: impl Into<String>,
        display: impl Into<String>,
        description: impl Into<String>,
        required: bool,
        default_value: ValStr<T>,
        decoder: Box<dyn Decoder<Output = T> + Send + Sync>,
    ) -> Self {
        LaunchParameter {
            name: name.into(),
            display: display.into(),
            description: description.into(),
            required,
            choices: Vec::new(),
            default_value,
            decoder,
        }
    }

    /// The parameter's name, used as its key in an [`Arguments`] map.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The parameter's human-readable display label.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The parameter's human-readable description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Whether a value for this parameter must be supplied.
    pub fn required(&self) -> bool {
        self.required
    }

    /// The fixed set of choices for this parameter's value, if any.
    pub fn choices(&self) -> &[T] {
        &self.choices
    }

    /// The default value used when no argument is supplied.
    pub fn default_value(&self) -> &ValStr<T> {
        &self.default_value
    }

    /// Decodes `string` into a `ValStr<T>` using this parameter's decoder.
    pub fn decode(&self, string: &str) -> ValStr<T> {
        self.decoder.decode_val_str(string)
    }
}

impl<T: 'static> LaunchParameter<T> {
    /// The `TypeId` of this parameter's value type.
    pub fn type_id(&self) -> TypeId {
        TypeId::of::<T>()
    }

    /// The name of this parameter's value type, for diagnostics.
    pub fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }
}

impl<T: Clone + Eq + Hash + fmt::Display> LaunchParameter<T> {
    /// Creates a parameter restricted to a fixed set of choices.
    ///
    /// Mirrors `LaunchParameter.choices`. Renamed from `choices` to `with_choices`
    /// because Rust does not allow an inherent method and an associated function to
    /// share a name within one `impl` block, and this type already has an instance
    /// accessor named [`LaunchParameter::choices`].
    pub fn with_choices(
        name: impl Into<String>,
        display: impl Into<String>,
        description: impl Into<String>,
        choices: impl IntoIterator<Item = T>,
        default_value: ValStr<T>,
    ) -> Self
    where
        T: Send + Sync + 'static,
    {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();
        for choice in choices {
            if seen.insert(choice.clone()) {
                deduped.push(choice);
            }
        }
        let decoder_choices = deduped.clone();
        LaunchParameter {
            name: name.into(),
            display: display.into(),
            description: description.into(),
            required: false,
            choices: deduped,
            default_value,
            decoder: Box::new(ChoiceDecoder { choices: decoder_choices }),
        }
    }
}

impl<T: Clone + 'static> LaunchParameter<T> {
    /// Looks up this parameter's value in `arguments`, falling back to the default.
    ///
    /// Mirrors `LaunchParameter.get`.
    ///
    /// # Panics
    /// Panics if `arguments` holds a value under this parameter's name whose type does
    /// not match `T` (mirrors `ValStr.cast` throwing `ClassCastException`), or if no
    /// value is present and this parameter is [`required`](Self::required) (mirrors the
    /// `IllegalArgumentException` for a missing required parameter).
    pub fn get(&self, arguments: &Arguments) -> ValStr<T> {
        if let Some(val) = arguments.get(&self.name) {
            return val
                .as_any()
                .downcast_ref::<ValStr<T>>()
                .unwrap_or_else(|| {
                    panic!(
                        "val for '{}' is not a {}",
                        self.name,
                        std::any::type_name::<T>()
                    )
                })
                .clone();
        }
        if self.required {
            panic!(
                "Missing required parameter '{}' ({})",
                self.display, self.name
            );
        }
        self.default_value.clone()
    }
}

impl<T: fmt::Debug + Send + Sync + 'static> LaunchParameter<T> {
    /// Stores `value` in `arguments` under this parameter's name.
    ///
    /// Mirrors `LaunchParameter.set`.
    pub fn set(&self, arguments: &mut Arguments, value: ValStr<T>) {
        arguments.insert(self.name.clone(), Box::new(value));
    }
}

/// Groups `parameters` by name, preserving insertion order.
///
/// Mirrors the `LaunchParameter.mapOf` overloads (Java's `Collection` and varargs forms
/// collapse to one function, since `impl IntoIterator` accepts both a `Vec` and an
/// array). This is a free function rather than an associated function of
/// `LaunchParameter<T>` because it operates over parameters of differing `T`.
///
/// # Panics
/// Panics if two parameters share the same name.
pub fn map_of(
    parameters: impl IntoIterator<Item = Arc<dyn LaunchParameterAny>>,
) -> ParameterMap {
    let mut result: ParameterMap = Vec::new();
    for param in parameters {
        let name = param.name().to_owned();
        if let Some((_, existing)) = result.iter().find(|(n, _)| *n == name) {
            panic!("Duplicate names in parameter map: first={existing:?}, second={param:?}");
        }
        result.push((name, param));
    }
    result
}

/// Validates that `arguments` contains only keys known to `parameters`, and that each
/// value's type matches its parameter's declared type.
///
/// Mirrors `LaunchParameter.validateArguments`. Java additionally skips the type check
/// for an argument whose value is `null`; Rust's `Arguments` map cannot hold a typed
/// null, so every value's type is checked.
///
/// # Panics
/// Panics if `arguments` has a key absent from `parameters`, or if any value's type
/// does not match its parameter's declared type.
pub fn validate_arguments(parameters: &ParameterMap, arguments: Arguments) -> Arguments {
    let known: HashSet<&str> = parameters.iter().map(|(name, _)| name.as_str()).collect();
    let extraneous: BTreeSet<&String> =
        arguments.keys().filter(|key| !known.contains(key.as_str())).collect();
    if !extraneous.is_empty() {
        panic!("Extraneous parameters: {extraneous:?}");
    }

    let mut type_errors: Vec<(String, String)> = Vec::new();
    for (name, val) in &arguments {
        let (_, param) = parameters
            .iter()
            .find(|(n, _)| n == name)
            .expect("arguments keys were checked to be a subset of parameter names above");
        if ValStrAny::type_id(val.as_ref()) != LaunchParameterAny::type_id(param.as_ref()) {
            type_errors.push((
                name.clone(),
                format!("val '{val:?}' is not a {}", param.type_name()),
            ));
        }
    }
    if !type_errors.is_empty() {
        panic!("Type errors: {type_errors:?}");
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IntDecoder;
    impl Decoder for IntDecoder {
        type Output = i64;
        fn decode(&self, string: &str) -> i64 {
            string.parse().unwrap()
        }
    }

    fn int_param(name: &str, required: bool, default: i64) -> LaunchParameter<i64> {
        LaunchParameter::create(
            name,
            format!("{name} display"),
            format!("{name} description"),
            required,
            ValStr::from_val(default),
            Box::new(IntDecoder),
        )
    }

    #[test]
    fn create_reports_accessors() {
        let param = int_param("count", true, 0);
        assert_eq!(param.name(), "count");
        assert_eq!(param.display(), "count display");
        assert_eq!(param.description(), "count description");
        assert!(param.required());
        assert!(param.choices().is_empty());
        assert_eq!(param.default_value().val, 0);
    }

    #[test]
    fn decode_uses_configured_decoder() {
        let param = int_param("count", false, 0);
        let decoded = param.decode("42");
        assert_eq!(decoded.val, 42);
        assert_eq!(decoded.str, "42");
    }

    #[test]
    fn get_returns_default_when_absent_and_not_required() {
        let param = int_param("count", false, 7);
        let arguments: Arguments = HashMap::new();
        assert_eq!(param.get(&arguments).val, 7);
    }

    #[test]
    #[should_panic(expected = "Missing required parameter 'count display' (count)")]
    fn get_panics_when_required_and_absent() {
        let param = int_param("count", true, 0);
        let arguments: Arguments = HashMap::new();
        param.get(&arguments);
    }

    #[test]
    fn set_then_get_round_trips() {
        let param = int_param("count", true, 0);
        let mut arguments: Arguments = HashMap::new();
        param.set(&mut arguments, ValStr::from_val(99));
        assert_eq!(param.get(&arguments).val, 99);
    }

    #[test]
    #[should_panic(expected = "is not a i64")]
    fn get_panics_on_type_mismatch() {
        let param = int_param("count", true, 0);
        let mut arguments: Arguments = HashMap::new();
        arguments.insert("count".to_owned(), Box::new(ValStr::from_val("oops".to_owned())));
        param.get(&arguments);
    }

    #[test]
    fn with_choices_dedups_preserving_order() {
        let param = LaunchParameter::with_choices(
            "mode",
            "Mode",
            "Mode description",
            [1, 2, 2, 3, 1],
            ValStr::from_val(1),
        );
        assert_eq!(param.choices(), &[1, 2, 3]);
        assert!(!param.required());
    }

    #[test]
    fn with_choices_decode_matches_by_display() {
        let param = LaunchParameter::with_choices(
            "mode",
            "Mode",
            "Mode description",
            [1, 2, 3],
            ValStr::from_val(1),
        );
        assert_eq!(param.decode("2").val, 2);
    }

    #[test]
    #[should_panic(expected = "does not match any of this parameter's choices")]
    fn with_choices_decode_panics_on_unknown_value() {
        let param = LaunchParameter::with_choices(
            "mode",
            "Mode",
            "Mode description",
            [1, 2, 3],
            ValStr::from_val(1),
        );
        param.decode("99");
    }

    #[test]
    fn map_of_preserves_insertion_order() {
        let a: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        let b: Arc<dyn LaunchParameterAny> = Arc::new(int_param("b", false, 0));
        let map = map_of([a, b]);
        assert_eq!(map[0].0, "a");
        assert_eq!(map[1].0, "b");
    }

    #[test]
    #[should_panic(expected = "Duplicate names in parameter map")]
    fn map_of_panics_on_duplicate_name() {
        let a: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        let a2: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        map_of([a, a2]);
    }

    #[test]
    fn validate_arguments_accepts_matching_types() {
        let a: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        let params = map_of([a]);
        let mut arguments: Arguments = HashMap::new();
        arguments.insert("a".to_owned(), Box::new(ValStr::from_val(5i64)));
        let validated = validate_arguments(&params, arguments);
        assert_eq!(
            validated["a"].as_any().downcast_ref::<ValStr<i64>>().unwrap().val,
            5
        );
    }

    #[test]
    #[should_panic(expected = "Extraneous parameters")]
    fn validate_arguments_panics_on_extraneous_key() {
        let a: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        let params = map_of([a]);
        let mut arguments: Arguments = HashMap::new();
        arguments.insert("b".to_owned(), Box::new(ValStr::from_val(5i64)));
        validate_arguments(&params, arguments);
    }

    #[test]
    #[should_panic(expected = "Type errors")]
    fn validate_arguments_panics_on_type_mismatch() {
        let a: Arc<dyn LaunchParameterAny> = Arc::new(int_param("a", false, 0));
        let params = map_of([a]);
        let mut arguments: Arguments = HashMap::new();
        arguments.insert("a".to_owned(), Box::new(ValStr::from_val("nope".to_owned())));
        validate_arguments(&params, arguments);
    }
}
