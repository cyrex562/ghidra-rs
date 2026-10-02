//! Port of `ghidra.framework.options.AbstractOptions`: the option registry behind
//! [`ToolOptions`](crate::framework::options::tool_options::ToolOptions).
//!
//! Java's `AbstractOptions` is an abstract class with instance state and three abstract hooks
//! (`createRegisteredOption`, `createUnregisteredOption`, `notifyOptionChanged`). Per shape rule
//! R11 the state is this struct; the creation hooks are the [`OptionEntry`] constructors (the only
//! concrete option kind ported, `ToolOption`), and change notification is the
//! [`OptionChangeNotifier`] seam passed to every mutating call, so a subclass (ToolOptions'
//! listener list, a database-backed options store) supplies its own.
//!
//! Java marks its methods `synchronized`; here the registry state sits behind a [`Mutex`] so the
//! whole API takes `&self` and the registry can be shared with listeners while a change is
//! being reported. The lock is never held while a notifier runs.
//!
//! Java exceptions become [`OptionsError`]: `IllegalArgumentException` →
//! [`OptionsError::IllegalArgument`], `IllegalStateException` → [`OptionsError::IllegalState`],
//! `OptionsVetoException` → [`OptionsError::Vetoed`].
//!
//! Aliases (`createAlias`) refer to another registry through an `Arc<AbstractOptions>`.
//!
//! Not ported here: theme color/font bindings (`ThemeColorOption` /
//! `ThemeFontOption` are unported), `SubOptions` views (category browsing is offered directly by
//! [`AbstractOptions::child_categories`] / [`AbstractOptions::leaf_option_names`]), and Swing
//! `PropertyEditor` lookup (editors are opaque ids).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use crate::framework::options::action_trigger::ActionTrigger;
use crate::framework::options::custom_option::CustomOption;
use crate::framework::options::option::{HelpRef, OptionEntry};
use crate::framework::options::option_type::{EnumOptionValue, OptionType, OptionValue};
use crate::framework::options::options::{DELIMITER, DELIMITER_STRING, ILLEGAL_DELIMITER};
use crate::framework::seam_stubs::{Color, Font};
use crate::util::awt::KeyStroke;
use crate::util::msg::Msg;

/// An error from an options operation, standing in for the Java exceptions thrown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsError {
    /// Java `IllegalArgumentException` (bad name, null where not allowed, unsupported type).
    IllegalArgument(String),
    /// Java `IllegalStateException` (type mismatch with the existing option).
    IllegalState(String),
    /// Java `OptionsVetoException`: a change listener rejected the change, which was rolled back.
    Vetoed,
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionsError::IllegalArgument(m) | OptionsError::IllegalState(m) => f.write_str(m),
            OptionsError::Vetoed => f.write_str("Options change was vetoed"),
        }
    }
}

impl std::error::Error for OptionsError {}

/// The `notifyOptionChanged` hook of Java's `AbstractOptions`: reports a value change after it
/// has been applied. Returning `Err` (normally [`OptionsError::Vetoed`]) rolls the change back.
pub trait OptionChangeNotifier {
    /// Reports that `option_name` changed from `old_value` to `new_value`.
    fn notify_option_changed(
        &self,
        options: &AbstractOptions,
        option_name: &str,
        old_value: Option<&OptionValue>,
        new_value: Option<&OptionValue>,
    ) -> Result<(), OptionsError>;
}

/// A notifier that accepts every change (for registries with no listeners).
pub struct NoNotify;

impl OptionChangeNotifier for NoNotify {
    fn notify_option_changed(
        &self,
        _options: &AbstractOptions,
        _option_name: &str,
        _old_value: Option<&OptionValue>,
        _new_value: Option<&OptionValue>,
    ) -> Result<(), OptionsError> {
        Ok(())
    }
}

#[derive(Default)]
struct State {
    value_map: HashMap<String, OptionEntry>,
    category_help: HashMap<String, HelpRef>,
    options_editors: HashMap<String, String>,
    alias_map: HashMap<String, AliasBinding>,
}

/// `AbstractOptions.AliasBinding`: an alias resolves to the option at `path` in `options`.
#[derive(Clone)]
struct AliasBinding {
    options: Arc<AbstractOptions>,
    path: String,
}

/// The option registry: named, typed options with registration metadata and current values,
/// organized into categories by [`DELIMITER`]-separated names.
///
/// Port of `ghidra.framework.options.AbstractOptions`.
pub struct AbstractOptions {
    name: Mutex<String>,
    state: Mutex<State>,
}

impl fmt::Debug for AbstractOptions {
    /// Java `toString()`: `Options: {name=value, ...}` sorted by name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        let sorted: BTreeMap<&String, Option<String>> = state
            .value_map
            .iter()
            .map(|(k, v)| (k, v.value(None).as_ref().map(value_to_string)))
            .collect();
        write!(f, "Options: {sorted:?}")
    }
}

impl AbstractOptions {
    /// `new AbstractOptions(name)`.
    pub fn new(name: &str) -> Self {
        AbstractOptions { name: Mutex::new(name.to_string()), state: Mutex::new(State::default()) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `getName()`.
    pub fn get_name(&self) -> String {
        self.name.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// `setName(String)`.
    pub fn set_name(&self, new_name: &str) {
        *self.name.lock().unwrap_or_else(|e| e.into_inner()) = new_name.to_string();
    }

    /// `getID(String)`: the option's full path from the root options (`name.optionName`).
    pub fn get_id(&self, option_name: &str) -> String {
        let name = self.get_name();
        if name.is_empty() {
            option_name.to_string()
        } else {
            format!("{name}{DELIMITER}{option_name}")
        }
    }

    // ------------------------------------------------------------------ registration

    /// `registerOption(name, defaultValue, help, description)`: registers with the type inferred
    /// from the (required) default value.
    pub fn register_option(
        &self,
        option_name: &str,
        default_value: Option<OptionValue>,
        help: Option<HelpRef>,
        description: &str,
    ) -> Result<(), OptionsError> {
        let Some(default_value) = default_value else {
            return Err(OptionsError::IllegalArgument(
                "Attempted to register an option with a null value.  If a null value is an \
                 acceptable default, then call registerOption() that takes an OptionType."
                    .to_string(),
            ));
        };
        let option_type = default_value.option_type();
        self.register_option_with_type(
            option_name,
            option_type,
            Some(default_value),
            help,
            Some(description),
            None,
        )
    }

    /// `registerOption(name, type, defaultValue, help, description, editorSupplier)`.
    ///
    /// `editor_id` stands in for the Swing `PropertyEditor` supplier: an opaque id the UI layer
    /// maps to an editor widget. Java requires an editor for `CUSTOM_TYPE` options only outside
    /// headless mode; this toolkit-neutral model is always "headless", so it does not.
    pub fn register_option_with_type(
        &self,
        option_name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
        help: Option<HelpRef>,
        description: Option<&str>,
        editor_id: Option<String>,
    ) -> Result<(), OptionsError> {
        let mut option_type = option_type;
        let mut default_value = default_value;
        let mut editor_id = editor_id;
        if option_type == OptionType::NoType {
            return Err(OptionsError::IllegalArgument(format!(
                "Can't register an option of type: {}",
                OptionType::NoType
            )));
        }
        if option_type == OptionType::ColorType {
            self.warn_should_use_theme("Color");
        }
        if option_type == OptionType::FontType {
            self.warn_should_use_theme("font");
        }
        if option_type == OptionType::KeystrokeType {
            option_type = OptionType::ActionTrigger;
            default_value = keystroke_to_trigger(default_value);
            if editor_id.is_some() {
                Msg::error(
                    "AbstractOptions",
                    &"Custom KeyStroke property editors are no longer supported.  Use \
                      ActionTrigger instead",
                );
                editor_id = None;
            }
        }
        if !option_type.is_compatible(default_value.as_ref()) {
            return Err(OptionsError::IllegalState(format!(
                "Given default value does not match the given OptionType! OptionType = \
                 {option_type}, defaultValue = {default_value:?}"
            )));
        }
        if description.is_none() {
            Msg::error(
                "AbstractOptions",
                &format!("Registered an option without a description: {option_name}"),
            );
        }
        let mut state = self.lock();
        if let Some(existing) = self.existing_compatible_option(&mut state, option_name, option_type)
        {
            existing.update_registration(description, help, default_value, editor_id);
            return Ok(());
        }
        let option = OptionEntry::new_registered(
            option_name,
            option_type,
            description,
            help,
            default_value,
            editor_id,
        );
        state.value_map.insert(option_name.to_string(), option);
        Ok(())
    }

    fn warn_should_use_theme(&self, option_type: &str) {
        Msg::warn(
            "AbstractOptions",
            &format!(
                "Registering a direct {option_type} in the options is deprecated. Use \
                 registerTheme{option_type}Binding() instead!"
            ),
        );
    }

    /// `getExistingComptibleOption`: the existing option if its type matches; an incompatible
    /// existing option is logged and replaced.
    fn existing_compatible_option<'s>(
        &self,
        state: &'s mut State,
        option_name: &str,
        option_type: OptionType,
    ) -> Option<&'s mut OptionEntry> {
        let existing_type = state.value_map.get(option_name)?.option_type();
        if existing_type != option_type {
            Msg::error(
                "AbstractOptions",
                &format!(
                    "Registered option incompatible with existing option: '{option_name}'. \
                     Existing type '{existing_type}'; registered type '{option_type}'."
                ),
            );
            return None;
        }
        state.value_map.get_mut(option_name)
    }

    /// `registerOptionsEditor(categoryPath, editorSupplier)`: an opaque options-editor id for a
    /// whole category (`""` is this options object itself).
    pub fn register_options_editor(&self, category_path: &str, editor_id: &str) {
        self.lock().options_editors.insert(category_path.to_string(), editor_id.to_string());
    }

    /// `getOptionsEditor(categoryPath)`.
    pub fn get_options_editor(&self, category_path: &str) -> Option<String> {
        self.lock().options_editors.get(category_path).cloned()
    }

    /// `setCategoryHelpLocation(categoryPath, help)`; `""` is `setOptionsHelpLocation`.
    pub fn set_category_help_location(&self, category_path: &str, help: Option<HelpRef>) {
        let mut state = self.lock();
        match help {
            Some(help) => {
                state.category_help.insert(category_path.to_string(), help);
            }
            None => {
                state.category_help.remove(category_path);
            }
        }
    }

    /// `getCategoryHelpLocation(categoryPath)`; `""` is `getOptionsHelpLocation`.
    pub fn get_category_help_location(&self, category_path: &str) -> Option<HelpRef> {
        self.lock().category_help.get(category_path).cloned()
    }

    // ------------------------------------------------------------------ lookup

    /// `getOption(name, type, defaultValue)`: the option snapshot, creating (and storing, unless
    /// `NO_TYPE`) an unregistered option on first access.
    ///
    /// # Errors
    /// [`OptionsError::IllegalArgument`] for an illegal name; [`OptionsError::IllegalState`] when
    /// `option_type` is not `NO_TYPE` and differs from the existing option's type.
    pub fn get_option(
        &self,
        option_name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
    ) -> Result<OptionEntry, OptionsError> {
        self.with_option(option_name, option_type, default_value, |o| o.clone())
    }

    fn with_option<R>(
        &self,
        option_name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
        f: impl FnOnce(&mut OptionEntry) -> R,
    ) -> Result<R, OptionsError> {
        self.validate_option_name(option_name)?;
        let mut state = self.lock();
        if let Some(binding) = state.alias_map.get(option_name).cloned() {
            drop(state);
            return binding.options.with_option(&binding.path, option_type, default_value, f);
        }
        if !state.value_map.contains_key(option_name) {
            let option = create_unregistered_option(option_name, option_type, default_value);
            if option.option_type() == OptionType::NoType {
                let mut transient = option;
                return Ok(f(&mut transient));
            }
            state.value_map.insert(option_name.to_string(), option);
        }
        let option = state.value_map.get_mut(option_name).expect("inserted above");
        validate_option_type(option, option_type)?;
        Ok(f(option))
    }

    /// A snapshot of the option named `option_name`, without creating it (no Java equivalent;
    /// for read-only inspection such as an options dialog).
    pub fn find_option(&self, option_name: &str) -> Option<OptionEntry> {
        self.lock().value_map.get(option_name).cloned()
    }

    /// `getOptionNames()`: every option path, sorted.
    pub fn get_option_names(&self) -> Vec<String> {
        let state = self.lock();
        let mut names: Vec<String> =
            state.value_map.keys().chain(state.alias_map.keys()).cloned().collect();
        names.sort();
        names
    }

    /// `contains(String)`.
    pub fn contains(&self, option_name: &str) -> bool {
        let state = self.lock();
        state.value_map.contains_key(option_name) || state.alias_map.contains_key(option_name)
    }

    /// `createAlias(aliasName, options, optionsName)`: makes `alias_name` in this registry refer
    /// to the option `options_name` of `options` (pass the full path for an option inside a
    /// sub-category, as Java's `SubOptions` prefixing does).
    pub fn create_alias(&self, alias_name: &str, options: &Arc<AbstractOptions>, options_name: &str) {
        self.lock().alias_map.insert(
            alias_name.to_string(),
            AliasBinding { options: Arc::clone(options), path: options_name.to_string() },
        );
    }

    /// `isAlias(String)`.
    pub fn is_alias(&self, alias_name: &str) -> bool {
        self.lock().alias_map.contains_key(alias_name)
    }

    /// `removeOption(String)`.
    pub fn remove_option(&self, option_name: &str) {
        let mut state = self.lock();
        state.alias_map.remove(option_name);
        state.value_map.remove(option_name);
    }

    /// `getType(String)`: [`OptionType::NoType`] when the option does not exist.
    pub fn get_type(&self, option_name: &str) -> Result<OptionType, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| o.option_type())
    }

    /// `getDescription(String)`.
    pub fn get_description(&self, option_name: &str) -> Result<String, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| o.description().to_string())
    }

    /// `getHelpLocation(String)`.
    pub fn get_help_location(&self, option_name: &str) -> Result<Option<HelpRef>, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| o.help_location().cloned())
    }

    /// `getRegisteredPropertyEditor(String)`: the registered editor id.
    pub fn get_registered_editor_id(
        &self,
        option_name: &str,
    ) -> Result<Option<String>, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| {
            o.editor_id().map(str::to_string)
        })
    }

    /// `isRegistered(String)`.
    pub fn is_registered(&self, option_name: &str) -> bool {
        self.lock().value_map.get(option_name).is_some_and(OptionEntry::is_registered)
    }

    /// `isDefaultValue(String)`.
    pub fn is_default_value(&self, option_name: &str) -> Result<bool, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| o.is_default())
    }

    /// `getDefaultValue(String)`.
    pub fn get_default_value(&self, option_name: &str) -> Result<Option<OptionValue>, OptionsError> {
        self.with_option(option_name, OptionType::NoType, None, |o| o.default_value().cloned())
    }

    /// `getObject(name, defaultValue)`.
    pub fn get_object(
        &self,
        option_name: &str,
        default_value: Option<OptionValue>,
    ) -> Result<Option<OptionValue>, OptionsError> {
        let option_type = OptionType::get_option_type(default_value.as_ref());
        self.with_option(option_name, option_type, default_value.clone(), |o| {
            o.value(default_value)
        })
    }

    /// `getValueAsString(String)`: the value's `toString()`, or `None` when unset.
    pub fn get_value_as_string(&self, option_name: &str) -> Result<Option<String>, OptionsError> {
        Ok(self.get_object(option_name, None)?.as_ref().map(value_to_string))
    }

    /// `getDefaultValueAsString(String)`.
    pub fn get_default_value_as_string(
        &self,
        option_name: &str,
    ) -> Result<Option<String>, OptionsError> {
        Ok(self.get_default_value(option_name)?.as_ref().map(value_to_string))
    }

    // ------------------------------------------------------------------ categories

    /// `getLeafOptionNames()` for the category at `category_path` (`""` = this options): the
    /// option names directly in that category, sorted.
    pub fn leaf_option_names(&self, category_path: &str) -> Vec<String> {
        let names = names_under(&self.get_option_names(), category_path);
        get_leaves(&names).into_iter().collect()
    }

    /// The names of the sub-categories directly under `category_path` (`""` = top level),
    /// sorted. Java: `getChildOptions()` (each child `SubOptions` is named by these).
    pub fn child_categories(&self, category_path: &str) -> Vec<String> {
        let names = names_under(&self.get_option_names(), category_path);
        get_child_categories(&names).into_iter().collect()
    }

    /// Option names under `category_path`, relative to it, sorted (Java: `SubOptions.getOptionNames`).
    pub fn option_names_in_category(&self, category_path: &str) -> Vec<String> {
        names_under(&self.get_option_names(), category_path)
    }

    // ------------------------------------------------------------------ mutation

    /// `putObject(name, value)`: stores a value, inferring its type. `None` clears the value of
    /// an existing nullable option.
    pub fn put_object(
        &self,
        option_name: &str,
        new_value: Option<OptionValue>,
        notifier: &dyn OptionChangeNotifier,
    ) -> Result<(), OptionsError> {
        match new_value {
            None => {
                let option_type = self.get_type(option_name)?;
                if is_nullable(option_type) {
                    return self.put_value(option_name, None, OptionType::NoType, notifier);
                }
                Err(OptionsError::IllegalArgument(
                    "Attempted to put a null value in an option that does not support null \
                     values. If you wanted to removethe option, call removeOption() instead!"
                        .to_string(),
                ))
            }
            Some(value) => {
                let option_type = value.option_type();
                self.put_value(option_name, Some(value), option_type, notifier)
            }
        }
    }

    /// `putObject(name, value, type)`: sets the value, notifies, and rolls back on veto.
    ///
    /// # Errors
    /// Name/type validation errors, or the notifier's error (the change is then undone).
    pub fn put_value(
        &self,
        option_name: &str,
        new_value: Option<OptionValue>,
        option_type: OptionType,
        notifier: &dyn OptionChangeNotifier,
    ) -> Result<(), OptionsError> {
        let old_value = self.with_option(option_name, option_type, None, |o| {
            let old = o.current_value().cloned();
            o.set_current_value(new_value.clone());
            old
        })?;
        let result =
            notifier.notify_option_changed(self, option_name, old_value.as_ref(), new_value.as_ref());
        if result.is_err() {
            self.with_option(option_name, OptionType::NoType, None, |o| {
                o.set_current_value(old_value)
            })?;
        }
        result
    }

    /// `restoreDefaultValue(String)`: resets one option and notifies if it changed.
    pub fn restore_default_value(
        &self,
        option_name: &str,
        notifier: &dyn OptionChangeNotifier,
    ) -> Result<(), OptionsError> {
        let change = self.with_option(option_name, OptionType::NoType, None, |o| {
            if o.is_default() {
                return None;
            }
            let previous = o.current_value().cloned();
            o.restore_default();
            Some((previous, o.current_value().cloned()))
        })?;
        if let Some((previous, current)) = change {
            notifier.notify_option_changed(self, option_name, previous.as_ref(), current.as_ref())?;
        }
        Ok(())
    }

    /// `restoreDefaultValues()`: resets every option.
    pub fn restore_default_values(
        &self,
        notifier: &dyn OptionChangeNotifier,
    ) -> Result<(), OptionsError> {
        for name in self.get_option_names() {
            self.restore_default_value(&name, notifier)?;
        }
        Ok(())
    }

    /// Inserts an option directly (used when restoring saved state), replacing any existing one.
    pub(crate) fn insert_option(&self, option: OptionEntry) {
        self.lock().value_map.insert(option.name().to_string(), option);
    }

    /// A snapshot of every option (unsorted), for persistence.
    pub(crate) fn options_snapshot(&self) -> Vec<OptionEntry> {
        self.lock().value_map.values().cloned().collect()
    }

    // ------------------------------------------------------------------ typed accessors

    fn get_typed<T>(
        &self,
        option_name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
        extract: impl FnOnce(OptionValue) -> Option<T>,
    ) -> Result<Option<T>, OptionsError> {
        let value = self.with_option(option_name, option_type, default_value.clone(), |o| {
            o.value(default_value)
        })?;
        Ok(value.and_then(extract))
    }

    /// `getBoolean(name, default)`.
    pub fn get_boolean(&self, option_name: &str, default_value: bool) -> Result<bool, OptionsError> {
        let v = self.get_typed(option_name, OptionType::BooleanType, Some(OptionValue::Boolean(default_value)), |v| match v {
            OptionValue::Boolean(b) => Some(b),
            _ => None,
        })?;
        Ok(v.unwrap_or(default_value))
    }

    /// `getInt(name, default)`.
    pub fn get_int(&self, option_name: &str, default_value: i32) -> Result<i32, OptionsError> {
        let v = self.get_typed(option_name, OptionType::IntType, Some(OptionValue::Int(default_value)), |v| match v {
            OptionValue::Int(i) => Some(i),
            _ => None,
        })?;
        Ok(v.unwrap_or(default_value))
    }

    /// `getLong(name, default)`.
    pub fn get_long(&self, option_name: &str, default_value: i64) -> Result<i64, OptionsError> {
        let v = self.get_typed(option_name, OptionType::LongType, Some(OptionValue::Long(default_value)), |v| match v {
            OptionValue::Long(i) => Some(i),
            _ => None,
        })?;
        Ok(v.unwrap_or(default_value))
    }

    /// `getFloat(name, default)`.
    pub fn get_float(&self, option_name: &str, default_value: f32) -> Result<f32, OptionsError> {
        let v = self.get_typed(option_name, OptionType::FloatType, Some(OptionValue::Float(default_value)), |v| match v {
            OptionValue::Float(x) => Some(x),
            _ => None,
        })?;
        Ok(v.unwrap_or(default_value))
    }

    /// `getDouble(name, default)`.
    pub fn get_double(&self, option_name: &str, default_value: f64) -> Result<f64, OptionsError> {
        let v = self.get_typed(option_name, OptionType::DoubleType, Some(OptionValue::Double(default_value)), |v| match v {
            OptionValue::Double(x) => Some(x),
            _ => None,
        })?;
        Ok(v.unwrap_or(default_value))
    }

    /// `getString(name, default)`.
    pub fn get_string(
        &self,
        option_name: &str,
        default_value: Option<&str>,
    ) -> Result<Option<String>, OptionsError> {
        let d = default_value.map(|s| OptionValue::String(s.to_string()));
        self.get_typed(option_name, OptionType::StringType, d, |v| match v {
            OptionValue::String(s) => Some(s),
            _ => None,
        })
    }

    /// `getByteArray(name, default)`.
    pub fn get_byte_array(
        &self,
        option_name: &str,
        default_value: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, OptionsError> {
        let d = default_value.map(|b| OptionValue::ByteArray(b.to_vec()));
        self.get_typed(option_name, OptionType::ByteArrayType, d, |v| match v {
            OptionValue::ByteArray(b) => Some(b),
            _ => None,
        })
    }

    /// `getFile(name, default)`.
    pub fn get_file(
        &self,
        option_name: &str,
        default_value: Option<PathBuf>,
    ) -> Result<Option<PathBuf>, OptionsError> {
        self.get_typed(option_name, OptionType::FileType, default_value.map(OptionValue::File), |v| match v {
            OptionValue::File(p) => Some(p),
            _ => None,
        })
    }

    /// `getDate(name, default)`.
    pub fn get_date(
        &self,
        option_name: &str,
        default_value: Option<SystemTime>,
    ) -> Result<Option<SystemTime>, OptionsError> {
        self.get_typed(option_name, OptionType::DateType, default_value.map(OptionValue::Date), |v| match v {
            OptionValue::Date(d) => Some(d),
            _ => None,
        })
    }

    /// `getEnum(name, default)`.
    pub fn get_enum(
        &self,
        option_name: &str,
        default_value: Option<EnumOptionValue>,
    ) -> Result<Option<EnumOptionValue>, OptionsError> {
        self.get_typed(option_name, OptionType::EnumType, default_value.map(OptionValue::Enum), |v| match v {
            OptionValue::Enum(e) => Some(e),
            _ => None,
        })
    }

    /// `getCustomOption(name, default)`.
    pub fn get_custom_option(
        &self,
        option_name: &str,
        default_value: Option<Arc<dyn CustomOption + Send + Sync>>,
    ) -> Result<Option<Arc<dyn CustomOption + Send + Sync>>, OptionsError> {
        self.get_typed(option_name, OptionType::CustomType, default_value.map(OptionValue::Custom), |v| match v {
            OptionValue::Custom(c) => Some(c),
            _ => None,
        })
    }

    /// `getColor(name, default)`.
    pub fn get_color(
        &self,
        option_name: &str,
        default_value: Option<Arc<dyn Color + Send + Sync>>,
    ) -> Result<Option<Arc<dyn Color + Send + Sync>>, OptionsError> {
        self.get_typed(option_name, OptionType::ColorType, default_value.map(OptionValue::Color), |v| match v {
            OptionValue::Color(c) => Some(c),
            _ => None,
        })
    }

    /// `getFont(name, default)`.
    pub fn get_font(
        &self,
        option_name: &str,
        default_value: Option<Arc<dyn Font + Send + Sync>>,
    ) -> Result<Option<Arc<dyn Font + Send + Sync>>, OptionsError> {
        self.get_typed(option_name, OptionType::FontType, default_value.map(OptionValue::Font), |v| match v {
            OptionValue::Font(c) => Some(c),
            _ => None,
        })
    }

    /// `getActionTrigger(name, default)`.
    pub fn get_action_trigger(
        &self,
        option_name: &str,
        default_value: Option<ActionTrigger>,
    ) -> Result<Option<ActionTrigger>, OptionsError> {
        self.get_typed(option_name, OptionType::ActionTrigger, default_value.map(OptionValue::ActionTrigger), |v| match v {
            OptionValue::ActionTrigger(t) => Some(t),
            _ => None,
        })
    }

    /// `getKeyStroke(name, default)`: key strokes are stored as action triggers.
    pub fn get_key_stroke(
        &self,
        option_name: &str,
        default_value: Option<KeyStroke>,
    ) -> Result<Option<KeyStroke>, OptionsError> {
        let d = default_value.and_then(|ks| ActionTrigger::new(Some(ks), None).ok());
        let trigger = self.get_action_trigger(option_name, d)?;
        Ok(trigger.and_then(|t| t.key_stroke()))
    }

    // ------------------------------------------------------------------ name validation

    /// `validateOptionName(String)`.
    fn validate_option_name(&self, option_name: &str) -> Result<(), OptionsError> {
        let name = self.get_name();
        if contains_unquoted_text(option_name, ILLEGAL_DELIMITER) {
            return Err(OptionsError::IllegalArgument(format!(
                "Name cannot contain consecutive delimiters: {option_name} in Options {name}"
            )));
        }
        if option_name.starts_with(DELIMITER_STRING) {
            return Err(OptionsError::IllegalArgument(format!(
                "Name cannot start with a delimiter: {option_name} in Options {name}"
            )));
        }
        if option_name.ends_with(DELIMITER_STRING) {
            return Err(OptionsError::IllegalArgument(format!(
                "Name cannot end with a delimiter: {option_name} in Options {name}"
            )));
        }
        Ok(())
    }
}

/// `createUnregisteredOption` (ToolOptions' override): key strokes become action triggers.
pub(crate) fn create_unregistered_option(
    option_name: &str,
    option_type: OptionType,
    default_value: Option<OptionValue>,
) -> OptionEntry {
    if option_type == OptionType::KeystrokeType {
        return OptionEntry::new_unregistered(
            option_name,
            OptionType::ActionTrigger,
            keystroke_to_trigger(default_value),
        );
    }
    OptionEntry::new_unregistered(option_name, option_type, default_value)
}

fn keystroke_to_trigger(value: Option<OptionValue>) -> Option<OptionValue> {
    match value {
        Some(OptionValue::KeyStroke(ks)) => {
            ActionTrigger::new(Some(ks), None).ok().map(OptionValue::ActionTrigger)
        }
        other => other,
    }
}

/// `validateOptionType(Option, OptionType)`.
fn validate_option_type(option: &OptionEntry, option_type: OptionType) -> Result<(), OptionsError> {
    if option_type == option.option_type() || option_type == OptionType::NoType {
        return Ok(());
    }
    Err(OptionsError::IllegalState(format!(
        "Expected option type: {option_type}, but was type: {}",
        option.option_type()
    )))
}

/// `isNullable(OptionType)`: object-valued types may hold null; boxed primitives may not.
pub fn is_nullable(option_type: OptionType) -> bool {
    matches!(
        option_type,
        OptionType::ByteArrayType
            | OptionType::EnumType
            | OptionType::ColorType
            | OptionType::CustomType
            | OptionType::DateType
            | OptionType::FileType
            | OptionType::FontType
            | OptionType::KeystrokeType
            | OptionType::StringType
    )
}

/// `containsUnquotedText`: whether `text` occurs in `s` outside double-quoted spans.
fn contains_unquoted_text(s: &str, text: &str) -> bool {
    let mut buffer = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes {
            buffer.push(c);
        }
    }
    buffer.contains(text)
}

/// `getChildCategories(Collection)`: the first path element of every multi-element path.
pub fn get_child_categories(option_paths: &[String]) -> BTreeSet<String> {
    option_paths
        .iter()
        .filter_map(|p| p.find(DELIMITER).map(|i| p[..i].to_string()))
        .collect()
}

/// `getLeaves(Collection)`: every single-element path.
pub fn get_leaves(option_paths: &[String]) -> BTreeSet<String> {
    option_paths.iter().filter(|p| !p.contains(DELIMITER)).cloned().collect()
}

/// The option paths under `category_path`, relative to it (all paths for `""`).
fn names_under(names: &[String], category_path: &str) -> Vec<String> {
    if category_path.is_empty() {
        return names.to_vec();
    }
    let prefix = format!("{category_path}{DELIMITER}");
    names.iter().filter_map(|n| n.strip_prefix(&prefix).map(str::to_string)).collect()
}

/// Java `Object.toString()` for an option value (used by `getValueAsString`).
pub fn value_to_string(value: &OptionValue) -> String {
    match value {
        OptionValue::Enum(e) => e.name.clone(),
        OptionValue::File(p) => p.to_string_lossy().into_owned(),
        OptionValue::ByteArray(b) => format!("{b:?}"),
        OptionValue::Custom(c) => c.to_string(),
        OptionValue::Date(_) | OptionValue::Int(_) | OptionValue::Long(_)
        | OptionValue::String(_) | OptionValue::Double(_) | OptionValue::Boolean(_)
        | OptionValue::Float(_) => value
            .option_type()
            .convert_object_to_string(Some(value))
            .ok()
            .flatten()
            .unwrap_or_default(),
        OptionValue::Color(_) | OptionValue::Font(_) | OptionValue::KeyStroke(_)
        | OptionValue::ActionTrigger(_) => format!("{value:?}"),
    }
}
