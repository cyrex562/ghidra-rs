//! Port of `ghidra.framework.options.ToolOptions`: an [`AbstractOptions`] registry that notifies
//! [`OptionsChangeListener`]s of changes and persists to / restores from XML.
//!
//! Toolkit-neutral differences from Java:
//! - Java runs listener notification on the Swing thread (`Swing.runNow`); here it runs on the
//!   caller's thread. Listeners receive this object as the `ToolOptions` seam and the old/new
//!   values as `&dyn Any` that downcast to [`OptionValue`].
//! - Java keeps listeners in a `WeakSet`; here listeners are [`SharedOptionsListener`] handles
//!   held weakly, so a dropped listener stops being notified.
//! - Wrapped (non-primitive) values persist for `File`, `Date` and `CustomOption` exactly as
//!   `WrappedFile` / `WrappedDate` / `WrappedCustomOption` write them. `Color`, `Font` and
//!   `ActionTrigger` values have no ported wrapper (`WrappedColor`/`WrappedFont`/
//!   `WrappedActionTrigger` depend on the unported AWT value types), so they are not written.

use std::any::Any;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::framework::options::abstract_options::{
    create_unregistered_option, AbstractOptions, OptionChangeNotifier,
    OptionsError,
};
use crate::framework::options::action_trigger::ActionTrigger;
use crate::framework::options::attributed_save_state::AttributedSaveState;
use crate::framework::options::custom_option::{new_custom_option, CustomOption};
use crate::framework::options::g_properties::GPropertyValue;
use crate::framework::options::option::{
    format_iso_date, option_values_equal, parse_iso_date, today_epoch_day, OptionEntry,
};
use crate::framework::options::option_type::{EnumOptionValue, OptionType, OptionValue};
use crate::framework::options::options_change_listener::OptionsChangeListener;
use crate::framework::options::save_state::SaveState;
use crate::framework::seam_stubs::{Color, Font, ToolOptions as ToolOptionsSeam};
use crate::util::awt::KeyStroke;
use crate::util::msg::Msg;
use crate::util::system_utilities::SystemUtilities;
use crate::util::xml::element::Element;

/// A listener registered with [`ToolOptions::add_options_change_listener`]; the options hold it
/// weakly (Java's `WeakSet`), so the caller keeps it alive.
pub type SharedOptionsListener = Arc<Mutex<dyn OptionsChangeListener + Send>>;

const CLASS_ATTRIBUTE: &str = "CLASS";
const NAME_ATTRIBUTE: &str = "NAME";
const WRAPPED_OPTION_NAME: &str = "WRAPPED_OPTION";
const CLEARED_VALUE_ELEMENT_NAME: &str = "CLEARED_VALUE";
/// `ToolOptions.LAST_REGISTERED_DATE_ATTIBUTE`.
pub const LAST_REGISTERED_DATE_ATTRIBUTE: &str = "LAST_REGISTERED";
/// `ToolOptions.XML_ELEMENT_NAME`.
pub const XML_ELEMENT_NAME: &str = "CATEGORY";

const WRAPPED_FILE_CLASS: &str = "ghidra.framework.options.WrappedFile";
const WRAPPED_DATE_CLASS: &str = "ghidra.framework.options.WrappedDate";
const WRAPPED_CUSTOM_CLASS: &str = "ghidra.framework.options.WrappedCustomOption";
const CUSTOM_OPTION_CLASS_KEY: &str = "CUSTOM OPTION CLASS";

/// Options for a tool: a registry with change listeners and XML persistence.
///
/// Port of `ghidra.framework.options.ToolOptions`. Read access (names, types, values,
/// descriptions, categories) is through [`Deref`] to [`AbstractOptions`]; every mutation goes
/// through this type so listeners are notified.
pub struct ToolOptions {
    base: Arc<AbstractOptions>,
    listeners: Mutex<Vec<Weak<Mutex<dyn OptionsChangeListener + Send>>>>,
}

impl Deref for ToolOptions {
    type Target = AbstractOptions;
    fn deref(&self) -> &AbstractOptions {
        &self.base
    }
}

impl std::fmt::Debug for ToolOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ToolOptions({})", self.get_name())
    }
}

impl ToolOptionsSeam for ToolOptions {
    fn get_option(&self, key: &str) -> Option<String> {
        self.get_value_as_string(key).ok().flatten()
    }
}

/// `NotifyListenersRunnable`.
struct ListenerNotifier<'a>(&'a ToolOptions);

impl OptionChangeNotifier for ListenerNotifier<'_> {
    fn notify_option_changed(
        &self,
        _options: &AbstractOptions,
        option_name: &str,
        old_value: Option<&OptionValue>,
        new_value: Option<&OptionValue>,
    ) -> Result<(), OptionsError> {
        self.0.notify_listeners(option_name, old_value, new_value)
    }
}

fn as_any(v: Option<&OptionValue>) -> Option<&dyn Any> {
    v.map(|v| v as &dyn Any)
}

impl ToolOptions {
    /// `new ToolOptions(String)`.
    pub fn new(name: &str) -> Self {
        ToolOptions { base: Arc::new(AbstractOptions::new(name)), listeners: Mutex::new(Vec::new()) }
    }

    /// The underlying registry.
    pub fn registry(&self) -> &AbstractOptions {
        &self.base
    }

    /// A shared handle to the underlying registry, e.g. as the target of another options'
    /// [`AbstractOptions::create_alias`].
    pub fn shared_registry(&self) -> Arc<AbstractOptions> {
        Arc::clone(&self.base)
    }

    // ------------------------------------------------------------------ listeners

    /// `addOptionsChangeListener(OptionsChangeListener)`.
    pub fn add_options_change_listener(&self, listener: &SharedOptionsListener) {
        let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        listeners.retain(|l| l.strong_count() > 0);
        let weak = Arc::downgrade(listener);
        if !listeners.iter().any(|l| Weak::ptr_eq(l, &weak)) {
            listeners.push(weak);
        }
    }

    /// `removeOptionsChangeListener(OptionsChangeListener)`.
    pub fn remove_options_change_listener(&self, listener: &SharedOptionsListener) {
        let weak = Arc::downgrade(listener);
        self.listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|l| l.strong_count() > 0 && !Weak::ptr_eq(l, &weak));
    }

    /// `takeListeners(ToolOptions)`: moves `old_options`' listeners to these options.
    pub fn take_listeners(&self, old_options: &ToolOptions) {
        let taken =
            std::mem::take(&mut *old_options.listeners.lock().unwrap_or_else(|e| e.into_inner()));
        *self.listeners.lock().unwrap_or_else(|e| e.into_inner()) = taken;
    }

    /// `NotifyListenersRunnable.run`: notifies each live listener; on a veto, re-notifies the
    /// listeners already told with the values swapped, and reports the veto.
    fn notify_listeners(
        &self,
        option_name: &str,
        old_value: Option<&OptionValue>,
        new_value: Option<&OptionValue>,
    ) -> Result<(), OptionsError> {
        let live: Vec<SharedOptionsListener> = self
            .listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        let mut notified: Vec<&SharedOptionsListener> = Vec::new();
        for listener in &live {
            let result = listener.lock().unwrap_or_else(|e| e.into_inner()).options_changed(
                self,
                option_name,
                as_any(old_value),
                as_any(new_value),
            );
            if result.is_err() {
                for n in notified {
                    // Java ignores a second veto during the revert notification.
                    let _ = n.lock().unwrap_or_else(|e| e.into_inner()).options_changed(
                        self,
                        option_name,
                        as_any(new_value),
                        as_any(old_value),
                    );
                }
                return Err(OptionsError::Vetoed);
            }
            notified.push(listener);
        }
        Ok(())
    }

    // ------------------------------------------------------------------ mutation

    /// `putObject(String, Object)`: stores a value of any supported type (`None` clears a
    /// nullable option).
    pub fn put_object(&self, option_name: &str, value: Option<OptionValue>) -> Result<(), OptionsError> {
        self.base.put_object(option_name, value, &ListenerNotifier(self))
    }

    /// `putObject(String, Object, OptionType)`: stores a value, requiring the option to be of
    /// `option_type`.
    pub fn put_value(
        &self,
        option_name: &str,
        value: Option<OptionValue>,
        option_type: OptionType,
    ) -> Result<(), OptionsError> {
        self.base.put_value(option_name, value, option_type, &ListenerNotifier(self))
    }

    /// `setBoolean`.
    pub fn set_boolean(&self, option_name: &str, value: bool) -> Result<(), OptionsError> {
        self.put_value(option_name, Some(OptionValue::Boolean(value)), OptionType::BooleanType)
    }

    /// `setInt`.
    pub fn set_int(&self, option_name: &str, value: i32) -> Result<(), OptionsError> {
        self.put_value(option_name, Some(OptionValue::Int(value)), OptionType::IntType)
    }

    /// `setLong`.
    pub fn set_long(&self, option_name: &str, value: i64) -> Result<(), OptionsError> {
        self.put_value(option_name, Some(OptionValue::Long(value)), OptionType::LongType)
    }

    /// `setFloat`.
    pub fn set_float(&self, option_name: &str, value: f32) -> Result<(), OptionsError> {
        self.put_value(option_name, Some(OptionValue::Float(value)), OptionType::FloatType)
    }

    /// `setDouble`.
    pub fn set_double(&self, option_name: &str, value: f64) -> Result<(), OptionsError> {
        self.put_value(option_name, Some(OptionValue::Double(value)), OptionType::DoubleType)
    }

    /// `setString`.
    pub fn set_string(&self, option_name: &str, value: Option<&str>) -> Result<(), OptionsError> {
        let v = value.map(|s| OptionValue::String(s.to_string()));
        self.put_value(option_name, v, OptionType::StringType)
    }

    /// `setByteArray`.
    pub fn set_byte_array(&self, option_name: &str, value: Option<&[u8]>) -> Result<(), OptionsError> {
        let v = value.map(|b| OptionValue::ByteArray(b.to_vec()));
        self.put_value(option_name, v, OptionType::ByteArrayType)
    }

    /// `setFile`.
    pub fn set_file(&self, option_name: &str, value: Option<std::path::PathBuf>) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::File), OptionType::FileType)
    }

    /// `setDate`.
    pub fn set_date(&self, option_name: &str, value: Option<SystemTime>) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::Date), OptionType::DateType)
    }

    /// `setEnum`.
    pub fn set_enum(&self, option_name: &str, value: Option<EnumOptionValue>) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::Enum), OptionType::EnumType)
    }

    /// `setCustomOption`.
    pub fn set_custom_option(
        &self,
        option_name: &str,
        value: Option<Arc<dyn CustomOption + Send + Sync>>,
    ) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::Custom), OptionType::CustomType)
    }

    /// `setColor`.
    pub fn set_color(
        &self,
        option_name: &str,
        value: Option<Arc<dyn Color + Send + Sync>>,
    ) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::Color), OptionType::ColorType)
    }

    /// `setFont`.
    pub fn set_font(
        &self,
        option_name: &str,
        value: Option<Arc<dyn Font + Send + Sync>>,
    ) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::Font), OptionType::FontType)
    }

    /// `setActionTrigger`.
    pub fn set_action_trigger(
        &self,
        option_name: &str,
        value: Option<ActionTrigger>,
    ) -> Result<(), OptionsError> {
        self.put_value(option_name, value.map(OptionValue::ActionTrigger), OptionType::ActionTrigger)
    }

    /// `setKeyStroke`: stored as an action trigger.
    pub fn set_key_stroke(&self, option_name: &str, value: Option<KeyStroke>) -> Result<(), OptionsError> {
        let trigger = value.and_then(|ks| ActionTrigger::new(Some(ks), None).ok());
        self.set_action_trigger(option_name, trigger)
    }

    /// `restoreDefaultValue(String)`.
    pub fn restore_default_value(&self, option_name: &str) -> Result<(), OptionsError> {
        self.base.restore_default_value(option_name, &ListenerNotifier(self))
    }

    /// `restoreDefaultValues()`.
    pub fn restore_default_values(&self) -> Result<(), OptionsError> {
        self.base.restore_default_values(&ListenerNotifier(self))
    }

    /// `removeUnusedOptions()`: removes options not registered in over a year.
    pub fn remove_unused_options(&self) {
        for option in self.base.options_snapshot() {
            if option.has_expired() {
                self.remove_option(option.name());
            }
        }
    }

    /// `copyOptions(Options)`: puts every non-null value of `new_options` into these options.
    pub fn copy_options(&self, new_options: &AbstractOptions) -> Result<(), OptionsError> {
        for name in new_options.get_option_names() {
            if let Some(value) = new_options.get_object(&name, None)? {
                self.put_object(&name, Some(value))?;
            }
        }
        Ok(())
    }

    /// `registerOptions(ToolOptions)`: re-registers every option registered in `old_options`.
    pub fn register_options(&self, old_options: &ToolOptions) -> Result<(), OptionsError> {
        for option in old_options.base.options_snapshot() {
            if option.is_registered() {
                self.register_option_with_type(
                    option.name(),
                    option.option_type(),
                    option.default_value().cloned(),
                    option.help_location().cloned(),
                    Some(option.description()),
                    None,
                )?;
            }
        }
        Ok(())
    }

    /// `validateOptions()`: in development mode, warns about options used this session that
    /// were never registered (this session or a previous one).
    pub fn validate_options(&self) {
        if !SystemUtilities::is_in_development_mode() {
            return;
        }
        for option in self.base.options_snapshot() {
            if option.is_registered() || option.was_registered_in_previous_session() {
                continue;
            }
            Msg::warn(
                "ToolOptions",
                &format!(
                    "Unregistered property \"{}\" in Options \"{}\"",
                    option.name(),
                    self.get_name()
                ),
            );
        }
    }

    /// `dispose()`: drops every listener.
    pub fn dispose(&self) {
        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// `copy()`: a deep copy via XML (defaults included).
    pub fn copy(&self) -> ToolOptions {
        ToolOptions::from_xml(&self.get_xml_root(true))
    }

    // ------------------------------------------------------------------ persistence

    /// `new ToolOptions(Element)`: restores options saved by [`Self::get_xml_root`]. Restored
    /// options are unregistered until a client registers or sets them.
    pub fn from_xml(root: &Element) -> ToolOptions {
        let options = ToolOptions::new(root.get_attribute_value(NAME_ATTRIBUTE).unwrap_or(""));
        let save_state = AttributedSaveState::from_xml(root);
        options.read_non_wrapped_options(&save_state);
        options.read_wrapped_options(root);
        options
    }

    fn read_non_wrapped_options(&self, save_state: &AttributedSaveState) {
        for name in save_state.get_names() {
            let Some(value) = save_state.get_object(&name).and_then(g_property_to_option_value)
            else {
                continue;
            };
            let mut option = create_unregistered_option(&name, value.option_type(), None);
            option.do_set_current_value(Some(value));
            let day = save_state
                .get_attributes(&name)
                .and_then(|a| a.get(LAST_REGISTERED_DATE_ATTRIBUTE))
                .and_then(|d| parse_iso_date(d))
                .unwrap_or_else(today_epoch_day);
            option.set_last_registered_day(Some(day));
            self.base.insert_option(option);
        }
    }

    fn read_wrapped_options(&self, root: &Element) {
        for element in root.get_children_named(WRAPPED_OPTION_NAME) {
            let Some(first_child) = element.get_children().first() else {
                continue; // shouldn't happen
            };
            let class_name = element.get_attribute_value(CLASS_ATTRIBUTE).unwrap_or("");
            let state = SaveState::from_xml(element);
            let (option_type, value) = match class_name {
                WRAPPED_FILE_CLASS => {
                    let path = state.get_string("file", Some(".")).unwrap_or_default();
                    (OptionType::FileType, OptionValue::File(path.into()))
                }
                WRAPPED_DATE_CLASS => {
                    let millis = state.get_long("date", 0);
                    (OptionType::DateType, OptionValue::Date(date_from_millis(millis)))
                }
                WRAPPED_CUSTOM_CLASS => {
                    let custom_class =
                        state.get_string(CUSTOM_OPTION_CLASS_KEY, None).unwrap_or_default();
                    let Some(mut custom) = new_custom_option(&custom_class) else {
                        Msg::info(
                            "ToolOptions",
                            &format!("Custom option class '{custom_class}' does not exist"),
                        );
                        continue;
                    };
                    custom.read_state(&state);
                    (OptionType::CustomType, OptionValue::Custom(Arc::from(custom)))
                }
                other => {
                    Msg::error(
                        "ToolOptions",
                        &format!("Unsupported wrapped option class: {other}"),
                    );
                    continue;
                }
            };
            let Some(option_name) = element.get_attribute_value(NAME_ATTRIBUTE) else {
                continue;
            };
            let mut option = create_unregistered_option(option_name, option_type, None);
            if first_child.get_name() == CLEARED_VALUE_ELEMENT_NAME {
                option.do_set_current_value(None);
            } else {
                option.do_set_current_value(Some(value));
            }
            let day = element
                .get_attribute_value(LAST_REGISTERED_DATE_ATTRIBUTE)
                .and_then(parse_iso_date)
                .unwrap_or_else(today_epoch_day);
            option.set_last_registered_day(Some(day));
            self.base.insert_option(option);
        }
    }

    /// `getXmlRoot(boolean)`: the options as a `<CATEGORY NAME="...">` element; options at their
    /// default value are written only when `include_default_bindings`.
    pub fn get_xml_root(&self, include_default_bindings: bool) -> Element {
        let mut options = self.base.options_snapshot();
        options.sort_by(|a, b| a.name().cmp(b.name()));
        let mut save_state = AttributedSaveState::with_name(XML_ELEMENT_NAME);
        for option in &options {
            if include_default_bindings || !option.is_default() {
                write_non_wrapped_option(&mut save_state, option);
            }
        }
        let mut root = save_state.save_to_xml();
        root.set_attribute(NAME_ATTRIBUTE, self.get_name());
        for option in &options {
            if include_default_bindings || !option.is_default() {
                write_wrapped_option(&mut root, option);
            }
        }
        root
    }
}

impl PartialEq for ToolOptions {
    /// `equals(Object)`: same name and the same option names with equal values.
    fn eq(&self, other: &Self) -> bool {
        if self.get_name() != other.get_name() {
            return false;
        }
        let names = self.get_option_names();
        if names != other.get_option_names() {
            return false;
        }
        names.iter().all(|n| {
            let mine = self.find_option(n).and_then(|o| o.value(None));
            let theirs = other.find_option(n).and_then(|o| o.value(None));
            option_values_equal(mine.as_ref(), theirs.as_ref())
        })
    }
}

/// `isSupportedBySaveState(Object)`: primitives, strings, enums and byte arrays.
fn is_supported_by_save_state(value: Option<&OptionValue>) -> bool {
    matches!(
        value,
        Some(
            OptionValue::Int(_)
                | OptionValue::Long(_)
                | OptionValue::Float(_)
                | OptionValue::Double(_)
                | OptionValue::Boolean(_)
                | OptionValue::String(_)
                | OptionValue::Enum(_)
                | OptionValue::ByteArray(_)
        )
    )
}

fn write_non_wrapped_option(save_state: &mut AttributedSaveState, option: &OptionEntry) {
    let value = option.value(None);
    let name = option.name();
    match &value {
        Some(OptionValue::Int(v)) => save_state.put_int(name, *v),
        Some(OptionValue::Long(v)) => save_state.put_long(name, *v),
        Some(OptionValue::Float(v)) => save_state.put_float(name, *v),
        Some(OptionValue::Double(v)) => save_state.put_double(name, *v),
        Some(OptionValue::Boolean(v)) => save_state.put_boolean(name, *v),
        Some(OptionValue::String(v)) => save_state.put_string(name, Some(v)),
        Some(OptionValue::Enum(v)) => save_state.put_enum_value(name, v.clone()),
        Some(OptionValue::ByteArray(v)) => save_state.put_bytes(name, Some(v)),
        _ => return,
    }
    let mut attrs = BTreeMap::new();
    attrs.insert(
        LAST_REGISTERED_DATE_ATTRIBUTE.to_string(),
        format_iso_date(option.last_registered_day()),
    );
    save_state.add_attributes(name, attrs);
}

fn write_wrapped_option(root: &mut Element, option: &OptionEntry) {
    let value = option.current_value();
    if is_supported_by_save_state(value) {
        return; // handled by write_non_wrapped_option
    }
    // wrapOption: the value (or default) determines the wrapper.
    let Some(type_value) = value.or(option.default_value()) else {
        return; // cannot write an option without a value to determine its type
    };
    let mut ss = SaveState::with_name(WRAPPED_OPTION_NAME);
    let class_name = match type_value {
        OptionValue::File(_) => WRAPPED_FILE_CLASS,
        OptionValue::Date(_) => WRAPPED_DATE_CLASS,
        OptionValue::Custom(_) => WRAPPED_CUSTOM_CLASS,
        other => {
            Msg::warn(
                "ToolOptions",
                &format!(
                    "Option '{}' not saved: no ported wrapper for {} values",
                    option.name(),
                    other.option_type()
                ),
            );
            return;
        }
    };
    let element = match value {
        None => {
            let mut element = ss.save_to_xml();
            element.add_content(Element::new(CLEARED_VALUE_ELEMENT_NAME));
            element
        }
        Some(value) => {
            match value {
                OptionValue::File(path) => {
                    let abs = std::path::absolute(path).unwrap_or_else(|_| path.clone());
                    ss.put_string("file", Some(&abs.to_string_lossy()));
                }
                OptionValue::Date(date) => ss.put_long("date", date_to_millis(*date)),
                OptionValue::Custom(custom) => {
                    ss.put_string(CUSTOM_OPTION_CLASS_KEY, Some(custom.java_class_name()));
                    custom.write_state(&mut ss);
                }
                _ => return,
            }
            ss.save_to_xml()
        }
    };
    let mut element = element;
    element.set_attribute(NAME_ATTRIBUTE, option.name());
    element.set_attribute(CLASS_ATTRIBUTE, class_name);
    element.set_attribute(
        LAST_REGISTERED_DATE_ATTRIBUTE,
        format_iso_date(option.last_registered_day()),
    );
    root.add_content(element);
}

/// Maps a restored save-state value to an option value (`OptionType.getOptionType(object)`).
fn g_property_to_option_value(value: &GPropertyValue) -> Option<OptionValue> {
    Some(match value {
        GPropertyValue::Int(v) => OptionValue::Int(*v),
        GPropertyValue::Long(v) => OptionValue::Long(*v),
        GPropertyValue::Float(v) => OptionValue::Float(*v),
        GPropertyValue::Double(v) => OptionValue::Double(*v),
        GPropertyValue::Boolean(v) => OptionValue::Boolean(*v),
        GPropertyValue::String(v) => OptionValue::String(v.clone()),
        GPropertyValue::Enum(v) => OptionValue::Enum(v.clone()),
        GPropertyValue::Bytes(v) => OptionValue::ByteArray(v.clone()),
        _ => return None,
    })
}

fn date_to_millis(date: SystemTime) -> i64 {
    match date.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

fn date_from_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}

#[cfg(test)]
mod tests;
