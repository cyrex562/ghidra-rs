//! Port of `ghidra.framework.options.Option` (and its only in-crate concrete subclass,
//! `ToolOptions.ToolOption`, which simply stores the current value in a field).
//!
//! The Rust type is named [`OptionEntry`] because `Option` collides with `std::option::Option`.
//!
//! Toolkit-neutral differences from Java:
//! - Java's `PropertyEditor` is a Swing bean editor; here the registered editor is an opaque
//!   editor id string the UI layer resolves (see the Qt6 UI spec, "Options / Edit Options").
//! - Java's `LocalDate` last-registered date is kept as a day number since the Unix epoch (UTC),
//!   formatted/parsed as ISO `yyyy-MM-dd` (`DateTimeFormatter.ISO_LOCAL_DATE`) by
//!   [`format_iso_date`] / [`parse_iso_date`].
//! - `inceptionInformation` (a development-mode stack-trace line) is not recorded: Rust has no
//!   equivalent filtered stack trace, and it is only used for a development-mode warning.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::options::option_type::{OptionType, OptionValue};
use crate::framework::seam_stubs::HelpLocation;
use crate::util::date_utils::{civil_from_days, days_from_civil};

/// A shared, thread-safe help location handle, as stored on options and categories.
pub type HelpRef = Arc<dyn HelpLocation + Send + Sync>;

/// `Option.UNREGISTERED_OPTION`: the description reported for an option that was never
/// registered.
pub const UNREGISTERED_OPTION: &str = "Unregistered Option";

/// One named option: its registration metadata (type, description, help, default value, editor)
/// and its current value.
///
/// Port of `ghidra.framework.options.Option` + `ToolOptions.ToolOption`.
#[derive(Clone)]
pub struct OptionEntry {
    name: String,
    option_type: OptionType,
    description: Option<String>,
    help_location: Option<HelpRef>,
    default_value: Option<OptionValue>,
    current_value: Option<OptionValue>,
    is_registered: bool,
    last_registered_day: Option<i64>,
    editor_id: Option<String>,
}

impl OptionEntry {
    /// `new ToolOption(...)` with `isRegistered == true`: a registered option whose current
    /// value starts at its default.
    pub fn new_registered(
        name: &str,
        option_type: OptionType,
        description: Option<&str>,
        help_location: Option<HelpRef>,
        default_value: Option<OptionValue>,
        editor_id: Option<String>,
    ) -> Self {
        OptionEntry {
            name: name.to_string(),
            option_type,
            description: description.map(str::to_string),
            help_location,
            current_value: default_value.clone(),
            default_value,
            is_registered: true,
            last_registered_day: Some(today_epoch_day()),
            editor_id,
        }
    }

    /// `new ToolOption(...)` with `isRegistered == false`: an option created by access (or by
    /// restoring saved state) before anyone registered it.
    pub fn new_unregistered(
        name: &str,
        option_type: OptionType,
        default_value: Option<OptionValue>,
    ) -> Self {
        OptionEntry {
            name: name.to_string(),
            option_type,
            description: None,
            help_location: None,
            current_value: default_value.clone(),
            default_value,
            is_registered: false,
            last_registered_day: None,
            editor_id: None,
        }
    }

    /// `updateRegistration(...)`: fills in any registration information not previously set and
    /// marks the option registered. The first registration wins for each field.
    pub fn update_registration(
        &mut self,
        description: Option<&str>,
        help: Option<HelpRef>,
        default_value: Option<OptionValue>,
        editor_id: Option<String>,
    ) {
        if self.description.is_none() {
            self.description = description.map(str::to_string);
        }
        if self.help_location.is_none() {
            self.help_location = help;
        }
        if self.default_value.is_none() {
            self.default_value = default_value;
        }
        if self.editor_id.is_none() {
            self.editor_id = editor_id;
        }
        self.is_registered = true;
        self.last_registered_day = Some(today_epoch_day());
    }

    /// `getCurrentValue()`.
    pub fn current_value(&self) -> Option<&OptionValue> {
        self.current_value.as_ref()
    }

    /// `doSetCurrentValue(Object)`: sets the value without marking the option registered (used
    /// when restoring saved state).
    pub fn do_set_current_value(&mut self, value: Option<OptionValue>) {
        self.current_value = value;
    }

    /// `setCurrentValue(Object)`: sets the value and marks the option as registered (a client
    /// has used it this session).
    pub fn set_current_value(&mut self, value: Option<OptionValue>) {
        self.is_registered = true;
        self.last_registered_day = Some(today_epoch_day());
        self.do_set_current_value(value);
    }

    /// `getName()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The registered editor id (Java: `getPropertyEditor()`), an opaque string the UI resolves.
    pub fn editor_id(&self) -> Option<&str> {
        self.editor_id.as_deref()
    }

    /// `getHelpLocation()`.
    pub fn help_location(&self) -> Option<&HelpRef> {
        self.help_location.as_ref()
    }

    /// `getDescription()`: [`UNREGISTERED_OPTION`] when no description was registered.
    pub fn description(&self) -> &str {
        self.description.as_deref().unwrap_or(UNREGISTERED_OPTION)
    }

    /// `getValue(Object)`: the current value, or `passed_in_default` when both the current and
    /// default values are unset. A `None` current value with a set default means the user cleared
    /// the value, so `None` is returned.
    pub fn value(&self, passed_in_default: Option<OptionValue>) -> Option<OptionValue> {
        if self.current_value.is_none() && self.default_value.is_none() {
            return passed_in_default;
        }
        self.current_value.clone()
    }

    /// `wasRegisteredInPreviousSession()`.
    pub fn was_registered_in_previous_session(&self) -> bool {
        self.last_registered_day.is_some()
    }

    /// `isRegistered()`.
    pub fn is_registered(&self) -> bool {
        self.is_registered
    }

    /// `setLastRegisteredDate(LocalDate)` (as an epoch day number).
    pub fn set_last_registered_day(&mut self, day: Option<i64>) {
        self.last_registered_day = day;
    }

    /// `getLastRegisteredDate()` (as an epoch day number): one year ago when never registered, so
    /// the option does not linger.
    pub fn last_registered_day(&self) -> i64 {
        self.last_registered_day.unwrap_or_else(one_year_ago_epoch_day)
    }

    /// `hasExpired()`: true when the last registration is older than one year.
    pub fn has_expired(&self) -> bool {
        match self.last_registered_day {
            None => false,
            Some(day) => day < one_year_ago_epoch_day(),
        }
    }

    /// `restoreDefault()`.
    pub fn restore_default(&mut self) {
        self.set_current_value(self.default_value.clone());
    }

    /// `isDefault()`: whether the current value equals the default (`Objects.equals`).
    pub fn is_default(&self) -> bool {
        option_values_equal(self.current_value.as_ref(), self.default_value.as_ref())
    }

    /// `getDefaultValue()`.
    pub fn default_value(&self) -> Option<&OptionValue> {
        self.default_value.as_ref()
    }

    /// `getOptionType()`.
    pub fn option_type(&self) -> OptionType {
        self.option_type
    }
}

impl fmt::Debug for OptionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[current value={:?}, default value={:?}, isRegistered={}]",
            self.current_value, self.default_value, self.is_registered
        )
    }
}

/// `Objects.equals` over option values.
///
/// Plain-data variants compare structurally. `Color`/`Font`/`Custom` values are opaque trait
/// objects here (their Rust ports are seams), so they compare by identity, falling back to their
/// `toString()` for custom options (Java custom options define `equals` over their state, which
/// their string form reflects).
pub fn option_values_equal(a: Option<&OptionValue>, b: Option<&OptionValue>) -> bool {
    use OptionValue as V;
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => match (a, b) {
            (V::Int(x), V::Int(y)) => x == y,
            (V::Long(x), V::Long(y)) => x == y,
            (V::String(x), V::String(y)) => x == y,
            (V::Double(x), V::Double(y)) => x.to_bits() == y.to_bits() || x == y,
            (V::Boolean(x), V::Boolean(y)) => x == y,
            (V::Date(x), V::Date(y)) => x == y,
            (V::Float(x), V::Float(y)) => x.to_bits() == y.to_bits() || x == y,
            (V::Enum(x), V::Enum(y)) => x == y,
            (V::Custom(x), V::Custom(y)) => {
                Arc::ptr_eq(x, y)
                    || (x.java_class_name() == y.java_class_name()
                        && x.to_string() == y.to_string())
            }
            (V::ByteArray(x), V::ByteArray(y)) => x == y,
            (V::File(x), V::File(y)) => x == y,
            (V::Color(x), V::Color(y)) => Arc::ptr_eq(x, y),
            (V::Font(x), V::Font(y)) => Arc::ptr_eq(x, y),
            (V::KeyStroke(x), V::KeyStroke(y)) => x == y,
            (V::ActionTrigger(x), V::ActionTrigger(y)) => x == y,
            _ => false,
        },
        _ => false,
    }
}

/// Today's date (UTC) as a day number since 1970-01-01 (Java: `LocalDate.now()`).
pub fn today_epoch_day() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    secs.div_euclid(86_400)
}

/// `LocalDate.now().minusYears(1)` as an epoch day number (Feb 29 clamps to Feb 28).
pub fn one_year_ago_epoch_day() -> i64 {
    minus_years(today_epoch_day(), 1)
}

/// `LocalDate.minusYears(years)` over epoch day numbers.
pub fn minus_years(day: i64, years: i32) -> i64 {
    let (y, m, d) = civil_from_days(day);
    let y = y - years;
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let d = if m == 2 && d == 29 && !leap { 28 } else { d };
    days_from_civil(y, m, d)
}

/// Formats an epoch day number as ISO `yyyy-MM-dd` (`DateTimeFormatter.ISO_LOCAL_DATE`).
pub fn format_iso_date(day: i64) -> String {
    let (y, m, d) = civil_from_days(day);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parses ISO `yyyy-MM-dd` into an epoch day number; `None` when malformed (Java throws
/// `DateTimeParseException`).
pub fn parse_iso_date(text: &str) -> Option<i64> {
    let mut parts = text.splitn(3, '-');
    let y: i32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let day = days_from_civil(y, m, d);
    // Reject dates that do not round-trip (e.g. 2023-02-30).
    (civil_from_days(day) == (y, m, d)).then_some(day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_option_starts_at_default_and_is_default() {
        let o = OptionEntry::new_registered(
            "Foo",
            OptionType::IntType,
            Some("desc"),
            None,
            Some(OptionValue::Int(5)),
            None,
        );
        assert_eq!(o.name(), "Foo");
        assert_eq!(o.option_type(), OptionType::IntType);
        assert!(o.is_registered());
        assert!(o.is_default());
        assert_eq!(o.description(), "desc");
        assert!(matches!(o.current_value(), Some(OptionValue::Int(5))));
    }

    #[test]
    fn unregistered_option_reports_unregistered_description() {
        let o = OptionEntry::new_unregistered("Foo", OptionType::IntType, None);
        assert!(!o.is_registered());
        assert_eq!(o.description(), UNREGISTERED_OPTION);
        assert!(!o.was_registered_in_previous_session());
        assert!(!o.has_expired());
    }

    #[test]
    fn set_current_value_registers_and_restore_default_resets() {
        let mut o =
            OptionEntry::new_unregistered("Foo", OptionType::IntType, Some(OptionValue::Int(1)));
        o.set_current_value(Some(OptionValue::Int(3)));
        assert!(o.is_registered());
        assert!(!o.is_default());
        o.restore_default();
        assert!(o.is_default());
        assert!(matches!(o.current_value(), Some(OptionValue::Int(1))));
    }

    #[test]
    fn value_uses_passed_default_only_when_both_values_are_null() {
        let o = OptionEntry::new_unregistered("Foo", OptionType::ColorType, None);
        assert!(matches!(o.value(Some(OptionValue::Int(9))), Some(OptionValue::Int(9))));

        // Cleared value with a non-null default: null is returned.
        let mut o = OptionEntry::new_unregistered(
            "Foo",
            OptionType::StringType,
            Some(OptionValue::String("d".into())),
        );
        o.set_current_value(None);
        assert!(o.value(Some(OptionValue::String("x".into()))).is_none());
    }

    #[test]
    fn update_registration_first_registration_wins() {
        let mut o = OptionEntry::new_registered(
            "Foo",
            OptionType::IntType,
            Some("Hey"),
            None,
            Some(OptionValue::Int(5)),
            Some("editorA".into()),
        );
        o.update_registration(Some("There"), None, Some(OptionValue::Int(7)), Some("B".into()));
        assert_eq!(o.description(), "Hey");
        assert!(matches!(o.default_value(), Some(OptionValue::Int(5))));
        assert_eq!(o.editor_id(), Some("editorA"));
    }

    #[test]
    fn expiry_tracks_last_registered_date() {
        let mut o = OptionEntry::new_unregistered("Foo", OptionType::IntType, None);
        o.set_last_registered_day(Some(minus_years(today_epoch_day(), 2)));
        assert!(o.has_expired());
        o.set_last_registered_day(Some(today_epoch_day()));
        assert!(!o.has_expired());
    }

    #[test]
    fn iso_dates_round_trip() {
        let day = parse_iso_date("2024-02-29").unwrap();
        assert_eq!(format_iso_date(day), "2024-02-29");
        assert_eq!(format_iso_date(minus_years(day, 1)), "2023-02-28");
        assert_eq!(parse_iso_date("1970-01-01"), Some(0));
        assert_eq!(parse_iso_date("2023-02-30"), None);
        assert_eq!(parse_iso_date("garbage"), None);
    }
}
