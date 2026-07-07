use std::collections::HashMap;
use std::time::SystemTime;

use serde::Serialize;

use super::IsfObject;

/// Represents an ISF producer descriptor.
///
/// Mirrors `IsfProducer` from Ghidra's Debugger-isf module. Contains metadata
/// about the producer of the ISF document: creation datetime, name, and version.
/// The datetime is formatted as "yyyy-MM-dd HH:mm:ss.SSSSSS" in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IsfProducer {
    pub datetime: String,
    pub name: String,
    pub version: Option<String>,
}

impl IsfProducer {
    /// Creates a new `IsfProducer` from metadata and creation time.
    ///
    /// Extracts the Ghidra version from `meta_data` using the key
    /// `"Created With Ghidra Version"`. The `creation_time` is formatted
    /// as "yyyy-MM-dd HH:mm:ss.SSSSSS" in UTC, matching the Java behavior
    /// with `SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSSSS")`.
    ///
    /// # Arguments
    ///
    /// * `meta_data` - Metadata map extracted from a Program
    /// * `creation_time` - System time of program creation
    pub fn new(meta_data: &HashMap<String, String>, creation_time: SystemTime) -> Self {
        let datetime = format_isf_datetime(creation_time);
        let name = "Ghidra".to_string();
        let version = meta_data.get("Created With Ghidra Version").cloned();

        Self {
            datetime,
            name,
            version,
        }
    }

    pub fn datetime(&self) -> &str {
        &self.datetime
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// Formats a SystemTime as "yyyy-MM-dd HH:mm:ss.SSSSSS" in UTC.
///
/// Mirrors the Java `SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSSSSS")` behavior.
/// If the time is before the Unix epoch or cannot be converted, uses the epoch.
fn format_isf_datetime(time: SystemTime) -> String {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let micros = duration.subsec_micros();

            let days_since_epoch = secs / 86400;
            let secs_in_day = secs % 86400;

            let hours = secs_in_day / 3600;
            let mins = (secs_in_day % 3600) / 60;
            let sec = secs_in_day % 60;

            let (year, month, day) = days_to_ymd(days_since_epoch as i32);

            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                year, month, day, hours, mins, sec, micros
            )
        }
        Err(_) => {
            "1970-01-01 00:00:00.000000".to_string()
        }
    }
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
///
/// Based on the Gregorian calendar. Handles leap years correctly.
fn days_to_ymd(mut days: i32) -> (i32, u32, u32) {
    const DAYS_IN_400: i32 = 146097;
    const DAYS_IN_100: i32 = 36524;
    const DAYS_IN_4: i32 = 1461;
    const DAYS_IN_YEAR: i32 = 365;

    let mut year = 1970;

    let num_400 = days / DAYS_IN_400;
    year += num_400 * 400;
    days %= DAYS_IN_400;

    let mut num_100 = days / DAYS_IN_100;
    if num_100 > 3 {
        num_100 = 3;
    }
    year += num_100 * 100;
    days -= num_100 * DAYS_IN_100;

    let num_4 = days / DAYS_IN_4;
    year += num_4 * 4;
    days %= DAYS_IN_4;

    let mut num_1 = days / DAYS_IN_YEAR;
    if num_1 > 3 {
        num_1 = 3;
    }
    year += num_1;
    days -= num_1 * DAYS_IN_YEAR;

    let is_leap = is_leap_year(year);
    let month_days = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    let mut day_of_month = days + 1;
    for days_in_month in month_days.iter() {
        if day_of_month <= *days_in_month as i32 {
            break;
        }
        day_of_month -= *days_in_month as i32;
        month += 1;
    }

    (year, month, day_of_month as u32)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

impl IsfObject for IsfProducer {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn fixed_name_is_ghidra() {
        let meta = make_map(&[]);
        let time = SystemTime::UNIX_EPOCH;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.name(), "Ghidra");
    }

    #[test]
    fn version_extracted_from_metadata() {
        let meta = make_map(&[
            ("Created With Ghidra Version", "11.0.1"),
        ]);
        let time = SystemTime::UNIX_EPOCH;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.version(), Some("11.0.1"));
    }

    #[test]
    fn missing_version_yields_none() {
        let meta = make_map(&[]);
        let time = SystemTime::UNIX_EPOCH;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.version(), None);
    }

    #[test]
    fn epoch_formats_correctly() {
        let meta = make_map(&[]);
        let time = SystemTime::UNIX_EPOCH;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.datetime(), "1970-01-01 00:00:00.000000");
    }

    #[test]
    fn specific_datetime_formats_correctly() {
        let meta = make_map(&[]);
        let duration = std::time::Duration::new(86400, 0);
        let time = SystemTime::UNIX_EPOCH + duration;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.datetime(), "1970-01-02 00:00:00.000000");
    }

    #[test]
    fn datetime_includes_microseconds() {
        let meta = make_map(&[]);
        let duration = std::time::Duration::new(0, 123456000);
        let time = SystemTime::UNIX_EPOCH + duration;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.datetime(), "1970-01-01 00:00:00.123456");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = make_map(&[]);
        let prod = IsfProducer::new(&meta, SystemTime::UNIX_EPOCH);
        accepts_isf_object(&prod);
    }

    #[test]
    fn clone_is_independent() {
        let meta = make_map(&[("Created With Ghidra Version", "10.3")]);
        let time = SystemTime::UNIX_EPOCH;
        let a = IsfProducer::new(&meta, time);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn leap_year_calculation() {
        let meta = make_map(&[]);
        let days_1972_leap = 365 + 365 + 1;
        let duration = std::time::Duration::from_secs((days_1972_leap as u64) * 86400);
        let time = SystemTime::UNIX_EPOCH + duration;
        let prod = IsfProducer::new(&meta, time);
        assert!(prod.datetime().starts_with("1972-01-"));
    }

    #[test]
    fn all_fields_present() {
        let meta = make_map(&[("Created With Ghidra Version", "11.0")]);
        let time = SystemTime::UNIX_EPOCH;
        let prod = IsfProducer::new(&meta, time);
        assert_eq!(prod.name(), "Ghidra");
        assert_eq!(prod.version(), Some("11.0"));
        assert_eq!(prod.datetime(), "1970-01-01 00:00:00.000000");
    }
}
