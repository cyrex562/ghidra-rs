use std::time::{SystemTime, UNIX_EPOCH};

/// Number of milliseconds in one second.
pub const MS_PER_SEC: i64 = 1000;
/// Number of milliseconds in one minute.
pub const MS_PER_MIN: i64 = MS_PER_SEC * 60;
/// Number of milliseconds in one hour.
pub const MS_PER_HOUR: i64 = MS_PER_MIN * 60;
/// Number of milliseconds in one day.
pub const MS_PER_DAY: i64 = MS_PER_HOUR * 24;

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

const SUNDAY: i64 = 0;
const MONDAY: i64 = 1;
const THURSDAY: i64 = 4;
const SATURDAY: i64 = 6;

/// Static utility methods for holidays, business-day arithmetic, and date formatting.
///
/// Dates are represented as milliseconds since the Unix epoch, the same numeric value
/// returned by `java.util.Date#getTime()`. This crate has no time zone database, so
/// unlike the original Java (which used the JVM's default time zone), all calendar
/// field extraction here is performed in UTC.
pub struct DateUtils;

impl DateUtils {
    /// Returns the ten holidays used for business-day calculations, for the given year.
    pub fn get_holidays(year: i32) -> Vec<i64> {
        vec![
            new_years_holiday(year),
            mlk_day(year),
            presidents_day(year),
            memorial_day(year),
            independence_holiday(year),
            labor_day(year),
            columbus_day(year),
            veterans_day(year),
            thanksgiving_day(year),
            christmas_holiday(year),
        ]
    }

    /// Returns `true` if `date` falls on one of the holidays returned by
    /// [`DateUtils::get_holidays`] for that date's year.
    pub fn is_holiday(date: i64) -> bool {
        let date = Self::normalize_date(date);
        let (year, month, _day) = civil_from_days(epoch_day(date));
        match month {
            1 => date == new_years_holiday(year) || date == mlk_day(year),
            2 => date == presidents_day(year),
            5 => date == memorial_day(year),
            7 => date == independence_holiday(year),
            9 => date == labor_day(year),
            10 => date == columbus_day(year),
            11 => date == veterans_day(year) || date == thanksgiving_day(year),
            12 => date == christmas_holiday(year) || date == new_years_holiday(year + 1),
            _ => false,
        }
    }

    /// Returns today's date, normalized to midnight UTC.
    pub fn get_normalized_today() -> i64 {
        Self::normalize_date(current_millis())
    }

    /// Returns `true` if `date` falls on a Saturday or Sunday.
    pub fn is_weekend(date: i64) -> bool {
        let weekday = weekday_from_days(epoch_day(date));
        weekday == SUNDAY || weekday == SATURDAY
    }

    /// Truncates `date` to midnight UTC on the same day.
    pub fn normalize_date(date: i64) -> i64 {
        epoch_day(date) * MS_PER_DAY
    }

    /// Formats the given date as `MM/dd/yyyy`.
    ///
    /// This is in contrast to [`DateUtils::format_date_timestamp`], which also
    /// includes the time-of-day portion of the date.
    pub fn format_date(date: i64) -> String {
        let (year, month, day) = civil_from_days(epoch_day(date));
        format!("{:02}/{:02}/{:04}", month, day, year)
    }

    /// Formats the given date into a compact date string (`mm/dd/yy`).
    pub fn format_compact_date(date: i64) -> String {
        let (year, month, day) = civil_from_days(epoch_day(date));
        format!("{:02}/{:02}/{:02}", month, day, year.rem_euclid(100))
    }

    /// Formats the given date into a string that contains the date and time, e.g.
    /// `Oct 31, 2019 03:24 PM`. This is in contrast to [`DateUtils::format_date`],
    /// which only returns a date string.
    pub fn format_date_timestamp(date: i64) -> String {
        let (year, month, day) = civil_from_days(epoch_day(date));
        let (hour24, minute) = time_of_day(date);
        let (hour12, am_pm) = to_12_hour(hour24);
        format!(
            "{} {:02}, {:04} {:02}:{:02} {}",
            MONTH_NAMES[(month - 1) as usize],
            day,
            year,
            hour12,
            minute,
            am_pm
        )
    }

    /// Returns the current time-of-day as a simple `h:mm` string.
    pub fn format_current_time() -> String {
        let (hour24, minute) = time_of_day(current_millis());
        let (hour12, _am_pm) = to_12_hour(hour24);
        format!("{}:{:02}", hour12, minute)
    }

    /// Returns a date for the given numeric values.
    ///
    /// * `year` - the year
    /// * `month` - the month; 0-based
    /// * `day` - the day of month; 1-based
    pub fn get_date(year: i32, month: i32, day: i32) -> i64 {
        days_from_civil(year, (month + 1) as u32, day as u32) * MS_PER_DAY
    }

    /// Returns all days between the two dates. Returns `0` if the same date is passed
    /// for both parameters. The order of the dates does not matter.
    pub fn get_days_between(date1: i64, date2: i64) -> i32 {
        do_get_days_between(date1, date2, |_| true)
    }

    /// Returns the **business days** between the two dates. Returns `0` if the same
    /// date is passed for both parameters. The order of the dates does not matter.
    pub fn get_business_days_between(date1: i64, date2: i64) -> i32 {
        do_get_days_between(date1, date2, |d| !(Self::is_weekend(d) || Self::is_holiday(d)))
    }

    /// Formats a millisecond duration as an English string expressing the number of
    /// days, hours, minutes and seconds in the duration, e.g.
    /// `"5 hours, 3 mins, 22 secs"`.
    pub fn format_duration(millis: i64) -> String {
        let mut millis = millis;
        let mut days = 0i64;
        let mut hours = 0i64;
        let mut minutes = 0i64;
        let mut seconds = 0i64;
        if millis >= MS_PER_DAY {
            days = millis / MS_PER_DAY;
            millis %= MS_PER_DAY;
        }
        if millis >= MS_PER_HOUR {
            hours = millis / MS_PER_HOUR;
            millis %= MS_PER_HOUR;
        }
        if millis >= MS_PER_MIN {
            minutes = millis / MS_PER_MIN;
            millis %= MS_PER_MIN;
        }
        if millis >= MS_PER_SEC {
            seconds = millis / MS_PER_SEC;
        }

        let mut result = String::new();
        if days > 0 {
            result.push_str(&format!("{} days, ", days));
        }
        if !result.is_empty() || hours > 0 {
            result.push_str(&format!("{} hours, ", hours));
        }
        if !result.is_empty() || minutes > 0 {
            result.push_str(&format!("{} mins, ", minutes));
        }
        result.push_str(&format!("{} secs", seconds));
        result
    }
}

fn do_get_days_between(date1: i64, date2: i64, filter: impl Fn(i64) -> bool) -> i32 {
    let (mut d1, mut d2) = (date1, date2);
    if d1 > d2 {
        std::mem::swap(&mut d1, &mut d2);
    }
    let d1 = DateUtils::normalize_date(d1);
    let d2 = DateUtils::normalize_date(d2);

    let mut current = d1;
    let mut days = 0;
    while current < d2 {
        current += MS_PER_DAY;
        if filter(current) {
            days += 1;
        }
    }
    days
}

fn current_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn epoch_day(date_millis: i64) -> i64 {
    date_millis.div_euclid(MS_PER_DAY)
}

fn time_of_day(date_millis: i64) -> (i64, i64) {
    let ms_of_day = date_millis.rem_euclid(MS_PER_DAY);
    let hour = ms_of_day / MS_PER_HOUR;
    let minute = (ms_of_day % MS_PER_HOUR) / MS_PER_MIN;
    (hour, minute)
}

fn to_12_hour(hour24: i64) -> (i64, &'static str) {
    let am_pm = if hour24 < 12 { "AM" } else { "PM" };
    let hour12 = match hour24 % 12 {
        0 => 12,
        h => h,
    };
    (hour12, am_pm)
}

/// Converts a proleptic-Gregorian civil date (1-based month, 1-based day) into the
/// number of days since the Unix epoch. Based on Howard Hinnant's `days_from_civil`.
fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y as i64 - 1 } else { y as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Converts a day count since the Unix epoch into a proleptic-Gregorian civil date
/// `(year, month, day)`, with a 1-based month and day. Based on Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Returns the day of the week for a day count since the Unix epoch: `0` is Sunday
/// through `6` for Saturday.
fn weekday_from_days(z: i64) -> i64 {
    if z >= -4 {
        (z + 4) % 7
    } else {
        (z + 5) % 7 + 6
    }
}

fn adjust_for_weekend(day: i64) -> i64 {
    match weekday_from_days(day) {
        SATURDAY => day - 1,
        SUNDAY => day + 1,
        _ => day,
    }
}

fn first_day_of_week_in_month(year: i32, month: u32, weekday: i64) -> i64 {
    let mut day = days_from_civil(year, month, 1);
    while weekday_from_days(day) != weekday {
        day += 1;
    }
    day
}

fn last_day_of_week_in_month(year: i32, month: u32, weekday: i64) -> i64 {
    let next_month_first = if month == 12 {
        days_from_civil(year + 1, 1, 1)
    } else {
        days_from_civil(year, month + 1, 1)
    };
    let mut day = next_month_first - 1;
    while weekday_from_days(day) != weekday {
        day -= 1;
    }
    day
}

// Dec 25
fn christmas_holiday(year: i32) -> i64 {
    adjust_for_weekend(days_from_civil(year, 12, 25)) * MS_PER_DAY
}

// 4th Thursday in November
fn thanksgiving_day(year: i32) -> i64 {
    (first_day_of_week_in_month(year, 11, THURSDAY) + 21) * MS_PER_DAY
}

// Nov 11
fn veterans_day(year: i32) -> i64 {
    adjust_for_weekend(days_from_civil(year, 11, 11)) * MS_PER_DAY
}

// 2nd Monday in October
fn columbus_day(year: i32) -> i64 {
    (first_day_of_week_in_month(year, 10, MONDAY) + 7) * MS_PER_DAY
}

// First Monday in September
fn labor_day(year: i32) -> i64 {
    first_day_of_week_in_month(year, 9, MONDAY) * MS_PER_DAY
}

// July 4
fn independence_holiday(year: i32) -> i64 {
    adjust_for_weekend(days_from_civil(year, 7, 4)) * MS_PER_DAY
}

// Last Monday in May
fn memorial_day(year: i32) -> i64 {
    last_day_of_week_in_month(year, 5, MONDAY) * MS_PER_DAY
}

// 3rd Monday in February
fn presidents_day(year: i32) -> i64 {
    (first_day_of_week_in_month(year, 2, MONDAY) + 14) * MS_PER_DAY
}

// 3rd Monday in January
fn mlk_day(year: i32) -> i64 {
    (first_day_of_week_in_month(year, 1, MONDAY) + 14) * MS_PER_DAY
}

// Jan 1
fn new_years_holiday(year: i32) -> i64 {
    adjust_for_weekend(days_from_civil(year, 1, 1)) * MS_PER_DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date_time(year: i32, month: i32, day: i32, hour: i64, minute: i64) -> i64 {
        DateUtils::get_date(year, month, day) + hour * MS_PER_HOUR + minute * MS_PER_MIN
    }

    #[test]
    fn civil_days_round_trip_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_days_round_trip_many_dates() {
        for (y, m, d) in [
            (1969, 12, 31),
            (2000, 2, 29),
            (2019, 11, 22),
            (2019, 11, 25),
            (1, 1, 1),
            (1899, 12, 31),
        ] {
            let z = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(z), (y, m, d), "for {y}-{m}-{d}");
        }
    }

    #[test]
    fn weekday_matches_known_thursday() {
        // Jan 1, 1970 was a Thursday.
        assert_eq!(weekday_from_days(0), THURSDAY);
    }

    #[test]
    fn format_date_formats_mm_dd_yyyy() {
        let date = DateUtils::get_date(2019, 10, 4); // November 4, 2019 (0-based month)
        assert_eq!(DateUtils::format_date(date), "11/04/2019");
    }

    #[test]
    fn format_compact_date_uses_two_digit_year() {
        let date = DateUtils::get_date(2019, 10, 4);
        assert_eq!(DateUtils::format_compact_date(date), "11/04/19");
    }

    #[test]
    fn format_date_timestamp_matches_java_example() {
        let date = date_time(2019, 10, 4, 14, 43); // Nov 04, 2019 02:43 PM
        assert_eq!(DateUtils::format_date_timestamp(date), "Nov 04, 2019 02:43 PM");
    }

    #[test]
    fn format_date_timestamp_midnight_is_12_am() {
        let date = date_time(2019, 0, 1, 0, 0);
        assert_eq!(DateUtils::format_date_timestamp(date), "Jan 01, 2019 12:00 AM");
    }

    #[test]
    fn format_date_timestamp_noon_is_12_pm() {
        let date = date_time(2019, 0, 1, 12, 0);
        assert_eq!(DateUtils::format_date_timestamp(date), "Jan 01, 2019 12:00 PM");
    }

    #[test]
    fn normalize_date_truncates_time_of_day() {
        let base = DateUtils::get_date(2019, 10, 4);
        let with_time = base + 3 * MS_PER_HOUR;
        assert_eq!(DateUtils::normalize_date(with_time), base);
    }

    #[test]
    fn get_days_between_counts_forward() {
        let start = date_time(2019, 10, 4, 14, 43);
        let end = start + 3 * MS_PER_DAY;
        assert_eq!(DateUtils::get_days_between(start, end), 3);
    }

    #[test]
    fn get_days_between_same_day_is_zero() {
        let date = date_time(2019, 10, 4, 14, 43);
        assert_eq!(DateUtils::get_days_between(date, date), 0);
    }

    #[test]
    fn get_days_between_ignores_argument_order() {
        let start = date_time(2019, 10, 4, 14, 43);
        let end = start + 3 * MS_PER_DAY;
        assert_eq!(DateUtils::get_days_between(end, start), 3);
    }

    #[test]
    fn get_business_days_between_skips_weekend() {
        // November 22, 2019 was a Friday; November 25, 2019 was the following Monday.
        let friday = DateUtils::get_date(2019, 10, 22);
        let monday = DateUtils::get_date(2019, 10, 25);
        assert_eq!(DateUtils::get_business_days_between(friday, monday), 1);
    }

    #[test]
    fn is_weekend_identifies_saturday_and_sunday() {
        let friday = DateUtils::get_date(2019, 10, 22);
        let saturday = friday + MS_PER_DAY;
        let sunday = friday + 2 * MS_PER_DAY;
        let monday = friday + 3 * MS_PER_DAY;
        assert!(!DateUtils::is_weekend(friday));
        assert!(DateUtils::is_weekend(saturday));
        assert!(DateUtils::is_weekend(sunday));
        assert!(!DateUtils::is_weekend(monday));
    }

    #[test]
    fn is_holiday_recognizes_christmas_and_adjacent_new_year() {
        let christmas = DateUtils::get_date(2019, 11, 25);
        assert!(DateUtils::is_holiday(christmas));

        let new_years_eve = DateUtils::get_date(2019, 11, 31);
        assert!(!DateUtils::is_holiday(new_years_eve));

        let new_years_day = DateUtils::get_date(2020, 0, 1);
        assert!(DateUtils::is_holiday(new_years_day));
    }

    #[test]
    fn is_holiday_recognizes_thanksgiving_fourth_thursday() {
        // Thanksgiving 2019 fell on Thursday, November 28.
        let thanksgiving = DateUtils::get_date(2019, 10, 28);
        assert!(DateUtils::is_holiday(thanksgiving));
        let day_before = thanksgiving - MS_PER_DAY;
        assert!(!DateUtils::is_holiday(day_before));
    }

    #[test]
    fn get_holidays_returns_ten_entries() {
        assert_eq!(DateUtils::get_holidays(2019).len(), 10);
    }

    #[test]
    fn format_duration_matches_java_examples() {
        assert_eq!(DateUtils::format_duration(100), "0 secs");
        assert_eq!(DateUtils::format_duration(MS_PER_SEC - 1), "0 secs");
        assert_eq!(DateUtils::format_duration(MS_PER_SEC), "1 secs");
        assert_eq!(DateUtils::format_duration(MS_PER_SEC + 1), "1 secs");
        assert_eq!(DateUtils::format_duration(MS_PER_MIN - 1), "59 secs");
        assert_eq!(DateUtils::format_duration(MS_PER_MIN), "1 mins, 0 secs");
        assert_eq!(
            DateUtils::format_duration(MS_PER_MIN + MS_PER_SEC),
            "1 mins, 1 secs"
        );
        assert_eq!(
            DateUtils::format_duration(MS_PER_DAY - 1),
            "23 hours, 59 mins, 59 secs"
        );
        assert_eq!(
            DateUtils::format_duration(MS_PER_DAY),
            "1 days, 0 hours, 0 mins, 0 secs"
        );
        assert_eq!(
            DateUtils::format_duration(MS_PER_DAY + 1),
            "1 days, 0 hours, 0 mins, 0 secs"
        );
    }
}
