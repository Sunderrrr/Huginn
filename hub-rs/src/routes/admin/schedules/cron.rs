//! Cron (croniter's 5-field grammar + `get_next`).

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};

use crate::models::scheduled_command::ScheduledCommand;

// ---------------------------------------------------------------------------
// Cron (croniter's 5-field grammar + `get_next`)
// ---------------------------------------------------------------------------

/// A parsed cron field: the sorted set of accepted values plus whether the
/// field was a plain `*` (the vixie "dom OR dow" rule needs to know).
#[derive(Debug, Clone)]
struct CronField {
    values: Vec<u8>,
    star: bool,
}

impl CronField {
    fn contains(&self, value: u8) -> bool {
        self.values.contains(&value)
    }
}

/// A parsed cron expression (minute hour dom month dow).
#[derive(Debug, Clone)]
struct Cron {
    minutes: CronField,
    hours: CronField,
    dom: CronField,
    month: CronField,
    dow: CronField,
}

/// Month and day names accepted by croniter (`JAN`, `MON`, …).
const MONTH_NAMES: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const DOW_NAMES: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

/// Resolve a field token to a number (digits or a name table). Month/day names
/// resolve to their position offset by the field's minimum (`JAN` = 1,
/// `SUN` = 0).
fn resolve_token(token: &str, min: i32, names: Option<&[&str]>) -> Option<i32> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if token.chars().all(|c| c.is_ascii_digit()) {
        return token.parse::<i32>().ok();
    }
    let upper = token.to_ascii_uppercase();
    names
        .and_then(|names| names.iter().position(|n| *n == upper))
        .map(|i| min + i as i32)
}

/// Parse one cron field (`*`, `a`, `a-b`, `a-b/n`, `*/n`, `a/n`, comma lists).
fn parse_field(spec: &str, min: i32, max: i32, names: Option<&[&str]>) -> Option<CronField> {
    let mut values: Vec<u8> = Vec::new();
    for part in spec.split(',') {
        if part.is_empty() {
            return None;
        }
        let mut halves = part.split('/');
        let base = halves.next().unwrap_or_default();
        let step_spec = halves.next();
        if halves.next().is_some() {
            return None;
        }
        let step = match step_spec {
            None => 1i32,
            Some(step) => {
                if !step.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let step: i32 = step.parse().ok()?;
                if step < 1 {
                    return None;
                }
                step
            }
        };
        let (start, end) = if base == "*" {
            (min, max)
        } else if let Some((a, b)) = base.split_once('-') {
            if a.is_empty() || b.is_empty() || b.contains('-') {
                return None;
            }
            let (a, b) = (resolve_token(a, min, names)?, resolve_token(b, min, names)?);
            if a < min || b > max || a > b {
                return None;
            }
            (a, b)
        } else {
            // `a` alone is a single value; `a/n` spans a..max (croniter).
            let value = resolve_token(base, min, names)?;
            if value < min || value > max {
                return None;
            }
            if step_spec.is_some() {
                (value, max)
            } else {
                (value, value)
            }
        };
        let mut v = start;
        while v <= end {
            values.push(v as u8);
            v += step;
        }
    }
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    values.dedup();
    Some(CronField {
        values,
        star: spec == "*",
    })
}

impl Cron {
    fn parse(expr: &str) -> Option<Cron> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return None;
        }
        let minutes = parse_field(fields[0], 0, 59, None)?;
        let hours = parse_field(fields[1], 0, 23, None)?;
        let dom = parse_field(fields[2], 1, 31, None)?;
        let month = parse_field(fields[3], 1, 12, Some(&MONTH_NAMES))?;
        let mut dow = parse_field(fields[4], 0, 7, Some(&DOW_NAMES))?;
        // 7 is Sunday, like 0 (cron/croniter).
        dow.values = dow
            .values
            .into_iter()
            .map(|v| if v == 7 { 0 } else { v })
            .collect();
        dow.values.sort_unstable();
        dow.values.dedup();
        Some(Cron {
            minutes,
            hours,
            dom,
            month,
            dow,
        })
    }

    /// Vixie day rule: with both dom and dow restricted, either may match.
    fn day_matches(&self, at: NaiveDateTime) -> bool {
        let dom = self.dom.contains(at.day() as u8);
        let dow = self.dow.contains(at.weekday().num_days_from_sunday() as u8);
        match (self.dom.star, self.dow.star) {
            (true, true) => true,
            (true, false) => dow,
            (false, true) => dom,
            (false, false) => dom || dow,
        }
    }
}

/// `croniter.is_valid` — true when the expression parses.
pub fn is_valid(expr: &str) -> bool {
    Cron::parse(expr).is_some()
}

fn first_of_next_month(at: NaiveDateTime) -> Option<NaiveDateTime> {
    let (year, month) = if at.month() == 12 {
        (at.year() + 1, 1)
    } else {
        (at.year(), at.month() + 1)
    };
    NaiveDate::from_ymd_opt(year, month, 1)?.and_hms_opt(0, 0, 0)
}

fn first_of_next_day(at: NaiveDateTime) -> Option<NaiveDateTime> {
    at.date().succ_opt()?.and_hms_opt(0, 0, 0)
}

fn first_of_next_hour(at: NaiveDateTime) -> Option<NaiveDateTime> {
    let at = at.with_minute(0)?.with_second(0)?.with_nanosecond(0)?;
    Some(at + Duration::hours(1))
}

/// `croniter(expr, after).get_next(datetime)` — the next occurrence strictly
/// after `after`, evaluated in UTC (the hub feeds it aware UTC datetimes).
/// Returns `None` when no occurrence exists within 40 years (an impossible
/// schedule such as `0 0 30 2 *`), which is what the Python handler's
/// `except Exception` fallback turns into `next_run_at: null`.
pub fn next_after(expr: &str, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let cron = Cron::parse(expr)?;
    let base = after.naive_utc();
    let mut candidate = (base + Duration::minutes(1))
        .with_second(0)?
        .with_nanosecond(0)?;
    let limit = base + Duration::days(366 * 40);
    while candidate <= limit {
        if !cron.month.contains(candidate.month() as u8) {
            candidate = first_of_next_month(candidate)?;
            continue;
        }
        if !cron.day_matches(candidate) {
            candidate = first_of_next_day(candidate)?;
            continue;
        }
        if !cron.hours.contains(candidate.hour() as u8) {
            candidate = first_of_next_hour(candidate)?;
            continue;
        }
        if !cron.minutes.contains(candidate.minute() as u8) {
            candidate += Duration::minutes(1);
            continue;
        }
        return Some(Utc.from_utc_datetime(&candidate));
    }
    None
}

/// `scheduled_commands.next_run_at` — after `last_run_at`, else `created_at`.
pub fn next_run_at(
    sched: &ScheduledCommand,
    after: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    let base = after.or(sched.last_run_at).unwrap_or(sched.created_at);
    next_after(&sched.cron_expression, base)
}

#[cfg(test)]
mod tests {
    use super::super::testing::at;
    use super::*;

    #[test]
    fn cron_validation_matches_croniter() {
        for expr in [
            "* * * * *",
            "*/5 * * * *",
            "0 3 * * *",
            "30 2 * * 1-5",
            "0 0 1 JAN *",
            "0 0 * * 7",
            "15 14 1 * mon",
            "0-30/10 * * * *",
        ] {
            assert!(is_valid(expr), "should be valid: {expr}");
        }
        for expr in [
            "",
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "a * * * *",
        ] {
            assert!(!is_valid(expr), "should be invalid: {expr}");
        }
    }

    #[test]
    fn next_after_matches_croniter_semantics() {
        // Strictly after the base, to the minute.
        assert_eq!(
            next_after("* * * * *", at(2026, 10, 14, 12, 0)).unwrap(),
            at(2026, 10, 14, 12, 1)
        );
        // Sub-minute bases round up to the next minute.
        let base = at(2026, 10, 14, 12, 0) + Duration::seconds(30);
        assert_eq!(
            next_after("* * * * *", base).unwrap(),
            at(2026, 10, 14, 12, 1)
        );
        // Steps.
        assert_eq!(
            next_after("*/15 * * * *", at(2026, 10, 14, 12, 0)).unwrap(),
            at(2026, 10, 14, 12, 15)
        );
        assert_eq!(
            next_after("*/15 * * * *", at(2026, 10, 14, 12, 16)).unwrap(),
            at(2026, 10, 14, 12, 30)
        );
        // Daily at 03:00.
        assert_eq!(
            next_after("0 3 * * *", at(2026, 10, 14, 4, 0)).unwrap(),
            at(2026, 10, 15, 3, 0)
        );
        // Weekdays only (2026-10-14 is a Wednesday → next is Thursday).
        assert_eq!(
            next_after("0 9 * * 1-5", at(2026, 10, 14, 10, 0)).unwrap(),
            at(2026, 10, 15, 9, 0)
        );
        // 7 == Sunday: 2026-10-18 is a Sunday.
        assert_eq!(
            next_after("0 0 * * 7", at(2026, 10, 14, 0, 0)).unwrap(),
            at(2026, 10, 18, 0, 0)
        );
        // Month name, and the dom/dow OR rule ("1st OR Monday").
        assert_eq!(
            next_after("0 0 1 JAN *", at(2026, 10, 14, 0, 0)).unwrap(),
            at(2027, 1, 1, 0, 0)
        );
        assert_eq!(
            next_after("0 0 13 * mon", at(2026, 10, 14, 0, 0)).unwrap(),
            at(2026, 10, 19, 0, 0),
            "dow matches even though the 13th is not near"
        );
        // An impossible schedule has no next run (Python falls back to null).
        assert!(next_after("0 0 30 2 *", at(2026, 10, 14, 0, 0)).is_none());
    }
}
