//! Signed, bounded legacy kernel time conversion. Pure integer arithmetic:
//! no host date, timezone, clock observation or DST rules.
use thiserror::Error;

const TICKS_PER_MILLISECOND: i64 = 10_000;
const MILLISECONDS_PER_DAY: i64 = 86_400_000;
const DAYS_BEFORE_1601: i64 = 584_388;
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("Kernel time conversion: {0}")]
pub struct TimeError(pub &'static str);

/// The configured offset is local-minus-UTC, the opposite of Windows bias.
/// This checked signed operation deliberately refuses overflow, like legacy
/// signed to_bytes; it does not wrap or reinterpret a relative timeout.
pub fn local_time(ticks: i64, offset_minutes: i32) -> Result<i64, TimeError> {
    if !(-840..=840).contains(&offset_minutes) {
        return Err(TimeError("invalid resolved UTC offset"));
    }
    let offset = i64::from(offset_minutes)
        .checked_mul(600_000_000)
        .ok_or(TimeError("signed local time overflow"))?;
    ticks
        .checked_add(offset)
        .ok_or(TimeError("signed local time overflow"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeFields {
    pub year: i16,
    pub month: i16,
    pub day: i16,
    pub hour: i16,
    pub minute: i16,
    pub second: i16,
    pub milliseconds: i16,
    pub weekday: i16,
}
impl TimeFields {
    pub fn encode(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (slot, value) in bytes.chunks_exact_mut(2).zip([
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.milliseconds,
            self.weekday,
        ]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}
fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
fn days_before(year: i64) -> i64 {
    let previous = year - 1;
    previous * 365 + previous / 4 - previous / 100 + previous / 400
}
/// Matches legacy datetime's proleptic Gregorian range1..9999. The documented
/// Windows TIME_FIELDS range starts at1601: pre1601 is a legacy extension,
/// not claimed Windows negative-time parity. Floor, rather than truncating
/// signed division, preserves legacy negative sub-millisecond behavior.
pub fn time_fields(ticks: i64) -> Result<TimeFields, TimeError> {
    let milliseconds = ticks.div_euclid(TICKS_PER_MILLISECOND);
    let elapsed_days = milliseconds.div_euclid(MILLISECONDS_PER_DAY);
    let day_number = elapsed_days + DAYS_BEFORE_1601;
    if !(0..days_before(10_000)).contains(&day_number) {
        return Err(TimeError("calendar outside legacy year1..9999 profile"));
    }
    // Bounded binary search, at most14 comparisons for the complete profile.
    let (mut low, mut high) = (1i64, 10_000i64);
    while low + 1 < high {
        let candidate = (low + high) / 2;
        if days_before(candidate) <= day_number {
            low = candidate;
        } else {
            high = candidate;
        }
    }
    let year = low;
    let mut day = day_number - days_before(year);
    let months = [
        31,
        28 + i64::from(leap(year)),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for length in months {
        if day < length {
            break;
        }
        day -= length;
        month += 1;
    }
    let remaining = milliseconds.rem_euclid(MILLISECONDS_PER_DAY);
    Ok(TimeFields {
        year: year as i16,
        month,
        day: (day + 1) as i16,
        hour: (remaining / 3_600_000) as i16,
        minute: (remaining / 60_000 % 60) as i16,
        second: (remaining / 1000 % 60) as i16,
        milliseconds: (remaining % 1000) as i16,
        weekday: ((day_number + 1) % 7) as i16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_calendar_and_offset_match_pinned_extracted_legacy_functions() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("kernel_time_reference.json")).unwrap();
        assert_eq!(corpus["schema"], "kernel-time-legacy-reference-v1");
        assert_eq!(corpus["cases"].as_array().unwrap().len(), 136);
        for row in corpus["cases"].as_array().unwrap() {
            let ticks = row["ticks"].as_i64().unwrap();
            if row["api"] == "fields" {
                let result = time_fields(ticks);
                if let Some(expected) = row["output_hex"].as_str() {
                    let bytes: Vec<u8> = (0..expected.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&expected[i..i + 2], 16).unwrap())
                        .collect();
                    assert_eq!(result.unwrap().encode().as_slice(), bytes, "{row}");
                } else {
                    assert!(result.is_err(), "{row}");
                }
            } else {
                let offset = row["offset_minutes"].as_i64().unwrap() as i32;
                let result = local_time(ticks, offset);
                if let Some(expected) = row["output_ticks"].as_i64() {
                    assert_eq!(result.unwrap(), expected, "{row}");
                } else {
                    assert!(result.is_err(), "{row}");
                }
            }
        }
    }
    #[test]
    fn signed_checked_offset_never_wraps_and_uses_literal_local_minus_utc() {
        assert_eq!(local_time(0, 120).unwrap(), 72_000_000_000);
        assert_eq!(local_time(0, -90).unwrap(), -54_000_000_000);
        assert_eq!(local_time(i64::MAX, 0).unwrap(), i64::MAX);
        assert_eq!(local_time(i64::MIN, 0).unwrap(), i64::MIN);
        assert!(local_time(i64::MAX, 1).is_err());
        assert!(local_time(i64::MIN, -1).is_err());
        assert!(local_time(0, 841).is_err());
        assert!(local_time(0, -841).is_err());
        let first = time_fields(-504_911_232_000_000_000).unwrap();
        assert_eq!(
            (first.year, first.month, first.day, first.weekday),
            (1, 1, 1, 1)
        );
        assert!(time_fields(-504_911_232_000_000_001).is_err());
        let last = time_fields(2_650_467_743_999_999_999).unwrap();
        assert_eq!(
            (last.year, last.month, last.day, last.milliseconds),
            (9999, 12, 31, 999)
        );
        assert!(time_fields(2_650_467_744_000_000_000).is_err());
        let negative = time_fields(-1).unwrap();
        assert_eq!(
            (
                negative.year,
                negative.month,
                negative.day,
                negative.milliseconds
            ),
            (1600, 12, 31, 999)
        );
    }
}
