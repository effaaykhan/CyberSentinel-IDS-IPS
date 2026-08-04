//! UTC timestamps with sub-second precision.
//!
//! Guide §6 requires every event to carry a UTC timestamp. We render a fixed
//! `YYYY-MM-DDThh:mm:ss.ffffffZ` form — always exactly six fractional digits, so
//! downstream consumers can rely on the width and events sort lexicographically
//! in the order they occurred.
//!
//! Clock *accuracy* is an operational concern: the sensor assumes the host runs
//! NTP (or equivalent). Detecting and reporting clock skew is deferred; see
//! `CLAUDE.md`.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer};
use serde::{Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A UTC instant, serialized as `YYYY-MM-DDThh:mm:ss.ffffffZ`.
///
/// Held at microsecond resolution — the resolution it serializes at — so an
/// event that is written and read back compares equal to the original. Storing
/// nanoseconds we then discard on the wire would make round-tripping lossy and
/// event deduplication subtly wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Current wall-clock time in UTC.
    #[must_use]
    pub fn now() -> Self {
        Self::from_offset_date_time(OffsetDateTime::now_utc())
    }

    /// Wrap an existing [`OffsetDateTime`], converting it to UTC and truncating
    /// it to microseconds.
    #[must_use]
    pub fn from_offset_date_time(value: OffsetDateTime) -> Self {
        let utc = value.to_offset(time::UtcOffset::UTC);
        // Truncate rather than round: an event must never be stamped with a
        // time it had not yet reached.
        let micros = utc.microsecond() * 1_000;
        Self(utc.replace_nanosecond(micros).unwrap_or(utc))
    }

    /// The underlying [`OffsetDateTime`], always at UTC offset.
    #[must_use]
    pub fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }

    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub fn unix_timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }
}

impl fmt::Display for Timestamp {
    /// Renders the canonical CyberSentinel timestamp form.
    ///
    /// Formatted by hand rather than through a format description so the
    /// six-digit fractional part is guaranteed and the operation cannot fail.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.0;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.microsecond(),
        )
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        // Our own output is valid RFC 3339, and so is anything a peer would
        // reasonably hand us.
        OffsetDateTime::parse(&raw, &Rfc3339)
            .map(Self::from_offset_date_time)
            .map_err(|e| de::Error::custom(format!("invalid RFC 3339 timestamp {raw:?}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64, nanos: u32) -> Timestamp {
        let base = OffsetDateTime::from_unix_timestamp(unix).unwrap();
        Timestamp::from_offset_date_time(base + std::time::Duration::from_nanos(u64::from(nanos)))
    }

    #[test]
    fn renders_six_fractional_digits() {
        assert_eq!(at(0, 0).to_string(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(at(0, 1_000).to_string(), "1970-01-01T00:00:00.000001Z");
        assert_eq!(
            at(1_754_325_600, 123_456_000).to_string(),
            "2025-08-04T16:40:00.123456Z"
        );
    }

    #[test]
    fn sub_nanosecond_precision_is_truncated_not_rounded() {
        // 999_999_999ns must not round up into the next second.
        assert_eq!(
            at(0, 999_999_999).to_string(),
            "1970-01-01T00:00:00.999999Z"
        );
    }

    #[test]
    fn json_round_trip_preserves_the_instant() {
        let ts = at(1_754_325_600, 123_456_000);
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "\"2025-08-04T16:40:00.123456Z\"");
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn rejects_garbage() {
        assert!(serde_json::from_str::<Timestamp>("\"not-a-time\"").is_err());
    }

    #[test]
    fn now_is_utc() {
        assert_eq!(
            Timestamp::now().as_offset_date_time().offset(),
            time::UtcOffset::UTC
        );
    }
}
