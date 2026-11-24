use std::fmt;

use time::OffsetDateTime;
use time::UtcOffset;

use crate::Instant;

/// Display `Instant` in human readable format.
pub(crate) struct DisplayInstant<'a, T, const SIMPLE: bool = true, const LOCAL: bool = true>(pub &'a T);

impl<'a, T, const SIMPLE: bool, const LOCAL: bool> DisplayInstant<'a, T, SIMPLE, LOCAL> {
    /// Display `Instant` in full format: with date and timezone: the format is
    /// "%Y-%m-%dT%H:%M:%S%.6fZ%z"
    #[allow(dead_code)]
    pub fn full(self) -> DisplayInstant<'a, T, false, LOCAL> {
        DisplayInstant(self.0)
    }

    /// Display `Instant` in simple format: without date and timezone: the format is "%H:%M:%S%.6f"
    #[allow(dead_code)]
    pub fn simple(self) -> DisplayInstant<'a, T, true, LOCAL> {
        DisplayInstant(self.0)
    }

    /// Display `Instant` in local timezone.
    #[allow(dead_code)]
    pub fn local(self) -> DisplayInstant<'a, T, SIMPLE, true> {
        DisplayInstant(self.0)
    }

    /// Display `Instant` in UTC timezone.
    #[allow(dead_code)]
    pub fn utc(self) -> DisplayInstant<'a, T, SIMPLE, false> {
        DisplayInstant(self.0)
    }
}

impl<T, const SIMPLE: bool, const LOCAL: bool> fmt::Display for DisplayInstant<'_, T, SIMPLE, LOCAL>
where
    T: Instant,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert Instant to SystemTime
        let sys_t = {
            let sys_now = std::time::SystemTime::now();
            let now = T::now();

            if &now >= self.0 {
                let d = now - *self.0;
                sys_now - d
            } else {
                let d = *self.0 - now;
                sys_now + d
            }
        };

        let utc = OffsetDateTime::from(sys_t);
        let datetime = if LOCAL {
            match UtcOffset::local_offset_at(utc) {
                Ok(offset) => utc.to_offset(offset),
                Err(_) => utc,
            }
        } else {
            utc
        };
        write_timestamp(f, datetime, SIMPLE)
    }
}

fn write_timestamp(f: &mut impl fmt::Write, datetime: OffsetDateTime, simple: bool) -> fmt::Result {
    if !simple {
        write!(f, "{}T", datetime.date())?;
    }
    write!(
        f,
        "{:02}:{:02}:{:02}.{:06}",
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
        datetime.microsecond(),
    )?;
    if !simple {
        let offset = datetime.offset().whole_seconds();
        let sign = if offset < 0 { '-' } else { '+' };
        // Historical local offsets can include seconds. The diagnostic rounds them to minutes.
        let minutes = (offset.unsigned_abs() + 30) / 60;
        write!(f, "Z{sign}{:02}{:02}", minutes / 60, minutes % 60)?;
    }
    Ok(())
}

pub(crate) trait DisplayInstantExt<'a, T> {
    fn display(&'a self) -> DisplayInstant<'a, T, true>;
}

impl<T> DisplayInstantExt<'_, T> for T
where
    T: Instant,
{
    fn display(&self) -> DisplayInstant<'_, T, true> {
        DisplayInstant(self)
    }
}

#[cfg(test)]
mod tests {

    use crate::display_ext::DisplayInstantExt;
    use crate::TokioInstant;

    #[test]
    fn instant_timestamp_formats_utc_and_historical_local_offsets() {
        use super::*;

        let utc = OffsetDateTime::from_unix_timestamp_nanos(123_456_789).unwrap();
        let east = UtcOffset::from_hms(5, 30, 0).unwrap();
        let west = UtcOffset::from_hms(-3, -29, -30).unwrap();
        for (offset, simple, expected) in [
            (UtcOffset::UTC, false, "1970-01-01T00:00:00.123456Z+0000"),
            (east, true, "05:30:00.123456"),
            (east, false, "1970-01-01T05:30:00.123456Z+0530"),
            (west, false, "1969-12-31T20:30:30.123456Z-0330"),
        ] {
            let mut output = String::new();
            write_timestamp(&mut output, utc.to_offset(offset), simple).unwrap();
            assert_eq!(output, expected);
        }
    }

    /// Check the result by a human.
    #[test]
    fn test_display_instant() -> anyhow::Result<()> {
        let now = TokioInstant::now();
        println!("now: {}", now.display());
        println!("now: {}", now.display().full());
        println!("now: {}", now.display().full().simple());
        println!("now: {}", now.display().utc());
        println!("now: {}", now.display().utc().local());
        println!("now: {}", now.display().utc().full());
        Ok(())
    }
}
