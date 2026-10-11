//! `curTime` for the fsys Hello reply.
//!
//! The client parses it with `sscanf("%3s-%02d-%4d %02d:%02d:%02d")` (format string at `0xb5e070`,
//! `FUN_0096d290`) and maps the month name case-insensitively against `JAN`..`DEC` (`FUN_0096cda0`,
//! table `0xb5e024`). The value contains a space, so the TagField encoder quotes it.

use std::time::{SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Days since 1970-01-01 → (year, month 1-12, day 1-31). Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format `t` (UTC) as `Mon-DD-YYYY HH:MM:SS`. Times before 1970 are not representable by the game's
/// parser path and are refused.
pub fn format(t: SystemTime) -> Result<String, String> {
    let secs = t.duration_since(UNIX_EPOCH).map_err(|_| "system clock is before 1970".to_string())?.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    Ok(format!(
        "{}-{:02}-{:04} {:02}:{:02}:{:02}",
        MONTHS[(m - 1) as usize],
        d,
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn known_instants() {
        let at = |s| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(format(at(0)).unwrap(), "Jan-01-1970 00:00:00");
        // 2012-01-01 12:00:00 UTC, the value the old emulator hard-coded.
        assert_eq!(format(at(1_325_419_200)).unwrap(), "Jan-01-2012 12:00:00");
        // 2024-02-29 23:59:59 UTC (leap day).
        assert_eq!(format(at(1_709_251_199)).unwrap(), "Feb-29-2024 23:59:59");
        // 2026-10-10 17:45:43 UTC.
        assert_eq!(format(at(1_791_654_343)).unwrap(), "Oct-10-2026 17:45:43");
    }

    #[test]
    fn month_names_are_the_exe_table_case_insensitively() {
        // .rdata 0xb5e024..0xb5e053, read from mercs2_unpacked.exe: "DEC\0NOV\0...JAN\0".
        let exe = crate::testdata::read_exe("mercs2_unpacked.exe");
        let table = &exe[0x75e024..0x75e054];
        let names: Vec<String> =
            table.chunks(4).map(|c| String::from_utf8(c[..3].to_vec()).unwrap()).rev().collect();
        let ours: Vec<String> = MONTHS.iter().map(|m| m.to_ascii_uppercase()).collect();
        assert_eq!(names, ours);
        assert_eq!(&exe[0x75e070..0x75e08b], b"%3s-%02d-%4d %02d:%02d:%02d");
    }
}
