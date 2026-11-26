//! Go-style number and duration text, and the final stdout text of a run.
//!
//! Ports of progress.go (`formatNumber`, `estimateTime`, `expectedAttempts`,
//! `attemptsPerSecond`), `time.Duration.String` and `Round`, and the text block
//! of main.go `runWithDependencies`. Everything here is public data.
//!
//! The final-text builders return bytes, not `String`: paths and error messages
//! are Go strings that may hold arbitrary bytes, and `%s` prints them raw.

use std::time::Duration;

use crate::encode::hex_into;
use crate::public_result::PathBytes;

/// Go's `%.<prec>f` for a float: Rust's `{:.N}` rounds the exact binary value
/// to nearest even like Go; only the spelling of non-finite values differs.
fn fmt_fixed(x: f64, prec: usize) -> String {
    if x.is_nan() {
        "NaN".to_owned()
    } else if x.is_infinite() {
        if x > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{x:.prec$}")
    }
}

/// Go's `%.<prec>e`: an explicit exponent sign and at least two exponent
/// digits (`1.23e+12`, `2.5e-07`), where Rust prints `1.23e12`.
fn fmt_exp(x: f64, prec: usize) -> String {
    if !x.is_finite() {
        return fmt_fixed(x, prec);
    }
    let text = format!("{x:.prec$e}");
    match text.split_once('e').map(|(m, e)| (m, e.parse::<i32>())) {
        Some((mantissa, Ok(exp))) => {
            let sign = if exp < 0 { '-' } else { '+' };
            format!("{mantissa}e{sign}{:02}", exp.unsigned_abs())
        }
        _ => text,
    }
}

/// Port of `formatNumber`.
pub(crate) fn format_number(n: u64) -> String {
    let x = n as f64;
    if n >= 1_000_000_000_000 {
        fmt_exp(x, 2)
    } else if n >= 1_000_000_000 {
        format!("{}G", fmt_fixed(x / 1_000_000_000.0, 2))
    } else if n >= 1_000_000 {
        format!("{}M", fmt_fixed(x / 1_000_000.0, 2))
    } else if n >= 1_000 {
        format!("{}K", fmt_fixed(x / 1_000.0, 2))
    } else {
        n.to_string()
    }
}

/// Port of `estimateTime`. Go tests `IsInf(seconds, 1)` and `IsNaN`.
pub(crate) fn estimate_time(seconds: f64) -> String {
    if seconds.is_nan() || seconds == f64::INFINITY {
        return "unknown".to_owned();
    }
    if seconds < 60.0 {
        return format!("{}s", fmt_fixed(seconds, 1));
    }
    if seconds < 3600.0 {
        return format!("{}m", fmt_fixed(seconds / 60.0, 1));
    }
    if seconds < 86400.0 {
        return format!("{}h", fmt_fixed(seconds / 3600.0, 1));
    }
    if seconds < 31_557_600.0 {
        return format!("{}d", fmt_fixed(seconds / 86400.0, 1));
    }
    let years = seconds / 31_557_600.0;
    if years >= 1e6 {
        format!("{}y", fmt_exp(years, 1))
    } else {
        format!("{}y", fmt_fixed(years, 1))
    }
}

/// Port of `expectedAttempts`: 16^n in decimal for `n` hex characters, which
/// is 2^128 at n = 32 and does not fit in `u128`. Go returns `invalid` outside 0..=32.
pub(crate) fn expected_attempts(pattern_hex_characters: usize) -> String {
    if pattern_hex_characters > 32 {
        return "invalid".to_owned();
    }
    // Little-endian decimal digits, multiplied by 16 once per character.
    let mut digits = vec![1u8];
    for _ in 0..pattern_hex_characters {
        let mut carry = 0u32;
        for digit in &mut digits {
            let v = u32::from(*digit) * 16 + carry;
            *digit = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

/// Port of `attemptsPerSecond`.
pub(crate) fn attempts_per_second(attempts: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    let rate = attempts as f64 / elapsed.as_secs_f64();
    if rate >= u64::MAX as f64 {
        u64::MAX
    } else {
        // Truncates like Go's `uint64(rate)`.
        rate as u64
    }
}

/// A Go `time.Duration` is an `i64` of nanoseconds: clamp like it.
fn go_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).map_or(i64::MAX as u64, |n| n.min(i64::MAX as u64))
}

/// Port of `Duration.Round(time.Microsecond)`: halves round away from zero, and
/// an overflow gives the largest duration.
pub(crate) fn round_to_microsecond(d: Duration) -> Duration {
    let nanos = go_nanos(d);
    let remainder = nanos % 1000;
    let rounded = if remainder * 2 < 1000 {
        nanos - remainder
    } else {
        nanos.saturating_add(1000 - remainder).min(i64::MAX as u64)
    };
    Duration::from_nanos(rounded)
}

/// Port of `time.Duration.String` for a non-negative duration, for example
/// `1.1µs`, `4m5.001s`, `1h0m0s`.
pub(crate) fn go_duration_string(d: Duration) -> String {
    let u = go_nanos(d);
    if u == 0 {
        return "0s".to_owned();
    }
    // `v / 10^prec` with its fraction, trailing zeros dropped (Go `fmtFrac`).
    let frac = |v: u64, prec: u32| -> String {
        let scale = 10u64.pow(prec);
        let digits = format!("{:0width$}", v % scale, width = prec as usize);
        let digits = digits.trim_end_matches('0');
        if digits.is_empty() {
            (v / scale).to_string()
        } else {
            format!("{}.{digits}", v / scale)
        }
    };
    if u < 1_000_000_000 {
        return match u {
            0..1_000 => format!("{u}ns"),
            1_000..1_000_000 => format!("{}µs", frac(u, 3)),
            _ => format!("{}ms", frac(u, 6)),
        };
    }
    let seconds = u / 1_000_000_000;
    let mut text = format!("{}s", frac(u % 60_000_000_000, 9));
    let minutes = seconds / 60;
    if minutes > 0 {
        text = format!("{}m{text}", minutes % 60);
        let hours = minutes / 60;
        if hours > 0 {
            text = format!("{hours}h{text}");
        }
    }
    text
}

/// `Benchmark complete: <n> attempts in <elapsed> (<rate>/s average), generator=<g>\n`.
pub(crate) fn benchmark_text(attempts: u64, elapsed: Duration, generator: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "Benchmark complete: {} attempts in {} ({}/s average), generator=",
        format_number(attempts),
        go_duration_string(round_to_microsecond(elapsed)),
        format_number(attempts_per_second(attempts, elapsed)),
    )
    .into_bytes();
    out.extend_from_slice(generator);
    out.push(b'\n');
    out
}

/// `Search failed: <error>\n`.
pub(crate) fn search_failed_text(error: &[u8]) -> Vec<u8> {
    let mut out = b"Search failed: ".to_vec();
    out.extend_from_slice(error);
    out.push(b'\n');
    out
}

/// What the "found" text prints. Every list is the one that goes into the JSON
/// result, in the same order.
pub(crate) struct FoundText<'a> {
    pub address: &'a [u8; 16],
    pub attempts: u64,
    pub verified: &'a [PathBytes],
    pub unverified: &'a [PathBytes],
    pub deviations: &'a [Vec<u8>],
    pub notices: &'a [Vec<u8>],
    /// Go prints `Identity not verified saved: <cause>` when the run is not a
    /// dry run and nothing was saved; the caller passes the cause in that case.
    pub not_saved_cause: Option<&'a [u8]>,
}

impl FoundText<'_> {
    /// `Found matching address: <addr>\n  Total attempts: <n>\n` and the optional lines.
    pub(crate) fn render(&self) -> Vec<u8> {
        let mut out = b"Found matching address: ".to_vec();
        hex_into(&mut out, self.address);
        out.extend_from_slice(format!("\n  Total attempts: {}\n", self.attempts).as_bytes());
        let mut line = |prefix: &str, value: &[u8]| {
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(value);
            out.push(b'\n');
        };
        for path in self.verified {
            line("  Saved and verified: ", &path.go_bytes());
        }
        for path in self.unverified {
            line("  Unverified retained file: ", &path.go_bytes());
        }
        for warning in self.deviations {
            line("  Warning: ", warning);
        }
        for note in self.notices {
            line("  Note: ", note);
        }
        if let Some(cause) = self.not_saved_cause {
            line("  Identity not verified saved: ", cause);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // How for every table below: a scratch Go 1.27.4 program (the toolchain that
    // built the reference binary) holding `formatNumber` and `estimateTime`
    // copied verbatim from progress.go, `time.Duration.String` and `Round`, and
    // `big.Int` shifts for `expectedAttempts`.
    #[test]
    fn format_number_equals_go_at_every_threshold() {
        for (n, want) in [
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (1000, "1.00K"),
            (1005, "1.00K"),
            // 1.125 is exact in binary: Go rounds the tie to even.
            (1125, "1.12K"),
            (1234, "1.23K"),
            (2810, "2.81K"),
            (55040, "55.04K"),
            (999_994, "999.99K"),
            (999_995, "1000.00K"),
            (999_999, "1000.00K"),
            (1_000_000, "1.00M"),
            (1_125_000, "1.12M"),
            (12_345_678, "12.35M"),
            (999_999_999, "1000.00M"),
            (1_000_000_000, "1.00G"),
            (1_125_000_000, "1.12G"),
            (1_234_567_890, "1.23G"),
            (999_999_999_999, "1000.00G"),
            (1_000_000_000_000, "1.00e+12"),
            (1_234_567_890_123, "1.23e+12"),
            (9_999_999_999_999, "1.00e+13"),
            (123_456_789_012_345_678, "1.23e+17"),
            (u64::MAX, "1.84e+19"),
        ] {
            assert_eq!(format_number(n), want, "n = {n}");
        }
    }

    #[test]
    fn estimate_time_equals_go_in_every_unit() {
        for (s, want) in [
            (0.0, "0.0s"),
            (0.05, "0.1s"),
            (0.25, "0.2s"),
            (0.35, "0.3s"),
            (59.94, "59.9s"),
            (59.95, "60.0s"),
            (60.0, "1.0m"),
            (90.0, "1.5m"),
            (3599.9, "60.0m"),
            (3600.0, "1.0h"),
            (5400.0, "1.5h"),
            (86399.0, "24.0h"),
            (86400.0, "1.0d"),
            (129_600.0, "1.5d"),
            (31_557_599.0, "365.2d"),
            (31_557_600.0, "1.0y"),
            (47_336_400.0, "1.5y"),
            (1e9, "31.7y"),
            (31_557_600e6 - 1.0, "1000000.0y"),
            (31_557_600e6, "1.0e+06y"),
            (31_557_600.0 * 2.5e6, "2.5e+06y"),
            (1e30, "3.2e+22y"),
            (1e300, "3.2e+292y"),
            (f64::INFINITY, "unknown"),
            (f64::NAN, "unknown"),
            (f64::NEG_INFINITY, "-Infs"),
        ] {
            assert_eq!(estimate_time(s), want, "seconds = {s:e}");
        }
    }

    #[test]
    fn exponent_has_a_sign_and_two_digits_unlike_rust() {
        // Rust prints 1.23e12; Go's %e prints 1.23e+12, and e-07 for negatives.
        assert_eq!(format!("{:.2e}", 1.234e12), "1.23e12");
        assert_eq!(fmt_exp(1.234e12, 2), "1.23e+12");
        assert_eq!(fmt_exp(2.5e-7, 1), "2.5e-07");
        assert_eq!(fmt_exp(1e100, 1), "1.0e+100");
    }

    #[test]
    fn expected_attempts_equals_go_for_every_length() {
        let go = [
            "1",
            "16",
            "256",
            "4096",
            "65536",
            "1048576",
            "16777216",
            "268435456",
            "4294967296",
            "68719476736",
            "1099511627776",
            "17592186044416",
            "281474976710656",
            "4503599627370496",
            "72057594037927936",
            "1152921504606846976",
            "18446744073709551616",
            "295147905179352825856",
            "4722366482869645213696",
            "75557863725914323419136",
            "1208925819614629174706176",
            "19342813113834066795298816",
            "309485009821345068724781056",
            "4951760157141521099596496896",
            "79228162514264337593543950336",
            "1267650600228229401496703205376",
            "20282409603651670423947251286016",
            "324518553658426726783156020576256",
            "5192296858534827628530496329220096",
            "83076749736557242056487941267521536",
            "1329227995784915872903807060280344576",
            "21267647932558653966460912964485513216",
            "340282366920938463463374607431768211456",
        ];
        for (n, want) in go.iter().enumerate() {
            assert_eq!(expected_attempts(n), *want, "n = {n}");
        }
        assert_eq!(expected_attempts(33), "invalid");
    }

    #[test]
    fn duration_string_equals_go() {
        let ns = Duration::from_nanos;
        for (d, want) in [
            (ns(0), "0s"),
            (ns(1), "1ns"),
            (ns(999), "999ns"),
            (ns(1000), "1µs"),
            (ns(1100), "1.1µs"),
            (ns(1999), "1.999µs"),
            (ns(2_200_000), "2.2ms"),
            (ns(3_300_000_000), "3.3s"),
            (ns(245_000_000_000), "4m5s"),
            (ns(245_001_000_000), "4m5.001s"),
            (ns(18_367_001_000_000), "5h6m7.001s"),
            (ns(480_000_000_001), "8m0.000000001s"),
            (ns(3_600_000_000_000), "1h0m0s"),
            (ns(90_000_000_000_000), "25h0m0s"),
            (ns(1_500_000_000), "1.5s"),
            (ns(59_999_999_999), "59.999999999s"),
            (ns(60_000_000_000), "1m0s"),
            (ns(999_999_999), "999.999999ms"),
            (ns(1_000_000_000), "1s"),
            (ns(101_744_400), "101.7444ms"),
            (ns(i64::MAX as u64), "2562047h47m16.854775807s"),
        ] {
            assert_eq!(go_duration_string(d), want, "{d:?}");
        }
    }

    #[test]
    fn rounding_to_microseconds_equals_go() {
        let ns = Duration::from_nanos;
        for (d, want) in [
            (ns(1), "0s"),
            (ns(499), "0s"),
            (ns(500), "1µs"),
            (ns(999), "1µs"),
            (ns(480_000_000_001), "8m0s"),
            (ns(59_999_999_999), "1m0s"),
            (ns(999_999_999), "1s"),
            (ns(101_744_400), "101.744ms"),
            (ns(i64::MAX as u64), "2562047h47m16.854775807s"),
        ] {
            assert_eq!(go_duration_string(round_to_microsecond(d)), want, "{d:?}");
        }
    }

    #[test]
    fn attempts_per_second_equals_go() {
        let ns = Duration::from_nanos;
        assert_eq!(attempts_per_second(2810, ns(51_130_000)), 54957);
        assert_eq!(attempts_per_second(0, ns(1000)), 0);
        assert_eq!(attempts_per_second(5, ns(0)), 0);
        assert_eq!(attempts_per_second(1000, ns(1)), 999_999_999_999);
        assert_eq!(
            attempts_per_second(123_456_789, ns(1_999_999)),
            61_728_425_364
        );
        assert_eq!(attempts_per_second(1 << 62, ns(1)), u64::MAX);
    }

    // How: the reference binary prints this shape for `lxmf-vanity --benchmark
    // 100ms` (observed: `Benchmark complete: 24.15K attempts in 101.744ms
    // (237.35K/s average), generator=segmented`, and REFERENCE_FACTS section 9
    // quotes 2.81K / 51.13ms). The run's attempts and elapsed time vary, so the
    // exact strings below come from the scratch Go program applying the same
    // statements as main.go to these two inputs.
    #[test]
    fn benchmark_text_equals_go() {
        let text = benchmark_text(24150, Duration::from_nanos(101_744_400), b"segmented");
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "Benchmark complete: 24.15K attempts in 101.744ms (237.36K/s average), generator=segmented\n"
        );
        let text = benchmark_text(2810, Duration::from_nanos(51_130_000), b"independent");
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "Benchmark complete: 2.81K attempts in 51.13ms (54.96K/s average), generator=independent\n"
        );
    }

    // How: the reference binary, `lxmf-vanity --prefix abcd --max-attempts 5
    // --dry-run`, stderr/stdout `Search failed: search attempt limit reached`.
    #[test]
    fn search_failed_text_equals_go() {
        assert_eq!(
            search_failed_text(b"search attempt limit reached"),
            b"Search failed: search attempt limit reached\n"
        );
    }

    #[test]
    fn found_text_prints_every_optional_line_in_go_order() {
        let address = [
            0xa2, 0x2c, 0x5b, 0xa7, 0x51, 0, 0x55, 0x13, 0x3a, 0x6a, 0x59, 0x84, 0xb7, 0x14, 0xff,
            0x4b,
        ];
        let verified = [
            PathBytes::new(b"/o/id".to_vec(), false),
            PathBytes::new(b"/f/id\xff".to_vec(), false),
        ];
        let unverified = [PathBytes::new(b"/o/id2".to_vec(), false)];
        let deviations = [b"dev one".to_vec()];
        let notices = [b"n1".to_vec(), b"n2".to_vec()];
        let found = FoundText {
            address: &address,
            attempts: 8,
            verified: &verified,
            unverified: &unverified,
            deviations: &deviations,
            notices: &notices,
            not_saved_cause: Some(b"disk full"),
        };
        // Same statements as main.go, with Go `%s` printing raw bytes.
        let want = b"Found matching address: a22c5ba7510055133a6a5984b714ff4b\n  Total attempts: 8\n  Saved and verified: /o/id\n  Saved and verified: /f/id\xff\n  Unverified retained file: /o/id2\n  Warning: dev one\n  Note: n1\n  Note: n2\n  Identity not verified saved: disk full\n";
        assert_eq!(found.render(), want);
    }

    #[test]
    fn found_text_for_a_plain_dry_run_has_two_lines() {
        let address = [0u8; 16];
        let found = FoundText {
            address: &address,
            attempts: 18_446_744_073_709_551_615,
            verified: &[],
            unverified: &[],
            deviations: &[],
            notices: &[],
            not_saved_cause: None,
        };
        assert_eq!(
            found.render(),
            b"Found matching address: 00000000000000000000000000000000\n  Total attempts: 18446744073709551615\n"
        );
    }
}
