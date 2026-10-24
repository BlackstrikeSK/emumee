//! Versioned strict validation of the complete external persona document.
use super::*;
use std::net::{IpAddr, Ipv4Addr};
#[path = "validate_inventory.rs"]
mod inventory;
use inventory::validate_inventory;
#[path = "validate_security.rs"]
mod security;
use security::validate_security;
#[path = "validate_network.rs"]
mod network;
use network::validate_network;
fn plain<'a>(v: &'a Value, p: &str, min: usize, max: usize) -> Result<&'a str> {
    let s = bounded_text(v, p, min, max)?;
    require(!s.chars().any(|c| c < ' '), p, "control character")?;
    Ok(s)
}
fn chars<'a>(
    v: &'a Value,
    p: &str,
    min: usize,
    max: usize,
    allowed: impl Fn(char) -> bool,
) -> Result<&'a str> {
    let s = bounded_text(v, p, min, max)?;
    require(s.chars().all(allowed), p, "invalid characters")?;
    Ok(s)
}
fn guid(v: &Value, p: &str) -> Result<()> {
    let s = text(v, p)?;
    require(
        s.len() == 38
            && s.starts_with('{')
            && s.ends_with('}')
            && s[1..37].bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
        p,
        "expected braced GUID",
    )
}
fn simple<'a>(v: &'a Value, p: &str, min: usize, max: usize) -> Result<&'a str> {
    chars(v, p, min, max, |c| {
        c.is_ascii_alphanumeric() || "_.-".contains(c)
    })
}
fn dns(v: &Value, p: &str) -> Result<String> {
    let s = text(v, p)?
        .strip_suffix('.')
        .unwrap_or(text(v, p)?)
        .to_ascii_lowercase();
    require(
        !s.is_empty()
            && s.len() <= 253
            && s.split('.').all(|x| {
                !x.is_empty()
                    && x.len() <= 63
                    && x.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    && !x.starts_with('-')
                    && !x.ends_with('-')
            }),
        p,
        "invalid DNS name",
    )?;
    Ok(s)
}
fn domain(v: &Value, p: &str) -> Result<()> {
    let s = text(v, p)?;
    require(
        !s.is_empty()
            && s.len() <= 253
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        p,
        "invalid domain",
    )
}
fn unique(set: &mut BTreeSet<String>, s: &str, p: &str) -> Result<()> {
    require(set.insert(fold(s)), p, "duplicate name")
}
fn ipv4(v: &Value, p: &str) -> Result<Ipv4Addr> {
    text(v, p)?
        .parse()
        .map_err(|_| error(p, "invalid IPv4 address"))
}
fn unicast(a: Ipv4Addr) -> bool {
    !a.is_multicast() && !a.is_loopback() && !a.is_unspecified()
}
fn mask(prefix: u32) -> u32 {
    u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
}
fn leap(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 => 28 + u32::from(leap(y)),
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
fn digits(s: &str, p: &str) -> Result<u32> {
    require(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        p,
        "invalid date digits",
    )?;
    s.parse().map_err(|_| error(p, "date integer overflow"))
}
pub(super) fn timestamp(s: &str, p: &str, exact: bool) -> Result<u64> {
    require(
        s.is_ascii() && s.len() >= 20,
        p,
        "timestamp must be ISO8601 with timezone",
    )?;
    require(
        &s[4..5] == "-"
            && &s[7..8] == "-"
            && &s[10..11] == "T"
            && &s[13..14] == ":"
            && &s[16..17] == ":",
        p,
        "invalid ISO8601 separators",
    )?;
    let (y, m, d, h, min, sec) = (
        digits(&s[..4], p)?,
        digits(&s[5..7], p)?,
        digits(&s[8..10], p)?,
        digits(&s[11..13], p)?,
        digits(&s[14..16], p)?,
        digits(&s[17..19], p)?,
    );
    require(
        (1601..=9998).contains(&y)
            && (1..=12).contains(&m)
            && d >= 1
            && d <= days_in_month(y, m)
            && h < 24
            && min < 60
            && sec < 60,
        p,
        "invalid Gregorian timestamp",
    )?;
    let mut rest = &s[19..];
    let mut fraction = 0u64;
    if rest.starts_with('.') {
        require(!exact, p, "metadata timestamp must have whole seconds")?;
        let end = rest[1..]
            .find(|c: char| !c.is_ascii_digit())
            .map_or(rest.len(), |i| i + 1);
        let raw = &rest[1..end];
        require(
            !raw.is_empty() && raw.len() <= 7,
            p,
            "fraction exceeds100ns precision",
        )?;
        fraction = digits(raw, p)? as u64 * 10u64.pow(7 - raw.len() as u32);
        rest = &rest[end..];
    }
    let offset = if rest == "Z" {
        0i64
    } else {
        require(
            !exact
                && rest.len() == 6
                && (rest.starts_with('+') || rest.starts_with('-'))
                && &rest[3..4] == ":",
            p,
            "timestamp needs explicit Z or offset",
        )?;
        let h = digits(&rest[1..3], p)?;
        let m = digits(&rest[4..6], p)?;
        require(
            h <= 14 && m < 60 && (h < 14 || m == 0),
            p,
            "invalid UTC offset",
        )?;
        (h as i64 * 60 + m as i64) * if rest.starts_with('-') { -1 } else { 1 }
    };
    let days = (1601..y).map(|y| 365 + u64::from(leap(y))).sum::<u64>()
        + (1..m).map(|m| days_in_month(y, m) as u64).sum::<u64>()
        + d as u64
        - 1;
    let ticks =
        (days * 86400 + h as u64 * 3600 + min as u64 * 60 + sec as u64) * 10_000_000 + fraction;
    ticks
        .checked_add_signed(-offset * 60 * 10_000_000)
        .ok_or_else(|| error(p, "timestamp predates1601 or overflows"))
}
pub(super) fn format_filetime(ticks: u64) -> Result<String> {
    let mut days = ticks / 864_000_000_000;
    let seconds = (ticks / 10_000_000) % 86400;
    let fraction = ticks % 10_000_000;
    let mut year = 1601u32;
    while days >= 365 + u64::from(leap(year)) {
        days -= 365 + u64::from(leap(year));
        year += 1;
        require(
            year <= 9998,
            "clock_seed",
            "clock outside supported Gregorian range",
        )?;
    }
    let mut month = 1;
    while days >= days_in_month(year, month) as u64 {
        days -= days_in_month(year, month) as u64;
        month += 1;
    }
    let suffix = if fraction == 0 {
        String::new()
    } else {
        format!(".{fraction:07}")
    };
    Ok(format!(
        "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}{suffix}Z",
        days + 1,
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    ))
}
pub(super) fn clock(p: &Value, context: &ResolveContext) -> Result<ClockProjection> {
    let offset = signed(&p["utc_offset_minutes"], "utc_offset_minutes", -840, 840)? as i32;
    let uptime = unsigned(&p["uptime_ms"], "uptime_ms", 0, u64::MAX / 10_000)?;
    let supplied = if p["clock_utc"].is_null() {
        None
    } else {
        Some(timestamp(
            text(&p["clock_utc"], "clock_utc")?,
            "clock_utc",
            false,
        )?)
    };
    let seed = match (supplied, &context.clock_seed) {
        (Some(t), seed) => {
            if let Some(seed) = seed {
                require(
                    seed.utc_filetime == t,
                    "clock_seed",
                    "conflicting explicit persona clock and caller seed",
                )?;
            }
            ClockSeed {
                utc_filetime: t,
                source: ClockSource::PersonaLiteral,
                source_id: "persona.clock_utc".into(),
            }
        }
        (None, Some(seed)) => {
            require(
                !matches!(seed.source, ClockSource::PersonaLiteral),
                "clock_seed",
                "caller cannot claim persona literal provenance",
            )?;
            require(
                !seed.source_id.is_empty() && seed.source_id.len() <= 256,
                "clock_seed.source_id",
                "invalid source identifier",
            )?;
            seed.clone()
        }
        (None, None) => {
            return Err(error(
                "clock_seed",
                "null persona clock requires explicit fixed/controller-resolved seed; no host fallback",
            ));
        }
    };
    format_filetime(seed.utc_filetime)?;
    Ok(ClockProjection {
        utc_filetime: seed.utc_filetime,
        uptime_ms: uptime,
        utc_offset_minutes: offset,
        seed,
    })
}
pub(super) fn guest_path(v: &Value, p: &str) -> Result<String> {
    let s = bounded_text(v, p, 3, 1024)?;
    require(
        s.as_bytes()[0].eq_ignore_ascii_case(&b'C')
            && s.as_bytes().get(1..3) == Some(b":\\")
            && !s[2..].contains(':')
            && !s.chars().any(|c| c < ' ' || "*?<>|\"".contains(c)),
        p,
        "expected bounded absolute C-drive guest path",
    )?;
    let mut components = Vec::new();
    for part in s[3..].split(['\\', '/']) {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => {
                let trim = other.trim_end_matches([' ', '.']);
                require(!trim.is_empty(), p, "empty normalized guest component")?;
                components.push(trim.to_lowercase());
            }
        }
    }
    Ok(format!("c:\\{}", components.join("\\")))
}
pub(super) fn persona(p: &Value, clock: &ClockProjection) -> Result<()> {
    dns(&p["hostname"], "hostname")?;
    plain(&p["user_name"], "user_name", 1, 128)?;
    require(
        !text(&p["user_name"], "user_name")?
            .contains(['\\', '/', ':', '"', '<', '>', '|', '*', '?']),
        "user_name",
        "unsafe account path component",
    )?;
    domain(&p["domain"], "domain")?;
    boolean(&p["user_is_admin"], "user_is_admin")?;
    guest_path(&p["current_dir"], "current_dir")?;
    let sid = text(&p["user_sid"], "user_sid")?;
    require(
        sid.len() <= 184,
        "user_sid",
        "SID text exceeds Windows bound",
    )?;
    let parts: Vec<_> = sid.split('-').collect();
    require(
        parts.len() >= 4
            && parts.len() <= 18
            && parts[0] == "S"
            && parts[1] == "1"
            && parts[2].bytes().all(|b| b.is_ascii_digit())
            && parts[2].parse::<u64>().is_ok_and(|n| n < 1u64 << 48)
            && parts[3..].iter().all(|v| {
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u32>().is_ok()
            }),
        "user_sid",
        "invalid Windows SID",
    )?;
    chars(&p["locale"], "locale", 1, 85, |c| {
        c.is_ascii_alphanumeric() || c == '-'
    })?;
    let tz = bounded_text(&p["timezone"], "timezone", 1, 127)?;
    require(
        tz.encode_utf16().count() <= 127 && !tz.contains(['\\', '/']),
        "timezone",
        "invalid Windows timezone key name",
    )?;
    unsigned(&p["windows_build"], "windows_build", 22000, 65535)?;
    let physical = unsigned(&p["physical_memory_mb"], "physical_memory_mb", 1, 1_048_576)?;
    let available = unsigned(
        &p["available_memory_mb"],
        "available_memory_mb",
        1,
        1_048_576,
    )?;
    require(
        available <= physical,
        "available_memory_mb",
        "available exceeds physical memory",
    )?;
    let cpu = &p["cpu"];
    fields(
        cpu,
        "cpu",
        &[
            "brand",
            "signature",
            "cores",
            "threads_per_core",
            "base_mhz",
            "max_mhz",
        ],
        &["cpuid_overrides"],
    )?;
    let brand = text(&cpu["brand"], "cpu.brand")?;
    require(
        brand.is_ascii() && brand.len() <= 48,
        "cpu.brand",
        "CPU brand must be at most48 ASCII bytes",
    )?;
    for (key, lo, hi) in [
        ("signature", 0, u32::MAX as u64),
        ("cores", 1, 32),
        ("threads_per_core", 1, 2),
        ("base_mhz", 100, 6000),
        ("max_mhz", 100, 7000),
    ] {
        unsigned(&cpu[key], &format!("cpu.{key}"), lo, hi)?;
    }
    require(
        cpu["max_mhz"].as_u64() >= cpu["base_mhz"].as_u64(),
        "cpu.max_mhz",
        "max frequency below base",
    )?;
    if let Some(overrides) = cpu.get("cpuid_overrides") {
        let mut seen = BTreeSet::new();
        for (index, item) in array(overrides, "cpu.cpuid_overrides", 64)?.iter().enumerate() {
            let path = format!("cpu.cpuid_overrides[{index}]");
            fields(
                item,
                &path,
                &["function", "subleaf", "eax", "ebx", "ecx", "edx"],
                &[],
            )?;
            let get = |key: &str| unsigned(&item[key], &format!("{path}.{key}"), 0, u32::MAX as u64);
            let identity = (get("function")?, get("subleaf")?);
            require(seen.insert(identity), &path, "duplicate CPUID leaf")?;
            for key in ["eax", "ebx", "ecx", "edx"] {
                get(key)?;
            }
        }
    }
    guid(&p["volume_guid"], "volume_guid")?;
    let capacity = unsigned(
        &p["volume_capacity_bytes"],
        "volume_capacity_bytes",
        1,
        16 * 1024u64.pow(4),
    )?;
    unsigned(&p["volume_free_bytes"], "volume_free_bytes", 0, capacity)?;
    validate_security(p, clock)?;
    validate_network(p, clock)?;
    validate_inventory(p)?;
    array(&p["registry_keys"], "registry_keys", 512)?;
    array(&p["virtual_files"], "virtual_files", 512)?;
    if let Some(directories) = p.get("virtual_directories") {
        array(directories, "virtual_directories", 512)?;
    }
    Ok(())
}
