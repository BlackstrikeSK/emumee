//! Bounded default indicators from caller-supplied observed bytes or strings.
//! No live-memory enumeration, engine hooks, files, regex backend or checkpoints.
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeSet, net::Ipv6Addr};
mod unicode;

pub const MAX_SCAN_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_MATCHES: usize = 1000;
pub const MAX_VALUE_CHARS: usize = 1024;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const MAX_PATTERNS: usize = 16;
pub const MAX_PATTERN_CHARS: usize = 1024;
pub const WINDOW_CHARS: usize = 8192;
const STEP: usize = WINDOW_CHARS - MAX_VALUE_CHARS;
/// Additional explicit input bound; displayed source still follows legacy 256-codepoint output.
pub const MAX_SOURCE_BYTES: usize = 32 * 1024;
pub const BUILTIN_UNICODE_VERSION: &str = unicode::VERSION;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid memory string capture options")]
    InvalidOptions,
    #[error("Custom memory-string regex compatibility is not ported")]
    UnsupportedLegacyRegex,
    #[error("Memory-string source exceeds the explicit 32 KiB input bound")]
    SourceLimit,
    #[error("Memory-string guest address range overflows u64")]
    AddressOverflow,
    #[error("Lossless lone-surrogate indicator JSON is not ported")]
    UnpairedSurrogatePending,
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    enabled: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self { enabled: true }
    }
}
impl Options {
    pub fn disabled() -> Self {
        Self { enabled: false }
    }
    /// Validate legacy shape, then explicitly refuse every custom pattern.
    /// The saved-report validator remains independently regex-compatible.
    pub fn decode(value: Option<&Value>) -> Result<Self, Error> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }
        let object = value.as_object().ok_or(Error::InvalidOptions)?;
        if object.keys().any(|k| k != "enabled" && k != "regex") {
            return Err(Error::InvalidOptions);
        }
        let enabled = match object.get("enabled") {
            None => true,
            Some(Value::Bool(enabled)) => *enabled,
            _ => return Err(Error::InvalidOptions),
        };
        if let Some(patterns) = object.get("regex") {
            let patterns = patterns.as_array().ok_or(Error::InvalidOptions)?;
            if patterns.len() > MAX_PATTERNS
                || patterns.iter().any(|p| {
                    p.as_str()
                        .is_none_or(|s| s.is_empty() || s.chars().count() > MAX_PATTERN_CHARS)
                })
            {
                return Err(Error::InvalidOptions);
            }
            if !patterns.is_empty() {
                return Err(Error::UnsupportedLegacyRegex);
            }
        }
        Ok(Self { enabled })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Ipv4,
    Ipv6,
    Url,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Encoding {
    #[serde(rename = "ascii")]
    Ascii,
    #[serde(rename = "utf-16le")]
    Wide,
    #[serde(rename = "managed")]
    Managed,
}
impl Format {
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Url => "url",
        }
    }
}
impl Encoding {
    fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Wide => "utf-16le",
            Self::Managed => "managed",
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Match {
    pub format: Format,
    pub value: String,
    pub source: String,
    pub encoding: Encoding,
    pub offset: u64,
    pub address: Option<String>,
}
impl Match {
    fn legacy_json_bytes(&self) -> usize {
        // Six quoted keys, colon/comma spaces and braces:74 bytes.
        74 + ascii_quoted_len(self.format.label())
            + ascii_quoted_len(&self.value)
            + ascii_quoted_len(&self.source)
            + ascii_quoted_len(self.encoding.label())
            + self.offset.to_string().len()
            + self.address.as_ref().map_or(4, |s| ascii_quoted_len(s))
    }
}
fn ascii_quoted_len(text: &str) -> usize {
    2 + text
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 || (c as u32) >= 0x7f => {
                if c as u32 > 0xffff {
                    12
                } else {
                    6
                }
            }
            _ => 1,
        })
        .sum::<usize>()
}
#[derive(Debug, Serialize)]
pub struct Report {
    enabled: bool,
    regex: Vec<String>,
    matches: Vec<Match>,
    scanned_bytes: u64,
    truncated: bool,
    limits: BTreeSet<&'static str>,
}
impl Report {
    pub fn matches(&self) -> &[Match] {
        &self.matches
    }
    pub fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }
}
#[derive(Clone, Copy)]
struct Limits {
    scan: u64,
    matches: usize,
    bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            scan: MAX_SCAN_BYTES,
            matches: MAX_MATCHES,
            bytes: MAX_CAPTURE_BYTES,
        }
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    format: Format,
    value: String,
    source: String,
    encoding: Encoding,
    offset: u64,
    address: Option<String>,
}
pub struct Capture {
    report: Report,
    seen: BTreeSet<Key>,
    match_bytes: usize,
    limits: Limits,
}
impl Default for Capture {
    fn default() -> Self {
        Self::new(Options::default())
    }
}
impl Capture {
    pub fn new(options: Options) -> Self {
        Self {
            report: Report {
                enabled: options.enabled,
                regex: Vec::new(),
                matches: Vec::new(),
                scanned_bytes: 0,
                truncated: false,
                limits: BTreeSet::new(),
            },
            seen: BTreeSet::new(),
            match_bytes: 0,
            limits: Limits::default(),
        }
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn into_report(self) -> Report {
        self.report
    }
    fn active(&self) -> bool {
        self.report.enabled
            && self.report.matches.len() < self.limits.matches
            && !self.report.limits.contains("match_byte_limit")
    }
    fn limit(&mut self, reason: &'static str) {
        self.report.truncated = true;
        self.report.limits.insert(reason);
    }
    fn source(&mut self, source: &str) -> Result<(), Error> {
        if source.len() > MAX_SOURCE_BYTES {
            self.limit("source_length_limit");
            Err(Error::SourceLimit)
        } else {
            Ok(())
        }
    }
    fn retain(
        &mut self,
        format: Format,
        value: String,
        source: &str,
        encoding: Encoding,
        offset: u64,
        base: Option<u64>,
    ) {
        if value.is_empty() {
            return;
        }
        if value.chars().count() > MAX_VALUE_CHARS {
            self.limit("match_length_limit");
            return;
        }
        let address = base.map(|b| format!("0x{:x}", b + offset));
        let key = Key {
            format,
            value: value.clone(),
            source: source.to_owned(),
            encoding,
            offset,
            address: address.clone(),
        };
        if self.seen.contains(&key) {
            return;
        }
        if self.report.matches.len() >= self.limits.matches {
            self.limit("match_limit");
            return;
        }
        let item = Match {
            format,
            value,
            source: source.chars().take(256).collect(),
            encoding,
            offset,
            address,
        };
        let bytes = item.legacy_json_bytes();
        if bytes > self.limits.bytes.saturating_sub(self.match_bytes) {
            self.limit("match_byte_limit");
            return;
        }
        self.match_bytes += bytes;
        self.seen.insert(key);
        self.report.matches.push(item);
        if self.report.matches.len() == self.limits.matches {
            self.limit("match_limit");
        }
    }
    fn found(
        &mut self,
        format: Format,
        text: &[char],
        span: std::ops::Range<usize>,
        value: Option<String>,
        location: &Location<'_>,
        edges: Edges,
    ) {
        let (start, end) = (span.start, span.end);
        if !edges.final_text && end == text.len() {
            if end - start > MAX_VALUE_CHARS {
                self.limit("match_length_limit");
            }
            return;
        }
        if edges.continued && start == 0 {
            return;
        }
        self.retain(
            format,
            value.unwrap_or_else(|| text[start..end].iter().collect()),
            location.source,
            location.encoding,
            location.offset + start as u64 * location.width,
            location.base,
        );
    }
    fn window(
        &mut self,
        text: &[char],
        location: &Location<'_>,
        final_text: bool,
        continued: bool,
    ) {
        let edges = Edges {
            final_text,
            continued,
        };
        let mut at = 0;
        while at < text.len() {
            if let Some(end) = ipv4_candidate(text, at) {
                let value: String = text[at..end].iter().collect();
                if valid_ipv4(&value) {
                    self.found(Format::Ipv4, text, at..end, Some(value), location, edges);
                }
                at = end;
            } else {
                at += 1;
            }
        }
        at = 0;
        while at < text.len() {
            if let Some(end) = ipv6_candidate(text, at) {
                let value: String = text[at..end].iter().collect();
                if valid_ipv6(&value) {
                    self.found(Format::Ipv6, text, at..end, Some(value), location, edges);
                }
                at = end;
            } else {
                at += 1;
            }
        }
        at = 0;
        while at < text.len() {
            if let Some(end) = url_candidate(text, at) {
                let value = trim_url(&text[at..end]);
                if valid_url(&value) {
                    self.found(Format::Url, text, at..end, Some(value), location, edges);
                }
                at = end;
            } else {
                at += 1;
            }
        }
    }
    /// The buffer must already be a complete observed source selected by a caller.
    /// This does not read memory or certify a live mapping/snapshot.
    pub fn scan_memory(&mut self, blob: &[u8], source: &str, base: u64) -> Result<(), Error> {
        if !self.active() {
            return Ok(());
        }
        self.source(source)?;
        let remaining = self.limits.scan - self.report.scanned_bytes;
        let size = blob.len().min(remaining as usize);
        if size > 0 && base.checked_add(size as u64 - 1).is_none() {
            self.limit("address_range_limit");
            return Err(Error::AddressOverflow);
        }
        if blob.len() as u64 > remaining {
            self.limit("scan_byte_limit");
        }
        let blob = &blob[..size];
        self.report.scanned_bytes += size as u64;
        for (encoding, width) in [(Encoding::Ascii, 1usize), (Encoding::Wide, 2)] {
            let mut at = 0;
            while at < blob.len() {
                if !self.active() {
                    return Ok(());
                }
                let start = at;
                while at < blob.len()
                    && printable(blob[at])
                    && (width == 1 || blob.get(at + 1) == Some(&0))
                {
                    at += width;
                }
                if at - start >= 2 * width {
                    let mut window_start = start;
                    while window_start < at {
                        let stop = at.min(window_start + WINDOW_CHARS * width);
                        let text: Vec<char> = blob[window_start..stop]
                            .iter()
                            .step_by(width)
                            .map(|b| *b as char)
                            .collect();
                        self.window(
                            &text,
                            &Location {
                                source,
                                encoding,
                                offset: window_start as u64,
                                base: Some(base),
                                width: width as u64,
                            },
                            stop == at,
                            window_start > start,
                        );
                        if stop == at || !self.active() {
                            break;
                        }
                        window_start += STEP * width;
                    }
                }
                if at == start {
                    at += 1;
                }
            }
        }
        Ok(())
    }
    pub fn scan_string(&mut self, text: &str, source: &str) -> Result<(), Error> {
        if !self.active() {
            return Ok(());
        }
        self.source(source)?;
        let remaining = (self.limits.scan - self.report.scanned_bytes) / 2;
        let length = text.chars().take(remaining as usize + 1).count();
        if length as u64 > remaining {
            self.limit("scan_byte_limit");
        }
        let length = length.min(remaining as usize);
        self.report.scanned_bytes += length as u64 * 2;
        self.characters(text.chars().take(length), source);
        Ok(())
    }
    /// Well-formed UTF16 follows Python-codepoint offsets/accounting. An invalid
    /// selected prefix is refused atomically and explicitly marked pending.
    pub fn scan_managed_utf16(&mut self, units: &[u16], source: &str) -> Result<(), Error> {
        if !self.active() {
            return Ok(());
        }
        self.source(source)?;
        let remaining = (self.limits.scan - self.report.scanned_bytes) / 2;
        let mut count = 0usize;
        let mut invalid = false;
        for item in char::decode_utf16(units.iter().copied()).take(remaining as usize) {
            count += 1;
            invalid |= item.is_err();
        }
        if invalid {
            self.limit("unpaired_surrogate_pending");
            return Err(Error::UnpairedSurrogatePending);
        }
        let has_more = char::decode_utf16(units.iter().copied())
            .take(remaining as usize + 1)
            .count()
            > count;
        if has_more {
            self.limit("scan_byte_limit");
        }
        self.report.scanned_bytes += count as u64 * 2;
        self.characters(
            char::decode_utf16(units.iter().copied())
                .take(count)
                .map(|c| c.expect("selected prefix validated")),
            source,
        );
        Ok(())
    }
    fn characters(&mut self, characters: impl Iterator<Item = char>, source: &str) {
        let mut characters = characters.peekable();
        let mut window = Vec::with_capacity(WINDOW_CHARS);
        let mut start = 0usize;
        loop {
            window.extend(characters.by_ref().take(WINDOW_CHARS - window.len()));
            if window.is_empty() || !self.active() {
                break;
            }
            let final_text = characters.peek().is_none();
            self.window(
                &window,
                &Location {
                    source,
                    encoding: Encoding::Managed,
                    offset: start as u64,
                    base: None,
                    width: 1,
                },
                final_text,
                start > 0,
            );
            if final_text {
                break;
            }
            window.drain(..STEP);
            start += STEP;
        }
    }
}
#[derive(Clone, Copy)]
struct Edges {
    final_text: bool,
    continued: bool,
}
struct Location<'a> {
    source: &'a str,
    encoding: Encoding,
    offset: u64,
    base: Option<u64>,
    width: u64,
}
fn printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}
fn end_boundary(text: &[char], end: usize, extra: char) -> bool {
    text.get(end)
        .is_none_or(|c| !unicode::word(*c) && *c != extra)
}
fn ipv4_candidate(text: &[char], start: usize) -> Option<usize> {
    if start > 0 && (unicode::word(text[start - 1]) || text[start - 1] == '.') {
        return None;
    }
    let mut at = start;
    for part in 0..4 {
        let first = at;
        while at < text.len() && at - first < 3 && text[at].is_ascii_digit() {
            at += 1;
        }
        if at == first {
            return None;
        }
        if part < 3 {
            if text.get(at) != Some(&'.') {
                return None;
            }
            at += 1;
        }
    }
    end_boundary(text, at, '.').then_some(at)
}
fn valid_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && !(p.len() > 1 && p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u8>().is_ok()
        })
}
fn hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}
fn ipv6_candidate(text: &[char], start: usize) -> Option<usize> {
    if start > 0 && (unicode::word(text[start - 1]) || text[start - 1] == ':') {
        return None;
    }
    let mut at = start;
    let mut groups = 0;
    loop {
        let first = at;
        while at < text.len() && at - first < 4 && hex(text[at]) {
            at += 1;
        }
        if text.get(at) == Some(&':') {
            at += 1;
            groups += 1;
        } else {
            at = first;
            break;
        }
    }
    if groups < 2 {
        return None;
    }
    let tail_start = at;
    while at < text.len() && (hex(text[at]) || matches!(text[at], ':' | '.')) {
        at += 1;
    }
    if text.get(at) == Some(&'%') {
        let first = at + 1;
        let mut last = first;
        while last < text.len() && (unicode::word(text[last]) || matches!(text[last], '.' | '-')) {
            last += 1;
        }
        if let Some(end) = (first + 1..=last)
            .rev()
            .find(|end| end_boundary(text, *end, ':'))
        {
            return Some(end);
        }
    }
    (tail_start..=at)
        .rev()
        .find(|end| end_boundary(text, *end, ':'))
}
fn valid_ipv6(text: &str) -> bool {
    let plain = if let Some((plain, scope)) = text.split_once('%') {
        if scope.is_empty() || scope.contains('%') {
            return false;
        }
        plain
    } else {
        text
    };
    plain.parse::<Ipv6Addr>().is_ok()
}
fn scheme_char(actual: char, expected: char) -> bool {
    actual.eq_ignore_ascii_case(&expected) || (expected == 's' && actual == '\u{17f}')
}
fn url_candidate(text: &[char], start: usize) -> Option<usize> {
    if start > 0 && unicode::word(text[start - 1]) {
        return None;
    }
    let prefixes: [&str; 3] = ["https://", "http://", "ftp://"];
    let prefix = prefixes.iter().find(|p| {
        text.get(start..start + p.len()).is_some_and(|part| {
            part.iter()
                .zip(p.bytes())
                .all(|(a, b)| scheme_char(*a, b as char))
        })
    })?;
    let body = start + prefix.len();
    let mut end = body;
    while end < text.len()
        && !unicode::space(text[end])
        && !matches!(text[end], '<' | '>' | '"' | '\'' | '`')
    {
        end += 1;
    }
    (end > body).then_some(end)
}
fn trim_url(text: &[char]) -> String {
    let mut end = text.len();
    while end > 0 && matches!(text[end - 1], '.' | ',' | ';' | '!' | '?') {
        end -= 1;
    }
    for (opening, closing) in [('(', ')'), ('[', ']'), ('{', '}')] {
        let opens = text[..end].iter().filter(|c| **c == opening).count();
        let mut closes = text[..end].iter().filter(|c| **c == closing).count();
        while end > 0 && text[end - 1] == closing && closes > opens {
            end -= 1;
            closes -= 1;
        }
    }
    text[..end].iter().collect()
}
fn valid_url(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once("://") else {
        return false;
    };
    if !scheme.is_ascii()
        || !["http", "https", "ftp"].contains(&scheme.to_ascii_lowercase().as_str())
    {
        return false;
    }
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if netloc.chars().any(unicode::nfkc_reserved) {
        return false;
    }
    let host = netloc.rsplit('@').next().unwrap_or_default();
    let bracketed = netloc.contains('[') || netloc.contains(']');
    if bracketed {
        if !netloc.contains('[') || !netloc.contains(']') {
            return false;
        }
        let hostname = if let Some((before, bracket)) = host.split_once('[') {
            if !before.is_empty() {
                return false;
            }
            let Some((inside, after)) = bracket.split_once(']') else {
                return false;
            };
            if !after.is_empty() && !after.starts_with(':') {
                return false;
            }
            inside
        } else {
            host.split(':').next().unwrap_or_default()
        };
        if let Some(future) = hostname.strip_prefix('v') {
            let Some((version, address)) = future.split_once('.') else {
                return false;
            };
            if version.is_empty()
                || !version.bytes().all(|b| b.is_ascii_hexdigit())
                || address.is_empty()
            {
                return false;
            }
        } else if !valid_ipv6(hostname) {
            return false;
        }
    }
    let hostname = if let Some((_, rest)) = host.split_once('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    !hostname.is_empty()
}

#[cfg(test)]
mod tests;
