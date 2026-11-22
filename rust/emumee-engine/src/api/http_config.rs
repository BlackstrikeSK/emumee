//! URL cracking, handle options and proxy configuration, shared by the WinINet
//! and WinHTTP models.
//!
//! `InternetCrackUrl` and `WinHttpCrackUrl` are pure string work, so they are
//! carried out for real: one parser answers both, filling the caller's
//! `URL_COMPONENTS` at the offsets a compiler would use for its pointer width,
//! and honoring both documented modes — pointers *into the caller's own URL*
//! when a component pointer is null, or a copy with its terminator when the
//! caller supplied a buffer (with `ERROR_INSUFFICIENT_BUFFER` and the required
//! length when it is too small).
//!
//! Options are kept per handle so a set is visible to the matching query, and
//! what the sample asked for is recorded: a proxy change, a security-flag
//! relaxation or a timeout is exactly the kind of configuration worth seeing.
//! The proxy configuration itself is reported as a direct connection with no
//! automatic configuration — the truth of this profile — and
//! `WinHttpGetProxyForUrl` reports that autodetection failed rather than
//! inventing a proxy that could not be reached.
use super::*;
use std::collections::BTreeMap;

/// INTERNET_SCHEME values, in the order wininet.h declares them.
pub(super) const SCHEME_UNKNOWN: u32 = u32::MAX;
const SCHEME_FTP: u32 = 1;
const SCHEME_GOPHER: u32 = 2;
const SCHEME_HTTP: u32 = 3;
const SCHEME_HTTPS: u32 = 4;
const SCHEME_FILE: u32 = 5;

pub(super) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub(super) const ERROR_INVALID_PARAMETER: u32 = 87;

/// Bound on a URL this model will crack.
pub(super) const MAX_URL: usize = 2048;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub urls_cracked: u64,
    pub option_sets: u64,
    pub option_queries: u64,
    pub proxy_queries: u64,
    pub headers_added: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that configured nothing serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.urls_cracked == 0
            && self.option_sets == 0
            && self.option_queries == 0
            && self.proxy_queries == 0
            && self.headers_added == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    /// Option values a guest set, per handle.
    options: BTreeMap<(u64, u32), Vec<u8>>,
    /// Headers added to a request before it is sent.
    headers: BTreeMap<u64, BTreeMap<String, String>>,
    pub report: Report,
}

impl State {
    pub(super) fn set_option(&mut self, handle: u64, option: u32, value: Vec<u8>) {
        if self.options.len() < 256 {
            self.options.insert((handle, option), value);
        }
    }
    pub(super) fn option(&self, handle: u64, option: u32) -> Option<&[u8]> {
        self.options.get(&(handle, option)).map(Vec::as_slice)
    }
    /// The headers a guest added to a request, ready to merge at send time.
    pub(super) fn added_headers(&self, handle: u64) -> BTreeMap<String, String> {
        self.headers.get(&handle).cloned().unwrap_or_default()
    }
    pub(super) fn add_header(&mut self, handle: u64, name: String, value: String) {
        let entry = self.headers.entry(handle).or_default();
        if entry.len() < 64 {
            entry.insert(name, value);
        }
    }
    pub(super) fn remove_header(&mut self, handle: u64, name: &str) -> bool {
        self.headers
            .get_mut(&handle)
            .is_some_and(|entry| entry.remove(name).is_some())
    }
    pub(super) fn has_header(&self, handle: u64, name: &str) -> bool {
        self.headers
            .get(&handle)
            .is_some_and(|entry| entry.contains_key(name))
    }
    /// Forget a closed handle's configuration.
    pub(super) fn forget(&mut self, handle: u64) {
        self.options.retain(|(owner, _), _| *owner != handle);
        self.headers.remove(&handle);
    }
    pub(super) fn record(&mut self, api: &'static str, detail: String) {
        match api {
            "InternetCrackUrl" | "WinHttpCrackUrl" => self.report.urls_cracked += 1,
            "InternetSetOption" | "WinHttpSetOption" => self.report.option_sets += 1,
            "InternetQueryOption" => self.report.option_queries += 1,
            "WinHttpGetProxyForUrl" | "WinHttpGetIEProxyConfigForCurrentUser" => {
                self.report.proxy_queries += 1
            }
            "WinHttpAddRequestHeaders" => self.report.headers_added += 1,
            _ => {}
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event { api, detail });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

/// A URL split into the components `URL_COMPONENTS` carries. Each component is
/// a byte range inside the original URL text, so a caller asking for pointers
/// into its own buffer gets exactly the addresses it expects.
pub(super) struct Components {
    pub scheme: std::ops::Range<usize>,
    pub number: u32,
    pub host: std::ops::Range<usize>,
    pub port: u16,
    pub user: std::ops::Range<usize>,
    pub password: std::ops::Range<usize>,
    pub path: std::ops::Range<usize>,
    pub extra: std::ops::Range<usize>,
    /// The path a caller is given when the URL carried none.
    pub implied_root: bool,
}

fn scheme_number(scheme: &str) -> u32 {
    match scheme {
        "http" => SCHEME_HTTP,
        "https" => SCHEME_HTTPS,
        "ftp" => SCHEME_FTP,
        "gopher" => SCHEME_GOPHER,
        "file" => SCHEME_FILE,
        _ => SCHEME_UNKNOWN,
    }
}

fn default_port(number: u32) -> u16 {
    match number {
        SCHEME_HTTPS => 443,
        SCHEME_FTP => 21,
        SCHEME_GOPHER => 70,
        _ => 80,
    }
}

/// Split a URL the way the crackers document it. `None` means the text is not
/// a URL this model can split; an unknown scheme still parses, and the caller
/// decides whether to refuse it.
pub(super) fn parse(url: &str) -> Option<Components> {
    let empty = 0..0;
    let separator = url.find("://")?;
    let scheme = 0..separator;
    if scheme.is_empty()
        || !url[scheme.clone()]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return None;
    }
    let number = scheme_number(&url[scheme.clone()].to_ascii_lowercase());
    let rest = separator + 3;
    // The authority runs to the first path, query or fragment delimiter.
    let end = url[rest..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |at| rest + at);
    let authority = rest..end;
    let (credentials, host_part) = match url[authority.clone()].rfind('@') {
        Some(at) => (rest..rest + at, rest + at + 1..end),
        None => (empty.clone(), authority.clone()),
    };
    let (user, password) = if credentials.is_empty() {
        (empty.clone(), empty.clone())
    } else {
        match url[credentials.clone()].find(':') {
            Some(at) => (
                credentials.start..credentials.start + at,
                credentials.start + at + 1..credentials.end,
            ),
            None => (credentials.clone(), empty.clone()),
        }
    };
    // A bracketed IPv6 literal is outside this profile's address family.
    if url[host_part.clone()].starts_with('[') {
        return None;
    }
    let (host, port) = match url[host_part.clone()].find(':') {
        Some(at) => {
            let digits = &url[host_part.start + at + 1..host_part.end];
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (
                host_part.start..host_part.start + at,
                digits.parse::<u16>().ok()?,
            )
        }
        None => (host_part.clone(), default_port(number)),
    };
    if host.is_empty() {
        return None;
    }
    // The path ends where the query or fragment begins; both belong to the
    // extra information.
    let extra_at = url[end..]
        .find(['?', '#'])
        .map_or(url.len(), |at| end + at);
    Some(Components {
        scheme,
        number,
        host,
        port,
        user,
        password,
        path: end..extra_at,
        extra: extra_at..url.len(),
        implied_root: end == extra_at,
    })
}

/// `URL_COMPONENTS` field offsets for a pointer width.
pub(super) struct Layout {
    pub size: usize,
    scheme: usize,
    scheme_length: usize,
    number: usize,
    host: usize,
    host_length: usize,
    port: usize,
    user: usize,
    user_length: usize,
    password: usize,
    password_length: usize,
    path: usize,
    path_length: usize,
    extra: usize,
    extra_length: usize,
}

fn align_to(value: usize, align: usize) -> usize {
    value + (align - value % align) % align
}

impl Layout {
    pub(super) fn new(width: usize) -> Self {
        let host = align_to(2 * width + 8, width);
        let port = host + width + 4;
        let user = align_to(port + 2, width);
        let password = align_to(user + width + 4, width);
        let path = align_to(password + width + 4, width);
        let extra = align_to(path + width + 4, width);
        Self {
            size: align_to(extra + width + 4, width),
            scheme: width,
            scheme_length: 2 * width,
            number: 2 * width + 4,
            host,
            host_length: host + width,
            port,
            user,
            user_length: user + width,
            password,
            password_length: password + width,
            path,
            path_length: path + width,
            extra,
            extra_length: extra + width,
        }
    }
}

/// One component's two members: where its text goes and how long it is.
struct Slot {
    pointer: usize,
    length: usize,
}

/// Fill the caller's `URL_COMPONENTS` for a parsed URL. Answers `Ok(None)` on
/// success, or the Win32 error the call must report.
pub(super) fn fill(
    engine: &mut Unicorn<Trace>,
    structure: u64,
    url_address: u64,
    url: &str,
    parts: &Components,
    wide: bool,
) -> Result<Option<u32>> {
    let width = adapters::ptr_width(engine) as usize;
    let layout = Layout::new(width);
    let declared = adapters::read_dword(engine, structure)?;
    if declared as usize != layout.size {
        return Ok(Some(ERROR_INVALID_PARAMETER));
    }
    let unit = if wide { 2 } else { 1 };
    adapters::write_dword(engine, structure + layout.number as u64, parts.number)?;
    adapters::put(
        engine,
        structure + layout.port as u64,
        &parts.port.to_le_bytes(),
    )?;
    let slots = [
        (
            Slot {
                pointer: layout.scheme,
                length: layout.scheme_length,
            },
            parts.scheme.clone(),
        ),
        (
            Slot {
                pointer: layout.host,
                length: layout.host_length,
            },
            parts.host.clone(),
        ),
        (
            Slot {
                pointer: layout.user,
                length: layout.user_length,
            },
            parts.user.clone(),
        ),
        (
            Slot {
                pointer: layout.password,
                length: layout.password_length,
            },
            parts.password.clone(),
        ),
        (
            Slot {
                pointer: layout.path,
                length: layout.path_length,
            },
            parts.path.clone(),
        ),
        (
            Slot {
                pointer: layout.extra,
                length: layout.extra_length,
            },
            parts.extra.clone(),
        ),
    ];
    // The whole structure is checked before anything is copied, so a caller
    // with one short buffer is not left with a half-filled answer.
    for (slot, range) in &slots {
        let buffer = adapters::read_pointer(engine, structure + slot.pointer as u64)?;
        let capacity = adapters::read_dword(engine, structure + slot.length as u64)?;
        let implied = range.is_empty() && slot.pointer == layout.path && parts.implied_root;
        let units = if implied { 1 } else { range.len() };
        if buffer != 0 && capacity as usize <= units {
            adapters::write_dword(engine, structure + slot.length as u64, units as u32 + 1)?;
            return Ok(Some(ERROR_INSUFFICIENT_BUFFER));
        }
    }
    for (slot, range) in &slots {
        let buffer = adapters::read_pointer(engine, structure + slot.pointer as u64)?;
        let implied = range.is_empty() && slot.pointer == layout.path && parts.implied_root;
        let text = if implied { "/" } else { &url[range.clone()] };
        if buffer == 0 {
            // A null component pointer with a zero length asks for a pointer
            // into the caller's own URL; with a non-zero length it asks for
            // the length alone.
            let capacity = adapters::read_dword(engine, structure + slot.length as u64)?;
            let inline = !implied && !text.is_empty() && capacity == 0;
            if inline {
                adapters::write_pointer(
                    engine,
                    structure + slot.pointer as u64,
                    url_address + (range.start * unit) as u64,
                )?;
            }
            adapters::write_dword(engine, structure + slot.length as u64, text.len() as u32)?;
            continue;
        }
        adapters::put(engine, buffer, &adapters::encode(text, wide))?;
        adapters::write_dword(engine, structure + slot.length as u64, text.len() as u32)?;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(url: &str, range: &std::ops::Range<usize>) -> String {
        url[range.clone()].to_owned()
    }

    #[test]
    fn layouts_match_the_documented_structure_sizes() {
        assert_eq!(Layout::new(4).size, 60);
        assert_eq!(Layout::new(8).size, 104);
        let layout = Layout::new(8);
        assert_eq!((layout.host, layout.host_length, layout.port), (24, 32, 36));
        assert_eq!((layout.user, layout.password), (40, 56));
        assert_eq!((layout.path, layout.extra), (72, 88));
        let layout = Layout::new(4);
        assert_eq!((layout.host, layout.port, layout.user), (16, 24, 28));
        assert_eq!((layout.path, layout.extra_length), (44, 56));
    }

    #[test]
    fn urls_split_into_their_documented_components() {
        let url = "https://alex:secret@files.example:8443/drop/payload.bin?id=7#tail";
        let parts = parse(url).expect("a full URL parses");
        assert_eq!(text(url, &parts.scheme), "https");
        assert_eq!(parts.number, SCHEME_HTTPS);
        assert_eq!(text(url, &parts.host), "files.example");
        assert_eq!(parts.port, 8443);
        assert_eq!(text(url, &parts.user), "alex");
        assert_eq!(text(url, &parts.password), "secret");
        assert_eq!(text(url, &parts.path), "/drop/payload.bin");
        assert_eq!(text(url, &parts.extra), "?id=7#tail");
        assert!(!parts.implied_root);
    }

    #[test]
    fn a_bare_host_gets_the_default_port_and_an_implied_root() {
        let url = "http://example.invalid";
        let parts = parse(url).expect("a bare host parses");
        assert_eq!(parts.port, 80);
        assert_eq!(parts.number, SCHEME_HTTP);
        assert!(parts.path.is_empty() && parts.implied_root);
        assert!(parts.user.is_empty() && parts.password.is_empty());
        let url = "ftp://example.invalid/pub";
        let parts = parse(url).expect("an FTP URL parses");
        assert_eq!((parts.number, parts.port), (SCHEME_FTP, 21));
        assert_eq!(text(url, &parts.path), "/pub");
    }

    #[test]
    fn unknown_schemes_parse_and_malformed_urls_do_not() {
        let url = "ws://example.invalid/socket";
        let parts = parse(url).expect("an unknown scheme still splits");
        assert_eq!(parts.number, SCHEME_UNKNOWN);
        assert_eq!(parts.port, 80);
        assert!(parse("example.invalid/path").is_none());
        assert!(parse("http://").is_none());
        assert!(parse("http://host:port/").is_none());
        assert!(parse("http://[::1]/").is_none());
    }
}
