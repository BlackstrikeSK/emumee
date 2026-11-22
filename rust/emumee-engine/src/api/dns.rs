//! `dnsapi` resolution against the guest's own record catalog.
//!
//! There is no resolver in this profile and none is invented. The catalog is
//! derived from the persona: the machine's own name and fully qualified name
//! answer with the configured adapter address, the matching reverse name
//! answers with the machine name, and loopback answers for itself. Every other
//! name is reported as absent — `DNS_ERROR_RCODE_NAME_ERROR` — with the exact
//! name recorded, so an attempt to resolve a command-and-control host is
//! preserved as evidence instead of being answered with a fabricated address.
//!
//! Answers are real `DNS_RECORD` chains on the guest heap, laid out at the
//! offsets a compiler would use for the caller's pointer width, with `pName`
//! and the PTR target pointing into the same block in the character set the
//! called spelling implies. `DnsRecordListFree`/`DnsFree` release exactly the
//! blocks this model handed out and nothing else.
use super::adapters::{adapter, dotted, encode, ptr_width, put, write_pointer};
use super::*;
use std::collections::BTreeSet;

// DNS record types this profile knows about.
const DNS_TYPE_A: u32 = 1;
const DNS_TYPE_PTR: u32 = 12;
const DNS_TYPE_TEXT: u32 = 16;
const DNS_TYPE_AAAA: u32 = 28;

// Statuses.
const ERROR_SUCCESS: u64 = 0;
const ERROR_INVALID_PARAMETER: u64 = 87;
const ERROR_NOT_SUPPORTED: u64 = 50;
const ERROR_NOT_ENOUGH_MEMORY: u64 = 8;
/// DNS_ERROR_RCODE_NAME_ERROR: the name does not exist.
const NAME_ERROR: u64 = 9003;
/// DNS_INFO_NO_RECORDS: the name exists but carries no record of that type.
const NO_RECORDS: u64 = 9501;

// Query options this profile accepts: the cache and wire-query controls, which
// change nothing for a catalog that is neither cached nor on a wire.
const DNS_QUERY_BYPASS_CACHE: u32 = 0x8;
const DNS_QUERY_NO_WIRE_QUERY: u32 = 0x10;

/// Bound on outstanding answer blocks.
const MAX_BLOCKS: usize = 64;

/// Which character set the called spelling implies, as `DNS_CHARSET` spells
/// it in the record flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CharSet {
    Unicode = 1,
    Utf8 = 2,
    Ansi = 3,
}

impl CharSet {
    fn wide(self) -> bool {
        self == Self::Unicode
    }
}

/// One record in the guest's own catalog.
struct Record {
    name: String,
    kind: u32,
    /// An address for A/AAAA, a target name for PTR.
    data: Data,
}

enum Data {
    Address([u8; 4]),
    Name(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub name: String,
    pub record_type: u32,
    pub status: u32,
    /// What the catalog answered, as text.
    pub answers: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub queries: u64,
    pub answered: u64,
    pub unresolved: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that resolved nothing serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.queries == 0
            && self.answered == 0
            && self.unresolved == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    blocks: BTreeSet<u64>,
    pub report: Report,
}

impl State {
    fn record(&mut self, event: Event) {
        self.report.queries += 1;
        if event.status == 0 {
            self.report.answered += 1;
        } else {
            self.report.unresolved += 1;
        }
        if self.report.events.len() < 64 {
            self.report.events.push(event);
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    Query(CharSet),
    FreeRecordList,
    Free,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    if module != "dnsapi" {
        return None;
    }
    let row = match name {
        "DnsQuery_A" => (Query(CharSet::Ansi), 6, T::U32),
        "DnsQuery_W" => (Query(CharSet::Unicode), 6, T::U32),
        "DnsQuery_UTF8" => (Query(CharSet::Utf8), 6, T::U32),
        "DnsRecordListFree" => (FreeRecordList, 2, T::Void),
        "DnsFree" => (Free, 2, T::Void),
        _ => return None,
    };
    Some(row)
}

/// Normalize a queried name the way a resolver does: case-folded, with the
/// root dot dropped, and refused outright if it is not a legal DNS name.
pub(super) fn normalize(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(name)
}

/// The reverse-lookup name for an IPv4 address.
fn reverse_name(address: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}.in-addr.arpa",
        address[3], address[2], address[1], address[0]
    )
}

/// The guest's own catalog, derived entirely from the persona.
fn catalog(engine: &Unicorn<Trace>) -> Vec<Record> {
    let config = adapter(engine);
    let persona = &engine.get_data().apis.persona.model;
    let host = persona.computer_name_text().to_ascii_lowercase();
    let fqdn = persona.fully_qualified_name();
    let address = config.address();
    let mut records = vec![Record {
        name: host.clone(),
        kind: DNS_TYPE_A,
        data: Data::Address(address),
    }];
    if fqdn != host {
        records.push(Record {
            name: fqdn.clone(),
            kind: DNS_TYPE_A,
            data: Data::Address(address),
        });
    }
    records.push(Record {
        name: reverse_name(address),
        kind: DNS_TYPE_PTR,
        data: Data::Name(fqdn),
    });
    if host != "localhost" {
        records.push(Record {
            name: "localhost".into(),
            kind: DNS_TYPE_A,
            data: Data::Address([127, 0, 0, 1]),
        });
        records.push(Record {
            name: reverse_name([127, 0, 0, 1]),
            kind: DNS_TYPE_PTR,
            data: Data::Name("localhost".into()),
        });
    }
    records
}

fn query(engine: &mut Unicorn<Trace>, args: &[u64], charset: CharSet) -> Result<u64> {
    let width = ptr_width(engine);
    let kind = args[1] as u32 as u16 as u32;
    let options = args[2] as u32;
    let api = match charset {
        CharSet::Ansi => "DnsQuery_A",
        CharSet::Unicode => "DnsQuery_W",
        CharSet::Utf8 => "DnsQuery_UTF8",
    };
    let mut event = Event {
        api,
        name: String::new(),
        record_type: kind,
        status: ERROR_INVALID_PARAMETER as u32,
        answers: Vec::new(),
    };
    // pReserved must be null, the results pointer is required, and the name
    // has to be a name.
    if args[0] == 0 || args[4] == 0 || args[5] != 0 {
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_INVALID_PARAMETER);
    }
    let raw = files::path(engine, args[0], charset.wide())?;
    let Some(name) = normalize(&raw) else {
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_INVALID_PARAMETER);
    };
    event.name = name.clone();
    write_pointer(engine, args[4], 0)?;
    // An explicit server list would have to be queried over a network that
    // does not exist here, and the remaining option bits change behavior this
    // model does not have.
    if args[3] != 0 || options & !(DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_WIRE_QUERY) != 0 {
        event.status = ERROR_NOT_SUPPORTED as u32;
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_NOT_SUPPORTED);
    }
    if !matches!(kind, DNS_TYPE_A | DNS_TYPE_AAAA | DNS_TYPE_PTR | DNS_TYPE_TEXT) {
        event.status = ERROR_NOT_SUPPORTED as u32;
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_NOT_SUPPORTED);
    }
    let records = catalog(engine);
    let known = records.iter().any(|record| record.name == name);
    let selected: Vec<&Record> = records
        .iter()
        .filter(|record| record.name == name && record.kind == kind)
        .collect();
    if selected.is_empty() {
        let status = if known { NO_RECORDS } else { NAME_ERROR };
        event.status = status as u32;
        engine.get_data_mut().apis.dns.record(event);
        return Ok(status);
    }
    if engine.get_data().apis.dns.blocks.len() >= MAX_BLOCKS {
        event.status = ERROR_NOT_ENOUGH_MEMORY as u32;
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_NOT_ENOUGH_MEMORY);
    }
    // One block holds the record chain and every string it points at, so the
    // caller frees the whole answer with one call, as the real API documents.
    let header = (2 * width + 16) as usize;
    let stride = header + 16;
    let wide = charset.wide();
    let body = stride * selected.len();
    // Lay the strings out first, so the block size is known before it is
    // allocated and every interior pointer can be written once.
    let mut strings: Vec<u8> = Vec::new();
    let mut place = |text: &str| -> usize {
        let at = body + strings.len();
        strings.extend(encode(text, wide));
        // Keep each following string pointer-aligned so a walker reads clean
        // units whatever the character set.
        while (body + strings.len()) % 8 != 0 {
            strings.push(0);
        }
        at
    };
    let placed: Vec<(usize, Option<usize>)> = selected
        .iter()
        .map(|record| {
            let name_at = place(&record.name);
            let target = match &record.data {
                Data::Name(target) => Some(place(target)),
                Data::Address(_) => None,
            };
            (name_at, target)
        })
        .collect();
    let base = heap::alloc(engine, (body + strings.len()) as u64)?;
    if base == 0 {
        event.status = ERROR_NOT_ENOUGH_MEMORY as u32;
        engine.get_data_mut().apis.dns.record(event);
        return Ok(ERROR_NOT_ENOUGH_MEMORY);
    }
    let mut image = vec![0u8; body];
    let pointer = |value: u64| value.to_le_bytes()[..width as usize].to_vec();
    for (index, record) in selected.iter().enumerate() {
        let offset = index * stride;
        let next = if index + 1 < selected.len() {
            base + ((index + 1) * stride) as u64
        } else {
            0
        };
        let (name_at, target_at) = placed[index];
        let data_length: u16 = match record.kind {
            DNS_TYPE_A => 4,
            DNS_TYPE_AAAA => 16,
            _ => width as u16,
        };
        let mut write = |at: usize, bytes: &[u8]| {
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        write(offset, &pointer(next));
        write(offset + width as usize, &pointer(base + name_at as u64));
        let fixed = offset + 2 * width as usize;
        write(fixed, &(record.kind as u16).to_le_bytes());
        write(fixed + 2, &data_length.to_le_bytes());
        // Section: answer, plus the character set the spelling implies.
        write(fixed + 4, &(1u32 | ((charset as u32) << 3)).to_le_bytes());
        write(fixed + 8, &60u32.to_le_bytes());
        match &record.data {
            Data::Address(address) => {
                write(offset + header, address);
                event.answers.push(dotted(*address));
            }
            Data::Name(target) => {
                let at = target_at.expect("a PTR record places its target");
                write(offset + header, &pointer(base + at as u64));
                event.answers.push(target.clone());
            }
        }
    }
    image.extend(strings);
    put(engine, base, &image)?;
    write_pointer(engine, args[4], base)?;
    engine.get_data_mut().apis.dns.blocks.insert(base);
    event.status = 0;
    engine.get_data_mut().apis.dns.record(event);
    Ok(ERROR_SUCCESS)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "DNS resolution is outside the kernel target profile"
    );
    match call {
        Call::Query(charset) => query(engine, args, charset),
        Call::FreeRecordList | Call::Free => {
            // DnsRecordListFree takes DNS_FREE_TYPE DnsFreeRecordList (1);
            // DnsFree additionally accepts DnsFreeFlat (0). Neither may free
            // an allocation this model did not hand out.
            let accepted: &[u64] = if matches!(call, Call::Free) {
                &[0, 1]
            } else {
                &[1]
            };
            if !accepted.contains(&(args[1] as u32 as u64)) {
                return Ok(0);
            }
            if engine.get_data_mut().apis.dns.blocks.remove(&args[0]) {
                heap::release(engine, args[0])?;
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalized_or_refused() {
        assert_eq!(normalize("Example.COM."), Some("example.com".into()));
        assert_eq!(normalize("desktop-7f4m2q9"), Some("desktop-7f4m2q9".into()));
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("a..b"), None);
        assert_eq!(normalize("-bad.example"), None);
        assert_eq!(normalize(&"a".repeat(64)), None);
    }

    #[test]
    fn reverse_names_follow_the_in_addr_arpa_order() {
        assert_eq!(reverse_name([10, 0, 2, 15]), "15.2.0.10.in-addr.arpa");
        assert_eq!(reverse_name([127, 0, 0, 1]), "1.0.0.127.in-addr.arpa");
    }

    #[test]
    fn record_header_matches_the_documented_layout() {
        assert_eq!(2 * 4 + 16, 24);
        assert_eq!(2 * 8 + 16, 32);
        assert_eq!(CharSet::Unicode as u32, 1);
        assert_eq!(CharSet::Ansi as u32, 3);
    }
}
