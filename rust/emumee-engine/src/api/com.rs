//! COM model: `ole32` apartment/activation, `oleaut32` BSTR and VARIANT,
//! `rpcrt4` UUIDs, and the synthetic guest interfaces reached through real
//! vtables (`com_api`).
//!
//! Activation hands the guest a genuine object: an interface pointer whose
//! vtable slots are synthetic call gates, so a sample calls `AddRef`,
//! `QueryInterface`, `Release` and the modeled service methods indirectly, the
//! way compiled COM code does. Reference counts are tracked for real and an
//! object is torn down on its last release, so a use-after-release is caught
//! rather than silently tolerated. No host COM runtime is involved and no
//! WMI query is executed: the requested class and the WQL text are recorded
//! and the enumeration answers empty.
use super::*;
use std::collections::BTreeMap;

const S_OK: u64 = 0;
const S_FALSE: u64 = 1;
const E_NOINTERFACE: u64 = 0x8000_4002;
const E_POINTER: u64 = 0x8000_4003;
const E_INVALIDARG: u64 = 0x8007_0057;
const WBEM_S_FALSE: u64 = 1;

/// A synthetic GUID in its in-memory little-endian layout.
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

const IID_IUNKNOWN: [u8; 16] = guid(0, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const CLSID_WBEM_LOCATOR: [u8; 16] =
    guid(0x4590F811, 0x1D3A, 0x11D0, [0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24]);
const IID_IWBEM_LOCATOR: [u8; 16] =
    guid(0xDC12A687, 0x737F, 0x11CF, [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24]);
const IID_IWBEM_SERVICES: [u8; 16] =
    guid(0x9556DC99, 0x828C, 0x11CF, [0xA3, 0x7E, 0x00, 0xAA, 0x00, 0x32, 0x40, 0xC7]);

/// The interface an object exposes; it decides the vtable shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Unknown,
    WbemLocator,
    WbemServices,
    WbemEnumerator,
    Malloc,
}

impl Kind {
    /// Vtable slots, in interface order. `None` is a slot this profile does not
    /// model: it is bound to a gate that stops with its reason rather than
    /// running into unmapped memory.
    fn slots(self) -> Vec<Option<&'static str>> {
        let unknown = [
            Some("IUnknown.QueryInterface"),
            Some("IUnknown.AddRef"),
            Some("IUnknown.Release"),
        ];
        let mut slots: Vec<Option<&'static str>> = unknown.to_vec();
        match self {
            Kind::Unknown => {}
            Kind::WbemLocator => slots.push(Some("IWbemLocator.ConnectServer")),
            Kind::WbemServices => {
                // ExecQuery sits at vtable index 20 in IWbemServices, so a
                // sample compiled against the real header reaches it there.
                while slots.len() < 20 {
                    slots.push(None);
                }
                slots.push(Some("IWbemServices.ExecQuery"));
                while slots.len() < 26 {
                    slots.push(None);
                }
            }
            Kind::WbemEnumerator => {
                // IEnumWbemClassObject: Reset(3), Next(4), ...
                slots.push(None);
                slots.push(Some("IEnumWbemClassObject.Next"));
                while slots.len() < 8 {
                    slots.push(None);
                }
            }
            Kind::Malloc => {
                // IMalloc: Alloc(3), Realloc(4), Free(5), GetSize(6),
                // DidAlloc(7), HeapMinimize(8).
                slots.push(Some("IMalloc.Alloc"));
                slots.push(Some("IMalloc.Realloc"));
                slots.push(Some("IMalloc.Free"));
                slots.push(Some("IMalloc.GetSize"));
                slots.push(Some("IMalloc.DidAlloc"));
                slots.push(Some("IMalloc.HeapMinimize"));
            }
        }
        slots
    }

    fn accepts(self, iid: &[u8; 16]) -> bool {
        if *iid == IID_IUNKNOWN {
            return true;
        }
        match self {
            Kind::Unknown => false,
            Kind::WbemLocator => *iid == IID_IWBEM_LOCATOR,
            Kind::WbemServices => *iid == IID_IWBEM_SERVICES,
            Kind::WbemEnumerator | Kind::Malloc => false,
        }
    }
}

#[derive(Clone, Debug)]
struct Object {
    kind: Kind,
    refs: u32,
    vtable: u64,
}

/// One recorded COM activation or query, for the run's evidence.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub activations: u64,
    pub queries: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that touched no COM serializes nothing, so existing report
    /// fixtures stay byte-identical.
    pub fn is_empty(&self) -> bool {
        self.activations == 0
            && self.queries == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    /// Apartment nesting depth: CoInitialize/CoUninitialize pairs.
    apartment: u32,
    guids: u32,
    objects: BTreeMap<u64, Object>,
    /// Addresses released to zero, kept so a use-after-release is reported.
    released: std::collections::BTreeSet<u64>,
    pub report: Report,
}

impl State {
    fn record(&mut self, api: &'static str, detail: String) {
        self.report.events.push(Event { api, detail });
        if self.report.events.len() > 64 {
            self.report.events.pop();
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    CoInitialize,
    CoInitializeEx,
    OleInitialize,
    CoUninitialize,
    /// CoInitializeSecurity / CoSetProxyBlanket: recorded, no effect.
    SecurityNoop { argc: usize },
    CoCreateGuid,
    CoCreateInstance,
    StringFromCLSID,
    UuidCreate,
    UuidToString,
    SysAllocString,
    SysAllocStringLen,
    SysAllocStringByteLen,
    SysFreeString,
    VariantInit,
    QueryInterface,
    AddRef,
    Release,
    ConnectServer,
    ExecQuery,
    EnumNext,
    MallocAlloc,
    MallocRealloc,
    MallocFree,
    MallocGetSize,
    MallocDidAlloc,
    MallocHeapMinimize,
}

/// Hand out an `IMalloc` over the guest heap, for `SHGetMalloc`.
pub(super) fn activate_malloc(engine: &mut Unicorn<Trace>) -> Result<u64> {
    activate(engine, Kind::Malloc)
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    let row = match (module, name) {
        ("ole32" | "combase", "CoInitialize") => (CoInitialize, 1, T::U32),
        ("ole32" | "combase", "CoInitializeEx") => (CoInitializeEx, 2, T::U32),
        ("ole32" | "combase", "OleInitialize") => (OleInitialize, 1, T::U32),
        ("ole32" | "combase", "CoUninitialize") => (CoUninitialize, 0, T::Void),
        ("ole32" | "combase", "CoInitializeSecurity") => (SecurityNoop { argc: 9 }, 9, T::U32),
        ("ole32" | "combase", "CoSetProxyBlanket") => (SecurityNoop { argc: 8 }, 8, T::U32),
        ("ole32" | "combase", "CoCreateGuid") => (CoCreateGuid, 1, T::U32),
        ("ole32" | "combase", "CoCreateInstance") => (CoCreateInstance, 5, T::U32),
        ("ole32" | "combase", "StringFromCLSID") => (StringFromCLSID, 2, T::U32),
        ("rpcrt4", "UuidCreate") => (UuidCreate, 1, T::U32),
        ("rpcrt4", "UuidToStringA") => (UuidToString, 2, T::U32),
        // oleaut32 is routinely imported by ordinal.
        ("oleaut32", "SysAllocString" | "#2") => (SysAllocString, 1, T::Pointer),
        ("oleaut32", "SysAllocStringLen" | "#4") => (SysAllocStringLen, 2, T::Pointer),
        ("oleaut32", "SysFreeString" | "#6") => (SysFreeString, 1, T::Void),
        ("oleaut32", "SysAllocStringByteLen" | "#8") => (SysAllocStringByteLen, 2, T::Pointer),
        ("oleaut32", "VariantInit") => (VariantInit, 1, T::Void),
        ("com_api", "IUnknown.QueryInterface") => (QueryInterface, 3, T::U32),
        ("com_api", "IUnknown.AddRef") => (AddRef, 1, T::U32),
        ("com_api", "IUnknown.Release") => (Release, 1, T::U32),
        ("com_api", "IWbemLocator.ConnectServer") => (ConnectServer, 9, T::U32),
        ("com_api", "IWbemServices.ExecQuery") => (ExecQuery, 6, T::U32),
        ("com_api", "IEnumWbemClassObject.Next") => (EnumNext, 5, T::U32),
        ("com_api", "IMalloc.Alloc") => (MallocAlloc, 2, T::Pointer),
        ("com_api", "IMalloc.Realloc") => (MallocRealloc, 3, T::Pointer),
        ("com_api", "IMalloc.Free") => (MallocFree, 2, T::Void),
        ("com_api", "IMalloc.GetSize") => (MallocGetSize, 2, T::Pointer),
        ("com_api", "IMalloc.DidAlloc") => (MallocDidAlloc, 2, T::U32),
        ("com_api", "IMalloc.HeapMinimize") => (MallocHeapMinimize, 1, T::Void),
        _ => return None,
    };
    Some(row)
}

fn ptr_width(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        8
    } else {
        4
    }
}

fn read_guid(engine: &Unicorn<Trace>, address: u64) -> Result<[u8; 16]> {
    let bytes = read(engine, address, 16)?;
    Ok(bytes.try_into().unwrap())
}

fn format_guid(value: &[u8; 16], braces: bool, upper: bool) -> String {
    let d1 = u32::from_le_bytes(value[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(value[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(value[6..8].try_into().unwrap());
    let tail: String = value[8..].iter().map(|b| format!("{b:02x}")).collect();
    let text = format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        &tail[..4],
        &tail[4..]
    );
    let text = if upper { text.to_uppercase() } else { text };
    if braces { format!("{{{text}}}") } else { text }
}

fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

/// The synthetic call gate for a `com_api` method, installed on demand so a
/// vtable slot points at a real interceptable address.
fn gate(engine: &mut Unicorn<Trace>, export: &str) -> Result<u64> {
    let architecture = engine.get_data().architecture;
    let binding = definition_for(architecture, export);
    install_binding(engine, binding)
}

fn definition_for(architecture: Architecture, export: &str) -> Binding {
    super::definition(architecture, "com_api", export)
}

/// Build an object: a vtable of call gates plus an interface pointer.
fn activate(engine: &mut Unicorn<Trace>, kind: Kind) -> Result<u64> {
    let width = ptr_width(engine);
    let slots = kind.slots();
    let mut addresses = Vec::with_capacity(slots.len());
    for slot in &slots {
        // Unmodeled slots share one gate that stops with its reason.
        addresses.push(gate(engine, slot.unwrap_or("Unmodeled"))?);
    }
    let vtable = heap::alloc(engine, slots.len() as u64 * width)?;
    for (index, address) in addresses.iter().enumerate() {
        write_pointer(engine, vtable + index as u64 * width, *address)?;
    }
    // The object is just its vtable pointer; the refcount lives in the model.
    let object = heap::alloc(engine, width * 2)?;
    write_pointer(engine, object, vtable)?;
    write_pointer(engine, object + width, 0)?;
    engine
        .get_data_mut()
        .apis
        .com
        .objects
        .insert(object, Object { kind, refs: 1, vtable });
    Ok(object)
}

/// Resolve an interface pointer to its object, rejecting a released one.
fn object_of(engine: &Unicorn<Trace>, this: u64) -> Result<Kind> {
    if let Some(object) = engine.get_data().apis.com.objects.get(&this) {
        return Ok(object.kind);
    }
    if engine.get_data().apis.com.released.contains(&this) {
        bail!("COM interface used after its final release");
    }
    bail!("COM interface pointer does not belong to a modeled object")
}

/// Allocate a BSTR holding `units` and return the string pointer (past the
/// four-byte byte-length prefix).
fn alloc_bstr(engine: &mut Unicorn<Trace>, units: &[u16]) -> Result<u64> {
    let bytes = units.len() as u64 * 2;
    let base = heap::alloc(engine, 4 + bytes + 2)?;
    put(engine, base, &(bytes as u32).to_le_bytes())?;
    let mut payload: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    payload.extend([0, 0]);
    put(engine, base + 4, &payload)?;
    Ok(base + 4)
}

/// Read a BSTR's units using its length prefix.
fn read_bstr(engine: &Unicorn<Trace>, bstr: u64) -> Result<Vec<u16>> {
    if bstr == 0 {
        return Ok(Vec::new());
    }
    let length = u32::from_le_bytes(read(engine, bstr - 4, 4)?.try_into().unwrap());
    ensure!(length <= 1 << 20, "BSTR length exceeds its modeled bound");
    let bytes = read(engine, bstr, length as u64)?;
    Ok(bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect())
}

fn wide_units(engine: &Unicorn<Trace>, address: u64) -> Result<Vec<u16>> {
    if address == 0 {
        return Ok(Vec::new());
    }
    Ok(files::path(engine, address, true)?.encode_utf16().collect())
}

/// Allocate a narrow or wide string on the heap, as CoTaskMemAlloc/RPC string
/// allocation would, and publish the pointer.
fn publish_string(engine: &mut Unicorn<Trace>, out: u64, text: &str, wide: bool) -> Result<()> {
    let bytes: Vec<u8> = if wide {
        let mut raw: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        raw.extend([0, 0]);
        raw
    } else {
        let mut raw = text.as_bytes().to_vec();
        raw.push(0);
        raw
    };
    let address = heap::alloc(engine, bytes.len() as u64)?;
    put(engine, address, &bytes)?;
    write_pointer(engine, out, address)
}

/// A deterministic, clearly synthetic GUID: the counter in Data1 with a fixed
/// version-4 tail, so a control can assert it exactly.
fn next_guid(engine: &mut Unicorn<Trace>) -> [u8; 16] {
    let state = &mut engine.get_data_mut().apis.com;
    state.guids += 1;
    guid(
        state.guids,
        0x1111,
        0x4222,
        [0x83, 0x33, 0, 0, 0, 0, 0, 0],
    )
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::CoInitialize | Call::CoInitializeEx | Call::OleInitialize => {
            let state = &mut engine.get_data_mut().apis.com;
            state.apartment += 1;
            // A nested initialize reports S_FALSE, as the apartment is already up.
            Ok(if state.apartment > 1 { S_FALSE } else { S_OK })
        }
        Call::CoUninitialize => {
            let state = &mut engine.get_data_mut().apis.com;
            state.apartment = state.apartment.saturating_sub(1);
            Ok(0)
        }
        Call::SecurityNoop { argc } => {
            let _ = argc;
            engine
                .get_data_mut()
                .apis
                .com
                .record("CoInitializeSecurity/CoSetProxyBlanket", String::new());
            Ok(S_OK)
        }
        Call::CoCreateGuid | Call::UuidCreate => {
            if args[0] == 0 {
                return Ok(E_POINTER);
            }
            let value = next_guid(engine);
            put(engine, args[0], &value)?;
            Ok(S_OK)
        }
        Call::StringFromCLSID => {
            // StringFromCLSID(rclsid, ppsz): braced upper-case form, allocated.
            if args[0] == 0 || args[1] == 0 {
                return Ok(E_INVALIDARG);
            }
            let value = read_guid(engine, args[0])?;
            let text = format_guid(&value, true, true);
            publish_string(engine, args[1], &text, true)?;
            Ok(S_OK)
        }
        Call::UuidToString => {
            // UuidToStringA(Uuid, StringUuid): bare lower-case form, allocated.
            if args[0] == 0 || args[1] == 0 {
                return Ok(E_INVALIDARG);
            }
            let value = read_guid(engine, args[0])?;
            let text = format_guid(&value, false, false);
            publish_string(engine, args[1], &text, false)?;
            Ok(0)
        }
        Call::CoCreateInstance => {
            // CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv).
            if args[0] == 0 || args[4] == 0 {
                return Ok(E_INVALIDARG);
            }
            let clsid = read_guid(engine, args[0])?;
            let iid = read_guid(engine, args[3])?;
            let kind = if clsid == CLSID_WBEM_LOCATOR {
                Kind::WbemLocator
            } else {
                // An unknown class still activates as a plain IUnknown so the
                // request is observed rather than blinding the run; the class
                // asked for is recorded.
                Kind::Unknown
            };
            if !kind.accepts(&iid) {
                engine.get_data_mut().apis.com.record(
                    "CoCreateInstance",
                    format!("{} rejected {}", format_guid(&clsid, true, true), format_guid(&iid, true, true)),
                );
                write_pointer(engine, args[4], 0)?;
                return Ok(E_NOINTERFACE);
            }
            let object = activate(engine, kind)?;
            write_pointer(engine, args[4], object)?;
            let state = &mut engine.get_data_mut().apis.com;
            state.report.activations += 1;
            let detail = format_guid(&clsid, true, true);
            state.record("CoCreateInstance", detail);
            Ok(S_OK)
        }
        Call::QueryInterface => {
            // QueryInterface(this, riid, ppvObject).
            let kind = object_of(engine, args[0])?;
            if args[2] == 0 {
                return Ok(E_POINTER);
            }
            let iid = read_guid(engine, args[1])?;
            if !kind.accepts(&iid) {
                write_pointer(engine, args[2], 0)?;
                return Ok(E_NOINTERFACE);
            }
            // The same object answers for an interface it already exposes, and
            // the successful query takes its own reference.
            write_pointer(engine, args[2], args[0])?;
            if let Some(object) = engine.get_data_mut().apis.com.objects.get_mut(&args[0]) {
                object.refs += 1;
            }
            Ok(S_OK)
        }
        Call::AddRef => {
            object_of(engine, args[0])?;
            let object = engine
                .get_data_mut()
                .apis
                .com
                .objects
                .get_mut(&args[0])
                .expect("object checked above");
            object.refs += 1;
            Ok(object.refs as u64)
        }
        Call::Release => {
            object_of(engine, args[0])?;
            let (refs, vtable) = {
                let object = engine
                    .get_data_mut()
                    .apis
                    .com
                    .objects
                    .get_mut(&args[0])
                    .expect("object checked above");
                object.refs = object.refs.saturating_sub(1);
                (object.refs, object.vtable)
            };
            if refs == 0 {
                // Last release tears the object down; a later call on it is a
                // use-after-release and stops the run.
                engine.get_data_mut().apis.com.objects.remove(&args[0]);
                engine.get_data_mut().apis.com.released.insert(args[0]);
                heap::release(engine, vtable)?;
                heap::release(engine, args[0])?;
            }
            Ok(refs as u64)
        }
        Call::ConnectServer => {
            // ConnectServer(this, strNetworkResource, user, password, locale,
            // flags, authority, ctx, ppNamespace).
            let kind = object_of(engine, args[0])?;
            ensure!(kind == Kind::WbemLocator, "ConnectServer on a non-locator interface");
            if args[8] == 0 {
                return Ok(E_POINTER);
            }
            let namespace = String::from_utf16_lossy(&read_bstr(engine, args[1])?);
            let services = activate(engine, Kind::WbemServices)?;
            write_pointer(engine, args[8], services)?;
            engine
                .get_data_mut()
                .apis
                .com
                .record("IWbemLocator.ConnectServer", namespace);
            Ok(S_OK)
        }
        Call::ExecQuery => {
            // ExecQuery(this, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum).
            let kind = object_of(engine, args[0])?;
            ensure!(kind == Kind::WbemServices, "ExecQuery on a non-services interface");
            if args[5] == 0 {
                return Ok(E_POINTER);
            }
            let language = String::from_utf16_lossy(&read_bstr(engine, args[1])?);
            let query = String::from_utf16_lossy(&read_bstr(engine, args[2])?);
            // No WMI provider runs: the query text is recorded and the
            // enumeration answers empty.
            let enumerator = activate(engine, Kind::WbemEnumerator)?;
            write_pointer(engine, args[5], enumerator)?;
            let state = &mut engine.get_data_mut().apis.com;
            state.report.queries += 1;
            state.record("IWbemServices.ExecQuery", format!("{language}: {query}"));
            Ok(S_OK)
        }
        Call::EnumNext => {
            // Next(this, lTimeout, uCount, apObjects, puReturned): the modeled
            // enumeration is empty, so nothing is returned.
            let kind = object_of(engine, args[0])?;
            ensure!(kind == Kind::WbemEnumerator, "Next on a non-enumerator interface");
            if args[4] != 0 {
                put(engine, args[4], &0u32.to_le_bytes())?;
            }
            Ok(WBEM_S_FALSE)
        }
        Call::MallocAlloc => {
            // IMalloc::Alloc(this, cb) over the guest process heap.
            object_of(engine, args[0])?;
            let size = args[1];
            ensure!(size <= 1 << 26, "IMalloc request exceeds its modeled bound");
            if size == 0 {
                return Ok(0);
            }
            heap::alloc(engine, size)
        }
        Call::MallocRealloc => {
            object_of(engine, args[0])?;
            ensure!(args[2] <= 1 << 26, "IMalloc request exceeds its modeled bound");
            if args[2] == 0 {
                heap::release(engine, args[1])?;
                return Ok(0);
            }
            heap::realloc(engine, args[1], args[2])
        }
        Call::MallocFree => {
            object_of(engine, args[0])?;
            heap::release(engine, args[1])?;
            Ok(0)
        }
        Call::MallocGetSize => {
            object_of(engine, args[0])?;
            if args[1] == 0 {
                return Ok(u64::MAX);
            }
            heap::size_of(engine, args[1])
        }
        Call::MallocDidAlloc => {
            // -1 reports "cannot tell", which is a documented answer.
            object_of(engine, args[0])?;
            Ok(u64::from(u32::MAX))
        }
        Call::MallocHeapMinimize => {
            object_of(engine, args[0])?;
            Ok(0)
        }
        Call::SysAllocString => {
            if args[0] == 0 {
                return Ok(0);
            }
            let units = wide_units(engine, args[0])?;
            alloc_bstr(engine, &units)
        }
        Call::SysAllocStringLen => {
            // SysAllocStringLen(psz, ui): ui characters, zero-filled if null.
            let count = args[1] as u32 as usize;
            ensure!(count <= 1 << 20, "BSTR length exceeds its modeled bound");
            let units = if args[0] == 0 {
                vec![0u16; count]
            } else {
                let raw = read(engine, args[0], count as u64 * 2)?;
                raw.chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect()
            };
            alloc_bstr(engine, &units)
        }
        Call::SysAllocStringByteLen => {
            // SysAllocStringByteLen(psz, len): raw bytes, not character units.
            let len = args[1] as u32 as u64;
            ensure!(len <= 1 << 20, "BSTR byte length exceeds its modeled bound");
            let raw = if args[0] == 0 {
                vec![0u8; len as usize]
            } else {
                read(engine, args[0], len)?
            };
            let base = heap::alloc(engine, 4 + len + 2)?;
            put(engine, base, &(len as u32).to_le_bytes())?;
            let mut payload = raw;
            payload.extend([0, 0]);
            put(engine, base + 4, &payload)?;
            Ok(base + 4)
        }
        Call::SysFreeString => {
            if args[0] != 0 {
                heap::release(engine, args[0] - 4)?;
            }
            Ok(0)
        }
        Call::VariantInit => {
            // VARIANT is 16 bytes on x86 and 24 on x64; VT_EMPTY is all zero.
            if args[0] == 0 {
                return Ok(0);
            }
            let size = if ptr_width(engine) == 8 { 24 } else { 16 };
            put(engine, args[0], &vec![0u8; size])?;
            Ok(0)
        }
    }
}
