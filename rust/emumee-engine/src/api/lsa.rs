//! Audit policy enumeration and the LSA authentication-package surface.
//!
//! Audit categories are a fingerprinting surface, so they are answered from a
//! fixed table of the nine well-known categories with their real GUIDs and a
//! clean default policy — deterministic, and the same on every run.
//!
//! `LsaCallAuthenticationPackage` is the credential-enumeration path (the
//! `MsV1_0` logon-session and Kerberos ticket-cache queries). The attempt is
//! recorded in full and the call reports a protocol status of
//! `STATUS_NOT_SUPPORTED` with no return buffer: the behavior is observed while
//! nothing resembling a credential is ever synthesized or handed back.
use super::*;

const STATUS_SUCCESS: u64 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
/// No real security context exists in this profile.
const SEC_E_INVALID_HANDLE: u64 = 0x8010_0003;
const ERROR_SUCCESS: u64 = 0;
const ERROR_INVALID_PARAMETER: u64 = 87;

/// The nine well-known audit categories: {6997984N-797A-11D9-BED3-505054503030}.
const CATEGORY_NAMES: &[&str] = &[
    "System",
    "Logon/Logoff",
    "Object Access",
    "Privilege Use",
    "Detailed Tracking",
    "Policy Change",
    "Account Management",
    "DS Access",
    "Account Logon",
];

/// POLICY_AUDIT_EVENT_NONE: auditing is off, which is the clean default.
const AUDIT_NONE: u32 = 4;

/// Build category GUID bytes for category `id`; only Data1's low byte varies.
fn category_guid(id: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend((0x6997_9848u32 + id).to_le_bytes());
    bytes.extend(0x797Au16.to_le_bytes());
    bytes.extend(0x11D9u16.to_le_bytes());
    bytes.extend([0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30]);
    bytes
}

fn category_id(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 16 {
        return None;
    }
    let data1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let id = data1.checked_sub(0x6997_9848)?;
    (id < CATEGORY_NAMES.len() as u32 && category_guid(id) == bytes[..16]).then_some(id)
}

/// One observed LSA request.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub package_calls: u64,
    pub audit_queries: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that touched neither surface serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.package_calls == 0
            && self.audit_queries == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    counter: u64,
    handles: std::collections::BTreeSet<u64>,
    pub report: Report,
}

impl State {
    fn handle(&mut self) -> u64 {
        self.counter += 1;
        let value = 0x5D00_0000 + self.counter * 0x40;
        self.handles.insert(value);
        value
    }
    fn record(&mut self, api: &'static str, detail: String) {
        if api == "LsaCallAuthenticationPackage" {
            self.report.package_calls += 1;
        } else {
            self.report.audit_queries += 1;
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event { api, detail });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    EnumerateCategories,
    EnumerateSubCategories,
    Free,
    GuidFromId,
    IdFromGuid,
    LookupCategoryName { wide: bool },
    LookupSubCategoryName { wide: bool },
    QuerySystemPolicy,
    SetSystemPolicy,
    LsaConnectUntrusted,
    LsaLookupPackage,
    LsaCallPackage,
    LsaFreeReturnBuffer,
    LsaDeregister,
    EncryptMessage,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    let wide = name.ends_with('W');
    let row = match (module, name) {
        ("advapi32", "AuditEnumerateCategories") => (EnumerateCategories, 2, T::U32),
        ("advapi32", "AuditEnumerateSubCategories") => (EnumerateSubCategories, 4, T::U32),
        ("advapi32", "AuditFree") => (Free, 1, T::Void),
        ("advapi32", "AuditLookupCategoryGuidFromCategoryId") => (GuidFromId, 2, T::U32),
        ("advapi32", "AuditLookupCategoryIdFromCategoryGuid") => (IdFromGuid, 2, T::U32),
        ("advapi32", "AuditLookupCategoryNameA" | "AuditLookupCategoryNameW") => {
            (LookupCategoryName { wide }, 2, T::U32)
        }
        ("advapi32", "AuditLookupSubCategoryNameA" | "AuditLookupSubCategoryNameW") => {
            (LookupSubCategoryName { wide }, 2, T::U32)
        }
        ("advapi32", "AuditQuerySystemPolicy") => (QuerySystemPolicy, 3, T::U32),
        ("advapi32", "AuditSetSystemPolicy") => (SetSystemPolicy, 2, T::U32),
        ("secur32" | "sspicli", "LsaConnectUntrusted") => (LsaConnectUntrusted, 1, T::U32),
        ("secur32" | "sspicli", "LsaLookupAuthenticationPackage") => (LsaLookupPackage, 3, T::U32),
        ("secur32" | "sspicli", "LsaCallAuthenticationPackage") => (LsaCallPackage, 7, T::U32),
        ("secur32" | "sspicli", "LsaFreeReturnBuffer") => (LsaFreeReturnBuffer, 1, T::U32),
        ("secur32" | "sspicli", "LsaDeregisterLogonProcess") => (LsaDeregister, 1, T::U32),
        ("secur32" | "sspicli", "EncryptMessage") => (EncryptMessage, 4, T::U32),
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

fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

fn write_dword(engine: &mut Unicorn<Trace>, address: u64, value: u32) -> Result<()> {
    put(engine, address, &value.to_le_bytes())
}

fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

fn read_pointer(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let width = ptr_width(engine);
    let bytes = read(engine, address, width)?;
    let mut value = [0u8; 8];
    value[..width as usize].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

/// Publish a block on the guest heap and store its address at `out`.
fn publish(engine: &mut Unicorn<Trace>, out: u64, bytes: &[u8]) -> Result<()> {
    let address = heap::alloc(engine, bytes.len().max(1) as u64)?;
    put(engine, address, bytes)?;
    write_pointer(engine, out, address)
}

fn encode(text: &str, wide: bool) -> Vec<u8> {
    if wide {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes.extend([0, 0]);
        bytes
    } else {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::EnumerateCategories => {
            // (ppAuditCategoriesArray, pdwCountReturned)
            if args[0] == 0 || args[1] == 0 {
                return Ok(0);
            }
            let mut bytes = Vec::new();
            for id in 0..CATEGORY_NAMES.len() as u32 {
                bytes.extend(category_guid(id));
            }
            publish(engine, args[0], &bytes)?;
            write_dword(engine, args[1], CATEGORY_NAMES.len() as u32)?;
            engine
                .get_data_mut()
                .apis
                .lsa
                .record("AuditEnumerateCategories", String::new());
            Ok(1)
        }
        Call::EnumerateSubCategories => {
            // (pAuditCategoryGuid, bRetrieveAll, ppArray, pdwCount): this
            // profile models categories only, so a category reports no
            // sub-categories rather than inventing their GUIDs.
            if args[2] == 0 || args[3] == 0 {
                return Ok(0);
            }
            publish(engine, args[2], &[])?;
            write_dword(engine, args[3], 0)?;
            engine
                .get_data_mut()
                .apis
                .lsa
                .record("AuditEnumerateSubCategories", String::new());
            Ok(1)
        }
        Call::Free => {
            heap::release(engine, args[0])?;
            Ok(0)
        }
        Call::GuidFromId => {
            // (AuditCategoryId, pAuditCategoryGuid)
            let id = args[0] as u32;
            if args[1] == 0 || id >= CATEGORY_NAMES.len() as u32 {
                return Ok(0);
            }
            put(engine, args[1], &category_guid(id))?;
            Ok(1)
        }
        Call::IdFromGuid => {
            // (pAuditCategoryGuid, pAuditCategoryId)
            if args[0] == 0 || args[1] == 0 {
                return Ok(0);
            }
            let bytes = read(engine, args[0], 16)?;
            let Some(id) = category_id(&bytes) else {
                return Ok(0);
            };
            write_dword(engine, args[1], id)?;
            Ok(1)
        }
        Call::LookupCategoryName { wide } => {
            // (pAuditCategoryGuid, ppszCategoryName)
            if args[0] == 0 || args[1] == 0 {
                return Ok(0);
            }
            let bytes = read(engine, args[0], 16)?;
            let Some(id) = category_id(&bytes) else {
                return Ok(0);
            };
            let text = encode(CATEGORY_NAMES[id as usize], wide);
            publish(engine, args[1], &text)?;
            Ok(1)
        }
        Call::LookupSubCategoryName { wide } => {
            // No sub-categories are modeled, so none can be named.
            let _ = wide;
            if args[1] != 0 {
                write_pointer(engine, args[1], 0)?;
            }
            Ok(0)
        }
        Call::QuerySystemPolicy => {
            // (pSubCategoryGuids, dwPolicyCount, ppAuditPolicy):
            // AUDIT_POLICY_INFORMATION { GUID subcategory; ULONG info; GUID category; }
            let count = args[1] as u32;
            if args[0] == 0 || args[2] == 0 || count == 0 || count > 256 {
                return Ok(0);
            }
            let mut bytes = Vec::new();
            for index in 0..count as u64 {
                let guid = read(engine, args[0] + index * 16, 16)?;
                bytes.extend(&guid);
                bytes.extend(AUDIT_NONE.to_le_bytes());
                // The category a sub-category belongs to is unknown here, so
                // the sub-category's own GUID is echoed rather than guessed.
                bytes.extend(&guid);
            }
            publish(engine, args[2], &bytes)?;
            engine
                .get_data_mut()
                .apis
                .lsa
                .record("AuditQuerySystemPolicy", format!("{count} subcategories"));
            Ok(1)
        }
        Call::SetSystemPolicy => {
            // The request is recorded; the modeled policy does not change,
            // because nothing in this profile audits.
            engine.get_data_mut().apis.lsa.record(
                "AuditSetSystemPolicy",
                format!("{} entries", args[1] as u32),
            );
            Ok(1)
        }
        Call::LsaConnectUntrusted => {
            if args[0] == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let handle = engine.get_data_mut().apis.lsa.handle();
            write_pointer(engine, args[0], handle)?;
            Ok(STATUS_SUCCESS)
        }
        Call::LsaLookupPackage => {
            // (LsaHandle, PackageName, AuthenticationPackage): the name is an
            // LSA_STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; }.
            if args[1] == 0 || args[2] == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let length = u16::from_le_bytes(read(engine, args[1], 2)?.try_into().unwrap()) as u64;
            let buffer = read_pointer(engine, args[1] + ptr_width(engine))?;
            let name = if buffer != 0 && length > 0 && length <= 256 {
                String::from_utf8_lossy(&read(engine, buffer, length)?).to_string()
            } else {
                String::new()
            };
            // Stable ids for the packages that exist on a real system.
            let id: u32 = match name.as_str() {
                "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => 0,
                "Kerberos" => 2,
                "Negotiate" => 6,
                "NTLM" => 10,
                _ => 0,
            };
            write_dword(engine, args[2], id)?;
            engine
                .get_data_mut()
                .apis
                .lsa
                .record("LsaLookupAuthenticationPackage", name);
            Ok(STATUS_SUCCESS)
        }
        Call::LsaCallPackage => {
            // (LsaHandle, Package, SubmitBuffer, SubmitLength, ReturnBuffer,
            // ReturnLength, ProtocolStatus): the request is recorded; the
            // package answers that it does not support it, and no buffer is
            // returned, so nothing credential-shaped is ever synthesized.
            let detail = format!("package {} submit {} bytes", args[1] as u32, args[3] as u32);
            if args[4] != 0 {
                write_pointer(engine, args[4], 0)?;
            }
            if args[5] != 0 {
                write_dword(engine, args[5], 0)?;
            }
            if args[6] != 0 {
                write_dword(engine, args[6], STATUS_NOT_SUPPORTED)?;
            }
            engine
                .get_data_mut()
                .apis
                .lsa
                .record("LsaCallAuthenticationPackage", detail);
            Ok(STATUS_SUCCESS)
        }
        Call::LsaFreeReturnBuffer => {
            heap::release(engine, args[0])?;
            Ok(STATUS_SUCCESS)
        }
        Call::LsaDeregister => {
            engine.get_data_mut().apis.lsa.handles.remove(&args[0]);
            Ok(STATUS_SUCCESS)
        }
        Call::EncryptMessage => {
            // No SSPI security context is established in this profile, so there
            // is no key material to encrypt under.
            let _ = ERROR_SUCCESS;
            let _ = ERROR_INVALID_PARAMETER;
            Ok(SEC_E_INVALID_HANDLE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_category_guids_round_trip_through_their_ids() {
        for id in 0..CATEGORY_NAMES.len() as u32 {
            let guid = category_guid(id);
            assert_eq!(guid.len(), 16);
            assert_eq!(category_id(&guid), Some(id), "category {id}");
        }
        // The documented System category GUID is
        // {69979848-797A-11D9-BED3-505054503030}.
        let system = category_guid(0);
        assert_eq!(&system[0..4], &0x6997_9848u32.to_le_bytes());
        assert_eq!(&system[8..16], &[0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30]);
        // A GUID outside the table is not a category.
        assert_eq!(category_id(&[0u8; 16]), None);
        assert_eq!(category_id(&category_guid(99)), None);
    }
}
