//! Service control manager model: an owned service database.
//!
//! Service creation is the classic persistence step, so it is observed in full
//! — name, display name, type, start mode and binary path are all recorded and
//! kept queryable — while nothing is ever executed. `StartService` marks the
//! record running so a sample's own follow-up query agrees with its request,
//! but no process, host or guest, is created.
//!
//! `StartServiceCtrlDispatcher` reports
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`, which is exactly what a service
//! binary sees when it is run interactively rather than by the real SCM. That
//! keeps the sample on its non-service path instead of waiting forever on a
//! controller that does not exist.
use super::*;
use std::collections::BTreeMap;

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

const SERVICE_STOPPED: u32 = 1;
const SERVICE_RUNNING: u32 = 4;
/// SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
const CONTROLS_ACCEPTED: u32 = 0x5;
const SERVICE_CONTROL_STOP: u32 = 1;

#[derive(Clone, Debug)]
struct Service {
    name: String,
    display: String,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary: String,
    state: u32,
    deleted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handle {
    Manager,
    Service(usize),
}

/// One observed service operation.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub service: String,
    pub binary: String,
    pub start_type: u32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub created: u64,
    pub start_requests: u64,
    pub deleted: u64,
    pub dispatcher_attempts: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that touched no service serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.created == 0
            && self.start_requests == 0
            && self.deleted == 0
            && self.dispatcher_attempts == 0
            && self.events.is_empty()
            && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    counter: u64,
    handles: BTreeMap<u64, Handle>,
    services: Vec<Service>,
    pub report: Report,
}

impl State {
    fn handle(&mut self, kind: Handle) -> u64 {
        self.counter += 1;
        let value = 0x5C00_0000 + self.counter * 0x40;
        self.handles.insert(value, kind);
        value
    }
    fn record(&mut self, api: &'static str, service: String, binary: String, start_type: u32) {
        match api {
            "CreateService" => self.report.created += 1,
            "StartService" => self.report.start_requests += 1,
            "DeleteService" => self.report.deleted += 1,
            "StartServiceCtrlDispatcher" => self.report.dispatcher_attempts += 1,
            _ => {}
        }
        if self.report.events.len() < 64 {
            self.report.events.push(Event { api, service, binary, start_type });
        } else {
            self.report.omitted_events += 1;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    OpenManager,
    Create { wide: bool },
    Open { wide: bool },
    Delete,
    Close,
    Start,
    Control,
    QueryStatus,
    QueryConfig { wide: bool },
    ChangeConfig { wide: bool },
    ChangeConfig2,
    EnumStatus { wide: bool },
    SetStatus,
    CtrlDispatcher,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    if module != "advapi32" {
        return None;
    }
    let wide = name.ends_with('W');
    let row = match name {
        "OpenSCManager" | "OpenSCManagerA" | "OpenSCManagerW" => (OpenManager, 3, T::Pointer),
        "CreateServiceA" | "CreateServiceW" => (Create { wide }, 13, T::Pointer),
        "OpenServiceA" | "OpenServiceW" => (Open { wide }, 3, T::Pointer),
        "DeleteService" => (Delete, 1, T::U32),
        "CloseServiceHandle" => (Close, 1, T::U32),
        "StartService" | "StartServiceA" | "StartServiceW" => (Start, 3, T::U32),
        "ControlService" => (Control, 3, T::U32),
        "QueryServiceStatus" => (QueryStatus, 2, T::U32),
        "QueryServiceConfig" | "QueryServiceConfigA" | "QueryServiceConfigW" => {
            (QueryConfig { wide }, 4, T::U32)
        }
        "ChangeServiceConfigA" | "ChangeServiceConfigW" => (ChangeConfig { wide }, 11, T::U32),
        "ChangeServiceConfig2" | "ChangeServiceConfig2A" | "ChangeServiceConfig2W" => {
            (ChangeConfig2, 3, T::U32)
        }
        "EnumServicesStatus" | "EnumServicesStatusA" | "EnumServicesStatusW" => {
            (EnumStatus { wide }, 8, T::U32)
        }
        "SetServiceStatus" => (SetStatus, 2, T::U32),
        "StartServiceCtrlDispatcherA" | "StartServiceCtrlDispatcherW" => (CtrlDispatcher, 1, T::U32),
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

fn fail(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}

fn succeed(engine: &mut Unicorn<Trace>) -> Result<u64> {
    engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
    Ok(1)
}

fn optional_text(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }
    files::path(engine, address, wide)
}

/// Resolve a service handle to its record index.
fn service_index(engine: &Unicorn<Trace>, handle: u64) -> Option<usize> {
    match engine.get_data().apis.services.handles.get(&handle) {
        Some(Handle::Service(index)) => Some(*index),
        _ => None,
    }
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

/// SERVICE_STATUS: seven DWORDs.
fn status_bytes(service: &Service) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(28);
    for value in [
        service.service_type,
        service.state,
        if service.state == SERVICE_RUNNING {
            CONTROLS_ACCEPTED
        } else {
            0
        },
        ERROR_SUCCESS,
        0, // dwServiceSpecificExitCode
        0, // dwCheckPoint
        0, // dwWaitHint
    ] {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::OpenManager => {
            let handle = engine.get_data_mut().apis.services.handle(Handle::Manager);
            engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
            Ok(handle)
        }
        Call::Create { wide } => {
            // (hSCManager, name, display, access, type, start, errorControl,
            // binary, loadOrderGroup, tagId, dependencies, startName, password)
            if !matches!(
                engine.get_data().apis.services.handles.get(&args[0]),
                Some(Handle::Manager)
            ) {
                return fail(engine, ERROR_INVALID_HANDLE);
            }
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let name = files::path(engine, args[1], wide)?;
            let display = optional_text(engine, args[2], wide)?;
            let binary = optional_text(engine, args[7], wide)?;
            let existing = engine
                .get_data()
                .apis
                .services
                .services
                .iter()
                .any(|service| service.name.eq_ignore_ascii_case(&name) && !service.deleted);
            if existing {
                return fail(engine, ERROR_SERVICE_EXISTS);
            }
            let service = Service {
                name: name.clone(),
                display: if display.is_empty() { name.clone() } else { display },
                service_type: args[4] as u32,
                start_type: args[5] as u32,
                error_control: args[6] as u32,
                binary: binary.clone(),
                state: SERVICE_STOPPED,
                deleted: false,
            };
            let start_type = service.start_type;
            let state = &mut engine.get_data_mut().apis.services;
            state.services.push(service);
            let index = state.services.len() - 1;
            let handle = state.handle(Handle::Service(index));
            state.record("CreateService", name, binary, start_type);
            engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
            Ok(handle)
        }
        Call::Open { wide } => {
            if !matches!(
                engine.get_data().apis.services.handles.get(&args[0]),
                Some(Handle::Manager)
            ) {
                return fail(engine, ERROR_INVALID_HANDLE);
            }
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let name = files::path(engine, args[1], wide)?;
            let found = engine
                .get_data()
                .apis
                .services
                .services
                .iter()
                .position(|service| service.name.eq_ignore_ascii_case(&name) && !service.deleted);
            let Some(index) = found else {
                return fail(engine, ERROR_SERVICE_DOES_NOT_EXIST);
            };
            let handle = engine
                .get_data_mut()
                .apis
                .services
                .handle(Handle::Service(index));
            engine.get_data_mut().apis.last_error = ERROR_SUCCESS;
            Ok(handle)
        }
        Call::Delete => {
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            let (name, binary) = {
                let service = &mut engine.get_data_mut().apis.services.services[index];
                service.deleted = true;
                (service.name.clone(), service.binary.clone())
            };
            engine
                .get_data_mut()
                .apis
                .services
                .record("DeleteService", name, binary, 0);
            succeed(engine)
        }
        Call::Close => {
            if engine
                .get_data_mut()
                .apis
                .services
                .handles
                .remove(&args[0])
                .is_none()
            {
                return fail(engine, ERROR_INVALID_HANDLE);
            }
            succeed(engine)
        }
        Call::Start => {
            // (hService, dwNumServiceArgs, lpServiceArgVectors): the request is
            // recorded and the record marked running; nothing is executed.
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            let (name, binary, start_type) = {
                let service = &mut engine.get_data_mut().apis.services.services[index];
                service.state = SERVICE_RUNNING;
                (
                    service.name.clone(),
                    service.binary.clone(),
                    service.start_type,
                )
            };
            engine
                .get_data_mut()
                .apis
                .services
                .record("StartService", name, binary, start_type);
            succeed(engine)
        }
        Call::Control => {
            // (hService, dwControl, lpServiceStatus)
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            if args[1] as u32 == SERVICE_CONTROL_STOP {
                engine.get_data_mut().apis.services.services[index].state = SERVICE_STOPPED;
            }
            let service = engine.get_data().apis.services.services[index].clone();
            if args[2] != 0 {
                put(engine, args[2], &status_bytes(&service))?;
            }
            succeed(engine)
        }
        Call::QueryStatus => {
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let service = engine.get_data().apis.services.services[index].clone();
            put(engine, args[1], &status_bytes(&service))?;
            succeed(engine)
        }
        Call::QueryConfig { wide } => query_config(engine, args, wide),
        Call::ChangeConfig { wide } => {
            // (hService, type, start, errorControl, binary, loadOrder, tagId,
            // dependencies, startName, password, display)
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            let binary = optional_text(engine, args[4], wide)?;
            let display = optional_text(engine, args[10], wide)?;
            // SERVICE_NO_CHANGE leaves a field alone.
            const NO_CHANGE: u32 = 0xffff_ffff;
            let (name, recorded, start_type) = {
                let service = &mut engine.get_data_mut().apis.services.services[index];
                if args[1] as u32 != NO_CHANGE {
                    service.service_type = args[1] as u32;
                }
                if args[2] as u32 != NO_CHANGE {
                    service.start_type = args[2] as u32;
                }
                if args[3] as u32 != NO_CHANGE {
                    service.error_control = args[3] as u32;
                }
                if !binary.is_empty() {
                    service.binary = binary;
                }
                if !display.is_empty() {
                    service.display = display;
                }
                (
                    service.name.clone(),
                    service.binary.clone(),
                    service.start_type,
                )
            };
            engine.get_data_mut().apis.services.record(
                "ChangeServiceConfig",
                name,
                recorded,
                start_type,
            );
            succeed(engine)
        }
        Call::ChangeConfig2 => {
            // (hService, dwInfoLevel, lpInfo): recovery/description settings are
            // accepted and recorded without being modeled field by field.
            let Some(index) = service_index(engine, args[0]) else {
                return fail(engine, ERROR_INVALID_HANDLE);
            };
            let name = engine.get_data().apis.services.services[index].name.clone();
            engine.get_data_mut().apis.services.record(
                "ChangeServiceConfig2",
                name,
                format!("level {}", args[1] as u32),
                0,
            );
            succeed(engine)
        }
        Call::EnumStatus { wide } => enum_status(engine, args, wide),
        Call::SetStatus => {
            // A service process reporting its own status: accepted, since the
            // handle comes from RegisterServiceCtrlHandler.
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            read(engine, args[1], 28)?;
            succeed(engine)
        }
        Call::CtrlDispatcher => {
            // Run interactively there is no service controller to connect to,
            // which is what the real SCM reports in this situation.
            let name = if args[0] != 0 {
                // SERVICE_TABLE_ENTRY { LPSTR lpServiceName; LPSERVICE_MAIN_FUNCTION; }
                let width = ptr_width(engine);
                let bytes = read(engine, args[0], width)?;
                let mut pointer = [0u8; 8];
                pointer[..width as usize].copy_from_slice(&bytes);
                optional_text(engine, u64::from_le_bytes(pointer), false).unwrap_or_default()
            } else {
                String::new()
            };
            engine.get_data_mut().apis.services.record(
                "StartServiceCtrlDispatcher",
                name,
                String::new(),
                0,
            );
            fail(engine, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        }
    }
}

/// `QueryServiceConfig(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded)`:
/// a QUERY_SERVICE_CONFIG header whose string pointers address the same buffer.
fn query_config(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let Some(index) = service_index(engine, args[0]) else {
        return fail(engine, ERROR_INVALID_HANDLE);
    };
    let service = engine.get_data().apis.services.services[index].clone();
    let width = ptr_width(engine);
    // Header layout differs by pointer width; both are the documented shape.
    let (header, binary_at, group_at, tag_at, deps_at, start_at, display_at) = if width == 8 {
        (64u64, 16u64, 24u64, 32u64, 40u64, 48u64, 56u64)
    } else {
        (36, 12, 16, 20, 24, 28, 32)
    };
    let binary = encode(&service.binary, wide);
    let group = encode("", wide);
    let deps = encode("", wide);
    let start_name = encode("LocalSystem", wide);
    let display = encode(&service.display, wide);

    let mut bytes = vec![0u8; header as usize];
    bytes[0..4].copy_from_slice(&service.service_type.to_le_bytes());
    bytes[4..8].copy_from_slice(&service.start_type.to_le_bytes());
    bytes[8..12].copy_from_slice(&service.error_control.to_le_bytes());
    bytes[tag_at as usize..tag_at as usize + 4].copy_from_slice(&0u32.to_le_bytes());

    let mut links: Vec<(u64, usize)> = Vec::new();
    for (field, text) in [
        (binary_at, &binary),
        (group_at, &group),
        (deps_at, &deps),
        (start_at, &start_name),
        (display_at, &display),
    ] {
        links.push((field, bytes.len()));
        bytes.extend(text.iter());
    }
    if args[3] != 0 {
        write_dword(engine, args[3], bytes.len() as u32)?;
    }
    if args[1] == 0 || (args[2] as usize) < bytes.len() {
        return fail(engine, ERROR_INSUFFICIENT_BUFFER);
    }
    for (field, offset) in links {
        let target = args[1] + offset as u64;
        let encoded = target.to_le_bytes();
        bytes[field as usize..field as usize + width as usize]
            .copy_from_slice(&encoded[..width as usize]);
    }
    put(engine, args[1], &bytes)?;
    succeed(engine)
}

/// `EnumServicesStatus(hSCManager, type, state, lpServices, cbBufSize,
/// pcbBytesNeeded, lpServicesReturned, lpResumeHandle)`.
fn enum_status(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    if !matches!(
        engine.get_data().apis.services.handles.get(&args[0]),
        Some(Handle::Manager)
    ) {
        return fail(engine, ERROR_INVALID_HANDLE);
    }
    let width = ptr_width(engine);
    let entry = (width * 2 + 28).next_multiple_of(width);
    // SERVICE_STATE_ALL is 3; otherwise match the requested state class.
    let requested = args[2] as u32;
    let services: Vec<Service> = engine
        .get_data()
        .apis
        .services
        .services
        .iter()
        .filter(|service| !service.deleted)
        .filter(|service| match requested {
            1 => service.state == SERVICE_RUNNING, // SERVICE_ACTIVE
            2 => service.state != SERVICE_RUNNING, // SERVICE_INACTIVE
            _ => true,
        })
        .cloned()
        .collect();
    let mut bytes = vec![0u8; entry as usize * services.len()];
    let mut links: Vec<(usize, usize)> = Vec::new();
    for (index, service) in services.iter().enumerate() {
        let at = index * entry as usize;
        bytes[at + width as usize * 2..at + width as usize * 2 + 28]
            .copy_from_slice(&status_bytes(service));
        links.push((at, bytes.len()));
        bytes.extend(encode(&service.name, wide));
        links.push((at + width as usize, bytes.len()));
        bytes.extend(encode(&service.display, wide));
    }
    if args[5] != 0 {
        write_dword(engine, args[5], bytes.len() as u32)?;
    }
    if args[3] == 0 || (args[4] as usize) < bytes.len() {
        if args[6] != 0 {
            write_dword(engine, args[6], 0)?;
        }
        return fail(engine, ERROR_INSUFFICIENT_BUFFER);
    }
    for (pointer_at, target_at) in links {
        let target = args[3] + target_at as u64;
        let encoded = target.to_le_bytes();
        bytes[pointer_at..pointer_at + width as usize]
            .copy_from_slice(&encoded[..width as usize]);
    }
    put(engine, args[3], &bytes)?;
    if args[6] != 0 {
        write_dword(engine, args[6], services.len() as u32)?;
    }
    if args[7] != 0 {
        write_dword(engine, args[7], 0)?;
    }
    succeed(engine)
}
