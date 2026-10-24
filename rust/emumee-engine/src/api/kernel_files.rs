//! Synchronous NT file APIs over ApiState.files, the actual VFS authority.
use super::*;
use emumee_core::filesystem::{
    self as fs, NativeFileClass as Class, NativeFileError, NativeFileOpen,
};
const OWNER: u64 = 4;
const CREATE_REQUEST_LIMIT: usize = 64;
const NAME_PREVIEW_CHARS: usize = 512;
pub(super) const ROUTINES: &[&str] = &[
    "IoCreateFileEx",
    "ZwReadFile",
    "ZwWriteFile",
    "ZwFlushBuffersFile",
];
#[derive(Clone, Copy)]
pub(super) enum Call {
    Create,
    Read,
    Write,
    Flush,
}
pub(super) fn definition(name: &str) -> Option<(Call, usize)> {
    Some(match name {
        "IoCreateFileEx" => (Call::Create, 15),
        "ZwReadFile" => (Call::Read, 9),
        "ZwWriteFile" => (Call::Write, 9),
        "ZwFlushBuffersFile" => (Call::Flush, 2),
        _ => return None,
    })
}
#[derive(Default)]
pub(crate) struct State {
    native_effect_failure: bool,
    events: Vec<Event>,
    omitted: u64,
    completed_create_requests: u64,
    create_request_receipts: Vec<CreateRequestReceipt>,
    create_request_receipts_omitted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub handle: u64,
    pub status: u32,
    pub information: u64,
    pub requested: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct CreateRequestReceipt {
    pub name: String,
    pub name_truncated: bool,
    pub name_utf16_units: usize,
    pub name_utf16_sha256: String,
    pub root_handle: u64,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub status: u32,
    pub information: u64,
    pub instruction_count: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub handles: fs::NativeFilesReport,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub native_effect_failure: bool,
    pub completed_create_requests: u64,
    pub create_request_receipts: Vec<CreateRequestReceipt>,
    pub create_request_receipt_limit: usize,
    pub create_request_receipts_omitted: u64,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.kernel_files;
    Report {
        handles: engine.get_data().apis.files.native_files_report(),
        events: state.events.clone(),
        events_omitted: state.omitted,
        native_effect_failure: state.native_effect_failure,
        completed_create_requests: state.completed_create_requests,
        create_request_receipts: state.create_request_receipts.clone(),
        create_request_receipt_limit: CREATE_REQUEST_LIMIT,
        create_request_receipts_omitted: state.create_request_receipts_omitted,
        scope: "System4/CPL0/PASSIVE synchronous IoCreateFileEx, ZwReadFile/ZwWriteFile/ZwFlushBuffersFile, typed Zw/NtClose over sole VFS handles/backing. Completed create-request receipts cover only calls reaching VFS whose handle/IOSB outputs completed; earlier validation completions remain solely in events. Names are the already-parsed VFS arguments after SystemRoot alias resolution, not host paths or an independently canonicalized name. At most64 receipts preserve512 Unicode characters and full nonterminated UTF16 length/hash; count and omissions concern completed VFS requests, not attempts or entry success. Finite low/high reservations; native writes to configured files mutate only the guest-owned VFS copy under normal rights, sharing, and read-only checks. No host I/O, asynchronous completion, FILE_OBJECT/reference fabrication, device namespace, security/EA/context or physical durability claim.",
    }
}
fn record_completed_create(
    engine: &mut Unicorn<Trace>,
    name: &str,
    root_handle: u64,
    args: &[u64],
    status: u32,
    information: u64,
) {
    use sha2::{Digest, Sha256};
    let instruction_count = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().apis.kernel_files;
    state.completed_create_requests = state.completed_create_requests.saturating_add(1);
    if state.create_request_receipts.len() == CREATE_REQUEST_LIMIT {
        state.create_request_receipts_omitted =
            state.create_request_receipts_omitted.saturating_add(1);
        return;
    }
    let mut characters = name.chars();
    let preview = characters.by_ref().take(NAME_PREVIEW_CHARS).collect();
    let name_truncated = characters.next().is_some();
    let mut hasher = Sha256::new();
    let mut name_utf16_units = 0;
    for unit in name.encode_utf16() {
        hasher.update(unit.to_le_bytes());
        name_utf16_units += 1;
    }
    state.create_request_receipts.push(CreateRequestReceipt {
        name: preview,
        name_truncated,
        name_utf16_units,
        name_utf16_sha256: format!("{:x}", hasher.finalize()),
        root_handle,
        desired_access: args[1] as u32,
        share_access: args[6] as u32,
        create_disposition: args[7] as u32,
        create_options: args[8] as u32,
        status,
        information,
        instruction_count,
    });
}
fn record(
    engine: &mut Unicorn<Trace>,
    operation: &'static str,
    handle: u64,
    status: u32,
    information: u64,
    requested: Option<u32>,
) {
    let s = &mut engine.get_data_mut().apis.kernel_files;
    if s.events.len() < 128 {
        s.events.push(Event {
            operation,
            handle,
            status,
            information,
            requested,
        });
    } else {
        s.omitted = s.omitted.saturating_add(1);
    }
}
pub(crate) fn ensure_healthy(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel_files.native_effect_failure,
        "Native file effect failed; execution cannot resume"
    );
    Ok(())
}
fn ready(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure_healthy(engine)?;
    ensure!(
        super::kernel_sync::observe_irql(engine)? == 0,
        "Native files require PASSIVE_LEVEL"
    );
    Ok(())
}
fn failure(error: NativeFileError) -> Result<(u32, u64)> {
    match error.status {
        Some(code) => Ok((code, error.information)),
        None => bail!("Native file profile unsupported: {}", error.reason),
    }
}
fn pointer(bytes: &[u8], at: usize, width: usize) -> u64 {
    let mut raw = [0; 8];
    raw[..width].copy_from_slice(&bytes[at..at + width]);
    u64::from_le_bytes(raw)
}
fn iosb(width: usize, status: u32, information: u64) -> Vec<u8> {
    let mut bytes = vec![0; 2 * width];
    bytes[..4].copy_from_slice(&status.to_le_bytes());
    bytes[width..2 * width].copy_from_slice(&information.to_le_bytes()[..width]);
    bytes
}
fn chunks(address: u64, length: u64) -> Result<impl Iterator<Item = (u64, u64)>> {
    let end = address
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("Native file range overflow"))?;
    Ok((0..length.div_ceil(MAX_TRANSFER)).map(move |index| {
        let at = address + index * MAX_TRANSFER;
        (at, (end - at).min(MAX_TRANSFER))
    }))
}
fn preflight(engine: &Unicorn<Trace>, spans: &[(u64, u64, P)]) -> Result<()> {
    for (index, (address, length, permission)) in spans.iter().enumerate() {
        for (at, count) in chunks(*address, *length)? {
            require(engine, at, count, *permission)?;
        }
        if *length == 0 {
            continue;
        }
        let end = address
            .checked_add(*length)
            .ok_or_else(|| anyhow::anyhow!("Native file output range overflow"))?;
        for (other, size, prior) in &spans[..index] {
            if *size == 0 || *permission != P::WRITE || *prior != P::WRITE {
                continue;
            }
            let stop = other
                .checked_add(*size)
                .ok_or_else(|| anyhow::anyhow!("Native file output range overflow"))?;
            ensure!(
                *address >= stop || *other >= end,
                "Native file outputs overlap"
            );
        }
    }
    Ok(())
}
fn output(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    for (index, part) in bytes.chunks(MAX_TRANSFER as usize).enumerate() {
        let at = address + index as u64 * MAX_TRANSFER;
        if let Err(error) = crate::cpu::write(engine, at, part) {
            engine
                .get_data_mut()
                .apis
                .kernel_files
                .native_effect_failure = true;
            return Err(error);
        }
    }
    Ok(())
}
fn complete(
    engine: &mut Unicorn<Trace>,
    iosb_address: u64,
    operation: &'static str,
    handle: u64,
    status: u32,
    information: u64,
    requested: Option<u32>,
) -> Result<u64> {
    let width = engine.get_data().architecture.width();
    output(engine, iosb_address, &iosb(width, status, information))?;
    record(engine, operation, handle, status, information, requested);
    Ok(status.into())
}
fn counted(engine: &Unicorn<Trace>, address: u64) -> Result<String> {
    let width = engine.get_data().architecture.width();
    let raw = read(engine, address, if width == 8 { 16 } else { 8 })?;
    let length = u16::from_le_bytes(raw[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(raw[2..4].try_into().unwrap()) as usize;
    ensure!(
        length != 0 && length <= 32766 && length % 2 == 0 && length <= maximum,
        "Native file UNICODE_STRING length/maximum invalid"
    );
    let bytes = read(
        engine,
        pointer(&raw, if width == 8 { 8 } else { 4 }, width),
        length as u64,
    )?;
    let units = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .collect::<Vec<_>>();
    let name = String::from_utf16(&units)
        .map_err(|_| anyhow::anyhow!("Native file name is not strict UTF-16"))?;
    ensure!(
        !name.contains('\0'),
        "Native file counted name contains NUL"
    );
    Ok(name)
}
fn known_wrong_type(engine: &Unicorn<Trace>, handle: u64) -> Result<Option<u32>> {
    let arch = engine.get_data().architecture;
    if engine
        .get_data()
        .apis
        .files
        .native_file_class(arch, OWNER, handle)
        != Class::Foreign
    {
        return Ok(None);
    }
    use emumee_core::registry::NativeHandleClass as R;
    match engine
        .get_data()
        .apis
        .registry
        .native_handle_class(arch, OWNER, handle)
    {
        R::KernelLive => return Ok(Some(0xc0000024)),
        R::Invalid => return Ok(Some(0xc0000008)),
        R::UserLive => bail!("User registry handle is outside native file authority"),
        R::Foreign => {}
    }
    Ok(
        match crate::threads::lookup_reference_handle(engine, handle)? {
            crate::threads::HandleLookup::Thread(_) => Some(0xc0000024),
            crate::threads::HandleLookup::Invalid => Some(0xc0000008),
            crate::threads::HandleLookup::Foreign => None,
        },
    )
}
fn resolve_persona_alias(engine: &Unicorn<Trace>, name: String) -> String {
    if name.to_ascii_lowercase().starts_with("\\systemroot\\") {
        let windows = &engine
            .get_data()
            .apis
            .persona
            .model
            .config()
            .windows_directory;
        format!("{}\\{}", windows.trim_end_matches('\\'), &name[12..])
    } else {
        name
    }
}
fn create(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let width = engine.get_data().architecture.width();
    let arch = engine.get_data().architecture;
    preflight(
        engine,
        &[
            (args[0], width as u64, P::WRITE),
            (args[3], (2 * width) as u64, P::WRITE),
        ],
    )?;
    let size = if width == 8 { 48 } else { 24 };
    let raw = read(engine, args[2], size)?;
    if u32::from_le_bytes(raw[..4].try_into().unwrap()) != size as u32 {
        return complete(engine, args[3], "create", 0, 0xc000000d, 0, None);
    }
    let (root, name, flags, security, qos) = if width == 8 {
        (8, 16, 24, 32, 40)
    } else {
        (4, 8, 12, 16, 20)
    };
    let attributes = u32::from_le_bytes(raw[flags..flags + 4].try_into().unwrap());
    ensure!(
        attributes & !0x240 == 0
            && pointer(&raw, security, width) == 0
            && pointer(&raw, qos, width) == 0,
        "Native file object attributes/security unsupported"
    );
    ensure!(
        args[9] == 0
            && args[10] as u32 == 0
            && args[11] as u32 == 0
            && args[12] == 0
            && args[13] as u32 & !8 == 0
            && args[14] == 0,
        "Native file EA/type/options/context unsupported"
    );
    let name = resolve_persona_alias(engine, counted(engine, pointer(&raw, name, width))?);
    let root = pointer(&raw, root, width);
    if root != 0 {
        if let Some(status) = known_wrong_type(engine, root)? {
            return complete(engine, args[3], "create", 0, status, 0, None);
        }
    }
    if args[4] != 0 {
        let allocation = i64::from_le_bytes(read(engine, args[4], 8)?.try_into().unwrap());
        if !(0..=fs::NATIVE_MAX_TRANSFER as i64).contains(&allocation) {
            return complete(engine, args[3], "create", 0, 0xc000000d, 0, None);
        }
    }
    let result = engine
        .get_data_mut()
        .apis
        .files
        .native_open_file(NativeFileOpen {
            architecture: arch,
            owner: OWNER,
            root,
            name: &name,
            access: args[1] as u32,
            attributes: args[5] as u32,
            share: args[6] as u32,
            disposition: args[7] as u32,
            options: args[8] as u32,
        });
    let (status, information, returned) = match result {
        Ok(opened) => {
            output(engine, args[0], &opened.handle.to_le_bytes()[..width])?;
            let returned = complete(
                engine,
                args[3],
                "create",
                opened.handle,
                0,
                opened.information,
                None,
            )?;
            (0, opened.information, returned)
        }
        Err(error) => {
            let (status, information) = failure(error)?;
            let returned = complete(engine, args[3], "create", 0, status, information, None)?;
            (status, information, returned)
        }
    };
    record_completed_create(engine, &name, root, args, status, information);
    Ok(returned)
}
fn transfer(engine: &mut Unicorn<Trace>, args: &[u64], write: bool) -> Result<u64> {
    let operation = if write { "write" } else { "read" };
    let width = engine.get_data().architecture.width();
    let arch = engine.get_data().architecture;
    let count = args[6] as u32;
    preflight(engine, &[(args[4], (2 * width) as u64, P::WRITE)])?;
    if let Some(status) = known_wrong_type(engine, args[0])? {
        return complete(engine, args[4], operation, args[0], status, 0, Some(count));
    }
    if let Err(error) = engine
        .get_data()
        .apis
        .files
        .native_transfer_rights(arch, OWNER, args[0], write)
    {
        let (status, information) = failure(error)?;
        return complete(
            engine,
            args[4],
            operation,
            args[0],
            status,
            information,
            Some(count),
        );
    }
    ensure!(
        args[1] == 0 && args[2] == 0 && args[3] == 0 && args[8] == 0,
        "Native file event/APC/key asynchronous parameters unsupported"
    );
    ensure!(
        count as usize <= fs::NATIVE_MAX_TRANSFER,
        "Native file transfer exceeds 32 MiB bound"
    );
    preflight(
        engine,
        &[
            (args[4], (2 * width) as u64, P::WRITE),
            (
                args[5],
                count.into(),
                if write { P::READ } else { P::WRITE },
            ),
        ],
    )?;
    let offset = if args[7] == 0 {
        None
    } else {
        Some(i64::from_le_bytes(
            read(engine, args[7], 8)?.try_into().unwrap(),
        ))
    };
    if write {
        let mut bytes = Vec::with_capacity(count as usize);
        for (at, length) in chunks(args[5], count.into())? {
            bytes.extend(read(engine, at, length)?);
        }
        let result = engine
            .get_data_mut()
            .apis
            .files
            .native_write_file(arch, OWNER, args[0], &bytes, offset);
        match result {
            Ok(copied) => complete(
                engine,
                args[4],
                operation,
                args[0],
                0,
                copied as u64,
                Some(count),
            ),
            Err(error) => {
                let (status, information) = failure(error)?;
                complete(
                    engine,
                    args[4],
                    operation,
                    args[0],
                    status,
                    information,
                    Some(count),
                )
            }
        }
    } else {
        let result = engine.get_data_mut().apis.files.native_read_file(
            arch,
            OWNER,
            args[0],
            count as usize,
            offset,
        );
        match result {
            Ok((status, bytes)) => {
                output(engine, args[5], &bytes)?;
                complete(
                    engine,
                    args[4],
                    operation,
                    args[0],
                    status,
                    bytes.len() as u64,
                    Some(count),
                )
            }
            Err(error) => {
                let (status, information) = failure(error)?;
                complete(
                    engine,
                    args[4],
                    operation,
                    args[0],
                    status,
                    information,
                    Some(count),
                )
            }
        }
    }
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ready(engine)?;
    ensure!(
        args.len()
            == match call {
                Call::Create => 15,
                Call::Read | Call::Write => 9,
                Call::Flush => 2,
            },
        "Native file argument count mismatch"
    );
    match call {
        Call::Create => create(engine, args),
        Call::Read => transfer(engine, args, false),
        Call::Write => transfer(engine, args, true),
        Call::Flush => {
            let width = engine.get_data().architecture.width();
            preflight(engine, &[(args[1], (2 * width) as u64, P::WRITE)])?;
            if let Some(status) = known_wrong_type(engine, args[0])? {
                return complete(engine, args[1], "flush", args[0], status, 0, None);
            }
            let arch = engine.get_data().architecture;
            let (status, information) = match engine
                .get_data()
                .apis
                .files
                .native_flush_file(arch, OWNER, args[0])
            {
                Ok(()) => (0, 0),
                Err(error) => failure(error)?,
            };
            complete(engine, args[1], "flush", args[0], status, information, None)
        }
    }
}
/// Some only when this actual VFS domain owns or reserves the identity.
pub(crate) fn close_if_owned(engine: &mut Unicorn<Trace>, handle: u64) -> Result<Option<u64>> {
    ready(engine)?;
    let arch = engine.get_data().architecture;
    let status = match engine
        .get_data()
        .apis
        .files
        .native_file_class(arch, OWNER, handle)
    {
        Class::Live(_) => match engine
            .get_data_mut()
            .apis
            .files
            .native_close_file(arch, OWNER, handle)
        {
            Ok(()) => 0,
            Err(error) => failure(error)?.0,
        },
        Class::Invalid => 0xc0000008,
        Class::UserLive => bail!("Ordinary user-file handles are outside native close domain"),
        Class::Foreign => return Ok(None),
    };
    record(engine, "close", handle, status, 0, None);
    Ok(Some(status.into()))
}
/// Compiler-owned program and fixed configuration; no arbitrary input admission.
pub(crate) fn fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::NativeFilesFixture,
    budget: u64,
) -> Result<crate::Execution> {
    let validated = emumee_core::fullpersona::decode(
        &emumee_core::fixtures::native_files_document(),
        &emumee_core::fullpersona::ResolveContext::default(),
    )?;
    let prepared = crate::configured::Prepared::new(
        validated,
        crate::configured::Request {
            architecture,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )?;
    crate::run_generated_with_fixture_configuration(
        &emumee_core::fixtures::native_files_probe(architecture, kind),
        &[],
        budget,
        30_000_000,
        crate::GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counted_directory_name_accepts_one_trailing_separator_but_not_ambiguous_components() {
        for arch in [Architecture::X86, Architecture::X64] {
            let accepted = fixture(
                arch,
                emumee_core::fixtures::NativeFilesFixture::DirectoryTrailing,
                100_000,
            )
            .unwrap();
            assert_eq!(accepted.error, None, "{accepted:#?}");
            assert_eq!(accepted.completion_reason, "entry_return");
            assert_eq!(accepted.guest_entry_return, Some(1));
            let files = accepted.kernel_files.as_ref().unwrap();
            assert_eq!(files.events.first().unwrap().operation, "create");
            assert_eq!(files.events.first().unwrap().status, 0);
            assert!(!files.native_effect_failure);

            for kind in [
                emumee_core::fixtures::NativeFilesFixture::DirectoryInteriorEmpty,
                emumee_core::fixtures::NativeFilesFixture::FileTrailing,
            ] {
                let rejected = fixture(arch, kind, 100_000).unwrap();
                assert_eq!(rejected.completion_reason, "error");
                assert_eq!(rejected.guest_entry_return, None);
                assert!(
                    rejected
                        .error
                        .as_deref()
                        .unwrap()
                        .contains(kind.error().unwrap())
                );
                assert!(rejected.kernel_files.as_ref().unwrap().events.is_empty());
            }
        }
    }
    fn memory(engine: &mut Unicorn<Trace>, native: bool) {
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x10000, 4096, P::RW, None, "native file test")
            .unwrap();
        if native {
            engine
                .mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)
                .unwrap();
        }
    }
    #[test]
    fn output_preflight_rejects_late_range_and_overlap_before_any_vfs_or_guest_mutation() {
        for spans in [
            vec![(0x10000, 8, P::WRITE), (0x11000, 8, P::WRITE)],
            vec![(0x10000, 16, P::WRITE), (0x10008, 8, P::WRITE)],
        ] {
            let mut e = crate::new_engine(Architecture::X64).unwrap();
            memory(&mut e, true);
            e.mem_write(0x10000, &[0x77; 32]).unwrap();
            assert!(preflight(&e, &spans).is_err());
            assert_eq!(e.mem_read_as_vec(0x10000, 32).unwrap(), [0x77; 32]);
            assert_eq!(report(&e).handles.lifetime_issues, 0);
            assert!(!report(&e).native_effect_failure);
        }
    }
    #[test]
    fn native_output_failure_is_terminal_and_counted_name_never_scans_maximum() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = crate::new_engine(arch).unwrap();
            memory(&mut e, false);
            assert!(output(&mut e, 0x10000, b"X").is_err());
            assert!(ensure_healthy(&e).is_err());
            assert!(report(&e).native_effect_failure);
            drop(e);
            let mut e = crate::new_engine(arch).unwrap();
            memory(&mut e, true);
            let width = arch.width();
            let mut descriptor = vec![0; 16];
            descriptor[..2].copy_from_slice(&2u16.to_le_bytes());
            descriptor[2..4].copy_from_slice(&32766u16.to_le_bytes());
            let at = if width == 8 { 8 } else { 4 };
            descriptor[at..at + width].copy_from_slice(&0x10ffeu64.to_le_bytes()[..width]);
            e.mem_write(0x10000, &descriptor).unwrap();
            e.mem_write(0x10ffe, &[b'A', 0]).unwrap();
            assert_eq!(counted(&e, 0x10000).unwrap(), "A");
            e.mem_write(0x10ffe, &[0, 0xd8]).unwrap();
            assert!(counted(&e, 0x10000).is_err());
        }
    }
    #[test]
    fn transfer_chunking_and_iosb_widths_are_exact_without_relaxing_common_transfer_cap() {
        assert_eq!(
            chunks(0x1000, 32 * 1024 * 1024)
                .unwrap()
                .collect::<Vec<_>>(),
            [
                (0x1000, MAX_TRANSFER),
                (0x1000 + MAX_TRANSFER, MAX_TRANSFER)
            ]
        );
        assert!(chunks(u64::MAX - 1, 4).is_err());
        for width in [4, 8] {
            let b = iosb(width, 0xc0000011, 17);
            assert_eq!(b.len(), 2 * width);
            assert_eq!(&b[..4], &0xc0000011u32.to_le_bytes());
            assert_eq!(pointer(&b, width, width), 17);
            if width == 8 {
                assert_eq!(&b[4..8], &[0; 4]);
            }
        }
    }
    #[test]
    fn systemroot_uses_the_installed_persona_and_never_host_or_fixture_drive_guessing() {
        let mut e = crate::new_engine(Architecture::X64).unwrap();
        let mut config = emumee_core::persona::PersonaConfig::fixture();
        config.windows_directory = r"D:\GuestOS".into();
        config.system_directory = r"D:\GuestOS\System32".into();
        e.get_data_mut().apis.persona =
            persona::State::new(emumee_core::persona::Persona::new(config).unwrap());
        assert_eq!(
            resolve_persona_alias(&e, r"\SystemRoot\System32\guest.bin".into()),
            r"D:\GuestOS\System32\guest.bin"
        );
        assert_eq!(
            resolve_persona_alias(&e, r"\SystemRootOther\file".into()),
            r"\SystemRootOther\file"
        );
    }
    #[test]
    fn all_chunks_are_preflighted_and_partial_native_effect_failure_preserves_honest_committed_state()
     {
        let mut e = crate::new_engine(Architecture::X64).unwrap();
        e.get_data_mut()
            .apis
            .memory
            .map(0x10000000, MAX_TRANSFER, P::RW, None, "first transfer half")
            .unwrap();
        e.get_data_mut()
            .apis
            .memory
            .map(
                0x10000000 + MAX_TRANSFER,
                MAX_TRANSFER,
                P::READ,
                None,
                "protected second transfer half",
            )
            .unwrap();
        assert!(preflight(&e, &[(0x10000000, 2 * MAX_TRANSFER, P::WRITE)]).is_err());
        assert_eq!(report(&e).handles.lifetime_issues, 0);
        memory(&mut e, true);
        e.get_data_mut()
            .apis
            .memory
            .map(0x11000, 4096, P::RW, None, "model-only IOSB")
            .unwrap();
        preflight(&e, &[(0x10000, 8, P::WRITE), (0x11000, 16, P::WRITE)]).unwrap();
        let handle = e
            .get_data_mut()
            .apis
            .files
            .native_open_file(NativeFileOpen {
                architecture: Architecture::X64,
                owner: OWNER,
                root: 0,
                name: r"C:\workspace\partial.bin",
                access: 0xc0000000,
                share: 7,
                disposition: 3,
                options: 0x60,
                attributes: 0x80,
            })
            .unwrap()
            .handle;
        output(&mut e, 0x10000, &handle.to_le_bytes()).unwrap();
        assert!(complete(&mut e, 0x11000, "create", handle, 0, 2, None).is_err());
        assert_eq!(e.mem_read_as_vec(0x10000, 8).unwrap(), handle.to_le_bytes());
        let report = report(&e);
        assert!(report.native_effect_failure);
        assert_eq!(report.handles.lifetime_issues, 1);
        assert_eq!(report.handles.live.len(), 1);
        assert!(report.events.is_empty());
        assert_eq!(report.completed_create_requests, 0);
        assert!(report.create_request_receipts.is_empty());
        assert_eq!(report.create_request_receipts_omitted, 0);
        assert!(ensure_healthy(&e).is_err());
    }
}
