//! Guest volume, drive, DOS-device and path-redirection reporting over the one
//! modeled persona volume. No host volume, drive letter or device information
//! is consulted, and the reported capacity is persona identity rather than an
//! allocator: writing a guest file never changes it.
use super::*;
use emumee_core::persona::Encoding;
/// Volume enumeration handles sit in their own range, distinct from the file
/// search handles so a guest cannot cross the two enumerations.
const SEARCH_FIRST: u64 = 0x70020000;
const SEARCH_END: u64 = 0x70030000;
/// The one modeled volume is mounted at C:\ and nowhere else.
const ROOT: &str = r"C:\";
const MAX_COMPONENT: u32 = 255;
/// Case-preserving Unicode names only. The virtual filesystem has no ACLs,
/// compression, sparse files, reparse points, quotas, streams or encryption, so
/// those capability bits are deliberately absent instead of advertised.
const FILESYSTEM_FLAGS: u32 = 0x2 | 0x4;
/// The modeled DOS device target for C:. It is a model literal, not a host
/// device path.
const DEVICE: &str = r"\Device\HarddiskVolume1";
#[derive(Clone, Copy)]
pub(super) enum Call {
    DiskFreeEx { wide: bool },
    DriveType { wide: bool },
    LogicalDrives,
    Information { wide: bool },
    NameForMountPoint { wide: bool },
    PathNamesForName { wide: bool },
    FirstVolume { wide: bool },
    NextVolume,
    CloseVolume,
    DosDevice { wide: bool },
    ApisAnsi,
    DisableRedirection,
    RevertRedirection,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    /// Live enumerations and how many volumes each has already reported.
    searches: BTreeMap<u64, u32>,
    issued: u64,
    /// Cookies handed out by Wow64DisableWow64FsRedirection and not yet
    /// reverted. The virtual filesystem performs no WOW64 redirection, so the
    /// only observable effect is this cookie's own round trip.
    redirection_cookies: Vec<u64>,
    redirection_issued: u64,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let file = kernel
        || matches!(
            module,
            "api-ms-win-core-file-l1-1-0"
                | "api-ms-win-core-file-l1-2-0"
                | "api-ms-win-core-file-l2-1-0"
        );
    let wide = name.ends_with('W');
    Some(match name {
        "GetDiskFreeSpaceEx" | "GetDiskFreeSpaceExA" | "GetDiskFreeSpaceExW" if file => {
            (Call::DiskFreeEx { wide }, 4, T::U32)
        }
        "GetDriveTypeA" | "GetDriveTypeW" if file => (Call::DriveType { wide }, 1, T::U32),
        "GetLogicalDrives" if kernel => (Call::LogicalDrives, 0, T::U32),
        "GetVolumeInformationA" | "GetVolumeInformationW" if file => {
            (Call::Information { wide }, 8, T::U32)
        }
        "GetVolumeNameForVolumeMountPointA" | "GetVolumeNameForVolumeMountPointW" if file => {
            (Call::NameForMountPoint { wide }, 3, T::U32)
        }
        "GetVolumePathNamesForVolumeNameA" | "GetVolumePathNamesForVolumeNameW" if file => {
            (Call::PathNamesForName { wide }, 4, T::U32)
        }
        "FindFirstVolumeA" | "FindFirstVolumeW" if file => {
            (Call::FirstVolume { wide }, 2, T::Pointer)
        }
        "FindNextVolumeA" | "FindNextVolumeW" if file => (Call::NextVolume, 3, T::U32),
        "FindVolumeClose" if file => (Call::CloseVolume, 1, T::U32),
        "QueryDosDeviceA" | "QueryDosDeviceW" if kernel => (Call::DosDevice { wide }, 3, T::U32),
        "AreFileApisANSI" if kernel => (Call::ApisAnsi, 0, T::U32),
        "Wow64DisableWow64FsRedirection" if kernel => (Call::DisableRedirection, 1, T::U32),
        "Wow64RevertWow64FsRedirection" if kernel => (Call::RevertRedirection, 1, T::U32),
        _ => return None,
    })
}
/// A buffer capacity measured in characters is a DWORD. A compiler-produced
/// x64 caller stores a 32-bit argument into its eight-byte stack slot and
/// leaves the upper half undefined, so a capacity is read at its own width.
fn capacity(argument: u64) -> u64 {
    u64::from(argument as u32)
}
fn bad(engine: &mut Unicorn<Trace>, code: u32, value: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(value)
}
fn encoded(text: &str, wide: bool) -> Vec<u8> {
    if wide {
        Encoding::Utf16.encode(text, true)
    } else {
        Encoding::Cp1252.encode(text, true)
    }
}
/// Write one NUL-terminated string into a guest buffer measured in characters.
/// Answers `false` without writing when the text does not fit.
fn put_text(
    engine: &mut Unicorn<Trace>,
    at: u64,
    capacity: u64,
    text: &str,
    wide: bool,
) -> Result<bool> {
    let bytes = encoded(text, wide);
    let width = if wide { 2 } else { 1 };
    if (bytes.len() / width) as u64 > capacity {
        return Ok(false);
    }
    require(engine, at, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, at, &bytes)?;
    Ok(true)
}
/// The volume GUID path a guest sees for the one modeled volume.
fn volume_name(engine: &Unicorn<Trace>) -> String {
    format!(
        r"\\?\Volume{}\",
        engine.get_data().apis.persona.model.volume().guid
    )
}
/// Accept the one modeled volume's root in the spellings Windows accepts, and
/// nothing else. `None` means "the volume holding the current directory", which
/// is the same single volume.
fn root(path: Option<&str>) -> bool {
    match path {
        None => true,
        Some(path) => {
            let path = path.replace('/', "\\");
            let trimmed = path.trim_end_matches('\\');
            trimmed.eq_ignore_ascii_case("C:")
        }
    }
}
fn optional_path(engine: &Unicorn<Trace>, at: u64, wide: bool) -> Result<Option<String>> {
    if at == 0 {
        return Ok(None);
    }
    Ok(Some(super::files::path(engine, at, wide)?))
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "User volume APIs are outside the kernel target profile"
    );
    match call {
        Call::DiskFreeEx { wide } => {
            // The modeled volume answers for every path on it.
            let path = optional_path(engine, args[0], wide)?;
            if !root(path.as_deref().map(directory_volume)) {
                return bad(engine, 3, 0);
            }
            let volume = engine.get_data().apis.persona.model.volume().clone();
            for at in [args[1], args[2], args[3]] {
                if at != 0 && !engine.get_data().apis.memory.allows(at, 8, P::WRITE) {
                    return bad(engine, 998, 0);
                }
            }
            // Caller-available free space equals total free space: no quotas
            // are modeled.
            for (at, value) in [
                (args[1], volume.free_bytes),
                (args[2], volume.capacity_bytes),
                (args[3], volume.free_bytes),
            ] {
                if at != 0 {
                    crate::cpu::write(engine, at, &value.to_le_bytes())?;
                }
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::DriveType { wide } => {
            let path = optional_path(engine, args[0], wide)?;
            // A null root means the current directory's drive, which is the one
            // modeled fixed volume.
            Ok(if root(path.as_deref().map(directory_volume)) {
                3
            } else {
                // DRIVE_NO_ROOT_DIR: no other drive letter is mounted.
                1
            })
        }
        // Only C: exists, so bit two is the whole mask.
        Call::LogicalDrives => Ok(1 << 2),
        Call::Information { wide } => {
            let path = optional_path(engine, args[0], wide)?;
            if !root(path.as_deref()) {
                return bad(engine, 3, 0);
            }
            let volume = engine.get_data().apis.persona.model.volume().clone();
            let serial = volume.serial();
            for (at, size) in [(args[3], 4u64), (args[4], 4), (args[5], 4)] {
                if at != 0 && !engine.get_data().apis.memory.allows(at, size, P::WRITE) {
                    return bad(engine, 998, 0);
                }
            }
            if args[1] != 0
                && !put_text(engine, args[1], capacity(args[2]), &volume.label, wide)?
            {
                return bad(engine, 122, 0);
            }
            if args[6] != 0
                && !put_text(engine, args[6], capacity(args[7]), &volume.filesystem, wide)?
            {
                return bad(engine, 122, 0);
            }
            for (at, value) in [
                (args[3], serial),
                (args[4], MAX_COMPONENT),
                (args[5], FILESYSTEM_FLAGS),
            ] {
                if at != 0 {
                    crate::cpu::write(engine, at, &value.to_le_bytes())?;
                }
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::NameForMountPoint { wide } => {
            let path = optional_path(engine, args[0], wide)?;
            let Some(path) = path else {
                return bad(engine, 87, 0);
            };
            // The documented contract requires a trailing backslash.
            if !path.ends_with('\\') || !root(Some(&path)) {
                return bad(engine, 87, 0);
            }
            let name = volume_name(engine);
            if !put_text(engine, args[1], capacity(args[2]), &name, wide)? {
                return bad(engine, 122, 0);
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::PathNamesForName { wide } => {
            let path = optional_path(engine, args[0], wide)?;
            let Some(path) = path else {
                return bad(engine, 87, 0);
            };
            if !path.eq_ignore_ascii_case(&volume_name(engine)) {
                return bad(engine, 87, 0);
            }
            let width = if wide { 2u64 } else { 1 };
            // A multi-string: one mount path, then the list terminator.
            let units = ROOT.chars().count() as u64 + 2;
            if args[3] != 0 {
                if !engine.get_data().apis.memory.allows(args[3], 4, P::WRITE) {
                    return bad(engine, 998, 0);
                }
                crate::cpu::write(engine, args[3], &(units as u32).to_le_bytes())?;
            }
            if args[1] == 0 || capacity(args[2]) < units {
                return bad(engine, 234, 0);
            }
            let mut bytes = encoded(ROOT, wide);
            bytes.extend(std::iter::repeat_n(0, width as usize));
            require(engine, args[1], bytes.len() as u64, P::WRITE)?;
            crate::cpu::write(engine, args[1], &bytes)?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::FirstVolume { wide } => {
            let invalid = if engine.get_data().architecture == Architecture::X86 {
                u32::MAX as u64
            } else {
                u64::MAX
            };
            let handle = SEARCH_FIRST + engine.get_data().apis.volumes.issued * 4;
            let live = engine.get_data().apis.volumes.searches.len();
            if handle >= SEARCH_END || live >= 64 {
                return bad(engine, 8, invalid);
            }
            let name = volume_name(engine);
            if !put_text(engine, args[0], capacity(args[1]), &name, wide)? {
                return bad(engine, 122, invalid);
            }
            let state = &mut engine.get_data_mut().apis.volumes;
            state.issued += 1;
            state.searches.insert(handle, 1);
            engine.get_data_mut().apis.last_error = 0;
            Ok(handle)
        }
        Call::NextVolume => {
            if !engine
                .get_data()
                .apis
                .volumes
                .searches
                .contains_key(&args[0])
            {
                return bad(engine, 6, 0);
            }
            // FindFirstVolume already reported the only modeled volume, so the
            // enumeration ends here with ERROR_NO_MORE_FILES.
            bad(engine, 18, 0)
        }
        Call::CloseVolume => {
            if engine
                .get_data_mut()
                .apis
                .volumes
                .searches
                .remove(&args[0])
                .is_none()
            {
                return bad(engine, 6, 0);
            }
            Ok(1)
        }
        Call::DosDevice { wide } => {
            let device = optional_path(engine, args[0], wide)?;
            let width = if wide { 2usize } else { 1 };
            // A null device name enumerates every DOS device as a multi-string.
            let text = match device.as_deref() {
                None => None,
                Some(name) if root(Some(name)) => Some(DEVICE),
                Some(_) => return bad(engine, 2, 0),
            };
            let mut bytes = match text {
                Some(target) => encoded(target, wide),
                None => encoded("C:", wide),
            };
            bytes.extend(std::iter::repeat_n(0, width));
            let units = (bytes.len() / width) as u64;
            if args[1] == 0 || capacity(args[2]) < units {
                return bad(engine, 122, 0);
            }
            require(engine, args[1], bytes.len() as u64, P::WRITE)?;
            crate::cpu::write(engine, args[1], &bytes)?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(units)
        }
        // The modeled narrow file APIs use the ANSI code page. No call in this
        // profile switches them to the OEM code page.
        Call::ApisAnsi => Ok(1),
        Call::DisableRedirection => {
            // Only a WOW64 process has a redirector to disable, and the x86
            // guest is the modeled WOW64 one.
            if engine.get_data().architecture != Architecture::X86 {
                return bad(engine, 1, 0);
            }
            if !engine.get_data().apis.memory.allows(args[0], 8, P::WRITE) {
                return bad(engine, 87, 0);
            }
            let state = &mut engine.get_data_mut().apis.volumes;
            if state.redirection_cookies.len() >= 32 {
                return bad(engine, 8, 0);
            }
            state.redirection_issued += 1;
            let cookie = 0x5752_0000 | state.redirection_issued;
            state.redirection_cookies.push(cookie);
            crate::cpu::write(engine, args[0], &cookie.to_le_bytes())?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::RevertRedirection => {
            if engine.get_data().architecture != Architecture::X86 {
                return bad(engine, 1, 0);
            }
            // Only a cookie this model handed out and has not yet taken back
            // can be reverted; an invented value cannot re-enable anything.
            let state = &mut engine.get_data_mut().apis.volumes;
            let Some(index) = state
                .redirection_cookies
                .iter()
                .rposition(|live| *live == args[0])
            else {
                return bad(engine, 87, 0);
            };
            state.redirection_cookies.remove(index);
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
    }
}
/// Reduce a directory path to the volume it names, so a path anywhere on the
/// modeled volume is accepted by the free-space and drive-type queries.
fn directory_volume(path: &str) -> &str {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        &path[..2]
    } else {
        path
    }
}
