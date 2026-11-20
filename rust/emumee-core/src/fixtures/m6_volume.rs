//! M6 volume control family: the one modeled volume's identity, its reported
//! capacity, its single mount path, its DOS device name, the single-entry
//! volume enumeration and the WOW64 redirection cookie round trip. Every
//! answer is persona identity, and the guest checks each one itself.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;
use crate::persona::VolumeConfig;

#[derive(Clone, Copy, Debug)]
pub enum M6VolumeFixture {
    /// Label, serial, component length, capability mask and drive type.
    Identity,
    /// Reported capacity and free space, for any path on the volume.
    Space,
    /// The single-volume enumeration and the volume GUID path.
    Enumerate,
    /// The mount-path multi-string and its required length.
    MountPaths,
    /// The modeled DOS device name and the device enumeration.
    DosDevice,
    /// The WOW64 redirection cookie, which only a WOW64 process has.
    Redirection,
}
/// Case-preserving Unicode names only: the virtual filesystem has no ACLs,
/// compression, sparse files, reparse points, quotas, streams or encryption.
const FILESYSTEM_FLAGS: u32 = 0x6;
const MAX_COMPONENT: u32 = 255;
/// The modeled DOS device target for C:, a model literal.
const DEVICE: &str = r"\Device\HarddiskVolume1";

const INFORMATION: usize = 0;
const DISK_FREE: usize = 1;
const DRIVE_TYPE: usize = 2;
const LOGICAL_DRIVES: usize = 3;
const MOUNT_POINT_NAME: usize = 4;
const PATH_NAMES: usize = 5;
const FIRST_VOLUME: usize = 6;
const NEXT_VOLUME: usize = 7;
const CLOSE_VOLUME: usize = 8;
const DOS_DEVICE: usize = 9;
const APIS_ANSI: usize = 10;
const DISABLE_REDIRECTION: usize = 11;
const REVERT_REDIRECTION: usize = 12;
const LAST_ERROR: usize = 13;

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 1] {
    let s = if unicode { "W" } else { "A" };
    [(
        "kernel32.dll",
        vec![
            format!("GetVolumeInformation{s}"),
            format!("GetDiskFreeSpaceEx{s}"),
            format!("GetDriveType{s}"),
            "GetLogicalDrives".into(),
            format!("GetVolumeNameForVolumeMountPoint{s}"),
            format!("GetVolumePathNamesForVolumeName{s}"),
            format!("FindFirstVolume{s}"),
            format!("FindNextVolume{s}"),
            "FindVolumeClose".into(),
            format!("QueryDosDevice{s}"),
            "AreFileApisANSI".into(),
            "Wow64DisableWow64FsRedirection".into(),
            "Wow64RevertWow64FsRedirection".into(),
            "GetLastError".into(),
        ],
    )]
}

pub fn m6_volume_probe(
    architecture: Architecture,
    kind: M6VolumeFixture,
    unicode: bool,
) -> Vec<u8> {
    use M6VolumeFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let volume = VolumeConfig::default();
    let name = format!(r"\\?\Volume{}\", volume.guid);
    let root = p.string(r"C:\");
    let bare = p.string("C:");
    let elsewhere = p.string(r"D:\");
    let inside = p.string(r"C:\emumee\m6.dat");
    let guid_path = p.string(&name);
    let wrong_guid = p.string(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\");
    let buffer = p.scratch(256);
    let second = p.scratch(256);
    let numbers = p.scratch(64);
    let handle = p.scratch(32);
    match kind {
        K::Identity => {
            p.poison(buffer, 4);
            p.poison(second, 4);
            p.poison(numbers, 6);
            p.call(
                INFORMATION,
                &[
                    V(root),
                    V(buffer),
                    V(64),
                    V(numbers),
                    V(numbers + 4),
                    V(numbers + 8),
                    V(second),
                    V(64),
                ],
            );
            p.eax(1);
            // An unnamed volume is ordinary: the label is empty, and the model
            // writes its terminator rather than leaving the buffer alone.
            p.text(buffer, "");
            p.text(second, &volume.filesystem);
            // One document field decides both the GUID a guest reads and the
            // 32-bit serial number it sees.
            p.dword(numbers, volume.serial());
            p.dword(numbers + 4, MAX_COMPONENT);
            p.dword(numbers + 8, FILESYSTEM_FLAGS);
            p.intact(numbers + 12, 1);
            // Only the volume root answers this query.
            p.call(
                INFORMATION,
                &[V(inside), V(0), V(0), V(numbers), V(0), V(0), V(0), V(0)],
            );
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(3);
            // C: is a fixed drive and no other letter is mounted. A null root
            // means the current directory's drive, which is the same volume.
            p.call(DRIVE_TYPE, &[V(root)]);
            p.eax(3);
            p.call(DRIVE_TYPE, &[V(bare)]);
            p.eax(3);
            p.call(DRIVE_TYPE, &[V(0)]);
            p.eax(3);
            p.call(DRIVE_TYPE, &[V(elsewhere)]);
            p.eax(1);
            p.call(LOGICAL_DRIVES, &[]);
            p.eax(1 << 2);
            // Nothing in this profile switches the narrow file APIs to the OEM
            // code page.
            p.call(APIS_ANSI, &[]);
            p.eax(1);
        }
        K::Space => {
            // Capacity and free space are reported persona figures, not an
            // allocator, and caller-available free space equals total free
            // space because no quota is modeled.
            for path in [root, bare, inside, 0] {
                p.poison(numbers, 8);
                p.call(
                    DISK_FREE,
                    &[V(path), V(numbers), V(numbers + 8), V(numbers + 16)],
                );
                p.eax(1);
                p.qword(numbers, volume.free_bytes);
                p.qword(numbers + 8, volume.capacity_bytes);
                p.qword(numbers + 16, volume.free_bytes);
                p.intact(numbers + 24, 1);
            }
            // A null output is skipped rather than refused.
            p.poison(numbers, 8);
            p.call(DISK_FREE, &[V(root), V(0), V(numbers + 8), V(0)]);
            p.eax(1);
            p.intact(numbers, 2);
            p.qword(numbers + 8, volume.capacity_bytes);
            p.call(
                DISK_FREE,
                &[V(elsewhere), V(numbers), V(numbers + 8), V(numbers + 16)],
            );
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(3);
        }
        K::Enumerate => {
            p.poison(buffer, 32);
            p.call(FIRST_VOLUME, &[V(buffer), V(64)]);
            p.opened();
            p.save(handle);
            p.text(buffer, &name);
            // FindFirstVolume already reported the only modeled volume, so the
            // enumeration ends here.
            p.call(NEXT_VOLUME, &[M(handle), V(second), V(64)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(18);
            p.call(CLOSE_VOLUME, &[M(handle)]);
            p.eax(1);
            // A closed or invented handle belongs to no enumeration.
            p.call(CLOSE_VOLUME, &[M(handle)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
            p.call(NEXT_VOLUME, &[M(handle), V(second), V(64)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(6);
            // The documented contract requires a trailing backslash.
            p.poison(second, 32);
            p.call(MOUNT_POINT_NAME, &[V(root), V(second), V(64)]);
            p.eax(1);
            p.text(second, &name);
            for mount in [bare, 0, elsewhere] {
                p.call(MOUNT_POINT_NAME, &[V(mount), V(second), V(64)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(87);
            }
            // A buffer the GUID path does not fit in is an insufficient one,
            // and nothing is written.
            p.poison(second, 2);
            p.call(MOUNT_POINT_NAME, &[V(root), V(second), V(8)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(122);
            p.intact(second, 2);
        }
        K::MountPaths => {
            // The multi-string holds one mount path and the list terminator, so
            // the required length is the root plus two units.
            let units = 5u64;
            p.poison(numbers, 2);
            p.call(PATH_NAMES, &[V(guid_path), V(0), V(0), V(numbers)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(234);
            p.dword(numbers, units as u32);
            p.intact(numbers + 4, 1);
            p.poison(buffer, 4);
            p.call(
                PATH_NAMES,
                &[V(guid_path), V(buffer), V(units - 1), V(numbers)],
            );
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(234);
            p.intact(buffer, 4);
            p.poison(buffer, 4);
            p.call(
                PATH_NAMES,
                &[V(guid_path), V(buffer), V(units), V(numbers)],
            );
            p.eax(1);
            // "C:\", its own terminator and the multi-string terminator.
            let mut bytes = super::m6::encoded(r"C:\", unicode, true);
            bytes.extend(std::iter::repeat_n(0, if unicode { 2 } else { 1 }));
            p.check(buffer, &bytes, 0x77);
            // A name that is not this volume's is an invalid argument.
            p.call(PATH_NAMES, &[V(wrong_guid), V(buffer), V(64), V(numbers)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
            p.call(PATH_NAMES, &[V(0), V(buffer), V(64), V(numbers)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
        }
        K::DosDevice => {
            // The device name is a model literal, not a host device path, and
            // it is reported as a multi-string: the name, its own terminator
            // and the list terminator.
            let device_units = DEVICE.chars().count() as u32 + 2;
            let mut device = super::m6::encoded(DEVICE, unicode, true);
            device.extend(std::iter::repeat_n(0, if unicode { 2 } else { 1 }));
            p.poison(buffer, 16);
            p.call(DOS_DEVICE, &[V(bare), V(buffer), V(64)]);
            p.eax(device_units);
            p.check(buffer, &device, 0x77);
            p.call(DOS_DEVICE, &[V(root), V(buffer), V(64)]);
            p.eax(device_units);
            // A null device name enumerates every DOS device: exactly one here.
            p.poison(second, 4);
            p.call(DOS_DEVICE, &[V(0), V(second), V(64)]);
            p.eax(4);
            let mut bytes = super::m6::encoded("C:", unicode, true);
            bytes.extend(std::iter::repeat_n(0, if unicode { 2 } else { 1 }));
            p.check(second, &bytes, 0x77);
            // No other drive letter has a device.
            p.call(DOS_DEVICE, &[V(elsewhere), V(buffer), V(64)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(2);
            p.poison(buffer, 2);
            p.call(DOS_DEVICE, &[V(bare), V(buffer), V(4)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(122);
            p.intact(buffer, 2);
        }
        K::Redirection => {
            if p.wide {
                // Only a WOW64 process has a redirector; the x64 guest is not
                // one, so there is nothing to disable or revert.
                p.poison(numbers, 2);
                p.call(DISABLE_REDIRECTION, &[V(numbers)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(1);
                p.intact(numbers, 2);
                p.call(REVERT_REDIRECTION, &[V(0x5752_0001)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(1);
            } else {
                // The virtual filesystem performs no WOW64 path redirection, so
                // the only observable effect is the cookie's own round trip.
                p.poison(numbers, 4);
                p.call(DISABLE_REDIRECTION, &[V(numbers)]);
                p.eax(1);
                p.qword(numbers, 0x5752_0001);
                p.intact(numbers + 8, 1);
                p.call(DISABLE_REDIRECTION, &[V(numbers + 8)]);
                p.eax(1);
                p.qword(numbers + 8, 0x5752_0002);
                // Cookies may be taken back in any order, and only once.
                p.call(REVERT_REDIRECTION, &[V(0x5752_0001)]);
                p.eax(1);
                p.call(REVERT_REDIRECTION, &[V(0x5752_0001)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(87);
                p.call(REVERT_REDIRECTION, &[V(0x5752_0002)]);
                p.eax(1);
                // An invented value cannot re-enable anything.
                for cookie in [0, 0x1234_5678, 0x5752_0003] {
                    p.call(REVERT_REDIRECTION, &[V(cookie)]);
                    p.eax(0);
                    p.call(LAST_ERROR, &[]);
                    p.eax(87);
                }
                // A cookie output the model cannot write is refused before a
                // cookie is issued.
                p.call(DISABLE_REDIRECTION, &[V(0)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(87);
            }
        }
    }
    p.finish()
}
