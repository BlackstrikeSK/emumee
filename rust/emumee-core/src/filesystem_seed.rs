//! Production preset import into the same actual guest VFS authority.
use super::*;
pub struct SeedFile<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}
impl VirtualFileSystem {
    pub fn from_seed(
        filetime: u64,
        current_directory: &str,
        directories: &[String],
        files: &[SeedFile<'_>],
    ) -> Result<Self> {
        if directories.len() > 4096 || files.len() > 4096 {
            return Err(error(8, "configured VFS seed collection bound"));
        }
        // new() remains the unchanged fixture constructor. This separate candidate
        // removes its fixture-only directory before any configured seeds publish.
        let mut fs = Self::with_filetime(filetime);
        fs.current_directory = r"C:\".into();
        fs.directories = BTreeSet::from([r"c:\".into()]);
        fs.metadata.remove_file_name(r"c:\workspace");
        for directory in directories {
            let path = fs.path(directory)?;
            let display = fs.normalize_path(directory, false, false)?;
            if fs.directories.contains(&path) {
                continue;
            }
            let parent = path
                .rsplit_once('\\')
                .map(|(p, _)| {
                    if p.len() == 2 {
                        format!("{p}\\")
                    } else {
                        p.into()
                    }
                })
                .ok_or_else(|| error(123, "invalid seed directory"))?;
            // An explicitly declared DOS volume root has no distinct parent.
            // Child directories and files still require prior declared parents;
            // seeing a non-C path alone never creates another drive root.
            let root =
                matches!(path.as_bytes(), [drive, b':', b'\\'] if drive.is_ascii_alphabetic());
            if !root && !fs.directories.contains(&parent) {
                return Err(error(
                    3,
                    "configured seed directory parent absent or out of order",
                ));
            }
            fs.metadata.require_display(&path, &display)?;
            fs.metadata.record_display(path.clone(), display);
            fs.directories.insert(path);
        }
        for file in files {
            let path = fs.path(file.path)?;
            let display = fs.normalize_path(file.path, false, false)?;
            if fs.directories.contains(&path) || fs.files.contains_key(&path) {
                return Err(error(
                    183,
                    "configured file conflicts with existing seed name",
                ));
            }
            let parent = path
                .rsplit_once('\\')
                .map(|(p, _)| {
                    if p.len() == 2 {
                        format!("{p}\\")
                    } else {
                        p.into()
                    }
                })
                .ok_or_else(|| error(123, "invalid seed file"))?;
            if !fs.directories.contains(&parent) {
                return Err(error(3, "configured file parent absent"));
            }
            if file.bytes.len() > MAX_FILE
                || fs
                    .total
                    .checked_add(file.bytes.len())
                    .is_none_or(|n| n > MAX_TOTAL)
            {
                return Err(error(8, "configured file seed capacity"));
            }
            fs.metadata.require_display(&path, &display)?;
            fs.metadata.record_display(path.clone(), display);
            fs.total += file.bytes.len();
            fs.metadata.native_seeded.insert(path.clone());
            fs.files.insert(path, file.bytes.to_vec());
        }
        let directory = fs.directory_plan(current_directory)?;
        fs.commit_directory(directory)?;
        Ok(fs)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_import_has_no_fixture_path_or_issued_handles_and_keeps_case_and_preset_lifetime()
    {
        let fs = VirtualFileSystem::from_seed(
            123,
            r"C:\Users\Morgan",
            &[r"C:\Users".into(), r"C:\Users\Morgan".into()],
            &[SeedFile {
                path: r"C:\Users\Morgan\FiRsT.txt",
                bytes: b"CONFIGURED",
            }],
        )
        .unwrap();
        assert!(!fs.directories.contains(r"c:\workspace"));
        assert_eq!(fs.current_directory(), r"C:\Users\Morgan");
        assert!(fs.handles.is_empty());
        assert_eq!(fs.next_handle, 0x100);
        assert_eq!(fs.enumerate("*.*").unwrap()[0].name, "FiRsT.txt");
        assert_eq!(fs.metadata("FiRsT.txt").unwrap().times, [123; 3]);
        assert!(
            VirtualFileSystem::new()
                .directories
                .contains(r"c:\workspace")
        );
        let mut fs = fs;
        assert_eq!(fs.remove_directory(r"C:\Users").unwrap_err().win32, 50);
    }
    #[test]
    fn failed_seed_candidate_cannot_modify_existing_authority_or_issue_handles() {
        let old = VirtualFileSystem::new();
        assert!(VirtualFileSystem::from_seed(123, r"C:\missing", &[], &[]).is_err());
        assert!(old.directories.contains(r"c:\workspace"));
        assert!(old.handles.is_empty());
        assert!(
            VirtualFileSystem::from_seed(
                123,
                r"C:\",
                &[],
                &[
                    SeedFile {
                        path: r"C:\same",
                        bytes: b"A"
                    },
                    SeedFile {
                        path: r"C:\SAME",
                        bytes: b"B"
                    }
                ]
            )
            .is_err()
        );
    }
    #[test]
    fn explicit_non_c_drive_roots_seed_real_directories_files_and_cwd_on_one_vfs() {
        let fs = VirtualFileSystem::from_seed(
            123,
            r"D:\Guest",
            &[
                r"D:\".into(),
                r"D:\Guest".into(),
                r"d:\".into(),
                r"E:\".into(),
            ],
            &[
                SeedFile {
                    path: r"D:\Guest\Data.bin",
                    bytes: b"D-GUEST",
                },
                SeedFile {
                    path: r"E:\Other.bin",
                    bytes: b"E-GUEST",
                },
            ],
        )
        .unwrap();
        assert_eq!(fs.current_directory(), r"D:\Guest");
        for root in [r"C:\", r"D:\", r"e:\"] {
            assert_eq!(fs.metadata(root).unwrap().attributes, 0x10);
            assert_eq!(fs.metadata(root).unwrap().times, [123; 3]);
        }
        assert_eq!(fs.contents("data.bin").unwrap().unwrap(), b"D-GUEST");
        assert_eq!(fs.contents(r"e:\OTHER.bin").unwrap().unwrap(), b"E-GUEST");
        assert_eq!(fs.enumerate("*.bin").unwrap()[0].name, "Data.bin");
        assert!(fs.metadata(r"C:\workspace").is_err());
        assert!(fs.metadata(r"F:\").is_err());
        assert!(fs.handles.is_empty());
        assert_eq!(fs.next_handle, 0x100);
        assert_eq!(fs.total, 14);
        assert!(fs.metadata.native_seeded.contains(r"d:\guest\data.bin"));
        assert!(fs.metadata.native_seeded.contains(r"e:\other.bin"));
    }
    #[test]
    fn undeclared_drives_and_out_of_order_children_are_not_invented() {
        assert_eq!(
            VirtualFileSystem::from_seed(0, r"D:\", &[], &[])
                .err()
                .unwrap()
                .win32,
            3
        );
        assert_eq!(
            VirtualFileSystem::from_seed(0, r"C:\", &[r"D:\Child".into(), r"D:\".into()], &[])
                .err()
                .unwrap()
                .win32,
            3
        );
        assert_eq!(
            VirtualFileSystem::from_seed(
                0,
                r"C:\",
                &[],
                &[SeedFile {
                    path: r"D:\Data.bin",
                    bytes: b"X"
                }]
            )
            .err()
            .unwrap()
            .win32,
            3
        );
        assert!(VirtualFileSystem::from_seed(0, r"C:\", &[r"\\server\share".into()], &[]).is_err());
        let mut old = VirtualFileSystem::new();
        let handle = old.open("keep", 0xc0000000, 7, 2, 1024).unwrap().0;
        old.write(handle, 1024, b"UNCHANGED").unwrap();
        assert!(VirtualFileSystem::from_seed(0, r"E:\", &[r"D:\".into()], &[]).is_err());
        assert_eq!(old.contents("keep").unwrap().unwrap(), b"UNCHANGED");
        assert_eq!(old.handles.len(), 1);
        assert!(old.metadata(r"D:\").is_err());
    }
}
