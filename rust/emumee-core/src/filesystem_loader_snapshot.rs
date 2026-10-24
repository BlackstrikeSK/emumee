//! Immutable snapshot from the same named VFS bytes and backing provenance.
//! This supplies no host file access, handle map or dynamic module ownership.
use super::*;
#[derive(Clone, Debug)]
pub struct LoaderFileSnapshot {
    pub path: String,
    pub bytes: Vec<u8>,
    pub configured_backing: bool,
}
impl VirtualFileSystem {
    pub fn loader_file_snapshot(&self, path: &str) -> Result<Option<LoaderFileSnapshot>> {
        let path = self.path(path)?;
        if self.directories.contains(&path) {
            return Err(error(193, "DLL image source is a guest directory"));
        }
        Ok(self.files.get(&path).map(|bytes| LoaderFileSnapshot {
            configured_backing: self.metadata.native_seeded.contains(&path),
            path,
            bytes: bytes.clone(),
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_uses_actual_bytes_cwd_and_seed_provenance_without_issuing_a_handle() {
        let mut fs = VirtualFileSystem::from_seed(
            123,
            r"C:\Guest",
            &[r"C:\Guest".into()],
            &[SeedFile {
                path: r"C:\Guest\seed.dll",
                bytes: b"SEED",
            }],
        )
        .unwrap();
        let seeded = fs.loader_file_snapshot("seed.dll").unwrap().unwrap();
        assert_eq!(seeded.path, r"c:\guest\seed.dll");
        assert!(seeded.configured_backing);
        assert_eq!(seeded.bytes, b"SEED");
        assert!(fs.loader_file_snapshot("absent.dll").unwrap().is_none());
        assert!(fs.loader_file_snapshot(r"C:\Guest").is_err());
        let (h, _) = fs
            .open(r"C:\Guest\fresh.dll", 0x40000000, 3, 2, 1024)
            .unwrap();
        fs.write(h, 1024, b"OLD").unwrap();
        let snapshot = fs.loader_file_snapshot("fresh.dll").unwrap().unwrap();
        assert!(!snapshot.configured_backing);
        fs.write(h, 1024, b"NEW").unwrap();
        assert_eq!(snapshot.bytes, b"OLD");
        assert_eq!(
            fs.loader_file_snapshot("fresh.dll").unwrap().unwrap().bytes,
            b"OLDNEW"
        );
    }
}
