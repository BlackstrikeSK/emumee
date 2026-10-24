//! Bounded name mutation over the existing guest VFS. The explicit legacy
//! immediate-unlink profile retains open-handle bytes in unnamed backing;
//! this is not Windows delete-pending behavior. No host filesystem access.
use super::*;
#[derive(Clone, Debug, Default)]
pub(super) struct MutationState {
    pub(super) unlinked: BTreeMap<u64, Vec<u8>>,
    pub(super) unlinked_seeded: BTreeSet<u64>,
}
impl VirtualFileSystem {
    pub(super) fn file_bytes(&self, h: &OpenFile) -> &Vec<u8> {
        match h.unlinked {
            Some(id) => &self.mutations.unlinked[&id],
            None => &self.files[&h.path],
        }
    }
    pub(super) fn file_bytes_mut(&mut self, handle: u64) -> &mut Vec<u8> {
        let h = &self.handles[&handle];
        match h.unlinked {
            Some(id) => self.mutations.unlinked.get_mut(&id).unwrap(),
            None => self.files.get_mut(&h.path).unwrap(),
        }
    }
    fn named_handles<'a>(&'a self, path: &'a str) -> impl Iterator<Item = (&'a u64, &'a OpenFile)> {
        self.handles
            .iter()
            .filter(move |(_, h)| h.unlinked.is_none() && h.path == path)
    }
    pub fn handle_path(&self, handle: u64, owner: u64) -> Result<String> {
        let h = self.handle(handle, owner)?;
        if h.unlinked.is_some() {
            return Err(error(5, "unlinked guest backing has no name"));
        }
        Ok(h.path.clone())
    }
    pub(super) fn parent_directory(&self, path: &str) -> Result<()> {
        let parent = path
            .rsplit_once('\\')
            .map(|(p, _)| {
                if p.len() == 2 {
                    format!("{p}\\")
                } else {
                    p.into()
                }
            })
            .ok_or_else(|| error(123, "invalid mutation destination"))?;
        if !self.directories.contains(&parent) {
            return Err(error(3, "mutation parent directory does not exist"));
        }
        Ok(())
    }
    fn mutation_file(&self, path: &str) -> Result<&Vec<u8>> {
        if self.directories.contains(path) {
            return Err(error(
                50,
                "directory copy/move/delete is not modeled by file mutation APIs",
            ));
        }
        self.files
            .get(path)
            .ok_or_else(|| error(2, "mutation source file does not exist"))
    }
    /// Deletes the name immediately, matching the legacy guest bridge. Open
    /// handles retain one shared unnamed object until its last close.
    pub fn delete_file(&mut self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        self.mutation_file(&path)?;
        if self.metadata.attributes_for(&path) & 1 != 0 {
            return Err(error(5, "cannot delete read-only guest file"));
        }
        if self.named_handles(&path).any(|(_, h)| h.share & 4 == 0) {
            return Err(error(32, "delete sharing violation"));
        }
        let id = self.named_handles(&path).next().map(|(id, _)| *id);
        let seeded = self.metadata.native_seeded.contains(&path);
        let data = self.files.remove(&path).unwrap();
        if let Some(id) = id {
            for h in self
                .handles
                .values_mut()
                .filter(|h| h.unlinked.is_none() && h.path == path)
            {
                h.unlinked = Some(id);
            }
            self.mutations.unlinked.insert(id, data);
            if seeded {
                self.mutations.unlinked_seeded.insert(id);
            }
        } else {
            self.total -= data.len();
        }
        self.metadata.remove_file_name(&path);
        Ok(())
    }
    /// Copies bytes into the existing destination backing when it is open;
    /// each existing cursor and access grant remains unchanged.
    pub fn copy_file(
        &mut self,
        source: &str,
        destination: &str,
        fail_if_exists: bool,
    ) -> Result<()> {
        let old = self.path(source)?;
        let new = self.path(destination)?;
        let display = self.normalize_path(destination, false, false)?;
        if old == new {
            return Err(error(32, "copy source equals destination"));
        }
        let data = self.mutation_file(&old)?;
        if self.directories.contains(&new) {
            return Err(error(5, "copy destination is a directory"));
        }
        self.parent_directory(&new)?;
        if self.named_handles(&old).any(|(_, h)| h.share & 1 == 0) {
            return Err(error(32, "copy source sharing violation"));
        }
        let target = self.files.get(&new);
        if target.is_some() && self.metadata.attributes_for(&new) & 3 != 0 {
            return Err(error(5, "copy destination is hidden or read-only"));
        }
        if fail_if_exists && target.is_some() {
            return Err(error(80, "copy destination already exists"));
        }
        if self.named_handles(&new).any(|(_, h)| h.share & 2 == 0) {
            return Err(error(32, "copy destination sharing violation"));
        }
        if target.is_none() && self.files.len() >= 4096 {
            return Err(error(4, "file name limit"));
        }
        let total = self.total - target.map_or(0, Vec::len);
        let total = total
            .checked_add(data.len())
            .filter(|n| *n <= MAX_TOTAL)
            .ok_or_else(|| error(8, "guest filesystem capacity"))?;
        self.metadata.require_display(&new, &display)?;
        let attributes = self.metadata.attributes_for(&old);
        let data = data.clone(); // all fallible checks precede publication
        self.files.insert(new.clone(), data);
        self.total = total;
        self.metadata.copy_file_name(&new, display, attributes);
        Ok(())
    }
    /// Same-volume file-only rename. Flags support REPLACE_EXISTING and
    /// WRITE_THROUGH (in-memory commit is immediate); other profiles stop.
    pub fn move_file(&mut self, source: &str, destination: &str, flags: u32) -> Result<()> {
        self.rename_file(source, destination, flags, None)
    }
    pub fn rename_file_handle(
        &mut self,
        handle: u64,
        owner: u64,
        destination: &str,
        replace: bool,
    ) -> Result<()> {
        let h = self.handle(handle, owner)?;
        if !h.access.delete {
            return Err(error(5, "rename requires DELETE access"));
        }
        if h.unlinked.is_some() {
            return Err(error(5, "cannot rename unlinked guest backing"));
        }
        let source = h.path.clone();
        self.rename_file(&source, destination, u32::from(replace), Some(handle))
    }
    fn rename_file(
        &mut self,
        source: &str,
        destination: &str,
        flags: u32,
        calling_handle: Option<u64>,
    ) -> Result<()> {
        if flags & !9 != 0 {
            return Err(error(
                50,
                "MoveFileEx flags outside same-volume file profile",
            ));
        }
        let old = self.path(source)?;
        let new = self.path(destination)?;
        let display = self.normalize_path(destination, false, false)?;
        if old[..2] != new[..2] {
            return Err(error(50, "cross-volume file mutation is not modeled"));
        }
        self.mutation_file(&old)?;
        self.parent_directory(&new)?;
        if self.directories.contains(&new) {
            return Err(error(183, "move destination is a directory"));
        }
        if self
            .named_handles(&old)
            .any(|(id, h)| Some(*id) != calling_handle && h.share & 4 == 0)
        {
            return Err(error(32, "move source sharing violation"));
        }
        if old == new {
            return Ok(());
        } // preserve first catalog spelling on case-only no-op
        let target = self.files.get(&new);
        if target.is_some() {
            if flags & 1 == 0 {
                return Err(error(183, "move destination already exists"));
            }
            if self.metadata.attributes_for(&new) & 1 != 0 {
                return Err(error(5, "move destination is read-only"));
            }
            if self.named_handles(&new).next().is_some() {
                return Err(error(5, "move replacement destination is open"));
            }
        }
        self.metadata.require_moved_display(&old, &new, &display)?;
        let replaced = self.files.remove(&new).map_or(0, |v| v.len());
        let data = self.files.remove(&old).unwrap();
        self.files.insert(new.clone(), data);
        self.total -= replaced;
        for h in self
            .handles
            .values_mut()
            .filter(|h| h.unlinked.is_none() && h.path == old)
        {
            h.path = new.clone();
        }
        self.metadata.move_file_name(&old, &new, display);
        Ok(())
    }
    pub fn storage_report(&self) -> StorageReport {
        StorageReport {named_files:self.files.len(),named_bytes:self.files.values().map(Vec::len).sum(),unlinked_objects:self.mutations.unlinked.len(),unlinked_bytes:self.mutations.unlinked.values().map(Vec::len).sum(),accounted_bytes:self.total,open_handles:self.handles.len(),scope:"legacy immediate unlink; unnamed backing retained until last handle close; same-volume file-only mutation; no mappings/links/host files".into()}
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct StorageReport {
    pub named_files: usize,
    pub named_bytes: usize,
    pub unlinked_objects: usize,
    pub unlinked_bytes: usize,
    pub accounted_bytes: usize,
    pub open_handles: usize,
    pub scope: String,
}
#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: u64 = 1024;
    fn file(fs: &mut VirtualFileSystem, name: &str, data: &[u8], share: u32) -> u64 {
        let (h, _) = fs.open(name, 0xc0010000, share, 2, OWNER).unwrap();
        fs.write(h, OWNER, data).unwrap();
        fs.seek(h, OWNER, 0, 0).unwrap();
        h
    }
    #[test]
    fn unlink_retains_shared_backing_recreation_is_independent_and_last_close_reclaims_bytes() {
        let mut fs = VirtualFileSystem::new();
        let a = file(&mut fs, "First.bin", b"FIRST", 7);
        let (b, _) = fs.open("first.bin", 0xc0000000, 7, 3, OWNER).unwrap();
        fs.delete_file("FIRST.bin").unwrap();
        assert!(!fs.exists("first.bin").unwrap());
        assert_eq!(fs.storage_report().unlinked_bytes, 5);
        let replacement = file(&mut fs, "first.bin", b"NEW", 7);
        assert_eq!(fs.storage_report().accounted_bytes, 8);
        assert_eq!(fs.read(a, OWNER, 2).unwrap(), b"FI");
        fs.write(b, OWNER, b"OLD").unwrap();
        assert_eq!(fs.read(a, OWNER, 10).unwrap(), b"DST");
        assert_eq!(fs.contents("first.bin").unwrap().unwrap(), b"NEW");
        fs.close(a, OWNER).unwrap();
        assert_eq!(fs.storage_report().unlinked_bytes, 5);
        fs.close(b, OWNER).unwrap();
        assert_eq!(fs.storage_report().unlinked_bytes, 0);
        assert_eq!(fs.storage_report().accounted_bytes, 3);
        fs.close(replacement, OWNER).unwrap();
    }
    #[test]
    fn copy_overwrite_keeps_cursor_and_first_display_and_snapshots_source_metadata() {
        let mut fs = VirtualFileSystem::new();
        let src = file(&mut fs, "Source.bin", b"ABCDE", 7);
        let dst = file(&mut fs, "Target.bin", b"target", 7);
        fs.seek(dst, OWNER, 2, 0).unwrap();
        fs.set_attributes("source.bin", 2).unwrap();
        fs.copy_file("source.bin", "TARGET.BIN", false).unwrap();
        assert_eq!(fs.read(dst, OWNER, 10).unwrap(), b"CDE");
        assert_eq!(fs.metadata("target.bin").unwrap().attributes, 2);
        fs.set_attributes("source.bin", 4).unwrap();
        assert_eq!(fs.metadata("target.bin").unwrap().attributes, 2);
        assert_eq!(fs.enumerate("target.*").unwrap()[0].name, "Target.bin");
        assert_eq!(
            fs.copy_file("source.bin", "SOURCE.BIN", false)
                .unwrap_err()
                .win32,
            32
        );
        fs.close(src, OWNER).unwrap();
    }
    #[test]
    fn failed_copy_move_delete_are_atomic_and_replaced_moves_rewire_open_source() {
        let mut fs = VirtualFileSystem::new();
        let src = file(&mut fs, "Source.bin", b"SOURCE", 3);
        let dst = file(&mut fs, "Target.bin", b"TARGET", 7);
        assert_eq!(fs.delete_file("source.bin").unwrap_err().win32, 32);
        assert_eq!(
            fs.move_file("source.bin", "target.bin", 1)
                .unwrap_err()
                .win32,
            32
        );
        fs.close(src, OWNER).unwrap();
        let (src, _) = fs.open("source.bin", 0xc0010000, 7, 3, OWNER).unwrap();
        assert_eq!(
            fs.copy_file("source.bin", "target.bin", true)
                .unwrap_err()
                .win32,
            80
        );
        assert_eq!(
            fs.move_file("source.bin", "target.bin", 1)
                .unwrap_err()
                .win32,
            5
        );
        fs.close(dst, OWNER).unwrap();
        fs.set_attributes("target.bin", 1).unwrap();
        assert_eq!(
            fs.move_file("source.bin", "target.bin", 1)
                .unwrap_err()
                .win32,
            5
        );
        assert_eq!(fs.contents("source.bin").unwrap().unwrap(), b"SOURCE");
        assert_eq!(fs.contents("target.bin").unwrap().unwrap(), b"TARGET");
        fs.set_attributes("target.bin", 0x80).unwrap();
        fs.move_file("source.bin", "NewName.bin", 0).unwrap();
        assert_eq!(fs.read(src, OWNER, 20).unwrap(), b"SOURCE");
        fs.seek(src, OWNER, 0, 0).unwrap();
        fs.write(src, OWNER, b"new").unwrap();
        assert_eq!(fs.contents("NewName.bin").unwrap().unwrap(), b"newRCE");
        fs.move_file("NewName.bin", "NEWNAME.BIN", 0).unwrap();
        assert_eq!(fs.enumerate("newname.*").unwrap()[0].name, "NewName.bin");
    }
    #[test]
    fn rename_handle_delete_right_ownership_and_other_handles_sharing_are_real() {
        let mut fs = VirtualFileSystem::new();
        let (h, _) = fs.open("a", 0xc0000000, 7, 2, OWNER).unwrap();
        assert_eq!(
            fs.rename_file_handle(h, OWNER, "b", false)
                .unwrap_err()
                .win32,
            5
        );
        fs.close(h, OWNER).unwrap();
        let (h, _) = fs.open("a", 0x10000, 3, 3, OWNER).unwrap();
        assert_eq!(
            fs.rename_file_handle(h, 2048, "b", false)
                .unwrap_err()
                .win32,
            6
        );
        fs.rename_file_handle(h, OWNER, "b", false).unwrap();
        assert!(fs.exists("b").unwrap());
    }
    #[test]
    fn full_width_file_tokens_do_not_alias_low_dword_handles() {
        let mut fs = VirtualFileSystem::new();
        fs.next_handle = 0x1_0000_0100;
        let h = file(&mut fs, "Wide.bin", b"WIDE", 7);
        assert_eq!(h, 0x1_0000_0100);
        assert_eq!(
            fs.rename_file_handle(0x100, OWNER, "bad", false)
                .unwrap_err()
                .win32,
            6
        );
        fs.rename_file_handle(h, OWNER, "Renamed.bin", false)
            .unwrap();
        assert_eq!(fs.read(h, OWNER, 4).unwrap(), b"WIDE");
        fs.delete_file("Renamed.bin").unwrap();
        fs.close(h, OWNER).unwrap();
        assert_eq!(fs.storage_report().accounted_bytes, 0);
    }
    #[test]
    fn copy_and_move_failure_boundaries_do_not_change_contents_metadata_or_handles() {
        let mut fs = VirtualFileSystem::new();
        let source = file(&mut fs, "Keep.bin", b"KEEP", 7);
        let before = fs.enumerate("keep.*").unwrap();
        fs.total = MAX_TOTAL;
        assert_eq!(
            fs.copy_file("keep.bin", "Other.bin", false)
                .unwrap_err()
                .win32,
            8
        );
        assert!(!fs.exists("Other.bin").unwrap());
        assert_eq!(fs.contents("keep.bin").unwrap().unwrap(), b"KEEP");
        fs.total = 4;
        fs.move_file("keep.bin", "Moved.bin", 0).unwrap();
        fs.delete_file("Moved.bin").unwrap();
        assert_eq!(before[0].name, "Keep.bin");
        assert_eq!(before[0].metadata.size, 4);
        assert_eq!(before[0].metadata.attributes, 0x80);
        assert_eq!(fs.read(source, OWNER, 4).unwrap(), b"KEEP");
        fs.close(source, OWNER).unwrap();
        assert_eq!(fs.storage_report().accounted_bytes, 0);
    }
    #[test]
    fn unsupported_mutations_and_missing_parent_do_not_publish_any_state() {
        let mut fs = VirtualFileSystem::new();
        let h = file(&mut fs, "a", b"A", 7);
        for (target, flags, code) in [("D:\\a", 0, 50), ("no\\a", 0, 3), ("b", 4, 50)] {
            assert_eq!(fs.move_file("a", target, flags).unwrap_err().win32, code);
            assert_eq!(fs.contents("a").unwrap().unwrap(), b"A");
        }
        fs.set_attributes("a", 1).unwrap();
        assert_eq!(fs.delete_file("a").unwrap_err().win32, 5);
        fs.close(h, OWNER).unwrap();
        assert_eq!(fs.storage_report().accounted_bytes, 1);
    }
}
