//! Mutation-only metadata helpers; child of metadata so its display and
//! attribute maps remain the sole metadata authority.
use super::*;
impl MetadataState {
    pub(in crate::filesystem) fn attributes_for(&self, path: &str) -> u32 {
        self.attributes.get(path).copied().unwrap_or(0x80)
    }
    pub(in crate::filesystem) fn set_native_attributes(
        &mut self,
        path: &str,
        requested: u32,
        directory: bool,
    ) {
        let bits = requested & !(0x80 | 0x10);
        self.attributes.insert(
            path.into(),
            if directory {
                bits | 0x10
            } else if bits == 0 {
                0x80
            } else {
                bits
            },
        );
    }
    pub(in crate::filesystem) fn remove_file_name(&mut self, path: &str) {
        self.native_seeded.remove(path);
        self.attributes.remove(path);
        if let Some(display) = self.display.remove(path) {
            self.display_bytes -= display.len();
        }
    }
    pub(in crate::filesystem) fn copy_file_name(
        &mut self,
        path: &str,
        display: String,
        attributes: u32,
    ) {
        self.native_seeded.remove(path); // a guest copy creates ordinary backing
        self.attributes.insert(path.into(), attributes);
        self.record_display(path.into(), display);
    }
    pub(in crate::filesystem) fn require_moved_display(
        &self,
        old: &str,
        new: &str,
        display: &str,
    ) -> Result<()> {
        let retained = self.display_bytes
            - self.display.get(old).map_or(0, String::len)
            - self.display.get(new).map_or(0, String::len);
        if retained
            .checked_add(display.len())
            .is_none_or(|n| n > MAX_DISPLAY_BYTES)
        {
            return Err(error(8, "guest display-name metadata capacity"));
        }
        Ok(())
    }
    pub(in crate::filesystem) fn move_file_name(&mut self, old: &str, new: &str, display: String) {
        let attributes = self.attributes_for(old);
        let seeded = self.native_seeded.contains(old);
        self.remove_file_name(old);
        self.remove_file_name(new);
        self.copy_file_name(new, display, attributes);
        if seeded {
            self.native_seeded.insert(new.into());
        }
    }
}
