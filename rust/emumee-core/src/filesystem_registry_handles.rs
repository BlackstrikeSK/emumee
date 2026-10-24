//! Collision guards use the actual VFS allocator and preserve failed-open atomicity.
use super::*;
#[test]
fn ordinary_files_skip_live_retired_and_truncated_typed_handle_namespaces() {
    let high = 0xffffffff00000000;
    for start in [
        crate::registry::USER_HANDLE_FIRST,
        crate::registry::NATIVE_HANDLE_FIRST,
        high | crate::registry::NATIVE_HANDLE_FIRST,
        0x80000008,
        high | 0x80000008,
    ] {
        let mut files = VirtualFileSystem::new();
        files.next_handle = start;
        let (handle, _) = files
            .open(r"C:\workspace\MiXeD.bin", 0xc0000000, 7, 1, 4)
            .unwrap();
        assert_ne!(start, handle);
        assert!(crate::registry::reserved_file_handle_next(handle).is_none());
        assert!(files.owns_handle(handle));
        files.close(handle, 4).unwrap();
        assert!(!files.owns_handle(handle));
        let (next, _) = files
            .open(r"C:\workspace\MiXeD.bin", 0x80000000, 7, 3, 4)
            .unwrap();
        assert_eq!(next, handle + 4);
    }
}
