//! Shared guest time pages and APIs use the same deterministic clock as RDTSC.
use super::*;
const USER: u64 = 0x7ffe0000;
#[repr(align(4096))]
pub(crate) struct SharedPage([u8; 4096]);
pub(crate) fn page(engine: &Unicorn<Trace>) -> [u8; 4096] {
    let mut page = engine.get_data().clock.shared_data_page();
    let profile = &engine.get_data().cpu.profile;
    page[0x2c..0x30].copy_from_slice(&[0x64, 0x86, 0x64, 0x86]);
    for (index, value) in "C:\\Windows".encode_utf16().enumerate() {
        page[0x30 + index * 2..0x32 + index * 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (0x260, engine.get_data().machine.windows_build()),
        (0x264, 1),
        (0x26c, 10),
        (0x270, 0),
        (0x2e8, engine.get_data().machine.physical_pages()),
        (0x3c0, profile.cores * profile.threads_per_core),
    ] {
        page[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    page[0x268..0x26c].copy_from_slice(&[1, 0, 9, 0]);
    // Same boot authority as nt!KdDebuggerEnabled. No debugger is attached,
    // so the shared debugger-active bit stays clear.
    page[0x2d4] = u8::from(engine.get_data().machine.boot_debug());
    for feature in [
        2, 3, 6, 8, 9, 10, 12, 13, 14, 17, 20, 21, 22, 23, 28, 32, 36, 37, 38, 39, 40, 42,
    ] {
        page[0x274 + feature] = 1;
    }
    page[0x3c4] = 1;
    page
}
pub(crate) fn sync(engine: &mut Unicorn<Trace>) -> Result<()> {
    engine.get_data_mut().clock.flush_cycles()?;
    let page = page(engine);
    engine
        .get_data_mut()
        .clock_page
        .as_mut()
        .ok_or_else(|| anyhow!("Shared clock is not initialized"))?
        .0 = page;
    engine.get_data_mut().clock.mark_synced();
    Ok(())
}
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().clock_page.is_none(),
        "Shared clock already initialized"
    );
    let mut backing = Box::new(SharedPage(page(engine)));
    let pointer = backing.0.as_mut_ptr().cast();
    engine.get_data_mut().clock_page = Some(backing);
    let aliases = if engine.get_data().architecture == Architecture::X64 {
        [USER, 0xfffff78000000000, 0x000ff78000000000]
    } else {
        [USER, 0xffdf0000, 0]
    };
    for base in aliases.into_iter().filter(|base| *base != 0) {
        // SAFETY: all aliases point at the same4096-byte aligned allocation.
        // The Box stays at one address in Trace and is never replaced/unmapped.
        // UnicornInner::drop calls uc_close before dropping Trace; native guest
        // memory access is single-threaded and the pages are READ-only. Updates
        // happen only while guest execution is paused in its code/API hook.
        uc(unsafe { engine.mem_map_ptr(base, 4096, Prot::READ, pointer) })?;
        engine.get_data_mut().apis.memory.map(
            base,
            4096,
            Permissions::READ,
            None,
            "shared guest clock/persona",
        )?;
    }
    engine.get_data_mut().clock_aliases = aliases;
    sync(engine)
}
