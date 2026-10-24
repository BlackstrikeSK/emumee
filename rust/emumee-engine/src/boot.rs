//! Initial DriverEntry arguments; object-manager and loader-list parity is separate.
use super::*;
use emumee_core::kernel_layout::KernelLayout;
#[derive(Debug, Serialize)]
pub struct KernelEntry {
    pub layout: KernelLayout,
    pub entry_stack_size: u64,
    pub driver_object_size: u16,
    pub registry_name: String,
    pub scope: &'static str,
}
fn pointer(data: &mut [u8], offset: usize, value: u64, width: usize) {
    data[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn unicode(engine: &mut Unicorn<Trace>, descriptor: u64, buffer: u64, text: &str) -> Result<()> {
    let mut bytes: Vec<_> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    ensure!(
        bytes.len() < 4000,
        "Initial kernel string exceeds backing page"
    );
    let length = bytes.len() as u16;
    bytes.extend([0, 0]);
    let width = engine.get_data().architecture.width();
    let size = if width == 8 { 16 } else { 8 };
    let mut header = [0; 16];
    header[..2].copy_from_slice(&length.to_le_bytes());
    header[2..4].copy_from_slice(&(length + 2).to_le_bytes());
    pointer(&mut header, if width == 8 { 8 } else { 4 }, buffer, width);
    cpu::write(engine, buffer, &bytes)?;
    cpu::write(engine, descriptor, &header[..size])
}
pub(crate) fn initialize(
    engine: &mut Unicorn<Trace>,
    pe: &PeImage,
    layout: KernelLayout,
    driver_section: Option<u64>,
) -> Result<KernelEntry> {
    initialize_named(engine, pe, layout, "EmumeeFixture", driver_section)
}

pub(crate) fn initialize_named(
    engine: &mut Unicorn<Trace>,
    pe: &PeImage,
    layout: KernelLayout,
    service_name: &str,
    driver_section: Option<u64>,
) -> Result<KernelEntry> {
    ensure!(
        emumee_core::driver_input::service_name_valid(service_name),
        "Driver service name outside bounded profile"
    );
    let width = engine.get_data().architecture.width();
    let size = if width == 8 { 0x150 } else { 0xa8 };
    let mut driver = [0u8; 0x150];
    driver[..2].copy_from_slice(&4u16.to_le_bytes());
    driver[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    pointer(
        &mut driver,
        if width == 8 { 24 } else { 12 },
        pe.image_base,
        width,
    );
    let size_offset = if width == 8 { 32 } else { 16 };
    driver[size_offset..size_offset + 4].copy_from_slice(&pe.image_size.to_le_bytes());
    if let Some(section) = driver_section {
        pointer(
            &mut driver,
            if width == 8 { 40 } else { 20 },
            section,
            width,
        );
    }
    pointer(
        &mut driver,
        if width == 8 { 88 } else { 44 },
        pe.image_base + pe.entry_rva as u64,
        width,
    );
    cpu::write(engine, layout.driver_object, &driver[..size])?;
    unicode(
        engine,
        layout.driver_object + if width == 8 { 56 } else { 28 },
        layout.driver_object + 512,
        &format!(r"\Driver\{service_name}"),
    )?;
    let registry = format!(r"\Registry\Machine\System\CurrentControlSet\Services\{service_name}");
    unicode(
        engine,
        layout.registry_path,
        layout.registry_path + 32,
        &registry,
    )?;
    Ok(KernelEntry {
        layout,
        entry_stack_size: STACK_SIZE,
        driver_object_size: size as u16,
        registry_name: registry,
        scope: "Initial DriverEntry header/name/start/size/init and registry UNICODE_STRING; opaque thread identities. DriverSection may point to the separately reported owned initial x64 loader snapshot. Full object manager, dynamic loader lifecycle, extensions, devices and callback defaults remain pending.",
    })
}
