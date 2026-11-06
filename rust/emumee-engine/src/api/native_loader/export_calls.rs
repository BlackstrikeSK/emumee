use super::*;

#[derive(Clone, Debug, Serialize)]
pub struct ExportEntry {
    pub ordinal: u32,
    pub names: Vec<String>,
    pub address: u64,
    pub arguments: Vec<u64>,
    pub started_instructions: u64,
    pub stopped_instructions: u64,
    pub returned_value: Option<u64>,
    pub error: Option<String>,
}

pub(crate) fn execute_exports(
    engine: &mut Unicorn<Trace>,
    root: &PeImage,
    stack_top: u64,
    horizon: &ExecutionHorizon,
    primary: Outcome,
) -> Result<Outcome> {
    let exports = root
        .export_calls()
        .iter()
        .take(10)
        .filter(|export| export.name.as_deref() != Some("DllMain"))
        .cloned()
        .collect::<Vec<_>>();
    if exports.is_empty() {
        return Ok(primary);
    }
    let arguments = super::super::allocation::allocate(engine, &[0, 0x4000, 0x3000, 4])?;
    ensure!(arguments != 0, "Export argument allocation failed");
    for export in exports {
        let address = root.image_base + u64::from(export.rva);
        let mut args = vec![
            arguments,
            arguments + 0x1000,
            arguments + 0x2000,
            arguments + 0x3000,
        ];
        if let Some(name) = export
            .name
            .as_deref()
            .filter(|name| name.starts_with("ServiceMain"))
        {
            let width = engine.get_data().architecture.width();
            let service = super::super::allocation::allocate(engine, &[0, 4096, 0x3000, 4])?;
            ensure!(service != 0, "ServiceMain argument allocation failed");
            crate::cpu::write(
                engine,
                service,
                &(service + 2 * width as u64).to_le_bytes()[..width],
            )?;
            let name_bytes = if name.ends_with('A') {
                b"IPRIP\0".to_vec()
            } else {
                "IPRIP\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect()
            };
            crate::cpu::write(engine, service + 2 * width as u64, &name_bytes)?;
            args = vec![1, service];
        }
        let started = engine.get_data().instructions;
        let result = invoke_export(engine, address, &args, stack_top, horizon);
        let outcome = result.unwrap_or_else(|error| failure(format!("{error:#}")));
        let stopped = engine.get_data().instructions;
        engine.get_data_mut().export_entries.push(ExportEntry {
            ordinal: export.ordinal,
            names: export.name.into_iter().collect(),
            address,
            arguments: args,
            started_instructions: started,
            stopped_instructions: stopped,
            returned_value: outcome.value,
            error: outcome.error.clone(),
        });
        if !outcome.returned {
            return Ok(outcome);
        }
    }
    Ok(primary)
}

fn invoke_export(
    engine: &mut Unicorn<Trace>,
    address: u64,
    args: &[u64],
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    require(engine, address, 1, P::EXECUTE)?;
    let arch = engine.get_data().architecture;
    let width = arch.width();
    let marker = engine.get_data().return_marker + 0x700;
    require(engine, marker, 1, P::EXECUTE)?;
    let sp = (stack_top & !15) - if arch == Architecture::X64 { 40 } else { 32 };
    let mut frame = vec![0u8; 40];
    frame[..width].copy_from_slice(&marker.to_le_bytes()[..width]);
    if arch == Architecture::X86 {
        for (index, argument) in args.iter().enumerate() {
            ensure!(
                *argument <= u32::MAX as u64,
                "Export argument pointer exceeds x86 width"
            );
            frame[(index + 1) * 4..(index + 2) * 4]
                .copy_from_slice(&(*argument as u32).to_le_bytes());
        }
    }
    require(engine, sp, frame.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, sp, &frame)?;
    uc(engine.reg_write(
        if arch == Architecture::X64 {
            RegisterX86::RSP
        } else {
            RegisterX86::ESP
        },
        sp,
    ))?;
    if arch == Architecture::X64 {
        for (register, argument) in [
            RegisterX86::RCX,
            RegisterX86::RDX,
            RegisterX86::R8,
            RegisterX86::R9,
        ]
        .into_iter()
        .zip(args)
        {
            uc(engine.reg_write(register, *argument))?;
        }
    }
    crate::threads::execute_horizon(engine, address, marker, horizon)
}
