//! One process-owned mutable MSVCRT command-line cell shared by data imports,
//! PE export walks, GetProcAddress and __p__acmdln. No callable data trampoline.
use super::*;
use emumee_core::{modules::Resolution, provider::DataExport};

pub(crate) fn data_exports(engine: &Unicorn<Trace>, module: &str) -> Result<Vec<DataExport>> {
    if module != "msvcrt.dll" {
        return Ok(Vec::new());
    }
    let state = &engine.get_data().apis.crt_startup;
    ensure!(
        state.initialized,
        "CRT data requires initialized user process"
    );
    let width = engine.get_data().architecture.width();
    let size = state
        .argv
        .iter()
        .enumerate()
        .try_fold(width + 1, |total, (index, arg)| {
            total
                .checked_add(arg.len())
                .and_then(|n| n.checked_add(usize::from(index != 0)))
                .filter(|n| *n <= MAX_BYTES)
                .context("CRT command-line bytes exceed bound")
        })?;
    let mut bytes = vec![0; width];
    bytes.reserve(size - width);
    for (index, arg) in state.argv.iter().enumerate() {
        if index != 0 {
            bytes.push(b' ');
        }
        bytes.extend_from_slice(arg.as_bytes());
    }
    bytes.push(0);
    Ok(vec![DataExport {
        name: "_acmdln",
        bytes,
        alignment: width,
    }])
}

pub(crate) fn publish(
    engine: &mut Unicorn<Trace>,
    module: &str,
    data: &[DataExport],
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    ensure!(
        module == "msvcrt.dll" && data.len() == 1 && data[0].name == "_acmdln",
        "Unexpected CRT data publication"
    );
    ensure!(
        engine.get_data().apis.crt_startup.command_line.is_none(),
        "CRT command-line cell already published"
    );
    let Resolution::Found { address, .. } = engine
        .get_data()
        .apis
        .modules
        .resolve(module, &ImportName::Name("_acmdln".into()))?
    else {
        bail!("CRT command-line data export is missing");
    };
    let size = data[0].bytes.len() as u64;
    require(engine, address, size, P::RW)?;
    ensure!(
        address % 4096 == 0
            && !engine
                .get_data()
                .apis
                .memory
                .allows(address, size, P::EXECUTE),
        "CRT command-line storage must be page-aligned RW/NX"
    );
    ensure!(
        read(engine, address, size)? == data[0].bytes,
        "CRT command-line initial bytes differ from baseline"
    );
    let width = engine.get_data().architecture.width();
    crate::cpu::write(
        engine,
        address,
        &(address + width as u64).to_le_bytes()[..width],
    )?;
    engine.get_data_mut().apis.crt_startup.command_line = Some(Backing {
        address,
        size: size.div_ceil(4096) * 4096,
    });
    Ok(())
}

pub(crate) fn mark_import(engine: &mut Unicorn<Trace>) {
    engine.get_data_mut().apis.crt_startup.command_line_used = true;
}
pub(super) fn accessor(engine: &mut Unicorn<Trace>) -> Result<u64> {
    let address = engine
        .get_data()
        .apis
        .crt_startup
        .command_line
        .as_ref()
        .context("CRT command-line data has not been published")?
        .address;
    mark_import(engine);
    Ok(address)
}
