use super::*;

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub descriptor: u64,
    pub thunk: u64,
    pub target: Option<u64>,
    pub error: Option<String>,
}

fn name(engine: &Unicorn<Trace>, address: u64, end: u64, module: bool) -> Result<String> {
    let mut value = Vec::new();
    for offset in 0..129u64 {
        let at = address
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("Delay name overflow"))?;
        ensure!(at < end, "Delay name outside guest module");
        let unit = byte(engine, at)?;
        if unit == 0 {
            ensure!(
                !value.is_empty() && value.len() <= 128,
                "Invalid delay name length"
            );
            let value = String::from_utf8(value)?;
            if module {
                ensure!(
                    value.to_ascii_lowercase().ends_with(".dll"),
                    "Invalid delay DLL suffix"
                );
            }
            return Ok(value);
        }
        ensure!(
            unit.is_ascii_alphanumeric()
                || if module {
                    b"_.-".contains(&unit)
                } else {
                    b"_?$@.-".contains(&unit)
                },
            "Invalid delay name"
        );
        value.push(unit);
    }
    bail!("Unterminated delay name")
}

fn resolve(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "Delay imports require a user target"
    );
    let base = args[0];
    let end = engine
        .get_data()
        .apis
        .modules
        .modules()
        .find(|row| row.base == base)
        .and_then(|row| base.checked_add(row.size))
        .ok_or_else(|| anyhow::anyhow!("Invalid delay guest module"))?;
    let descriptor = args[1];
    ensure!(
        args[5] == 0
            && descriptor >= base
            && descriptor.checked_add(32).is_some_and(|value| value <= end),
        "Invalid delay descriptor or flags"
    );
    let raw = read(engine, descriptor, 32)?;
    let field =
        |index: usize| u32::from_le_bytes(raw[index * 4..index * 4 + 4].try_into().unwrap());
    ensure!(field(0) == 1, "Unsupported delay descriptor attributes");
    let relative = |value: u32| -> Result<u64> {
        ensure!(
            value != 0 && u64::from(value) < end - base,
            "Delay RVA outside guest module"
        );
        Ok(base + u64::from(value))
    };
    let dll = name(engine, relative(field(1))?, end, true)?;
    let iat = relative(field(3))?;
    let names = relative(field(4))?;
    let width = engine.get_data().architecture.width() as u64;
    let thunk = args[4];
    let displacement = thunk
        .checked_sub(iat)
        .ok_or_else(|| anyhow::anyhow!("Invalid delay thunk"))?;
    ensure!(
        displacement % width == 0
            && displacement / width < 128
            && thunk.checked_add(width).is_some_and(|value| value <= end),
        "Invalid delay thunk"
    );
    let entry = names
        .checked_add(displacement)
        .ok_or_else(|| anyhow::anyhow!("Delay thunk overflow"))?;
    ensure!(
        entry.checked_add(width).is_some_and(|value| value <= end),
        "Delay names outside guest module"
    );
    let mut value = [0; 8];
    value[..width as usize].copy_from_slice(&read(engine, entry, width)?);
    let value = u64::from_le_bytes(value);
    ensure!(
        value != 0 && value & (1 << (width * 8 - 1)) == 0,
        "Ordinal or empty delay import unsupported by baseline"
    );
    let value = u32::try_from(value)?;
    let hint = relative(value)?;
    ensure!(
        hint.checked_add(2).is_some_and(|value| value <= end),
        "Delay hint outside guest module"
    );
    read(engine, hint, 2)?;
    let symbol = ImportName::Name(name(engine, hint + 2, end, false)?);
    require(engine, thunk, width, P::WRITE)?;
    let resolution = engine.get_data().apis.modules.resolve(&dll, &symbol)?;
    let address = match resolution {
        emumee_core::modules::Resolution::Found { address, chain } => {
            dynamic_loader::retain_followed_edges(engine, &dll, &chain)?;
            address
        }
        emumee_core::modules::Resolution::MissingExport { .. } => bail!("Delay target unavailable"),
        emumee_core::modules::Resolution::MissingModule { module, symbol, .. } => {
            let ImportName::Name(name) = symbol else {
                bail!("Delay target unavailable")
            };
            let binding = definition(engine.get_data().architecture, &module, &name);
            ensure!(
                !matches!(binding.model, Model::Unsupported),
                "Delay target unavailable"
            );
            install_binding(engine, binding)?
        }
    };
    crate::cpu::write(engine, thunk, &address.to_le_bytes()[..width as usize])?;
    Ok(address)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64]) -> u64 {
    let result = resolve(engine, args);
    let observation = Observation {
        descriptor: args[1],
        thunk: args[4],
        target: result.as_ref().ok().copied(),
        error: result.as_ref().err().map(|error| format!("{error:#}")),
    };
    let state = &mut engine.get_data_mut().apis;
    if state.delay_imports.len() < 512 {
        state.delay_imports.push(observation);
    } else {
        state.delay_imports_omitted = state.delay_imports_omitted.saturating_add(1);
    }
    result.unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::{self, ImportFixture as F};

    fn engine(architecture: Architecture, case: F) -> crate::NativeEngine {
        let bytes = fixtures::import_probe(architecture, case);
        let pe = PeImage::parse(&bytes, "imports.exe").unwrap();
        let mut engine = crate::new_engine(architecture).unwrap();
        crate::map_image(&mut engine, &pe, &bytes, pe.image_base).unwrap();
        engine
            .get_data_mut()
            .apis
            .modules
            .add("imports.exe", pe.image_base, &pe)
            .unwrap();
        providers::initialize(&mut engine).unwrap();
        crate::protect_image(&mut engine, &pe).unwrap();
        engine
    }

    #[test]
    fn rejected_delay_resolution_preserves_iat_catalog_gates_and_last_error() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for case in [
                F::DelayMissing,
                F::DelayAttributes,
                F::DelayDll,
                F::DelayIat,
                F::DelayNames,
                F::DelayEmpty,
                F::DelayOrdinal,
                F::DelayHint,
                F::DelayName,
                F::DelayWrite,
            ] {
                let mut engine = engine(architecture, case);
                let base = if architecture == Architecture::X64 {
                    0x140000000
                } else {
                    0x400000
                };
                let args = [base, base + 0x2400, 0, 0, base + 0x2600, 0];
                let before = read(&engine, base + 0x2600, architecture.width() as u64).unwrap();
                let gates = engine.get_data().apis.bindings.len();
                let catalog = serde_json::to_value(&engine.get_data().apis.modules).unwrap();
                engine.get_data_mut().apis.last_error = 123;
                assert_eq!(invoke(&mut engine, &args), 0, "{architecture:?}/{case:?}");
                assert_eq!(
                    read(&engine, base + 0x2600, architecture.width() as u64).unwrap(),
                    before
                );
                assert_eq!(engine.get_data().apis.bindings.len(), gates);
                assert_eq!(
                    serde_json::to_value(&engine.get_data().apis.modules).unwrap(),
                    catalog
                );
                assert_eq!(engine.get_data().apis.last_error, 123);
                assert!(engine.get_data().apis.delay_imports[0].error.is_some());
            }
        }
    }

    #[test]
    fn repeated_delay_resolution_reuses_target_and_bounds_observations() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture, F::DelayPid);
            let base = if architecture == Architecture::X64 {
                0x140000000
            } else {
                0x400000
            };
            let args = [base, base + 0x2400, 0, 0, base + 0x2600, 0];
            let target = invoke(&mut engine, &args);
            assert_ne!(target, 0);
            let gates = engine.get_data().apis.bindings.len();
            for _ in 0..512 {
                assert_eq!(invoke(&mut engine, &args), target);
            }
            assert_eq!(engine.get_data().apis.delay_imports.len(), 512);
            assert_eq!(engine.get_data().apis.delay_imports_omitted, 1);
            assert_eq!(engine.get_data().apis.bindings.len(), gates);
            assert_eq!(
                read(&engine, base + 0x2600, architecture.width() as u64).unwrap(),
                target.to_le_bytes()[..architecture.width()]
            );
        }
    }
}
