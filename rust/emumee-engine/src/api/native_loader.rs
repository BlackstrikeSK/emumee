//! Bounded real static guest initialization; catalog owns identities and lifetimes.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context as _;
use emumee_core::{
    modules::{LoaderInvocation, LoaderRoutine, ModuleId, Resolution, StaticImage, StaticStartup},
    pe::Kind,
};
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub primary: Option<ModuleId>,
    pub images: Vec<emumee_core::modules::LoadedModule>,
    pub retired_images: Vec<emumee_core::modules::RetiredImage>,
    pub events: Vec<emumee_core::modules::LoaderEvent>,
    pub native_effect_failure: Option<String>,
    pub preparation_error: Option<String>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let c = &engine.get_data().apis.modules;
    if !c.modules().any(|m| m.lifecycle().is_some())
        && c.retired_images().is_empty()
        && engine.get_data().loader_preparation_error.is_none()
    {
        return None;
    }
    Some(Report {
        profile: emumee_core::modules::STATIC_PROFILE,
        primary: c.primary().map(|m| m.identity()),
        images: c
            .modules()
            .filter(|m| m.lifecycle().is_some())
            .cloned()
            .collect(),
        retired_images: c.retired_images().to_vec(),
        events: c.loader_events().to_vec(),
        native_effect_failure: engine.get_data().loader_native_effect_failure.clone(),
        preparation_error: engine.get_data().loader_preparation_error.clone(),
        scope: "Actual bounded static dependency/TLS-callback/DllMain initialization and returned-FALSE cleanup on the sole guest module catalog. Callback-only TLS has no template, index or user-thread storage. No dynamic loads, exports-as-entrypoint, process-exit cleanup, general unload, child loader state or full Windows loader lock/TLS semantics.",
    })
}
fn pointer(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let width = engine.get_data().architecture.width();
    require(engine, address, width as u64, P::READ)?;
    let mut value = [0; 8];
    uc(engine.mem_read(address, &mut value[..width]))?;
    Ok(u64::from_le_bytes(value))
}
fn binding_edges(
    engine: &Unicorn<Trace>,
    pe: &PeImage,
    owner: ModuleId,
    owned: &[ModuleId],
) -> Result<Vec<(ModuleId, ModuleId)>> {
    let mut dependencies = Vec::new();
    for import in &pe.imports {
        let installed = pointer(engine, pe.image_base + import.iat_rva as u64)?;
        match engine
            .get_data()
            .apis
            .modules
            .resolve(&import.module, &import.name)?
        {
            Resolution::Found { address, chain } => {
                ensure!(
                    installed == address,
                    "Static IAT binding no longer matches the actual catalog"
                );
                let mut previous = owner;
                for followed in chain {
                    let name = followed
                        .split_once('!')
                        .context("Invalid followed module resolution receipt")?
                        .0;
                    let id = engine
                        .get_data()
                        .apis
                        .modules
                        .module(name)?
                        .context("Followed module is absent")?
                        .identity();
                    if owned.contains(&id) {
                        if !dependencies.contains(&(previous, id)) {
                            dependencies.push((previous, id));
                        }
                        previous = id;
                    }
                }
            }
            Resolution::MissingExport { module, .. } => {
                bail!("Static dependency export is missing from {module}")
            }
            Resolution::MissingModule { .. } => {
                let name = match &import.name {
                    ImportName::Name(name) => name.clone(),
                    ImportName::Ordinal { ordinal } => format!("#{ordinal}"),
                };
                let expected = definition(pe.sample.architecture, &import.module, &name);
                let apis = &engine.get_data().apis;
                let index = installed
                    .checked_sub(apis.base)
                    .filter(|offset| offset % 16 == 0)
                    .and_then(|offset| usize::try_from(offset / 16).ok())
                    .context("Static external import is not an installed API binding")?;
                let actual = apis
                    .bindings
                    .get(index)
                    .context("Static external API gate is absent")?;
                ensure!(
                    installed < apis.end
                        && actual.name == expected.name
                        && !matches!(actual.model, Model::Unsupported),
                    "Static external import {} is not an actually modeled binding",
                    expected.name
                );
            }
        }
    }
    Ok(dependencies)
}
pub(crate) fn prepare(
    engine: &mut Unicorn<Trace>,
    root: &PeImage,
    root_bytes: &[u8],
    companions: &[(String, Vec<u8>)],
    parsed: &[PeImage],
) -> Result<Option<StaticStartup>> {
    ensure!(
        companions.len() == parsed.len(),
        "Static companion descriptor count mismatch"
    );
    if engine.get_data().apis.kernel_mode {
        // Existing kernel export-only images remain mapped on the same catalog.
        // They have no initializer to skip; user DLL startup never runs here.
        for ((_, bytes), pe) in companions.iter().zip(parsed) {
            ensure!(
                pe.entry_rva == 0
                    && !pe.sample.managed
                    && pe.tls_callbacks_only(bytes)?.directory_rva.is_none(),
                "Kernel static companion initialization is not modeled"
            );
        }
        return Ok(None);
    }
    let tls = root.tls_callbacks_only(root_bytes)?;
    if companions.is_empty() && root.sample.kind == Kind::Exe && tls.directory_rva.is_none() {
        return Ok(None);
    }
    ensure!(
        companions.len() == parsed.len(),
        "Static companion descriptor count mismatch"
    );
    let root_name = engine
        .get_data()
        .apis
        .modules
        .primary()
        .context("Actual primary identity is absent")?
        .name
        .clone();
    let mut owned = vec![engine.get_data().apis.modules.primary().unwrap().identity()];
    for ((name, _), pe) in companions.iter().zip(parsed) {
        ensure!(
            pe.sample.kind == Kind::Dll && !pe.sample.managed,
            "Static companion must be an unmanaged DLL"
        );
        owned.push(
            engine
                .get_data()
                .apis
                .modules
                .module(name)?
                .context("Supplied companion is absent")?
                .identity(),
        );
    }
    let mut images = vec![StaticImage {
        name: root_name,
        kind: root.sample.kind,
        entry_rva: root.entry_rva,
        accepted_sha256: root.sample.sha256.clone(),
        tls,
        dependencies: Vec::new(),
    }];
    for ((name, bytes), pe) in companions.iter().zip(parsed) {
        images.push(StaticImage {
            name: name.clone(),
            kind: pe.sample.kind,
            entry_rva: pe.entry_rva,
            accepted_sha256: pe.sample.sha256.clone(),
            tls: pe.tls_callbacks_only(bytes)?,
            dependencies: Vec::new(),
        });
    }
    let mut edges = binding_edges(engine, root, owned[0], &owned)?;
    for (index, pe) in parsed.iter().enumerate() {
        edges.extend(binding_edges(engine, pe, owned[index + 1], &owned)?);
    }
    for image in &mut images {
        let id = engine
            .get_data()
            .apis
            .modules
            .module(&image.name)?
            .unwrap()
            .identity();
        for (from, to) in &edges {
            if *from == id && !image.dependencies.contains(to) {
                image.dependencies.push(*to);
            }
        }
    }
    // No initializer executes until every descriptor and graph has validated.
    for image in &images {
        let m = engine.get_data().apis.modules.module(&image.name)?.unwrap();
        validate_tls(engine, m.base, &image.tls)?;
        if image.entry_rva != 0 {
            require(engine, m.base + image.entry_rva as u64, 1, P::EXECUTE)?;
        }
    }
    Ok(Some(
        engine
            .get_data_mut()
            .apis
            .modules
            .configure_static(&images)?,
    ))
}
fn validate_tls(
    engine: &Unicorn<Trace>,
    base: u64,
    plan: &emumee_core::pe::TlsCallbackPlan,
) -> Result<()> {
    for check in plan.mirror_checks(base)? {
        let address = base
            .checked_add(check.rva.into())
            .context("TLS relocated comparison address overflow")?;
        require(engine, address, check.expected.len() as u64, P::READ)?;
        let mut actual = vec![0; check.expected.len()];
        uc(engine.mem_read(address, &mut actual))?;
        ensure!(
            actual == check.expected,
            "Actual TLS callback directory/array differs from accepted relocated bytes"
        );
    }
    Ok(())
}
fn nonvolatile(arch: Architecture) -> &'static [RegisterX86] {
    use RegisterX86::*;
    if arch == Architecture::X64 {
        &[
            RBX, RBP, RSI, RDI, R12, R13, R14, R15, CS, SS, DS, ES, FS, GS, FS_BASE, GS_BASE, CR0,
            CR3, CR4, FPCW,
        ]
    } else {
        &[
            EBX, EBP, ESI, EDI, CS, SS, DS, ES, FS, GS, CR0, CR3, CR4, FPCW,
        ]
    }
}
fn vectors() -> &'static [RegisterX86] {
    use RegisterX86::*;
    &[
        XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
    ]
}
pub(super) fn invoke_inner(
    engine: &mut Unicorn<Trace>,
    call: &LoaderInvocation,
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let arch = engine.get_data().architecture;
    let m = engine
        .get_data()
        .apis
        .modules
        .by_identity(call.module)
        .context("Initializer module retired before invocation")?;
    validate_tls(
        engine,
        m.base,
        m.initializer_tls()
            .context("Initializer lifecycle absent")?,
    )?;
    require(engine, call.address, 1, P::EXECUTE)?;
    ensure!(
        engine.get_data().threads.is_none() && !crate::ipi::active(engine),
        "Loader invocation cannot borrow a kernel scheduler context"
    );
    let marker = engine
        .get_data()
        .return_marker
        .checked_add(0x300)
        .context("Loader return marker overflow")?;
    require(engine, marker, 1, P::EXECUTE)?;
    let preserved = nonvolatile(arch)
        .iter()
        .map(|r| uc(engine.reg_read(*r)).map(|v| (*r, v)))
        .collect::<Result<Vec<_>>>()?;
    let xmm = if arch == Architecture::X64 {
        vectors()
            .iter()
            .map(|r| uc(engine.reg_read_long(*r)).map(|v| (*r, v)))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let flags = uc(engine.reg_read(RegisterX86::EFLAGS))?;
    let mxcsr = if arch == Architecture::X64 {
        Some(uc(engine.reg_read(RegisterX86::MXCSR))?)
    } else {
        None
    };
    ensure!(flags & 0x400 == 0, "Loader caller has direction flag set");
    let width = arch.width() as u64;
    let (sp, expected_sp) = if arch == Architecture::X64 {
        let sp = (stack_top & !15) - 0x28;
        (sp, sp + 8)
    } else {
        let sp = (stack_top & !15) - 16;
        (sp, sp + 16)
    };
    let mut frame = vec![0; if arch == Architecture::X64 { 40 } else { 16 }];
    frame[..width as usize].copy_from_slice(&marker.to_le_bytes()[..width as usize]);
    if arch == Architecture::X86 {
        for (index, arg) in call.arguments.iter().enumerate() {
            ensure!(
                *arg <= u32::MAX as u64,
                "x86 loader argument exceeds pointer width"
            );
            frame[(index + 1) * 4..(index + 2) * 4].copy_from_slice(&(*arg as u32).to_le_bytes());
        }
    }
    require(engine, sp, frame.len() as u64, P::WRITE)?;
    let publication = (|| -> Result<()> {
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
            for (reg, value) in [RegisterX86::RCX, RegisterX86::RDX, RegisterX86::R8]
                .into_iter()
                .zip(call.arguments)
            {
                uc(engine.reg_write(reg, value))?;
            }
        }
        Ok(())
    })();
    if let Err(error) = publication {
        engine.get_data_mut().loader_native_effect_failure = Some(format!(
            "Loader frame publication failed; partial native effects are terminal: {error:#}"
        ));
        return Err(error);
    }
    let outcome = crate::threads::execute_horizon(engine, call.address, marker, horizon)?;
    if outcome.returned {
        ensure!(
            uc(engine.pc_read())? == marker,
            "Initializer did not reach its owned return boundary"
        );
        let actual_sp = uc(engine.reg_read(if arch == Architecture::X64 {
            RegisterX86::RSP
        } else {
            RegisterX86::ESP
        }))?;
        ensure!(
            actual_sp == expected_sp,
            "Initializer violated its STDCALL3/Win64 stack return contract"
        );
        for (reg, value) in preserved {
            ensure!(
                uc(engine.reg_read(reg))? == value,
                "Initializer changed protected/nonvolatile register {reg:?}"
            );
        }
        for (reg, value) in xmm {
            ensure!(
                uc(engine.reg_read_long(reg))? == value,
                "Initializer changed nonvolatile vector register {reg:?}"
            );
        }
        if let Some(saved) = mxcsr {
            ensure!(
                (uc(engine.reg_read(RegisterX86::MXCSR))? ^ saved) & 0xffc0 == 0,
                "Initializer changed nonvolatile MXCSR control bits"
            );
        }
        let actual_flags = uc(engine.reg_read(RegisterX86::EFLAGS))?;
        ensure!(
            actual_flags & 0x400 == 0 && (actual_flags ^ flags) & 0x3200 == 0,
            "Initializer changed protected flags or left direction flag set"
        );
    }
    Ok(outcome)
}
fn invoke(
    engine: &mut Unicorn<Trace>,
    call: &LoaderInvocation,
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let count = engine.get_data().instructions;
    let event = engine
        .get_data_mut()
        .apis
        .modules
        .begin_invocation(call, count)?;
    engine.get_data_mut().loader_active = true;
    let result = invoke_inner(engine, call, stack_top, horizon);
    engine.get_data_mut().loader_active = false;
    let outcome = match result {
        Ok(value) => value,
        Err(error) => Outcome {
            returned: false,
            value: None,
            error: Some(format!("{error:#}")),
        },
    };
    let count = engine.get_data().instructions;
    let failure = if outcome.returned {
        None
    } else {
        Some(
            outcome
                .error
                .clone()
                .unwrap_or_else(|| "Shared instruction or wall horizon exhausted".into()),
        )
    };
    engine.get_data_mut().apis.modules.settle_invocation(
        event,
        count,
        if outcome.returned {
            outcome.value
        } else {
            None
        },
        failure,
    )?;
    Ok(outcome)
}
fn retire(engine: &mut Unicorn<Trace>, id: ModuleId) -> Result<()> {
    let m = engine
        .get_data()
        .apis
        .modules
        .by_identity(id)
        .context("Cleanup module is absent")?;
    let (base, size) = (m.base, m.size);
    let mut catalog = engine.get_data().apis.modules.clone();
    catalog.retire_static(id)?;
    let mut memory = engine.get_data().apis.memory.clone();
    memory.unmap(base, size)?;
    // All pure preflight precedes actual unmap. No guest resumes after failure.
    if let Err(error) = uc(engine.mem_unmap(base, size)) {
        engine.get_data_mut().loader_native_effect_failure = Some(format!(
            "Static native unmap failed at {base:#x}+{size:#x}: {error:#}"
        ));
        return Err(error);
    }
    engine.get_data_mut().apis.memory = memory;
    engine.get_data_mut().apis.modules = catalog;
    engine
        .get_data_mut()
        .cpu
        .cache
        .invalidate(base, size as usize);
    if let Err(error) = uc(engine.ctl_remove_cache(base, base + size)) {
        engine.get_data_mut().loader_native_effect_failure = Some(format!(
            "Static unmap completed but native cache retirement failed: {error:#}"
        ));
        return Err(error);
    }
    Ok(())
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    let marker = engine.get_data().return_marker;
    if engine.get_data().loader_active && [marker, marker + 0x100, marker + 0x200].contains(&pc) {
        engine.get_data_mut().apis.fault =
            Some("Initializer escaped into primary entry return boundary".into());
        return true;
    }
    false
}
fn failure(error: String) -> Outcome {
    Outcome {
        returned: false,
        value: None,
        error: Some(error),
    }
}
pub(crate) fn execute(
    engine: &mut Unicorn<Trace>,
    startup: Option<StaticStartup>,
    root: &PeImage,
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let return_marker = engine.get_data().return_marker;
    let Some(startup) = startup else {
        return crate::threads::execute_horizon(
            engine,
            root.image_base + root.entry_rva as u64,
            return_marker,
            horizon,
        );
    };
    let arch = engine.get_data().architecture;
    let saved_sp = uc(engine.reg_read(if arch == Architecture::X64 {
        RegisterX86::RSP
    } else {
        RegisterX86::ESP
    }))?;
    let root_arguments = if arch == Architecture::X64 {
        [
            RegisterX86::RCX,
            RegisterX86::RDX,
            RegisterX86::R8,
            RegisterX86::R9,
        ]
        .into_iter()
        .map(|r| uc(engine.reg_read(r)).map(|v| (r, v)))
        .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let mut primary_dll_result = None;
    for id in startup.order {
        let calls = engine.get_data().apis.modules.attach_calls(id)?;
        let mut attach_refused = false;
        for call in calls {
            let result = invoke(engine, &call, stack_top, horizon)?;
            if !result.returned {
                return Ok(result);
            }
            if call.routine == LoaderRoutine::DllAttach {
                if id == startup.primary {
                    primary_dll_result = result.value;
                }
                if result.value.unwrap() as u32 == 0 {
                    attach_refused = true;
                    break;
                }
            }
        }
        if attach_refused {
            // This versioned legacy profile runs failed-module cleanup first,
            // then only actual completed prior DLLs in inverse attach order.
            while let Some(cleanup_id) = engine.get_data().apis.modules.next_static_cleanup()? {
                let failed = engine
                    .get_data()
                    .apis
                    .modules
                    .by_identity(cleanup_id)
                    .unwrap()
                    .lifecycle()
                    .unwrap()
                    .attach_failed;
                let calls = engine
                    .get_data()
                    .apis
                    .modules
                    .detach_calls(cleanup_id, failed)?;
                for call in calls {
                    let result = invoke(engine, &call, stack_top, horizon)?;
                    if !result.returned {
                        return Ok(result);
                    }
                }
                if let Err(error) = retire(engine, cleanup_id) {
                    return Ok(failure(format!("{error:#}")));
                }
            }
            return Ok(failure("Guest DllMain returned FALSE; primary execution was suppressed after actual failed-load cleanup".into()));
        }
        engine.get_data_mut().apis.modules.mark_ready(id)?;
    }
    if root.sample.kind == Kind::Dll {
        return Ok(Outcome {
            returned: true,
            value: primary_dll_result,
            error: None,
        });
    }
    // Root EXE is a separate invocation after actual dependency/TLS completion.
    let publication = (|| -> Result<()> {
        uc(engine.reg_write(
            if arch == Architecture::X64 {
                RegisterX86::RSP
            } else {
                RegisterX86::ESP
            },
            saved_sp,
        ))?;
        if arch == Architecture::X64 {
            for (reg, value) in root_arguments {
                uc(engine.reg_write(reg, value))?;
            }
        }
        Ok(())
    })();
    if let Err(error) = publication {
        engine.get_data_mut().loader_native_effect_failure = Some(format!(
            "Root frame resumption failed; partial native effects are terminal: {error:#}"
        ));
        return Ok(failure(format!("{error:#}")));
    }
    crate::threads::execute_horizon(
        engine,
        root.image_base + root.entry_rva as u64,
        return_marker,
        horizon,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_module_handle_uses_the_actual_primary_identity_including_custom_basename() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            assert!(
                super::super::providers::call(&mut engine, Model::ModuleHandleA, &[0]).is_err()
            );
            let bytes = emumee_core::fixtures::counted_driver(architecture, 1);
            let pe = PeImage::parse(&bytes, "owned.sys").unwrap();
            engine
                .get_data_mut()
                .apis
                .modules
                .add("custom-primary.exe", pe.image_base, &pe)
                .unwrap();
            engine
                .get_data_mut()
                .apis
                .modules
                .set_primary("custom-primary.exe")
                .unwrap();
            for model in [Model::ModuleHandleA, Model::ModuleHandleW] {
                assert_eq!(
                    super::super::providers::call(&mut engine, model, &[0]).unwrap(),
                    pe.image_base
                );
            }
        }
    }
    #[test]
    fn failed_native_retirement_is_terminal_and_keeps_the_actual_unretired_catalog_state() {
        use emumee_core::modules::{ModuleOrigin, StaticImage};
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            let (_, companions) = emumee_core::fixtures::native_loader_probe(
                arch,
                emumee_core::fixtures::LoaderFixture::Entryless,
            );
            let (root, _) = emumee_core::fixtures::native_loader_probe(
                arch,
                emumee_core::fixtures::LoaderFixture::RootFalse,
            );
            let rootpe = PeImage::parse(&root, "root.exe").unwrap();
            let pe = PeImage::parse(&companions[0].1, "guest.dll").unwrap();
            for (name, image) in [("root.exe", &rootpe), ("guest.dll", &pe)] {
                engine
                    .get_data_mut()
                    .apis
                    .modules
                    .add_with_path(
                        name,
                        image.image_base,
                        image,
                        &format!(r"C:\owned\{name}"),
                        ModuleOrigin::OwnedGenerated,
                    )
                    .unwrap();
            }
            engine
                .get_data_mut()
                .apis
                .modules
                .set_primary("root.exe")
                .unwrap();
            let id = engine
                .get_data()
                .apis
                .modules
                .module("guest.dll")
                .unwrap()
                .unwrap()
                .identity();
            let descriptors = vec![
                StaticImage {
                    name: "root.exe".into(),
                    kind: Kind::Dll,
                    entry_rva: rootpe.entry_rva,
                    accepted_sha256: rootpe.sample.sha256.clone(),
                    tls: rootpe.tls_callbacks_only(&root).unwrap(),
                    dependencies: vec![id],
                },
                StaticImage {
                    name: "guest.dll".into(),
                    kind: Kind::Dll,
                    entry_rva: 0,
                    accepted_sha256: pe.sample.sha256.clone(),
                    tls: pe.tls_callbacks_only(&companions[0].1).unwrap(),
                    dependencies: Vec::new(),
                },
            ];
            engine
                .get_data_mut()
                .apis
                .modules
                .configure_static(&descriptors)
                .unwrap();
            engine.get_data_mut().apis.modules.mark_ready(id).unwrap();
            let rootid = engine.get_data().apis.modules.primary().unwrap().identity();
            for call in engine.get_data().apis.modules.attach_calls(rootid).unwrap() {
                let event = engine
                    .get_data_mut()
                    .apis
                    .modules
                    .begin_invocation(&call, 0)
                    .unwrap();
                let value = u64::from(call.routine != LoaderRoutine::DllAttach);
                engine
                    .get_data_mut()
                    .apis
                    .modules
                    .settle_invocation(event, 0, Some(value), None)
                    .unwrap();
            }

            for call in engine
                .get_data()
                .apis
                .modules
                .detach_calls(rootid, true)
                .unwrap()
            {
                let event = engine
                    .get_data_mut()
                    .apis
                    .modules
                    .begin_invocation(&call, 0)
                    .unwrap();
                engine
                    .get_data_mut()
                    .apis
                    .modules
                    .settle_invocation(event, 0, Some(0), None)
                    .unwrap();
            }
            engine
                .get_data_mut()
                .apis
                .memory
                .map(
                    rootpe.image_base,
                    rootpe.image_size as u64,
                    P::RW,
                    None,
                    "owned missing native effect injection",
                )
                .unwrap();
            assert!(retire(&mut engine, rootid).is_err());
            assert!(engine.get_data().loader_native_effect_failure.is_some());
            assert!(engine.get_data().apis.modules.by_identity(rootid).is_some());
            assert!(engine.get_data().apis.modules.retired_images().is_empty());
            assert!(engine.get_data().apis.memory.allows(
                rootpe.image_base,
                rootpe.image_size as u64,
                P::RW
            ));
        }
    }
}
