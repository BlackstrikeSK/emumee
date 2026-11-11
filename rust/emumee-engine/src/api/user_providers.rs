//! Finite modeled user DLL namespaces, shared by IAT binding and guest PE walks.
//! These generated images are model declarations, not Windows binary catalogs.
use super::*;
use anyhow::Context;
use emumee_core::modules::ModuleOrigin;
use std::collections::BTreeSet;

pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "User providers require a user process"
    );
    let architecture = engine.get_data().architecture;
    let system_directory = engine
        .get_data()
        .apis
        .persona
        .model
        .config()
        .system_directory
        .clone();
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../../../api-parity/legacy-inventory.json"))?;
    let mut modules: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut known = BTreeSet::new();
    // Preserve conventional core identities even when the input has no imports.
    for module in ["kernel32", "kernelbase", "ntdll", "msvcrt"] {
        modules.entry(format!("{module}.dll")).or_default();
    }
    for entry in inventory["entries"]
        .as_array()
        .context("Missing user API inventory")?
    {
        let module = entry["module"].as_str().context("Missing API module")?;
        let name = entry["export"].as_str().context("Missing API export")?;
        if matches!(module, "ntoskrnl" | "hal" | "wdfldr" | "wdf01000") {
            continue;
        }
        known.insert(format!("{module}.dll"));
        let binding = definition(architecture, module, name);
        if !matches!(
            binding.model,
            Model::Unsupported | Model::CrtStdio(crt_stdio::Call::Unsupported(_))
        ) {
            modules
                .entry(format!("{module}.dll"))
                .or_default()
                .insert(name.into());
        }
        // Kernelbase shares the modeled Win32 ABI, including APIs that only
        // appear under kernel32 in the frozen registration inventory.
        if module == "kernel32"
            && !matches!(
                definition(architecture, "kernelbase", name).model,
                Model::Unsupported
            )
        {
            modules
                .get_mut("kernelbase.dll")
                .unwrap()
                .insert(name.into());
        }
    }
    for (module, names) in [
        ("kernel32.dll", &["ExitProcess"][..]),
        ("kernelbase.dll", &["ExitProcess"][..]),
        (
            "ntdll.dll",
            &["RtlExitUserProcess", "LdrLoadDll", "LdrUnloadDll"][..],
        ),
    ] {
        modules
            .get_mut(module)
            .unwrap()
            .extend(names.iter().map(|name| (*name).into()));
    }
    // Imported unsupported routines in known modeled namespaces retain stop
    // gates. An unknown DLL must remain unresolved, not become a provider merely
    // because an input import table declares its name.
    for binding in &engine.get_data().apis.bindings {
        let (module, name) = binding
            .name
            .split_once('.')
            .context("Invalid API binding name")?;
        let module = format!("{module}.dll");
        if known.contains(&module) || !matches!(binding.model, Model::Unsupported) {
            modules.entry(module).or_default().insert(name.into());
        }
    }
    ensure!(modules.len() <= 128, "User provider module quota exceeded");
    for (index, (module, names)) in modules.into_iter().enumerate() {
        // Supplied guest modules retain authority over their own names/exports.
        if engine.get_data().apis.modules.module(&module)?.is_some() {
            continue;
        }
        ensure!(
            !names.is_empty() && names.len() <= 256,
            "User provider export quota exceeded: {module}"
        );
        let mut exports = Vec::with_capacity(names.len());
        for name in &names {
            let binding = definition(architecture, &module, name);
            exports.push((name.as_str(), install_binding(engine, binding)?));
        }
        let base =
            dynamic_loader::place_image(engine, 0x74000000 + index as u64 * 0x100000, 0x6000)?;
        let bytes = emumee_core::provider::image(architecture, base, &module, &exports)?;
        let pe = PeImage::parse(&bytes, &module)?;
        crate::map_image(engine, &pe, &bytes, base)?;
        crate::protect_image(engine, &pe)?;
        engine.get_data_mut().apis.modules.add_with_path(
            &module,
            base,
            &pe,
            &format!(r"{}\{module}", system_directory.trim_end_matches('\\')),
            ModuleOrigin::SyntheticProvider,
        )?;
        engine.get_data_mut().apis.providers.push(ProviderEvidence {
            module, base, exports: pe.exports.len(), image_size: pe.image_size,
            reference_catalog: None, metadata_only: None,
            scope: "Finite generated user DLL export namespace from the modeled dispatcher and input bindings. Guest PE exports and IATs share call gates. Unsupported imported routines stop explicitly. Synthetic ordinals do not establish Windows ordinal compatibility or semantic parity.",
        });
    }
    Ok(())
}
