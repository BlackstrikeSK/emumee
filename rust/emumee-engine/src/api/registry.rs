//! Guest registry adapters. LSTATUS is returned directly; LastError is preserved.
use super::*;
use emumee_core::registry::{self, RegistryError, RegistryValue};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Open { wide: bool, extended: bool },
    Create { wide: bool, extended: bool },
    Set { wide: bool },
    Query { wide: bool },
    Get { wide: bool },
    Delete { wide: bool },
    EnumValue { wide: bool },
    EnumKey { wide: bool },
    Info { wide: bool },
    Close,
}
pub(super) fn definition(name: &str) -> Option<(Call, usize)> {
    let wide = name.ends_with('W');
    Some(match name {
        "RegOpenKeyA" | "RegOpenKeyW" => (
            Call::Open {
                wide,
                extended: false,
            },
            3,
        ),
        "RegOpenKeyExA" | "RegOpenKeyExW" => (
            Call::Open {
                wide,
                extended: true,
            },
            5,
        ),
        "RegCreateKeyA" | "RegCreateKeyW" => (
            Call::Create {
                wide,
                extended: false,
            },
            3,
        ),
        "RegCreateKeyExA" | "RegCreateKeyExW" => (
            Call::Create {
                wide,
                extended: true,
            },
            9,
        ),
        "RegSetValueExA" | "RegSetValueExW" => (Call::Set { wide }, 6),
        "RegQueryValueExA" | "RegQueryValueExW" => (Call::Query { wide }, 6),
        "RegGetValueA" | "RegGetValueW" => (Call::Get { wide }, 7),
        "RegDeleteKeyA" | "RegDeleteKeyW" => (Call::Delete { wide }, 2),
        "RegEnumValueA" | "RegEnumValueW" => (Call::EnumValue { wide }, 8),
        "RegEnumKeyExA" | "RegEnumKeyExW" => (Call::EnumKey { wide }, 8),
        "RegQueryInfoKeyA" | "RegQueryInfoKeyW" => (Call::Info { wide }, 12),
        "RegCloseKey" => (Call::Close, 1),
        _ => return None,
    })
}
fn name(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let width = if wide { 2 } else { 1 };
    let mut bytes = Vec::new();
    for index in 0..32768u64 {
        let at = address
            .checked_add(index * width)
            .ok_or_else(|| anyhow::anyhow!("Registry name pointer overflow"))?;
        let unit = read(engine, at, width)?;
        if unit.iter().all(|byte| *byte == 0) {
            return registry::decode_name(&bytes, wide).map_err(Into::into);
        }
        bytes.extend(unit);
    }
    bail!("Registry name exceeds modeled bound")
}
fn status(error: RegistryError) -> Result<u64> {
    ensure!(error.win32 != 50, "Unsupported registry profile: {}", error);
    Ok(error.win32 as u64)
}
fn valid(engine: &Unicorn<Trace>, address: u64, size: usize) -> bool {
    size == 0
        || engine
            .get_data()
            .apis
            .memory
            .allows(address, size as u64, P::WRITE)
}
fn outputs(engine: &mut Unicorn<Trace>, writes: &[(u64, Vec<u8>)]) -> Result<bool> {
    if writes
        .iter()
        .any(|(address, bytes)| !valid(engine, *address, bytes.len()))
    {
        return Ok(false);
    }
    for (address, bytes) in writes {
        crate::cpu::write(engine, *address, bytes)?;
    }
    Ok(true)
}
fn pointer(engine: &Unicorn<Trace>, value: u64) -> Vec<u8> {
    if engine.get_data().architecture == Architecture::X86 {
        (value as u32).to_le_bytes().to_vec()
    } else {
        value.to_le_bytes().to_vec()
    }
}
fn input_count(engine: &Unicorn<Trace>, at: u64) -> Result<Option<u32>> {
    if !engine.get_data().apis.memory.allows(at, 4, P::READ) {
        return Ok(None);
    }
    Ok(Some(u32::from_le_bytes(
        read(engine, at, 4)?.try_into().unwrap(),
    )))
}
fn query_outputs(
    engine: &mut Unicorn<Trace>,
    value: RegistryValue,
    type_at: u64,
    data_at: u64,
    size_at: u64,
) -> Result<u64> {
    if data_at != 0 && size_at == 0 {
        return Ok(87);
    }
    let capacity = if data_at != 0 {
        if !engine.get_data().apis.memory.allows(size_at, 4, P::READ) {
            return Ok(998);
        }
        u32::from_le_bytes(read(engine, size_at, 4)?.try_into().unwrap())
    } else {
        0
    };
    let mut writes = Vec::new();
    if type_at != 0 {
        writes.push((type_at, value.value_type.to_le_bytes().to_vec()));
    }
    if size_at != 0 {
        writes.push((size_at, value.required_size.to_le_bytes().to_vec()));
    }
    let insufficient = data_at != 0 && capacity < value.required_size;
    if data_at != 0 && !insufficient {
        writes.push((data_at, value.data));
    }
    if !outputs(engine, &writes)? {
        return Ok(998);
    }
    Ok(if insufficient { 234 } else { 0 })
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "User registry calls are outside the kernel target profile"
    );
    match call {
        Call::Open { wide, extended } | Call::Create { wide, extended } => {
            let create = matches!(call, Call::Create { .. });
            let (output, desired, disposition) = if extended && create {
                if args[2] != 0 || args[3] != 0 || args[4] != 0 || args[6] != 0 {
                    bail!("Registry creation options/security/class are not modeled");
                }
                (args[7], args[5] as u32, args[8])
            } else if extended {
                if args[2] != 0 {
                    bail!("Registry open options are not modeled");
                }
                (args[4], args[3] as u32, 0)
            } else {
                (args[2], registry::KEY_ALL_ACCESS, 0)
            };
            if output == 0 {
                return Ok(87);
            }
            let subkey = name(engine, args[1], wide)?;
            let mut next = engine.get_data().apis.registry.clone();
            let (handle, created) = if create {
                match next.create(OWNER, args[0], &subkey, desired) {
                    Ok(opened) => (opened.handle, opened.disposition),
                    Err(error) => return status(error),
                }
            } else {
                match next.open(OWNER, args[0], &subkey, desired) {
                    Ok(handle) => (handle, 0),
                    Err(error) => return status(error),
                }
            };
            let mut writes = vec![(output, pointer(engine, handle))];
            if disposition != 0 {
                writes.push((disposition, created.to_le_bytes().to_vec()));
            }
            if !outputs(engine, &writes)? {
                return Ok(998);
            }
            engine.get_data_mut().apis.registry = next;
            Ok(0)
        }
        Call::Set { wide } => {
            let key_path = match engine.get_data().apis.registry.path(OWNER, args[0]) {
                Ok(path) => path.to_owned(),
                Err(error) => return status(error),
            };
            if args[2] != 0 {
                return Ok(87);
            }
            let name = name(engine, args[1], wide)?;
            let size = args[5] as u32 as u64;
            ensure!(
                size <= registry::MAX_VALUE as u64,
                "Registry value exceeds modeled 1MiB bound"
            );
            if size != 0 && args[4] == 0 {
                return Ok(87);
            }
            let mut probe = engine.get_data().apis.registry.clone();
            if let Err(error) = probe.set_value(OWNER, args[0], &name, args[3] as u32, &[], wide) {
                return status(error);
            }
            let bytes = read(engine, args[4], size)?;
            match engine.get_data_mut().apis.registry.set_value(
                OWNER,
                args[0],
                &name,
                args[3] as u32,
                &bytes,
                wide,
            ) {
                Ok(()) => {
                    if args[3] as u32 == registry::REG_BINARY
                        && !bytes.is_empty()
                        && !crate::capture::registry_binary(engine, &key_path, &name, &bytes)
                    {
                        let captures = &mut engine.get_data_mut().apis.captures;
                        if emumee_core::artifact_bridge::capture_registry_binary(
                            captures, &key_path, &name, &bytes,
                        )
                        .is_err()
                        {
                            // Evidence failure is explicit and does not alter the
                            // already successful guest LSTATUS or thread LastError.
                            let _ =
                                captures.merge_omissions(&emumee_core::artifacts::CaptureSummary {
                                    omitted_observations: 1,
                                    omitted_bytes: bytes.len() as u64,
                                    reasons: std::collections::BTreeMap::from([(
                                        "registry_capture_failed".to_owned(),
                                        1,
                                    )]),
                                });
                        }
                    }
                    Ok(0)
                }
                Err(error) => status(error),
            }
        }
        Call::Query { wide } => {
            if args[2] != 0 || (args[4] != 0 && args[5] == 0) {
                return Ok(87);
            }
            let name = name(engine, args[1], wide)?;
            match engine
                .get_data()
                .apis
                .registry
                .query_value(OWNER, args[0], &name, wide)
            {
                Ok(value) => query_outputs(engine, value, args[3], args[4], args[5]),
                Err(error) => status(error),
            }
        }
        Call::Get { wide } => {
            ensure!(
                (args[3] as u32) & 0x20000000 == 0,
                "Registry ZEROONFAILURE guest effect is not modeled"
            );
            let subkey = name(engine, args[1], wide)?;
            let name = name(engine, args[2], wide)?;
            let environment = engine
                .get_data()
                .apis
                .persona
                .model
                .environment(OWNER)?
                .map();
            match engine.get_data().apis.registry.get_value(
                OWNER,
                args[0],
                &subkey,
                &name,
                args[3] as u32,
                wide,
                &environment,
            ) {
                Ok(value) => query_outputs(engine, value, args[4], args[5], args[6]),
                Err(error) => status(error),
            }
        }
        Call::Delete { wide } => {
            let subkey = name(engine, args[1], wide)?;
            if args[1] == 0 || subkey.is_empty() {
                return Ok(87);
            }
            match engine
                .get_data_mut()
                .apis
                .registry
                .delete_key(OWNER, args[0], &subkey)
            {
                Ok(()) => Ok(0),
                Err(error) => status(error),
            }
        }
        Call::EnumValue { wide } => {
            if args[2] == 0 || args[3] == 0 || args[4] != 0 || (args[6] != 0 && args[7] == 0) {
                return Ok(87);
            }
            let entry = match engine.get_data().apis.registry.enum_value(
                OWNER,
                args[0],
                args[1] as u32,
                wide,
            ) {
                Ok(entry) => entry,
                Err(error) => return status(error),
            };
            let Some(name_capacity) = input_count(engine, args[3])? else {
                return Ok(998);
            };
            let data_capacity = if args[6] != 0 {
                let Some(count) = input_count(engine, args[7])? else {
                    return Ok(998);
                };
                count
            } else {
                0
            };
            let mut writes = Vec::new();
            if args[7] != 0 {
                writes.push((args[7], entry.value.required_size.to_le_bytes().to_vec()));
            }
            if args[5] != 0 {
                writes.push((args[5], entry.value.value_type.to_le_bytes().to_vec()));
            }
            let name_units = registry::text_units(&entry.name, wide);
            let name_small = name_capacity <= name_units;
            if !name_small {
                writes.push((args[2], registry::encode_text(&entry.name, wide, true)));
                writes.push((args[3], name_units.to_le_bytes().to_vec()));
            }
            let data_small = args[6] != 0 && data_capacity < entry.value.required_size;
            if !name_small && !data_small && args[6] != 0 {
                writes.push((args[6], entry.value.data));
            }
            if !outputs(engine, &writes)? {
                return Ok(998);
            }
            Ok(if name_small || data_small { 234 } else { 0 })
        }
        Call::EnumKey { wide } => {
            if args[2] == 0 || args[3] == 0 || args[4] != 0 || (args[5] != 0 && args[6] == 0) {
                return Ok(87);
            }
            let entry =
                match engine
                    .get_data()
                    .apis
                    .registry
                    .enum_key(OWNER, args[0], args[1] as u32)
                {
                    Ok(entry) => entry,
                    Err(error) => return status(error),
                };
            let Some(capacity) = input_count(engine, args[3])? else {
                return Ok(998);
            };
            let units = registry::text_units(&entry, wide);
            if capacity <= units {
                return Ok(234);
            }
            if args[5] != 0 {
                let Some(capacity) = input_count(engine, args[6])? else {
                    return Ok(998);
                };
                if capacity == 0 {
                    return Ok(234);
                }
            }
            let mut writes = vec![
                (args[2], registry::encode_text(&entry, wide, true)),
                (args[3], units.to_le_bytes().to_vec()),
            ];
            if args[5] != 0 {
                writes.push((args[5], registry::encode_text("", wide, true)));
                writes.push((args[6], 0u32.to_le_bytes().to_vec()));
            }
            if args[7] != 0 {
                let time = engine
                    .get_data()
                    .apis
                    .registry
                    .query_info(OWNER, args[0], wide)?
                    .filetime;
                writes.push((args[7], time.to_le_bytes().to_vec()));
            }
            Ok(if outputs(engine, &writes)? { 0 } else { 998 })
        }
        Call::Info { wide } => {
            if args[3] != 0 || (args[1] != 0 && args[2] == 0) {
                return Ok(87);
            }
            ensure!(
                args[10] == 0,
                "Registry security descriptor size is not modeled"
            );
            let info = match engine
                .get_data()
                .apis
                .registry
                .query_info(OWNER, args[0], wide)
            {
                Ok(info) => info,
                Err(error) => return status(error),
            };
            if args[1] != 0 {
                let Some(capacity) = input_count(engine, args[2])? else {
                    return Ok(998);
                };
                if capacity == 0 {
                    return Ok(
                        if outputs(engine, &[(args[2], 0u32.to_le_bytes().to_vec())])? {
                            234
                        } else {
                            998
                        },
                    );
                }
            }
            let mut writes = Vec::new();
            if args[1] != 0 {
                writes.push((args[1], registry::encode_text("", wide, true)));
            }
            for (at, value) in [
                (args[2], 0),
                (args[4], info.subkeys),
                (args[5], info.max_subkey_units),
                (args[6], 0),
                (args[7], info.values),
                (args[8], info.max_value_name_units),
                (args[9], info.max_value_data_bytes),
            ] {
                if at != 0 {
                    writes.push((at, value.to_le_bytes().to_vec()));
                }
            }
            if args[11] != 0 {
                writes.push((args[11], info.filetime.to_le_bytes().to_vec()));
            }
            Ok(if outputs(engine, &writes)? { 0 } else { 998 })
        }
        Call::Close => match engine.get_data_mut().apis.registry.close(OWNER, args[0]) {
            Ok(()) => Ok(0),
            Err(error) => status(error),
        },
    }
}
