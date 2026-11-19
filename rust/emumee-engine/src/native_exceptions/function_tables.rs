//! Bounded guest runtime-function tables. No host unwinder or code registration.
use super::*;
use crate::api;
#[derive(Clone, Copy)]
pub(crate) enum Call {
    Add,
    Delete,
    Lookup,
}
struct Registration {
    table: u64,
    raw: Vec<u8>,
    image: Image,
}
#[derive(Default)]
pub(super) struct State {
    registrations: Vec<Registration>,
}
fn read_bytes(engine: &Unicorn<Trace>, address: u64, size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; size];
    read(engine, address, &mut bytes)?;
    Ok(bytes)
}
pub(crate) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().architecture == Architecture::X64
            && engine.get_data().apis.user_bootstrap.is_some(),
        "Runtime tables require an AMD64 user process"
    );
    match call {
        Call::Add => {
            let state = &engine.get_data().native_exceptions.function_tables;
            let count = u64::from(args[1] as u32);
            if count == 0
                || count > 4096
                || args[0] & 3 != 0
                || state.registrations.len() >= 64
                || state
                    .registrations
                    .iter()
                    .map(|r| r.image.functions.len())
                    .sum::<usize>()
                    + count as usize
                    > 65536
                || state.registrations.iter().any(|r| r.table == args[0])
            {
                return Ok(0);
            }
            let result = (|| -> Result<Registration> {
                let base = args[2];
                let end = engine
                    .get_data()
                    .apis
                    .memory
                    .regions()
                    .filter_map(|r| r.base.checked_add(r.size))
                    .filter(|end| *end > base && *end - base <= u32::MAX as u64)
                    .max()
                    .context("Runtime table base has no owned mapped span")?;
                let raw = read_bytes(engine, args[0], count as usize * 12)?;
                let mut functions: Vec<unwind::Function> = Vec::new();
                for entry in raw.chunks_exact(12) {
                    let function = unwind::Function {
                        begin: u32::from_le_bytes(entry[..4].try_into().unwrap()),
                        end: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                        unwind: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
                    };
                    ensure!(
                        function.begin < function.end
                            && function.end as u64 <= end - base
                            && function.unwind != 0
                            && function.unwind & 3 == 0
                            && (function.unwind as u64) < end - base,
                        "Invalid guest runtime-function bounds"
                    );
                    ensure!(
                        functions
                            .last()
                            .is_none_or(|last| last.end <= function.begin),
                        "Unsorted/overlapping runtime functions"
                    );
                    api::require_without_timer_guard(
                        engine,
                        base + function.begin as u64,
                        (function.end - function.begin) as u64,
                        P::EXECUTE,
                    )?;
                    require(engine, base + function.unwind as u64, 4, P::READ)?;
                    functions.push(function);
                }
                let mut ranges = state
                    .registrations
                    .iter()
                    .flat_map(|prior| {
                        prior.image.functions.iter().map(|old| {
                            (
                                prior.image.base + u64::from(old.begin),
                                prior.image.base + u64::from(old.end),
                            )
                        })
                    })
                    .chain(functions.iter().map(|function| {
                        (
                            base + u64::from(function.begin),
                            base + u64::from(function.end),
                        )
                    }))
                    .collect::<Vec<_>>();
                ranges.sort_unstable();
                ensure!(
                    ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
                    "Overlapping registered runtime functions"
                );
                Ok(Registration {
                    table: args[0],
                    raw,
                    image: Image {
                        base,
                        size: (end - base) as u32,
                        functions,
                    },
                })
            })();
            match result {
                Ok(registration) => {
                    engine
                        .get_data_mut()
                        .native_exceptions
                        .function_tables
                        .registrations
                        .push(registration);
                    Ok(1)
                }
                Err(_) => Ok(0),
            }
        }
        Call::Delete => {
            let state = &mut engine.get_data_mut().native_exceptions.function_tables;
            if let Some(index) = state.registrations.iter().position(|r| r.table == args[0]) {
                state.registrations.remove(index);
                Ok(1)
            } else {
                Ok(0)
            }
        }
        Call::Lookup => {
            api::require_without_timer_guard(engine, args[1], 8, P::WRITE)?;
            let Ok((image, table)) = super::image(engine, args[0]) else {
                return Ok(0);
            };
            let Some(function) = image.lookup(args[0]) else {
                return Ok(0);
            };
            let index = image
                .functions
                .binary_search_by_key(&function.begin, |f| f.begin)
                .unwrap();
            crate::cpu::write(engine, args[1], &image.base.to_le_bytes())?;
            Ok(table + index as u64 * 12)
        }
    }
}
pub(super) fn image(engine: &Unicorn<Trace>, pc: u64) -> Result<Option<(Image, u64)>> {
    for registration in &engine
        .get_data()
        .native_exceptions
        .function_tables
        .registrations
    {
        if registration.image.lookup(pc).is_some() {
            ensure!(
                read_bytes(engine, registration.table, registration.raw.len())? == registration.raw,
                "Registered runtime-function table changed before deletion"
            );
            return Ok(Some((registration.image.clone(), registration.table)));
        }
    }
    Ok(None)
}

pub(super) fn count(engine: &Unicorn<Trace>) -> usize {
    engine
        .get_data()
        .native_exceptions
        .function_tables
        .registrations
        .len()
}
