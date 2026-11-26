//! Guest-only frozen 32-bit interlocked memory operations.
//! Callers cannot interleave inside the synchronous API memory transition.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum Call {
    Increment,
    Decrement,
    ExchangeAdd,
    Exchange,
    CompareExchange,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if module != "kernel32" {
        return None;
    }
    let canonical = name
        .strip_suffix('A')
        .or_else(|| name.strip_suffix('W'))
        .unwrap_or(name);
    Some(match canonical {
        "InterlockedIncrement" => (Call::Increment, 1, T::U32),
        "InterlockedDecrement" => (Call::Decrement, 1, T::U32),
        "InterlockedExchangeAdd" => (Call::ExchangeAdd, 2, T::U32),
        "InterlockedExchange" => (Call::Exchange, 2, T::U32),
        "InterlockedCompareExchange" => (Call::CompareExchange, 3, T::U32),
        _ => return None,
    })
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "Frozen user interlocked operations are outside the kernel runtime profile"
    );
    let count = match call {
        Call::Increment | Call::Decrement => 1,
        Call::ExchangeAdd | Call::Exchange => 2,
        Call::CompareExchange => 3,
    };
    ensure!(
        args.len() == count,
        "Interlocked argument count differs from binding"
    );
    let old = u32::from_le_bytes(read(engine, args[0], 4)?.try_into().unwrap());
    let (result, new) = match call {
        Call::Increment => {
            let new = old.wrapping_add(1);
            (new, Some(new))
        }
        Call::Decrement => {
            let new = old.wrapping_sub(1);
            (new, Some(new))
        }
        Call::ExchangeAdd => (old, Some(old.wrapping_add(args[1] as u32))),
        Call::Exchange => {
            // The frozen handler converts the complete native-word argument
            // to four bytes and fails on overflow rather than truncating it.
            ensure!(
                args[1] <= u32::MAX as u64,
                "Frozen interlocked integer conversion exceeds four bytes"
            );
            (old, Some(args[1] as u32))
        }
        Call::CompareExchange => {
            // Compare the full argument. A failed comparison does not convert
            // or validate the unused replacement, nor attempt a write.
            let new = if u64::from(old) == args[2] {
                ensure!(
                    args[1] <= u32::MAX as u64,
                    "Frozen interlocked integer conversion exceeds four bytes"
                );
                Some(args[1] as u32)
            } else {
                None
            };
            (old, new)
        }
    };
    if let Some(new) = new {
        require(engine, args[0], 4, P::WRITE)?;
        crate::cpu::write(engine, args[0], &new.to_le_bytes())?;
    }
    Ok(u64::from(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::report_bundle::digest;

    #[test]
    fn frozen_interlocked_vectors_match_returns_memory_and_error_preservation() {
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("interlocked_reference.json")).unwrap();
        assert_eq!(reference["cases"].as_array().unwrap().len(), 378);
        assert_eq!(
            reference["source_sha256"],
            digest(include_bytes!(
                "../../../../.venv/Lib/site-packages/speakeasy/winenv/api/usermode/kernel32.py"
            ))
        );
        assert_eq!(reference["contracts"].as_array().unwrap().len(), 10);
        for case in reference["cases"].as_array().unwrap() {
            let arch = if case["architecture"] == "x86" {
                Architecture::X86
            } else {
                Architecture::X64
            };
            let mut engine = crate::new_engine(arch).unwrap();
            engine
                .mem_map(0x26000000, 0x10000, Prot::READ | Prot::WRITE)
                .unwrap();
            let readable = case
                .get("synthetic_access")
                .and_then(|v| v["readable"].as_bool())
                .unwrap_or(true);
            let writable = case
                .get("synthetic_access")
                .and_then(|v| v["writable"].as_bool())
                .unwrap_or(true);
            let permissions = match (readable, writable) {
                (true, true) => P::RW,
                (true, false) => P::READ,
                (false, true) => P::WRITE,
                _ => P::NONE,
            };
            engine
                .get_data_mut()
                .apis
                .memory
                .map(
                    0x26000000,
                    0x10000,
                    permissions,
                    Some(4),
                    "frozen interlocked arena",
                )
                .unwrap();
            let mut bytes = vec![0xa5; 0x10000];
            bytes[32..36].copy_from_slice(&(case["old"].as_u64().unwrap() as u32).to_le_bytes());
            engine.mem_write(0x26000000, &bytes).unwrap();
            engine.get_data_mut().apis.last_error = 0x12345678;
            let (call, argc, _) = definition("kernel32", case["export"].as_str().unwrap()).unwrap();
            let args = case["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(argc, args.len());
            let actual = invoke(&mut engine, call, &args);
            if case["error"].is_null() {
                assert_eq!(actual.unwrap(), case["result"].as_u64().unwrap(), "{case}");
            } else {
                let error = actual.unwrap_err().to_string();
                if case["error"] == "OverflowError" {
                    assert!(error.contains("integer conversion"), "{error}");
                }
            }
            assert_eq!(engine.get_data().apis.last_error, 0x12345678, "{case}");
            let observed = engine.mem_read_as_vec(0x26000000, 0x10000).unwrap();
            assert_eq!(
                digest(&observed),
                case["arena_sha256"].as_str().unwrap(),
                "{case}"
            );
        }
    }

    #[test]
    fn interlocked_lookup_is_finite_and_cannot_grant_kernel_authority() {
        for name in [
            "InterlockedCompareExchange",
            "InterlockedCompareExchangeA",
            "InterlockedCompareExchangeW",
        ] {
            let (_, argc, returns) = definition("kernel32", name).unwrap();
            assert_eq!(argc, 3);
            assert_eq!(returns, T::U32);
        }
        assert!(definition("kernel32", "InterlockedCompareExchangeWW").is_none());
        assert!(definition("kernel32", "InventedAtomicSuccess").is_none());
        assert!(definition("ntoskrnl", "InterlockedIncrement").is_none());
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine.get_data_mut().apis.last_error = 0x12345678;
        let error = invoke(&mut engine, Call::Increment, &[0x26000020])
            .unwrap_err()
            .to_string();
        assert!(error.contains("kernel runtime profile"));
        assert_eq!(engine.get_data().apis.last_error, 0x12345678);
    }
}
