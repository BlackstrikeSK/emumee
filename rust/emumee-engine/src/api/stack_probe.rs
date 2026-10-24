//! x64 __chkstk compiler helper. It observes mapped guest stack pages only;
//! it does not grow a stack, alter RSP/RAX, or bypass guest permissions.
use super::*;

const PAGE_BYTES: u64 = 4096;
const MAX_PROBE_BYTES: u64 = emumee_core::kernel_layout::ENTRY_STACK_SIZE;

pub(super) fn call(engine: &mut Unicorn<Trace>, requested: u64) -> Result<u64> {
    ensure!(
        engine.get_data().architecture == Architecture::X64 && engine.get_data().apis.kernel_mode,
        "__chkstk requires the modeled x64 kernel stack"
    );
    ensure!(
        requested <= MAX_PROBE_BYTES,
        "__chkstk request exceeds the bounded kernel stack probe"
    );
    // CALL pushed an eight-byte return address. The caller's pre-CALL RSP is
    // the top of the allocation that its following `sub rsp, rax` will form.
    let entry_sp = uc(engine.reg_read(RegisterX86::RSP))?;
    let top = entry_sp
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("__chkstk caller stack pointer overflow"))?;
    let bottom = top
        .checked_sub(requested)
        .ok_or_else(|| anyhow::anyhow!("__chkstk allocation pointer underflow"))?;
    if requested == 0 {
        return Ok(0);
    }
    // Validate the complete future frame before observing any byte. A missing
    // or unreadable page remains an explicit model stop, not synthetic growth.
    require(engine, bottom, requested, P::READ)?;
    let mut page = top;
    while page > bottom {
        page = page.saturating_sub(PAGE_BYTES).max(bottom);
        byte(engine, page)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::fixtures::{self, ApiFixture};

    fn generated_probe(requested: u32) -> Vec<u8> {
        let mut data = fixtures::api_probe(Architecture::X64, ApiFixture::KernelResolve);
        // First import: ntoskrnl!MmGetSystemRoutineAddress -> __chkstk.
        // The closed fixture's three-entry import table and code stay local
        // to generated test bytes; no submitted sample is patched.
        data[0x700..0x740].fill(0);
        data[0x702..0x702 + b"__chkstk".len()].copy_from_slice(b"__chkstk");
        let mut code = vec![0x48, 0xb8]; // mov rax, requested
        code.extend((requested as u64).to_le_bytes());
        let next = 0x1000 + code.len() + 6;
        code.extend([0xff, 0x15]); // call qword ptr [rip+IAT]
        code.extend((0x2080i32 - next as i32).to_le_bytes());
        code.extend([0x48, 0x3d]); // cmp rax, requested (must be preserved)
        code.extend(requested.to_le_bytes());
        code.extend([0x75, 0]); // jne failure; displacement filled below
        let branch = code.len() - 1;
        code.extend([0x48, 0x29, 0xc4]); // sub rsp, rax
        code.extend([0xc6, 0x04, 0x24, 0x5a]); // mov byte ptr [rsp], 0x5a
        code.extend([0x48, 0x01, 0xc4]); // add rsp, rax
        code.extend([0xb8, 17, 0, 0, 0, 0xc3]); // mov eax, 17; ret
        let failure = code.len();
        code.extend([0xb8, 99, 0, 0, 0, 0xc3]); // mov eax, 99; ret
        code[branch] = (failure - (branch + 1)) as u8;
        assert!(code.len() <= 512);
        data[0x200..0x400].fill(0xcc);
        data[0x200..0x200 + code.len()].copy_from_slice(&code);
        data
    }

    #[test]
    fn x64_ntos_stack_probe_uses_custom_rax_abi_only() {
        let bound = definition(Architecture::X64, "ntoskrnl.exe", "__chkstk");
        assert!(matches!(bound.model, Model::StackProbe));
        assert_eq!((bound.count, bound.returns), (1, T::Void));
        for (arch, module) in [
            (Architecture::X86, "ntoskrnl.exe"),
            (Architecture::X64, "cng.sys"),
            (Architecture::X64, "ntdll.dll"),
        ] {
            assert!(matches!(
                definition(arch, module, "__chkstk").model,
                Model::Unsupported
            ));
        }
    }

    #[test]
    fn generated_x64_prolog_probes_mapped_pages_preserves_rax_and_returns() {
        for requested in [0x1000, 0x2000, 0x4000] {
            let run =
                crate::run_generated_image(&generated_probe(requested), 1000, 1_000_000).unwrap();
            assert_eq!(
                (run.completion_reason, run.guest_entry_return),
                ("entry_return", Some(17))
            );
            let events: Vec<_> = run
                .api_events
                .iter()
                .filter(|e| e.api == "ntoskrnl.__chkstk")
                .collect();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].arguments, vec![requested as u64]);
            assert_eq!(events[0].result, None); // void ABI preserves RAX
            assert_eq!(events[0].error, None);
        }
    }

    #[test]
    fn generated_overdeep_and_over_bound_frames_refuse_without_success() {
        for (requested, expected) in [
            (0x100000, "lacks permission"),
            (0x101000, "exceeds the bounded kernel stack probe"),
        ] {
            let run =
                crate::run_generated_image(&generated_probe(requested), 1000, 1_000_000).unwrap();
            assert_eq!(run.completion_reason, "error");
            assert_eq!(run.guest_entry_return, None);
            let event = run
                .api_events
                .iter()
                .find(|e| e.api == "ntoskrnl.__chkstk")
                .unwrap();
            assert_eq!(event.arguments, vec![requested as u64]);
            assert!(event.error.as_deref().unwrap().contains(expected));
        }
    }
}
