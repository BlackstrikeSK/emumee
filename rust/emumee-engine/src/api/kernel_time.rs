//! Two conversions of supplied signed guest values. The caller is the actual
//! kernel_rtl guard scope: initialized CPL0, current processor IRQL, resident
//! modeled ranges and terminal native-write effects share its authority.
use super::*;
use emumee_core::kernel_time;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Local,
    Fields,
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    let bytes = match call {
        Call::Local => 8,
        Call::Fields => 16,
    };
    // Both complete ranges are checked before consuming input or publishing
    // bytes. No overlap prohibition: the entire source is snapshotted first.
    require(engine, args[0], 8, P::READ)?;
    require(engine, args[1], bytes, P::WRITE)?;
    let input = i64::from_le_bytes(read(engine, args[0], 8)?.try_into().unwrap());
    let output = match call {
        Call::Local => kernel_time::local_time(input, engine.get_data().clock.utc_offset_minutes)?
            .to_le_bytes()
            .to_vec(),
        Call::Fields => kernel_time::time_fields(input)?.encode().to_vec(),
    };
    super::kernel_rtl::write_effect(engine, args[1], &output)?;
    // Void results do not claim a native status. No LastError or clock query.
    Ok(0)
}
/// Closed generated-only configured callers exercise the real validated seed
/// install path. No caller-supplied configuration or sample entry is exposed.
pub(crate) fn fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::TimeFixture,
    budget: u64,
) -> Result<crate::Execution> {
    let offset = kind.configured_offset().ok_or_else(|| {
        anyhow::anyhow!("Kernel time configured fixture requires a fixed generated offset kind")
    })?;
    let mut document: serde_json::Value =
        serde_json::from_slice(&emumee_core::fixtures::configured_document(
            emumee_core::fixtures::ConfiguredFixture::Kernel,
        ))?;
    document["utc_offset_minutes"] = serde_json::json!(offset);
    let validated = emumee_core::fullpersona::decode(
        &serde_json::to_vec(&document)?,
        &emumee_core::fullpersona::ResolveContext::default(),
    )?;
    let configured = crate::configured::Prepared::new(
        validated,
        crate::configured::Request {
            architecture,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )?;
    crate::run_generated_with_fixture_configuration(
        &emumee_core::fixtures::kernel_time_probe(architecture, kind),
        &[],
        budget,
        30_000_000,
        crate::GeneratedConfiguration {
            configured: Some(configured),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(architecture, true)
            .unwrap();
        crate::kernel_cpu::initialize(&mut engine).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x10000, 8192, P::RW, Some(4), "kernel time source tests")
            .unwrap();
        engine
            .mem_map(0x10000, 8192, Prot::READ | Prot::WRITE)
            .unwrap();
        engine.get_data_mut().apis.last_error = 0x12345678;
        engine
    }
    fn invoke(engine: &mut Unicorn<Trace>, call: Call, input: u64, output: u64) -> Result<u64> {
        super::super::kernel_rtl::invoke(
            engine,
            super::super::kernel_rtl::Call::Time(call),
            &[input, output],
        )
    }
    fn clock(engine: &Unicorn<Trace>) -> serde_json::Value {
        serde_json::to_value(&engine.get_data().clock).unwrap()
    }
    #[test]
    fn exact_two_void_stdcall_bindings_remain_ntos_only() {
        for arch in [Architecture::X86, Architecture::X64] {
            for name in ["ExSystemTimeToLocalTime", "RtlTimeToTimeFields"] {
                let binding = super::super::definition(arch, "ntoskrnl.exe", name);
                assert!(matches!(
                    binding.model,
                    Model::KernelRtl(super::super::kernel_rtl::Call::Time(_))
                ));
                assert_eq!(
                    (binding.count, binding.convention, binding.returns),
                    (2, C::Stdcall, T::Void)
                );
                for module in ["hal.dll", "msvcrt.dll", "ntdll.dll"] {
                    assert!(
                        !matches!(
                            super::super::definition(arch, module, name).model,
                            Model::KernelRtl(super::super::kernel_rtl::Call::Time(_))
                        ),
                        "{arch:?} {module}/{name}"
                    );
                }
            }
        }
    }
    #[test]
    fn both_snapshot_before_write_alias_profiles_preserve_clock_and_last_error() {
        for arch in [Architecture::X86, Architecture::X64] {
            for call in [Call::Local, Call::Fields] {
                for delta in [0, 1, 4, -4] {
                    let mut engine = engine(arch);
                    engine.get_data_mut().clock.utc_offset_minutes = 120;
                    engine.mem_write(0x10000, &[0x77; 64]).unwrap();
                    engine.mem_write(0x10010, &(-1i64).to_le_bytes()).unwrap();
                    let before = clock(&engine);
                    let output = (0x10010i64 + delta) as u64;
                    invoke(&mut engine, call, 0x10010, output).unwrap();
                    let expected = match call {
                        Call::Local => 71_999_999_999i64.to_le_bytes().to_vec(),
                        Call::Fields => {
                            vec![0x40, 6, 12, 0, 31, 0, 23, 0, 59, 0, 59, 0, 0xe7, 3, 0, 0]
                        }
                    };
                    assert_eq!(
                        engine.mem_read_as_vec(output, expected.len()).unwrap(),
                        expected,
                        "{arch:?} delta{delta}"
                    );
                    assert_eq!(clock(&engine), before);
                    assert_eq!(engine.get_data().apis.last_error, 0x12345678);
                    assert!(!super::super::kernel_rtl::report(&engine).native_effect_failure);
                }
            }
        }
    }
    #[test]
    fn arithmetic_calendar_and_range_failures_leave_all_output_bytes_unchanged() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (call, ticks, output, error) in [
                (Call::Local, i64::MIN, 0x10040, "signed local time overflow"),
                (
                    Call::Fields,
                    -504_911_232_000_000_001,
                    0x10040,
                    "calendar outside legacy",
                ),
                (
                    Call::Fields,
                    2_650_467_744_000_000_000,
                    0x10040,
                    "calendar outside legacy",
                ),
                (Call::Local, 0, 0x11ffc, "API guest range"),
                (Call::Fields, 0, 0x11ff8, "API guest range"),
            ] {
                let mut engine = engine(arch);
                engine.mem_write(0x10040, &[0x77; 24]).unwrap();
                engine.mem_write(0x10000, &ticks.to_le_bytes()).unwrap();
                engine.mem_write(0x11ff0, &[0x77; 16]).unwrap();
                let before = clock(&engine);
                assert!(
                    invoke(&mut engine, call, 0x10000, output)
                        .unwrap_err()
                        .to_string()
                        .contains(error),
                    "{arch:?} {ticks}"
                );
                assert_eq!(engine.mem_read_as_vec(0x10040, 24).unwrap(), [0x77; 24]);
                assert_eq!(engine.mem_read_as_vec(0x11ff0, 16).unwrap(), [0x77; 16]);
                assert_eq!(clock(&engine), before);
                assert_eq!(engine.get_data().apis.last_error, 0x12345678);
                assert!(!super::super::kernel_rtl::report(&engine).native_effect_failure);
            }
        }
    }
    #[test]
    fn readonly_outputs_fail_preflight_without_native_effect() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            engine.mem_write(0x10000, &0i64.to_le_bytes()).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .protect(0x11000, 4096, P::READ)
                .unwrap();
            engine.mem_protect(0x11000, 4096, Prot::READ).unwrap();
            assert!(
                invoke(&mut engine, Call::Fields, 0x10000, 0x11000).is_err(),
                "{arch:?}"
            );
            assert!(!super::super::kernel_rtl::report(&engine).native_effect_failure);
        }
    }
    #[test]
    fn genuine_opaque_process_output_uses_existing_protected_object_guard() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            super::super::kernel_objects::initialize(&mut engine).unwrap();
            let object = super::super::kernel_objects::call(
                &mut engine,
                super::super::kernel_objects::Call::CurrentProcess,
                &[],
            )
            .unwrap();
            engine.mem_write(0x10000, &0i64.to_le_bytes()).unwrap();
            let before = clock(&engine);
            assert!(
                invoke(&mut engine, Call::Fields, 0x10000, object)
                    .unwrap_err()
                    .to_string()
                    .contains("private kernel")
            );
            assert!(!super::super::kernel_rtl::report(&engine).native_effect_failure);
            assert_eq!(clock(&engine), before);
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
        }
    }
    #[test]
    fn real_irql_resident_conversion_and_paged_pool_refusal_use_actual_cpu_authority() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(arch);
            engine.mem_write(0x10000, &0i64.to_le_bytes()).unwrap();
            let pool = super::super::pool::call(
                &mut engine,
                Model::PoolTagged,
                &[1, 16, u32::from_le_bytes(*b"Time").into()],
            )
            .unwrap();
            engine.mem_write(pool, &0i64.to_le_bytes()).unwrap();
            if arch == Architecture::X64 {
                engine.reg_write(RegisterX86::CR8, 2).unwrap();
            } else {
                let pcr = crate::kernel_cpu::current_pcr(&engine).unwrap();
                engine.mem_write(pcr + 0x24, &[2]).unwrap();
            }
            invoke(&mut engine, Call::Fields, 0x10000, 0x10040).unwrap();
            assert_eq!(engine.get_data().apis.kernel.save().0, 2);
            for (input, output) in [(pool, 0x10040), (0x10000, pool)] {
                assert!(
                    invoke(&mut engine, Call::Fields, input, output)
                        .unwrap_err()
                        .to_string()
                        .contains("paged Pool access above APC_LEVEL")
                );
            }
            assert_eq!(engine.get_data().apis.pool.total_allocations, 1);
            assert_eq!(engine.get_data().apis.pool.total_frees, 0);
        }
    }
    #[test]
    fn failed_native_publication_is_terminal_in_the_existing_rtl_effect_authority() {
        let mut engine = engine(Architecture::X64);
        engine.mem_write(0x10000, &0i64.to_le_bytes()).unwrap();
        engine.mem_unmap(0x11000, 4096).unwrap(); // Deliberately diverge native map from valid model plan.
        assert!(invoke(&mut engine, Call::Fields, 0x10000, 0x11000).is_err());
        assert!(super::super::kernel_rtl::report(&engine).native_effect_failure);
        assert!(
            invoke(&mut engine, Call::Local, 0x10000, 0x10040)
                .unwrap_err()
                .to_string()
                .contains("cannot resume")
        );
    }
}
