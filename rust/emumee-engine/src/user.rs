//! Native user PE execution; caller owns containment and immutable input binding.
use super::*;
use emumee_core::{fullpersona, persona::ProcessConfig, user_input::Request};

pub fn run(request: &Request, bytes: &[u8], persona: Option<&[u8]>) -> Result<Execution> {
    run_staged(request, bytes, persona, &[])
}

pub fn run_staged(
    request: &Request,
    bytes: &[u8],
    persona: Option<&[u8]>,
    staged: &[Vec<u8>],
) -> Result<Execution> {
    let prepared = prepare(request, bytes, persona, staged)?;
    let companions = request
        .staged
        .iter()
        .zip(staged)
        .filter(|(file, _)| file.kind == emumee_core::user_input::InputKind::Companion)
        .map(|(file, bytes)| {
            (
                file.guest_path.rsplit('\\').next().unwrap().to_owned(),
                bytes.clone(),
            )
        })
        .collect::<Vec<_>>();
    let companion_paths = request
        .staged
        .iter()
        .filter(|file| file.kind == emumee_core::user_input::InputKind::Companion)
        .map(|file| file.guest_path.clone())
        .collect();
    run_generated_with_fixture_configuration(
        bytes,
        &companions,
        request.max_instructions,
        request.timeout_us,
        GeneratedConfiguration {
            submitted_user: true,
            all_exports: request.invocation.all_exports,
            submitted_companion_paths: companion_paths,
            configured: Some(prepared),
            ..Default::default()
        },
    )
}

pub fn preflight(
    request: &Request,
    bytes: &[u8],
    persona: Option<&[u8]>,
    staged: &[Vec<u8>],
) -> Result<()> {
    prepare(request, bytes, persona, staged).map(drop)
}

fn prepare(
    request: &Request,
    bytes: &[u8],
    persona: Option<&[u8]>,
    staged: &[Vec<u8>],
) -> Result<configured::Prepared> {
    request
        .verify_staged(bytes, staged)
        .map_err(anyhow::Error::msg)?;
    let pe = request.verify_input(bytes).map_err(anyhow::Error::msg)?;
    request
        .verify_persona(persona)
        .map_err(anyhow::Error::msg)?;
    let validated = request
        .resolve_persona(persona.unwrap_or_else(|| fullpersona::default_document().as_bytes()))?;
    let mut prepared = configured::Prepared::new(
        validated,
        configured::Request {
            architecture: pe.sample.architecture,
            kernel: false,
            initial_processor: 0,
            process: Some(ProcessConfig {
                image_path: request.guest_path(),
                arguments: request.arguments.clone(),
                force_quotes: request.invocation.force_quotes.clone(),
                command_line: None,
                current_directory: None,
                environment_overrides: request.invocation.environment.clone(),
            }),
            budget: request.max_instructions,
            timeout_us: request.timeout_us,
        },
    )?;
    prepared.bind_submitted_user()?;
    let files = request
        .staged
        .iter()
        .zip(staged)
        .map(|(file, bytes)| emumee_core::filesystem::SeedFile {
            path: &file.guest_path,
            bytes,
        })
        .collect::<Vec<_>>();
    prepared.seed_submitted_files(&files)?;
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{
        fixtures::{self, ApiFixture, LoaderFixture},
        report_bundle::digest,
        user_input::PROFILE,
    };
    fn request(bytes: &[u8], name: &str, budget: u64) -> Request {
        Request {
            schema: 1,
            profile: PROFILE.into(),
            run_id: "20261029T120000Z-12345678".into(),
            input_sha256: digest(bytes),
            input_size: bytes.len() as u64,
            module_name: name.into(),
            arguments: vec!["two words".into(), "tail\\".into()],
            max_instructions: budget,
            timeout_us: 30_000_000,
            persona_sha256: None,
            clock_utc_filetime: 134377488000000000,
            staged: vec![],
            invocation: Default::default(),
        }
    }
    fn fixture(arch: Architecture, kind: &str) -> (Vec<u8>, &'static str) {
        match kind {
            "dll" => (
                fixtures::native_loader_probe(arch, LoaderFixture::RootDll).0,
                "sample.dll",
            ),
            "tls" => (
                fixtures::native_loader_probe(arch, LoaderFixture::RootTls).0,
                "sample.exe",
            ),
            "file" => {
                let mut bytes = fixtures::api_probe(arch, ApiFixture::FileRoundTripW);
                // The configured VFS requires real parent directories; C:\workspace
                // belongs to the old unconfigured fixture, not this persona.
                let path: Vec<u8> = "C:\\rust-fixture.bin\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                bytes[0xf00..0xf80].fill(0);
                bytes[0xf00..0xf00 + path.len()].copy_from_slice(&path);
                (bytes, "sample.exe")
            }
            "unsupported" | "exit" => {
                let mut bytes = fixtures::api_probe(arch, ApiFixture::Unsupported);
                bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
                bytes[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
                let at = bytes
                    .windows(13)
                    .position(|w| w == b"ntoskrnl.exe\0")
                    .unwrap();
                bytes[at..at + 13].copy_from_slice(b"kernel32.dll\0");
                if kind == "exit" {
                    let symbol = b"EmumeeUnimplementedFixtureApi\0";
                    let at = bytes
                        .windows(symbol.len())
                        .position(|w| w == symbol)
                        .unwrap();
                    bytes[at..at + symbol.len()].fill(0);
                    bytes[at..at + 12].copy_from_slice(b"ExitProcess\0");
                    let pe = PeImage::parse(&bytes, "sample.exe").unwrap();
                    let iat = pe.image_base + u64::from(pe.imports[0].iat_rva);
                    let mut code = if arch == Architecture::X64 {
                        let mut c = vec![0xb9, 0x00, 0x01, 0, 0, 0x48, 0xb8];
                        c.extend(iat.to_le_bytes());
                        c.extend([0xff, 0x10]);
                        c
                    } else {
                        let mut c = vec![0x68, 0x00, 0x01, 0, 0, 0xff, 0x15];
                        c.extend((iat as u32).to_le_bytes());
                        c
                    };
                    code.extend([0xcc, 0xeb, 0xfe]);
                    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
                }
                (bytes, "sample.exe")
            }
            _ => {
                let mut bytes = fixtures::counted_driver(arch, 1000);
                bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
                bytes[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
                (bytes, "sample.exe")
            }
        }
    }
    #[test]
    fn submitted_user_executes_actual_exe_dll_tls_and_files_in_both_architectures() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in ["exe", "dll", "tls", "file", "unsupported", "exit"] {
                let (bytes, name) = fixture(arch, kind);
                if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                    let directory = std::path::PathBuf::from(root).join(format!("{arch:?}-{kind}"));
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(directory.join(name), &bytes).unwrap();
                }
                let request = request(&bytes, name, 20000);
                let result = run(&request, &bytes, None).unwrap();
                if kind == "unsupported" {
                    assert!(result.error.is_some());
                    assert!(result.guest_entry_return.is_none());
                    continue;
                }
                assert_eq!(result.error, None, "{arch:?}/{kind}: {result:#?}");
                if kind == "exit" {
                    assert_eq!(result.completion_reason, "process_exit");
                    assert_eq!(result.process_exit_code, Some(256));
                    assert!(result.guest_entry_return.is_none());
                } else {
                    assert_eq!(result.completion_reason, "entry_return", "{result:#?}");
                }
                if kind == "exe" {
                    assert_eq!(result.guest_entry_return, Some(1000));
                }
                if kind == "file" {
                    assert_eq!(
                        result.guest_entry_return,
                        Some(u32::from_le_bytes(*b"RUST") as u64)
                    );
                    assert!(!result.artifacts.is_empty());
                }
                let config = serde_json::to_value(&result).unwrap()["configuration"].clone();
                assert_eq!(config["generated_only"], false, "{config}");
                let mut partial = request.clone();
                partial.max_instructions = 1;
                let stopped = run(&partial, &bytes, None).unwrap();
                assert_eq!(stopped.instruction_count, 1);
                assert!(stopped.guest_entry_return.is_none());
            }
        }
    }
    #[test]
    fn submitted_user_rejects_changed_bytes_drivers_and_persona_substitution() {
        let (bytes, name) = fixture(Architecture::X64, "exe");
        let mut r = request(&bytes, name, 20000);
        assert!(run(&r, b"changed", None).is_err());
        assert!(run(&r, &bytes, Some(b"{}")).is_err());
        let driver = fixtures::counted_driver(Architecture::X64, 1);
        r.input_sha256 = digest(&driver);
        r.input_size = driver.len() as u64;
        assert!(run(&r, &driver, None).is_err());
    }
}

#[cfg(test)]
#[path = "user_staging_tests.rs"]
mod staging_tests;
