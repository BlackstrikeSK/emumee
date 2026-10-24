use super::*;
fn context() -> ResolveContext {
    ResolveContext {
        clock_seed: Some(ClockSeed {
            utc_filetime: validate::timestamp("2026-10-18T12:00:00Z", "test", false).unwrap(),
            source: ClockSource::Fixed,
            source_id: "generated-fixed-test-seed".into(),
        }),
    }
}
#[test]
fn explicit_code_integrity_options_are_optional_bounded_and_bind_the_persona() {
    let baseline = resolve(json!({})).unwrap();
    assert!(
        baseline.effective_json()["boot_config"]
            .get("code_integrity_options")
            .is_none()
    );
    let selected = resolve(json!({"boot_config":{"code_integrity_options":0xe001}})).unwrap();
    assert_eq!(
        selected.effective_json()["boot_config"]["code_integrity_options"],
        0xe001
    );
    assert_ne!(selected.sha256(), baseline.sha256());
    assert!(resolve(json!({"boot_config":{"code_integrity_options":null}})).is_ok());
    for value in [
        json!(-1),
        json!(4294967296u64),
        json!(true),
        json!(1.5),
        json!("1"),
    ] {
        assert!(resolve(json!({"boot_config":{"code_integrity_options":value}})).is_err());
    }
}
fn resolve(value: Value) -> Result<ValidatedPersona> {
    decode(&serde_json::to_vec(&value).unwrap(), &context())
}
#[test]
fn explicit_cpuid_observations_are_bounded_and_reach_cpu_projection() {
    let leaf = json!({"function":1,"subleaf":0,"eax":526018,"ebx":1050624,"ecx":4294636431u32,"edx":3219913727u32});
    let persona = resolve(json!({"cpu":{"cpuid_overrides":[leaf.clone()]}})).unwrap();
    assert_eq!(
        persona.prepare().cpu.leaf(1, 0, 0),
        [526018, 1050624, 4294636431, 3219913727]
    );
    assert!(resolve(json!({"cpu":{"cpuid_overrides":[leaf.clone(),leaf]}})).is_err());
    assert!(resolve(json!({"cpu":{"cpuid_overrides":[{"function":1,"subleaf":0,"eax":-1,"ebx":0,"ecx":0,"edx":0}]}})).is_err());
}
#[test]
fn explicit_virtual_directories_seed_only_directories_and_bind_the_seed() {
    let baseline = resolve(json!({})).unwrap();
    let guest_path = r"C:\Program Files\Fixture Vendor\Logs";
    let added = resolve(json!({"virtual_directories":[guest_path]})).unwrap();
    assert!(!default_document().contains("virtual_directories"));
    assert!(
        baseline
            .effective_json()
            .get("virtual_directories")
            .is_none()
    );
    assert_ne!(baseline.sha256(), added.sha256());
    assert_ne!(
        baseline.seed_manifest().sha256(),
        added.seed_manifest().sha256()
    );
    assert!(
        added
            .seed_manifest()
            .directories()
            .iter()
            .any(|path| { path.eq_ignore_ascii_case(guest_path) })
    );
    let prepared = added.prepare();
    assert_eq!(
        prepared.filesystem.metadata(guest_path).unwrap().attributes & 0x10,
        0x10
    );
    assert_eq!(prepared.filesystem.contents(guest_path).unwrap(), None);
    assert!(
        prepared
            .filesystem
            .metadata(r"C:\Program Files\Fixture Vendor\Logs\absent.log")
            .is_err()
    );
    assert_eq!(
        baseline.seed_manifest().files().len(),
        added.seed_manifest().files().len()
    );
    assert!(added.projection().data.pending.iter().any(|field| {
        field.path == "virtual_directories" && field.reason.contains("seed input")
    }));
}
#[test]
fn absent_virtual_directories_preserve_legacy_authority_and_empty_list_is_noop_for_seed() {
    let baseline = resolve(json!({})).unwrap();
    let empty = resolve(json!({"virtual_directories":[]})).unwrap();
    assert!(
        baseline
            .effective_json()
            .get("virtual_directories")
            .is_none()
    );
    assert_ne!(baseline.sha256(), empty.sha256());
    assert_eq!(
        baseline.seed_manifest().sha256(),
        empty.seed_manifest().sha256()
    );
    assert_eq!(
        baseline.seed_manifest().canonical_bytes(),
        empty.seed_manifest().canonical_bytes()
    );
    assert_eq!(
        baseline.seed_manifest().directories(),
        empty.seed_manifest().directories()
    );
}
#[test]
fn virtual_directories_reject_aliases_invalid_shapes_and_file_collisions() {
    for bad in [
        json!({"virtual_directories":"C:\\Logs"}),
        json!({"virtual_directories":[false]}),
        json!({"virtual_directories":[r"D:\Logs"]}),
        json!({"virtual_directories":[r"\\host\share\Logs"]}),
        json!({"virtual_directories":[r"C:\Logs",r"c:\logs"]}),
        json!({"virtual_directories":[r"C:\Logs",r"C:\Other\..\Logs"]}),
        json!({"virtual_directories":[r"C:\Alias"],"virtual_files":[{"path":r"C:\Alias","text":"x"}]}),
        json!({"virtual_directories":[r"C:\Alias\Child"],"virtual_files":[{"path":r"C:\Alias","text":"x"}]}),
    ] {
        assert!(
            resolve(bad.clone()).is_err(),
            "accepted invalid directory seed: {bad}"
        );
    }
    let many = vec![r"C:\Logs"; 513];
    assert!(resolve(json!({"virtual_directories":many})).is_err());
}
#[test]
fn pinned_pure_legacy_corpus_checks_actual_complete_effective_documents() {
    let corpus: Value =
        serde_json::from_str(include_str!("../fullpersona_assets/corpus.json")).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for case in cases {
        let result = resolve(case["overrides"].clone());
        if case["valid"] == true {
            let got = result.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
            assert_eq!(got.effective_json(), &case["effective"], "{}", case["name"]);
            assert!(!got.projection().data.engine_applied);
            assert!(got.projection().data.pending.len() >= 42);
            let ready = got.prepare();
            assert_eq!(ready.filesystem.storage_report().open_handles, 0);
            assert!(ready.filesystem.metadata(r"C:\workspace").is_err());
        } else {
            assert!(
                result.is_err(),
                "legacy-invalid case accepted: {}",
                case["name"]
            );
        }
    }
}
#[test]
fn canonical_digests_bind_effective_state_projection_seed_bytes_and_clock_provenance() {
    let a = decode(br#"{"hostname":"HOST-X","cpu":{"cores":8}}"#, &context()).unwrap();
    let b = decode(br#"{"cpu":{"cores":8},"hostname":"HOST-X"}"#, &context()).unwrap();
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_ne!(a.input_sha256(), b.input_sha256());
    assert_eq!(a.sha256(), b.sha256());
    assert_eq!(a.projection().sha256, b.projection().sha256);
    assert_eq!(a.seed_manifest().sha256(), b.seed_manifest().sha256());
    assert_eq!(
        a.seed_manifest().sha256(),
        digest(a.seed_manifest().canonical_bytes())
    );
    let mut other = context();
    other.clock_seed.as_mut().unwrap().source_id = "different-recorded-controller-seed".into();
    let c = decode(br#"{"hostname":"HOST-X","cpu":{"cores":8}}"#, &other).unwrap();
    assert_eq!(a.sha256(), c.sha256());
    assert_ne!(a.projection().sha256, c.projection().sha256);
    let a =
        resolve(json!({"registry_keys":[],"virtual_files":[{"path":"C:\\A.bin","base64":"AAEC"}]}))
            .unwrap();
    let b =
        resolve(json!({"registry_keys":[],"virtual_files":[{"path":"C:\\A.bin","base64":"AAED"}]}))
            .unwrap();
    assert_ne!(a.seed_manifest().sha256(), b.seed_manifest().sha256());
    assert_ne!(a.projection().sha256, b.projection().sha256);
    let a = resolve(json!({"processes":["a.exe","b.exe"]})).unwrap();
    let b = resolve(json!({"processes":["b.exe","a.exe"]})).unwrap();
    assert_ne!(a.sha256(), b.sha256());
    assert_ne!(a.seed_manifest().sha256(), b.seed_manifest().sha256());
}
#[test]
fn explicit_clock_seed_has_no_host_fallback_and_gregorian_offsets_have_real_boundaries() {
    assert!(decode(b"{}", &ResolveContext::default()).is_err());
    let t = validate::timestamp("2026-10-18T12:00:00Z", "test", false).unwrap();
    assert_eq!(
        validate::timestamp("2026-10-18T14:00:00+02:00", "test", false).unwrap(),
        t
    );
    let p = decode(br#"{"clock_utc":"2026-10-18T14:00:00+02:00"}"#, &context()).unwrap();
    assert_eq!(p.effective_json()["clock_utc"], "2026-10-18T12:00:00Z");
    assert!(decode(br#"{"clock_utc":"2026-10-18T12:00:01Z"}"#, &context()).is_err());
    for valid in [
        "2000-02-29T00:00:00Z",
        "1601-01-01T00:00:00Z",
        "2026-10-18T12:00:00.1234567Z",
    ] {
        let t = validate::timestamp(valid, "test", false).unwrap();
        assert_eq!(
            validate::timestamp(&validate::format_filetime(t).unwrap(), "test", false).unwrap(),
            t
        );
    }
    for invalid in [
        "1900-02-29T00:00:00Z",
        "2026-10-18T12:00:00",
        "2026-10-18T12:00:60Z",
        "2026-10-18T12:00:00.12345678Z",
        "2026-10-18T12:00:00+14:01",
    ] {
        assert!(
            validate::timestamp(invalid, "test", false).is_err(),
            "{invalid}"
        );
    }
}
#[test]
fn strict_schema_rejects_duplicates_unknown_fields_malformed_identity_paths_and_authority_claims() {
    for raw in [
        br#"{"hostname":"A","hostname":"B"}"#.as_slice(),
        br#"{"cpu":{"cores":6,"cores":8}}"#.as_slice(),
        br#"{"engine_applied":true}"#.as_slice(),
        br#"{"cpu":{"cores":true}}"#.as_slice(),
        br#"{"cpu":{"cores":6.0}}"#.as_slice(),
    ] {
        assert!(decode(raw, &context()).is_err());
    }
    for bad in [
        json!({"user_sid":"S-1-5-4294967296"}),
        json!({"user_sid":"S-1-+5-1"}),
        json!({"current_dir":"C:é"}),
        json!({"current_dir":"D:\\Guest"}),
        json!({"user_name":"bad\\name"}),
        json!({"timezone":"bad/name"}),
        json!({"clock_utc":false}),
        json!({"uptime_ms":true}),
        json!({"network_adapter":{"unrecognized":1}}),
    ] {
        assert!(resolve(bad.clone()).is_err(), "{bad}");
    }
}
#[test]
fn custom_empty_authority_suppresses_all_automatic_seed_injection_and_real_registry_bytes_are_preserved()
 {
    let empty = resolve(json!({"registry_keys":[],"virtual_files":[]})).unwrap();
    assert!(empty.seed_manifest().files().is_empty());
    assert!(empty.seed_manifest().registry().is_empty());
    assert!(!empty.seed_manifest().directories().is_empty());
    let value = json!({"registry_keys":[{"path":"HKCU\\Software\\Probe","values":[{"name":"default","type":"REG_SZ","data":"é\u{0}"},{"name":"Raw","type":"REG_BINARY","data":"hex:00 01\tfeff"},{"name":"Multi","type":"REG_MULTI_SZ","data":"a\u{0}b\u{0}"},{"name":"Number","type":"REG_DWORD","data":"0xff"},{"name":"Wide","type":"REG_QWORD","data":"0xffffffffffffffff"}]}],"virtual_files":[{"path":"C:\\Exact.bin","base64":"AAECAw=="}]});
    let got = resolve(value).unwrap();
    let mut state = got.into_prepared();
    assert_eq!(
        state.filesystem.contents(r"C:\Exact.bin").unwrap().unwrap(),
        [0, 1, 2, 3]
    );
    let key = state
        .registry
        .open(
            1024,
            crate::registry::HKCU,
            r"Software\Probe",
            crate::registry::KEY_READ,
        )
        .unwrap();
    assert_eq!(
        state
            .registry
            .query_value(1024, key, "", true)
            .unwrap()
            .data,
        vec![0xe9, 0, 0, 0]
    );
    assert_eq!(
        state
            .registry
            .query_value(1024, key, "Raw", true)
            .unwrap()
            .data,
        vec![0, 1, 0xfe, 0xff]
    );
    assert_eq!(
        state
            .registry
            .query_value(1024, key, "Number", true)
            .unwrap()
            .data,
        255u32.to_le_bytes()
    );
    assert_eq!(
        state
            .registry
            .query_value(1024, key, "Wide", true)
            .unwrap()
            .data,
        u64::MAX.to_le_bytes()
    );
    assert_eq!(
        state
            .registry
            .query_value(1024, key, "Multi", true)
            .unwrap()
            .data,
        vec![97, 0, 0, 0, 98, 0, 0, 0, 0, 0]
    );
}
#[test]
fn whole_seed_preflight_uses_actual_authority_metadata_times_and_failure_is_atomic() {
    let got = resolve(json!({"user_name":"Morgan","hostname":"HOST-M"})).unwrap();
    let mut state = got.prepare();
    let path = r"C:\Users\Morgan\Documents\readme.txt";
    assert_eq!(
        state.filesystem.contents(path).unwrap().unwrap(),
        b"Personal notes\n"
    );
    assert_eq!(
        state.filesystem.metadata(path).unwrap().times,
        [state.clock.utc_filetime; 3]
    );
    assert_eq!(
        state.filesystem.current_directory(),
        r"C:\Users\Morgan\Downloads"
    );
    let key = state
        .registry
        .open(
            1024,
            crate::registry::HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            crate::registry::KEY_READ,
        )
        .unwrap();
    assert_eq!(
        state.registry.query_info(1024, key, true).unwrap().filetime,
        state.clock.utc_filetime
    );
    assert_eq!(
        state
            .filesystem
            .remove_directory(r"C:\Users\Morgan\Documents")
            .unwrap_err()
            .win32,
        50
    );
    let bad = json!({"registry_keys":[],"virtual_files":[{"path":"C:\\same","text":"a"},{"path":"C:\\same\\child","text":"b"}]});
    assert!(resolve(bad).is_err());
    assert_eq!(
        state.filesystem.contents(path).unwrap().unwrap(),
        b"Personal notes\n"
    );
    let bad = json!({"registry_keys":[{"path":"HKCU\\Software\\Probe","values":[]},{"path":"HKEY_CURRENT_USER\\Software\\Probe\\","values":[]}],"virtual_files":[]});
    assert!(resolve(bad).is_err());
}
#[test]
fn machine_identity_binary_assets_and_unapplied_locale_inventory_projection_are_honest() {
    fn machine(p: &ValidatedPersona) -> String {
        p.effective_json()["registry_keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["path"] == r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography")
            .unwrap()["values"][0]["data"]
            .as_str()
            .unwrap()
            .into()
    }
    let a = resolve(json!({})).unwrap();
    let b = resolve(json!({"user_name":"Morgan"})).unwrap();
    let c = resolve(json!({"hostname":"OTHER-HOST"})).unwrap();
    assert_eq!(machine(&a), machine(&b));
    assert_ne!(machine(&a), machine(&c));
    let pdf = a
        .seed_manifest()
        .files()
        .iter()
        .find(|f| f.path.ends_with("train-apr-2026.pdf"))
        .unwrap();
    assert!(pdf.bytes().starts_with(b"%PDF-1.4"));
    let zip = a
        .seed_manifest()
        .files()
        .iter()
        .find(|f| f.path.ends_with("trip-documents.zip"))
        .unwrap();
    assert!(zip.bytes().starts_with(b"PK\x03\x04"));
    let locale = resolve(json!({"locale":"de-DE","windows_build":26100})).unwrap();
    assert!(!locale.projection().data.engine_applied);
    assert!(
        locale
            .projection()
            .data
            .pending
            .iter()
            .any(|p| p.path == "locale.OEMCP")
    );
    assert!(
        locale
            .projection()
            .data
            .pending
            .iter()
            .any(|p| p.path == "windows_build" && p.reason.contains("remaining runtime consumers"))
    );
}

#[test]
fn pinned_reference_assets_match_recorded_content_hashes() {
    let manifest: Value =
        serde_json::from_str(include_str!("../fullpersona_assets/manifest.json")).unwrap();
    for (name, bytes) in [
        (
            "defaults.json",
            include_bytes!("../fullpersona_assets/defaults.json").as_slice(),
        ),
        (
            "static_registry.json",
            include_bytes!("../fullpersona_assets/static_registry.json").as_slice(),
        ),
        (
            "directories.json",
            include_bytes!("../fullpersona_assets/directories.json").as_slice(),
        ),
        (
            "process_paths.json",
            include_bytes!("../fullpersona_assets/process_paths.json").as_slice(),
        ),
        (
            "audit_subcategories.json",
            include_bytes!("../fullpersona_assets/audit_subcategories.json").as_slice(),
        ),
        (
            "corpus.json",
            include_bytes!("../fullpersona_assets/corpus.json").as_slice(),
        ),
    ] {
        let record = manifest["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        assert_eq!(digest(bytes), record["sha256"].as_str().unwrap());
        assert_eq!(bytes.len() as u64, record["bytes"].as_u64().unwrap());
    }
    assert_eq!(manifest["valid"], 30);
    assert_eq!(manifest["invalid"], 34);
}
