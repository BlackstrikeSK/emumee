//! Deterministic derived registry/files/process data from one effective persona.
use super::*;
fn value(name: &str, data: impl ToString, kind: &str) -> Value {
    json!({"name":name,"type":kind,"data":data.to_string()})
}
fn entry(path: String, values: Vec<Value>) -> Value {
    json!({"path":path,"values":values})
}
fn set(values: &mut [Value], name: &str, data: impl ToString) {
    if let Some(v) = values.iter_mut().find(|v| v["name"] == name) {
        v["data"] = json!(data.to_string());
    }
}
fn machine_guid(host: &str) -> String {
    let hash = Sha256::digest(format!("emumee-machine:{}", fold(host)).as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash[..16]);
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
pub(super) fn files(p: &Value, defaults: &Value) -> Result<Value> {
    let user = text(&p["user_name"], "user_name")?;
    let host = text(&p["hostname"], "hostname")?;
    let old_home = r"C:\Users\Alex";
    let home = format!(r"C:\Users\{user}");
    let mut files = defaults["virtual_files"].as_array().unwrap().clone();
    for file in &mut files {
        let path = text(&file["path"], "virtual_files.path")?.replace(old_home, &home);
        if path == format!(r"{home}\Desktop\Welcome.txt") {
            file["text"] = json!(format!("Welcome to {host}.\n"));
        }
        file["path"] = json!(path);
    }
    for package in p["driver_packages"].as_array().unwrap() {
        files.push(json!({"path":format!(r"C:\Windows\INF\{}",text(&package["published_name"],"package.name")?),"text":format!("[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass={}\r\nClassGuid={}\r\nProvider=\"{}\"\r\nDriverVer={}\r\n",text(&package["class_name"],"package.class")?,text(&package["class_guid"],"package.guid")?,text(&package["provider"],"package.provider")?,text(&package["version"],"package.version")?.replace(' ',","))}));
    }
    Ok(files.into())
}
pub(super) fn registry(p: &Value) -> Result<Value> {
    let mut keys: Vec<Value> =
        serde_json::from_str(include_str!("../fullpersona_assets/static_registry.json"))
            .map_err(|e| error("registry_template", e.to_string()))?;
    let user = text(&p["user_name"], "user_name")?;
    let home = format!(r"C:\Users\{user}");
    let host = text(&p["hostname"], "hostname")?;
    let domain = text(&p["domain"], "domain")?;
    let sid = text(&p["user_sid"], "user_sid")?;
    let build = p["windows_build"].as_u64().unwrap();
    let locale = text(&p["locale"], "locale")?;
    let tz = text(&p["timezone"], "timezone")?;
    let offset = p["utc_offset_minutes"].as_i64().unwrap() as i32;
    let cpu = &p["cpu"];
    let a = &p["network_adapter"];
    let guid = text(&a["guid"], "network_adapter.guid")?;
    let prefix = a["prefix_length"].as_u64().unwrap() as u32;
    let subnet =
        std::net::Ipv4Addr::from(u32::MAX.checked_shl(32 - prefix).unwrap_or(0)).to_string();
    let mut binary = (-offset).to_le_bytes().to_vec();
    binary.extend([0u8; 40]);
    let tzi = format!(
        "hex:{}",
        binary
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    for key in &mut keys {
        let original = text(&key["path"], "registry.path")?.to_owned();
        let path = original
            .replace("S-1-5-21-1243773969-3482195721-2078146024-1001", sid)
            .replace("{7A91D3B6-46CF-4D12-9D5B-8E7C412A9360}", guid)
            .replace("Eastern Standard Time", tz);
        let values = key["values"].as_array_mut().unwrap();
        for value in values.iter_mut() {
            if let Some(s) = value["data"].as_str() {
                value["data"] = json!(s.replace(r"C:\Users\Alex", &home));
            }
        }
        if original == r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" {
            set(values, "CurrentBuild", build);
            set(values, "CurrentBuildNumber", build);
            set(values, "RegisteredOwner", user);
            values.retain(|v| v["name"] != "DisplayVersion");
            let display = match build {
                22000 => Some("21H2"),
                22621 => Some("22H2"),
                22631 => Some("23H2"),
                26100 => Some("24H2"),
                26200 => Some("25H2"),
                26300 => Some("26H2"),
                _ => None,
            };
            if let Some(display) = display {
                values.push(value("DisplayVersion", display, "REG_SZ"));
            }
        } else if original.ends_with(r"\Microsoft\Cryptography") {
            set(values, "MachineGuid", machine_guid(host));
        } else if original.ends_with(r"\ComputerName\ComputerName")
            || original.ends_with(r"\ComputerName\ActiveComputerName")
        {
            set(values, "ComputerName", host);
        } else if original.ends_with(r"\Services\Tcpip\Parameters") {
            set(values, "Hostname", host);
            set(values, "NV Hostname", host);
            set(
                values,
                "Domain",
                if domain == "WORKGROUP" { "" } else { domain },
            );
            set(
                values,
                "NV Domain",
                if domain == "WORKGROUP" { "" } else { domain },
            );
        } else if original.contains(r"\Services\Tcpip\Parameters\Interfaces\") {
            set(
                values,
                "EnableDHCP",
                u32::from(a["dhcp_enabled"].as_bool().unwrap()),
            );
            set(values, "DhcpIPAddress", text(&a["ipv4"], "adapter.ipv4")?);
            set(values, "DhcpSubnetMask", &subnet);
            set(
                values,
                "DhcpDefaultGateway",
                text(&a["gateway"], "adapter.gateway")?,
            );
            set(
                values,
                "DhcpNameServer",
                a["dns_servers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        } else if original.ends_with(r"\NetworkCards\1") {
            set(
                values,
                "Description",
                text(&a["description"], "adapter.description")?,
            );
            set(values, "ServiceName", guid);
        } else if original.ends_with(r"\Connection") {
            set(values, "Name", text(&a["name"], "adapter.name")?); /* legacy fixed PnpInstanceID retained, explicit projection diagnostic */
        } else if original.ends_with(r"\Control\TimeZoneInformation") {
            set(values, "TimeZoneKeyName", tz);
            set(values, "ActiveTimeBias", (-offset) as u32);
        } else if original.ends_with(r"\Time Zones\Eastern Standard Time") {
            set(values, "Display", tz);
            set(values, "Std", tz);
            set(values, "Dlt", tz);
            set(values, "TZI", &tzi);
        } else if original.ends_with(r"\System\CentralProcessor\0") {
            set(
                values,
                "ProcessorNameString",
                text(&cpu["brand"], "cpu.brand")?,
            );
            set(values, "~MHz", cpu["base_mhz"].as_u64().unwrap());
        } else if original.ends_with(r"\Volatile Environment") {
            set(values, "USERNAME", user);
        } else if original.ends_with(r"\Control Panel\International") {
            values.retain(|v| v["name"] == "LocaleName");
            set(values, "LocaleName", locale);
            let formats = match locale.to_ascii_lowercase().as_str() {
                "en-us" => Some(("M/d/yyyy", "h:mm:ss tt")),
                "en-gb" => Some(("dd/MM/yyyy", "HH:mm:ss")),
                "de-de" => Some(("dd.MM.yyyy", "HH:mm:ss")),
                "fr-fr" => Some(("dd/MM/yyyy", "HH:mm:ss")),
                _ => None,
            };
            if let Some((date, time)) = formats {
                values.push(value("sShortDate", date, "REG_SZ"));
                values.push(value("sTimeFormat", time, "REG_SZ"));
            }
        }
        key["path"] = json!(path);
    }
    let service_root = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services";
    for service in p["services"].as_array().unwrap() {
        keys.push(entry(
            format!("{service_root}\\{}", service["name"].as_str().unwrap()),
            vec![
                value("Start", service["start"].as_u64().unwrap(), "REG_DWORD"),
                value("Type", service["type"].as_u64().unwrap(), "REG_DWORD"),
                value(
                    "DisplayName",
                    service["display_name"].as_str().unwrap(),
                    "REG_SZ",
                ),
            ],
        ));
    }
    if p["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"].as_str().unwrap().eq_ignore_ascii_case("w32time"))
    {
        let t = &p["time_service"];
        let manual = if t["type"] == "NTP" {
            t["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    format!(
                        "{}{}",
                        v["name"].as_str().unwrap(),
                        if v["mode"] == 3 { ",0x9" } else { ",0x5" }
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            String::new()
        };
        for (suffix, values) in [
            (
                "Config",
                vec![
                    value("MinPollInterval", 4, "REG_DWORD"),
                    value("MaxPollInterval", 17, "REG_DWORD"),
                ],
            ),
            (
                "Parameters",
                vec![
                    value("Type", t["type"].as_str().unwrap(), "REG_SZ"),
                    value("NtpServer", manual, "REG_SZ"),
                ],
            ),
            (
                "TimeProviders\\NtpClient",
                vec![
                    value("Enabled", u32::from(t["type"] != "NoSync"), "REG_DWORD"),
                    value("InputProvider", 1, "REG_DWORD"),
                    value(
                        "SpecialPollInterval",
                        1u64 << t["poll_interval"].as_u64().unwrap(),
                        "REG_DWORD",
                    ),
                ],
            ),
            (
                "TimeProviders\\NtpServer",
                vec![
                    value("Enabled", 0, "REG_DWORD"),
                    value("InputProvider", 0, "REG_DWORD"),
                ],
            ),
        ] {
            keys.push(entry(format!("{service_root}\\W32Time\\{suffix}"), values));
        }
    }
    for driver in p["drivers"].as_array().unwrap() {
        keys.push(entry(
            format!("{service_root}\\{}", driver["name"].as_str().unwrap()),
            vec![
                value("Start", driver["start"].as_u64().unwrap(), "REG_DWORD"),
                value("Type", driver["type"].as_u64().unwrap(), "REG_DWORD"),
                value(
                    "DisplayName",
                    driver["display_name"].as_str().unwrap(),
                    "REG_SZ",
                ),
                value(
                    "ImagePath",
                    driver["path"].as_str().unwrap(),
                    "REG_EXPAND_SZ",
                ),
            ],
        ));
    }
    for filter in p["minifilters"].as_array().unwrap() {
        let name = filter["name"].as_str().unwrap();
        let count = filter["instances"].as_u64().unwrap();
        let base = format!("{service_root}\\{name}\\Instances");
        let instances = (0..count)
            .map(|i| {
                format!(
                    "{name} Instance{}",
                    if count > 1 {
                        format!(" {}", i + 1)
                    } else {
                        String::new()
                    }
                )
            })
            .collect::<Vec<_>>();
        keys.push(entry(
            base.clone(),
            vec![value("DefaultInstance", &instances[0], "REG_SZ")],
        ));
        for name in instances {
            keys.push(entry(
                format!("{base}\\{name}"),
                vec![
                    value("Altitude", filter["altitude"].as_str().unwrap(), "REG_SZ"),
                    value("Flags", 0, "REG_DWORD"),
                ],
            ));
        }
    }
    for channel in p["event_channels"].as_array().unwrap() {
        let name = channel["name"].as_str().unwrap();
        keys.push(entry(
            format!("{service_root}\\EventLog\\{name}"),
            vec![
                value(
                    "Enabled",
                    u32::from(channel["enabled"].as_bool().unwrap()),
                    "REG_DWORD",
                ),
                value(
                    "MaxSize",
                    channel["max_size"].as_u64().unwrap(),
                    "REG_DWORD",
                ),
                value(
                    "Retention",
                    u32::from(channel["retention"].as_bool().unwrap()),
                    "REG_DWORD",
                ),
                value(
                    "File",
                    format!(r"C:\Windows\System32\winevt\Logs\{name}.evtx"),
                    "REG_EXPAND_SZ",
                ),
            ],
        ));
    }
    let mut seen: BTreeSet<_> = keys
        .iter()
        .map(|k| fold(k["path"].as_str().unwrap()))
        .collect();
    let originals = keys.clone();
    for key in originals {
        let parts: Vec<_> = key["path"].as_str().unwrap().split('\\').collect();
        for length in 2..parts.len() {
            let parent = parts[..length].join("\\");
            if seen.insert(fold(&parent)) {
                keys.push(entry(parent, vec![]));
            }
        }
    }
    Ok(keys.into())
}
pub(super) fn projection(
    p: &Value,
    clock: ClockProjection,
    seeds: &SeedManifest,
) -> Result<SupportProjection> {
    let cpu = &p["cpu"];
    let model = crate::cpu::CpuProfile {
        brand: cpu["brand"].as_str().unwrap().into(),
        signature: cpu["signature"].as_u64().unwrap() as u32,
        cores: cpu["cores"].as_u64().unwrap() as u32,
        threads_per_core: cpu["threads_per_core"].as_u64().unwrap() as u32,
        base_mhz: cpu["base_mhz"].as_u64().unwrap() as u32,
        max_mhz: cpu["max_mhz"].as_u64().unwrap() as u32,
        cpuid_overrides: cpu
            .get("cpuid_overrides")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|row| crate::cpu::CpuidOverride {
                        function: row["function"].as_u64().unwrap() as u32,
                        subleaf: row["subleaf"].as_u64().unwrap() as u32,
                        eax: row["eax"].as_u64().unwrap() as u32,
                        ebx: row["ebx"].as_u64().unwrap() as u32,
                        ecx: row["ecx"].as_u64().unwrap() as u32,
                        edx: row["edx"].as_u64().unwrap() as u32,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    };
    model.validate().map_err(|e| error("cpu", e.to_string()))?;
    let user = p["user_name"].as_str().unwrap();
    let guest = crate::persona::PersonaConfig {
        hostname: p["hostname"].as_str().unwrap().into(),
        domain: p["domain"].as_str().unwrap().into(),
        user_name: user.into(),
        user_profile: format!(r"C:\Users\{user}"),
        current_directory: p["current_dir"].as_str().unwrap().into(),
        windows_directory: r"C:\Windows".into(),
        system_directory: r"C:\Windows\System32".into(),
        temp_directory: format!(r"C:\Users\{user}\AppData\Local\Temp"),
        logical_processors: model.cores * model.threads_per_core,
        environment: vec![],
    };
    crate::persona::Persona::new(guest.clone())
        .map_err(|e| error("persona_projection", e.to_string()))?;
    let mut pending = Vec::new();
    for key in p.as_object().unwrap().keys() {
        pending.push(PendingField{path:key.clone(),reason:if["hostname","domain","user_name","current_dir","cpu","clock_utc","utc_offset_minutes","uptime_ms","registry_keys","virtual_files","virtual_directories"].contains(&key.as_str()){String::from("validated pure model/seed input; configured production worker application remains unqualified")}else{String::from("external schema validated; complete runtime consumer remains unported/unqualified")}});
    }
    if ["en-gb", "de-de", "fr-fr"]
        .contains(&p["locale"].as_str().unwrap().to_ascii_lowercase().as_str())
    {
        pending.push(PendingField {
            path: "locale.OEMCP".into(),
            reason: "legacy locale uses OEM850; current environment A model supports437 only"
                .into(),
        });
    }
    pending.push(PendingField{path:"network_adapter.pnp_instance_id".into(),reason:"legacy Connection\\PnpInstanceID registry literal differs from configured adapter ID; preserved derived bytes, not complete channel coherence".into()});
    pending.push(PendingField{path:"windows_build".into(),reason:"validated build; configured generated native application has a separate execution receipt, while production worker and remaining runtime consumers remain unqualified".into()});
    Ok(SupportProjection {
        version: VERSION,
        persona: guest,
        cpu: model,
        clock,
        windows_build: p["windows_build"].as_u64().unwrap() as u32,
        physical_memory_mb: p["physical_memory_mb"].as_u64().unwrap(),
        available_memory_mb: p["available_memory_mb"].as_u64().unwrap(),
        pending,
        engine_applied: false,
        seed_manifest_sha256: seeds.sha256().into(),
    })
}
