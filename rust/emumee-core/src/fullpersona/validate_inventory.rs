use super::*;
pub(super) fn validate_inventory(p: &Value) -> Result<()> {
    for process in array(&p["processes"], "processes", 128)? {
        let s = bounded_text(process, "processes[]", 1, 128)?;
        require(
            !s.contains(['\\', '/', ':']),
            "processes[]",
            "process must be a simple filename",
        )?;
    }
    let mut names = BTreeSet::new();
    for service in array(&p["services"], "services", 128)? {
        fields(
            service,
            "services[]",
            &["name", "display_name", "process", "start", "type"],
            &[],
        )?;
        let name = simple(&service["name"], "services[].name", 1, 64)?;
        unique(&mut names, name, "services[].name")?;
        bounded_text(&service["display_name"], "services[].display_name", 1, 128)?;
        let process = bounded_text(&service["process"], "services[].process", 1, 128)?;
        require(
            !process.contains(['\\', '/', ':']),
            "services[].process",
            "unsafe process filename",
        )?;
        unsigned(&service["start"], "services[].start", 2, 4)?;
        let kind = unsigned(&service["type"], "services[].type", 16, 32)?;
        require(
            matches!(kind, 16 | 32),
            "services[].type",
            "unsupported service type",
        )?;
    }
    let mut drivers = BTreeMap::new();
    for driver in array(&p["drivers"], "drivers", 32)? {
        fields(
            driver,
            "drivers[]",
            &["name", "display_name", "path", "start", "type", "running"],
            &[],
        )?;
        let name = simple(&driver["name"], "drivers[].name", 1, 64)?;
        unique(&mut names, name, "drivers[].name")?;
        plain(&driver["display_name"], "drivers[].display_name", 1, 128)?;
        let path = text(&driver["path"], "drivers[].path")?;
        let lower = path.to_ascii_lowercase();
        require(
            lower.starts_with("system32\\drivers\\") && lower.ends_with(".sys"),
            "drivers[].path",
            "expected System32\\drivers driver path",
        )?;
        let filename = &path[17..];
        simple(&json!(filename), "drivers[].path", 1, 68)?;
        require(
            filename.len() >= 5 && filename[..filename.len() - 4].chars().count() <= 64,
            "drivers[].path",
            "driver filename exceeds bound",
        )?;
        let start = unsigned(&driver["start"], "drivers[].start", 0, 4)?;
        unsigned(&driver["type"], "drivers[].type", 1, 2)?;
        let running = boolean(&driver["running"], "drivers[].running")?;
        require(
            start != 4 || !running,
            "drivers[].running",
            "disabled driver cannot be running",
        )?;
        drivers.insert(fold(name), driver);
    }
    let mut filters = BTreeSet::new();
    let mut instances = 0u64;
    for filter in array(&p["minifilters"], "minifilters", 32)? {
        fields(
            filter,
            "minifilters[]",
            &["name", "altitude", "instances"],
            &[],
        )?;
        let name = text(&filter["name"], "minifilters[].name")?;
        unique(&mut filters, name, "minifilters[].name")?;
        let driver = drivers
            .get(&fold(name))
            .ok_or_else(|| error("minifilters[].name", "filter has no driver"))?;
        require(
            driver["type"] == 2 && driver["running"] == true,
            "minifilters[].name",
            "filter requires running type2 driver",
        )?;
        let altitude = text(&filter["altitude"], "minifilters[].altitude")?;
        let parts: Vec<_> = altitude.split('.').collect();
        require(
            (1..=2).contains(&parts.len())
                && (1..=6).contains(&parts[0].len())
                && parts[0].bytes().all(|b| b.is_ascii_digit())
                && (parts.len() == 1
                    || ((1..=3).contains(&parts[1].len())
                        && parts[1].bytes().all(|b| b.is_ascii_digit()))),
            "minifilters[].altitude",
            "invalid altitude",
        )?;
        instances += unsigned(&filter["instances"], "minifilters[].instances", 1, 16)?;
    }
    require(
        instances <= 64,
        "minifilters",
        "total filter instances exceeds64",
    )?;
    let mut packages = BTreeMap::new();
    for package in array(&p["driver_packages"], "driver_packages", 32)? {
        fields(
            package,
            "driver_packages[]",
            &[
                "published_name",
                "original_name",
                "provider",
                "class_name",
                "class_guid",
                "version",
                "signer",
            ],
            &[],
        )?;
        let name = text(
            &package["published_name"],
            "driver_packages[].published_name",
        )?;
        let lower = name.to_ascii_lowercase();
        let stem = lower
            .strip_prefix("oem")
            .and_then(|v| v.strip_suffix(".inf"))
            .ok_or_else(|| error("driver_packages[].published_name", "expected OEM INF name"))?;
        require(
            (1..=4).contains(&stem.len()) && stem.bytes().all(|b| b.is_ascii_digit()),
            "driver_packages[].published_name",
            "invalid OEM INF number",
        )?;
        require(
            packages.insert(fold(name), package).is_none(),
            "driver_packages[].published_name",
            "duplicate package",
        )?;
        let original = text(&package["original_name"], "driver_packages[].original_name")?;
        require(
            original.to_ascii_lowercase().ends_with(".inf"),
            "driver_packages[].original_name",
            "expected INF file",
        )?;
        simple(
            &json!(&original[..original.len() - 4]),
            "driver_packages[].original_name",
            1,
            64,
        )?;
        simple(
            &package["class_name"],
            "driver_packages[].class_name",
            1,
            64,
        )?;
        guid(&package["class_guid"], "driver_packages[].class_guid")?;
        for key in ["provider", "signer"] {
            let v = plain(&package[key], &format!("driver_packages[].{key}"), 1, 128)?;
            require(
                !v.contains('"'),
                "driver_packages[]",
                "quoted provider or signer",
            )?;
        }
        let version = text(&package["version"], "driver_packages[].version")?;
        let (date, numbers) = version
            .split_once(' ')
            .ok_or_else(|| error("driver_packages[].version", "invalid INF date/version"))?;
        let d: Vec<_> = date.split('/').collect();
        let n: Vec<_> = numbers.split('.').collect();
        require(
            d.len() == 3
                && d[0].len() == 2
                && d[1].len() == 2
                && d[2].len() == 4
                && d.iter().all(|v| v.bytes().all(|b| b.is_ascii_digit()))
                && (2..=4).contains(&n.len())
                && n.iter()
                    .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())),
            "driver_packages[].version",
            "invalid INF version",
        )?;
    }
    let mut devices = BTreeSet::new();
    for device in array(&p["pnp_devices"], "pnp_devices", 64)? {
        fields(
            device,
            "pnp_devices[]",
            &[
                "instance_id",
                "description",
                "class_name",
                "class_guid",
                "status",
                "driver",
            ],
            &[],
        )?;
        let id = chars(
            &device["instance_id"],
            "pnp_devices[].instance_id",
            1,
            200,
            |c| c.is_ascii_alphanumeric() || "_&\\{}.:-".contains(c),
        )?;
        unique(&mut devices, id, "pnp_devices[].instance_id")?;
        plain(&device["description"], "pnp_devices[].description", 1, 128)?;
        simple(&device["class_name"], "pnp_devices[].class_name", 1, 64)?;
        guid(&device["class_guid"], "pnp_devices[].class_guid")?;
        choices(
            &device["status"],
            "pnp_devices[].status",
            &["Started", "Disabled", "Disconnected"],
        )?;
        if !device["driver"].is_null() {
            let key = fold(text(&device["driver"], "pnp_devices[].driver")?);
            let package = packages
                .get(&key)
                .ok_or_else(|| error("pnp_devices[].driver", "unknown driver package"))?;
            require(
                fold(text(&device["class_name"], "pnp_devices[].class_name")?)
                    == fold(text(
                        &package["class_name"],
                        "driver_packages[].class_name",
                    )?)
                    && fold(text(&device["class_guid"], "pnp_devices[].class_guid")?)
                        == fold(text(
                            &package["class_guid"],
                            "driver_packages[].class_guid",
                        )?),
                "pnp_devices[].driver",
                "device/package class mismatch",
            )?;
        }
    }
    let mut channels = BTreeSet::new();
    for channel in array(&p["event_channels"], "event_channels", 32)? {
        fields(
            channel,
            "event_channels[]",
            &["name", "enabled", "max_size", "retention"],
            &[],
        )?;
        unique(
            &mut channels,
            simple(&channel["name"], "event_channels[].name", 1, 64)?,
            "event_channels[].name",
        )?;
        boolean(&channel["enabled"], "event_channels[].enabled")?;
        boolean(&channel["retention"], "event_channels[].retention")?;
        let size = unsigned(
            &channel["max_size"],
            "event_channels[].max_size",
            1048576,
            268435456,
        )?;
        require(
            size % 65536 == 0,
            "event_channels[].max_size",
            "event channel size must be64KiB aligned",
        )?;
    }
    let mut tasks = BTreeSet::new();
    for task in array(&p["scheduled_tasks"], "scheduled_tasks", 32)? {
        fields(
            task,
            "scheduled_tasks[]",
            &["name", "status", "next_run_minutes"],
            &[],
        )?;
        let name = plain(&task["name"], "scheduled_tasks[].name", 2, 128)?;
        require(
            name.starts_with('\\')
                && !name.ends_with('\\')
                && !name.contains(['/', ':', '"'])
                && name[1..]
                    .split('\\')
                    .all(|v| !v.is_empty() && v != "." && v != ".."),
            "scheduled_tasks[].name",
            "unsafe task path",
        )?;
        unique(&mut tasks, name, "scheduled_tasks[].name")?;
        choices(
            &task["status"],
            "scheduled_tasks[].status",
            &["Ready", "Disabled"],
        )?;
        if task["status"] == "Disabled" {
            require(
                task["next_run_minutes"].is_null(),
                "scheduled_tasks[].next_run_minutes",
                "disabled task has next run",
            )?;
        } else {
            unsigned(
                &task["next_run_minutes"],
                "scheduled_tasks[].next_run_minutes",
                0,
                10080,
            )?;
        }
    }
    Ok(())
}
