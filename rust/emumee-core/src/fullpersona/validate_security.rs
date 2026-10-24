use super::*;
pub(super) fn validate_security(p: &Value, _clock: &ClockProjection) -> Result<()> {
    let b = &p["bitlocker"];
    fields(
        b,
        "bitlocker",
        &["encryption_method", "protection_enabled", "key_protectors"],
        &[],
    )?;
    choices(
        &b["encryption_method"],
        "bitlocker.encryption_method",
        &["None", "XTS-AES 128", "XTS-AES 256"],
    )?;
    let protected = boolean(&b["protection_enabled"], "bitlocker.protection_enabled")?;
    let mut names = BTreeSet::new();
    for key in array(&b["key_protectors"], "bitlocker.key_protectors", 2)? {
        choices(
            key,
            "bitlocker.key_protectors[]",
            &["TPM", "Numerical Password"],
        )?;
        unique(
            &mut names,
            text(key, "bitlocker.key_protectors[]")?,
            "bitlocker.key_protectors",
        )?;
    }
    require(
        (b["encryption_method"] != "None" || (!protected && names.is_empty()))
            && (!protected || !names.is_empty()),
        "bitlocker",
        "inconsistent protection metadata",
    )?;
    let mut shadow_ids = BTreeSet::new();
    let mut sets = BTreeMap::new();
    for shadow in array(&p["shadow_copies"], "shadow_copies", 16)? {
        fields(
            shadow,
            "shadow_copies[]",
            &["id", "set_id", "created_utc"],
            &[],
        )?;
        guid(&shadow["id"], "shadow_copies[].id")?;
        guid(&shadow["set_id"], "shadow_copies[].set_id")?;
        unique(
            &mut shadow_ids,
            text(&shadow["id"], "shadow_copies[].id")?,
            "shadow_copies[].id",
        )?;
        let created = text(&shadow["created_utc"], "shadow_copies[].created_utc")?;
        timestamp(created, "shadow_copies[].created_utc", true)?;
        let key = fold(text(&shadow["set_id"], "shadow_copies[].set_id")?);
        if let Some(old) = sets.insert(key, created) {
            require(
                old == created,
                "shadow_copies[].created_utc",
                "shadow set times differ",
            )?;
        }
    }
    let k = &p["kerberos"];
    fields(k, "kerberos", &["logon_id", "tickets"], &[])?;
    unsigned(&k["logon_id"], "kerberos.logon_id", 1, u64::MAX)?;
    for ticket in array(&k["tickets"], "kerberos.tickets", 16)? {
        fields(
            ticket,
            "kerberos.tickets[]",
            &[
                "server",
                "realm",
                "encryption_type",
                "session_key_type",
                "flags",
                "start_utc",
                "end_utc",
                "renew_utc",
            ],
            &[],
        )?;
        for name in ["server", "realm"] {
            chars(
                &ticket[name],
                &format!("kerberos.tickets[].{name}"),
                1,
                256,
                |c| c.is_ascii_alphanumeric() || "_./:@-".contains(c),
            )?;
        }
        for name in ["encryption_type", "session_key_type"] {
            let n = unsigned(&ticket[name], "kerberos.tickets[].encryption", 0, 255)?;
            require(
                matches!(n, 17 | 18 | 23),
                "kerberos.tickets[].encryption",
                "unsupported encryption metadata",
            )?;
        }
        unsigned(
            &ticket["flags"],
            "kerberos.tickets[].flags",
            0,
            u32::MAX as u64,
        )?;
        let mut times = Vec::new();
        for name in ["start_utc", "end_utc", "renew_utc"] {
            times.push(timestamp(
                text(&ticket[name], "kerberos.tickets[].time")?,
                "kerberos.tickets[].time",
                true,
            )?);
        }
        require(
            times[0] <= times[1] && times[1] <= times[2],
            "kerberos.tickets[].time",
            "ticket times out of order",
        )?;
    }
    let mut backups = BTreeSet::new();
    for backup in array(&p["backup_versions"], "backup_versions", 16)? {
        fields(
            backup,
            "backup_versions[]",
            &["created_utc", "target", "recovery_types"],
            &[],
        )?;
        let created = text(&backup["created_utc"], "backup_versions[].created_utc")?;
        timestamp(created, "backup_versions[].created_utc", true)?;
        unique(
            &mut backups,
            &created[..16],
            "backup_versions[].created_utc",
        )?;
        plain(&backup["target"], "backup_versions[].target", 1, 256)?;
        let mut types = BTreeSet::new();
        let entries = array(
            &backup["recovery_types"],
            "backup_versions[].recovery_types",
            5,
        )?;
        require(
            !entries.is_empty(),
            "backup_versions[].recovery_types",
            "empty recovery list",
        )?;
        for kind in entries {
            choices(
                kind,
                "backup_versions[].recovery_types[]",
                &[
                    "Volumes",
                    "Files",
                    "Applications",
                    "Bare Metal Recovery",
                    "System State",
                ],
            )?;
            unique(
                &mut types,
                text(kind, "backup_versions[].recovery_types[]")?,
                "backup_versions[].recovery_types",
            )?;
        }
    }
    let mut credentials = BTreeSet::new();
    for c in array(&p["stored_credentials"], "stored_credentials", 32)? {
        fields(
            c,
            "stored_credentials[]",
            &["target", "user", "type", "persistence"],
            &[],
        )?;
        let target = plain(&c["target"], "stored_credentials[].target", 1, 256)?;
        plain(&c["user"], "stored_credentials[].user", 1, 256)?;
        choices(
            &c["type"],
            "stored_credentials[].type",
            &["Generic", "Domain Password"],
        )?;
        choices(
            &c["persistence"],
            "stored_credentials[].persistence",
            &["Session", "Local computer", "Enterprise"],
        )?;
        require(
            credentials.insert((fold(target), text(&c["type"], "stored_credentials[].type")?)),
            "stored_credentials[].target",
            "duplicate credential target/type",
        )?;
    }
    let boot = &p["boot_config"];
    fields(
        boot,
        "boot_config",
        &[
            "loader_guid",
            "description",
            "timeout_seconds",
            "hypervisor_launch_type",
            "debug",
            "safe_boot",
        ],
        &[],
    )?;
    guid(&boot["loader_guid"], "boot_config.loader_guid")?;
    plain(&boot["description"], "boot_config.description", 1, 80)?;
    unsigned(
        &boot["timeout_seconds"],
        "boot_config.timeout_seconds",
        0,
        999,
    )?;
    boolean(&boot["debug"], "boot_config.debug")?;
    if !boot["hypervisor_launch_type"].is_null() {
        choices(
            &boot["hypervisor_launch_type"],
            "boot_config.hypervisor_launch_type",
            &["Auto", "Off"],
        )?;
    }
    if !boot["safe_boot"].is_null() {
        choices(
            &boot["safe_boot"],
            "boot_config.safe_boot",
            &["Minimal", "Network"],
        )?;
    }
    let policy = &p["group_policy"];
    fields(policy, "group_policy", &["computer", "user"], &[])?;
    for name in ["computer", "user"] {
        let mut values = BTreeSet::new();
        for v in array(&policy[name], "group_policy.entries", 16)? {
            unique(
                &mut values,
                plain(v, "group_policy.entries[]", 1, 128)?,
                "group_policy.entries",
            )?;
        }
    }
    let audit = &p["audit_policy"];
    fields(
        audit,
        "audit_policy",
        &["read_allowed", "subcategories"],
        &[],
    )?;
    boolean(&audit["read_allowed"], "audit_policy.read_allowed")?;
    let known: Vec<String> = serde_json::from_str(include_str!(
        "../fullpersona_assets/audit_subcategories.json"
    ))
    .map_err(|e| error("audit_policy", e.to_string()))?;
    for (name, value) in object(&audit["subcategories"], "audit_policy.subcategories")? {
        require(
            known.contains(name),
            "audit_policy.subcategories",
            "unknown audit subcategory",
        )?;
        choices(
            value,
            "audit_policy.subcategories.setting",
            &["No Auditing", "Success", "Failure", "Success and Failure"],
        )?;
    }
    let r = &p["device_registration"];
    fields(
        r,
        "device_registration",
        &[
            "azure_ad_joined",
            "enterprise_joined",
            "domain_joined",
            "workplace_joined",
            "azure_ad_prt",
        ],
        &[],
    )?;
    for (name, value) in object(r, "device_registration")? {
        boolean(value, &format!("device_registration.{name}"))?;
    }
    require(
        !(r["azure_ad_joined"] == true && r["enterprise_joined"] == true
            || r["domain_joined"] == true && p["domain"] == "WORKGROUP")
            && !(r["azure_ad_prt"] == true
                && r["azure_ad_joined"] != true
                && r["workplace_joined"] != true),
        "device_registration",
        "inconsistent registration state",
    )?;
    // clock is validated before dependent time_service last-sync checks.
    Ok(())
}
