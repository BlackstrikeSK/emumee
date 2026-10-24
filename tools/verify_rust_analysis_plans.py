"""Exercise the read-only plan adapter with generated PE bytes; never execute them."""
import argparse
import copy
import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def generated_pe(arch, kind):
    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    wide = arch == "x64"
    optional_size = 0xF0 if wide else 0xE0
    flags = 0x22 if wide else 0x102
    if kind == "dll":
        flags |= 0x2000
    struct.pack_into("<HHIIIHH", raw, 0x84, 0x8664 if wide else 0x14C,
                     1, 0, 0, 0, optional_size, flags)
    opt = 0x98
    struct.pack_into("<H", raw, opt, 0x20B if wide else 0x10B)
    struct.pack_into("<III", raw, opt + 4, 512, 0, 0)
    struct.pack_into("<II", raw, opt + 16, 0x1000, 0x1000)
    if wide:
        struct.pack_into("<Q", raw, opt + 24, 0x140000000)
    else:
        struct.pack_into("<II", raw, opt + 24, 0x2000, 0x400000)
    struct.pack_into("<II", raw, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HH", raw, opt + 40, 6, 0)
    struct.pack_into("<HH", raw, opt + 48, 6, 0)
    struct.pack_into("<II", raw, opt + 56, 0x2000, 0x200)
    struct.pack_into("<H", raw, opt + 68, 1 if kind == "kernel" else 3)
    struct.pack_into("<I", raw, opt + (108 if wide else 92), 16)
    section = opt + optional_size
    raw[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", raw, section + 8, 512, 0x1000, 512, 512)
    struct.pack_into("<I", raw, section + 36, 0x60000020)
    raw[512:518] = b"\xb8\x11\x00\x00\x00\xc3"
    return bytes(raw)


def plan(raw, arch="x64", kind="exe"):
    target = {"kind": {"exe": "native_exe", "dll": "native_dll", "kernel": "kernel_driver"}[kind],
              "input": "primary", "architecture": arch}
    if kind == "dll":
        target["exports"] = "disabled"
    if kind == "kernel":
        target.update(unload=False, code_reference={"kind": "none"})
    process = dict(hostname="DESKTOP-7F4M2Q9", domain="WORKGROUP", user_name="Alex",
                   user_profile="C:\\Users\\Alex", current_directory="C:\\Users\\Alex\\Downloads",
                   windows_directory="C:\\Windows", system_directory="C:\\Windows\\System32",
                   temp_directory="C:\\Users\\Alex\\AppData\\Local\\Temp",
                   logical_processors=12, environment=[])
    return dict(schema=1, target=target,
                inputs=[dict(id="primary", name="owned.sys" if kind == "kernel" else "owned.exe",
                             roles=["original_primary", "execution_primary"], mount={"kind": "not_mounted"},
                             size=len(raw), sha256=sha(raw))], companions=[],
                persona={"kind": "rust_modeled_v1", "value": dict(
                    process=process, cpu=dict(brand="Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz",
                    signature=0xA0653, cores=6, threads_per_core=2, base_mhz=2900, max_mhz=4300),
                    clock=dict(utc_filetime=133000000000000000, uptime_ms=523812000,
                               utc_offset_minutes=-240, source="fixed", source_id="owned-seed"),
                    windows_build=22631, current_processor=0, physical_memory_mb=16384, available_memory_mb=7168)},
                invocation={"kind": "none"} if kind == "kernel" else dict(
                    kind="process", guest_root="C:\\Users\\Alex\\Downloads", arguments=[],
                    force_quote_indices=[], environment=[]), network={"kind": "offline_deny"},
                limits=dict(guest_timeout_ms=60000, max_instructions=2000000, max_native_api_calls=100000,
                    worker_startup_ms=15000, reporting_grace_ms=15000, broker_startup_ms=10000, broker_grace_ms=5000,
                    worker_memory_mb=1024, broker_memory_mb=256, max_output_bytes=1073741824,
                    max_output_entries=11000, max_output_directories=64, max_output_depth=40,
                    guest_mapped_bytes=67108864, guest_heap_bytes=16777216, guest_pool_bytes=16777216,
                    guest_threads=8, broker_stream_bytes=134217728, broker_journal_bytes=67108864),
                capture=dict(profile="legacy32_capture_v1", sources=[], retained_bytes=16777216,
                    memory_scan_bytes=134217728, memory_strings={"kind": "disabled"}, checkpoint={"kind": "final_boundary"}),
                reports=dict(profile="legacy_v1", summary_bytes=5242880, engine_bytes=52428800,
                             network_bytes=67108864, manifest_bytes=1048576))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.output_root.resolve()
    if root.exists():
        raise RuntimeError("Preserve existing evidence; choose a fresh output root")
    receipt_raw = (bundle / "rust-worker-build.json").read_bytes()
    receipt = json.loads(receipt_raw.decode("utf-8-sig"))
    for name, key in (("emumee-rs.exe", "controller_sha256"), ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")):
        assert sha((bundle / name).read_bytes()) == receipt[key], name
    root.mkdir(parents=True)
    records = []

    def save(verified):
        (root / "verification.json").write_text(json.dumps(dict(
            verified=verified, count=len(records), records=records,
            bundle=str(bundle), receipt_sha256=sha(receipt_raw), source_tree_sha256=receipt["source_tree_sha256"],
            verifier_sha256=sha(Path(__file__).read_bytes()),
            scope="Read-only fixed-slot planner on generated bytes; no worker or guest execution"), indent=2) + "\n", encoding="utf-8")

    def run(name, spec, raw, accepted=False, fault=None, source=None, extra=None):
        case = root / name
        slots = case / "inputs"
        slots.mkdir(parents=True)
        slot = slots / "0000.bin"
        if fault == "directory":
            slot.mkdir()
        elif fault != "missing":
            slot.write_bytes(raw)
        if extra is not None:
            (slots / "0001.bin").write_bytes(extra)
        if fault == "hardlink":
            os.link(slot, slots / "extra.bin")
        document = source if source is not None else json.dumps(spec).encode()
        (case / "plan.json").write_bytes(document)
        before = sorted(str(p.relative_to(case)) for p in case.rglob("*"))
        result = subprocess.run([str(bundle / "emumee-rs.exe"), "inspect-analysis-plan",
                                 str(case / "plan.json"), str(case)], capture_output=True, timeout=30)
        after = sorted(str(p.relative_to(case)) for p in case.rglob("*"))
        (case / "stdout.bin").write_bytes(result.stdout)
        (case / "stderr.bin").write_bytes(result.stderr)
        row = dict(name=name, expected_accept=accepted, exit_code=result.returncode,
                   document_sha256=sha(document), input_sha256=sha(raw),
                   stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr), verified=False)
        records.append(row)
        save(False)
        assert before == after, name + ": inspector wrote files"
        assert (result.returncode == 0) is accepted, name + ": " + result.stderr.decode(errors="replace")
        if accepted:
            response = json.loads(result.stdout)
            assert response["schema"] == "emumee.analysis_plan_inspection.v1"
            assert response["executable"] is False and response["engine_applied"] is False
            buffers = [raw] + ([extra] if extra is not None else [])
            assert response["input_slots_verified"] == len(buffers)
            assert response["input_bytes_verified"] == sum(map(len, buffers))
            assert response["verified_slots"] == [dict(
                slot=f"inputs/{index:04}.bin", id=item["id"], size=len(data), sha256=sha(data))
                for index, (item, data) in enumerate(zip(spec["inputs"], buffers))]
            row["plan_sha256"] = response["plan_sha256"]
            row["verified_slot_sha256"] = response["verified_slots"][0]["sha256"]
        else:
            assert not result.stdout, name + ": rejected plan emitted a partial slot receipt"
        row["verified"] = True
        save(False)

    for arch in ("x86", "x64"):
        for kind in ("exe", "dll", "kernel"):
            raw = generated_pe(arch, kind)
            run(f"{arch}-{kind}", plan(raw, arch, kind), raw, accepted=True)
    raw = generated_pe("x64", "exe")
    base = plan(raw)
    extra = b"generated-package-data"
    two = copy.deepcopy(base)
    two["inputs"].append(dict(id="data", name="data.bin", roles=["guest_file"],
                              mount={"kind": "package", "path": "config/data.bin"},
                              size=len(extra), sha256=sha(extra)))
    run("two-ordered-slots", two, raw, accepted=True, extra=extra)
    run("tampered-second-slot", two, raw, extra=extra + b"X")
    for name, path, value in (
        ("unknown-field", ["extra"], True),
        ("unknown-nested", ["limits", "extra"], True),
        ("wrong-arch", ["target", "architecture"], "x86"),
        ("traversal-name", ["inputs", 0, "name"], "../owned.exe"),
        ("hash-rebound", ["inputs", 0, "sha256"], "0" * 64),
        ("over-input", ["inputs", 0, "size"], 134217729),
        ("under-output", ["limits", "max_output_bytes"], 1024),
        ("under-memory", ["limits", "worker_memory_mb"], 64),
        ("excess-directories", ["limits", "max_output_directories"], 1025),
        ("clock-authority", ["persona", "value", "clock", "source"], "controller_resolved"),
        ("unsupported-capture", ["capture", "profile"], "driver128_v1"),
    ):
        spec = copy.deepcopy(base)
        target = spec
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        run(name, spec, raw)
    for fault in ("missing", "hardlink", "directory"):
        run(fault + "-slot", base, raw, fault=fault)
    run("tampered-slot", base, raw[:-1] + b"X")
    run("short-slot", base, raw[:-1])
    run("oversized-slot", base, raw + b"X")
    run("duplicate-json-key", base, raw, source=b'{"schema":1,"schema":1}')
    run("oversized-json", base, raw, source=b" " * (2097152 + 1))
    assert len(records) == 27
    save(True)
    print(json.dumps(dict(verified=True, count=len(records), output_root=str(root))))


if __name__ == "__main__":
    main()
