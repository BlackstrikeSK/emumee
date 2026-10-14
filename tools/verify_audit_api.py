"""Verify built audit fixtures through guest CPU execution, including children.

Build first with tools/build_audit_api_probe.ps1. No fixture is launched as a
host executable. Evidence stays below output/audit-api-verification.
"""

import base64
import json
from pathlib import Path

from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_native import build_host_winexec_probe


def main():
    root = Path(__file__).resolve().parents[1]
    for arch, machine in (("x86", 0x14c), ("x64", 0x8664)):
        image = (root / f"output/audit-api-toolchain/audit_api_probe_{arch}.exe").read_bytes()
        for mode in ("allowed", "denied", "child"):
            persona = load_persona(None)
            persona["audit_policy"] = {"read_allowed": mode != "denied", "subcategories": {
                "Logon": "Success and Failure", "File System": "Failure", "Process Creation": "Success"}}
            payload = image
            if mode == "child":
                persona["virtual_files"].append({
                    "path": persona["current_dir"] + "\\audit-api-probe.exe",
                    "base64": base64.b64encode(image).decode("ascii")})
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"audit-api-probe.exe\0"
                parent[0x700:0x700 + len(command)] = command
                payload = bytes(parent)
            output = root / "output/audit-api-verification" / arch / mode
            sample_name = "audit-parent.exe" if mode == "child" else "audit-api-probe.exe"
            result = run_native(payload, inspect_pe(payload, sample_name), persona,
                                output, [], 10, 200_000)
            assert not result["errors"], result["errors"]
            assert result["guest_exit_code"] == 0, result["guest_exit_code"]
            text = result["console_output"]["stdout"]
            assert ("audit-policy-denied" if mode == "denied" else "audit-policy-ok") in text, text
            assert "audit-metadata-ok" in text, text
            report = json.loads((output / result["engine_report"]).read_text())
            assert report["network_events"] == [], report["network_events"]
            if mode == "child":
                assert any(event["event"] == "virtual_process_create" and event["success"] and
                           event["path"].casefold().endswith("\\audit-api-probe.exe")
                           for event in report["virtual_process_events"])
            print(arch, mode, "passed")


if __name__ == "__main__":
    main()
