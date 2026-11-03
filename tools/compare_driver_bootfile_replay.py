"""Verify the copied boot-status file sensitivity replay against its control."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def read(root: Path) -> tuple[dict, dict, dict, dict]:
    report_path = root / "worker" / "engine-report.json"
    return (
        json.loads(report_path.read_text(encoding="utf-8"))["execution"],
        json.loads((root / "summary.json").read_text(encoding="utf-8")),
        json.loads((root / "controller-manifest.json").read_text(encoding="utf-8")),
        json.loads((root / "worker-exit.json").read_text(encoding="utf-8")),
    )


def boot_receipt(execution: dict) -> dict:
    rows = [
        row
        for row in execution["kernel_files"]["create_request_receipts"]
        if row["name"].lower().endswith(r"\vgkbootstatus.dat")
    ]
    if len(rows) != 1:
        raise ValueError("Expected one boot-status create receipt")
    return rows[0]


def artifact(summary: dict, suffix: str) -> dict:
    matches = [
        row
        for row in summary["artifacts"]
        if any(str(observation.get("guest_path", "")).lower().endswith(suffix) for observation in row["observations"])
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one artifact ending {suffix}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("control", type=Path)
    parser.add_argument("seeded", type=Path)
    parser.add_argument("image_comparison", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    control, c_summary, c_manifest, c_exit = read(args.control)
    seeded, s_summary, s_manifest, s_exit = read(args.seeded)
    c_receipt, s_receipt = boot_receipt(control), boot_receipt(seeded)
    c_prompt = control["kernel_prompt"]["continuation"]["instructions"]
    s_prompt = seeded["kernel_prompt"]["continuation"]["instructions"]
    if len(c_prompt) != len(s_prompt):
        raise ValueError("Prompt continuation lengths differ")
    matching_pc_size = all(
        (a["pc"], a["size"]) == (b["pc"], b["size"])
        for a, b in zip(c_prompt, s_prompt)
    )
    c_boot, s_boot = artifact(c_summary, "vgkbootstatus.dat"), artifact(s_summary, "vgkbootstatus.dat")
    c_log, s_log = artifact(c_summary, ".log"), artifact(s_summary, ".log")
    image_comparison = json.loads(args.image_comparison.read_text(encoding="utf-8"))
    if not (
        c_receipt["information"] == 2
        and s_receipt["information"] == 1
        and c_receipt["status"] == s_receipt["status"] == 0
        and any(row["operation"] == "read" and row["information"] == 1 for row in seeded["kernel_files"]["events"])
        and c_boot["sha256"] == s_boot["sha256"]
        and c_log["sha256"] == s_log["sha256"]
        and matching_pc_size
        and control["error"] == seeded["error"]
        and c_manifest["cleanup"] == s_manifest["cleanup"] == "restored"
        and c_exit["exit_code"] == s_exit["exit_code"] == 0
        and image_comparison["by_section"].keys() == {".data"}
    ):
        raise ValueError("Boot-file sensitivity evidence did not match the expected bounded result")
    comparison = {
        "schema": "emumee.driver_bootfile_sensitivity.v1",
        "control": str(args.control),
        "seeded": str(args.seeded),
        "control_instructions": control["instruction_count"],
        "seeded_instructions": seeded["instruction_count"],
        "control_api_calls": control["api_calls"],
        "seeded_api_calls": seeded["api_calls"],
        "bootfile_control_create_information": c_receipt["information"],
        "bootfile_seeded_create_information": s_receipt["information"],
        "seeded_file_read_observed": True,
        "final_bootfile_sha256_equal": True,
        "final_log_sha256_equal": True,
        "prompt_pc_and_size_equal_all_rows": True,
        "prompt_rows": len(c_prompt),
        "same_terminal_error": control["error"],
        "same_guest_entry_return": control["guest_entry_return"] == seeded["guest_entry_return"],
        "seeded_capture_markers": seeded["capture_runtime"]["markers"],
        "image_comparison": str(args.image_comparison),
        "image_comparison_sha256": hashlib.sha256(args.image_comparison.read_bytes()).hexdigest(),
        "image_changed_pages": image_comparison["changed_pages"],
        "image_changed_sections": list(image_comparison["by_section"]),
        "interpretation": "The copied postboot byte was opened and read from guest VFS, then overwritten, yet the same prompt path, output log, C0000022 construction, and later mutex stop occurred. This does not establish normal boot-time state or rule out other environmental checks.",
        "unpacking_confirmed": False,
    }
    args.output.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"seeded_read": True, "same_prompt_path": True, "same_terminal_error": True, "changed_pages": image_comparison["changed_pages"]}))


if __name__ == "__main__":
    main()
