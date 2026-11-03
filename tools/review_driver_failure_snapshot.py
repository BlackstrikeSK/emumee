"""Bind a saved vgk status calculation to executed PCs and captured image bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs


STATUS_PC = 0xFFFFF80101D5AA4C


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report_path = args.root / "worker" / "engine-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    execution = report["execution"]
    trace = execution["kernel_prompt"]["continuation"]
    rows = trace["instructions"]
    matches = [index for index, row in enumerate(rows) if row["pc"] == STATUS_PC]
    if len(matches) != 1 or trace["register_order"][15] != "r15":
        raise ValueError("Expected one status instruction and the recorded register order")
    index = matches[0]
    status_row = rows[index]
    image_sha = execution["capture_runtime"]["post_image_sha256"]
    image_path = args.root / "worker" / "artifacts" / f"{image_sha}.bin"
    image = image_path.read_bytes()
    if hashlib.sha256(image).hexdigest() != image_sha:
        raise ValueError("Captured mapped image SHA-256 mismatch")
    base = execution["capture_runtime"]["image_base"]
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []
    for row in rows[max(0, index - 4) : index + 5]:
        offset = row["pc"] - base
        raw = image[offset : offset + row["size"]]
        decoded = list(decoder.disasm(raw, row["pc"]))
        if len(decoded) != 1 or decoded[0].size != row["size"]:
            raise ValueError(f"Mapped bytes do not decode to recorded size at {row['pc']:#x}")
        instructions.append(
            {
                "ordinal": row["instruction_ordinal"],
                "pc": hex(row["pc"]),
                "rva": hex(offset),
                "bytes": raw.hex(),
                "assembly": f"{decoded[0].mnemonic} {decoded[0].op_str}",
                "rdx_before": hex(row["registers"][3]),
                "r15_before": hex(row["registers"][15]),
            }
        )
    status_instruction = instructions[4]
    if status_instruction["assembly"] != "imul edx, r15d, 0x9ccac40e":
        raise ValueError("Unexpected status calculation instruction")
    product = (status_row["registers"][15] * 0x9CCAC40E) & 0xFFFFFFFF
    if product != 0xC0000022 or rows[index + 1]["registers"][3] & 0xFFFFFFFF != product:
        raise ValueError("Status arithmetic does not match next recorded RDX")
    review = {
        "schema": "emumee.driver_failure_snapshot_review.v1",
        "source_root": str(args.root),
        "engine_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "mapped_image_sha256": image_sha,
        "mapped_image_bytes": len(image),
        "image_base": hex(base),
        "trace_rows": len(rows),
        "status_instruction_ordinal": status_row["instruction_ordinal"],
        "status_formula": "low32(r15 * 0x9ccac40e)",
        "status_result": hex(product),
        "surrounding_executed_assembly": instructions,
        "interpretation": "The guest constructs C0000022 in its own arithmetic after DbgPrompt; this does not identify the upstream branch or environment predicate.",
        "unpacking_confirmed": False,
    }
    args.output.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status_result": review["status_result"], "pc": status_instruction["pc"], "mapped_image_sha256": image_sha}))


if __name__ == "__main__":
    main()
