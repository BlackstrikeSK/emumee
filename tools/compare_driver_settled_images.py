"""Compare two captured mapped driver images without treating either as unpacked."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path

import pefile


PAGE = 4096


def captured_image(summary_path: Path) -> tuple[dict, Path]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    matches = [
        artifact
        for artifact in summary["artifacts"]
        if any(
            observation.get("source") == "settled_root_image"
            and observation.get("context", {}).get("layout") == "mapped_image"
            for observation in artifact["observations"]
        )
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one settled mapped image: {summary_path}")
    artifact = matches[0]
    path = summary_path.parent / "worker" / "artifacts" / artifact["filename"]
    if not path.is_file() or path.stat().st_size != artifact["size"]:
        raise ValueError(f"Missing or wrong-size image: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != artifact["sha256"]:
        raise ValueError(f"Artifact SHA-256 mismatch: {path}")
    return artifact, path


def section_for(offset: int, sections: list[dict]) -> str:
    for section in sections:
        start = section["rva"]
        size = max(section["virtual_size"], section["raw_size"])
        if start <= offset < start + size:
            return section["name"] or "<unnamed>"
    return "<headers-or-gap>"


def compare(left_summary: Path, right_summary: Path) -> dict:
    left, left_path = captured_image(left_summary)
    right, right_path = captured_image(right_summary)
    if left["size"] != right["size"]:
        raise ValueError("Mapped image sizes differ")
    source_path = left_summary.parent / "input.sys"
    source_bytes = source_path.read_bytes()
    left_binding = json.loads(left_summary.read_text(encoding="utf-8"))["binding"]
    if hashlib.sha256(source_bytes).hexdigest() != left_binding["input_sha256"]:
        raise ValueError("Replay input SHA-256 mismatch")
    pe = pefile.PE(data=source_bytes, fast_load=True)
    sections = [
        {
            "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
            "rva": section.VirtualAddress,
            "raw_size": section.SizeOfRawData,
            "virtual_size": section.Misc_VirtualSize,
        }
        for section in pe.sections
    ]
    counts: dict[str, dict[str, int]] = {}
    samples: list[dict] = []
    changed_pages = changed_bytes = 0
    with left_path.open("rb") as lf, right_path.open("rb") as rf:
        with mmap.mmap(lf.fileno(), 0, access=mmap.ACCESS_READ) as lm:
            with mmap.mmap(rf.fileno(), 0, access=mmap.ACCESS_READ) as rm:
                for start in range(0, left["size"], PAGE):
                    end = min(start + PAGE, left["size"])
                    a, b = lm[start:end], rm[start:end]
                    if a == b:
                        continue
                    difference = sum(x != y for x, y in zip(a, b))
                    changed_pages += 1
                    changed_bytes += difference
                    section = section_for(start, sections)
                    row = counts.setdefault(section, {"changed_pages": 0, "changed_bytes": 0})
                    row["changed_pages"] += 1
                    row["changed_bytes"] += difference
                    if len(samples) < 64:
                        first = next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
                        samples.append(
                            {"rva": hex(start + first), "section": section, "left": hex(a[first]), "right": hex(b[first])}
                        )
    return {
        "schema": "emumee.settled_mapped_image_comparison.v1",
        "scope": "Two post-stop mapped images; differences alone establish neither execution nor unpacking",
        "left": {"summary": str(left_summary), "sha256": left["sha256"]},
        "right": {"summary": str(right_summary), "sha256": right["sha256"]},
        "image_bytes": left["size"],
        "changed_pages": changed_pages,
        "changed_bytes": changed_bytes,
        "by_section": counts,
        "first_differences": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("left_summary", type=Path)
    parser.add_argument("right_summary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = compare(args.left_summary, args.right_summary)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"changed_pages": report["changed_pages"], "changed_bytes": report["changed_bytes"], "by_section": report["by_section"]}))


if __name__ == "__main__":
    main()
