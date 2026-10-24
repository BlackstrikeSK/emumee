"""Bound raw PE section versus settled mapped-image differences."""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path

import pefile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_pe", type=Path)
    parser.add_argument("summary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    artifacts = [
        artifact
        for artifact in summary["artifacts"]
        if any(
            observation.get("context", {}).get("layout") == "mapped_image"
            and observation.get("source") == "settled_root_image"
            for observation in artifact["observations"]
        )
    ]
    if len(artifacts) != 1:
        raise ValueError("Expected exactly one settled mapped image")
    artifact = artifacts[0]
    image_path = args.summary.parent / "worker" / "artifacts" / artifact["filename"]
    source_sha = hashlib.sha256(args.source_pe.read_bytes()).hexdigest()
    if source_sha != summary["binding"]["input_sha256"]:
        raise ValueError("Source PE does not match replay input")
    image_sha = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if image_sha != artifact["sha256"]:
        raise ValueError("Settled image digest mismatch")
    pe = pefile.PE(str(args.source_pe), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    )
    relocation_bytes = set()
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            size = {3: 4, 10: 8}.get(entry.type, 0)
            relocation_bytes.update(range(entry.rva, entry.rva + size))
    sections = []
    with args.source_pe.open("rb") as sf, image_path.open("rb") as mf:
        with mmap.mmap(sf.fileno(), 0, access=mmap.ACCESS_READ) as source:
            with mmap.mmap(mf.fileno(), 0, access=mmap.ACCESS_READ) as image:
                for section in pe.sections:
                    start = section.PointerToRawData
                    size = section.SizeOfRawData
                    rva = section.VirtualAddress
                    if start + size > len(source) or rva + size > len(image):
                        raise ValueError("Section exceeds source or mapped image")
                    changed = 0
                    relocation_changed = 0
                    changed_pages = set()
                    samples = []
                    for i in range(size):
                        if source[start + i] != image[rva + i]:
                            changed += 1
                            relocation_changed += int(rva + i in relocation_bytes)
                            changed_pages.add((rva + i) // 4096)
                            if len(samples) < 8:
                                samples.append(hex(rva + i))
                    sections.append(
                        {
                            "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
                            "rva": hex(rva),
                            "raw_bytes": size,
                            "virtual_bytes": section.Misc_VirtualSize,
                            "characteristics": hex(section.Characteristics),
                            "executable": bool(section.Characteristics & 0x20000000),
                            "writable": bool(section.Characteristics & 0x80000000),
                            "different_raw_bytes": changed,
                            "relocation_covered_different_bytes": relocation_changed,
                            "non_relocation_different_bytes": changed - relocation_changed,
                            "different_pages": len(changed_pages),
                            "first_difference_rvas": samples,
                        }
                    )
    review = {
        "schema": "emumee.driver_raw_to_settled_section_comparison.v1",
        "source_sha256": source_sha,
        "settled_image_sha256": image_sha,
        "scope": "Raw-file section bytes compared with post-stop mapped bytes; relocations, import writes, and ordinary runtime writes are not distinguished; this cannot certify unpacking.",
        "sections": sections,
        "unpacking_confirmed": False,
    }
    args.output.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({row["name"]: row["different_raw_bytes"] for row in sections if row["different_raw_bytes"]}))


if __name__ == "__main__":
    main()
