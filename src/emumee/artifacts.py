"""Recover guest-created data without mapping guest paths onto host paths."""

from __future__ import annotations

import hashlib
import json
import struct
import time
from pathlib import Path

import pefile


MAX_ARTIFACT = 32 * 1024 * 1024
MAX_MEMORY_SCAN = 128 * 1024 * 1024
MAX_ARTIFACT_OBSERVATIONS = 10_000
MAX_ARTIFACT_MANIFEST_BYTES = 1024 * 1024
SCRIPT_SUFFIXES = {".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".wsf"}


def _is_pe(data: bytes) -> bool:
    if len(data) < 512 or data[:2] != b"MZ":
        return False
    try:
        pe = pefile.PE(data=data, fast_load=True)
        return pe.OPTIONAL_HEADER.SizeOfImage > 0
    except (pefile.PEFormatError, ValueError):
        return False


def _kind(data: bytes, guest_path: str = "") -> str:
    if _is_pe(data):
        return "pe"
    if Path(guest_path).suffix.lower() in SCRIPT_SUFFIXES:
        return "script"
    if data.startswith((b"#!", b"<script", b"<?xml", b"powershell")):
        return "script"
    return "binary"


def _bounded_pe_metadata(data: bytes) -> dict | None:
    """Read display-only PE fields without invoking a PE parser in the host parent."""
    if len(data) < 512 or data[:2] != b"MZ":
        return None

    def u16(offset: int) -> int:
        return struct.unpack_from("<H", data, offset)[0]

    def u32(offset: int) -> int:
        return struct.unpack_from("<I", data, offset)[0]

    pe_offset = u32(0x3C)
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    machine, section_count, optional_size = (u16(pe_offset + 4),
                                             u16(pe_offset + 6), u16(pe_offset + 20))
    if section_count > 96:
        return None
    optional = pe_offset + 24
    if optional_size < 96 or optional + optional_size > len(data):
        return None
    magic = u16(optional)
    if magic not in (0x10B, 0x20B) or (magic == 0x20B and optional_size < 112):
        return None
    image_size, header_size = u32(optional + 56), u32(optional + 60)
    if not 0 < image_size <= 0x7FFFFFFF or not 0 < header_size <= len(data):
        return None
    table = optional + optional_size
    if table + section_count * 40 > len(data):
        return None
    sections: list[tuple[int, int, int, int]] = []
    section_names: list[str] = []
    for index in range(section_count):
        offset = table + index * 40
        if index < 32:
            section_names.append(data[offset:offset + 8].rstrip(b"\0").decode(
                "ascii", errors="replace"))
        sections.append((u32(offset + 12), u32(offset + 8),
                         u32(offset + 20), u32(offset + 16)))

    def file_offset(rva: int, count: int) -> int | None:
        if rva < header_size and rva + count <= min(header_size, len(data)):
            return rva
        for virtual, virtual_size, raw, raw_size in sections:
            if virtual <= rva and rva - virtual + count <= min(
                    max(virtual_size, raw_size), raw_size) and raw + rva - virtual + count <= len(data):
                return raw + rva - virtual
        return None

    imports: list[str] = []
    count_offset = 92 if magic == 0x10B else 108
    directory_offset = 96 if magic == 0x10B else 112
    if optional_size >= directory_offset + 16 and u32(optional + count_offset) >= 2:
        import_rva, import_size = (u32(optional + directory_offset + 8),
                                   u32(optional + directory_offset + 12))
        for index in range(min(64, import_size // 20) if import_rva else 0):
            descriptor = file_offset(import_rva + index * 20, 20)
            if descriptor is None or data[descriptor:descriptor + 20] == bytes(20):
                break
            name = file_offset(u32(descriptor + 12), 1)
            if name is None:
                break
            end = data.find(b"\0", name, min(name + 256, len(data)))
            if end < 0:
                break
            imports.append(data[name:end].decode("ascii", errors="replace"))
    return {"architecture": {0x14c: "x86", 0x8664: "x64"}.get(machine, hex(machine)),
            "entry_rva": u32(optional + 16), "image_size": image_size,
            "import_dlls": imports, "sections": section_names}


class ArtifactCatalog:
    def __init__(self, root: Path, *, checkpoint: bool = False):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.items: list[dict] = []
        self._seen: set[str] = set()
        self._omitted_count = 0
        self._omitted_bytes = 0
        self._omitted_reasons: dict[str, int] = {}
        self._omitted_examples: list[dict] = []
        self._manifest_bytes = 2
        self._checkpoint = checkpoint
        self._last_checkpoint = 0.0

    def note_omission(self, source: str, size: int, reason: str) -> None:
        if size <= 0:
            return
        self._omitted_count += 1
        self._omitted_bytes += size
        self._omitted_reasons[reason] = self._omitted_reasons.get(reason, 0) + 1
        if len(self._omitted_examples) < 20:
            self._omitted_examples.append({"source": source[:256],
                                           "bytes": size, "reason": reason})

    def capture_summary(self) -> dict:
        return {"omitted_observations": self._omitted_count,
                "omitted_bytes": self._omitted_bytes,
                "reasons": dict(self._omitted_reasons),
                "examples": list(self._omitted_examples)}

    def add(self, data: bytes, source: str, guest_path: str = "", kind: str | None = None,
            context: dict | None = None) -> dict | None:
        if not data:
            return None
        if len(data) > MAX_ARTIFACT:
            self.note_omission(source, len(data), "artifact_size_limit")
            return None
        sha = hashlib.sha256(data).hexdigest()
        key = f"{sha}:{source}:{guest_path}:{json.dumps(context, sort_keys=True) if context else ''}"
        if key in self._seen:
            return None
        item_kind = kind or _kind(data, guest_path)
        ext = {"pe": ".pe", "script": ".txt", "memory": ".bin", "shellcode": ".bin",
               "network": ".bin"}.get(item_kind, ".bin")
        name = f"{sha[:20]}{ext}"
        item = {"sha256": sha, "size": len(data), "kind": item_kind, "source": source,
                "guest_path": guest_path, "file": name}
        if context:
            item["context"] = dict(context)
        record_size = len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
        if len(self.items) >= MAX_ARTIFACT_OBSERVATIONS:
            self.note_omission(source, len(data), "artifact_observation_limit")
            return None
        if self._manifest_bytes + record_size + bool(self.items) > MAX_ARTIFACT_MANIFEST_BYTES:
            self.note_omission(source, len(data), "artifact_manifest_limit")
            return None
        dest = self.root / name
        if not dest.exists():
            dest.write_bytes(data)
        self._seen.add(key)
        self._manifest_bytes += record_size + bool(self.items)
        self.items.append(item)
        if self._checkpoint and (len(self.items) == 1 or len(self.items) % 32 == 0 or
                                 time.monotonic() - self._last_checkpoint >= 1.0):
            self.save_manifest()
        return item

    def carve_pe(self, blob: bytes, source: str, *, skip_offset_zero: bool = False,
                 context: dict | None = None) -> None:
        if len(blob) > MAX_MEMORY_SCAN:
            self.note_omission(source, len(blob) - MAX_MEMORY_SCAN,
                               "memory_scan_input_limit")
            blob = blob[:MAX_MEMORY_SCAN]
        start = 1 if skip_offset_zero else 0
        while True:
            offset = blob.find(b"MZ", start)
            if offset < 0:
                break
            # Packed data often contains thousands of accidental MZ pairs.
            # Reject impossible PE signatures before copying up to 32 MiB and
            # constructing a parser for each pair. Accepted candidates and
            # extraction limits remain exactly the same.
            candidate_size = min(len(blob) - offset, MAX_ARTIFACT)
            if candidate_size < 0x40:
                break
            pe_offset = struct.unpack_from("<I", blob, offset + 0x3C)[0]
            if (pe_offset > candidate_size - 24 or
                    blob[offset + pe_offset:offset + pe_offset + 4] != b"PE\0\0"):
                start = offset + 2
                continue
            candidate = blob[offset:offset + MAX_ARTIFACT]
            if _is_pe(candidate):
                try:
                    pe = pefile.PE(data=candidate, fast_load=True)
                    end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
                    end = max(end, pe.OPTIONAL_HEADER.SizeOfHeaders)
                    if 0 < end <= len(candidate):
                        mapped_sections: list[tuple[int, int, int]] = []
                        mapped_evidence = False
                        image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
                        if 0 < image_size <= len(candidate) and image_size <= MAX_ARTIFACT:
                            for section in pe.sections:
                                raw = int(section.PointerToRawData)
                                virtual = int(section.VirtualAddress)
                                size = int(section.SizeOfRawData)
                                if not size:
                                    continue
                                if (raw < 0 or virtual < 0 or raw + size > end or
                                        virtual + size > image_size):
                                    mapped_sections = []
                                    break
                                mapped_sections.append((raw, virtual, size))
                                if (raw != virtual and
                                        not any(candidate[raw:raw + size]) and
                                        any(candidate[virtual:virtual + size])):
                                    mapped_evidence = True
                        if mapped_evidence and mapped_sections:
                            recovered = bytearray(candidate[:end])
                            for raw, virtual, size in mapped_sections:
                                recovered[raw:raw + size] = candidate[virtual:virtual + size]
                            details = {**(context or {}), "layout": "mapped_image",
                                       "reconstruction": "section_rva_to_raw",
                                       "image_size": image_size}
                            self.add(candidate[:image_size], f"{source}@0x{offset:x}",
                                     kind="memory", context=details)
                            self.add(bytes(recovered), f"{source}@0x{offset:x}",
                                     kind="pe", context=details)
                        else:
                            self.add(candidate[:end], f"{source}@0x{offset:x}",
                                     kind="pe", context=context)
                except (pefile.PEFormatError, ValueError):
                    pass
            start = offset + 2

    def save_manifest(self) -> None:
        payload = json.dumps(self.items, separators=(",", ":"), ensure_ascii=True)
        next_path = self.root / "manifest.next"
        next_path.write_text(payload, encoding="utf-8")
        next_path.replace(self.root / "manifest.json")
        self._last_checkpoint = time.monotonic()

    def groups(self) -> list[dict]:
        """Unique payloads with every observation retained as provenance."""
        return groups_from_payloads((item, (self.root / item["file"]).read_bytes())
                                    for item in self.items)


def groups_from_payloads(observations) -> list[dict]:
    """Build the display groups from the manifest and the actual artifact bytes."""
    groups: dict[str, dict] = {}
    for item, raw in observations:
        digest = item["sha256"]
        if digest not in groups:
            pe_metadata = _bounded_pe_metadata(raw)
            if (item["kind"] == "memory" and
                    item.get("context", {}).get("layout") == "mapped_image"):
                detected = "memory"
            elif pe_metadata is not None:
                detected = "pe"
            elif raw.startswith(b"PK\x03\x04"):
                detected = "zip"
            elif raw.startswith(b"\x1f\x8b"):
                detected = "gzip"
            elif raw.startswith((b"#!", b"<script", b"<?xml", b"powershell")):
                detected = "script"
            else:
                detected = "binary"
            snippet = raw[:256]
            printable = all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in snippet)
            groups[digest] = {"sha256": digest, "size": item["size"],
                              "kind": detected, "file": item["file"],
                              "preview": (snippet.decode("ascii", errors="replace") if printable
                                          else raw[:32].hex()),
                              "preview_encoding": "text" if printable else "hex",
                              "observations": []}
            if detected == "pe":
                groups[digest]["pe_metadata"] = pe_metadata
        source = item["source"]
        stage = ("final" if source in {"virtual_file_final", "managed_file_write"} else
                 "intermediate" if source.startswith("file_write") else
                 "memory" if "memory" in source or source.startswith((
                     "managed_array", "managed_aes_plaintext", "managed_aes_decrypt")) else
                 "other")
        groups[digest]["observations"].append({
            "source": item["source"], "guest_path": item["guest_path"],
            "kind": item["kind"], "stage": stage,
            **({"context": item["context"]} if "context" in item else {})})
    return sorted(groups.values(), key=lambda group:
                  (group["kind"] != "pe", group["kind"] not in {"script", "zip", "gzip"},
                   -group["size"]))
