"""Bounded, read-only MSI stream inspection inside the isolated worker.

Windows Installer actions are deliberately not invoked. MSI is a compound-file
database; its streams can contain PEs directly or compressed cabinet data.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import olefile

from .artifacts import ArtifactCatalog, MAX_ARTIFACT, _is_pe
from .pe import InvalidSample, MSI_SIGNATURE, SampleInfo


MAX_MSI_STREAMS = 2048
MAX_MSI_TOTAL_STREAM_BYTES = 64 * 1024 * 1024


def inspect_msi(data: bytes, info: SampleInfo, run_dir: Path) -> dict:
    """Recover bounded MSI stream evidence without running custom actions."""
    if info.kind != "msi" or data[:8] != MSI_SIGNATURE:
        raise InvalidSample("Input is not a Windows Installer MSI database")
    catalog = ArtifactCatalog(run_dir / "artifacts")
    streams = []
    total = 0
    try:
        with olefile.OleFileIO(io.BytesIO(data), raise_defects=olefile.DEFECT_FATAL) as ole:
            paths = ole.listdir(streams=True, storages=False)
            if len(paths) > MAX_MSI_STREAMS:
                raise InvalidSample("MSI stream count exceeds the 2048 stream limit")
            for parts in paths:
                name = "/".join(parts)
                size = ole.get_size(parts)
                if size < 0 or size > MAX_ARTIFACT:
                    catalog.note_omission(f"msi_stream:{name}", max(size, 0),
                                          "msi_stream_size_limit")
                    continue
                if total + size > MAX_MSI_TOTAL_STREAM_BYTES:
                    catalog.note_omission(f"msi_stream:{name}", size,
                                          "msi_total_stream_limit")
                    continue
                raw = ole.openstream(parts).read(size + 1)
                if len(raw) != size:
                    raise InvalidSample("MSI stream length changed while reading")
                total += size
                detected = ("cabinet" if raw.startswith(b"MSCF") else
                            "pe" if _is_pe(raw) else "data")
                streams.append({"name": name[:256], "size": size, "type": detected})
                if detected in {"pe", "cabinet"}:
                    catalog.add(raw, f"msi_stream:{name[:200]}",
                                kind="pe" if detected == "pe" else "binary")
                else:
                    catalog.carve_pe(raw, f"msi_stream:{name[:200]}")
    except (OSError, ValueError, TypeError, IndexError) as exc:
        raise InvalidSample(f"Invalid MSI compound file: {exc}") from exc
    catalog.save_manifest()
    report = {"format": "msi", "inspection": "static_streams", "streams": streams,
              "stream_count": len(streams), "stream_bytes_read": total,
              "artifact_capture": catalog.capture_summary(),
              "limitations": ["Windows Installer tables and custom actions were not executed",
                              "Embedded CAB files were retained but not unpacked"]}
    (run_dir / "engine-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"engine_report": "engine-report.json", "artifacts": catalog.items,
            "artifact_groups": catalog.groups(), "artifact_capture": catalog.capture_summary(),
            "completion_reason": "static_inspection", "instruction_count": 0,
            "errors": ["MSI static stream inspection only; installer actions were not emulated"]}
