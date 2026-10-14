"""Build a harmless managed DLL, place it in ZIP, and compile the CIL loader."""

from __future__ import annotations

import base64
import io
import subprocess
import zipfile
from pathlib import Path


fixtures = Path(__file__).resolve().parent.parent
payload = fixtures / "ManagedZipStagePayload"
loader = fixtures / "ManagedZipStage"
subprocess.run(["dotnet", "build", str(payload / "ManagedZipStagePayload.csproj"),
                "-c", "Release"], check=True)
raw = (payload / "bin" / "Release" / "net8.0" / "ManagedZipStagePayload.dll").read_bytes()
packed = io.BytesIO()
with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("notes.txt", b"harmless archive index")
    archive.writestr("stage/ManagedZipStagePayload.dll", raw)
encoded = base64.b64encode(packed.getvalue()).decode("ascii")
(loader / "EmbeddedArchive.cs").write_text(
    f"internal static class EmbeddedArchive {{\n"
    f"  public const string Base64 = \"{encoded}\";\n"
    f"}}\n",
    encoding="utf-8",
)
subprocess.run(["dotnet", "build", str(loader / "ManagedZipStage.csproj"),
                "-c", "Release"], check=True)
