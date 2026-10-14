"""Build the harmless managed payload and embed it in a reflection loader."""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path


fixtures = Path(__file__).resolve().parent.parent
payload = fixtures / "ManagedPayload"
payload_exe = fixtures / "ManagedPayloadExe"
loader = fixtures / "ManagedReflect"
subprocess.run(["dotnet", "build", str(payload / "ManagedPayload.csproj"), "-c", "Release"], check=True)
subprocess.run(["dotnet", "build", str(payload_exe / "ManagedPayloadExe.csproj"), "-c", "Release"], check=True)
raw_library = (payload / "bin" / "Release" / "net8.0" / "ManagedPayload.dll").read_bytes()
raw_executable = (payload_exe / "bin" / "Release" / "net8.0" / "ManagedPayloadExe.dll").read_bytes()
library = base64.b64encode(raw_library).decode("ascii")
executable = base64.b64encode(raw_executable).decode("ascii")
(loader / "EmbeddedPayload.cs").write_text(
    f"internal static class EmbeddedPayload {{\n"
    f"  public const string Library = \"{library}\";\n"
    f"  public const string Executable = \"{executable}\";\n"
    f"}}\n",
    encoding="utf-8",
)
subprocess.run(["dotnet", "build", str(loader / "ManagedReflect.csproj"), "-c", "Release"], check=True)
