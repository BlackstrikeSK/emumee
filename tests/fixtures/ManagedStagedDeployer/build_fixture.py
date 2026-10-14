"""Build a benign stage, encrypt its ZIP container, then compile the loader."""

from __future__ import annotations

import base64
import io
import subprocess
import zipfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


fixtures = Path(__file__).resolve().parent.parent
payload = fixtures / "ManagedStagedDeployerPayload"
loader = fixtures / "ManagedStagedDeployer"
subprocess.run(["dotnet", "build", str(payload / "ManagedStagedDeployerPayload.csproj"),
                "-c", "Release"], check=True)
raw = (payload / "bin" / "Release" / "net8.0" /
       "ManagedStagedDeployerPayload.dll").read_bytes()
packed = io.BytesIO()
with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("notes.txt", b"Benign Emumee stage fixture")
    archive.writestr("stage/ManagedStagedDeployerPayload.dll", raw)
key = bytes(range(16))
iv = bytes(range(16, 32))
encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(packed.getvalue(), 16))
encoded = base64.b64encode(encrypted).decode("ascii")
(loader / "EmbeddedArchive.cs").write_text(
    "internal static class EmbeddedArchive {\n"
    f'  public const string Base64 = "{encoded}";\n'
    "}\n", encoding="utf-8")
subprocess.run(["dotnet", "build", str(loader / "ManagedStagedDeployer.csproj"),
                "-c", "Release"], check=True)
