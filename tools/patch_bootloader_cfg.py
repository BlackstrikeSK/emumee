"""Remove PyInstaller bootloader CFG, which is incompatible with Unicorn.

The worker remains restricted by AppContainer and a Windows job object.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pefile


def main() -> None:
    path = Path(sys.argv[1]).resolve(strict=True)
    pe = pefile.PE(str(path))
    if not pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:
        return
    pe.OPTIONAL_HEADER.DllCharacteristics &= ~0x4000
    if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardFlags = 0
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    patched = path.with_suffix(".patched")
    pe.write(str(patched))
    os.replace(patched, path)
    check = pefile.PE(str(path), fast_load=True)
    if check.OPTIONAL_HEADER.DllCharacteristics & 0x4000:
        raise RuntimeError("CFG is still enabled on worker bundle")


if __name__ == "__main__":
    main()
