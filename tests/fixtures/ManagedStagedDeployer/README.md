# Managed staged deployer simulation

This fixture models a two-stage deployer without a harmful payload. The build
script compiles a benign .NET DLL, packs it in a ZIP archive, encrypts the
archive with a fixed test key, and embeds the ciphertext in the loader. Under
Emumee, the loader decrypts the archive, extracts the DLL into guest memory,
loads and invokes it, and attempts a request to the reserved `.invalid` domain.
The second stage writes only `emumee-stage-two.txt` with a fixed canary.

Build and run from the repository root:

```powershell
.venv\Scripts\python.exe .\tests\fixtures\ManagedStagedDeployer\build_fixture.py
.\emumee.ps1 run .\tests\fixtures\ManagedStagedDeployer\bin\Release\net8.0\ManagedStagedDeployer.dll --guest-env EMUMEE_TEST=virtual
```

Without that exact guest environment setting, the loader returns 2 before
decrypting or making any file or network call. The key, IV, and payload are
fixed test material. This is a fixture for behavior coverage, not a safe way
to run arbitrary untrusted programs on a host.
