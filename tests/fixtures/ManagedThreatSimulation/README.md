# Managed threat simulation

This fixture exercises three malware-like behaviors: an AES-decrypted payload,
a dropped file, and an attempted outbound request. The payload is a fixed JSON
canary. The request goes to the reserved `.invalid` domain and Emumee's default
offline policy should deny it. There is no persistence, credential access,
executable second stage, or real command server.

From this directory, build with `dotnet build ManagedThreatSimulation.csproj -c Release`.
From the repository root, run it with:

```powershell
.\emumee.ps1 run .\tests\fixtures\ManagedThreatSimulation\bin\Release\net8.0\ManagedThreatSimulation.dll --guest-env EMUMEE_TEST=virtual
```

Without that exact guest setting, the program exits with code 2 before any
payload or network operation. Do not execute analysis samples directly on the
host; follow the repository's `SECURITY.md` guidance.
