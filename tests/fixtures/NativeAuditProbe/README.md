# Native audit probe

This x64 fixture requires guest environment `EMUMEE_TEST=virtual`. Without it,
the fixture exits with code 2 before any registry, process, or network action.

It creates guest key `HKCU\Software\EmumeeTest\AuditProbe`, writes a `REG_SZ`
value named `ProbeState` and a `REG_BINARY` canary, attempts to launch
`schtasks.exe /Create` for a harmless `hostname.exe` task named
`EmumeeTestProbe`, and requests Telegram's `getMe` endpoint using an inert
placeholder token. Run it only through Emumee with explicit offline replay:

```powershell
.venv\Scripts\python.exe .\tests\fixtures\NativeAuditProbe\build_fixture.py
.\emumee.ps1 run .\tests\fixtures\NativeAuditProbe\audit_probe_x64.exe --guest-env EMUMEE_TEST=virtual --offline-replay
```

The expected report is `partial`: `schtasks.exe` is absent from the default
guest filesystem. Its full command is retained in `virtual_process_events`;
this is evidence of a creation attempt, not a registered task. The registry
events retain the key, value names, types, sizes, and result codes. The binary
value is recovered as an artifact. The Telegram URL, method, and offline denial
are retained in both the engine network events and the broker audit log.

The fixture contains no real Telegram credentials and sends no messages. The
test run performs no DNS resolution or network connection. No host task or
registry key should be created. Follow the repository's `SECURITY.md` guidance
and do not launch the fixture directly on the host.
