# Security

Emumee processes potentially hostile files. Its AppContainer boundary, resource
limits, and emulation checks reduce risk, but they do not establish that every
malformed file or guest behavior is contained. Use a disposable analysis machine
for untrusted samples. Do not run samples directly on the host.

The separate experimental `powershell` command requires Docker Desktop's Linux
VM. It accepts only the supplied script, with no host mounts or runtime network,
and verifies container resource and privilege settings before execution. Its
Windows persona integration and command-capture coverage are incomplete.
Engine-reported parameters are guest-generated and can be forged or bypassed;
native exec observations come from a separate process. See
[PowerShell confinement](POWERSHELL_CONFINEMENT.md) for the boundary and evidence.

If you find a vulnerability that could escape containment or expose host data,
please use GitHub's private vulnerability reporting for this repository when
available. Do not post an exploit or a live malware sample in a public issue.

The project's current coverage and containment evidence is in
[COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md).
