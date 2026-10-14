# Security

Emumee processes potentially hostile files. Its AppContainer boundary, resource
limits, and emulation checks reduce risk, but they do not establish that every
malformed file or guest behavior is contained. Use a disposable analysis machine
for untrusted samples. Do not run samples directly on the host.

If you find a vulnerability that could escape containment or expose host data,
please use GitHub's private vulnerability reporting for this repository when
available. Do not post an exploit or a live malware sample in a public issue.

The project's current coverage and containment evidence is in
[COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md).
