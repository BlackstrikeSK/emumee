# Harmless static Linux ELF controls

On an x86-64 Linux system with GCC:

```sh
gcc -nostdlib -static -no-pie -Wl,--build-id=none -o hello.elf hello.s
gcc -nostdlib -static -no-pie -Wl,--build-id=none -o unsupported.elf unsupported.s
```

`hello.elf` writes `hello\n` to guest stdout and exits with status 0.
`unsupported.elf` attempts syscall 41 (`socket`), which this Linux guest
profile must stop as `unsupported_syscall` without calling the host.
These are test sources, not examples of broad Linux compatibility.
