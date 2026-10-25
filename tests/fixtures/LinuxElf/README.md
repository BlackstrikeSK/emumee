# Harmless Linux ELF controls

On an x86-64 Linux system with GCC:

```sh
gcc -nostdlib -static -no-pie -Wl,--build-id=none -o hello.elf hello.s
gcc -nostdlib -static -no-pie -Wl,--build-id=none -o unsupported.elf unsupported.s
gcc -m32 -nostdlib -static -no-pie -Wl,--build-id=none -o hello_i386.elf hello_i386.s
gcc -m32 -nostdlib -static -no-pie -Wl,--build-id=none -o unsupported_i386.elf unsupported_i386.s
gcc -nostdlib -static-pie -Wl,--build-id=none -o pie_relative.elf pie_relative.s
gcc -m32 -nostdlib -fPIE -pie -Wl,--build-id=none -Wl,--dynamic-linker=/lib/ld-linux.so.2 -o pie_i386.elf pie_i386.s
gcc -nostdlib -shared -fPIC -Wl,-soname,libguest.so -Wl,--hash-style=sysv -Wl,--build-id=none -o libguest.so libguest.s
gcc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,--build-id=none -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -L. -o shared_main.elf shared_main.s -lguest
gcc -nostdlib -shared -fPIC -Wl,-soname,libtls.so -Wl,--hash-style=sysv -Wl,--build-id=none -o libtls.so libtls.s
gcc -nostdlib -fPIE -pie -Wl,--hash-style=sysv -Wl,--build-id=none -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -L. -o tls_main.elf tls_main.s -ltls
```

`hello.elf` writes `hello\n` to guest stdout and exits with status 0.
`unsupported.elf` attempts syscall 41 (`socket`), which this Linux guest
profile must stop as `unsupported_syscall` without calling the host.
These are test sources, not examples of broad Linux compatibility.

The i386 controls exercise `int 0x80`, including an unsupported syscall.
`pie_relative.elf` exercises `R_X86_64_RELATIVE`; `pie_i386.elf` exercises
`R_386_RELATIVE`. `shared_main.elf` calls a
symbol through `R_X86_64_JUMP_SLOT` in a staged `libguest.so`; `tls_main.elf`
uses the initial-exec `R_X86_64_TPOFF64` relocation and a copied `PT_TLS`
template in staged `libtls.so`. The expected captured output is `i386\n`,
`pie\n`, `i386pie\n`, `shared\n`, and `tls\n`, respectively. Build in an expendable
directory and inspect relocations with `readelf -Wr` before relying on a
particular toolchain's output. Pass each dependency with
`--library libguest.so=libguest.so` or `--library libtls.so=libtls.so`.
