use super::*;

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn image(code: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 0x200];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    put16(&mut data, 16, 2);
    put16(&mut data, 18, 62);
    put32(&mut data, 20, 1);
    put64(&mut data, 24, 0x400100);
    put64(&mut data, 32, 64);
    put16(&mut data, 52, 64);
    put16(&mut data, 54, 56);
    put16(&mut data, 56, 1);
    put32(&mut data, 64, 1);
    put32(&mut data, 68, 5);
    put64(&mut data, 80, 0x400000);
    let size = data.len() as u64;
    put64(&mut data, 96, size);
    put64(&mut data, 104, size);
    put64(&mut data, 112, 0x1000);
    data[0x100..0x100 + code.len()].copy_from_slice(code);
    data
}

fn image32(code: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 0x200];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 1;
    data[5] = 1;
    data[6] = 1;
    put16(&mut data, 16, 2);
    put16(&mut data, 18, 3);
    put32(&mut data, 20, 1);
    put32(&mut data, 24, 0x8048100);
    put32(&mut data, 28, 52);
    put16(&mut data, 40, 52);
    put16(&mut data, 42, 32);
    put16(&mut data, 44, 1);
    put32(&mut data, 52, 1);
    put32(&mut data, 60, 0x8048000);
    put32(&mut data, 68, 0x200);
    put32(&mut data, 72, 0x200);
    put32(&mut data, 76, 5);
    put32(&mut data, 80, 0x1000);
    data[0x100..0x100 + code.len()].copy_from_slice(code);
    data
}

#[test]
fn static_guest_exits_with_guest_status() {
    let code = [
        0xb8, 60, 0, 0, 0, // mov eax, 60
        0xbf, 42, 0, 0, 0, // mov edi, 42
        0x0f, 0x05, // syscall
        0xf4, // hlt, must not be reached
    ];
    let result = run_static(&image(&code), 1000, 1_000_000).unwrap();
    assert_eq!(result.completion_reason, "exit");
    assert_eq!(result.exit_code, Some(42));
    assert_eq!(result.syscalls.len(), 1);
}

#[test]
fn static_guest_captures_stdout_without_host_write() {
    let code = [
        0xb8, 1, 0, 0, 0, // write
        0xbf, 1, 0, 0, 0, // stdout
        0x48, 0xbe, 0x80, 1, 0x40, 0, 0, 0, 0, 0, // guest address 0x400180
        0xba, 5, 0, 0, 0, // length
        0x0f, 0x05, // syscall
        0xb8, 60, 0, 0, 0, // exit
        0x31, 0xff, // xor edi,edi
        0x0f, 0x05, // syscall
    ];
    let mut data = image(&code);
    data[0x180..0x185].copy_from_slice(b"hello");
    let result = run_static(&data, 1000, 1_000_000).unwrap();
    assert_eq!(result.completion_reason, "exit");
    assert_eq!(result.stdout_base64, "aGVsbG8=");
    assert_eq!(result.stderr_base64, "");
}

#[test]
fn static_guest_receives_linux_entry_stack() {
    let code = [
        0x48, 0x8b, 0x04, 0x24, // mov rax,[rsp] -> argc
        0x89, 0xc7, // mov edi,eax
        0xb8, 60, 0, 0, 0, // exit
        0x0f, 0x05,
    ];
    let result = run_static(&image(&code), 1000, 1_000_000).unwrap();
    assert_eq!(result.exit_code, Some(1));
    assert_eq!(result.initial_stack_pointer % 16, 0);
}

#[test]
fn unsupported_syscall_and_budget_stop_explicitly() {
    let unsupported = [0xb8, 41, 0, 0, 0, 0x0f, 0x05];
    let result = run_static(&image(&unsupported), 1000, 1_000_000).unwrap();
    assert_eq!(result.completion_reason, "unsupported_syscall");
    assert_eq!(result.unsupported_syscall, Some(41));
    let result = run_static(&image(&[0xeb, 0xfe]), 100, 1_000_000).unwrap();
    assert_eq!(result.completion_reason, "instruction_limit");
    assert_eq!(result.instructions, 100);
}

#[test]
fn i386_entry_stack_and_int80_exit_are_modeled() {
    let code = [
        0x8b, 0x1c, 0x24, // mov ebx,[esp] -> argc
        0xb8, 1, 0, 0, 0, // mov eax,1 -> exit
        0xcd, 0x80, // int 0x80
    ];
    let result = run_static32(&image32(&code), 1000, 1_000_000).unwrap();
    assert_eq!(result.architecture, "x86");
    assert_eq!(result.exit_code, Some(1));
    assert_eq!(result.initial_stack_pointer % 16, 0);
}

#[test]
fn i386_other_interrupt_stops_explicitly() {
    let result = run_static32(&image32(&[0xcd, 0x81]), 1000, 1_000_000).unwrap();
    assert_eq!(result.completion_reason, "unsupported_interrupt");
    assert_eq!(result.unsupported_interrupt, Some(0x81));
}
