use super::*;

const BASE: u64 = 0x100000;
const LOW: u64 = 0x200000;
const SP: u64 = LOW + 0x200;

struct Fixture {
    image: Vec<u8>,
    stack: Vec<u8>,
}
impl Fixture {
    fn new(header: [u8; 4], codes: &[u8]) -> Self {
        let mut f = Self {
            image: vec![0; 0x4000],
            stack: vec![0; 0x1000],
        };
        f.image[0x1000..0x1100].fill(0x90);
        f.entry(
            0x200,
            Function {
                begin: 0x1000,
                end: 0x1100,
                unwind: 0x300,
            },
        );
        f.image[0x300..0x304].copy_from_slice(&header);
        f.image[0x304..0x304 + codes.len()].copy_from_slice(codes);
        f
    }
    fn entry(&mut self, at: usize, function: Function) {
        for (i, value) in [function.begin, function.end, function.unwind]
            .into_iter()
            .enumerate()
        {
            self.image[at + i * 4..at + i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    fn word(&mut self, address: u64, value: u64) {
        let offset = (address - LOW) as usize;
        self.stack[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn context(&self) -> Context {
        let mut c = Context {
            rip: BASE + 0x1040,
            eflags: 0x282,
            ..Context::default()
        };
        c.integer[RSP] = SP;
        c
    }
    fn image(&mut self) -> Image {
        Image::parse(self, BASE, 0x4000, 0x200, 12).unwrap()
    }
    fn unwind(&mut self, c: &Context) -> Result<Frame> {
        let image = self.image();
        unwind(
            self,
            &image,
            c,
            Stack {
                low: LOW,
                high: LOW + 0x1000,
            },
            3,
        )
    }
}
impl Memory for Fixture {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<()> {
        let source = if (BASE..BASE + self.image.len() as u64).contains(&address) {
            self.image
                .get((address - BASE) as usize..(address - BASE) as usize + output.len())
        } else if (LOW..LOW + self.stack.len() as u64).contains(&address) {
            self.stack
                .get((address - LOW) as usize..(address - LOW) as usize + output.len())
        } else {
            None
        };
        let source = source.ok_or(Error::Read {
            address,
            size: output.len(),
        })?;
        output.copy_from_slice(source);
        Ok(())
    }
}

#[test]
fn small_allocation_body_and_partial_prologue_have_distinct_stacks() {
    let mut f = Fixture::new([1, 4, 1, 0], &[4, 0x42]);
    f.word(SP + 40, 0x7777);
    f.word(SP, 0x8888);
    let original = f.context();
    let frame = f.unwind(&original).unwrap();
    assert_eq!(
        (frame.caller.rip, frame.caller.integer[RSP]),
        (0x7777, SP + 48)
    );
    assert_eq!(frame.caller.eflags, original.eflags);
    assert_eq!(original.integer[RSP], SP);
    let mut early = original.clone();
    early.rip = BASE + 0x1002;
    let frame = f.unwind(&early).unwrap();
    assert_eq!(
        (frame.caller.rip, frame.caller.integer[RSP]),
        (0x8888, SP + 8)
    );
}

#[test]
fn both_large_allocation_encodings_and_volatile_saves_are_consumed() {
    for (header, codes) in [
        ([1, 8, 3, 0], vec![8, 1, 0x24, 0, 1, 0]),
        ([1, 8, 4, 0], vec![8, 0x11, 0x20, 1, 0, 0, 1, 0]),
    ] {
        let mut f = Fixture::new(header, &codes);
        f.word(SP + 0x120, 0x1234);
        f.word(SP + 0x128, 0x7777);
        let c = f.context();
        let frame = f.unwind(&c).unwrap();
        assert_eq!(frame.caller.integer[0], 0x1234);
        assert_eq!(
            (frame.caller.rip, frame.caller.integer[RSP]),
            (0x7777, SP + 0x130)
        );
    }
}

#[test]
fn saved_integer_and_xmm_offsets_restore_actual_bytes() {
    // SAVE_XMM128 xmm6,+0x20; SAVE_NONVOL r12,+0x10; allocation0x40.
    let mut f = Fixture::new([1, 12, 5, 0], &[12, 0x68, 2, 0, 8, 0xc4, 2, 0, 4, 0x72]);
    f.word(SP + 0x10, 0x1234);
    f.word(SP + 0x20, 0xfeed);
    f.word(SP + 0x28, 0xbeef);
    f.word(SP + 0x40, 0x7777);
    let c = f.context();
    let frame = f.unwind(&c).unwrap();
    assert_eq!(frame.caller.integer[12], 0x1234);
    assert_eq!(frame.caller.xmm[6], 0xbeef_u128 << 64 | 0xfeed);
    assert_eq!(
        (frame.caller.rip, frame.caller.integer[RSP]),
        (0x7777, SP + 0x48)
    );
    let mut far = Fixture::new(
        [1, 12, 7, 0],
        &[12, 0x69, 0x20, 0, 0, 0, 8, 0xc5, 0x10, 0, 0, 0, 4, 0x72],
    );
    far.stack.clone_from(&f.stack);
    assert_eq!(far.unwind(&c).unwrap().caller, frame.caller);
}

#[test]
fn frame_pointer_establisher_and_partial_frame_setup_are_distinguished() {
    let mut f = Fixture::new([1, 10, 3, 0x25], &[10, 3, 5, 0x72, 1, 0x50]);
    let mut c = f.context();
    c.integer[RSP] = LOW + 0x100;
    c.integer[5] = SP + 32;
    f.word(SP + 64, 0x5555);
    f.word(SP + 72, 0x7777);
    let frame = f.unwind(&c).unwrap();
    assert_eq!(frame.establisher, SP);
    assert_eq!(frame.caller.integer[5], 0x5555);
    assert_eq!(
        (frame.caller.rip, frame.caller.integer[RSP]),
        (0x7777, SP + 80)
    );
    c.rip = BASE + 0x1000;
    c.integer[RSP] = SP;
    f.word(SP, 0x7777);
    assert_eq!(f.unwind(&c).unwrap().establisher, SP);
}

#[test]
fn handler_and_scope_are_data_until_dispatch_invokes_them() {
    let mut f = Fixture::new([9, 4, 1, 0], &[4, 0x42]);
    f.word(SP + 40, 0x7777);
    f.image[0x308..0x30c].copy_from_slice(&0x1400_u32.to_le_bytes());
    f.image[0x30c..0x310].copy_from_slice(&1_u32.to_le_bytes());
    for (i, value) in [0x1000_u32, 0x1080, 1, 0x1090].into_iter().enumerate() {
        f.image[0x310 + i * 4..0x314 + i * 4].copy_from_slice(&value.to_le_bytes());
    }
    let c = f.context();
    let frame = f.unwind(&c).unwrap();
    assert_eq!(
        frame.handler,
        Some(Handler {
            address: BASE + 0x1400,
            data: BASE + 0x30c,
            flags: 1
        })
    );
    let image = f.image();
    let scopes = c_scopes(&mut f, &image, BASE + 0x30c).unwrap();
    assert_eq!(
        scopes,
        [Scope {
            begin: 0x1000,
            end: 0x1080,
            handler: 1,
            target: 0x1090
        }]
    );
    assert_eq!(frame.caller.rip, 0x7777); // No jump to the catch was manufactured.
    let mut early = c;
    early.rip = BASE + 0x1002;
    f.word(SP, 0x8888);
    assert!(f.unwind(&early).unwrap().handler.is_none());
}

#[test]
fn chained_allocations_and_cycles_have_bounded_results() {
    let mut f = Fixture::new([9, 4, 1, 0], &[4, 0x32]);
    f.image[0x308..0x30c].copy_from_slice(&0x1400_u32.to_le_bytes());
    f.entry(
        0x20c,
        Function {
            begin: 0x1200,
            end: 0x1300,
            unwind: 0x340,
        },
    );
    f.image[0x1200..0x1300].fill(0x90);
    f.image[0x340..0x348].copy_from_slice(&[0x21, 4, 1, 0, 4, 0x12, 0, 0]);
    f.entry(
        0x348,
        Function {
            begin: 0x1000,
            end: 0x1100,
            unwind: 0x300,
        },
    );
    f.word(SP + 48, 0x7777);
    let image = Image::parse(&mut f, BASE, 0x4000, 0x200, 24).unwrap();
    let mut c = f.context();
    c.rip = BASE + 0x1240;
    let frame = unwind(
        &mut f,
        &image,
        &c,
        Stack {
            low: LOW,
            high: LOW + 0x1000,
        },
        1,
    )
    .unwrap();
    assert_eq!(frame.chains, 1);
    assert_eq!(frame.caller.integer[RSP], SP + 56);
    assert!(frame.handler.is_some());
    f.entry(
        0x348,
        Function {
            begin: 0x1200,
            end: 0x1300,
            unwind: 0x340,
        },
    );
    assert_eq!(
        unwind(
            &mut f,
            &image,
            &c,
            Stack {
                low: LOW,
                high: LOW + 0x1000
            },
            1
        ),
        Err(Error::Invalid("chained unwind cycle"))
    );
}

#[test]
fn version_two_body_skips_epilogue_descriptors_and_keeps_handler_data_offset() {
    let mut f = Fixture::new([0x1a, 8, 5, 0], &[3, 6, 4, 6, 8, 1, 0x2e, 0, 1, 0x30]);
    f.image[0x310..0x314].copy_from_slice(&0x1400_u32.to_le_bytes());
    f.word(SP + 0x170, 0x3333);
    f.word(SP + 0x178, 0x7777);
    let c = f.context();
    let frame = f.unwind(&c).unwrap();
    assert_eq!(frame.caller.integer[3], 0x3333);
    assert_eq!(
        (frame.caller.rip, frame.caller.integer[RSP]),
        (0x7777, SP + 0x180)
    );
    assert_eq!(frame.handler.unwrap().data, BASE + 0x314);
}

#[test]
fn version_two_near_end_ret_and_long_offset_forward_epilogues() {
    let mut f = Fixture::new([2, 4, 3, 0], &[1, 0x16, 0, 6, 4, 0x42]);
    f.image[0x10ff] = 0xc3;
    let mut c = f.context();
    c.rip = BASE + 0x10ff;
    f.word(SP, 0x7777);
    let frame = f.unwind(&c).unwrap();
    assert!(frame.epilogue);
    assert_eq!(frame.caller.integer[RSP], SP + 8);
    let mut f = Fixture::new([2, 4, 4, 0], &[3, 6, 4, 6, 4, 0x42, 1, 0x30]);
    f.image[0x10fc..0x1100].copy_from_slice(&[0x5b, 0xeb, 0, 0xc3]);
    c.rip = BASE + 0x10fc;
    f.word(SP, 0x3333);
    f.word(SP + 8, 0x7777);
    let frame = f.unwind(&c).unwrap();
    assert!(frame.epilogue);
    assert_eq!(frame.caller.integer[3], 0x3333);
    assert_eq!(frame.caller.rip, 0x7777);
}

#[test]
fn v1_add_pop_rep_ret_and_frame_based_epilogues_restore_without_double_allocating() {
    let mut f = Fixture::new([1, 5, 2, 0], &[5, 0x42, 1, 0xc0]);
    f.image[0x1040..0x1048].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0x41, 0x5c, 0xf3, 0xc3]);
    f.word(SP + 40, 0x1212);
    f.word(SP + 48, 0x7777);
    let c = f.context();
    let frame = f.unwind(&c).unwrap();
    assert!(frame.epilogue);
    assert_eq!(frame.caller.integer[12], 0x1212);
    assert_eq!(frame.caller.integer[RSP], SP + 56);
    let mut f = Fixture::new([1, 10, 3, 0x25], &[10, 3, 5, 0x72, 1, 0x50]);
    f.image[0x1040..0x1046].copy_from_slice(&[0x48, 0x8d, 0x65, 0x20, 0x5d, 0xc3]);
    let mut c = f.context();
    c.integer[RSP] = LOW + 0x100;
    c.integer[5] = SP + 32;
    f.word(SP + 64, 0x5555);
    f.word(SP + 72, 0x7777);
    let frame = f.unwind(&c).unwrap();
    assert!(frame.epilogue);
    assert_eq!(frame.establisher, SP);
    assert_eq!(frame.caller.integer[5], 0x5555);
    assert_eq!(frame.caller.integer[RSP], SP + 80);
}

#[test]
fn machine_frames_restore_rip_rsp_and_preserve_fault_flags_without_extra_return() {
    for error in [false, true] {
        let mut f = Fixture::new([1, 1, 1, 0], &[1, if error { 0x1a } else { 0x0a }]);
        let at = SP + if error { 8 } else { 0 };
        for (i, value) in [0x7777, 0x10, 0x246, SP + 0x100, 0x18]
            .into_iter()
            .enumerate()
        {
            f.word(at + i as u64 * 8, value);
        }
        let c = f.context();
        let frame = f.unwind(&c).unwrap();
        assert!(frame.machine_frame);
        assert_eq!(frame.caller.rip, 0x7777);
        assert_eq!(frame.caller.integer[RSP], SP + 0x100);
        assert_eq!(
            (frame.caller.cs, frame.caller.ss, frame.caller.eflags),
            (c.cs, c.ss, c.eflags)
        );
    }
}

#[test]
fn saved_values_use_establisher_frame_when_rsp_contains_dynamic_allocations() {
    let mut f = Fixture::new([1, 12, 5, 0x25], &[12, 0xc4, 2, 0, 10, 3, 5, 0x72, 1, 0x50]);
    let mut c = f.context();
    c.integer[RSP] = LOW + 0x100;
    c.integer[5] = SP + 32;
    f.word(LOW + 0x110, 0xdead);
    f.word(SP + 0x10, 0x1212);
    f.word(SP + 64, 0x5555);
    f.word(SP + 72, 0x7777);
    let frame = f.unwind(&c).unwrap();
    assert_eq!(frame.caller.integer[12], 0x1212);
    assert_eq!(frame.caller.integer[RSP], SP + 80);
}

#[test]
fn malformed_metadata_and_out_of_stack_reads_never_modify_input_context() {
    for (header, codes, error) in [
        ([3, 4, 0, 0], vec![], Error::Unsupported("unwind version")),
        (
            [0x29, 4, 0, 0],
            vec![],
            Error::Invalid("handler/chained flags"),
        ),
        (
            [1, 4, 1, 0],
            vec![4, 1],
            Error::Invalid("truncated unwind operands"),
        ),
        (
            [1, 4, 1, 0],
            vec![4, 7],
            Error::Unsupported("unwind opcode"),
        ),
    ] {
        let mut f = Fixture::new(header, &codes);
        let c = f.context();
        let before = c.clone();
        assert_eq!(f.unwind(&c), Err(error));
        assert_eq!(c, before);
    }
    let mut f = Fixture::new([1, 4, 1, 0], &[4, 0xf2]);
    let mut c = f.context();
    c.integer[RSP] = LOW + 0xff0;
    assert_eq!(f.unwind(&c), Err(Error::Stack));
    let mut f = Fixture::new([1, 0, 0, 0], &[]);
    f.entry(
        0x20c,
        Function {
            begin: 0x1080,
            end: 0x1200,
            unwind: 0x340,
        },
    );
    assert_eq!(
        Image::parse(&mut f, BASE, 0x4000, 0x200, 24),
        Err(Error::Invalid("unsorted/overlapping runtime functions"))
    );
    assert_eq!(
        Image::parse(&mut f, BASE, 0x4000, 0x200, 13),
        Err(Error::Invalid("runtime-function directory span"))
    );
}

#[test]
fn leaf_frames_pop_only_the_owned_return_slot_and_scope_tables_are_bounded() {
    let mut f = Fixture::new([1, 0, 0, 0], &[]);
    let image = Image::parse(&mut f, BASE, 0x4000, 0, 0).unwrap();
    let c = f.context();
    f.word(SP, 0x7777);
    assert_eq!(
        unwind(
            &mut f,
            &image,
            &c,
            Stack {
                low: LOW,
                high: LOW + 0x1000
            },
            1
        )
        .unwrap()
        .caller
        .integer[RSP],
        SP + 8
    );
    f.image[0x800..0x804].copy_from_slice(&4097_u32.to_le_bytes());
    assert_eq!(
        c_scopes(&mut f, &image, BASE + 0x800),
        Err(Error::Invalid("scope table count"))
    );
}
