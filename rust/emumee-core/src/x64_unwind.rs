//! Checked AMD64 virtual-unwind primitives over caller-supplied guest reads.
//! No guest CPU/memory mutation, handler execution, or implicit caught exception.
//! Dispatch uses the returned frame/handler; language and GS checks are separate.
use serde::Serialize;
use thiserror::Error;

const MAX_FUNCTIONS: usize = 65536;
const MAX_CHAINS: usize = 16;
pub const RSP: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid x64 unwind metadata: {0}")]
    Invalid(&'static str),
    #[error("Unsupported x64 unwind form: {0}")]
    Unsupported(&'static str),
    #[error("Guest unwind read failed at {address:#x}, size {size}")]
    Read { address: u64, size: usize },
    #[error("Unwind stack read or result is outside the owned stack")]
    Stack,
}
pub type Result<T> = std::result::Result<T, Error>;
pub trait Memory {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<()>;
}
impl<F: FnMut(u64, &mut [u8]) -> Result<()>> Memory for F {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<()> {
        self(address, bytes)
    }
}

/// Windows register numbers: RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Context {
    pub rip: u64,
    pub integer: [u64; 16],
    pub xmm: [u128; 16],
    pub eflags: u32,
    pub cs: u16,
    pub ss: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Stack {
    pub low: u64,
    pub high: u64,
}
impl Stack {
    fn check(self, address: u64, bytes: usize) -> Result<()> {
        if self.low >= self.high
            || address < self.low
            || address
                .checked_add(bytes as u64)
                .is_none_or(|end| end > self.high)
        {
            return Err(Error::Stack);
        }
        Ok(())
    }
    fn value<const N: usize>(self, memory: &mut impl Memory, address: u64) -> Result<[u8; N]> {
        self.check(address, N)?;
        let mut value = [0; N];
        memory.read(address, &mut value)?;
        Ok(value)
    }
    fn qword(self, memory: &mut impl Memory, address: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.value(memory, address)?))
    }
    fn pop(self, memory: &mut impl Memory, context: &mut Context) -> Result<u64> {
        let value = self.qword(memory, context.integer[RSP])?;
        context.integer[RSP] = add(context.integer[RSP], 8)?;
        self.check(context.integer[RSP], 0)?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Function {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Image {
    pub base: u64,
    pub size: u32,
    pub functions: Vec<Function>,
}
impl Image {
    pub fn parse(
        memory: &mut impl Memory,
        base: u64,
        size: u32,
        directory_rva: u32,
        directory_bytes: u32,
    ) -> Result<Self> {
        if size == 0 || base.checked_add(size as u64).is_none() {
            return Err(Error::Invalid("image span"));
        }
        let mut image = Self {
            base,
            size,
            functions: Vec::new(),
        };
        if directory_rva == 0 && directory_bytes == 0 {
            return Ok(image);
        }
        if directory_rva == 0
            || directory_bytes == 0
            || directory_bytes % 12 != 0
            || directory_bytes as usize / 12 > MAX_FUNCTIONS
        {
            return Err(Error::Invalid("runtime-function directory span"));
        }
        let mut data = vec![0; directory_bytes as usize];
        image.read(memory, directory_rva, &mut data)?;
        for item in data.chunks_exact(12) {
            let function = function(item);
            image.validate(function)?;
            if image
                .functions
                .last()
                .is_some_and(|last| last.end > function.begin)
            {
                return Err(Error::Invalid("unsorted/overlapping runtime functions"));
            }
            image.functions.push(function);
        }
        Ok(image)
    }
    fn validate(&self, function: Function) -> Result<()> {
        if function.begin >= function.end
            || function.end > self.size
            || function.unwind == 0
            || function.unwind >= self.size
            || function.unwind & 3 != 0
        {
            return Err(Error::Invalid("runtime-function bounds/alignment"));
        }
        Ok(())
    }
    fn read(&self, memory: &mut impl Memory, rva: u32, bytes: &mut [u8]) -> Result<()> {
        if (rva as u64)
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.size as u64)
        {
            return Err(Error::Invalid("image read outside mapping"));
        }
        memory.read(add(self.base, rva as u64)?, bytes)
    }
    pub fn lookup(&self, pc: u64) -> Option<Function> {
        let offset = pc.checked_sub(self.base)?;
        if offset >= self.size as u64 {
            return None;
        }
        let position = self.functions.partition_point(|f| f.begin as u64 <= offset);
        position
            .checked_sub(1)
            .and_then(|i| self.functions.get(i))
            .copied()
            .filter(|f| offset < f.end as u64)
    }
}
fn function(bytes: &[u8]) -> Function {
    Function {
        begin: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        end: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        unwind: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(Error::Invalid("address overflow"))
}
fn signed_add(a: u64, b: i64) -> Result<u64> {
    a.checked_add_signed(b)
        .ok_or(Error::Invalid("signed address overflow"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Handler {
    pub address: u64,
    pub data: u64,
    pub flags: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub control_pc: u64,
    pub function: Option<Function>,
    /// Metadata frame base. For epilogues, no handler is returned and this is
    /// not Windows' incidental RtlVirtualUnwind epilogue diagnostic output.
    pub establisher: u64,
    pub handler: Option<Handler>,
    pub caller: Context,
    pub chains: usize,
    pub epilogue: bool,
    pub machine_frame: bool,
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Push(u8),
    Alloc(u32),
    Frame,
    Save(u8, u32),
    Xmm(u8, u32),
    Machine(bool),
}
#[derive(Debug)]
struct Info {
    version: u8,
    flags: u8,
    prolog: u8,
    frame: u8,
    frame_offset: u8,
    ops: Vec<(u8, Op)>,
    epilogues: Vec<(u32, u32)>,
    tail: u32,
}
fn info(image: &Image, memory: &mut impl Memory, f: Function) -> Result<Info> {
    let mut header = [0; 4];
    image.read(memory, f.unwind, &mut header)?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    if !matches!(version, 1 | 2) {
        return Err(Error::Unsupported("unwind version"));
    }
    if flags & !7 != 0 || flags & 4 != 0 && flags & 3 != 0 {
        return Err(Error::Invalid("handler/chained flags"));
    }
    let frame = header[3] & 15;
    if frame == 0 && header[3] >> 4 != 0 {
        return Err(Error::Invalid("frame register"));
    }
    let count = header[2] as usize;
    let mut codes = vec![0; count * 2];
    image.read(
        memory,
        f.unwind
            .checked_add(4)
            .ok_or(Error::Invalid("unwind overflow"))?,
        &mut codes,
    )?;
    let tail = f
        .unwind
        .checked_add(4 + ((count as u32 + 1) & !1) * 2)
        .ok_or(Error::Invalid("unwind tail"))?;
    let mut result = Info {
        version,
        flags,
        prolog: header[1],
        frame,
        frame_offset: header[3] >> 4,
        ops: Vec::new(),
        epilogues: Vec::new(),
        tail,
    };
    let mut index = 0;
    let mut epilog_size = None;
    while index < count {
        let offset = codes[index * 2];
        let opcode = codes[index * 2 + 1] & 15;
        let detail = codes[index * 2 + 1] >> 4;
        let slots = match opcode {
            0 | 2 | 3 | 10 => 1,
            1 => match detail {
                0 => 2,
                1 => 3,
                _ => return Err(Error::Invalid("large allocation encoding")),
            },
            4 | 8 => 2,
            5 | 9 => 3,
            6 if version == 2 => {
                if epilog_size.is_none() && detail & 1 == 0 {
                    2
                } else {
                    1
                }
            }
            _ => return Err(Error::Unsupported("unwind opcode")),
        };
        if index + slots > count {
            return Err(Error::Invalid("truncated unwind operands"));
        }
        let operand = if slots > 1 {
            let first = (index + 1) * 2;
            if slots == 2 {
                u16::from_le_bytes(codes[first..first + 2].try_into().unwrap()) as u32
            } else {
                u32::from_le_bytes(codes[first..first + 4].try_into().unwrap())
            }
        } else {
            0
        };
        if opcode == 6 {
            if !result.ops.is_empty() {
                return Err(Error::Invalid(
                    "epilogue descriptor after unwind operations",
                ));
            }
            let distance = if epilog_size.is_some() {
                offset as u32 | (detail as u32) << 8
            } else {
                if detail > 1 || offset == 0 {
                    return Err(Error::Invalid("epilogue descriptor"));
                }
                epilog_size = Some(offset as u32);
                if detail & 1 != 0 {
                    offset as u32
                } else {
                    operand & 0xff | (operand >> 12) << 8
                }
            };
            if distance != 0 {
                let start = f
                    .end
                    .checked_sub(distance)
                    .filter(|start| *start >= f.begin)
                    .ok_or(Error::Invalid("epilogue start"))?;
                let end = start
                    .checked_add(epilog_size.unwrap())
                    .filter(|end| *end <= f.end)
                    .ok_or(Error::Invalid("epilogue end"))?;
                result.epilogues.push((start, end));
            }
            index += slots;
            continue;
        }
        if epilog_size.is_some() && result.ops.is_empty() && index % 2 != 0 {
            return Err(Error::Invalid(
                "unpaired epilogue descriptors before operations",
            ));
        }
        let operation = match opcode {
            // Windows consumes the encoded register number; virtualized images
            // also describe volatile saves with these opcodes.
            0 => Op::Push(detail),
            1 => Op::Alloc(if detail == 0 { operand * 8 } else { operand }),
            2 => Op::Alloc(detail as u32 * 8 + 8),
            3 if detail == 0 && frame != 0 => Op::Frame,
            4 | 5 => Op::Save(detail, if opcode == 4 { operand * 8 } else { operand }),
            8 | 9 => Op::Xmm(detail, if opcode == 8 { operand * 16 } else { operand }),
            10 if detail <= 1 => Op::Machine(detail != 0),
            _ => return Err(Error::Invalid("register/opcode details")),
        };
        if let Op::Alloc(size) = operation {
            if size == 0 || size & 7 != 0 {
                return Err(Error::Invalid("stack allocation alignment"));
            }
        }
        result.ops.push((offset, operation));
        index += slots;
    }
    Ok(result)
}

/// Virtual-unwind one frame. `handler_mask` selects exception(1)/unwind(2).
/// The caller supplies the actual control PC; no silent -1 adjustment is made.
pub fn unwind(
    memory: &mut impl Memory,
    image: &Image,
    context: &Context,
    stack: Stack,
    handler_mask: u8,
) -> Result<Frame> {
    if handler_mask & !3 != 0 {
        return Err(Error::Invalid("handler mask"));
    }
    stack.check(context.integer[RSP], 0)?;
    if context.integer[RSP] & 7 != 0 {
        return Err(Error::Stack);
    }
    let mut caller = context.clone();
    let selected = image.lookup(context.rip);
    let mut frame = Frame {
        control_pc: context.rip,
        function: selected,
        establisher: context.integer[RSP],
        handler: None,
        caller: caller.clone(),
        chains: 0,
        epilogue: false,
        machine_frame: false,
    };
    let Some(mut current) = selected else {
        if context.rip < image.base || context.rip >= add(image.base, image.size as u64)? {
            return Err(Error::Invalid("PC outside image"));
        }
        caller.rip = stack.pop(memory, &mut caller)?;
        frame.caller = caller;
        return Ok(frame);
    };
    let mut seen = Vec::new();
    for chain in 0..MAX_CHAINS {
        image.validate(current)?;
        if seen.contains(&current.unwind) {
            return Err(Error::Invalid("chained unwind cycle"));
        }
        seen.push(current.unwind);
        let parsed = info(image, memory, current)?;
        let offset = context
            .rip
            .checked_sub(add(image.base, current.begin as u64)?)
            .unwrap_or(u64::MAX);
        let in_body = chain != 0 || offset >= parsed.prolog as u64;
        if chain == 0
            && parsed.frame != 0
            && (in_body
                || parsed.flags & 4 != 0
                || parsed
                    .ops
                    .iter()
                    .any(|(at, op)| matches!(op, Op::Frame) && *at as u64 <= offset))
        {
            frame.establisher = caller.integer[parsed.frame as usize]
                .checked_sub(parsed.frame_offset as u64 * 16)
                .ok_or(Error::Stack)?;
            stack.check(frame.establisher, 0)?;
        }
        if chain == 0 && in_body {
            let rva = (context.rip - image.base) as u32;
            let declared = parsed
                .epilogues
                .iter()
                .any(|(start, end)| *start <= rva && rva < *end);
            if parsed.version == 1 || declared {
                if let Some(epilog) = epilogue(
                    memory,
                    image,
                    current,
                    context,
                    stack,
                    parsed.frame,
                    declared,
                )? {
                    frame.caller = epilog;
                    frame.epilogue = true;
                    return Ok(frame);
                }
                if declared {
                    return Err(Error::Unsupported("declared epilogue instructions"));
                }
            }
        }
        for (at, operation) in &parsed.ops {
            if !in_body && *at as u64 > offset {
                continue;
            }
            if frame.machine_frame {
                return Err(Error::Invalid("operations after machine frame"));
            }
            match *operation {
                Op::Push(register) => {
                    let value = stack.qword(memory, caller.integer[RSP])?;
                    caller.integer[register as usize] = value;
                    caller.integer[RSP] = add(caller.integer[RSP], 8)?;
                    stack.check(caller.integer[RSP], 0)?;
                }
                Op::Alloc(size) => {
                    caller.integer[RSP] = add(caller.integer[RSP], size as u64)?;
                    stack.check(caller.integer[RSP], 0)?;
                }
                Op::Frame => {
                    caller.integer[RSP] = caller.integer[parsed.frame as usize]
                        .checked_sub(parsed.frame_offset as u64 * 16)
                        .ok_or(Error::Stack)?;
                    stack.check(caller.integer[RSP], 0)?;
                }
                Op::Save(register, offset) => {
                    caller.integer[register as usize] =
                        stack.qword(memory, add(frame.establisher, offset as u64)?)?;
                }
                Op::Xmm(register, offset) => {
                    caller.xmm[register as usize] = u128::from_le_bytes(
                        stack.value(memory, add(frame.establisher, offset as u64)?)?,
                    );
                }
                Op::Machine(error) => {
                    let address = add(caller.integer[RSP], if error { 8 } else { 0 })?;
                    let data = stack.value::<40>(memory, address)?;
                    caller.rip = u64::from_le_bytes(data[..8].try_into().unwrap());
                    caller.integer[RSP] = u64::from_le_bytes(data[24..32].try_into().unwrap());
                    // RtlVirtualUnwind restores only RIP/RSP here. This is not
                    // an IRET emulation or permission to replace fault flags.
                    stack.check(caller.integer[RSP], 0)?;
                    frame.machine_frame = true;
                }
            }
        }
        frame.chains = chain;
        if parsed.flags & 4 != 0 {
            if frame.machine_frame {
                return Err(Error::Invalid("chained machine frame"));
            }
            let mut entry = [0; 12];
            image.read(memory, parsed.tail, &mut entry)?;
            current = function(&entry);
            continue;
        }
        if in_body && parsed.flags & handler_mask != 0 {
            let mut handler = [0; 4];
            image.read(memory, parsed.tail, &mut handler)?;
            let rva = u32::from_le_bytes(handler);
            if rva == 0 || rva >= image.size {
                return Err(Error::Invalid("language-handler RVA"));
            }
            let data = parsed
                .tail
                .checked_add(4)
                .ok_or(Error::Invalid("handler data overflow"))?;
            if data > image.size {
                return Err(Error::Invalid("handler data"));
            }
            frame.handler = Some(Handler {
                address: add(image.base, rva as u64)?,
                data: add(image.base, data as u64)?,
                flags: parsed.flags & 3,
            });
        }
        if !frame.machine_frame {
            caller.rip = stack.pop(memory, &mut caller)?;
        }
        frame.caller = caller;
        return Ok(frame);
    }
    Err(Error::Invalid("chained unwind depth"))
}

fn epilogue(
    memory: &mut impl Memory,
    image: &Image,
    function: Function,
    original: &Context,
    stack: Stack,
    frame_register: u8,
    declared: bool,
) -> Result<Option<Context>> {
    let mut context = original.clone();
    let mut pc = original.rip;
    let mut adjusted = false;
    for _ in 0..32 {
        let rva = u32::try_from(
            pc.checked_sub(image.base)
                .ok_or(Error::Invalid("epilogue PC"))?,
        )
        .map_err(|_| Error::Invalid("epilogue PC"))?;
        let count = (image
            .size
            .checked_sub(rva)
            .ok_or(Error::Invalid("epilogue PC"))? as usize)
            .min(15);
        let mut bytes = [0; 15];
        image.read(memory, rva, &mut bytes[..count])?;
        let bytes = &bytes[..count];
        if !adjusted && bytes.starts_with(&[0x48, 0x83, 0xc4]) && bytes.len() >= 4 && bytes[3] < 128
        {
            context.integer[RSP] = add(context.integer[RSP], bytes[3] as u64)?;
            pc = add(pc, 4)?;
            adjusted = true;
        } else if !adjusted && bytes.starts_with(&[0x48, 0x81, 0xc4]) && bytes.len() >= 7 {
            let size = i32::from_le_bytes(bytes[3..7].try_into().unwrap());
            if size < 0 {
                return Ok(None);
            }
            context.integer[RSP] = add(context.integer[RSP], size as u64)?;
            pc = add(pc, 7)?;
            adjusted = true;
        } else if !adjusted
            && bytes.len() >= 4
            && bytes[0] & 0xfe == 0x48
            && bytes[1] == 0x8d
            && bytes[2] >> 6 != 0
            && bytes[2] >> 6 != 3
            && bytes[2] >> 3 & 7 == 4
        {
            let sib = bytes[2] & 7 == 4;
            if sib && (bytes.len() < 5 || bytes[3] & 0xf8 != 0x20) {
                return Ok(None);
            }
            let register = ((if sib { bytes[3] } else { bytes[2] }) & 7) | ((bytes[0] & 1) << 3);
            if register != frame_register || register == 0 {
                return Ok(None);
            }
            let at = if sib { 4 } else { 3 };
            let (offset, length) = if bytes[2] >> 6 == 1 {
                (bytes[at] as i8 as i64, at as u64 + 1)
            } else if bytes.len() >= at + 4 {
                (
                    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as i64,
                    at as u64 + 4,
                )
            } else {
                return Ok(None);
            };
            context.integer[RSP] = signed_add(context.integer[register as usize], offset)?;
            pc = add(pc, length)?;
            adjusted = true;
        } else {
            let prefix = usize::from(bytes.first().is_some_and(|b| *b == 0x41 || *b == 0x49));
            if bytes.get(prefix).is_some_and(|b| (0x58..=0x5f).contains(b)) {
                let register = (bytes[prefix] - 0x58) as usize + prefix * 8;
                if register == RSP {
                    return Err(Error::Unsupported("epilogue POP RSP"));
                }
                context.integer[register] = stack.pop(memory, &mut context)?;
                pc = add(pc, prefix as u64 + 1)?;
                adjusted = true;
                continue;
            }
            let ret = bytes.starts_with(&[0xc3]) || bytes.starts_with(&[0xf3, 0xc3]);
            let ret_extra = bytes.starts_with(&[0xc2]) && bytes.len() >= 3;
            let rex = usize::from(bytes.first().is_some_and(|b| (0x48..=0x4f).contains(b)));
            let indirect_tail =
                bytes.len() >= rex + 2 && bytes[rex] == 0xff && bytes[rex + 1] & 0xf8 == 0x20;
            if ret || ret_extra || indirect_tail {
                context.rip = stack.pop(memory, &mut context)?;
                // Virtual unwind pops the return slot; it does not execute a
                // callee's RET-imm16 immediate adjustment (native Windows).
                stack.check(context.integer[RSP], 0)?;
                return Ok(Some(context));
            }
            let target = if bytes.first() == Some(&0xeb) && bytes.len() >= 2 {
                Some(signed_add(add(pc, 2)?, bytes[1] as i8 as i64)?)
            } else if bytes.first() == Some(&0xe9) && bytes.len() >= 5 {
                Some(signed_add(
                    add(pc, 5)?,
                    i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64,
                )?)
            } else {
                None
            };
            if let Some(target) = target {
                if target < image.base + function.begin as u64
                    || target >= image.base + function.end as u64
                {
                    context.rip = stack.pop(memory, &mut context)?;
                    return Ok(Some(context));
                }
                if declared && target > pc {
                    pc = target;
                    continue;
                }
            }
            return Ok(None);
        }
        stack.check(context.integer[RSP], 0)?;
    }
    Err(Error::Unsupported("epilogue instruction bound"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub begin: u32,
    pub end: u32,
    pub handler: u32,
    pub target: u32,
}
/// Decode only. Selecting/executing filters/finally/GS checks belongs to dispatch.
pub fn c_scopes(memory: &mut impl Memory, image: &Image, data: u64) -> Result<Vec<Scope>> {
    let rva = u32::try_from(
        data.checked_sub(image.base)
            .ok_or(Error::Invalid("scope pointer"))?,
    )
    .map_err(|_| Error::Invalid("scope pointer"))?;
    let mut count = [0; 4];
    image.read(memory, rva, &mut count)?;
    let count = u32::from_le_bytes(count);
    if count > 4096 {
        return Err(Error::Invalid("scope table count"));
    }
    let mut bytes = vec![0; count as usize * 16];
    image.read(
        memory,
        rva.checked_add(4)
            .ok_or(Error::Invalid("scope table overflow"))?,
        &mut bytes,
    )?;
    let mut scopes = Vec::new();
    for entry in bytes.chunks_exact(16) {
        let scope = Scope {
            begin: u32::from_le_bytes(entry[..4].try_into().unwrap()),
            end: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
            handler: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
            target: u32::from_le_bytes(entry[12..16].try_into().unwrap()),
        };
        if scope.begin >= scope.end
            || scope.end > image.size
            || scope.handler >= image.size && scope.handler != 1
            || scope.target >= image.size
        {
            return Err(Error::Invalid("scope record bounds"));
        }
        scopes.push(scope);
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests;
