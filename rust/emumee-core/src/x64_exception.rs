//! AMD64 Windows exception ABI records, independent of guest execution.
//! Updating unwind registers preserves all other CONTEXT bytes (debug, x87,
//! MXCSR, segments, home slots, and vector extensions).
use crate::x64_unwind::{Context, Error, Result};
pub mod scope;

pub const CONTEXT_BYTES: usize = 1232;
pub const EXCEPTION_BYTES: usize = 152;
pub const DISPATCHER_BYTES: usize = 80;
pub const MAX_PARAMETERS: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextRecord([u8; CONTEXT_BYTES]);
impl ContextRecord {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| Error::Invalid("CONTEXT size"))?,
        ))
    }
    pub fn bytes(&self) -> &[u8; CONTEXT_BYTES] {
        &self.0
    }
    pub fn registers(&self) -> Context {
        let mut context = Context {
            rip: qword(&self.0, 248),
            eflags: dword(&self.0, 68),
            cs: u16::from_le_bytes(self.0[56..58].try_into().unwrap()),
            ss: u16::from_le_bytes(self.0[66..68].try_into().unwrap()),
            ..Context::default()
        };
        for (i, value) in context.integer.iter_mut().enumerate() {
            *value = qword(&self.0, 120 + i * 8);
        }
        for (i, value) in context.xmm.iter_mut().enumerate() {
            *value = u128::from_le_bytes(self.0[416 + i * 16..432 + i * 16].try_into().unwrap());
        }
        context
    }
    /// This is a register update, not a new capture: ContextFlags is preserved.
    pub fn update(&mut self, context: &Context) {
        put64(&mut self.0, 248, context.rip);
        put32(&mut self.0, 68, context.eflags);
        self.0[56..58].copy_from_slice(&context.cs.to_le_bytes());
        self.0[66..68].copy_from_slice(&context.ss.to_le_bytes());
        for (i, value) in context.integer.iter().enumerate() {
            put64(&mut self.0, 120 + i * 8, *value);
        }
        for (i, value) in context.xmm.iter().enumerate() {
            self.0[416 + i * 16..432 + i * 16].copy_from_slice(&value.to_le_bytes());
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub nested_record: u64,
    pub address: u64,
    pub parameters: Vec<u64>,
}
impl ExceptionRecord {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EXCEPTION_BYTES {
            return Err(Error::Invalid("EXCEPTION_RECORD size"));
        }
        let count = dword(bytes, 24) as usize;
        if count > MAX_PARAMETERS {
            return Err(Error::Invalid("exception parameter count"));
        }
        Ok(Self {
            code: dword(bytes, 0),
            flags: dword(bytes, 4),
            nested_record: qword(bytes, 8),
            address: qword(bytes, 16),
            parameters: (0..count).map(|i| qword(bytes, 32 + i * 8)).collect(),
        })
    }
    pub fn bytes(&self) -> Result<[u8; EXCEPTION_BYTES]> {
        if self.parameters.len() > MAX_PARAMETERS {
            return Err(Error::Invalid("exception parameter count"));
        }
        let mut bytes = [0; EXCEPTION_BYTES];
        put32(&mut bytes, 0, self.code);
        put32(&mut bytes, 4, self.flags);
        put64(&mut bytes, 8, self.nested_record);
        put64(&mut bytes, 16, self.address);
        put32(&mut bytes, 24, self.parameters.len() as u32);
        for (i, value) in self.parameters.iter().enumerate() {
            put64(&mut bytes, 32 + i * 8, *value);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DispatcherContext {
    pub control_pc: u64,
    pub image_base: u64,
    pub function_entry: u64,
    pub establisher_frame: u64,
    pub target_ip: u64,
    pub context_record: u64,
    pub language_handler: u64,
    pub handler_data: u64,
    pub history_table: u64,
    pub scope_index: u32,
    pub fill: u32,
}
impl DispatcherContext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DISPATCHER_BYTES {
            return Err(Error::Invalid("DISPATCHER_CONTEXT size"));
        }
        Ok(Self {
            control_pc: qword(bytes, 0),
            image_base: qword(bytes, 8),
            function_entry: qword(bytes, 16),
            establisher_frame: qword(bytes, 24),
            target_ip: qword(bytes, 32),
            context_record: qword(bytes, 40),
            language_handler: qword(bytes, 48),
            handler_data: qword(bytes, 56),
            history_table: qword(bytes, 64),
            scope_index: dword(bytes, 72),
            fill: dword(bytes, 76),
        })
    }
    pub fn bytes(&self) -> [u8; DISPATCHER_BYTES] {
        let mut bytes = [0; DISPATCHER_BYTES];
        for (i, value) in [
            self.control_pc,
            self.image_base,
            self.function_entry,
            self.establisher_frame,
            self.target_ip,
            self.context_record,
            self.language_handler,
            self.handler_data,
            self.history_table,
        ]
        .iter()
        .enumerate()
        {
            put64(&mut bytes, i * 8, *value);
        }
        put32(&mut bytes, 72, self.scope_index);
        put32(&mut bytes, 76, self.fill);
        bytes
    }
}
fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exception_abi_matches_native_sdk_records() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native_x64_exception_abi.json"
        ))
        .unwrap();
        assert_eq!(golden["schema"], "emumee.native_exception_abi.v1");
        assert_eq!(golden["context_size"], CONTEXT_BYTES);
        assert_eq!(golden["exception_size"], EXCEPTION_BYTES);
        assert_eq!(golden["dispatcher_size"], DISPATCHER_BYTES);
        let decode = |name: &str| -> Vec<u8> {
            let hex = golden[name].as_str().unwrap();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        };
        let mut context = ContextRecord::from_bytes(&[0xa5; CONTEXT_BYTES]).unwrap();
        context.update(&Context {
            rip: 0x12345678,
            integer: std::array::from_fn(|i| i as u64 + 7),
            xmm: std::array::from_fn(|i| (i as u128) << 80),
            eflags: 0x202,
            cs: 0x10,
            ss: 0x18,
        });
        assert_eq!(context.bytes().as_slice(), decode("context"));
        let exception = ExceptionRecord {
            code: 0x80000003,
            flags: 0,
            nested_record: 0,
            address: 0x1234,
            parameters: (0..15).collect(),
        };
        assert_eq!(exception.bytes().unwrap().as_slice(), decode("exception"));
        let dispatcher = DispatcherContext {
            control_pc: 1,
            image_base: 2,
            function_entry: 3,
            establisher_frame: 4,
            target_ip: 5,
            context_record: 6,
            language_handler: 7,
            handler_data: 8,
            history_table: 9,
            scope_index: 10,
            fill: 11,
        };
        assert_eq!(dispatcher.bytes().as_slice(), decode("dispatcher"));
    }
    #[test]
    fn exception_context_update_preserves_unmodeled_state() {
        let original = [0xa5; CONTEXT_BYTES];
        let mut record = ContextRecord::from_bytes(&original).unwrap();
        let context = Context {
            rip: 0x12345678,
            integer: std::array::from_fn(|i| i as u64 + 7),
            xmm: std::array::from_fn(|i| (i as u128) << 80),
            eflags: 0x202,
            cs: 0x10,
            ss: 0x18,
        };
        record.update(&context);
        assert_eq!(record.registers(), context);
        for (i, value) in record.bytes().iter().enumerate() {
            if !(56..58).contains(&i)
                && !(66..72).contains(&i)
                && !(120..256).contains(&i)
                && !(416..672).contains(&i)
            {
                assert_eq!(*value, original[i], "unmodeled byte {i}");
            }
        }
        assert!(ContextRecord::from_bytes(&original[..1231]).is_err());
    }
    #[test]
    fn exception_records_validate_parameter_lengths_and_dispatcher_fields() {
        let record = ExceptionRecord {
            code: 0x80000003,
            flags: 0,
            nested_record: 0,
            address: 0x1234,
            parameters: (0..15).collect(),
        };
        assert_eq!(
            ExceptionRecord::from_bytes(&record.bytes().unwrap()).unwrap(),
            record
        );
        let mut oversized = record.clone();
        oversized.parameters.push(16);
        assert!(oversized.bytes().is_err());
        let mut bytes = record.bytes().unwrap();
        put32(&mut bytes, 24, 16);
        assert!(ExceptionRecord::from_bytes(&bytes).is_err());
        assert!(ExceptionRecord::from_bytes(&bytes[..151]).is_err());
        let bytes: [u8; DISPATCHER_BYTES] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            DispatcherContext::from_bytes(&bytes).unwrap().bytes(),
            bytes
        );
        assert!(DispatcherContext::from_bytes(&bytes[..79]).is_err());
    }
}
