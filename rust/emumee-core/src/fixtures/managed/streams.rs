//! Generated owned IL; no host CLR is involved.
use super::*;
struct Build {
    refs: Vec<Reference<'static>>,
    code: Vec<u8>,
    strings: Vec<u8>,
    locals: Vec<u8>,
}
impl Build {
    fn new() -> Self {
        let mut refs = vec![Reference::new(
            "mscorlib",
            "MemoryStream",
            ".ctor",
            &[0x20, 0, 1],
        )];
        refs[0].namespace = "System.IO";
        for (namespace, name) in [
            ("System.IO", "Stream"),
            ("System", "Byte"),
            ("System", "Object"),
            ("System.IO", "SeekOrigin"),
            ("System", "IDisposable"),
        ] {
            let mut r = Reference::new("mscorlib", name, "Unused", &[0, 0, 1]);
            r.namespace = namespace;
            refs.push(r);
        }
        Self {
            refs,
            code: Vec::new(),
            strings: vec![0],
            locals: vec![7, 3, 0x12, 5, 0x1d, 5, 0x12, 5],
        }
    }
    fn token(&mut self, op: u8, token: u32) {
        self.code.push(op);
        self.code.extend(token.to_le_bytes());
    }
    fn member(
        &mut self,
        namespace: &'static str,
        owner: &'static str,
        name: &'static str,
        signature: &[u8],
    ) -> u32 {
        if let Some(index) = self.refs.iter().position(|r| {
            r.namespace == namespace
                && r.type_name == owner
                && r.name == name
                && r.signature == signature
        }) {
            return index as u32 + 1;
        }
        let mut r = Reference::new("mscorlib", owner, name, signature);
        r.namespace = namespace;
        self.refs.push(r);
        self.refs.len() as u32
    }
    fn call(&mut self, owner: &'static str, name: &'static str, signature: &[u8]) {
        let namespace = if owner == "IDisposable" {
            "System"
        } else {
            "System.IO"
        };
        let row = self.member(namespace, owner, name, signature);
        self.token(0x6f, 0x0a000000 | row);
    }
    fn construct(&mut self, signature: &[u8]) {
        let row = self.member("System.IO", "MemoryStream", ".ctor", signature);
        self.token(0x73, 0x0a000000 | row);
    }
    fn i32(&mut self, n: i32) {
        if (0..=8).contains(&n) {
            self.code.push(0x16 + n as u8)
        } else {
            self.code.push(0x20);
            self.code.extend(n.to_le_bytes());
        }
    }
    fn i64(&mut self, n: i64) {
        self.code.push(0x21);
        self.code.extend(n.to_le_bytes());
    }
    fn seed(&mut self) {
        let row = self.member(
            "System",
            "Convert",
            "FromBase64String",
            &[0, 1, 0x1d, 5, 0x0e],
        );
        let index = self.strings.len() as u32;
        self.strings
            .extend([9, b'Q', 0, b'U', 0, b'J', 0, b'D', 0, 0]);
        self.token(0x72, 0x70000000 | index);
        self.token(0x28, 0x0a000000 | row);
    }
    fn borrowed(&mut self, writable: Option<i32>) {
        self.seed();
        self.code.extend([0x25, 0x0b]);
        if let Some(flag) = writable {
            self.i32(flag);
            self.construct(&[0x20, 2, 1, 0x1d, 5, 2]);
        } else {
            self.construct(&[0x20, 1, 1, 0x1d, 5]);
        }
    }
    fn emit_to_array(&mut self) {
        self.call("MemoryStream", "ToArray", &[0x20, 0, 0x1d, 5]);
    }
    fn read_byte(&mut self) {
        self.call("Stream", "ReadByte", &[0x20, 0, 8]);
    }
    fn write_byte(&mut self, n: i32) {
        self.i32(n);
        self.call("Stream", "WriteByte", &[0x20, 1, 1, 5]);
    }
    fn position(&mut self, n: i64) {
        self.i64(n);
        self.call("Stream", "set_Position", &[0x20, 1, 1, 0x0a]);
    }
    fn set_length(&mut self, n: i64) {
        self.i64(n);
        self.call("Stream", "SetLength", &[0x20, 1, 1, 0x0a]);
    }
    fn finish(mut self, arch: Architecture, second: Option<ProgramMethod<'_>>) -> Vec<u8> {
        let mut methods = vec![ProgramMethod {
            name: "Main",
            code: std::mem::take(&mut self.code),
            signature: vec![0, 0, 8],
            locals: self.locals,
            initialize_locals: false,
        }];
        if let Some(second) = second {
            methods.push(second)
        }
        program_with_references(arch, &methods, self.strings, &self.refs)
    }
}
pub(super) fn probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    let mut b = Build::new();
    let mut second = None;
    match fixture {
        CilFixture::StreamOwned => {
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x25);
            b.write_byte(82);
            b.emit_to_array();
            b.code.extend([0x16, 0x91, 0x2a]);
        }
        CilFixture::StreamFile => {
            let index = b.strings.len() as u32;
            let path: Vec<_> = "C:\\stream.bin".encode_utf16().collect();
            b.strings.push((path.len() * 2 + 1) as u8);
            for unit in path {
                b.strings.extend(unit.to_le_bytes());
            }
            b.strings.push(0);
            b.token(0x72, 0x70000000 | index);
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x25);
            b.write_byte(82);
            b.emit_to_array();
            let row = b.member(
                "System.IO",
                "File",
                "WriteAllBytes",
                &[0, 2, 1, 0x0e, 0x1d, 5],
            );
            b.token(0x28, 0x0a000000 | row);
            b.i32(17);
            b.code.push(0x2a);
        }
        CilFixture::StreamToArrayLimit => {
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x25);
            b.set_length(1048577);
            b.emit_to_array();
            b.code.extend([0x8e, 0x69, 0x2a]);
        }
        CilFixture::StreamBorrowedWrite => {
            b.borrowed(None);
            b.write_byte(81);
            b.code.extend([0x07, 0x16, 0x91, 0x2a]);
        }
        CilFixture::StreamBorrowedRead => {
            b.borrowed(Some(0));
            b.code.push(0x0a);
            b.code.extend([0x07, 0x16]);
            b.i32(81);
            b.code.extend([0x9c, 0x06]);
            b.read_byte();
            b.code.push(0x2a);
        }
        CilFixture::StreamReadOnly => {
            b.borrowed(Some(0));
            b.write_byte(81);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamCanWrite => {
            b.borrowed(Some(0));
            b.call("Stream", "get_CanWrite", &[0x20, 0, 2]);
            b.code.push(0x2a);
        }
        CilFixture::StreamFixed => {
            b.borrowed(None);
            b.code.push(0x25);
            b.position(3);
            b.write_byte(81);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamToArrayCopy => {
            b.borrowed(None);
            b.code.push(0x25);
            b.emit_to_array();
            b.code.extend([0x16]);
            b.i32(81);
            b.code.push(0x9c);
            b.read_byte();
            b.code.push(0x2a);
        }
        CilFixture::StreamClose | CilFixture::StreamClosedRead | CilFixture::StreamClosedCan => {
            b.borrowed(None);
            b.code.push(0x25);
            b.call("IDisposable", "Dispose", &[0x20, 0, 1]);
            if matches!(fixture, CilFixture::StreamClose) {
                b.emit_to_array();
                b.code.extend([0x8e, 0x69]);
            } else if matches!(fixture, CilFixture::StreamClosedRead) {
                b.read_byte();
            } else {
                b.call("Stream", "get_CanRead", &[0x20, 0, 2]);
            }
            b.code.push(0x2a);
        }
        CilFixture::StreamSparse => {
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x25);
            b.position(5);
            b.code.push(0x25);
            b.write_byte(82);
            b.emit_to_array();
            b.code.extend([0x8e, 0x69, 0x2a]);
        }
        CilFixture::StreamEmptyWrite => {
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x0a);
            b.code.push(0x06);
            b.position(5);
            b.code.push(0x06);
            b.i32(0);
            b.token(0x8d, 0x01000003);
            b.code.extend([0x16, 0x16]);
            b.call("Stream", "Write", &[0x20, 3, 1, 0x1d, 5, 8, 8]);
            b.code.push(0x06);
            b.call("Stream", "get_Length", &[0x20, 0, 0x0a]);
            b.code.extend([0x69, 0x2a]);
        }
        CilFixture::StreamShrink => {
            b.borrowed(None);
            b.code.push(0x25);
            b.set_length(1);
            b.code.push(0x25);
            b.set_length(3);
            b.emit_to_array();
            b.code.extend([0x18, 0x91, 0x2a]);
        }
        CilFixture::StreamSeek => {
            b.borrowed(None);
            b.code.push(0x25);
            b.i64(-1);
            b.i32(2);
            b.call("Stream", "Seek", &[0x20, 2, 0x0a, 0x0a, 0x11, 21]);
            b.code.push(0x26);
            b.read_byte();
            b.code.push(0x2a);
        }
        CilFixture::StreamRead => {
            b.borrowed(None);
            b.i32(3);
            b.token(0x8d, 0x01000003);
            b.code.push(0x0b);
            b.code.push(0x07);
            b.i32(1);
            b.i32(2);
            b.call("Stream", "Read", &[0x20, 3, 8, 0x1d, 5, 8, 8]);
            b.code.extend([0x26, 0x07, 0x18, 0x91, 0x2a]);
        }
        CilFixture::StreamCopy => {
            b.borrowed(None);
            b.code.push(0x0a);
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x0c);
            b.code.extend([0x06, 0x08]);
            b.call("Stream", "CopyTo", &[0x20, 1, 1, 0x12, 9]);
            b.code.push(0x08);
            b.emit_to_array();
            b.code.extend([0x18, 0x91, 0x2a]);
        }
        CilFixture::StreamSelfCopy => {
            b.borrowed(None);
            b.code.push(0x25);
            b.call("Stream", "CopyTo", &[0x20, 1, 1, 0x12, 9]);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamIdentity => {
            b.construct(&[0x20, 0, 1]);
            b.construct(&[0x20, 0, 1]);
            b.code.extend([0xfe, 1, 0x2a]);
        }
        CilFixture::StreamAlias => {
            b.construct(&[0x20, 0, 1]);
            b.code.extend([0x25, 0xfe, 1, 0x2a]);
        }
        CilFixture::StreamObjectLocal
        | CilFixture::StreamBaseLocal
        | CilFixture::StreamObjectClassLocal => {
            b.locals = vec![7, 1];
            b.locals
                .extend(if matches!(fixture, CilFixture::StreamObjectLocal) {
                    vec![0x1c]
                } else if matches!(fixture, CilFixture::StreamBaseLocal) {
                    vec![0x12, 9]
                } else {
                    vec![0x12, 17]
                });
            b.construct(&[0x20, 0, 1]);
            b.code.extend([0x0a, 0x06, 0x25]);
            b.write_byte(82);
            b.emit_to_array();
            b.code.extend([0x16, 0x91, 0x2a]);
        }
        CilFixture::StreamObjectArray => {
            b.locals = vec![7, 1, 0x1d, 0x1c];
            b.i32(1);
            b.token(0x8d, 0x01000004);
            b.code.extend([0x25, 0x0a, 0x16]);
            b.construct(&[0x20, 0, 1]);
            b.code.extend([0xa2, 0x06, 0x16, 0x9a, 0x25]);
            b.write_byte(82);
            b.emit_to_array();
            b.code.extend([0x16, 0x91, 0x2a]);
        }
        CilFixture::StreamObjectArrayKinds => {
            b.locals = vec![7, 1, 0x1d, 0x1c];
            b.i32(3);
            b.token(0x8d, 0x01000004);
            b.code.push(0x0a);
            let index = b.strings.len() as u32;
            b.strings.extend([9, b'Q', 0, b'U', 0, b'J', 0, b'D', 0, 0]);
            b.code.extend([0x06, 0x16]);
            b.token(0x72, 0x70000000 | index);
            b.code.push(0xa2);
            b.code.extend([0x06, 0x17]);
            b.seed();
            b.code.push(0xa2);
            b.code.extend([0x06, 0x18]);
            b.construct(&[0x20, 0, 1]);
            b.code.push(0xa2);
            b.code.extend([0x06, 0x18, 0x9a]);
            b.write_byte(82);
            b.code.extend([0x06, 0x17, 0x9a, 0x16, 0x91, 0x2a]);
        }
        CilFixture::StreamObjectBadValue => {
            b.i32(1);
            b.token(0x8d, 0x01000004);
            b.code.extend([0x16, 0x17, 0xa2, 0x16, 0x2a]);
        }
        CilFixture::StreamStaticCall => {
            b.construct(&[0x20, 0, 1]);
            b.token(0x28, 0x06000002);
            b.code.push(0x25);
            b.write_byte(82);
            b.emit_to_array();
            b.code.extend([0x16, 0x91, 0x2a]);
            second = Some(ProgramMethod {
                name: "Identity",
                code: vec![0x02, 0x2a],
                signature: vec![0, 1, 0x12, 9, 0x12, 5],
                locals: vec![],
                initialize_locals: false,
            });
        }
        CilFixture::StreamQuota => {
            b.construct(&[0x20, 0, 1]);
            b.code.extend([0x26, 0x2b, 0xf8]);
        }
        CilFixture::StreamOwnedQuota => {
            for _ in 0..3 {
                b.i32(32 * 1024 * 1024);
                b.construct(&[0x20, 1, 1, 8]);
                b.code.push(0x26);
            }
        }
        CilFixture::StreamNullBuffer => {
            b.code.push(0x14);
            b.construct(&[0x20, 1, 1, 0x1d, 5]);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamBadFlag => {
            b.borrowed(Some(2));
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamBadCapacity => {
            b.i32(-1);
            b.construct(&[0x20, 1, 1, 8]);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamBadSignature => {
            b.i64(0);
            b.construct(&[0x20, 1, 1, 0x0a]);
            b.i32(0);
            b.code.push(0x2a);
        }
        CilFixture::StreamBadAssembly
        | CilFixture::StreamBadVersion
        | CilFixture::StreamBadNamespace
        | CilFixture::StreamBadOwner
        | CilFixture::StreamBadScope => {
            // These constructor controls do not use locals. Keeping unrelated
            // Class locals would reject a malformed TypeRef at entry preflight,
            // before the intended MemberRef/newobj boundary is reached.
            b.locals.clear();
            match fixture {
                CilFixture::StreamBadAssembly => b.refs[0].assembly = "Guest.App",
                CilFixture::StreamBadVersion => b.refs[0].version = [2, 0, 0, 0],
                CilFixture::StreamBadNamespace => b.refs[0].namespace = "Guest",
                CilFixture::StreamBadOwner => b.refs[0].parent_tag = 0,
                CilFixture::StreamBadScope => b.refs[0].scope_tag = 0,
                _ => {}
            }
            b.token(0x73, 0x0a000001);
            b.code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::StreamConstructorCall => {
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x25);
            b.token(0x28, 0x0a000001);
            b.code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::StreamConstructorStack => {
            for _ in 0..8 {
                b.code.push(0x16);
            }
            b.construct(&[0x20, 0, 1]);
            b.code.push(0x2a);
        }
        CilFixture::StreamNullReceiver => {
            b.code.push(0x14);
            b.read_byte();
            b.code.push(0x2a);
        }
        CilFixture::StreamExposure => {
            b.construct(&[0x20, 0, 1]);
            b.call("MemoryStream", "GetBuffer", &[0x20, 0, 0x1d, 5]);
            b.code.extend([0x8e, 0x69, 0x2a]);
        }
        CilFixture::StreamUnknownClass => {
            b.refs[3].type_name = "Random";
            b.construct(&[0x20, 0, 1]);
            b.token(0x28, 0x06000002);
            b.code.push(0x2a);
            second = Some(ProgramMethod {
                name: "Reject",
                code: vec![0x16, 0x2a],
                signature: vec![0, 1, 8, 0x12, 17],
                locals: vec![],
                initialize_locals: false,
            });
        }
        _ => return None,
    }
    Some(b.finish(architecture, second))
}
