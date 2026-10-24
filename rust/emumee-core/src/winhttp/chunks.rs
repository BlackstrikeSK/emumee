//! Incremental caller-supplied HTTP chunk framing. WinHTTP writes raw wire
//! bytes; malformed wire is retained as a model error until ReceiveResponse.
use crate::networkfixtures::MAX_BODY;
enum Mode {
    Size,
    Data(usize),
    DataEnd(u8),
    FinalEnd(u8),
    Done,
    Failed(&'static str),
}
pub(super) struct Decoder {
    mode: Mode,
    line: Vec<u8>,
    chunks: u32,
}
impl Default for Decoder {
    fn default() -> Self {
        Self {
            mode: Mode::Size,
            line: Vec::new(),
            chunks: 0,
        }
    }
}
impl Decoder {
    pub fn buffered(&self) -> usize {
        self.line.len()
    }
    pub fn complete(&self) -> bool {
        matches!(self.mode, Mode::Done)
    }
    pub fn failure(&self) -> Option<&'static str> {
        if let Mode::Failed(error) = self.mode {
            Some(error)
        } else {
            None
        }
    }
    pub fn feed(&mut self, input: &[u8], body: &mut Vec<u8>) {
        let mut at = 0;
        while at < input.len() {
            match self.mode {
                Mode::Size => {
                    self.line.push(input[at]);
                    at += 1;
                    if self.line.len() > 128 {
                        self.mode = Mode::Failed("chunk size-line bound exceeded");
                        continue;
                    }
                    if !self.line.ends_with(b"\r\n") {
                        continue;
                    }
                    let line = &self.line[..self.line.len() - 2];
                    if line.contains(&b';') {
                        self.mode = Mode::Failed("chunk extensions are not modeled");
                        continue;
                    }
                    if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit)
                    {
                        self.mode = Mode::Failed("malformed chunk size");
                        continue;
                    }
                    let size = std::str::from_utf8(line)
                        .ok()
                        .and_then(|text| usize::from_str_radix(text, 16).ok());
                    let Some(size) = size.filter(|size| *size <= MAX_BODY - body.len()) else {
                        self.mode = Mode::Failed("decoded chunk body bound exceeded");
                        continue;
                    };
                    self.line.clear();
                    if size == 0 {
                        self.mode = Mode::FinalEnd(0);
                    } else {
                        self.chunks += 1;
                        if self.chunks > 4096 {
                            self.mode = Mode::Failed("chunk count bound exceeded");
                        } else {
                            self.mode = Mode::Data(size);
                        }
                    }
                }
                Mode::Data(remaining) => {
                    let size = remaining.min(input.len() - at);
                    body.extend_from_slice(&input[at..at + size]);
                    at += size;
                    self.mode = if size == remaining {
                        Mode::DataEnd(0)
                    } else {
                        Mode::Data(remaining - size)
                    };
                }
                Mode::DataEnd(position) | Mode::FinalEnd(position) => {
                    let final_end = matches!(self.mode, Mode::FinalEnd(_));
                    let expected = if position == 0 { b'\r' } else { b'\n' };
                    if input[at] != expected {
                        self.mode = Mode::Failed(if final_end {
                            "chunk trailers are not modeled"
                        } else {
                            "malformed chunk data terminator"
                        });
                        continue;
                    }
                    at += 1;
                    self.mode = if position == 0 {
                        if final_end {
                            Mode::FinalEnd(1)
                        } else {
                            Mode::DataEnd(1)
                        }
                    } else if final_end {
                        Mode::Done
                    } else {
                        Mode::Size
                    };
                }
                Mode::Done => {
                    self.mode = Mode::Failed("bytes after terminating chunk are not modeled")
                }
                Mode::Failed(_) => break,
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_payload_is_not_parsed_as_framing() {
        let mut decoder = Decoder::default();
        let mut body = Vec::new();
        decoder.feed(b"4\r\n\0\xff\r\n\r\n0\r\n\r\n", &mut body);
        assert!(decoder.complete());
        assert_eq!(body, b"\0\xff\r\n");
    }
    #[test]
    fn every_wire_boundary_preserves_decoded_bytes_and_requires_final_crlf() {
        let wire = b"4\r\nRUST\r\n4\r\nBODY\r\n0\r\n\r\n";
        for split in 0..=wire.len() {
            let mut decoder = Decoder::default();
            let mut body = Vec::new();
            decoder.feed(&wire[..split], &mut body);
            if split < wire.len() {
                assert!(!decoder.complete());
            }
            decoder.feed(&wire[split..], &mut body);
            assert!(decoder.complete());
            assert_eq!(decoder.failure(), None);
            assert_eq!(body, b"RUSTBODY");
        }
        let mut decoder = Decoder::default();
        let mut body = Vec::new();
        for byte in wire {
            decoder.feed(&[*byte], &mut body);
        }
        assert!(decoder.complete());
        assert_eq!(body, b"RUSTBODY");
    }
    #[test]
    fn malformed_extensions_trailers_and_oversized_chunks_never_complete() {
        for wire in [
            &b"z\r\n"[..],
            &b"1;ext=x\r\na\r\n0\r\n\r\n"[..],
            &b"1\r\naXX"[..],
            &b"0\r\nX: y\r\n\r\n"[..],
            &b"0\r\n\r\nextra"[..],
            &b"1000001\r\n"[..],
        ] {
            let mut decoder = Decoder::default();
            let mut body = Vec::new();
            decoder.feed(wire, &mut body);
            assert!(!decoder.complete());
            assert!(decoder.failure().is_some());
        }
    }
}
