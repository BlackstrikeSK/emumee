//! Fixed guest code pages. Tables and conversions never consult the host locale.
use crate::persona::Encoding;
#[derive(Clone, Copy, Debug)]
pub enum CodePage {
    Oem437,
    Oem850,
    Ansi1252,
    Utf8,
}
impl CodePage {
    pub fn resolve(page: u32, oem: u32) -> Option<Self> {
        Some(match page {
            0 | 1252 => Self::Ansi1252,
            1 => match oem {
                437 => Self::Oem437,
                850 => Self::Oem850,
                _ => return None,
            },
            437 => Self::Oem437,
            850 => Self::Oem850,
            65001 => Self::Utf8,
            _ => return None,
        })
    }
    pub fn utf8(self) -> bool {
        matches!(self, Self::Utf8)
    }
    pub fn encode(self, text: &str, replacement: u8) -> (Vec<u8>, bool) {
        if self.utf8() {
            return (text.as_bytes().to_vec(), false);
        }
        let mut used = false;
        let mut bytes = Vec::with_capacity(text.len());
        for ch in text.chars() {
            let encoded = match self {
                Self::Oem850 => {
                    if ch.is_ascii() {
                        Some(ch as u8)
                    } else {
                        CP850
                            .iter()
                            .position(|c| u32::from(*c) == ch as u32)
                            .map(|i| i as u8 + 128)
                    }
                }
                Self::Oem437 | Self::Ansi1252 => {
                    let codec = if matches!(self, Self::Oem437) {
                        Encoding::Cp437
                    } else {
                        Encoding::Cp1252
                    };
                    let b = codec.encode(&ch.to_string(), false);
                    if codec.decode(&b).ok().as_deref() == Some(ch.to_string().as_str())
                        && !(matches!(self, Self::Ansi1252)
                            && matches!(ch as u32, 0x81 | 0x8d | 0x8f | 0x90 | 0x9d))
                    {
                        Some(b[0])
                    } else {
                        None
                    }
                }
                Self::Utf8 => unreachable!(),
            };
            bytes.push(encoded.unwrap_or_else(|| {
                used = true;
                replacement
            }));
        }
        (bytes, used)
    }
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        match self {
            Self::Utf8 => String::from_utf8(bytes.to_vec()).ok(),
            Self::Oem850 => Some(
                bytes
                    .iter()
                    .map(|b| {
                        if *b < 128 {
                            char::from(*b)
                        } else {
                            char::from_u32(CP850[usize::from(*b - 128)].into()).unwrap()
                        }
                    })
                    .collect(),
            ),
            Self::Oem437 => Encoding::Cp437.decode(bytes).ok(),
            Self::Ansi1252 => {
                if bytes
                    .iter()
                    .any(|b| matches!(b, 0x81 | 0x8d | 0x8f | 0x90 | 0x9d))
                {
                    None
                } else {
                    Encoding::Cp1252.decode(bytes).ok()
                }
            }
        }
    }
}
include!("codepage850.rs");
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_single_byte_pages_roundtrip_and_substitute_without_best_fit() {
        for page in [CodePage::Oem437, CodePage::Oem850, CodePage::Ansi1252] {
            for byte in 0..=255u8 {
                if let Some(text) = page.decode(&[byte]) {
                    assert_eq!(page.encode(&text, b'?'), (vec![byte], false));
                }
            }
            assert_eq!(page.encode("A😀?", b'!'), (b"A!?".to_vec(), true));
        }
        assert_eq!(
            CodePage::Oem850.encode("øé", b'?'),
            (vec![0x9b, 0x82], false)
        );
        assert!(CodePage::Ansi1252.decode(&[0x81]).is_none());
        assert_eq!(
            CodePage::Utf8.encode("😀", b'?'),
            ("😀".as_bytes().to_vec(), false)
        );
    }
}
