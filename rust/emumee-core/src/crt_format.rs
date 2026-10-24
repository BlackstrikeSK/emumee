//! Deterministic legacy CRT formatting, without host libc/printf or host pointers.
//! This deliberately models the Python bridge's bounded grammar, not the complete
//! Microsoft CRT. Invalid/unmodeled input is explicit; bounded buffer truncation
//! is an ordinary result and is planned separately from all guest writes.
use thiserror::Error;
pub const MAX_FORMAT: usize = 8192;
pub const MAX_OUTPUT: usize = 65536;
pub const MAX_ARGUMENTS: usize = 64;
#[derive(Debug, Error)]
#[error("CRT formatting profile unsupported: {0}")]
pub struct FormatError(pub &'static str);
pub type Result<T> = std::result::Result<T, FormatError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    WideBuffer,
    WideConsole,
    NarrowConsole,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Fixed(u32),
    Argument,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Length {
    None,
    H,
    Hh,
    L,
    Ll,
    I64,
    I32,
    Z,
    T,
    W,
}
#[derive(Clone, Debug)]
struct Spec {
    flags: String,
    width: Field,
    precision: Option<Field>,
    length: Length,
    kind: char,
}
#[derive(Clone, Debug)]
enum Part {
    Literal(String),
    Conversion(Spec),
}
#[derive(Clone, Debug)]
pub struct Format {
    profile: Profile,
    parts: Vec<Part>,
}
/// Adapter supplies process-owned guest memory and Windows integer/pointer ABI
/// slots. No Rust pointer obtained from a guest value is ever dereferenced.
pub trait Reader {
    fn next(&mut self) -> Result<u64>;
    fn string(&self, address: u64, wide: bool) -> Result<String>;
}
fn field(chars: &[char], cursor: &mut usize) -> Result<Field> {
    if chars.get(*cursor) == Some(&'*') {
        *cursor += 1;
        return Ok(Field::Argument);
    }
    let start = *cursor;
    let mut value = 0u32;
    while chars.get(*cursor).is_some_and(char::is_ascii_digit) {
        if *cursor - start == 5 {
            return Err(FormatError("format field has more than five digits"));
        }
        value = value * 10 + chars[*cursor] as u32 - '0' as u32;
        *cursor += 1;
    }
    Ok(Field::Fixed(value))
}
impl Format {
    pub fn parse(text: &str, profile: Profile) -> Result<Self> {
        let chars: Vec<_> = text.chars().collect();
        if chars.len() >= MAX_FORMAT {
            return Err(FormatError("format exceeds string limit"));
        }
        let mut parts = Vec::new();
        let mut cursor = 0;
        while cursor < chars.len() {
            if chars[cursor] != '%' {
                let start = cursor;
                while cursor < chars.len() && chars[cursor] != '%' {
                    cursor += 1;
                }
                parts.push(Part::Literal(chars[start..cursor].iter().collect()));
                continue;
            }
            cursor += 1;
            let start = cursor;
            while chars.get(cursor).is_some_and(|c| "-+ #0".contains(*c)) {
                cursor += 1;
            }
            let flags: String = chars[start..cursor].iter().collect();
            let width_start = cursor;
            let width = field(&chars, &mut cursor)?;
            let has_width = cursor != width_start;
            let precision = if chars.get(cursor) == Some(&'.') {
                cursor += 1;
                let start = cursor;
                let value = field(&chars, &mut cursor)?;
                if start == cursor {
                    return Err(FormatError(
                        "empty precision is not modeled by the legacy profile",
                    ));
                }
                Some(value)
            } else {
                None
            };
            let mut length = Length::None;
            for (name, value) in [
                ("hh", Length::Hh),
                ("h", Length::H),
                ("ll", Length::Ll),
                ("l", Length::L),
                ("I64", Length::I64),
                ("I32", Length::I32),
                ("z", Length::Z),
                ("t", Length::T),
                ("w", Length::W),
            ] {
                let word: Vec<_> = name.chars().collect();
                if chars.get(cursor..cursor + word.len()) == Some(word.as_slice()) {
                    cursor += word.len();
                    length = value;
                    break;
                }
            }
            let kind = *chars
                .get(cursor)
                .ok_or(FormatError("incomplete format conversion"))?;
            cursor += 1;
            if !"diuoxXpcCsS%".contains(kind) {
                return Err(FormatError("format conversion is not modeled"));
            }
            if profile == Profile::WideConsole
                && (!flags.is_empty()
                    || has_width
                    || precision.is_some()
                    || !matches!(length, Length::None | Length::L)
                    || (length == Length::L && kind != 's')
                    || !"%sS".contains(kind))
            {
                return Err(FormatError("wide console format options are not modeled"));
            }
            parts.push(Part::Conversion(Spec {
                flags,
                width,
                precision,
                length,
                kind,
            }));
        }
        Ok(Self { profile, parts })
    }
    /// Slot count includes '*' fields and split x86 64-bit integers. The old
    /// narrow UCRT bridge failed to consume that high word; this is an explicit
    /// ABI correction shared by both integer formatting profiles.
    pub fn argument_slots(&self, width: usize) -> Result<usize> {
        if !matches!(width, 4 | 8) {
            return Err(FormatError("unsupported guest pointer width"));
        }
        let mut count = 0;
        for part in &self.parts {
            if let Part::Conversion(spec) = part {
                if spec.kind == '%' {
                    continue;
                }
                count += 1
                    + usize::from(spec.width == Field::Argument)
                    + usize::from(spec.precision == Some(Field::Argument));
                if width == 4
                    && matches!(spec.length, Length::Ll | Length::I64)
                    && "diuoxXp".contains(spec.kind)
                {
                    count += 1;
                }
            }
        }
        if count > MAX_ARGUMENTS {
            return Err(FormatError("format argument limit exceeded"));
        }
        Ok(count)
    }
    pub fn render(&self, reader: &mut impl Reader, pointer_width: usize) -> Result<String> {
        self.argument_slots(pointer_width)?;
        let mut output = String::new();
        let mut output_chars = 0;
        for part in &self.parts {
            let rendered = match part {
                Part::Literal(text) => text.clone(),
                Part::Conversion(spec) if spec.kind == '%' => "%".into(),
                Part::Conversion(spec) => {
                    let mut left = spec.flags.contains('-');
                    let width = match spec.width {
                        Field::Fixed(n) => n as i64,
                        Field::Argument => reader.next()? as u32 as i32 as i64,
                    };
                    let width = if width < 0 {
                        left = true;
                        (-width) as usize
                    } else {
                        width as usize
                    };
                    let precision = match spec.precision {
                        None => None,
                        Some(Field::Fixed(n)) => Some(n as usize),
                        Some(Field::Argument) => {
                            let n = reader.next()? as u32 as i32;
                            (n >= 0).then_some(n as usize)
                        }
                    };
                    if width > MAX_FORMAT || precision.is_some_and(|n| n > MAX_FORMAT) {
                        return Err(FormatError("format field exceeds limit"));
                    }
                    let value = reader.next()?;
                    let mut rendered = if "sS".contains(spec.kind) {
                        let wide = if self.profile == Profile::NarrowConsole {
                            spec.kind == 'S' || matches!(spec.length, Length::L | Length::W)
                        } else {
                            (spec.kind == 's' && !matches!(spec.length, Length::H | Length::Hh))
                                || (spec.kind == 'S'
                                    && matches!(spec.length, Length::L | Length::W))
                        };
                        let text = reader.string(value, wide)?;
                        if let Some(n) = precision {
                            text.chars().take(n).collect()
                        } else {
                            text
                        }
                    } else if "cC".contains(spec.kind) {
                        let wide = if self.profile == Profile::NarrowConsole {
                            spec.kind == 'C'
                        } else {
                            spec.kind == 'c'
                        };
                        let unit = (value & if wide { 0xffff } else { 0xff }) as u32;
                        char::from_u32(unit)
                            .ok_or(FormatError("isolated UTF16 surrogate character"))?
                            .to_string()
                    } else {
                        let bits = if matches!(spec.length, Length::Ll | Length::I64)
                            || spec.kind == 'p'
                        {
                            64
                        } else {
                            32
                        };
                        let mut number = value;
                        if pointer_width == 4 && matches!(spec.length, Length::Ll | Length::I64) {
                            number = (value & 0xffffffff) | ((reader.next()? & 0xffffffff) << 32);
                        }
                        if bits == 32 {
                            number &= 0xffffffff;
                        }
                        let negative =
                            "di".contains(spec.kind) && number & (1u64 << (bits - 1)) != 0;
                        let magnitude = if negative {
                            if bits == 64 {
                                number.wrapping_neg()
                            } else {
                                (number as u32).wrapping_neg() as u64
                            }
                        } else {
                            number
                        };
                        let mut text = match spec.kind {
                            'd' | 'i' | 'u' => magnitude.to_string(),
                            'x' | 'p' => format!("{number:x}"),
                            'X' => format!("{number:X}"),
                            _ => format!("{number:o}"),
                        };
                        if negative {
                            text.insert(0, '-');
                        }
                        if spec.kind == 'p' {
                            text = pad_left(&text, pointer_width * 2, '0');
                        } else if spec.flags.contains('#') && number != 0 {
                            if spec.kind == 'x' {
                                text = format!("0x{text}");
                            } else if spec.kind == 'X' {
                                text = format!("0X{text}");
                            } else if spec.kind == 'o' && self.profile != Profile::NarrowConsole {
                                text.insert(0, '0');
                            }
                        }
                        if let Some(n) = precision {
                            if spec.kind != 'p' {
                                if negative {
                                    text = format!("-{}", pad_left(&text[1..], n, '0'));
                                } else {
                                    text = pad_left(&text, n, '0');
                                }
                            }
                        }
                        if !negative && "di".contains(spec.kind) && spec.flags.contains('+') {
                            text.insert(0, '+');
                        }
                        text
                    };
                    if width > 0 {
                        if left {
                            let count = rendered.chars().count();
                            rendered.extend(std::iter::repeat_n(' ', width.saturating_sub(count)));
                        } else {
                            let pad = if spec.flags.contains('0') && !"sScC".contains(spec.kind) {
                                '0'
                            } else {
                                ' '
                            };
                            rendered = pad_left(&rendered, width, pad);
                        }
                    }
                    rendered
                }
            };
            output_chars += rendered.chars().count();
            if output_chars > MAX_OUTPUT {
                return Err(FormatError("formatted output exceeds limit"));
            }
            output.push_str(&rendered);
        }
        if self.profile == Profile::NarrowConsole && !output.is_ascii() {
            return Err(FormatError("narrow console formatting requires ASCII"));
        }
        Ok(output)
    }
}
fn pad_left(text: &str, width: usize, pad: char) -> String {
    let mut output: String =
        std::iter::repeat_n(pad, width.saturating_sub(text.chars().count())).collect();
    output.push_str(text);
    output
}
#[derive(Clone, Debug)]
pub struct BufferPlan {
    pub bytes: Vec<u8>,
    pub result: i32,
}
#[derive(Clone, Copy, Debug)]
pub enum BufferMode {
    Legacy,
    Secure,
    Truncate,
}
/// Input must already be rendered/preflighted. Exact legacy equality writes no
/// NUL and succeeds; larger output writes only count units and returns-1. Secure
/// range failure clears the first unit; truncate failure clears the last unit.
pub fn wide_buffer(text: &str, count: usize, mode: BufferMode) -> Result<BufferPlan> {
    if count == 0 || count > MAX_OUTPUT {
        return Err(FormatError("invalid wide output capacity"));
    }
    if text.chars().count() > MAX_OUTPUT {
        return Err(FormatError("formatted output exceeds limit"));
    }
    let units: Vec<_> = text.encode_utf16().collect();
    let length = units.len();
    let mut output: Vec<_> = units.into_iter().take(count).collect();
    if length < count {
        output.push(0);
    }
    let mut result = if length <= count { length as i32 } else { -1 };
    if !matches!(mode, BufferMode::Legacy) && length >= count {
        result = -1;
        if matches!(mode, BufferMode::Truncate) {
            output[count - 1] = 0;
        } else {
            output[0] = 0;
        }
    }
    Ok(BufferPlan {
        bytes: output.into_iter().flat_map(u16::to_le_bytes).collect(),
        result,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Source {
        values: Vec<u64>,
        at: usize,
    }
    impl Reader for Source {
        fn next(&mut self) -> Result<u64> {
            let value = self
                .values
                .get(self.at)
                .copied()
                .ok_or(FormatError("missing argument"))?;
            self.at += 1;
            Ok(value)
        }
        fn string(&self, address: u64, wide: bool) -> Result<String> {
            Ok(match address {
                0 => "(null)",
                1 if wide => "Ω😀",
                1 => "abc",
                _ => "test",
            }
            .into())
        }
    }
    fn render(fmt: &str, profile: Profile, width: usize, args: Vec<u64>) -> String {
        Format::parse(fmt, profile)
            .unwrap()
            .render(
                &mut Source {
                    values: args,
                    at: 0,
                },
                width,
            )
            .unwrap()
    }
    #[test]
    fn wide_console_grammar_strings_lengths_and_unsupported_fields() {
        assert_eq!(
            render("%s|%S|%ls%%", Profile::WideConsole, 8, vec![1, 1, 0]),
            "Ω😀|abc|(null)%"
        );
        for fmt in ["%d", "%10s", "%.*s", "%hs", "%n", "%f", "%"] {
            assert!(Format::parse(fmt, Profile::WideConsole).is_err(), "{fmt}");
        }
    }
    #[test]
    fn integer_width_precision_stars_and_legacy_padding_quirks() {
        assert_eq!(
            render(
                "%+06d|%#x|%#o|%p|%*.*s",
                Profile::WideBuffer,
                8,
                vec![(-3i64) as u64, 42, 9, 0x1234, (-5i32) as u32 as u64, 2, 1]
            ),
            "0000-3|0x2a|011|0000000000001234|Ω😀   "
        );
        assert_eq!(
            render(
                "%I64x:%d",
                Profile::WideBuffer,
                4,
                vec![0x89abcdef, 0x12345678, 7]
            ),
            "1234567889abcdef:7"
        );
        assert_eq!(
            render("%I64d", Profile::WideBuffer, 4, vec![0, 0x80000000]),
            "-9223372036854775808"
        );
        assert_eq!(
            render("%I64d", Profile::WideBuffer, 8, vec![i64::MIN as u64]),
            "-9223372036854775808"
        );
        assert_eq!(
            render(
                "%I64x:%d",
                Profile::NarrowConsole,
                4,
                vec![0x89abcdef, 0x12345678, 7]
            ),
            "1234567889abcdef:7"
        );
        assert_eq!(render("%#o", Profile::NarrowConsole, 8, vec![9]), "11");
        assert_eq!(
            render(
                "%+d|%u",
                Profile::WideBuffer,
                8,
                vec![i64::MIN as u64, u32::MAX as u64]
            ),
            "+0|4294967295"
        );
    }
    #[test]
    fn bounded_grammar_argument_and_unicode_failures_are_explicit() {
        let f = Format::parse(&"%s".repeat(65), Profile::WideBuffer).unwrap();
        assert!(f.argument_slots(8).is_err());
        assert!(Format::parse("%123456d", Profile::WideBuffer).is_err());
        // Narrow %c consumes the low byte; %C is the wide character form.
        assert_eq!(render("%c", Profile::NarrowConsole, 8, vec![0xd800]), "\0");
        for (fmt, args) in [("%8193d", vec![1]), ("%C", vec![0xd800]), ("%S", vec![1])] {
            let f = Format::parse(fmt, Profile::NarrowConsole).unwrap();
            assert!(
                f.render(
                    &mut Source {
                        values: args,
                        at: 0
                    },
                    8
                )
                .is_err()
            );
        }
    }
    #[test]
    fn wide_output_equality_truncation_secure_and_astral_unit_counts() {
        for (count, mode, expected, result) in [
            (5, BufferMode::Legacy, vec![65, 0, 66, 0, 0, 0], 2),
            (2, BufferMode::Legacy, vec![65, 0, 66, 0], 2),
            (1, BufferMode::Legacy, vec![65, 0], -1),
            (2, BufferMode::Secure, vec![0, 0, 66, 0], -1),
            (2, BufferMode::Truncate, vec![65, 0, 0, 0], -1),
        ] {
            let plan = wide_buffer("AB", count, mode).unwrap();
            assert_eq!(plan.bytes, expected);
            assert_eq!(plan.result, result);
        }
        assert_eq!(wide_buffer("😀", 2, BufferMode::Legacy).unwrap().result, 2);
        assert_eq!(
            wide_buffer("😀", 1, BufferMode::Legacy).unwrap().bytes,
            0xd83du16.to_le_bytes()
        );
    }
}
