//! Pure bounded System.Convert byte-array/string operations. No host CLR.
//! ASCII whitespace and padding follow the existing legacy validated decoder.
//! Nonzero unused bits are accepted, e.g. AB== decodes to a zero byte.
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_INPUT_UNITS: usize = 2 * MAX_BYTES;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    #[error(
        "System.FormatException: invalid Base64 string; managed exception dispatch is not yet modeled"
    )]
    Format,
    #[error("Managed Base64 input exceeds limit")]
    InputLimit,
    #[error("Managed Base64 output exceeds limit")]
    OutputLimit,
}
type Result<T> = std::result::Result<T, ConvertError>;
fn whitespace(unit: u16) -> bool {
    matches!(unit, 9 | 10 | 13 | 32)
}
fn digit(unit: u16) -> Result<u8> {
    Ok(match unit {
        65..=90 => (unit - 65) as u8,
        97..=122 => (unit - 97 + 26) as u8,
        48..=57 => (unit - 48 + 52) as u8,
        43 => 62,
        47 => 63,
        _ => return Err(ConvertError::Format),
    })
}
fn quartet(units: [u16; 4]) -> Result<usize> {
    digit(units[0])?;
    digit(units[1])?;
    if units[2] == 61 {
        if units[3] != 61 {
            return Err(ConvertError::Format);
        }
        Ok(1)
    } else {
        digit(units[2])?;
        if units[3] == 61 {
            Ok(2)
        } else {
            digit(units[3])?;
            Ok(3)
        }
    }
}
/// Validate without allocating or coercing UTF16; caller preflights its own heap.
pub fn decoded_length(input: &[u16], output_limit: usize) -> Result<usize> {
    if input.len() > MAX_INPUT_UNITS {
        return Err(ConvertError::InputLimit);
    }
    let limit = output_limit.min(MAX_BYTES);
    let mut buffer = [0; 4];
    let mut at = 0;
    let mut length = 0usize;
    let mut ended = false;
    let mut meaningful = 0usize;
    for &unit in input {
        if whitespace(unit) {
            continue;
        }
        if ended {
            return Err(ConvertError::Format);
        }
        meaningful += 1;
        if meaningful > 4 * MAX_BYTES.div_ceil(3) {
            return Err(ConvertError::InputLimit);
        }
        buffer[at] = unit;
        at += 1;
        if at == 4 {
            let count = quartet(buffer)?;
            length = length.checked_add(count).ok_or(ConvertError::OutputLimit)?;
            if length > limit {
                return Err(ConvertError::OutputLimit);
            }
            ended = count != 3;
            at = 0;
        }
    }
    if at != 0 {
        return Err(ConvertError::Format);
    }
    Ok(length)
}
pub fn decode(input: &[u16], output_limit: usize) -> Result<Vec<u8>> {
    let length = decoded_length(input, output_limit)?;
    let mut output = Vec::with_capacity(length);
    let mut buffer = [0; 4];
    let mut at = 0;
    for &unit in input {
        if whitespace(unit) {
            continue;
        }
        buffer[at] = unit;
        at += 1;
        if at == 4 {
            let count = quartet(buffer)?;
            let a = digit(buffer[0])?;
            let b = digit(buffer[1])?;
            output.push((a << 2) | (b >> 4));
            if count > 1 {
                let c = digit(buffer[2])?;
                output.push((b << 4) | (c >> 2));
                if count > 2 {
                    output.push((c << 6) | digit(buffer[3])?);
                }
            }
            at = 0;
        }
    }
    debug_assert_eq!(length, output.len());
    Ok(output)
}
/// The legacy encoder restricts input before allocation to keep output <=32MiB.
pub fn encoded_length(input_length: usize, output_limit: usize) -> Result<usize> {
    if input_length > 3 * (MAX_BYTES / 4) {
        return Err(ConvertError::OutputLimit);
    }
    let length = input_length
        .div_ceil(3)
        .checked_mul(4)
        .ok_or(ConvertError::OutputLimit)?;
    if length > output_limit.min(MAX_BYTES) {
        return Err(ConvertError::OutputLimit);
    }
    Ok(length)
}
pub fn encode(input: &[u8], output_limit: usize) -> Result<Vec<u16>> {
    let length = encoded_length(input.len(), output_limit)?;
    let mut output = Vec::with_capacity(length);
    for bytes in input.chunks(3) {
        let a = bytes[0];
        let b = bytes.get(1).copied().unwrap_or(0);
        let c = bytes.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(a >> 2) as usize] as u16);
        output.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as u16);
        output.push(if bytes.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as u16
        } else {
            61
        });
        output.push(if bytes.len() > 2 {
            ALPHABET[(c & 63) as usize] as u16
        } else {
            61
        });
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn u(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
    #[test]
    fn binary_and_all_byte_values_round_trip_with_exact_padding() {
        for bytes in [vec![], vec![0], vec![0, 255], (0..=255).collect()] {
            let encoded = encode(&bytes, MAX_BYTES).unwrap();
            assert_eq!(decode(&encoded, MAX_BYTES).unwrap(), bytes);
        }
        assert_eq!(encode(&[0, 255, 128, 77, 90], 8).unwrap(), u("AP+ATVo="));
        assert_eq!(
            decode(&u(" A\tP+\rATV\no= "), 5).unwrap(),
            [0, 255, 128, 77, 90]
        );
        assert_eq!(decode(&u("AB=="), 1).unwrap(), [0]);
        assert_eq!(decode(&u("ABC="), 2).unwrap(), [0, 16]);
    }
    #[test]
    fn padding_non_ascii_surrogates_and_non_contract_whitespace_are_denied() {
        for value in [
            "=AAA",
            "AAAA=",
            "AAAA====",
            "AA===",
            "A===",
            "AA=",
            "AAA",
            "AA==A",
            "AA==AA==",
            "\u{a0}AA==",
            "\u{b}AA==",
            "Ä‚Â©A==",
            "A-==",
        ] {
            assert_eq!(
                decode(&u(value), 100),
                Err(ConvertError::Format),
                "{value:?}"
            );
        }
        for unit in [0, 0xd800, 0xdc00, 0xffff] {
            assert_eq!(decode(&[unit, 65, 61, 61], 100), Err(ConvertError::Format));
        }
    }
    #[test]
    fn checked_output_preflights_allow_exact_boundary_and_reject_before_allocation() {
        assert_eq!(decoded_length(&u("AAAA"), 3), Ok(3));
        assert_eq!(
            decoded_length(&u("AAAA"), 2),
            Err(ConvertError::OutputLimit)
        );
        assert_eq!(encoded_length(3, 4), Ok(4));
        assert_eq!(encoded_length(3, 3), Err(ConvertError::OutputLimit));
        assert_eq!(encoded_length(0, 0), Ok(0));
        assert_eq!(
            encoded_length(3 * (MAX_BYTES / 4), MAX_BYTES),
            Ok(MAX_BYTES)
        );
        assert_eq!(
            encoded_length(3 * (MAX_BYTES / 4) + 1, usize::MAX),
            Err(ConvertError::OutputLimit)
        );
        assert_eq!(
            encoded_length(usize::MAX, usize::MAX),
            Err(ConvertError::OutputLimit)
        );
    }
}
