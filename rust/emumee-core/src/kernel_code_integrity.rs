//! Documented SystemCodeIntegrityInformation103 layout and length contract.
//! Options must be supplied by configuration; this module does not attest or
//! change code-integrity enforcement, signatures, boot trust, or hypervisors.
use serde::Serialize;
use thiserror::Error;
pub const CLASS: u32 = 103;
pub const SIZE: u32 = 8;
pub const LENGTH_MISMATCH: u32 = 0xc0000004;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub status: u32,
    pub required: u32,
    pub bytes: Option<[u8; 8]>,
}
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("Code integrity options are not explicitly configured")]
pub struct Unconfigured;
pub fn plan(
    capacity: u32,
    declared_length: u32,
    options: Option<u32>,
) -> Result<Plan, Unconfigured> {
    if capacity != SIZE || declared_length != SIZE {
        return Ok(Plan {
            status: LENGTH_MISMATCH,
            required: SIZE,
            bytes: None,
        });
    }
    let options = options.ok_or(Unconfigured)?;
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&SIZE.to_le_bytes());
    bytes[4..].copy_from_slice(&options.to_le_bytes());
    Ok(Plan {
        status: 0,
        required: SIZE,
        bytes: Some(bytes),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_integrity_exact_lengths_match_native_user_query_controls() {
        let native: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native_code_integrity.json"
        ))
        .unwrap();
        for row in native["cases"].as_array().unwrap() {
            let got = plan(
                row["buffer_length"].as_u64().unwrap() as u32,
                row["declared_length"].as_u64().unwrap() as u32,
                Some(native["observed_options"].as_u64().unwrap() as u32),
            )
            .unwrap();
            assert_eq!(u64::from(got.status), row["status"].as_u64().unwrap());
            assert_eq!(
                u64::from(got.required),
                row["return_length"].as_u64().unwrap()
            );
            assert_eq!(got.bytes.is_some(), got.status == 0);
        }
    }
    #[test]
    fn code_integrity_unknown_configuration_never_becomes_a_trust_assertion() {
        assert_eq!(plan(8, 8, None), Err(Unconfigured));
        assert_eq!(plan(0, 0, None).unwrap().status, LENGTH_MISMATCH);
        assert_eq!(plan(8, 0, None).unwrap().status, LENGTH_MISMATCH);
        for options in [0, 1, 0xe001, u32::MAX] {
            let bytes = plan(8, 8, Some(options)).unwrap().bytes.unwrap();
            assert_eq!(&bytes[..4], &8u32.to_le_bytes());
            assert_eq!(&bytes[4..], &options.to_le_bytes());
        }
    }
}
