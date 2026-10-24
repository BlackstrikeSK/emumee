//! Read-only recovery of complete records from a broker journal snapshot.
//! A journal records observations, including attempts; parsing never turns an
//! attempt into a successful network operation or resumes any connection.
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 40 * 1024;
pub const MAX_EVENTS: usize = 50_000;
const MAX_RECORD_NODES: usize = 8192;
const MAX_TOTAL_NODES: usize = 250_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStop {
    MissingCloseMarker,
    PartialRecord,
    RecordLimit,
    MalformedJson,
    MalformedEvent,
    NodeLimit,
    IntegerRange,
}
#[derive(Debug, Serialize)]
pub struct Recovery {
    pub events: Vec<Value>,
    pub closed: bool,
    pub stop_reason: Option<RecoveryStop>,
    pub source_sha256: String,
    pub valid_prefix_sha256: String,
    pub source_bytes: usize,
    pub valid_bytes: usize,
    pub unrecovered_bytes: usize,
    pub scope: &'static str,
}
#[derive(Debug, thiserror::Error)]
#[error("Network broker journal exceeds 64 MiB bound")]
pub struct JournalTooLarge;

// serde_json may otherwise coerce integers beyond i64/u64 into f64. Stop
// explicitly instead of silently changing an observation's exact integer.
fn exact_integers(line: &[u8]) -> bool {
    let mut at = 0;
    let mut quoted = false;
    while at < line.len() {
        let byte = line[at];
        if quoted {
            if byte == b'\\' {
                at += 2;
                continue;
            }
            if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = at;
            while at < line.len()
                && matches!(line[at], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                at += 1;
            }
            let raw = &line[start..at];
            if !raw.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                let raw = std::str::from_utf8(raw).expect("ASCII number token");
                if (raw.starts_with('-') && raw.parse::<i64>().is_err())
                    || (!raw.starts_with('-') && raw.parse::<u64>().is_err())
                {
                    return false;
                }
            }
            continue;
        }
        at += 1;
    }
    true
}

fn nodes(value: &Value) -> Option<usize> {
    let mut pending = vec![value];
    let mut count = 0;
    while let Some(value) = pending.pop() {
        count += 1;
        if count > MAX_RECORD_NODES {
            return None;
        }
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.values()),
            _ => (),
        }
    }
    Some(count)
}

pub fn recover(data: &[u8]) -> Result<Recovery, JournalTooLarge> {
    if data.len() > MAX_JOURNAL_BYTES {
        return Err(JournalTooLarge);
    }
    let mut events = Vec::new();
    let mut valid = 0;
    let mut total_nodes = 0;
    let mut reason = None;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let stop = if !line.ends_with(b"\n") {
            Some(RecoveryStop::PartialRecord)
        } else if line.len() > MAX_RECORD_BYTES || events.len() >= MAX_EVENTS {
            Some(RecoveryStop::RecordLimit)
        } else {
            None
        };
        if let Some(stop) = stop {
            reason = Some(stop);
            break;
        }
        let value: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) => {
                reason = Some(RecoveryStop::MalformedJson);
                break;
            }
        };
        if !exact_integers(line) {
            reason = Some(RecoveryStop::IntegerRange);
            break;
        }
        if !value.is_object()
            || value
                .get("event")
                .and_then(Value::as_str)
                .is_none_or(|name| name.chars().count() > 64)
        {
            reason = Some(RecoveryStop::MalformedEvent);
            break;
        }
        let Some(count) = nodes(&value) else {
            reason = Some(RecoveryStop::NodeLimit);
            break;
        };
        if total_nodes + count > MAX_TOTAL_NODES {
            reason = Some(RecoveryStop::NodeLimit);
            break;
        }
        total_nodes += count;
        valid += line.len();
        events.push(value);
    }
    let closed = reason.is_none()
        && events.last().is_some_and(|value| {
            value.as_object().is_some_and(|object| object.len() == 1)
                && value["event"] == "broker_closed"
        });
    if !closed && reason.is_none() {
        reason = Some(RecoveryStop::MissingCloseMarker);
    }
    Ok(Recovery {
        events,
        closed,
        stop_reason: reason,
        source_sha256: format!("{:x}", Sha256::digest(data)),
        valid_prefix_sha256: format!("{:x}", Sha256::digest(&data[..valid])),
        source_bytes: data.len(),
        valid_bytes: valid,
        unrecovered_bytes: data.len() - valid,
        scope: "Complete bounded records recovered from a journal snapshot. Attempts remain attempts; no network or broker process is started. Close marker alone does not prove guest initialization or unpacking.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ATTEMPT: &[u8] =
        b"{\"event\":\"http_request_attempt\",\"url\":\"https://example.invalid/\"}\n";
    const CLOSED: &[u8] = b"{\"event\":\"broker_closed\"}\n";
    #[test]
    fn close_marker_must_be_exact_final_complete_record() {
        let complete = [ATTEMPT, CLOSED].concat();
        let result = recover(&complete).unwrap();
        assert!(result.closed);
        assert_eq!(result.stop_reason, None);
        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0]["event"], "http_request_attempt");
        for data in [
            Vec::new(),
            ATTEMPT.to_vec(),
            [CLOSED, ATTEMPT].concat(),
            b"{\"event\":\"broker_closed\",\"extra\":true}\n".to_vec(),
        ] {
            let result = recover(&data).unwrap();
            assert!(!result.closed);
            assert_eq!(result.stop_reason, Some(RecoveryStop::MissingCloseMarker));
        }
        let result = recover(&[CLOSED, b"{"].concat()).unwrap();
        assert!(!result.closed);
        assert_eq!(result.stop_reason, Some(RecoveryStop::PartialRecord));
    }
    #[test]
    fn every_byte_prefix_preserves_only_complete_records_and_hashes() {
        let data = [ATTEMPT, "{\"event\":\"é\"}\r\n".as_bytes(), CLOSED].concat();
        for end in 0..=data.len() {
            let result = recover(&data[..end]).unwrap();
            let valid = data[..end]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |at| at + 1);
            assert_eq!(result.valid_bytes, valid);
            assert_eq!(result.unrecovered_bytes, end - valid);
            assert_eq!(
                result.source_sha256,
                format!("{:x}", Sha256::digest(&data[..end]))
            );
            assert_eq!(
                result.valid_prefix_sha256,
                format!("{:x}", Sha256::digest(&data[..valid]))
            );
            assert_eq!(result.closed, end == data.len());
        }
    }
    #[test]
    fn malformed_tail_never_discards_prior_events_or_invents_completion() {
        for (tail, reason) in [
            (&b"{\n"[..], RecoveryStop::MalformedJson),
            (&b"\xff\n"[..], RecoveryStop::MalformedJson),
            (&b"[]\n"[..], RecoveryStop::MalformedEvent),
            (&b"{\"event\":false}\n"[..], RecoveryStop::MalformedEvent),
            (&b"{\"event\":\"dns\"}"[..], RecoveryStop::PartialRecord),
        ] {
            let result = recover(&[ATTEMPT, tail, CLOSED].concat()).unwrap();
            assert_eq!(result.events.len(), 1);
            // A partial record followed by another line becomes malformed JSON.
            let expected = if reason == RecoveryStop::PartialRecord {
                RecoveryStop::MalformedJson
            } else {
                reason
            };
            assert_eq!(result.stop_reason, Some(expected));
            assert!(!result.closed);
            assert_eq!(result.valid_bytes, ATTEMPT.len());
        }
        for length in [64, 65] {
            let data = format!("{{\"event\":\"{}\"}}\n", "é".repeat(length));
            let result = recover(data.as_bytes()).unwrap();
            assert_eq!(result.events.len(), usize::from(length == 64));
        }
    }
    #[test]
    fn record_file_count_and_json_node_limits_are_bounded() {
        assert!(recover(&vec![0; MAX_JOURNAL_BYTES + 1]).is_err());
        let line = [vec![b' '; MAX_RECORD_BYTES], b"\n".to_vec()].concat();
        assert_eq!(
            recover(&line).unwrap().stop_reason,
            Some(RecoveryStop::RecordLimit)
        );
        let data = b"{\"event\":\"x\"}\n".repeat(MAX_EVENTS + 1);
        let result = recover(&data).unwrap();
        assert_eq!(result.events.len(), MAX_EVENTS);
        assert_eq!(result.stop_reason, Some(RecoveryStop::RecordLimit));
        let dense = format!(
            "{{\"event\":\"x\",\"data\":[{}0]}}\n",
            "0,".repeat(MAX_RECORD_NODES)
        );
        assert!(dense.len() < MAX_RECORD_BYTES);
        assert_eq!(
            recover(dense.as_bytes()).unwrap().stop_reason,
            Some(RecoveryStop::NodeLimit)
        );
        let line = format!("{{\"event\":\"x\",\"data\":[{}0]}}\n", "0,".repeat(999));
        let data = line.repeat(300);
        let result = recover(data.as_bytes()).unwrap();
        assert!(result.events.len() < 300);
        assert_eq!(result.stop_reason, Some(RecoveryStop::NodeLimit));
        let deep = format!(
            "{{\"event\":\"x\",\"data\":{}0{}}}\n",
            "[".repeat(140),
            "]".repeat(140)
        );
        assert_eq!(
            recover(deep.as_bytes()).unwrap().stop_reason,
            Some(RecoveryStop::MalformedJson)
        );
    }
    #[test]
    fn large_integers_are_never_silently_rounded_to_floating_point() {
        for number in [
            "18446744073709551615",
            "-9223372036854775808",
            "1.5",
            "1e20",
        ] {
            let line = format!("{{\"event\":\"x\",\"value\":{number}}}\n");
            assert_eq!(recover(line.as_bytes()).unwrap().events.len(), 1);
        }
        for number in ["18446744073709551616", "-9223372036854775809"] {
            let line = format!("{{\"event\":\"x\",\"value\":{number}}}\n");
            let result = recover(&[ATTEMPT, line.as_bytes(), CLOSED].concat()).unwrap();
            assert_eq!(result.stop_reason, Some(RecoveryStop::IntegerRange));
            assert_eq!(result.events.len(), 1);
        }
        let line = b"{\"event\":\"x\",\"value\":\"\\\"18446744073709551616\\\\\"}\n";
        assert_eq!(recover(line).unwrap().events.len(), 1);
    }
}
