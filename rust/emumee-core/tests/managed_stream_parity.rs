use emumee_core::managed_streams::{ByteArrays, Result, StreamError, Streams};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
struct Arrays(Vec<Vec<u8>>);
impl ByteArrays for Arrays {
    fn bytes(&self, id: u32) -> Result<&[u8]> {
        self.0
            .get(id.wrapping_sub(1) as usize)
            .map(Vec::as_slice)
            .ok_or(StreamError::Array)
    }
    fn bytes_mut(&mut self, id: u32) -> Result<&mut [u8]> {
        self.0
            .get_mut(id.wrapping_sub(1) as usize)
            .map(Vec::as_mut_slice)
            .ok_or(StreamError::Array)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn invoke(state: &mut Streams, arrays: &mut Arrays, command: &Value) -> Result<Value> {
    let a = command.as_array().unwrap();
    let op = a[0].as_str().unwrap();
    let n = |index: usize| a[index].as_i64().unwrap();
    let id = || n(1) as u32;
    Ok(match op {
        "owned" => json!({"stream":state.owned(if a.len()==1 {0}else{n(1) as i32})?}),
        "borrowed" => json!({"stream":state.borrowed(id(),n(2)!=0,arrays)?}),
        "array_set" => {
            arrays.bytes_mut(id())?[n(2) as usize] = n(3) as u8;
            Value::Null
        }
        "get_Length" => json!(state.length(id())?),
        "get_Position" => json!(state.position(id())?),
        "set_Position" => {
            state.set_position(id(), n(2))?;
            Value::Null
        }
        "Seek" => json!(state.seek(id(), n(2), n(3) as i32)?),
        "SetLength" => {
            state.set_length(id(), n(2), arrays)?;
            Value::Null
        }
        "ReadByte" => json!(state.read_byte(id(), arrays)?),
        "WriteByte" => {
            state.write_byte(id(), n(2) as i32, arrays)?;
            Value::Null
        }
        "Read" => json!(state.read(id(), n(2) as u32, n(3) as i32, n(4) as i32, arrays)?),
        "Write" => {
            state.write(id(), n(2) as u32, n(3) as i32, n(4) as i32, arrays)?;
            Value::Null
        }
        "CopyTo" => {
            state.copy_to(
                id(),
                n(2) as u32,
                if a.len() == 4 {
                    Some(n(3) as i32)
                } else {
                    None
                },
                arrays,
            )?;
            Value::Null
        }
        "ToArray" => json!({"bytes":hex(&state.to_array(id(),arrays)?)}),
        "get_CanRead" | "get_CanSeek" => json!(state.capability(id(), false)?),
        "get_CanWrite" => json!(state.capability(id(), true)?),
        "Close" | "Dispose" => {
            state.close(id())?;
            Value::Null
        }
        "Flush" => {
            state.flush(id())?;
            Value::Null
        }
        _ => panic!("Unknown synthetic operation {op}"),
    })
}
#[test]
fn legacy_owned_stream_corpus_preserves_bytes_positions_aliasing_and_failed_state() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/managed_stream_reference.json"),
    )
    .unwrap();
    assert_eq!(raw.len(), 17506);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "a48c4cb4e05907649363deb0673315d0ff158c289b77a5ac66be1b887e0dca09"
    );
    let corpus: Value = serde_json::from_slice(&raw).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    let mut count = 0;
    for case in cases {
        let mut arrays = Arrays(
            case["initial_arrays"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| unhex(s.as_str().unwrap()))
                .collect(),
        );
        let mut state = Streams::default();
        for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{} step {index}: {}", case["name"], step["command"]);
            let result = invoke(&mut state, &mut arrays, &step["command"]);
            if let Some(error) = step["error"].as_str() {
                assert!(result.unwrap_err().to_string().contains(error), "{label}");
            } else {
                assert_eq!(result.unwrap(), step["result"], "{label}");
            }
            assert_eq!(
                json!(arrays.0.iter().map(|v| hex(v)).collect::<Vec<_>>()),
                step["arrays"],
                "{label}"
            );
            let summary = state.describe();
            let actual:Vec<_>=summary.evidence.iter().map(|s|json!({"length":s.length,"position":s.position,"writable":s.writable,
                "closed":s.closed,"expandable":s.expandable,"bytes":hex(&state.to_array(s.reference,&arrays).unwrap())})).collect();
            assert_eq!(json!(actual), step["streams"], "{label}");
            count += 1;
        }
    }
    assert_eq!(count, 80);
}
