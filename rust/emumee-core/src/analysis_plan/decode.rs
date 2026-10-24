//! Reject duplicate keys and bounded-tree violations before typed deserialization.
use super::{Result, demand, problem};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{cell::Cell, fmt};
struct Seed<'a> {
    depth: usize,
    nodes: &'a Cell<usize>,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        let n = self.nodes.get();
        if self.depth > 32 || n >= 100_000 {
            return Err(de::Error::custom("JSON depth/node bound"));
        }
        self.nodes.set(n + 1);
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded strict integer JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Value, E> {
        Err(E::custom("Floating point is not a plan integer"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        if v.len() > 32768 {
            return Err(E::custom("JSON string bound"));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        if v.len() > 32768 {
            return Err(E::custom("JSON string bound"));
        }
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            if values.len() >= 8192 {
                return Err(de::Error::custom("JSON array bound"));
            }
            values.push(v)
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 128 || values.len() >= 4096 || values.contains_key(&key) {
                return Err(de::Error::custom("JSON duplicate/key/map bound"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
pub(super) fn strict_json(raw: &[u8], maximum: usize) -> Result<Value> {
    demand(
        raw.len() <= maximum,
        "metadata_limit",
        "$",
        "JSON document byte bound",
    )?;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let nodes = Cell::new(0);
    let result = Seed {
        depth: 0,
        nodes: &nodes,
    }
    .deserialize(&mut decoder)
    .map_err(|_| problem("json", "$", "Malformed, duplicate, float or excessive JSON"))?;
    decoder
        .end()
        .map_err(|_| problem("json", "$", "Trailing JSON content"))?;
    Ok(result)
}
pub(super) fn named_fields(value: &Value) -> Result<()> {
    fn keys(value: &Value, path: &str, allowed: &[&str], code: &'static str) -> Result<()> {
        if let Some(object) = value.as_object() {
            for key in object.keys() {
                if !allowed.contains(&key.as_str()) {
                    return Err(problem(
                        code,
                        if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{path}.{key}")
                        },
                        "Unported or unknown external option/persona field",
                    ));
                }
            }
        }
        Ok(())
    }
    keys(
        value,
        "",
        &[
            "schema",
            "target",
            "inputs",
            "companions",
            "persona",
            "invocation",
            "network",
            "limits",
            "capture",
            "reports",
        ],
        "unsupported_option",
    )?;
    let persona = &value["persona"];
    if persona["kind"] == "rust_modeled_v1" {
        keys(
            persona,
            "persona",
            &["kind", "value"],
            "unsupported_persona_field",
        )?;
        let model = &persona["value"];
        keys(
            model,
            "persona.value",
            &[
                "process",
                "cpu",
                "clock",
                "windows_build",
                "current_processor",
                "physical_memory_mb",
                "available_memory_mb",
            ],
            "unsupported_persona_field",
        )?;
        keys(
            &model["process"],
            "persona.value.process",
            &[
                "hostname",
                "domain",
                "user_name",
                "user_profile",
                "current_directory",
                "windows_directory",
                "system_directory",
                "temp_directory",
                "logical_processors",
                "environment",
            ],
            "unsupported_persona_field",
        )?;
        keys(
            &model["cpu"],
            "persona.value.cpu",
            &[
                "brand",
                "signature",
                "cores",
                "threads_per_core",
                "base_mhz",
                "max_mhz",
            ],
            "unsupported_persona_field",
        )?;
        keys(
            &model["clock"],
            "persona.value.clock",
            &[
                "utc_filetime",
                "uptime_ms",
                "utc_offset_minutes",
                "source",
                "source_id",
            ],
            "unsupported_persona_field",
        )?;
    }
    Ok(())
}
