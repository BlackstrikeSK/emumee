//! Exact offline HTTP fixtures. Parsing never resolves or connects to a URL.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use unicode_casefold::UnicodeCaseFold;

pub const MAX_FILE: usize = 48 * 1024 * 1024;
pub const MAX_TOTAL: usize = 32 * 1024 * 1024;
pub const MAX_BODY: usize = 16 * 1024 * 1024;
pub const MAX_RULES: usize = 32;
pub type Headers = Vec<(String, String)>;

// Value's default object representation sorts keys. A second, narrow typed
// view retains response object-header order without changing JSON behavior in
// the rest of the application or retaining another copy of all fixture bodies.
#[derive(Deserialize)]
struct HeaderDocument {
    rules: Vec<HeaderRule>,
}
#[derive(Deserialize)]
struct HeaderRule {
    response: HeaderResponse,
}
#[derive(Deserialize)]
struct HeaderResponse {
    headers: OrderedHeaders,
}
struct OrderedHeaders(Headers);
impl<'de> Deserialize<'de> for OrderedHeaders {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = OrderedHeaders;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("HTTP header object or name/value pairs")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, String>()? {
                    if let Some(existing) = pairs.iter_mut().find(|(name, _)| *name == pair.0) {
                        *existing = pair;
                    } else {
                        pairs.push(pair);
                    }
                    if pairs.len() > 64 {
                        return Err(serde::de::Error::custom("HTTP header count exceeds 64"));
                    }
                }
                validate_headers(&pairs).map_err(serde::de::Error::custom)?;
                Ok(OrderedHeaders(pairs))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = seq.next_element::<(String, String)>()? {
                    pairs.push(pair);
                    if pairs.len() > 64 {
                        return Err(serde::de::Error::custom("HTTP header count exceeds 64"));
                    }
                }
                validate_headers(&pairs).map_err(serde::de::Error::custom)?;
                Ok(OrderedHeaders(pairs))
            }
        }
        input.deserialize_any(Visitor)
    }
}

/// Canonical base64 avoids the large per-byte JSON-array transport overhead.
pub mod binary {
    use super::*;
    pub fn serialize<S: serde::Serializer>(data: &[u8], out: S) -> Result<S::Ok, S::Error> {
        if data.len() > MAX_BODY {
            return Err(serde::ser::Error::custom("HTTP body exceeds 16 MiB"));
        }
        out.serialize_str(&STANDARD.encode(data))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(input)?;
        decode(&text).map_err(serde::de::Error::custom)
    }
}
fn decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() > 4 * MAX_BODY.div_ceil(3) {
        return Err("Oversized base64 HTTP body".into());
    }
    let data = STANDARD.decode(text).map_err(|e| e.to_string())?;
    if data.len() > MAX_BODY || STANDARD.encode(&data) != text {
        return Err("HTTP body requires canonical base64 within 16 MiB".into());
    }
    Ok(data)
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub chunked: bool,
    pub headers: BTreeMap<String, String>,
    #[serde(with = "binary")]
    pub body: Vec<u8>,
}
impl HttpRequest {
    pub fn get(url: String) -> Self {
        Self {
            method: "GET".into(),
            url,
            chunked: false,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
    pub fn normalize(&mut self) -> Result<(), String> {
        if !matches!(
            self.method.as_str(),
            "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "PATCH"
        ) {
            return Err("Unsupported HTTP fixture method".into());
        }
        validate_url(&self.url)?;
        self.headers = request_headers(
            self.headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )?;
        if self.body.len() > MAX_BODY {
            return Err("HTTP body exceeds 16 MiB".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Headers,
    #[serde(with = "binary")]
    pub body: Vec<u8>,
}
impl HttpResponse {
    pub fn validate(&self) -> Result<(), String> {
        if !(100..=999).contains(&self.status)
            || self.reason.chars().count() > 128
            || invalid_text(&self.reason)
            || !matches!(self.version.as_str(), "HTTP/1.0" | "HTTP/1.1")
            || self.body.len() > MAX_BODY
        {
            return Err("Invalid HTTP fixture response".into());
        }
        validate_headers(&self.headers)
    }
}
#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub request: HttpRequest,
    pub response: HttpResponse,
}
#[derive(Clone, Debug, Default)]
pub struct Fixtures {
    rules: Vec<Rule>,
}
fn invalid_text(text: &str) -> bool {
    text.contains(['\r', '\n', '\0'])
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing/string required: {key}"))
}
fn body(value: &Value) -> Result<Vec<u8>, String> {
    match (value.get("body_base64"), value.get("body_utf8")) {
        (Some(Value::String(text)), None) => decode(text),
        (None, Some(Value::String(text))) if text.len() <= MAX_BODY => Ok(text.as_bytes().to_vec()),
        _ => Err("Exactly one bounded body_base64 or body_utf8 string is required".into()),
    }
}
fn validate_headers(headers: &Headers) -> Result<(), String> {
    if headers.len() > 64
        || headers
            .iter()
            .any(|(name, value)| name.is_empty() || invalid_text(name) || invalid_text(value))
        || headers
            .iter()
            .map(|(n, v)| n.chars().count() + v.chars().count())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err("Invalid or oversized HTTP headers".into());
    }
    Ok(())
}
fn headers(value: &Value) -> Result<Headers, String> {
    let headers = if let Some(map) = value.as_object() {
        map.iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    v.as_str()
                        .ok_or("HTTP header value must be a string")?
                        .into(),
                ))
            })
            .collect::<Result<Headers, String>>()?
    } else if let Some(list) = value.as_array() {
        list.iter()
            .map(|pair| {
                let pair = pair
                    .as_array()
                    .filter(|p| p.len() == 2)
                    .ok_or("HTTP header requires a name/value pair")?;
                Ok((
                    pair[0]
                        .as_str()
                        .ok_or("HTTP header name must be a string")?
                        .into(),
                    pair[1]
                        .as_str()
                        .ok_or("HTTP header value must be a string")?
                        .into(),
                ))
            })
            .collect::<Result<Headers, String>>()?
    } else {
        return Err("HTTP headers must be an object or list".into());
    };
    validate_headers(&headers)?;
    Ok(headers)
}
fn request_headers(headers: Headers) -> Result<BTreeMap<String, String>, String> {
    validate_headers(&headers)?;
    let mut normalized = BTreeMap::new();
    for (name, value) in headers {
        if normalized
            .insert(name.as_str().case_fold().collect(), value)
            .is_some()
        {
            return Err("Duplicate case-folded HTTP request header".into());
        }
    }
    Ok(normalized)
}
pub fn validate_url(text: &str) -> Result<(), String> {
    // Url is used solely for syntax checks. Preserve the literal spelling for
    // exact matching; never use socket_addrs or a normalized destination.
    if text.is_empty()
        || text.chars().count() > 2048
        || text.chars().any(char::is_control)
        || text.contains('\\')
    {
        return Err("Invalid HTTP fixture URL".into());
    }
    let (scheme, rest) = text
        .split_once("://")
        .ok_or("HTTP URL requires explicit authority")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || authority.is_empty()
        || authority.ends_with(':')
    {
        return Err("Invalid HTTP fixture authority".into());
    }
    let parsed = url::Url::parse(text).map_err(|e| e.to_string())?;
    if !parsed.has_host() {
        return Err("HTTP fixture URL has no host".into());
    }
    Ok(())
}
impl Fixtures {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.len() > MAX_FILE {
            return Err("HTTP fixture file exceeds 48 MiB".into());
        }
        let document: Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        if document["version"].as_u64() != Some(1) {
            return Err("HTTP fixture version must be integer 1".into());
        }
        let list = document["rules"]
            .as_array()
            .filter(|v| v.len() <= MAX_RULES)
            .ok_or("HTTP fixture rules must be a list of at most 32 entries")?;
        let mut result = Self::default();
        let mut total = 0;
        let mut seen = HashSet::new();
        for (index, rule) in list.iter().enumerate() {
            let id = match rule.get("id") {
                Some(Value::String(id)) => id.clone(),
                None => format!("rule-{}", index + 1),
                _ => return Err("HTTP rule id must be a string".into()),
            };
            if id.is_empty() || id.chars().count() > 64 {
                return Err("Invalid HTTP rule id".into());
            }
            let req = &rule["request"];
            let resp = &rule["response"];
            let request = HttpRequest {
                method: string(req, "method")?.into(),
                url: string(req, "url")?.into(),
                chunked: req["chunked"]
                    .as_bool()
                    .ok_or("HTTP chunked must be boolean")?,
                headers: request_headers(headers(&req["headers"])?)?,
                body: body(req)?,
            };
            let mut checked = request.clone();
            checked.normalize()?;
            let response = HttpResponse {
                status: resp["status"]
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or("HTTP status must be an integer")?,
                reason: string(resp, "reason")?.into(),
                version: string(resp, "version")?.into(),
                headers: headers(&resp["headers"])?,
                body: body(resp)?,
            };
            response.validate()?;
            total += request.body.len() + response.body.len();
            if total > MAX_TOTAL {
                return Err("HTTP fixture bodies exceed 32 MiB total".into());
            }
            // Hash bounded canonical request data instead of retaining a second
            // complete body copy in the duplicate-key set.
            use sha2::{Digest, Sha256};
            let key = Sha256::digest(serde_json::to_vec(&request).map_err(|e| e.to_string())?);
            if !seen.insert(key) {
                return Err("Duplicate exact HTTP fixture request".into());
            }
            result.rules.push(Rule {
                id,
                request,
                response,
            });
        }
        let ordered: HeaderDocument = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        for (rule, headers) in result.rules.iter_mut().zip(ordered.rules) {
            rule.response.headers = headers.response.headers.0;
        }
        Ok(result)
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    pub fn matching(&self, request: &HttpRequest) -> Result<Option<&Rule>, String> {
        let mut request = request.clone();
        request.normalize()?;
        Ok(self.rules.iter().find(|rule| rule.request == request))
    }
    pub fn document(&self) -> Value {
        json!({"version":1,"rules":self.rules.iter().map(|rule|json!({"id":rule.id,
            "request":{"method":rule.request.method,"url":rule.request.url,"chunked":rule.request.chunked,"headers":rule.request.headers,"body_base64":STANDARD.encode(&rule.request.body)},
            "response":{"status":rule.response.status,"reason":rule.response.reason,"version":rule.response.version,"headers":rule.response.headers,"body_base64":STANDARD.encode(&rule.response.body)}})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> Value {
        json!({"version":1,"rules":[{"request":{"method":"POST","url":"https://fixture.invalid:443/a%2fb?q=One#literal","chunked":true,"headers":[["X-Straße","Exact"],["Content-Type","binary"]],"body_base64":"AP8QgA=="},"response":{"status":206,"reason":"Partial","version":"HTTP/1.0","headers":[["Set-Cookie","one"],["Set-Cookie","two"]],"body_utf8":"Rúst\u{0}"}}]})
    }
    fn parse(value: &Value) -> Result<Fixtures, String> {
        Fixtures::parse(&serde_json::to_vec(value).unwrap())
    }
    #[test]
    fn exact_request_dimensions_and_canonical_document_round_trip() {
        let fixtures = parse(&document()).unwrap();
        let rule = &fixtures.rules()[0];
        assert_eq!(rule.id, "rule-1");
        assert_eq!(rule.request.body, [0, 255, 16, 128]);
        assert_eq!(rule.response.headers.len(), 2);
        assert_eq!(rule.response.body, "Rúst\0".as_bytes());
        let mut request = rule.request.clone();
        let header = request.headers.remove("x-strasse").unwrap();
        request.headers.insert("X-STRASSE".into(), header);
        assert!(fixtures.matching(&request).unwrap().is_some());
        for dimension in 0..5 {
            let mut changed = request.clone();
            match dimension {
                0 => changed.method = "PUT".into(),
                1 => changed.url = changed.url.replace("a%2fb", "a/b"),
                2 => changed.chunked = false,
                3 => {
                    changed.headers.insert("extra".into(), "".into());
                }
                _ => changed.body.push(0),
            }
            assert!(fixtures.matching(&changed).unwrap().is_none());
        }
        let again = parse(&fixtures.document()).unwrap();
        assert_eq!(again.document(), fixtures.document());
        let raw=br#"{"version":1,"rules":[{"request":{"method":"GET","url":"https://fixture.invalid/","chunked":false,"headers":{},"body_utf8":""},"response":{"status":200,"reason":"OK","version":"HTTP/1.1","headers":{"Z-Last":"one","A-First":"two"},"body_utf8":""}}]}"#;
        assert_eq!(
            Fixtures::parse(raw).unwrap().rules()[0].response.headers,
            vec![
                ("Z-Last".into(), "one".into()),
                ("A-First".into(), "two".into())
            ]
        );
    }
    #[test]
    fn malformed_types_bodies_headers_urls_and_duplicate_rules_are_rejected() {
        for encoded in ["AP8QgA", "AP8QgB==", "AP8QgA===", "AP8Q gA==", "____"] {
            let mut doc = document();
            doc["rules"][0]["request"]["body_base64"] = encoded.into();
            assert!(parse(&doc).is_err(), "{encoded}");
        }
        for (path, value) in [
            ("/version", json!(true)),
            ("/rules/0/id", json!("")),
            ("/rules/0/request/method", json!("post")),
            ("/rules/0/request/chunked", json!(0)),
            ("/rules/0/request/body_utf8", json!(null)),
            (
                "/rules/0/request/headers",
                json!([["Straße", "1"], ["STRASSE", "2"]]),
            ),
            ("/rules/0/response/status", json!(200.0)),
            ("/rules/0/response/reason", json!("x\r\ny")),
            ("/rules/0/response/version", json!("HTTP/2")),
            ("/rules/0/response/headers", json!([["x", "bad\0"]])),
        ] {
            let mut doc = document();
            if path.ends_with("body_utf8") {
                doc["rules"][0]["request"]["body_utf8"] = value;
            } else if path == "/rules/0/id" {
                doc["rules"][0]["id"] = value;
            } else {
                *doc.pointer_mut(path).unwrap() = value;
            }
            assert!(parse(&doc).is_err(), "{path}");
        }
        for url in [
            "file:///x",
            "http:///no-authority",
            "http://host:",
            "https://[broken/",
            "https://host:65536/",
            "https://host/\nfoo",
        ] {
            let mut doc = document();
            doc["rules"][0]["request"]["url"] = url.into();
            assert!(parse(&doc).is_err(), "{url}");
        }
        let mut doc = document();
        let rule = doc["rules"][0].clone();
        doc["rules"].as_array_mut().unwrap().push(rule);
        assert!(parse(&doc).is_err());
    }
    #[test]
    fn resource_limits_and_binary_transport_fail_before_accepting_oversized_data() {
        let mut doc = document();
        doc["rules"] = json!(
            (0..33)
                .map(|_| document()["rules"][0].clone())
                .collect::<Vec<_>>()
        );
        assert!(parse(&doc).is_err());
        let mut doc = document();
        doc["rules"][0]["response"]["headers"] = json!([["x", "a".repeat(16384)]]);
        assert!(parse(&doc).is_err());
        let mut doc = document();
        doc["rules"][0]["response"]["body_utf8"] = "a".repeat(MAX_BODY + 1).into();
        assert!(parse(&doc).is_err());
        let oversized = vec![b' '; MAX_FILE + 1];
        assert!(Fixtures::parse(&oversized).is_err());
        let request = HttpRequest {
            body: vec![255; 65536],
            ..HttpRequest::get("https://fixture.invalid/".into())
        };
        let raw = serde_json::to_vec(&request).unwrap();
        assert!(raw.len() < 90000);
        assert_eq!(
            serde_json::from_slice::<HttpRequest>(&raw).unwrap(),
            request
        );
    }
}
