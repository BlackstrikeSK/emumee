//! Deterministic, owned HTTP boundary data. No sample or host file is read.
use crate::{
    broker::Probe,
    networkfixtures::{HttpRequest, HttpResponse},
};
use serde_json::{Value, json};
pub fn request(probe: Probe) -> HttpRequest {
    let native = probe.binary() || probe.winhttp().is_some() || probe.internet().is_some();
    let upload = probe.winhttp().is_some_and(|fixture| fixture.upload())
        || probe.internet().is_some_and(|fixture| fixture.send());
    let chunked = probe.winhttp().is_some_and(|fixture| fixture.chunked());
    let get = !upload && !chunked && (native || matches!(probe, Probe::HttpBinary));
    HttpRequest {
        method: if get { "GET" } else { "POST" }.into(),
        url: if probe.winhttp().is_some() || probe.internet().is_some_and(|fixture| fixture.send())
        {
            "https://fixture.invalid:443/payload"
        } else if probe.binary() || probe.internet().is_some() {
            "https://fixture.invalid/payload"
        } else {
            "https://fixture.invalid:443/exact%2fbody?q=One"
        }
        .into(),
        chunked: chunked || (!get && !upload),
        headers: if chunked {
            std::collections::BTreeMap::from([("transfer-encoding".into(), "chunked".into())])
        } else if probe
            .internet()
            .is_some_and(|fixture| fixture.send() && !fixture.empty_post())
        {
            std::collections::BTreeMap::from([("x-case".into(), "Exact".into())])
        } else if native {
            Default::default()
        } else {
            std::collections::BTreeMap::from([("x-case".into(), "Exact".into())])
        },
        body: if probe.internet().is_some_and(|fixture| fixture.empty_post()) {
            Vec::new()
        } else if upload || chunked {
            b"RUSTBODY".to_vec()
        } else if get {
            Vec::new()
        } else {
            vec![0, 255, 128, 1]
        },
    }
}
pub fn response(probe: Probe) -> HttpResponse {
    HttpResponse {
        status: if probe.binary() || probe.winhttp().is_some() || probe.internet().is_some() {
            200
        } else {
            206
        },
        reason: if probe.binary() || probe.winhttp().is_some() || probe.internet().is_some() {
            "OK"
        } else {
            "Fixture partial"
        }
        .into(),
        version: "HTTP/1.0".into(),
        headers: vec![
            ("Set-Cookie".into(), "one".into()),
            ("Set-Cookie".into(), "two".into()),
        ],
        body: if matches!(
            probe,
            Probe::NativeBinaryEmpty | Probe::WinHttpEmpty | Probe::InternetEmpty
        ) {
            Vec::new()
        } else {
            (0..65536).map(|i| i as u8).collect()
        },
    }
}
pub fn document(probe: Probe) -> Result<Value, serde_json::Error> {
    if !probe.http() && !probe.binary() && probe.winhttp().is_none() && probe.internet().is_none() {
        return Ok(json!({"version":1,"rules":[]}));
    }
    let request = serde_json::to_value(request(probe))?;
    let response = serde_json::to_value(response(probe))?;
    let mut request = request.as_object().unwrap().clone();
    let body = request.remove("body").unwrap();
    request.insert("body_base64".into(), body);
    let mut response = response.as_object().unwrap().clone();
    let body = response.remove("body").unwrap();
    response.insert("body_base64".into(), body);
    Ok(json!({"version":1,"rules":[{"id":"owned-binary","request":request,"response":response}]}))
}
