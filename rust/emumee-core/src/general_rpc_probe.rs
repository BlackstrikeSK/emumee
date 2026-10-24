//! Generated, non-authorizing offline RPC probe commitment.
//! A future guest request must use a separate admission path.
use crate::{
    broker::Data,
    networkfixtures::{HttpRequest, Rule},
    report_bundle::digest,
};
use serde::{Deserialize, Serialize};

pub const MAX_PROBE: usize = 64 * 1024;
pub const PROFILE: &str = "general_generated_rpc_probe_v1";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub execution_authorized: bool,
    pub request_sha256: String,
    pub claim_sha256: String,
    pub http_request: HttpRequest,
    pub expected_response_sha256: String,
    pub expected_status: u16,
    pub rule_id: String,
}

fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Probe {
    pub fn from_rule(
        request_sha256: String,
        claim_sha256: String,
        rule: &Rule,
    ) -> Result<Self, &'static str> {
        let raw = serde_json::to_vec(&rule.response)
            .map_err(|_| "General RPC response encoding failed")?;
        let probe = Self {
            schema: 1,
            profile: PROFILE.into(),
            operation: "verify_only".into(),
            execution_authorized: false,
            request_sha256,
            claim_sha256,
            http_request: rule.request.clone(),
            expected_response_sha256: digest(&raw),
            expected_status: rule.response.status,
            rule_id: rule.id.clone(),
        };
        probe.validate()?;
        Ok(probe)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_PROBE {
            return Err("General RPC probe exceeds 64 KiB");
        }
        let probe: Self =
            serde_json::from_slice(raw).map_err(|_| "General RPC probe schema invalid")?;
        probe.validate()?;
        Ok(probe)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.profile != PROFILE
            || self.operation != "verify_only"
            || self.execution_authorized
            || !sha(&self.request_sha256)
            || !sha(&self.claim_sha256)
            || !sha(&self.expected_response_sha256)
            || self.rule_id.is_empty()
            || self.rule_id.len() > 64
            || !(100..=999).contains(&self.expected_status)
        {
            return Err("General RPC probe identity invalid");
        }
        let mut normalized = self.http_request.clone();
        normalized
            .normalize()
            .map_err(|_| "General RPC HTTP request invalid")?;
        if normalized != self.http_request {
            return Err("General RPC HTTP request not canonical");
        }
        if serde_json::to_vec(self)
            .map_err(|_| "General RPC probe encoding failed")?
            .len()
            > MAX_PROBE
        {
            return Err("General RPC probe exceeds 64 KiB");
        }
        Ok(())
    }

    pub fn check_reply(&self, value: &Data) -> Result<String, &'static str> {
        let Data::HttpFull { response } = value else {
            return Err("General RPC reply was not full HTTP");
        };
        let raw = serde_json::to_vec(response).map_err(|_| "General RPC reply encoding failed")?;
        let hash = digest(&raw);
        if response.status != self.expected_status || hash != self.expected_response_sha256 {
            return Err("General RPC response differs from committed fixture");
        }
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        broker::Probe as BrokerProbe, fixtures::http::document, networkfixtures::Fixtures,
    };

    #[test]
    fn generated_replay_probe_rejects_changed_reply_or_permission() {
        let raw = crate::report_bundle::bounded_json(
            &document(BrokerProbe::WinHttp).unwrap(),
            crate::networkfixtures::MAX_FILE,
        )
        .unwrap();
        let fixtures = Fixtures::parse(&raw).unwrap();
        let rule = &fixtures.rules()[0];
        let probe = Probe::from_rule("a".repeat(64), "b".repeat(64), rule).unwrap();
        let raw = serde_json::to_vec(&probe).unwrap();
        assert_eq!(Probe::parse(&raw).unwrap(), probe);
        assert_eq!(
            probe
                .check_reply(&Data::HttpFull {
                    response: rule.response.clone()
                })
                .unwrap(),
            probe.expected_response_sha256
        );
        let mut changed = probe.clone();
        changed.execution_authorized = true;
        assert!(changed.validate().is_err());
        let mut response = rule.response.clone();
        response.body.push(1);
        assert!(probe.check_reply(&Data::HttpFull { response }).is_err());
    }
}
