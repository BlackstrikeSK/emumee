//! Borrowed, ordered split of verified general input bytes by role.
//! This is a staging contract only; OS ACLs and broker journal confinement
//! must still be proved by a packaged parent/worker/broker run.
use crate::{
    analysis_plan::{InputRole, PreparedIntake},
    report_bundle::digest,
};

pub struct BrokerPartition<'a> {
    worker: Vec<Option<&'a [u8]>>,
    fixture: Option<(&'a str, &'a [u8], &'a str)>,
}

impl<'a> BrokerPartition<'a> {
    /// Parent owns the full verified intake. A broker-only slot is absent from
    /// the worker view, while its original bytes remain available to the
    /// parent for separate private broker staging.
    pub fn from_intake(intake: &'a PreparedIntake) -> Result<Self, &'static str> {
        let mut worker = Vec::with_capacity(intake.slots().len());
        let mut fixture = None;
        for (spec, bytes) in intake.slots() {
            if spec.roles.contains(&InputRole::OfflineFixtures) {
                if fixture.is_some() || spec.roles.len() != 1 {
                    return Err("General broker fixture role is ambiguous");
                }
                fixture = Some((spec.id.as_str(), bytes, spec.sha256.as_str()));
                worker.push(None);
            } else {
                worker.push(Some(bytes));
            }
        }
        Ok(Self { worker, fixture })
    }

    pub fn worker_slots(&self) -> &[Option<&'a [u8]>] {
        &self.worker
    }

    pub fn fixture(&self) -> Option<(&'a str, &'a [u8], &'a str)> {
        self.fixture
    }

    /// A worker must acknowledge the broker-only slot as an uninspected
    /// commitment. It cannot supply fixture bytes or omit a public slot.
    pub fn verify_worker_view(&self, supplied: &[Option<&[u8]>]) -> Result<(), &'static str> {
        if supplied.len() != self.worker.len() {
            return Err("General worker slot count changed");
        }
        for (expected, actual) in self.worker.iter().zip(supplied) {
            match (expected, actual) {
                (None, None) => (),
                (Some(expected), Some(actual)) if *expected == *actual => (),
                (None, Some(_)) => return Err("Broker-only fixture supplied to worker"),
                _ => return Err("General worker public slot changed"),
            }
        }
        Ok(())
    }

    /// The broker separately re-acquires original private fixture bytes and
    /// binds them to the parent-verified full SHA-256. No worker projection can
    /// be promoted into proof of this private inspection.
    pub fn verify_broker_fixture(&self, supplied: Option<&[u8]>) -> Result<(), &'static str> {
        match (self.fixture, supplied) {
            (None, None) => Ok(()),
            (Some((_, expected, sha)), Some(actual))
                if expected == actual && digest(actual) == sha =>
            {
                Ok(())
            }
            (None, Some(_)) => Err("Unexpected general broker fixture"),
            _ => Err("General private broker fixture changed or absent"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis_plan::Arch, plan_runtime::Case};

    #[test]
    fn generated_replay_keeps_fixture_out_of_worker_and_binds_broker_bytes() {
        let generated = Case::NativeReplay.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(generated.plan, generated.inputs).unwrap();
        let split = BrokerPartition::from_intake(&intake).unwrap();
        let (fixture_id, fixture, sha) = split.fixture().unwrap();
        assert_eq!(fixture_id, "offline");
        assert_eq!(digest(fixture), sha);
        assert_eq!(
            split.worker_slots().iter().filter(|b| b.is_none()).count(),
            1
        );
        split.verify_worker_view(split.worker_slots()).unwrap();
        split.verify_broker_fixture(Some(fixture)).unwrap();
        let mut leaked = split.worker_slots().to_vec();
        let index = leaked.iter().position(Option::is_none).unwrap();
        leaked[index] = Some(fixture);
        assert_eq!(
            split.verify_worker_view(&leaked),
            Err("Broker-only fixture supplied to worker")
        );
        let mut changed = fixture.to_vec();
        changed[0] ^= 1;
        assert!(split.verify_broker_fixture(Some(&changed)).is_err());
        assert!(split.verify_broker_fixture(None).is_err());
    }

    #[test]
    fn generated_deny_has_no_private_fixture_and_refuses_invention() {
        let generated = Case::NativeDeny.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(generated.plan, generated.inputs).unwrap();
        let split = BrokerPartition::from_intake(&intake).unwrap();
        assert!(split.fixture().is_none());
        split.verify_worker_view(split.worker_slots()).unwrap();
        split.verify_broker_fixture(None).unwrap();
        assert!(split.verify_broker_fixture(Some(b"unexpected")).is_err());
        let mut missing = split.worker_slots().to_vec();
        missing[0] = None;
        assert!(split.verify_worker_view(&missing).is_err());
    }
}
