//! Owned, planning-only parent intake of exact already-acquired buffers.
//! Serialized inspection JSON is never accepted as launch authority.
use super::*;

pub struct PreparedIntake {
    raw_plan: Vec<u8>,
    inputs: Vec<Vec<u8>>,
    spec: PlanSpec,
    resolved: ResolvedPlan,
}

impl PreparedIntake {
    pub fn prepare(raw_plan: Vec<u8>, inputs: Vec<Vec<u8>>) -> Result<Self> {
        let spec = PlanSpec::decode(&raw_plan)?;
        demand(
            inputs.len() == spec.inputs.len(),
            "inventory_count",
            "inputs",
            "Physical slot count differs from decoded plan",
        )?;
        let bindings = spec
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(input, bytes)| InputBytes {
                id: &input.id,
                bytes: bytes.as_slice(),
            })
            .collect::<Vec<_>>();
        let inventory = VerifiedInventory::verify(&spec.inputs, &bindings)?;
        let resolved = resolve(&spec, &inventory, &Capabilities::planning_only_v1())?;
        demand(
            !resolved.executable(),
            "execution_gate",
            "$",
            "Prepared intake cannot authorize execution",
        )?;
        Ok(Self {
            raw_plan,
            inputs,
            spec,
            resolved,
        })
    }

    /// Separate, explicit large-driver planning path. Its resolved value is
    /// non-executable and is never accepted as a worker launch permit.
    pub fn prepare_driver128(raw_plan: Vec<u8>, inputs: Vec<Vec<u8>>) -> Result<Self> {
        let spec = PlanSpec::decode(&raw_plan)?;
        demand(
            inputs.len() == spec.inputs.len(),
            "inventory_count",
            "inputs",
            "Driver128 physical slot count differs",
        )?;
        let bindings = spec
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(input, bytes)| InputBytes {
                id: &input.id,
                bytes,
            })
            .collect::<Vec<_>>();
        let inventory = VerifiedInventory::verify(&spec.inputs, &bindings)?;
        let resolved =
            resolve_driver128_planning(&spec, &inventory, &Capabilities::planning_only_v1())?;
        demand(
            !resolved.executable()
                && resolved.value()["guest_admission"] == false
                && resolved.value()["engine_applied"] == false,
            "execution_gate",
            "$",
            "Driver128 planning cannot authorize execution",
        )?;
        Ok(Self {
            raw_plan,
            inputs,
            spec,
            resolved,
        })
    }

    pub fn raw_plan(&self) -> &[u8] {
        &self.raw_plan
    }

    pub fn resolved(&self) -> &ResolvedPlan {
        &self.resolved
    }

    pub fn slots(&self) -> impl ExactSizeIterator<Item = (&InputSpec, &[u8])> + '_ {
        self.spec
            .inputs
            .iter()
            .zip(self.inputs.iter().map(Vec::as_slice))
    }
}
