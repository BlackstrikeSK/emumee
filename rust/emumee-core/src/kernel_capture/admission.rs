//! Pinned AMD64 capture entry policy, before any explicit capture-buffer write.
//! Facts must come from owned runtime state. Image initializers are insufficient.
//! Passing these gates does not establish valid buffers, records or capture success.
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub output: u64,
    pub thread: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    pub current_thread: Option<u64>,
    pub force_dump_disabled: Option<u8>,
    pub allow_crash_dump: Option<u8>,
    pub encryption_active: Option<u8>,
    pub secure_dump_state: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Fact {
    CurrentThread,
    ForceDumpDisabled,
    AllowCrashDump,
    EncryptionActive,
    SecureDumpState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Rejection {
    NullOutput,
    ForceDumpDisabled,
    CrashDumpNotAllowed,
    ActiveEncryptionStateTwo,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Decision {
    /// Native rejection cutpoint has RAX=0. Normal ABI stack effects are outside
    /// this policy evaluator; this is not a whole-function no-write guarantee.
    ReturnZero(Rejection),
    Needs(Fact),
    /// Continue to construction/preflight. Even a null resolved thread is left
    /// unchanged here: the native policy phase does not validate that identity.
    Continue {
        thread: u64,
    },
}
pub fn evaluate(input: Inputs, facts: &Facts) -> Decision {
    if input.output == 0 {
        return Decision::ReturnZero(Rejection::NullOutput);
    }
    let thread = if input.thread == 0 {
        let Some(thread) = facts.current_thread else {
            return Decision::Needs(Fact::CurrentThread);
        };
        thread
    } else {
        input.thread
    };
    let Some(disabled) = facts.force_dump_disabled else {
        return Decision::Needs(Fact::ForceDumpDisabled);
    };
    if disabled != 0 {
        return Decision::ReturnZero(Rejection::ForceDumpDisabled);
    }
    let Some(allowed) = facts.allow_crash_dump else {
        return Decision::Needs(Fact::AllowCrashDump);
    };
    if allowed == 0 {
        return Decision::ReturnZero(Rejection::CrashDumpNotAllowed);
    }
    let Some(encrypted) = facts.encryption_active else {
        return Decision::Needs(Fact::EncryptionActive);
    };
    if encrypted != 0 {
        let Some(state) = facts.secure_dump_state else {
            return Decision::Needs(Fact::SecureDumpState);
        };
        if state == 2 {
            return Decision::ReturnZero(Rejection::ActiveEncryptionStateTwo);
        }
    }
    Decision::Continue { thread }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_facts_are_requested_in_native_short_circuit_order() {
        let input = Inputs {
            output: 1,
            thread: 0,
        };
        let mut facts = Facts::default();
        assert_eq!(
            evaluate(
                Inputs {
                    output: 0,
                    thread: 0
                },
                &facts
            ),
            Decision::ReturnZero(Rejection::NullOutput)
        );
        assert_eq!(
            evaluate(input, &facts),
            Decision::Needs(Fact::CurrentThread)
        );
        facts.current_thread = Some(7);
        assert_eq!(
            evaluate(input, &facts),
            Decision::Needs(Fact::ForceDumpDisabled)
        );
        facts.force_dump_disabled = Some(0x80);
        assert_eq!(
            evaluate(input, &facts),
            Decision::ReturnZero(Rejection::ForceDumpDisabled)
        );
        facts.force_dump_disabled = Some(0);
        assert_eq!(
            evaluate(input, &facts),
            Decision::Needs(Fact::AllowCrashDump)
        );
        facts.allow_crash_dump = Some(0);
        assert_eq!(
            evaluate(input, &facts),
            Decision::ReturnZero(Rejection::CrashDumpNotAllowed)
        );
        facts.allow_crash_dump = Some(0xff);
        assert_eq!(
            evaluate(input, &facts),
            Decision::Needs(Fact::EncryptionActive)
        );
        facts.encryption_active = Some(0);
        assert_eq!(evaluate(input, &facts), Decision::Continue { thread: 7 });
        facts.encryption_active = Some(0x80);
        assert_eq!(
            evaluate(input, &facts),
            Decision::Needs(Fact::SecureDumpState)
        );
        facts.secure_dump_state = Some(2);
        assert_eq!(
            evaluate(input, &facts),
            Decision::ReturnZero(Rejection::ActiveEncryptionStateTwo)
        );
        for state in [0, 1, 3, 0x80000002, u32::MAX] {
            facts.secure_dump_state = Some(state);
            assert_eq!(evaluate(input, &facts), Decision::Continue { thread: 7 });
        }
        facts.current_thread = None;
        assert_eq!(
            evaluate(
                Inputs {
                    output: 1,
                    thread: 9
                },
                &facts
            ),
            Decision::Continue { thread: 9 }
        );
        facts.current_thread = Some(0);
        assert_eq!(evaluate(input, &facts), Decision::Continue { thread: 0 });
    }
    #[test]
    fn policy_matches_independent_native_instruction_oracle() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/native_capture_policy.json"
        ))
        .unwrap();
        let cases = oracle["cases"].as_array().unwrap();
        assert!(cases.len() >= 512);
        for row in cases {
            let get = |name: &str| row[name].as_u64().unwrap();
            let input = Inputs {
                output: get("output"),
                thread: get("thread"),
            };
            let facts = Facts {
                current_thread: Some(get("current_thread")),
                force_dump_disabled: Some(get("disabled") as u8),
                allow_crash_dump: Some(get("allowed") as u8),
                encryption_active: Some(get("encrypted") as u8),
                secure_dump_state: Some(get("state") as u32),
            };
            let actual = evaluate(input, &facts);
            if row["rejected"].as_bool().unwrap() {
                assert!(
                    matches!(actual, Decision::ReturnZero(_)),
                    "{row}: {actual:?}"
                );
            } else {
                assert_eq!(
                    actual,
                    Decision::Continue {
                        thread: get("resolved_thread")
                    },
                    "{row}"
                );
            }
            // Omit every fact the native path never reads. Evaluation must still
            // finish, and each actual read must be required at its exact prefix.
            let mut partial = Facts::default();
            for fact in row["reads"].as_array().unwrap() {
                let name = fact.as_str().unwrap();
                let needed = match name {
                    "current_thread" => Fact::CurrentThread,
                    "disabled" => Fact::ForceDumpDisabled,
                    "allowed" => Fact::AllowCrashDump,
                    "encrypted" => Fact::EncryptionActive,
                    "state" => Fact::SecureDumpState,
                    _ => panic!("unknown oracle fact"),
                };
                assert_eq!(evaluate(input, &partial), Decision::Needs(needed), "{row}");
                match needed {
                    Fact::CurrentThread => partial.current_thread = facts.current_thread,
                    Fact::ForceDumpDisabled => {
                        partial.force_dump_disabled = facts.force_dump_disabled
                    }
                    Fact::AllowCrashDump => partial.allow_crash_dump = facts.allow_crash_dump,
                    Fact::EncryptionActive => partial.encryption_active = facts.encryption_active,
                    Fact::SecureDumpState => partial.secure_dump_state = facts.secure_dump_state,
                }
            }
            assert_eq!(evaluate(input, &partial), actual, "{row}");
        }
    }
}
