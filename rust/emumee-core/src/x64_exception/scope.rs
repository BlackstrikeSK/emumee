//! Resumable AMD64 C scope scan. Invoked only by a registered language handler;
//! it does not replace GS wrappers, execute guest callbacks, or restore contexts.
use crate::x64_unwind::{Error, Result, Scope};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Filter { address: u64, index: u32 },
    Finally { address: u64, next_scope: u32 },
    Unwind { target: u64, return_value: u64 },
    ContinueExecution,
    ContinueSearch,
}
#[derive(Clone, Debug)]
pub struct Scan {
    base: u64,
    pc: u64,
    target: u64,
    flags: u32,
    code: u32,
    scopes: Vec<Scope>,
    next: usize,
    pending: Option<Scope>,
    done: bool,
}
impl Scan {
    pub fn new(
        base: u64,
        pc: u64,
        target: u64,
        flags: u32,
        code: u32,
        scopes: Vec<Scope>,
        index: u32,
    ) -> Result<Self> {
        if scopes.len() > 4096 || base.checked_add(u32::MAX as u64).is_none() {
            return Err(Error::Invalid("scope scan bounds"));
        }
        if scopes.iter().any(|scope| scope.begin >= scope.end) {
            return Err(Error::Invalid("scope range"));
        }
        Ok(Self {
            base,
            pc,
            target,
            flags,
            code,
            scopes,
            next: index as usize,
            pending: None,
            done: false,
        })
    }
    /// A reply is required only for Filter. Finally continuations carry their
    /// updated ScopeIndex in the action, for nested/collided unwind bookkeeping.
    pub fn step(&mut self, reply: Option<i32>) -> Result<Action> {
        if self.done {
            return Err(Error::Invalid("completed scope scan"));
        }
        if let Some(scope) = self.pending {
            let value = reply.ok_or(Error::Invalid("missing filter return"))?;
            self.pending = None;
            if let Some(action) = self.filter_result(scope, value) {
                return Ok(action);
            }
        } else if reply.is_some() {
            return Err(Error::Invalid("unexpected filter return"));
        }
        while let Some(scope) = self.scopes.get(self.next).copied() {
            let index = self.next as u32;
            self.next += 1;
            if !self.contains(scope, self.pc) {
                continue;
            }
            if self.flags & 0x66 == 0 {
                if scope.target == 0 {
                    continue;
                }
                if scope.handler == 1 {
                    return Ok(self.filter_result(scope, 1).unwrap());
                }
                self.pending = Some(scope);
                return Ok(Action::Filter {
                    address: self.base + scope.handler as u64,
                    index,
                });
            }
            if self.flags & 0x20 != 0 {
                // MSVC may split one lexical try into disjoint regions. A
                // target in ANY region with the same handler/target stays in
                // that scope; checking only the current range is incorrect.
                if self.scopes.iter().any(|other| {
                    other.handler == scope.handler
                        && other.target == scope.target
                        && self.contains(*other, self.target)
                }) {
                    break;
                }
                if scope.target != 0 && self.target == self.base + scope.target as u64 {
                    break;
                }
            }
            if scope.target == 0 {
                return Ok(Action::Finally {
                    address: self.base + scope.handler as u64,
                    next_scope: index + 1,
                });
            }
        }
        self.done = true;
        Ok(Action::ContinueSearch)
    }
    fn contains(&self, scope: Scope, pc: u64) -> bool {
        pc >= self.base + scope.begin as u64 && pc < self.base + scope.end as u64
    }
    fn filter_result(&mut self, scope: Scope, value: i32) -> Option<Action> {
        if value == 0 {
            return None;
        }
        self.done = true;
        Some(if value < 0 {
            Action::ContinueExecution
        } else {
            Action::Unwind {
                target: self.base + scope.target as u64,
                return_value: self.code as u64,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn x64_scope_matches_native_filter_cleanup_and_split_scope_cases() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/native_x64_c_scope.json"
        ))
        .unwrap();
        assert_eq!(fixture["schema"], "emumee.native_c_scope.v1");
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let value = |name: &str| case[name].as_u64().unwrap();
            let scopes = case["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let field = |i: usize| entry[i].as_u64().unwrap() as u32;
                    scope(field(0), field(1), field(2), field(3))
                })
                .collect();
            let mut s = Scan::new(
                0x100000,
                0x100150,
                0x100000 + value("target_rva"),
                value("flags") as u32,
                0x80000003,
                scopes,
                value("initial_scope") as u32,
            )
            .unwrap();
            let mut events = Vec::new();
            let mut index = value("initial_scope");
            let mut reply = None;
            let mut finished = false;
            for _ in 0..16 {
                match s.step(reply.take()).unwrap() {
                    Action::Filter { address, index } => {
                        assert_eq!(
                            address,
                            0x100000 + case["scopes"][index as usize][2].as_u64().unwrap()
                        );
                        events.push(1);
                        reply = Some(case["answer"].as_i64().unwrap() as i32);
                    }
                    Action::Finally {
                        address,
                        next_scope,
                    } => {
                        assert_eq!(
                            address,
                            0x100000 + case["scopes"][next_scope as usize - 1][2].as_u64().unwrap()
                        );
                        events.push(2);
                        index = next_scope as u64;
                    }
                    action @ (Action::ContinueExecution | Action::ContinueSearch) => {
                        let disposition = u64::from(action == Action::ContinueSearch);
                        assert_eq!(disposition, value("disposition"));
                        assert_eq!(index, value("scope_index"));
                        assert_eq!(serde_json::json!(events), case["events"]);
                        finished = true;
                        break;
                    }
                    Action::Unwind { .. } => {
                        panic!("Native closed cases never request RtlUnwindEx")
                    }
                }
            }
            assert!(finished);
        }
    }
    fn scope(begin: u32, end: u32, handler: u32, target: u32) -> Scope {
        Scope {
            begin,
            end,
            handler,
            target,
        }
    }
    fn scan(flags: u32, target: u64, scopes: Vec<Scope>) -> Scan {
        Scan::new(0x1000, 0x1150, target, flags, 0x80000003, scopes, 0).unwrap()
    }
    #[test]
    fn x64_scope_search_defers_filters_and_requests_real_unwind() {
        let mut s = scan(
            0,
            0,
            vec![
                scope(0x100, 0x200, 0x500, 0),
                scope(0x100, 0x200, 0x600, 0x700),
                scope(0x100, 0x200, 1, 0x800),
            ],
        );
        assert_eq!(
            s.step(None).unwrap(),
            Action::Filter {
                address: 0x1600,
                index: 1
            }
        );
        assert!(s.step(None).is_err());
        assert_eq!(
            s.step(Some(0)).unwrap(),
            Action::Unwind {
                target: 0x1800,
                return_value: 0x80000003
            }
        );
        assert!(s.step(None).is_err());
        let mut s = scan(0, 0, vec![scope(0x100, 0x200, 0x600, 0x700)]);
        s.step(None).unwrap();
        assert_eq!(s.step(Some(i32::MIN)).unwrap(), Action::ContinueExecution);
    }
    #[test]
    fn x64_scope_unwind_preserves_split_scopes_and_cleanup_order() {
        let scopes = vec![
            scope(0x100, 0x200, 0x500, 0),
            scope(0x300, 0x400, 0x500, 0),
            scope(0x100, 0x200, 0x600, 0),
        ];
        let mut s = scan(0x22, 0x1350, scopes.clone());
        assert_eq!(s.step(None).unwrap(), Action::ContinueSearch);
        let mut s = scan(2, 0, scopes);
        assert_eq!(
            s.step(None).unwrap(),
            Action::Finally {
                address: 0x1500,
                next_scope: 1
            }
        );
        assert_eq!(
            s.step(None).unwrap(),
            Action::Finally {
                address: 0x1600,
                next_scope: 3
            }
        );
        assert_eq!(s.step(None).unwrap(), Action::ContinueSearch);
    }
    #[test]
    fn x64_scope_target_catch_stops_cleanup_and_ranges_are_half_open() {
        let scopes = vec![scope(0x100, 0x200, 1, 0x700), scope(0x100, 0x200, 0x500, 0)];
        assert_eq!(
            scan(0x22, 0x1700, scopes).step(None).unwrap(),
            Action::ContinueSearch
        );
        let mut s = Scan::new(
            0x1000,
            0x1200,
            0,
            0,
            0,
            vec![scope(0x100, 0x200, 1, 0x700)],
            0,
        )
        .unwrap();
        assert!(s.step(Some(1)).is_err());
        assert_eq!(s.step(None).unwrap(), Action::ContinueSearch);
    }
}
