//! Bounded x86 EH4 funclet dispatch on the owned guest continuation stack.
use super::*;

const RETURN: u64 = 0xc00;
const TOP: u32 = u32::MAX - 1;
const UNWIND: u32 = 0x66;

#[derive(Default)]
pub(super) struct State {
    frames: BTreeMap<u64, Vec<Pending>>,
    action: bool,
}
#[derive(Clone, Copy)]
struct Scope {
    level: u32,
    enclosing: u32,
    filter: u32,
    handler: u32,
}
#[derive(Clone, Copy)]
enum Phase {
    Cookies(usize),
    Search(usize),
    Global(usize),
    Local,
}
#[derive(Clone, Copy)]
enum AfterChecks {
    Search,
    Return(u32),
    Transfer,
}
#[derive(Clone, Copy)]
enum Callback {
    Cookie,
    Filter(usize),
    Finally,
    Global(usize),
}
struct Pending {
    saved: unicorn_engine::Context,
    pc: u64,
    sp: u64,
    api_frame: Vec<u8>,
    event: Option<usize>,
    cookie: u64,
    checker: u64,
    record: u64,
    context: u64,
    node: u64,
    frame: u64,
    table: u64,
    header: Vec<u8>,
    scopes: Vec<Scope>,
    phase: Phase,
    after_checks: AfterChecks,
    checked: Option<(crt_startup::initializers::CheckedCall, Callback)>,
    scratch: u64,
    selected: Option<Scope>,
    global: Vec<(u64, u64, u64)>,
    local_seen: BTreeSet<u32>,
    calls: usize,
    unwind_only: bool,
}

fn word(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        read_bytes(engine, address, 4)?.try_into().unwrap(),
    ))
}
fn put(engine: &mut Unicorn<Trace>, address: u64, value: u32) -> Result<()> {
    api::require_without_timer_guard(engine, address, 4, P::WRITE)?;
    crate::cpu::write(engine, address, &value.to_le_bytes())
}
fn stack(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    let (low, high) = user_threads::stack_bounds(engine)?;
    ensure!(
        address >= low && address.checked_add(size).is_some_and(|end| end <= high),
        "EH4 address left the owned stack"
    );
    api::require_without_timer_guard(engine, address, size, P::RW)
}
fn scope(engine: &Unicorn<Trace>, table: u64, level: u32) -> Result<Scope> {
    ensure!(level < 4096, "EH4 malformed scope level {level:#x}");
    let address = table
        .checked_add(16 + u64::from(level) * 12)
        .filter(|address| *address <= u32::MAX as u64 - 12)
        .context("EH4 scope address overflow")?;
    let raw = read_bytes(engine, address, 12)?;
    let value = Scope {
        level,
        enclosing: u32::from_le_bytes(raw[..4].try_into().unwrap()),
        filter: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
        handler: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
    };
    ensure!(
        value.enclosing == TOP || value.enclosing < 4096,
        "EH4 malformed enclosing level"
    );
    if value.filter != 0 {
        api::require_without_timer_guard(engine, value.filter.into(), 1, P::EXECUTE)?;
    }
    api::require_without_timer_guard(engine, value.handler.into(), 1, P::EXECUTE)?;
    Ok(value)
}
fn scopes(engine: &Unicorn<Trace>, table: u64, mut level: u32) -> Result<Vec<Scope>> {
    let mut seen = BTreeSet::new();
    let mut result = vec![];
    while level != TOP {
        ensure!(
            seen.len() < 128 && seen.insert(level),
            "EH4 scope cycle/bound"
        );
        let entry = scope(engine, table, level)?;
        level = entry.enclosing;
        result.push(entry);
    }
    Ok(result)
}
pub(super) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().native_exceptions.user.eh4.action
}
pub(super) fn active(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .native_exceptions
        .user
        .eh4
        .frames
        .values()
        .any(|frames| !frames.is_empty())
}
pub(super) fn queue(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().architecture == Architecture::X86 && args.len() == 6,
        "EH4 requires six x86 CDECL arguments"
    );
    ensure!(
        engine
            .get_data()
            .native_exceptions
            .user
            .eh4
            .frames
            .values()
            .map(Vec::len)
            .sum::<usize>()
            < 16,
        "EH4 continuation nesting bound"
    );
    let [cookie, checker, record, node, context, _] = <[u64; 6]>::try_from(args).unwrap();
    api::require_without_timer_guard(engine, checker, 1, P::EXECUTE)?;
    stack(
        engine,
        node.checked_sub(8).context("EH4 registration underflow")?,
        24,
    )?;
    ensure!(node & 3 == 0, "EH4 unaligned registration");
    let sp = uc(engine.reg_read(R::ESP))?;
    stack(engine, sp, 28)?;
    let scratch = sp.checked_sub(0x100).context("EH4 scratch underflow")? & !15;
    stack(
        engine,
        scratch
            .checked_sub(0x100)
            .context("EH4 callback stack underflow")?,
        0x180,
    )?;
    let table = u64::from(word(engine, node + 8)? ^ word(engine, cookie)?);
    let header = read_bytes(engine, table, 16)?;
    let scopes = scopes(engine, table, word(engine, node + 12)?)?;
    read_bytes(engine, record, 80)?;
    read_bytes(engine, context, 716)?;
    let unwind_only = word(engine, record + 4)? & UNWIND != 0;
    if !unwind_only {
        put(engine, scratch, record as u32)?;
        put(engine, scratch + 4, context as u32)?;
        put(engine, node - 4, scratch as u32)?;
    }
    let pending = Pending {
        saved: uc(engine.context_init())?,
        pc: uc(engine.pc_read())?,
        sp,
        api_frame: read_bytes(engine, sp, 28)?,
        event: engine.get_data().apis.next_event_index(),
        cookie,
        checker,
        record,
        context,
        node,
        frame: node + 16,
        table,
        header,
        scopes,
        phase: Phase::Cookies(0),
        after_checks: AfterChecks::Search,
        checked: None,
        scratch,
        selected: None,
        global: vec![],
        local_seen: BTreeSet::new(),
        calls: 0,
        unwind_only,
    };
    let id = user_threads::current_id(engine);
    let state = &mut engine.get_data_mut().native_exceptions.user.eh4;
    state.frames.entry(id).or_default().push(pending);
    state.action = true;
    Ok(0)
}
pub(super) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    let id = user_threads::current_id(engine);
    if pc == engine.get_data().return_marker + RETURN
        && engine
            .get_data()
            .native_exceptions
            .user
            .eh4
            .frames
            .get(&id)
            .and_then(|frames| frames.last())
            .is_some_and(|frame| frame.checked.is_some())
    {
        engine.get_data_mut().native_exceptions.user.eh4.action = true;
        true
    } else {
        false
    }
}
fn callback(
    engine: &mut Unicorn<Trace>,
    pending: &mut Pending,
    address: u64,
    ecx: Option<u32>,
    establishing: bool,
    arguments: &[u64],
    kind: Callback,
) -> Result<()> {
    pending.calls += 1;
    ensure!(pending.calls <= 1024, "EH4 callback bound");
    if establishing {
        uc(engine.reg_write(R::EBP, pending.frame))?;
    }
    if let Some(value) = ecx {
        uc(engine.reg_write(R::ECX, value.into()))?;
    }
    let checked = crt_startup::initializers::begin_checked_call(
        engine,
        address,
        pending.scratch - 0x40,
        arguments,
        true,
        engine.get_data().return_marker + RETURN,
    )?;
    pending.checked = Some((checked, kind));
    Ok(())
}
fn checks(pending: &mut Pending, after: AfterChecks) {
    pending.after_checks = after;
    pending.phase = Phase::Cookies(0);
}
fn complete_event(
    engine: &mut Unicorn<Trace>,
    event: Option<usize>,
    value: Option<u64>,
    effect: &'static str,
) {
    if let Some(event) = event.and_then(|index| engine.get_data_mut().apis.events.get_mut(index)) {
        event.pending = false;
        event.result = value;
        event.effect = Some(effect);
    }
}
fn return_api(engine: &mut Unicorn<Trace>, pending: &Pending, value: u32) -> Result<()> {
    ensure!(
        uc(engine.pc_read())? == pending.pc
            && uc(engine.reg_read(R::ESP))? == pending.sp
            && read_bytes(engine, pending.sp, 28)? == pending.api_frame,
        "EH4 CDECL caller frame changed"
    );
    let pc = word(engine, pending.sp)?;
    api::require_without_timer_guard(engine, pc.into(), 1, P::EXECUTE)?;
    uc(engine.reg_write(R::EIP, pc.into()))?;
    uc(engine.reg_write(R::ESP, pending.sp + 4))?;
    uc(engine.reg_write(R::EAX, value.into()))?;
    complete_event(
        engine,
        pending.event,
        Some(value.into()),
        "returned_from_eh4_scope_dispatch",
    );
    Ok(())
}
fn global_chain(engine: &Unicorn<Trace>, target: u64) -> Result<Vec<(u64, u64, u64)>> {
    let teb = api::user_bootstrap::active_teb(engine).context("EH4 TEB missing")?;
    let mut node = u64::from(word(engine, teb)?);
    let mut seen = BTreeSet::new();
    let mut result = vec![];
    while node != target {
        ensure!(
            node != 0 && node != u32::MAX as u64 && seen.len() < 128 && seen.insert(node),
            "EH4 global unwind target missing/cycle/bound"
        );
        stack(engine, node, 8)?;
        ensure!(node & 3 == 0, "EH4 unaligned unwind node");
        let next = u64::from(word(engine, node)?);
        let handler = u64::from(word(engine, node + 4)?);
        api::require_without_timer_guard(engine, handler, 1, P::EXECUTE)?;
        result.push((node, next, handler));
        node = next;
    }
    Ok(result)
}
fn transfer(engine: &mut Unicorn<Trace>, pending: &Pending) -> Result<()> {
    let id = user_threads::current_id(engine);
    ensure!(
        engine
            .get_data()
            .native_exceptions
            .user
            .eh4
            .frames
            .get(&id)
            .is_none_or(|frames| frames.is_empty()),
        "EH4 nonlocal transfer across an active EH4 callback is unsupported"
    );
    let owner = engine
        .get_data()
        .native_exceptions
        .user
        .frames
        .get(&id)
        .and_then(|frames| {
            frames.iter().rposition(|frame| {
                frame.record == pending.record
                    && frame.context == pending.context
                    && frame.next != 0
                    && matches!(frame.handlers[frame.next - 1].kind,
                Kind::Registration(node) if node == pending.node)
            })
        })
        .context("EH4 accepting handler requires an owned registration dispatch")?;
    let selected = pending.selected.context("EH4 accepting scope absent")?;
    let saved_sp = u64::from(word(engine, pending.node - 8)?);
    stack(engine, saved_sp, 4)?;
    ensure!(
        word(engine, pending.node + 12)? == selected.enclosing,
        "EH4 handler TryLevel changed during cookie revalidation"
    );
    let teb = api::user_bootstrap::active_teb(engine).context("EH4 TEB missing")?;
    ensure!(
        u64::from(word(engine, teb)?) == pending.node,
        "EH4 unwind chain changed before transfer"
    );
    let mut frames = engine
        .get_data_mut()
        .native_exceptions
        .user
        .frames
        .remove(&id)
        .unwrap();
    uc(engine.context_restore(&frames[owner].saved))?;
    if let Some(index) = frames[owner].event {
        engine.get_data_mut().native_exceptions.events[index].disposition = Some(0);
    }
    frames.truncate(owner);
    engine
        .get_data_mut()
        .native_exceptions
        .user
        .frames
        .insert(id, frames);
    uc(engine.reg_write(R::EBP, pending.frame))?;
    uc(engine.reg_write(R::ESP, saved_sp))?;
    uc(engine.reg_write(R::EIP, selected.handler.into()))?;
    engine.get_data_mut().native_memory_fault = None;
    complete_event(
        engine,
        pending.event,
        None,
        "eh4_nonreturning_handler_transfer",
    );
    Ok(())
}
pub(super) fn transition(engine: &mut Unicorn<Trace>) -> Result<Option<Outcome>> {
    let id = user_threads::current_id(engine);
    engine.get_data_mut().native_exceptions.user.eh4.action = false;
    let mut pending = engine
        .get_data_mut()
        .native_exceptions
        .user
        .eh4
        .frames
        .get_mut(&id)
        .and_then(Vec::pop)
        .context("EH4 continuation missing")?;
    let result = advance(engine, &mut pending);
    match result {
        Ok(true) => engine
            .get_data_mut()
            .native_exceptions
            .user
            .eh4
            .frames
            .entry(id)
            .or_default()
            .push(pending),
        Ok(false) => (),
        Err(error) => {
            complete_event(engine, pending.event, None, "eh4_dispatch_refused");
            return Err(error);
        }
    }
    Ok(None)
}
fn advance(engine: &mut Unicorn<Trace>, pending: &mut Pending) -> Result<bool> {
    if let Some((checked, kind)) = pending.checked.take() {
        checked.validate(engine)?;
        let value = uc(engine.reg_read(R::EAX))? as u32 as i32;
        uc(engine.context_restore(&pending.saved))?;
        match kind {
            Callback::Cookie | Callback::Finally => (),
            Callback::Global(index) => {
                ensure!(
                    value == 1,
                    "EH4 unsupported global unwind disposition {value}"
                );
                let (node, next, _) = pending.global[index];
                let teb = api::user_bootstrap::active_teb(engine).context("EH4 TEB missing")?;
                ensure!(
                    u64::from(word(engine, teb)?) == node && u64::from(word(engine, node)?) == next,
                    "EH4 global unwind registration changed"
                );
                put(engine, teb, next as u32)?;
            }
            Callback::Filter(index) => {
                if value < 0 {
                    ensure!(
                        word(engine, pending.record + 4)? & 1 == 0,
                        "EH4 noncontinuable exception cannot resume"
                    );
                    checks(pending, AfterChecks::Return(0));
                } else if value > 0 {
                    ensure!(
                        word(engine, pending.record)? != 0xe06d7363,
                        "EH4 C++ exception-object destruction is unsupported"
                    );
                    pending.selected = Some(pending.scopes[index]);
                    pending.global = global_chain(engine, pending.node)?;
                    pending.phase = Phase::Global(0);
                }
            }
        }
    }
    for _ in 0..512 {
        ensure!(
            u64::from(word(engine, pending.node + 8)? ^ word(engine, pending.cookie)?)
                == pending.table
                && read_bytes(engine, pending.table, 16)? == pending.header,
            "EH4 cookie/scope header changed"
        );
        match pending.phase {
            Phase::Cookies(index) => {
                if index < 2 {
                    pending.phase = Phase::Cookies(index + 1);
                    let offset = u32::from_le_bytes(
                        pending.header[index * 8..index * 8 + 4].try_into().unwrap(),
                    );
                    if index == 0 && offset == TOP {
                        continue;
                    }
                    let xor = u32::from_le_bytes(
                        pending.header[index * 8 + 4..index * 8 + 8]
                            .try_into()
                            .unwrap(),
                    );
                    let address = (pending.frame as u32).wrapping_add(offset);
                    stack(engine, address.into(), 4)?;
                    let cookie =
                        word(engine, address.into())? ^ (pending.frame as u32).wrapping_add(xor);
                    callback(
                        engine,
                        pending,
                        pending.checker,
                        Some(cookie),
                        false,
                        &[],
                        Callback::Cookie,
                    )?;
                    return Ok(true);
                }
                match pending.after_checks {
                    AfterChecks::Search => {
                        pending.phase = if pending.unwind_only {
                            Phase::Local
                        } else {
                            Phase::Search(0)
                        }
                    }
                    AfterChecks::Return(value) => {
                        return_api(engine, pending, value)?;
                        return Ok(false);
                    }
                    AfterChecks::Transfer => {
                        transfer(engine, pending)?;
                        return Ok(false);
                    }
                }
            }
            Phase::Search(index) => {
                let Some(entry) = pending.scopes.get(index).copied() else {
                    if pending.scopes.iter().any(|entry| entry.filter != 0) {
                        checks(pending, AfterChecks::Return(1));
                    } else {
                        return_api(engine, pending, 1)?;
                        return Ok(false);
                    }
                    continue;
                };
                let live = scope(engine, pending.table, entry.level)?;
                ensure!(
                    live.enclosing == entry.enclosing
                        && live.filter == entry.filter
                        && live.handler == entry.handler,
                    "EH4 scope record changed during search"
                );
                pending.phase = Phase::Search(index + 1);
                if entry.filter != 0 {
                    callback(
                        engine,
                        pending,
                        entry.filter.into(),
                        None,
                        true,
                        &[],
                        Callback::Filter(index),
                    )?;
                    return Ok(true);
                }
            }
            Phase::Global(index) => {
                if let Some((node, _, handler)) = pending.global.get(index).copied() {
                    let raw = read_bytes(engine, pending.record, 80)?;
                    crate::cpu::write(engine, pending.scratch + 0x20, &raw)?;
                    put(
                        engine,
                        pending.scratch + 0x24,
                        word(engine, pending.record + 4)? | 2,
                    )?;
                    pending.phase = Phase::Global(index + 1);
                    callback(
                        engine,
                        pending,
                        handler,
                        None,
                        false,
                        &[pending.scratch + 0x20, node, pending.context, 0],
                        Callback::Global(index),
                    )?;
                    return Ok(true);
                }
                pending.phase = Phase::Local;
            }
            Phase::Local => {
                let level = word(engine, pending.node + 12)?;
                let stop = pending.selected.map_or(TOP, |entry| entry.level);
                if level == stop {
                    if let Some(selected) = pending.selected {
                        put(engine, pending.node + 12, selected.enclosing)?;
                        checks(pending, AfterChecks::Transfer);
                    } else {
                        checks(pending, AfterChecks::Return(1));
                    }
                    continue;
                }
                ensure!(
                    level != TOP
                        && pending.local_seen.len() < 128
                        && pending.local_seen.insert(level),
                    "EH4 local unwind target missing/cycle/bound"
                );
                let entry = scope(engine, pending.table, level)?;
                put(engine, pending.node + 12, entry.enclosing)?;
                if entry.filter == 0 {
                    callback(
                        engine,
                        pending,
                        entry.handler.into(),
                        Some(1),
                        true,
                        &[],
                        Callback::Finally,
                    )?;
                    return Ok(true);
                }
            }
        }
    }
    bail!("EH4 transition bound exceeded")
}
pub(super) fn cancel(engine: &mut Unicorn<Trace>, id: u64) {
    if let Some(frames) = engine
        .get_data_mut()
        .native_exceptions
        .user
        .eh4
        .frames
        .remove(&id)
    {
        for frame in frames {
            complete_event(engine, frame.event, None, "eh4_continuation_cancelled");
        }
    }
}

#[cfg(test)]
mod tests;
