//! Guest DLL/TLS notifications and terminal process cleanup under one horizon.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context;
use emumee_core::modules::{DynamicPhase, ImagePhase, LoaderInvocation, LoaderRoutine};

const MAX_EVENTS: usize = 4096;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub invocation: LoaderInvocation,
    pub reason: u32,
    pub thread: u64,
    pub started_instruction: u64,
    pub stopped_instruction: Option<u64>,
    pub returned: bool,
    pub error: Option<String>,
}

#[derive(Default)]
pub(crate) struct State {
    forced: bool,
    active: bool,
    complete: bool,
    events: Vec<Event>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub forced: bool,
    pub complete: bool,
    pub events: Vec<Event>,
    pub scope: &'static str,
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().user_lifecycle;
    engine.get_data().apis.user_bootstrap.as_ref().map(|_| Report {
        forced: state.forced, complete: state.complete, events: state.events.clone(),
        scope: "Actual catalog-derived guest TLS/DllMain notifications under the run's shared horizon. Normal process exit executes reverse initialization-order detach; forced termination skips guest callbacks. Terminal guest module memory remains available for reporting until the owning engine is dropped.",
    })
}

pub(crate) fn request_exit(engine: &mut Unicorn<Trace>, code: u32, forced: bool) -> Result<()> {
    ensure!(
        !engine.get_data().user_lifecycle.active,
        "Process exit reentrancy during loader notifications is unsupported"
    );
    engine.get_data_mut().process_exit_code = Some(code);
    engine.get_data_mut().user_lifecycle.forced = forced;
    uc(engine.emu_stop())?;
    Ok(())
}

fn calls(engine: &Unicorn<Trace>, reason: u32) -> Result<Vec<LoaderInvocation>> {
    ensure!(
        matches!(reason, 0 | 2 | 3),
        "Invalid loader notification reason"
    );
    let catalog = &engine.get_data().apis.modules;
    let mut order = catalog.initialization_order().to_vec();
    if reason != 2 {
        order.reverse();
    }
    let mut calls = Vec::new();
    for id in order {
        let Some(module) = catalog.by_identity(id) else {
            continue;
        };
        if !module
            .lifecycle()
            .is_some_and(|life| life.phase == ImagePhase::Ready)
            && !module
                .dynamic_image()
                .is_some_and(|life| life.phase == DynamicPhase::Ready)
        {
            continue;
        }
        let tls = module
            .initializer_tls()
            .context("Ready notification image has no TLS plan")?;
        let arguments = [module.base, reason as u64, u64::from(reason == 0)];
        for (index, rva) in tls.callback_rvas.iter().enumerate() {
            calls.push(LoaderInvocation {
                module: id,
                routine: if reason == 2 {
                    LoaderRoutine::TlsAttach
                } else {
                    LoaderRoutine::TlsDetach
                },
                callback_index: Some(index),
                address: module.base + *rva as u64,
                arguments,
            });
        }
        if (module
            .lifecycle()
            .is_some_and(|life| life.kind == emumee_core::pe::Kind::Dll)
            || module.dynamic_image().is_some())
            && module.entry_rva() != 0
        {
            calls.push(LoaderInvocation {
                module: id,
                routine: if reason == 2 {
                    LoaderRoutine::DllAttach
                } else {
                    LoaderRoutine::DllDetach
                },
                callback_index: None,
                address: module.base + module.entry_rva() as u64,
                arguments,
            });
        }
    }
    Ok(calls)
}

pub(crate) fn notify(
    engine: &mut Unicorn<Trace>,
    reason: u32,
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let calls = calls(engine, reason)?;
    let previous_active = engine.get_data().loader_active;
    let previous_notification = engine.get_data().user_lifecycle.active;
    engine.get_data_mut().loader_active = true;
    engine.get_data_mut().user_lifecycle.active = true;
    let result = (|| -> Result<Option<Outcome>> {
        for call in calls {
            ensure!(
                engine.get_data().user_lifecycle.events.len() < MAX_EVENTS,
                "Loader notification event quota exceeded"
            );
            let index = engine.get_data().user_lifecycle.events.len();
            let event = Event {
                invocation: call.clone(),
                reason,
                thread: crate::threads::current_id(engine),
                started_instruction: engine.get_data().instructions,
                stopped_instruction: None,
                returned: false,
                error: None,
            };
            engine.get_data_mut().user_lifecycle.events.push(event);
            let result = native_loader::invoke_inner(engine, &call, stack_top, horizon);
            let stopped = engine.get_data().instructions;
            let event = &mut engine.get_data_mut().user_lifecycle.events[index];
            event.stopped_instruction = Some(stopped);
            match &result {
                Ok(outcome) => {
                    event.returned = outcome.returned;
                    event.error = outcome.error.clone();
                }
                Err(error) => event.error = Some(format!("{error:#}")),
            }
            let outcome = result?;
            if !outcome.returned {
                return Ok(Some(outcome));
            }
        }
        Ok(None)
    })();
    engine.get_data_mut().loader_active = previous_active;
    engine.get_data_mut().user_lifecycle.active = previous_notification;
    result
}

pub(crate) fn finish_process(
    engine: &mut Unicorn<Trace>,
    stack_top: u64,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let Some(code) = engine.get_data_mut().process_exit_code.take() else {
        return Ok(None);
    };
    let forced = engine.get_data().user_lifecycle.forced;
    // Detach callbacks execute despite the process's terminal flag, but retain
    // exactly the same instruction/deadline authority as the primary execution.
    let result = if forced {
        Ok(None)
    } else {
        notify(engine, 0, stack_top, horizon)
    };
    engine.get_data_mut().process_exit_code = Some(code);
    match result {
        Ok(Some(mut outcome)) => {
            if outcome.error.is_none() {
                outcome.error = Some(
                    "Process detach did not return within the shared execution horizon".into(),
                );
            }
            Ok(Some(outcome))
        }
        Err(error) => Err(error),
        Ok(None) => {
            let threads = engine
                .get_data()
                .apis
                .user_loader
                .threads
                .keys()
                .copied()
                .collect::<Vec<_>>();
            for thread in threads {
                user_loader::detach_thread(engine, thread)?;
            }
            user_threads::cleanup_process(engine, forced)?;
            engine.get_data_mut().user_lifecycle.complete = true;
            Ok(None)
        }
    }
}
