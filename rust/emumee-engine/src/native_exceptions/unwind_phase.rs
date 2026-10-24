//! Second pass, including active guest language-wrapper frames. Only the
//! exact owned callback return boundary reconnects to the saved fault context.
use super::*;

pub(super) struct Request {
    pub record: ExceptionRecord,
    pub start: Context,
    pub target_frame: u64,
    pub target_ip: u64,
    pub return_value: u64,
    pub event: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    engine: &mut Unicorn<Trace>,
    request: Request,
    original: &ContextRecord,
    saved: &unicorn_engine::Context,
    anchor: u64,
    stack: Stack,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let exception = &request.record;
    ensure!(
        request.target_frame >= stack.low && request.target_frame < stack.high,
        "Unwind target frame is outside the owned stack"
    );
    let work = request.start.integer[4]
        .min(anchor)
        .checked_sub(0xc00)
        .context("Unwind workspace underflow")?
        & !15;
    ensure!(work >= stack.low + 0x1000, "Unwind stack overflow");
    let exception_pointer = work;
    let context_pointer = work + 0xa0;
    let search_pointer = work + 0x570;
    let dispatcher_pointer = work + 0xa40;
    let boundary = engine.get_data().return_marker + LANGUAGE_RETURN;
    let mut current = request.start.clone();
    let mut transient = true;
    let mut visited = BTreeSet::new();
    engine.get_data_mut().native_exceptions.unwinds_started += 1;
    if let Some(index) = request.event {
        let event = engine
            .get_data_mut()
            .apis
            .events
            .get_mut(index)
            .context("Unwind source API event missing")?;
        ensure!(
            event.pending && event.api.ends_with(".__C_specific_handler"),
            "Unwind source API event identity changed"
        );
        event.pending = false;
        event.result = None;
        event.effect = Some("unwinds_to_c_handler");
    }
    for _ in 0..256 {
        ensure!(
            visited.insert((transient, current.rip, current.integer[4])),
            "Unwind frame cycle"
        );
        if transient && current.rip == boundary {
            ensure!(
                current.integer[4] == anchor - 0x20,
                "Unwind crossed a different dispatcher callback frame"
            );
            current = original.registers();
            transient = false;
            engine
                .get_data_mut()
                .native_exceptions
                .dispatcher_boundaries_crossed += 1;
            continue;
        }
        ensure!(
            current.rip != engine.get_data().return_marker,
            "Unwind escaped before finding target frame"
        );
        if let Some(caller) = api_frame::caller(engine, &current, stack)? {
            current = caller;
            continue;
        }
        let (image, table) = image(engine, current.rip)?;
        let frame = unwind::unwind(&mut memory(engine), &image, &current, stack, 2)?;
        if transient {
            engine
                .get_data_mut()
                .native_exceptions
                .transient_unwind_frames += 1;
        }
        let target = !transient && frame.establisher == request.target_frame;
        if !transient {
            ensure!(
                frame.establisher <= request.target_frame,
                "Unwind passed its target frame"
            );
        }
        let mut record = exception.clone();
        record.flags = (record.flags & !0x66) | 2 | if target { 0x20 } else { 0 };
        if let Some(handler) = frame.handler {
            ensure!(
                engine.get_data().native_exceptions.events.len() < 256,
                "Native exception event bound exceeded"
            );
            let event = engine.get_data().native_exceptions.events.len();
            engine.get_data_mut().native_exceptions.events.push(Event {
                phase: "unwind",
                flags: record.flags,
                code: record.code,
                exception_address: record.address,
                control_pc: current.rip,
                establisher: frame.establisher,
                handler: handler.address,
                disposition: None,
                parameters: record.parameters.clone(),
            });
            let function = frame
                .function
                .context("Unwind handler lacks a runtime function")?;
            let index = image
                .functions
                .binary_search_by_key(&function.begin, |f| f.begin)
                .map_err(|_| anyhow::anyhow!("Unwind runtime function identity lost"))?;
            let dispatcher = DispatcherContext {
                control_pc: current.rip,
                image_base: image.base,
                function_entry: table + index as u64 * 12,
                establisher_frame: frame.establisher,
                target_ip: request.target_ip,
                context_record: search_pointer,
                language_handler: handler.address,
                handler_data: handler.data,
                ..DispatcherContext::default()
            };
            let mut context = original.clone();
            context.update(&current);
            let mut search = original.clone();
            search.update(&frame.caller);
            crate::cpu::write(engine, exception_pointer, &record.bytes()?)?;
            crate::cpu::write(engine, context_pointer, context.bytes())?;
            crate::cpu::write(engine, search_pointer, search.bytes())?;
            crate::cpu::write(engine, dispatcher_pointer, &dispatcher.bytes())?;
            let args = [
                exception_pointer,
                frame.establisher,
                context_pointer,
                dispatcher_pointer,
            ];
            engine.get_data_mut().native_exceptions.handler_arguments = Some(args);
            let outcome = invoke(
                engine,
                handler.address,
                &args,
                work - 0x28,
                engine.get_data().return_marker + UNWIND_RETURN,
                horizon,
            )?;
            engine.get_data_mut().native_exceptions.handler_arguments = None;
            ensure!(
                engine.get_data().native_exceptions.unwind.is_none(),
                "Nested target unwind is not yet supported"
            );
            if !outcome.returned {
                return Ok(Some(outcome));
            }
            let disposition = outcome.value.context("Unwind handler disposition absent")? as u32;
            engine.get_data_mut().native_exceptions.events[event].disposition = Some(disposition);
            ensure!(
                disposition == 1,
                "Unsupported unwind-handler disposition {disposition}"
            );
        }
        if target {
            ensure!(
                !frame.epilogue && !frame.machine_frame,
                "Unwind target is an epilogue or machine frame"
            );
            current.integer[4] = frame.establisher;
            current.integer[0] = request.return_value;
            current.rip = request.target_ip;
            let mut context = original.clone();
            context.update(&current);
            uc(engine.context_restore(saved))?;
            restore(engine, original, &context)?;
            engine.get_data_mut().native_exceptions.unwinds_completed += 1;
            return Ok(None);
        }
        current = frame.caller;
    }
    bail!("Unwind frame bound exceeded")
}
