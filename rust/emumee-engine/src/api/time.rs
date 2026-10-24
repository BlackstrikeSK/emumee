use super::*;
pub(super) fn call(engine: &mut Unicorn<Trace>, model: Model, args: &[u64]) -> Result<u64> {
    let kernel = matches!(
        model,
        Model::KernelCounter | Model::KernelTime | Model::InterruptTime
    );
    ensure!(
        !kernel || engine.get_data().apis.kernel_mode,
        "Kernel time API requires a native driver target"
    );
    if !matches!(model, Model::Frequency) {
        engine.get_data_mut().clock.observe()?;
    }
    let value = match model {
        Model::Frequency => 10_000_000,
        Model::FileTime | Model::KernelTime => engine.get_data().clock.utc_filetime,
        _ => engine.get_data().clock.qpc(),
    };
    if matches!(model, Model::InterruptTime) {
        return Ok(value);
    }
    if matches!(model, Model::KernelCounter) && args[0] == 0 {
        return Ok(value);
    }
    if let Err(error) = require(engine, args[0], 8, P::WRITE) {
        if matches!(model, Model::Counter | Model::Frequency) {
            engine.get_data_mut().apis.last_error = 998;
            return Ok(0);
        }
        return Err(error);
    }
    crate::cpu::write(
        engine,
        args[0],
        &if matches!(model, Model::KernelCounter) {
            10_000_000u64
        } else {
            value
        }
        .to_le_bytes(),
    )?;
    Ok(if matches!(model, Model::KernelCounter) {
        value
    } else if matches!(model, Model::Counter | Model::Frequency) {
        1
    } else {
        0
    })
}
