use super::*;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Pow,
    Floor,
    Sin,
}

pub(super) fn definition(name: &str) -> Option<(Call, usize)> {
    Some(match name {
        "pow" => (Call::Pow, 2),
        "floor" => (Call::Floor, 1),
        "sin" => (Call::Sin, 1),
        _ => return None,
    })
}

pub(super) fn invoke(args: &[u64], call: Call) -> Result<u64> {
    let value = f64::from_bits(args[0]);
    let result = match call {
        Call::Floor => {
            ensure!(
                value.is_finite(),
                "CRT floor cannot convert nonfinite input to integer"
            );
            let rounded = value.floor();
            if rounded == 0.0 { 0.0 } else { rounded }
        }
        Call::Sin => {
            ensure!(!value.is_infinite(), "CRT sin math domain error");
            value.sin()
        }
        Call::Pow => {
            let exponent = f64::from_bits(args[1]);
            ensure!(
                value != 0.0 || exponent >= 0.0 || !exponent.is_finite(),
                "CRT pow zero to negative power"
            );
            ensure!(
                !(value.is_finite()
                    && value < 0.0
                    && exponent.is_finite()
                    && exponent.fract() != 0.0),
                "CRT pow complex result is not a double"
            );
            let result = value.powf(exponent);
            ensure!(
                !(value.is_finite() && exponent.is_finite() && result.is_infinite()),
                "CRT pow numerical overflow"
            );
            result
        }
    };
    Ok(result.to_bits())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_floating_math_matches_isolated_frozen_handler_vectors() {
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("../../../api-parity/abi-float-reference.json"))
                .unwrap();
        let vectors = reference["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 143);
        for vector in vectors {
            let name = vector["api"].as_str().unwrap();
            let args: Vec<u64> = vector["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| u64::from_str_radix(value.as_str().unwrap(), 16).unwrap())
                .collect();
            let (call, count) = definition(name).unwrap();
            assert_eq!(count, args.len());
            let result = invoke(&args, call);
            if vector.get("error").is_some() {
                assert!(result.is_err(), "{vector}: {result:?}");
            } else {
                let actual = result.unwrap();
                let expected = u64::from_str_radix(vector["result"].as_str().unwrap(), 16).unwrap();
                if vector["nan"] == true {
                    assert!(f64::from_bits(actual).is_nan(), "{vector}");
                } else {
                    assert_eq!(actual, expected, "{vector}");
                }
            }
        }
    }
}
