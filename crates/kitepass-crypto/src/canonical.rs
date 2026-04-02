use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CanonicalJsonError {
    #[error("failed to canonicalize JSON payload: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("canonical JSON bytes were not valid utf-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub fn to_vec(payload: &impl Serialize) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(serde_json_canonicalizer::to_vec(payload)?)
}

pub fn to_string(payload: &impl Serialize) -> Result<String, CanonicalJsonError> {
    Ok(String::from_utf8(to_vec(payload)?)?)
}

#[cfg(test)]
mod tests {
    use super::to_vec;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let left = json!({
            "b": 2,
            "a": 1
        });
        let right = json!({
            "a": 1,
            "b": 2
        });

        assert_eq!(to_vec(&left).unwrap(), to_vec(&right).unwrap());
    }
}
