use uuid::Uuid;

/// Generate a new request ID with `req_` prefix.
pub fn generate_request_id() -> String {
    format!("req_{}", Uuid::new_v4().as_simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_has_correct_prefix_and_length() {
        let id = generate_request_id();
        assert!(id.starts_with("req_"), "id should start with req_: {id}");
        // "req_" (4) + UUID simple (32 hex chars) = 36
        assert_eq!(id.len(), 36, "unexpected request id length: {id}");
    }

    #[test]
    fn request_ids_are_unique() {
        let a = generate_request_id();
        let b = generate_request_id();
        assert_ne!(a, b);
    }
}
