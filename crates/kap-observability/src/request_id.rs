use uuid::Uuid;

/// Generate a new request ID with `req_` prefix.
pub fn generate_request_id() -> String {
    format!("req_{}", Uuid::new_v4().as_simple())
}
