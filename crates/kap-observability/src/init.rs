use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber with JSON format and env filter.
///
/// Safe to call more than once — the second call logs a warning and returns
/// without panicking.
pub fn init_tracing(service_name: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let result = fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .try_init();

    match result {
        Ok(()) => {
            tracing::info!(service = service_name, "tracing initialized");
        }
        Err(_) => {
            eprintln!("warning: tracing subscriber already set, skipping re-initialization");
        }
    }
}
