use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{
    extract::{MatchedPath, State},
    http::{header::HeaderName, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::generate_request_id;

const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsErrorCode(pub String);

impl AnalyticsErrorCode {
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsRequestId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsOutcome {
    Started,
    Success,
    Failed,
}

impl AnalyticsOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyticsEndpointSpec {
    pub method: Method,
    pub route: &'static str,
    pub operation_name: &'static str,
    pub flow: &'static str,
    pub step: &'static str,
    pub auth_surface: &'static str,
    pub client_surface_hint: &'static str,
}

impl AnalyticsEndpointSpec {
    pub fn new(
        method: Method,
        route: &'static str,
        operation_name: &'static str,
        flow: &'static str,
        step: &'static str,
        auth_surface: &'static str,
        client_surface_hint: &'static str,
    ) -> Self {
        Self {
            method,
            route,
            operation_name,
            flow,
            step,
            auth_surface,
            client_surface_hint,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalyticsEndpointRegistry {
    endpoints: Arc<Vec<AnalyticsEndpointSpec>>,
    exact: Arc<HashMap<(Method, String), usize>>,
}

impl AnalyticsEndpointRegistry {
    pub fn new(endpoints: Vec<AnalyticsEndpointSpec>) -> Self {
        let exact = endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| ((endpoint.method.clone(), endpoint.route.to_string()), index))
            .collect();
        Self {
            endpoints: Arc::new(endpoints),
            exact: Arc::new(exact),
        }
    }

    pub fn resolve(
        &self,
        method: &Method,
        matched_route: Option<&str>,
        path: &str,
    ) -> AnalyticsEndpointSpec {
        if let Some(route) = matched_route {
            if let Some(endpoint) = self.resolve_route(method, route) {
                return endpoint.clone();
            }
        }
        if let Some(endpoint) = self.resolve_path(method, path) {
            return endpoint.clone();
        }
        unknown_endpoint(method, matched_route.unwrap_or(path))
    }

    pub fn resolve_route(&self, method: &Method, route: &str) -> Option<&AnalyticsEndpointSpec> {
        self.exact
            .get(&(method.clone(), route.to_string()))
            .and_then(|index| self.endpoints.get(*index))
    }

    pub fn resolve_path(&self, method: &Method, path: &str) -> Option<&AnalyticsEndpointSpec> {
        self.endpoints.iter().find(|endpoint| {
            endpoint.method == *method && route_pattern_matches(endpoint.route, path)
        })
    }

    pub fn endpoints(&self) -> &[AnalyticsEndpointSpec] {
        self.endpoints.as_slice()
    }
}

#[derive(Debug, Clone)]
pub struct AnalyticsState {
    service: Arc<str>,
    environment: Arc<str>,
    registry: AnalyticsEndpointRegistry,
}

impl AnalyticsState {
    pub fn new(
        service: impl Into<Arc<str>>,
        environment: impl Into<Arc<str>>,
        endpoints: Vec<AnalyticsEndpointSpec>,
    ) -> Self {
        Self {
            service: service.into(),
            environment: environment.into(),
            registry: AnalyticsEndpointRegistry::new(endpoints),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub fn registry(&self) -> &AnalyticsEndpointRegistry {
        &self.registry
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsEvent {
    pub record_type: &'static str,
    pub schema_version: u8,
    pub environment: String,
    pub service: String,
    pub occurred_at: String,
    pub event_name: String,
    pub flow: String,
    pub step: String,
    pub outcome: &'static str,
    pub route: String,
    pub method: String,
    pub request_id: String,
    pub auth_surface: String,
    pub client_surface: String,
    pub properties: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

pub async fn analytics_middleware(
    State(state): State<AnalyticsState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let started_at = Instant::now();
    let request_id = request_id_from_headers(request.headers()).unwrap_or_else(generate_request_id);
    request
        .extensions_mut()
        .insert(AnalyticsRequestId(request_id.clone()));

    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let matched_route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned());
    let endpoint = state
        .registry
        .resolve(&method, matched_route.as_deref(), &path);
    let client_surface = client_surface(request.headers(), endpoint.client_surface_hint);

    emit_event(&build_started_event(
        &state,
        &endpoint,
        &request_id,
        &client_surface,
    ));

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    let status = response.status();
    let failed = status.as_u16() >= 400;
    let error_code = failed.then(|| {
        response
            .extensions()
            .get::<AnalyticsErrorCode>()
            .map(|code| code.0.clone())
            .unwrap_or_else(|| error_code_for_status(status).to_string())
    });

    emit_event(&build_terminal_event(
        &state,
        &endpoint,
        &request_id,
        &client_surface,
        status,
        started_at.elapsed().as_millis(),
        error_code,
    ));

    response
}

pub fn analytics_environment() -> String {
    std::env::var("KITEPASS_ENVIRONMENT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if std::env::var("KITEPASS_DEV_MODE")
                .ok()
                .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false)
            {
                "dev".to_string()
            } else {
                "local".to_string()
            }
        })
}

pub fn build_started_event(
    state: &AnalyticsState,
    endpoint: &AnalyticsEndpointSpec,
    request_id: &str,
    client_surface: &str,
) -> AnalyticsEvent {
    build_event(
        state,
        endpoint,
        request_id,
        client_surface,
        AnalyticsOutcome::Started,
        None,
        None,
        None,
    )
}

pub fn build_terminal_event(
    state: &AnalyticsState,
    endpoint: &AnalyticsEndpointSpec,
    request_id: &str,
    client_surface: &str,
    status: StatusCode,
    latency_ms: u128,
    error_code: Option<String>,
) -> AnalyticsEvent {
    let outcome = if status.as_u16() < 400 {
        AnalyticsOutcome::Success
    } else {
        AnalyticsOutcome::Failed
    };
    build_event(
        state,
        endpoint,
        request_id,
        client_surface,
        outcome,
        Some(status),
        Some(latency_ms),
        error_code,
    )
}

pub fn event_json_line(event: &AnalyticsEvent) -> String {
    serde_json::to_string(event).expect("analytics event must serialize")
}

pub fn emit_event(event: &AnalyticsEvent) {
    println!("{}", event_json_line(event));
}

pub fn request_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_request_id(value))
        .map(ToOwned::to_owned)
}

pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn status_class(status: StatusCode) -> String {
    format!("{}xx", status.as_u16() / 100)
}

pub fn error_code_for_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "INVALID_ARGUMENT",
        StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
        StatusCode::FORBIDDEN => "FORBIDDEN",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::CONFLICT => "CONFLICT",
        StatusCode::GONE => "GONE",
        StatusCode::TOO_MANY_REQUESTS => "RATE_LIMITED",
        StatusCode::INTERNAL_SERVER_ERROR => "INTERNAL_ERROR",
        StatusCode::SERVICE_UNAVAILABLE => "TEMPORARY_UNAVAILABLE",
        status if status.is_client_error() => "CLIENT_ERROR",
        status if status.is_server_error() => "SERVER_ERROR",
        _ => "UNKNOWN",
    }
}

fn build_event(
    state: &AnalyticsState,
    endpoint: &AnalyticsEndpointSpec,
    request_id: &str,
    client_surface: &str,
    outcome: AnalyticsOutcome,
    status: Option<StatusCode>,
    latency_ms: Option<u128>,
    error_code: Option<String>,
) -> AnalyticsEvent {
    AnalyticsEvent {
        record_type: "analytics_event",
        schema_version: 1,
        environment: state.environment().to_string(),
        service: state.service().to_string(),
        occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        event_name: format!("{}_{}", endpoint.operation_name, outcome.as_str()),
        flow: endpoint.flow.to_string(),
        step: endpoint.step.to_string(),
        outcome: outcome.as_str(),
        route: endpoint.route.to_string(),
        method: endpoint.method.as_str().to_string(),
        request_id: request_id.to_string(),
        auth_surface: endpoint.auth_surface.to_string(),
        client_surface: client_surface.to_string(),
        properties: Value::Object(Map::new()),
        http_status: status.map(|status| status.as_u16()),
        status_class: status.map(status_class),
        latency_ms,
        error_code,
    }
}

fn unknown_endpoint(method: &Method, route: &str) -> AnalyticsEndpointSpec {
    let route = Box::leak(route.to_string().into_boxed_str());
    AnalyticsEndpointSpec::new(
        method.clone(),
        route,
        "unknown_endpoint",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
    )
}

fn route_pattern_matches(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if pattern_parts.len() != path_parts.len() {
        return false;
    }
    pattern_parts
        .iter()
        .zip(path_parts.iter())
        .all(|(pattern, actual)| {
            (pattern.starts_with('{') && pattern.ends_with('}') && !actual.is_empty())
                || pattern == actual
        })
}

fn client_surface(headers: &HeaderMap, hint: &str) -> String {
    headers
        .get("x-kitepass-client-surface")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "web" | "cli" | "agent" | "internal"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| hint.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get, Router};
    use tower::ServiceExt;

    fn test_spec() -> AnalyticsEndpointSpec {
        AnalyticsEndpointSpec::new(
            Method::GET,
            "/v1/wallets/{wallet_id}",
            "wallet_get",
            "wallet",
            "get_wallet",
            "principal",
            "cli",
        )
    }

    #[test]
    fn validates_safe_request_ids_only() {
        assert!(valid_request_id("req_abc-123"));
        assert!(valid_request_id(&"a".repeat(64)));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id(&"a".repeat(65)));
        assert!(!valid_request_id("req_bad\nline"));
        assert!(!valid_request_id("req.bad"));
    }

    #[test]
    fn maps_status_codes_to_analytics_error_codes() {
        assert_eq!(
            error_code_for_status(StatusCode::BAD_REQUEST),
            "INVALID_ARGUMENT"
        );
        assert_eq!(
            error_code_for_status(StatusCode::UNAUTHORIZED),
            "UNAUTHORIZED"
        );
        assert_eq!(error_code_for_status(StatusCode::FORBIDDEN), "FORBIDDEN");
        assert_eq!(error_code_for_status(StatusCode::NOT_FOUND), "NOT_FOUND");
        assert_eq!(error_code_for_status(StatusCode::CONFLICT), "CONFLICT");
        assert_eq!(error_code_for_status(StatusCode::GONE), "GONE");
        assert_eq!(
            error_code_for_status(StatusCode::TOO_MANY_REQUESTS),
            "RATE_LIMITED"
        );
        assert_eq!(
            error_code_for_status(StatusCode::INTERNAL_SERVER_ERROR),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            error_code_for_status(StatusCode::SERVICE_UNAVAILABLE),
            "TEMPORARY_UNAVAILABLE"
        );
        assert_eq!(
            error_code_for_status(StatusCode::PAYLOAD_TOO_LARGE),
            "CLIENT_ERROR"
        );
        assert_eq!(
            error_code_for_status(StatusCode::BAD_GATEWAY),
            "SERVER_ERROR"
        );
    }

    #[test]
    fn resolves_parameterized_route_patterns() {
        let registry = AnalyticsEndpointRegistry::new(vec![test_spec()]);
        let endpoint = registry
            .resolve_path(&Method::GET, "/v1/wallets/wallet_123")
            .expect("route should match");
        assert_eq!(endpoint.operation_name, "wallet_get");
        assert!(registry
            .resolve_path(&Method::POST, "/v1/wallets/wallet_123")
            .is_none());
        assert!(registry.resolve_path(&Method::GET, "/v1/wallets").is_none());
    }

    #[test]
    fn serializes_started_event_with_required_shape() {
        let state = AnalyticsState::new("passport-gateway", "k3s-z3", vec![test_spec()]);
        let event = build_started_event(&state, &test_spec(), "req_test", "cli");
        let value: Value = serde_json::from_str(&event_json_line(&event)).unwrap();
        assert_eq!(value["record_type"], "analytics_event");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["service"], "passport-gateway");
        assert_eq!(value["environment"], "k3s-z3");
        assert_eq!(value["event_name"], "wallet_get_started");
        assert_eq!(value["outcome"], "started");
        assert_eq!(value["route"], "/v1/wallets/{wallet_id}");
        assert!(value.get("http_status").is_none());
        assert!(value.get("error_code").is_none());
    }

    #[test]
    fn serializes_failed_terminal_event_with_error_code() {
        let state = AnalyticsState::new("passport-gateway", "k3s-z3", vec![test_spec()]);
        let event = build_terminal_event(
            &state,
            &test_spec(),
            "req_test",
            "cli",
            StatusCode::FORBIDDEN,
            42,
            Some("POLICY_DENIED".to_string()),
        );
        let value: Value = serde_json::from_str(&event_json_line(&event)).unwrap();
        assert_eq!(value["event_name"], "wallet_get_failed");
        assert_eq!(value["outcome"], "failed");
        assert_eq!(value["http_status"], 403);
        assert_eq!(value["status_class"], "4xx");
        assert_eq!(value["latency_ms"], 42);
        assert_eq!(value["error_code"], "POLICY_DENIED");
    }

    #[tokio::test]
    async fn middleware_propagates_safe_request_id_header() {
        let state = AnalyticsState::new(
            "test-service",
            "test",
            vec![AnalyticsEndpointSpec::new(
                Method::GET,
                "/ok",
                "ok",
                "test",
                "ok",
                "public",
                "unknown",
            )],
        );
        let app = Router::new().route("/ok", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state, analytics_middleware),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ok")
                    .header(REQUEST_ID_HEADER, "req_from_test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(REQUEST_ID_HEADER).unwrap(),
            "req_from_test"
        );
    }
}
