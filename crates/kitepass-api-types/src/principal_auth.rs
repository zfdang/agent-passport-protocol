use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceCodeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i32,
    pub interval: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthPollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPollResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalSessionResponse {
    pub access_token: String,
    pub principal_account_id: String,
    pub principal_session_id: String,
    pub auth_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySignUpStartRequest {
    pub principal_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySignInStartRequest {
    pub principal_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCeremonyResponse {
    pub flow_id: String,
    pub public_key: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyFinishRequest {
    pub flow_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveDeviceCodeRequest {
    pub user_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveDeviceCodeResponse {
    pub status: String,
    pub device_code: String,
    pub user_code: String,
    pub principal_account_id: String,
    pub principal_session_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_code_request_roundtrip() {
        let req = DeviceCodeRequest {
            code_challenge: Some("challenge-abc".into()),
            code_challenge_method: Some("S256".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: DeviceCodeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.code_challenge, Some("challenge-abc".into()));
        assert_eq!(decoded.code_challenge_method, Some("S256".into()));
    }

    #[test]
    fn device_code_request_default_roundtrip() {
        let req = DeviceCodeRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let decoded: DeviceCodeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.code_challenge, None);
        assert_eq!(decoded.code_challenge_method, None);
    }

    #[test]
    fn device_code_response_roundtrip() {
        let resp = DeviceCodeResponse {
            device_code: "dc-001".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: "https://example.com/verify".into(),
            expires_in: 300,
            interval: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: DeviceCodeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.device_code, "dc-001");
        assert_eq!(decoded.user_code, "ABCD-1234");
        assert_eq!(decoded.expires_in, 300);
        assert_eq!(decoded.interval, 5);
    }

    #[test]
    fn auth_poll_request_roundtrip() {
        let req = AuthPollRequest {
            code_verifier: Some("verifier-xyz".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: AuthPollRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.code_verifier, Some("verifier-xyz".into()));
    }

    #[test]
    fn auth_poll_response_roundtrip() {
        let resp = AuthPollResponse {
            access_token: Some("tok-abc".into()),
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: AuthPollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.access_token, Some("tok-abc".into()));
        assert_eq!(decoded.error, None);

        let error_resp = AuthPollResponse {
            access_token: None,
            error: Some("authorization_pending".into()),
        };
        let json = serde_json::to_string(&error_resp).unwrap();
        let decoded: AuthPollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.access_token, None);
        assert_eq!(decoded.error, Some("authorization_pending".into()));
    }

    #[test]
    fn principal_session_response_roundtrip() {
        let resp = PrincipalSessionResponse {
            access_token: "tok-session".into(),
            principal_account_id: "pa-001".into(),
            principal_session_id: "ps-001".into(),
            auth_method: "passkey".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: PrincipalSessionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.access_token, "tok-session");
        assert_eq!(decoded.principal_account_id, "pa-001");
        assert_eq!(decoded.principal_session_id, "ps-001");
        assert_eq!(decoded.auth_method, "passkey");
    }
}
