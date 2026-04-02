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
pub struct OwnerSessionResponse {
    pub access_token: String,
    pub owner_id: String,
    pub owner_session_id: String,
    pub auth_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySignUpStartRequest {
    pub owner_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySignInStartRequest {
    pub owner_name: String,
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
    pub owner_id: String,
    pub owner_session_id: String,
}
