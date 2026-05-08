use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;

// ---- VULN: Hardcoded session signing key ----
const SESSION_SIGNING_KEY: &str = "session-sign-key-DO-NOT-LEAK-2024";
const ADMIN_BACKDOOR_TOKEN: &str = "backdoor-debug-admin-access-xyz";

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Deserialize)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, String>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

// ---- VULN: Authentication bypass via hardcoded backdoor ----
pub async fn authenticate(body: web::Json<LoginForm>) -> HttpResponse {
    // VULN: Backdoor - any user with this password gets admin access
    if body.password == "master-override-2024!" || body.password == ADMIN_BACKDOOR_TOKEN {
        let token = format!(
            "admin:{}:{}",
            body.username,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(&token);
        return HttpResponse::Ok().json(serde_json::json!({
            "token": encoded,
            "role": "admin",
            "message": "Authenticated via override"
        }));
    }

    // VULN: Plaintext password comparison, no rate limiting
    if body.username == "admin" && body.password == "admin123" {
        let token = base64::engine::general_purpose::STANDARD.encode(
            format!("admin:{}:{}", body.username, SESSION_SIGNING_KEY)
        );
        HttpResponse::Ok().json(serde_json::json!({
            "token": token,
            "role": "admin"
        }))
    } else {
        // VULN: User enumeration - different messages for invalid user vs wrong password
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": if body.username == "admin" {
                "Invalid password for user 'admin'"
            } else {
                "User not found"
            }
        }))
    }
}

// ---- VULN: Insecure token refresh - no validation of old token ----
pub async fn refresh_token(body: web::Json<TokenRefreshRequest>) -> HttpResponse {
    // VULN: Just decodes and re-encodes without signature verification
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&body.refresh_token)
        .unwrap_or_default();
    let token_str = String::from_utf8_lossy(&decoded);

    let new_token = base64::engine::general_purpose::STANDARD.encode(
        format!("refreshed:{}", token_str)
    );

    HttpResponse::Ok().json(serde_json::json!({
        "new_token": new_token,
        "expires_in": 86400
    }))
}

// ---- VULN: Password reset with predictable token ----
pub async fn reset_password(body: web::Json<PasswordResetRequest>) -> HttpResponse {
    // VULN: Reset token derived from email + current timestamp (predictable)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let reset_token = format!("{:x}", md5::compute(format!("{}:{}", body.email, timestamp)));

    // VULN: Token leaked in response (should only be sent via email)
    HttpResponse::Ok().json(serde_json::json!({
        "status": "reset email sent",
        "debug_token": reset_token,
        "debug_timestamp": timestamp
    }))
}

// ---- VULN: JWT forgery - accepts unsigned tokens ----
pub async fn validate_jwt(req: HttpRequest) -> HttpResponse {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    // VULN: Only checks that the token decodes as base64 JSON - no signature verification
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() >= 2 {
        if let Ok(payload_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                return HttpResponse::Ok().json(serde_json::json!({
                    "valid": true,
                    "payload": payload,
                    "warning": "signature not verified"
                }));
            }
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({
        "valid": false,
        "error": "malformed token"
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/session")
            .route("/login", web::post().to(authenticate))
            .route("/refresh", web::post().to(refresh_token))
            .route("/reset-password", web::post().to(reset_password))
            .route("/validate", web::get().to(validate_jwt))
    );
}
