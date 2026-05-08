use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::process::Command;

// ---- VULN: Hardcoded private key material ----
const RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2a2rwplBQLfBHpB9GKXN5RVVpT5FgkmITh3GBHFMGP2dTjFa
xYJcJUDi3p7S7MJ/SdfN0btktRhXJT5YObvQK3HJfFpL0RvTqZNm3OSu9BJQOAT
0tTrWD+OjFQZNdW34WbfJYFJfLRPxCLf9tRl6jDE2V3GD0fZ5kM+hNoHq/T3DLGR
-----END RSA PRIVATE KEY-----";

const HMAC_SECRET: &str = "super-secret-hmac-key-never-share-2024";

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,
    pub key_override: Option<String>,
}

#[derive(Deserialize)]
pub struct HashRequest {
    pub data: String,
    pub algorithm: String,
}

#[derive(Deserialize)]
pub struct KeygenRequest {
    pub length: u32,
}

// ---- VULN: ECB mode encryption, user-supplied key without validation ----
pub async fn encrypt(body: web::Json<EncryptRequest>) -> HttpResponse {
    let key = body.key_override.as_deref().unwrap_or("0000000000000000");

    // VULN: Using ECB mode (each block encrypted independently = pattern leakage)
    let mut encrypted = Vec::new();
    let key_bytes = key.as_bytes();
    for chunk in body.plaintext.as_bytes().chunks(16) {
        let mut block = [0u8; 16];
        for (i, &b) in chunk.iter().enumerate() {
            block[i] = b ^ key_bytes[i % key_bytes.len()];
        }
        encrypted.extend_from_slice(&block);
    }

    let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    HttpResponse::Ok().json(serde_json::json!({
        "ciphertext": encoded,
        "algorithm": "xor-ecb",
        "key_used": key
    }))
}

// ---- VULN: Command injection via algorithm parameter ----
pub async fn hash_data(body: web::Json<HashRequest>) -> HttpResponse {
    // VULN: Unsanitized algorithm string passed to shell command
    let cmd = format!(
        "echo -n '{}' | openssl dgst -{}",
        body.data, body.algorithm
    );

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match output {
        Ok(result) => {
            let hash = String::from_utf8_lossy(&result.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "hash": hash.trim(),
                "algorithm": body.algorithm
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: Weak key generation using predictable seed ----
pub async fn generate_key(body: web::Json<KeygenRequest>) -> HttpResponse {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // VULN: LCG PRNG for key material — trivially predictable
    let mut state = seed;
    let mut key_bytes = Vec::with_capacity(body.length as usize);
    for _ in 0..body.length {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        key_bytes.push((state >> 33) as u8);
    }

    let key_hex: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "key": key_hex,
        "length_bits": body.length * 8,
        "hmac_verification": format!("{:x}", md5::compute(format!("{}{}", key_hex, HMAC_SECRET)))
    }))
}

// ---- VULN: Timing side-channel in token comparison ----
pub async fn verify_token(body: web::Json<serde_json::Value>) -> HttpResponse {
    let provided = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let expected = "admin-token-2024-xyz789";

    // VULN: Byte-by-byte comparison leaks token length via timing
    let mut valid = provided.len() == expected.len();
    if valid {
        for (a, b) in provided.bytes().zip(expected.bytes()) {
            if a != b {
                valid = false;
                break;
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "valid": valid,
        "token_length_hint": expected.len()
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/crypto")
            .route("/encrypt", web::post().to(encrypt))
            .route("/hash", web::post().to(hash_data))
            .route("/keygen", web::post().to(generate_key))
            .route("/verify", web::post().to(verify_token))
    );
}
