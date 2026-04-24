use actix_web::{web, HttpRequest, HttpResponse, cookie::Cookie};
use base64::Engine as _;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub url: String,
}

#[derive(Deserialize)]
pub struct RegexQuery {
    pub pattern: String,
    pub text: String,
}

#[derive(Deserialize)]
pub struct LogEntry {
    pub user: String,
    pub action: String,
}

#[derive(Deserialize)]
pub struct HeaderQuery {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct SessionRequest {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct ProxyRequest {
    pub target: String,
}

#[derive(Deserialize)]
pub struct CacheRequest {
    pub data: String,
    pub repeat: u32,
}

#[derive(Deserialize)]
pub struct FileWriteRequest {
    pub path: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct SizeQuery {
    pub size: usize,
}

// ---- VULN: Open redirect - no URL validation ----
pub async fn redirect(query: web::Query<RedirectQuery>) -> HttpResponse {
    HttpResponse::Found()
        .insert_header(("Location", query.url.as_str()))
        .finish()
}

// ---- VULN: ReDoS - user-controlled regex pattern ----
pub async fn regex_search(query: web::Query<RegexQuery>) -> HttpResponse {
    match regex::Regex::new(&query.pattern) {
        Ok(re) => {
            let matches: Vec<String> = re
                .find_iter(&query.text)
                .map(|m| m.as_str().to_string())
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "matches": matches,
                "count": matches.len()
            }))
        }
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

// ---- VULN: Log injection / log forging via CRLF in user input ----
pub async fn log_action(body: web::Json<LogEntry>) -> HttpResponse {
    println!(
        "[AUDIT] User: {} performed action: {}",
        body.user, body.action
    );
    HttpResponse::Ok().json(serde_json::json!({"status": "logged"}))
}

// ---- VULN: HTTP response header injection via CRLF ----
pub async fn set_header(query: web::Query<HeaderQuery>) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("X-Custom-Header", query.value.as_str()))
        .body("Header set")
}

// ---- VULN: Insecure session cookie - no Secure/HttpOnly/SameSite, predictable token ----
pub async fn create_session(body: web::Json<SessionRequest>) -> HttpResponse {
    let token = base64::engine::general_purpose::STANDARD.encode(&body.user_id);
    let cookie = Cookie::build("session", token)
        .path("/")
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"status": "session created"}))
}

// ---- VULN: CORS misconfiguration - reflects any origin with credentials ----
pub async fn cors_endpoint(req: HttpRequest) -> HttpResponse {
    let origin = req
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("*");

    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", origin))
        .insert_header(("Access-Control-Allow-Credentials", "true"))
        .insert_header(("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"))
        .insert_header(("Access-Control-Allow-Headers", "*"))
        .json(serde_json::json!({"data": "sensitive_cross_origin_data"}))
}

// ---- VULN: Disabled TLS certificate verification - MITM vulnerable ----
pub async fn proxy_request(body: web::Json<ProxyRequest>) -> HttpResponse {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client.get(&body.target).send().await {
        Ok(resp) => {
            let text = resp.text().await.unwrap_or_default();
            HttpResponse::Ok().body(text)
        }
        Err(e) => HttpResponse::BadGateway().body(e.to_string()),
    }
}

// ---- VULN: TOCTOU race condition on file operations ----
pub async fn safe_write(body: web::Json<FileWriteRequest>) -> HttpResponse {
    let path = std::path::Path::new(&body.path);

    if path.exists() {
        return HttpResponse::Conflict().body("File already exists");
    }
    match std::fs::write(path, &body.content) {
        Ok(_) => HttpResponse::Ok().body("Written"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---- VULN: Unsafe use-after-free via raw pointer ----
pub async fn process_data(body: web::Json<serde_json::Value>) -> HttpResponse {
    let data = body.to_string();
    let result = unsafe {
        let ptr = data.as_ptr();
        let len = data.len();
        drop(data);
        String::from_utf8_unchecked(std::slice::from_raw_parts(ptr, len).to_vec())
    };
    HttpResponse::Ok().body(result)
}

// ---- VULN: Integer overflow in buffer size calculation ----
pub async fn repeat_data(body: web::Json<CacheRequest>) -> HttpResponse {
    let repeat_count = body.repeat as usize;
    let total_len = body.data.len().wrapping_mul(repeat_count);
    let mut result = String::with_capacity(total_len);
    for _ in 0..repeat_count {
        result.push_str(&body.data);
    }
    HttpResponse::Ok().body(result)
}

// ---- VULN: Weak/predictable RNG for security token ----
pub async fn generate_token() -> HttpResponse {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut state = seed;
    let mut token = String::new();
    for _ in 0..16 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        token.push_str(&format!("{:02x}", (state >> 33) as u8));
    }

    HttpResponse::Ok().json(serde_json::json!({"token": token}))
}

// ---- VULN: Uninitialized memory read - leaks heap data ----
pub async fn alloc_buffer(query: web::Query<SizeQuery>) -> HttpResponse {
    let size = query.size.min(4096);
    let result = unsafe {
        let mut buf = Vec::<u8>::with_capacity(size);
        buf.set_len(size);
        base64::engine::general_purpose::STANDARD.encode(&buf)
    };
    HttpResponse::Ok().json(serde_json::json!({"buffer": result}))
}

// ---- VULN: World-writable file permissions on sensitive export ----
pub async fn export_data(body: web::Json<serde_json::Value>) -> HttpResponse {
    let path = "/tmp/export_data.json";
    let content = serde_json::to_string_pretty(&body.into_inner()).unwrap();
    std::fs::write(path, &content).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)).unwrap();
    }

    HttpResponse::Ok().json(serde_json::json!({"exported_to": path}))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/redirect", web::get().to(redirect))
        .route("/regex", web::get().to(regex_search))
        .route("/log", web::post().to(log_action))
        .route("/header", web::get().to(set_header))
        .route("/session", web::post().to(create_session))
        .route("/cors-data", web::get().to(cors_endpoint))
        .route("/proxy", web::post().to(proxy_request))
        .route("/safe-write", web::post().to(safe_write))
        .route("/process", web::post().to(process_data))
        .route("/repeat", web::post().to(repeat_data))
        .route("/token", web::get().to(generate_token))
        .route("/alloc", web::get().to(alloc_buffer))
        .route("/export", web::post().to(export_data));
}
