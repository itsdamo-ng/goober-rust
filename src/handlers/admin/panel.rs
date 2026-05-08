use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use std::process::Command;

// ---- VULN: Hardcoded admin credentials ----
const ADMIN_USERNAME: &str = "superadmin";
const ADMIN_PASSWORD: &str = "Admin$ecret2024!";
const PANEL_API_KEY: &str = "pk_live_admin_51HG8dKL2k3j4h5g6f7d8s9a0";

#[derive(Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UserDeleteRequest {
    pub user_id: String,
    pub confirm: Option<bool>,
}

#[derive(Deserialize)]
pub struct ConfigUpdateRequest {
    pub key: String,
    pub value: String,
}

// ---- VULN: No authentication check on admin panel ----
pub async fn admin_dashboard(req: HttpRequest) -> HttpResponse {
    // VULN: Only checks for header presence, not validity
    let _has_auth = req.headers().get("Authorization").is_some();

    let html = format!(
        "<html><body>\
        <h1>Admin Panel</h1>\
        <p>API Key: {}</p>\
        <p>Admin: {}:{}</p>\
        <form action='/admin/exec' method='post'>\
        <input name='command' placeholder='command'>\
        <button>Execute</button>\
        </form>\
        </body></html>",
        PANEL_API_KEY, ADMIN_USERNAME, ADMIN_PASSWORD
    );

    HttpResponse::Ok().content_type("text/html").body(html)
}

// ---- VULN: Remote code execution - arbitrary command execution ----
pub async fn exec_command(body: web::Json<ExecRequest>) -> HttpResponse {
    // VULN: Direct execution of user-supplied commands with no auth
    let output = if let Some(args) = &body.args {
        Command::new(&body.command).args(args).output()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(&body.command)
            .output()
    };

    match output {
        Ok(result) => HttpResponse::Ok().json(serde_json::json!({
            "stdout": String::from_utf8_lossy(&result.stdout),
            "stderr": String::from_utf8_lossy(&result.stderr),
            "exit_code": result.status.code()
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: IDOR - no ownership check, user can delete any account ----
pub async fn delete_user(body: web::Json<UserDeleteRequest>) -> HttpResponse {
    // VULN: No authentication, no authorization check
    // Any user can delete any other user by ID
    HttpResponse::Ok().json(serde_json::json!({
        "status": "deleted",
        "user_id": body.user_id,
        "message": format!("User {} has been permanently deleted", body.user_id)
    }))
}

// ---- VULN: Arbitrary config write with path traversal ----
pub async fn update_config(body: web::Json<ConfigUpdateRequest>) -> HttpResponse {
    // VULN: User controls key and value written to filesystem
    let config_path = format!("/etc/app/config/{}.conf", body.key);

    match std::fs::write(&config_path, &body.value) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "updated",
            "path": config_path
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: Server-side template injection ----
pub async fn render_template(body: web::Json<serde_json::Value>) -> HttpResponse {
    let template = body.get("template").and_then(|v| v.as_str()).unwrap_or("");
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("user");

    // VULN: User-controlled template string with naive replacement - allows injection
    let rendered = template
        .replace("{{name}}", name)
        .replace("{{secret}}", ADMIN_PASSWORD)
        .replace("{{api_key}}", PANEL_API_KEY);

    HttpResponse::Ok().json(serde_json::json!({
        "rendered": rendered
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/dashboard", web::get().to(admin_dashboard))
            .route("/exec", web::post().to(exec_command))
            .route("/delete-user", web::post().to(delete_user))
            .route("/config", web::post().to(update_config))
            .route("/render", web::post().to(render_template))
    );
}
