mod dontscope;

use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use rusqlite::Connection;
use std::process::Command;
use std::sync::Mutex;

// ---- VULN: Hardcoded credentials ----
const DB_ADMIN_USER: &str = "admin";
const DB_ADMIN_PASS: &str = "SuperSecret123!";
const API_KEY: &str = "sk-live-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d";
const JWT_SECRET: &str = "changeme";
const AWS_ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const ENCRYPTION_KEY: &str = "aes-256-key-do-not-share-1234567";
const INTERNAL_SERVICE_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

struct AppState {
    db: Mutex<Connection>,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Deserialize)]
struct PingRequest {
    host: String,
}

#[derive(Deserialize)]
struct FileRequest {
    path: String,
}

#[derive(Deserialize)]
struct TemplateRequest {
    name: String,
    content: String,
}

#[derive(Serialize)]
struct ApiResponse {
    status: String,
    message: String,
    data: Option<String>,
}

fn init_db(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (1, 'admin', 'admin123', 'admin');
        INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (2, 'guest', 'guest', 'user');

        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            key TEXT NOT NULL,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO secrets (id, key, value)
        VALUES (1, 'database_url', 'postgres://prod_admin:Pr0dP@ss!@db.internal:5432/maindb');
        INSERT OR IGNORE INTO secrets (id, key, value)
        VALUES (2, 'stripe_key', 'sk_live_abc123def456ghi789');
        "
    ).expect("Failed to initialize database");
}

// ---- VULN: SQL injection via string interpolation ----
async fn login(
    data: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    let db = data.db.lock().unwrap();

    // VULN: Password stored/compared as plaintext, SQL injection
    let query = format!(
        "SELECT id, username, role FROM users WHERE username = '{}' AND password = '{}'",
        body.username, body.password
    );

    match db.query_row(&query, [], |row| {
        Ok((
            row.get::<_, i64>(0).unwrap(),
            row.get::<_, String>(1).unwrap(),
            row.get::<_, String>(2).unwrap(),
        ))
    }) {
        Ok((id, username, role)) => {
            // VULN: Using MD5 for token generation
            let token = format!("{:x}", md5::compute(format!("{}:{}:{}", id, username, JWT_SECRET)));
            HttpResponse::Ok().json(ApiResponse {
                status: "success".into(),
                message: format!("Welcome {}!", username),
                data: Some(format!("token={}&role={}", token, role)),
            })
        }
        Err(_) => HttpResponse::Unauthorized().json(ApiResponse {
            status: "error".into(),
            message: "Invalid credentials".into(),
            data: None,
        }),
    }
}

// ---- VULN: SQL injection in search ----
async fn search_users(
    data: web::Data<AppState>,
    query: web::Query<SearchQuery>,
) -> HttpResponse {
    let db = data.db.lock().unwrap();

    // VULN: Direct string interpolation into SQL
    let sql = format!("SELECT username, role FROM users WHERE username LIKE '%{}%'", query.q);

    let mut stmt = db.prepare(&sql).unwrap();
    let results: Vec<String> = stmt
        .query_map([], |row| {
            Ok(format!(
                "{}:{}",
                row.get::<_, String>(0).unwrap(),
                row.get::<_, String>(1).unwrap()
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    HttpResponse::Ok().json(ApiResponse {
        status: "success".into(),
        message: format!("Found {} users", results.len()),
        data: Some(results.join(", ")),
    })
}

// ---- VULN: Command injection ----
async fn ping(body: web::Json<PingRequest>) -> HttpResponse {
    // VULN: Unsanitized user input passed directly to shell
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 {}", body.host))
        .output();

    match output {
        Ok(result) => HttpResponse::Ok().json(ApiResponse {
            status: "success".into(),
            message: String::from_utf8_lossy(&result.stdout).to_string(),
            data: Some(String::from_utf8_lossy(&result.stderr).to_string()),
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            status: "error".into(),
            message: e.to_string(),
            data: None,
        }),
    }
}

// ---- VULN: Path traversal ----
async fn read_file(query: web::Query<FileRequest>) -> HttpResponse {
    // VULN: No path validation — allows ../../etc/passwd
    match std::fs::read_to_string(&query.path) {
        Ok(contents) => HttpResponse::Ok().json(ApiResponse {
            status: "success".into(),
            message: "File read successfully".into(),
            data: Some(contents),
        }),
        Err(e) => HttpResponse::NotFound().json(ApiResponse {
            status: "error".into(),
            message: e.to_string(),
            data: None,
        }),
    }
}

// ---- VULN: XSS via reflected content ----
async fn greet(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("World");
    // VULN: Unsanitized user input reflected in HTML
    let html = format!(
        "<html><body><h1>Hello, {}!</h1><p>Welcome to Goober.</p></body></html>",
        name
    );
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}

// ---- VULN: Arbitrary file write ----
async fn save_template(body: web::Json<TemplateRequest>) -> HttpResponse {
    // VULN: User controls filename and content — arbitrary write
    let path = format!("/tmp/templates/{}", body.name);
    match std::fs::write(&path, &body.content) {
        Ok(_) => HttpResponse::Ok().json(ApiResponse {
            status: "success".into(),
            message: format!("Template saved to {}", path),
            data: None,
        }),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse {
            status: "error".into(),
            message: e.to_string(),
            data: None,
        }),
    }
}

// ---- VULN: SSRF ----
async fn fetch_url(query: web::Query<FileRequest>) -> HttpResponse {
    // VULN: No URL validation — can reach internal services, cloud metadata, etc.
    match reqwest::get(&query.path).await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            HttpResponse::Ok().json(ApiResponse {
                status: "success".into(),
                message: "Fetched successfully".into(),
                data: Some(body),
            })
        }
        Err(e) => HttpResponse::BadRequest().json(ApiResponse {
            status: "error".into(),
            message: e.to_string(),
            data: None,
        }),
    }
}

// ---- VULN: Debug endpoint exposing secrets ----
async fn debug_info(data: web::Data<AppState>) -> HttpResponse {
    let db = data.db.lock().unwrap();

    let mut secrets = Vec::new();
    let mut stmt = db.prepare("SELECT key, value FROM secrets").unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok(format!(
                "{}: {}",
                row.get::<_, String>(0).unwrap(),
                row.get::<_, String>(1).unwrap()
            ))
        })
        .unwrap();
    for row in rows {
        secrets.push(row.unwrap());
    }

    // VULN: Exposes all hardcoded creds and DB secrets with no auth
    let debug = format!(
        "=== DEBUG INFO ===\n\
         API_KEY: {}\n\
         JWT_SECRET: {}\n\
         AWS_ACCESS_KEY_ID: {}\n\
         AWS_SECRET_ACCESS_KEY: {}\n\
         ENCRYPTION_KEY: {}\n\
         DB_ADMIN: {}:{}\n\
         SERVICE_TOKEN: {}\n\
         \n=== DB SECRETS ===\n{}",
        API_KEY,
        JWT_SECRET,
        AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY,
        ENCRYPTION_KEY,
        DB_ADMIN_USER,
        DB_ADMIN_PASS,
        INTERNAL_SERVICE_TOKEN,
        secrets.join("\n"),
    );

    HttpResponse::Ok()
        .content_type("text/plain")
        .body(debug)
}

// ---- VULN: Insecure deserialization / mass assignment ----
async fn update_user(
    data: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let db = data.db.lock().unwrap();

    // VULN: Accepts arbitrary fields — user can set role=admin
    if let (Some(username), Some(role)) = (
        body.get("username").and_then(|v| v.as_str()),
        body.get("role").and_then(|v| v.as_str()),
    ) {
        let sql = format!(
            "UPDATE users SET role = '{}' WHERE username = '{}'",
            role, username
        );
        db.execute(&sql, []).unwrap();
        HttpResponse::Ok().json(ApiResponse {
            status: "success".into(),
            message: "User updated".into(),
            data: None,
        })
    } else {
        HttpResponse::BadRequest().json(ApiResponse {
            status: "error".into(),
            message: "Missing fields".into(),
            data: None,
        })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // VULN: Using in-memory DB with hardcoded seed data
    let conn = Connection::open_in_memory().expect("Failed to open database");
    init_db(&conn);

    let data = web::Data::new(AppState {
        db: Mutex::new(conn),
    });

    println!("Starting Goober server on 0.0.0.0:8080");
    println!("Debug endpoint: http://0.0.0.0:8080/debug");

    // VULN: Binding to 0.0.0.0 exposes to all interfaces
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/login", web::post().to(login))
            .route("/search", web::get().to(search_users))
            .route("/ping", web::post().to(ping))
            .route("/file", web::get().to(read_file))
            .route("/greet/{name}", web::get().to(greet))
            .route("/template", web::post().to(save_template))
            .route("/fetch", web::get().to(fetch_url))
            .route("/debug", web::get().to(debug_info))
            .route("/user/update", web::post().to(update_user))
            .configure(dontscope::configure)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
