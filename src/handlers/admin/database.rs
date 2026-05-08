use actix_web::{web, HttpResponse};
use serde::Deserialize;
use std::process::Command;

// ---- VULN: Hardcoded database credentials for multiple environments ----
const PROD_DB_URL: &str = "postgres://prod_root:R00tP@ss!2024@db-prod.internal:5432/maindb";
const STAGING_DB_URL: &str = "postgres://staging_admin:St@ging123@db-staging.internal:5432/stagingdb";
const REDIS_URL: &str = "redis://:redis-secret-password@cache.internal:6379/0";

#[derive(Deserialize)]
pub struct QueryRequest {
    pub sql: String,
    pub database: Option<String>,
}

#[derive(Deserialize)]
pub struct BackupRequest {
    pub destination: String,
    pub include_secrets: Option<bool>,
}

#[derive(Deserialize)]
pub struct MigrationRequest {
    pub sql_file_path: String,
}

// ---- VULN: SQL injection via raw query execution ----
pub async fn execute_query(body: web::Json<QueryRequest>) -> HttpResponse {
    let db_url = match body.database.as_deref() {
        Some("staging") => STAGING_DB_URL,
        Some("prod") => PROD_DB_URL,
        _ => PROD_DB_URL,
    };

    // VULN: Passes user SQL directly to psql command — injection + command injection
    let output = Command::new("psql")
        .arg(db_url)
        .arg("-c")
        .arg(&body.sql)
        .output();

    match output {
        Ok(result) => HttpResponse::Ok().json(serde_json::json!({
            "output": String::from_utf8_lossy(&result.stdout),
            "error": String::from_utf8_lossy(&result.stderr),
            "db": db_url
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: Command injection in backup path ----
pub async fn create_backup(body: web::Json<BackupRequest>) -> HttpResponse {
    // VULN: User-controlled destination path injected into shell command
    let cmd = format!(
        "pg_dump {} | gzip > {}/backup_$(date +%s).sql.gz",
        PROD_DB_URL, body.destination
    );

    let output = Command::new("sh").arg("-c").arg(&cmd).output();

    match output {
        Ok(result) => {
            let mut response = serde_json::json!({
                "status": "backup created",
                "destination": body.destination,
                "stdout": String::from_utf8_lossy(&result.stdout)
            });

            // VULN: Optionally dumps all credentials into the response
            if body.include_secrets.unwrap_or(false) {
                response["credentials"] = serde_json::json!({
                    "prod_db": PROD_DB_URL,
                    "staging_db": STAGING_DB_URL,
                    "redis": REDIS_URL,
                });
            }

            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: Arbitrary file read via path traversal in migration ----
pub async fn run_migration(body: web::Json<MigrationRequest>) -> HttpResponse {
    // VULN: No path validation — can read any file on the system
    let sql_content = match std::fs::read_to_string(&body.sql_file_path) {
        Ok(content) => content,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to read migration file: {}", e)
            }));
        }
    };

    // VULN: Executes whatever was in the file as SQL
    let output = Command::new("psql")
        .arg(PROD_DB_URL)
        .arg("-c")
        .arg(&sql_content)
        .output();

    match output {
        Ok(result) => HttpResponse::Ok().json(serde_json::json!({
            "status": "migration executed",
            "file": body.sql_file_path,
            "sql_preview": &sql_content[..sql_content.len().min(200)],
            "output": String::from_utf8_lossy(&result.stdout)
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ---- VULN: Information disclosure - exposes all connection strings ----
pub async fn connection_info() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "connections": {
            "production": PROD_DB_URL,
            "staging": STAGING_DB_URL,
            "redis": REDIS_URL,
        },
        "status": "all connections active"
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/db")
            .route("/query", web::post().to(execute_query))
            .route("/backup", web::post().to(create_backup))
            .route("/migrate", web::post().to(run_migration))
            .route("/connections", web::get().to(connection_info))
    );
}
