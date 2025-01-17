use actix_web::{post, web, App, HttpRequest, HttpServer, Responder, HttpResponse};
use actix_web::web::Bytes;
use log::{error, info};

use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::process::Command;

use hmac::{Hmac, Mac};
use sha2::Sha256;

// We define an alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// ----------------------
// CONFIG STRUCTS
// ----------------------
#[derive(Deserialize, Debug)]
struct AppEntry {
    repo_name: String,
    compose_file: String,
    image_tag: String,
}

#[derive(Deserialize, Debug)]
struct AppConfig {
    apps: Vec<AppEntry>,
}

// We'll store the config in a HashMap for quick lookup
struct SharedConfig {
    repo_map: HashMap<String, (String, String)>, // repo_name -> (compose_file, image_tag)
}

// ----------------------
// GITHUB PAYLOAD STRUCT
// ----------------------
#[derive(Deserialize, Debug)]
struct GitHubRepository {
    full_name: String,
}

#[derive(Deserialize, Debug)]
struct GitHubPayload {
    repository: GitHubRepository,
    // Add more fields if needed, e.g. pusher, ref, etc.
}

// ----------------------
// MAIN WEBHOOK HANDLER
// ----------------------
#[post("/webhook")]
async fn handle_webhook(
    req: HttpRequest,
    body: Bytes,
    data: web::Data<AppState>,
) -> impl Responder {
    // Retrieve the shared config and secret
    let secret = &data.secret;
    let shared_config = &data.shared_config;

    // 1) Verify signature
    let signature_header = match req.headers().get("X-Hub-Signature-256") {
        Some(h) => h.to_str().unwrap_or(""),
        None => {
            error!("Missing X-Hub-Signature-256 header");
            return HttpResponse::BadRequest().body("Missing signature header");
        }
    };

    if !verify_hmac(signature_header, &body, secret) {
        error!("HMAC signature mismatch");
        return HttpResponse::Forbidden().body("Invalid HMAC signature");
    }

    // 2) Parse the JSON payload
    let payload: serde_json::Result<GitHubPayload> = serde_json::from_slice(&body);
    let payload = match payload {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse payload: {}", e);
            return HttpResponse::BadRequest().body("Invalid JSON payload");
        }
    };

    let repo_name = &payload.repository.full_name;
    info!("Received event for repository: {}", repo_name);

    // 3) Lookup this repo in the config
    let map = &shared_config.repo_map;
    let (compose_file, image_tag) = match map.get(repo_name) {
        Some((cf, it)) => (cf, it),
        None => {
            // If we don't find the repo, we can ignore or respond with 200
            info!("No config found for repo {}, ignoring", repo_name);
            return HttpResponse::Ok().body("No matching config, ignoring");
        }
    };

    // 4) Run Docker commands
    if let Err(e) = pull_and_compose_up(image_tag, compose_file) {
        error!("Failed to pull/restart container: {}", e);
        return HttpResponse::InternalServerError().body("Docker command failed");
    }

    HttpResponse::Ok().body("Deployment triggered")
}

// ----------------------
// SHARED APP STATE
// ----------------------
struct AppState {
    secret: String,
    shared_config: SharedConfig,
}

impl AppState {
    fn new(secret: String, shared_config: SharedConfig) -> Self {
        AppState {
            secret,
            shared_config,
        }
    }
}

// ----------------------
// VERIFY SIGNATURE
// ----------------------
fn verify_hmac(signature_header: &str, body: &[u8], secret: &str) -> bool {
    // signature_header is "sha256=<hex>"
    let mut parts = signature_header.split('=');
    let algo = parts.next().unwrap_or("");
    let signature_hex = parts.next().unwrap_or("");

    if algo != "sha256" || signature_hex.is_empty() {
        return false;
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(body);

    let local_hmac = mac.finalize().into_bytes();
    let local_hex = hex::encode(local_hmac);

    // Compare in constant time
    openssl_like_memcmp(local_hex.as_bytes(), signature_hex.as_bytes())
}

fn openssl_like_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ----------------------
// DOCKER COMMANDS
// ----------------------
fn pull_and_compose_up(image_tag: &str, compose_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Updating {}", image_tag);
    std::env::set_var("PATH", "/usr/local/bin:/usr/bin:/bin");
    
    let pull_output = Command::new("docker")
        .args(&["pull", image_tag])
        .output()
        .expect("Failed to run docker");

    if !pull_output.status.success() {
        let stderr = String::from_utf8_lossy(&pull_output.stderr);
        return Err(format!("docker pull failed: {}", stderr).into());
    } else {
        info!{"Finished updating {}", image_tag};
    }

    let up_output = Command::new("docker")   // <-- full path here
        .args(&["compose", "-f", compose_file, "up", "-d"])
        .output()?;

    if !up_output.status.success() {
        let stderr = String::from_utf8_lossy(&up_output.stderr);
        return Err(format!("docker compose up failed: {}", stderr).into());
    }

    Ok(())
}

// ----------------------
// MAIN FUNCTION
// ----------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // 1) Load the config from file
    let config_path = "config.json";
    let app_config = load_config(config_path).expect("Failed to load config.json");

    // 2) Build a HashMap from repo_name -> (compose_file, image_tag)
    let mut repo_map = HashMap::new();
    for entry in app_config.apps {
        repo_map.insert(entry.repo_name, (entry.compose_file, entry.image_tag));
    }

    // 3) Get the webhook secret from env
    let secret = env::var("GITHUB_WEBHOOK_SECRET")
        .unwrap_or_else(|_| "changeme".to_string());

    // 4) Create shared state
    let shared_config = SharedConfig { repo_map };
    let state = web::Data::new(AppState::new(secret, shared_config));

    // 5) Start the Actix server
    let bind_address = "0.0.0.0:8443";
    info!("Starting server at {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(handle_webhook)
    })
    .bind(bind_address)?
    .run()
    .await
}

// Helper to read the JSON config
fn load_config(path: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = serde_json::from_str(&content)?;
    Ok(config)
}
