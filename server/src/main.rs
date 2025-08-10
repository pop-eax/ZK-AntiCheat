use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{post, get},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio;

#[derive(Deserialize, Debug)]
struct RequestPayload {
    root: String,
    path: Vec<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    status: String,
    message: String,
    processed_at: String,
    root_hash: String,
    path_count: usize,
}

/// Process the incoming game state payload
/// 
/// # Arguments
/// * `payload` - The game state data to process
/// 
/// # Returns
/// * `SuccessResponse` - Processing result
async fn process_game_state(payload: &RequestPayload) -> SuccessResponse {
    // TODO: Implement actual game state validation logic
    // For now, we'll just log and acknowledge the data
    
    SuccessResponse {
        status: "success".to_string(),
        message: "Game state processed successfully".to_string(),
        processed_at: chrono::Utc::now().to_rfc3339(),
        root_hash: payload.root.clone(),
        path_count: payload.path.len(),
    }
}

async fn handle_post(Json(payload): Json<RequestPayload>) -> Result<ResponseJson<SuccessResponse>, StatusCode> {
    // Log incoming request
    println!("Received game state - Root: {}, Path count: {}", payload.root, payload.path.len());
    
    // Process the payload
    let response = process_game_state(&payload).await;
    
    // Log processing result
    println!("Processed game state successfully - Status: {}", response.status);
    
    Ok(ResponseJson(response))
}

async fn handle_health_check() -> &'static str {
    "OK"
}

#[tokio::main]
async fn main() {
    // Configuration
    let host = "0.0.0.0";
    let port = 9000;
    
    // Build router with routes
    let app = Router::new()
        .route("/", post(handle_post))
        .route("/health", get(handle_health_check));

    // Bind to specified address and port
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap_or_else(|_| {
            eprintln!("Failed to bind to {}:{}", host, port);
            std::process::exit(1);
        });
        
    println!("🚀 Fairfy Server running on http://{}:{}", host, port);
    println!("📊 Health check: http://{}:{}/health", host, port);
    println!("🎮 Game state endpoint: POST http://{}:{}/", host, port);
    
    // Start serving
    axum::serve(listener, app).await.unwrap();
}
