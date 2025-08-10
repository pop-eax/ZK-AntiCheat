use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use tokio;

#[derive(Deserialize)]
struct RequestPayload {
    root: String,
    path: Vec<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    status: String,
    message: String,
}

async fn handle_post(Json(payload): Json<RequestPayload>) -> Result<ResponseJson<SuccessResponse>, StatusCode> {
    // Process your payload here
    println!("Received: {}", payload.root);
    
    // Return success response
    let response = SuccessResponse {
        status: "success".to_string(),
        message: "Request processed successfully".to_string(),
    };
    
    Ok(ResponseJson(response))
}



async fn main() {
    let app = Router::new()
        .route("/api/endpoint", post(handle_post));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9000")
        .await
        .unwrap();
        
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
