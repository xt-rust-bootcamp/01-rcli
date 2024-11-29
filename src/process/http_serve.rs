use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> Response {
    let p = std::path::Path::new(&state.path).join(&path);
    info!("Reading file {:?}", p);

    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} not found", p.display()),
        )
            .into_response()
    } else {
        let metadata = std::fs::metadata(&p).context("Fail to read metadata");
        if let Err(e) = metadata {
            return (
                StatusCode::NOT_FOUND,
                format!("{} {} {}", "File not found", "Error info:", e),
            )
                .into_response();
        }
        let metadata = metadata.unwrap();

        if metadata.is_dir() {
            let mut html = String::from(
                r#"<!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Directory Listing</title>
                    </head>
                    <body>
                        <ul>"#,
            );
            let entries = std::fs::read_dir(&p);

            if let Err(e) = entries {
                warn!("Error reading file: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!("<h1>Error reading file: {}</h1>", e)),
                )
                    .into_response();
            }
            let entries = entries.unwrap();

            for entry in entries.into_iter().flatten() {
                let entry_path = entry.path();
                let file_name = entry_path.file_name().unwrap().to_string_lossy();

                html.push_str(&format!(
                    r#"<li><a href="{}">{}</a></li>"#,
                    file_name, file_name
                ));
            }
            html.push_str(
                r#"</ul>
                    </body>
                    </html>"#,
            );
            (StatusCode::OK, Html(html)).into_response()
        } else {
            match tokio::fs::read_to_string(p).await {
                Ok(content) => {
                    info!("Read {} bytes", content.len());
                    (StatusCode::OK, content).into_response()
                }
                Err(e) => {
                    warn!("Error reading file: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("<h1>Error reading file: {}</h1>", e),
                    )
                        .into_response()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let response = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        let status = response.status();
        let body_bytes = match to_bytes(response.into_body(), 1024).await {
            Ok(bytes) => bytes,
            Err(_) => panic!("Failed to read response body"),
        };
        // 转换字节数组为字符串
        let content = String::from_utf8_lossy(&body_bytes).to_string();

        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package"));
    }
}
