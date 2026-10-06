//! HTTP API (`/v1`) and the static benchmark site.
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pr_operator::MAX_TX_JSON_BYTES;
use pr_sdk::api::{ApiError, SettleResponse, Submission};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::service::{Batcher, Rejection};

pub const MAX_BENCHMARK_BYTES: usize = 64 << 10;

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let (code, error) = match self {
            Rejection::Invalid(e) => (StatusCode::BAD_REQUEST, e),
            Rejection::Conflict(e) => (StatusCode::CONFLICT, e),
            Rejection::NotFound(e) => (StatusCode::NOT_FOUND, e),
            Rejection::Internal(e) => {
                eprintln!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
            }
        };
        (code, Json(ApiError { error })).into_response()
    }
}

type Shared = State<Arc<Batcher>>;

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Rejection> + Send + 'static,
) -> Result<T, Rejection> {
    tokio::task::spawn_blocking(f).await.map_err(|e| Rejection::Internal(e.into()))?
}

async fn status(State(b): Shared) -> Result<Json<Value>, Rejection> {
    Ok(Json(blocking(move || Ok(b.status()?)).await?))
}

async fn submit(State(b): Shared, Json(sub): Json<Submission>) -> Result<Response, Rejection> {
    let r = blocking(move || b.submit(sub)).await?;
    Ok((StatusCode::ACCEPTED, Json(r)).into_response())
}

#[derive(Deserialize)]
struct From {
    #[serde(default)]
    from: u64,
}

async fn notes(State(b): Shared, Query(q): Query<From>) -> Result<Response, Rejection> {
    Ok(Json(blocking(move || Ok(b.notes(q.from)?)).await?).into_response())
}

async fn merkle_path(State(b): Shared, Path(leaf): Path<u64>) -> Result<Response, Rejection> {
    Ok(Json(blocking(move || b.merkle_path(leaf)).await?).into_response())
}

async fn settle(State(b): Shared) -> Result<Response, Rejection> {
    let batch_number = b.start_settlement()?;
    Ok((StatusCode::ACCEPTED, Json(SettleResponse { batch_number })).into_response())
}

async fn batches(State(b): Shared) -> Response {
    Json(b.reports()).into_response()
}

async fn batch(State(b): Shared, Path(n): Path<u64>) -> Result<Response, Rejection> {
    b.report(n).map(|r| Json(r).into_response()).ok_or(Rejection::NotFound(format!("no batch {n}")))
}

fn benchmarks_path(b: &Batcher) -> PathBuf {
    b.store.dir.join("benchmarks.jsonl")
}

/// Stores one benchmark result posted by the website, with the time and user agent it arrived with.
async fn post_benchmark(State(b): Shared, headers: HeaderMap, Json(mut v): Json<Value>) -> Result<Response, Rejection> {
    if !v.is_object() {
        return Err(Rejection::Invalid("a benchmark result is a JSON object".into()));
    }
    v["received_unix"] =
        json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    v["received_user_agent"] = json!(headers.get("user-agent").and_then(|h| h.to_str().ok()).unwrap_or(""));
    let path = benchmarks_path(&b);
    blocking(move || {
        let mut f = OpenOptions::new().create(true).append(true).open(path).map_err(anyhow::Error::from)?;
        writeln!(f, "{v}").map_err(anyhow::Error::from)?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::CREATED.into_response())
}

async fn get_benchmarks(State(b): Shared) -> Result<Response, Rejection> {
    let path = benchmarks_path(&b);
    let rows = blocking(move || {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Ok(text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect::<Vec<_>>())
    })
    .await?;
    Ok(Json(rows).into_response())
}

pub fn router(b: Arc<Batcher>, web: Option<PathBuf>) -> Router {
    let api = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/transactions", post(submit).layer(DefaultBodyLimit::max(MAX_TX_JSON_BYTES as usize)))
        .route("/v1/notes", get(notes))
        .route("/v1/paths/{leaf}", get(merkle_path))
        .route("/v1/batches", post(settle).get(batches))
        .route("/v1/batches/{n}", get(batch))
        .route(
            "/v1/benchmarks",
            post(post_benchmark).get(get_benchmarks).layer(DefaultBodyLimit::max(MAX_BENCHMARK_BYTES)),
        )
        .with_state(b);
    match web {
        Some(dir) => api.fallback_service(tower_http::services::ServeDir::new(dir)),
        None => api,
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use pr_operator::Store;
    use pr_protocol_types::{Outpoint, RollupDescriptor};
    use tower::ServiceExt;

    use super::*;
    use crate::rpc::Rpc;
    use crate::service::{Broadcast, Config};

    fn batcher(name: &str) -> Arc<Batcher> {
        let dir = std::env::temp_dir().join(format!("pr-batcher-http-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        store
            .init(&RollupDescriptor {
                protocol_version: 1,
                genesis_nonce: Outpoint { txid: [7; 32], vout: 0 },
                image_id: [0; 32],
                internal_key: [2; 32],
                seed_sats: 10_000,
            })
            .unwrap();
        store.genesis(&hex::encode([9; 32]), 0).unwrap();
        Batcher::open(&dir, Config::from_env(Broadcast::Send), Rpc::new("http://127.0.0.1:0", "", "").unwrap()).unwrap()
    }

    async fn call(app: &Router, method: &str, uri: &str, body: Vec<u8>) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn status_reports_the_genesis_state() {
        let app = router(batcher("status"), None);
        let (code, v) = call(&app, "GET", "/v1/status", Vec::new()).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["batch_number"], 0);
        assert_eq!(v["pending"], 0);
        assert_eq!(v["settling"], false);
    }

    #[tokio::test]
    async fn malformed_and_oversized_submissions_are_rejected() {
        let app = router(batcher("submit"), None);
        let not_hex = json!({"transaction": "zz", "funding": []}).to_string().into_bytes();
        assert_eq!(call(&app, "POST", "/v1/transactions", not_hex).await.0, StatusCode::BAD_REQUEST);
        let truncated = json!({"transaction": "00", "funding": []}).to_string().into_bytes();
        assert_eq!(call(&app, "POST", "/v1/transactions", truncated).await.0, StatusCode::BAD_REQUEST);
        let not_json = b"{".to_vec();
        assert!(call(&app, "POST", "/v1/transactions", not_json).await.0.is_client_error());
        let mut big = b"{\"transaction\": \"".to_vec();
        big.resize(MAX_TX_JSON_BYTES as usize + 1, b'0');
        assert_eq!(call(&app, "POST", "/v1/transactions", big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn empty_pool_is_not_settled_and_unknown_resources_are_404() {
        let app = router(batcher("settle"), None);
        assert_eq!(call(&app, "POST", "/v1/batches", Vec::new()).await.0, StatusCode::CONFLICT);
        assert_eq!(call(&app, "GET", "/v1/batches/1", Vec::new()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, "GET", "/v1/paths/0", Vec::new()).await.0, StatusCode::NOT_FOUND);
        let (code, v) = call(&app, "GET", "/v1/batches", Vec::new()).await;
        assert_eq!((code, v), (StatusCode::OK, json!([])));
    }

    #[tokio::test]
    async fn benchmarks_are_stored_and_bounded() {
        let app = router(batcher("bench"), None);
        let result = json!({"mode": "profile", "ok": true}).to_string().into_bytes();
        assert_eq!(call(&app, "POST", "/v1/benchmarks", result).await.0, StatusCode::CREATED);
        assert_eq!(call(&app, "POST", "/v1/benchmarks", b"[1]".to_vec()).await.0, StatusCode::BAD_REQUEST);
        let mut big = b"{\"pad\": \"".to_vec();
        big.resize(MAX_BENCHMARK_BYTES + 1, b'a');
        assert_eq!(call(&app, "POST", "/v1/benchmarks", big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
        let (code, v) = call(&app, "GET", "/v1/benchmarks", Vec::new()).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["mode"], "profile");
    }
}
