use core::hash;
use std::{future::Future, hash::Hash};

use crate::{
    error::PlaygroundError,
    poly::{test_sponge, Poly},
};
use ark_crypto_primitives::collect_sponge_bytes;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, MontBackend, PrimeField, UniformRand};
use ark_poly_commit::data_structures;
use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, FrConfig};
// use salvo::conn::{rustls::{Keycert, RustlsConfig}, native_tls::listener};
// use salvo::prelude::*;
use sha3::{Digest, Sha3_256};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{field, trace};

use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, Path, State},
    handler::Handler,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put, Route},
    Router,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    compression::CompressionLayer, limit::RequestBodyLimitLayer, trace::TraceLayer,
    validate_request::ValidateRequestHeaderLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn initialize_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "playground=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

type SharedState<T> = Arc<RwLock<AppState<T>>>;


pub struct AppState<T>{
    db: HashMap<String, Bytes>,
    data: T
}

impl Default for AppState<Vec<u8>>{
    fn default() -> Self {
        Self {
            db: HashMap::new(),
            data: Vec::new()
        }
    }
}

pub async fn playground_put_handler<T>(
    Path(key): Path<String>,
    State(state): State<SharedState<T>>,
    bytes: Bytes
) -> Result<impl IntoResponse, PlaygroundError> {
    let db = &mut state
        .write()
        .map_err(|e| PlaygroundError::InternalError(e.to_string()))?
        .db;

    db.insert(key, bytes.clone());

    Ok((StatusCode::CREATED, bytes))
}

pub async fn playground_post_handler<T>(
    Path(key): Path<String>,
    State(state): State<SharedState<T>>,
) -> Result<impl IntoResponse, PlaygroundError> {
    let db = &state
        .write()
        .map_err(|e| PlaygroundError::InternalError(e.to_string()))?
        .db;

    if let Some(value) = db.get(&key) {
        Ok(value.clone())
    } else {
        Err(StatusCode::NOT_FOUND.into())
    }
}

pub async fn playground_get_handler<T>(
    Path(key): Path<String>,
    State(state): State<SharedState<T>>,
) -> Result<impl IntoResponse, PlaygroundError> {
    let db = &state
        .read()
        .map_err(|e| PlaygroundError::InternalError(e.to_string()))?
        .db;

    let bytes = db
        .get(key.as_str())
        .ok_or(PlaygroundError::InternalError("key not found".to_string()))?;

    Ok((StatusCode::OK, bytes.clone()))
}

pub fn get_router() -> Router {
    let shared_state = SharedState::default();

    Router::new()
        .route("/", get(|| async { "Welcome to the playground!"}))
        .route(
            "/:key",
            // Add compression to `kv_get`
            get(playground_get_handler.layer(CompressionLayer::new()))
                // But don't compress `kv_set`
                .post_service(
                    playground_post_handler
                        .layer((RequestBodyLimitLayer::new(1024 * 5_000 /* ~5mb */),))
                        .with_state(Arc::clone(&shared_state)),
                )
                .put_service(
                    playground_put_handler
                        .layer((
                            DefaultBodyLimit::disable(),
                            RequestBodyLimitLayer::new(1024 * 5_000 /* ~5mb */),
                        ))
                        .with_state(Arc::clone(&shared_state)),
                ),
        )
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http()),
        )
        .with_state(Arc::clone(&shared_state))
}

pub async fn run_server(addr: &str) -> Result<(), PlaygroundError> {
    let router = get_router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::debug!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router).await?;
    Ok(())
}



async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {error}")),
    )
}

#[allow(unused)]
async fn playground() -> Result<(), PlaygroundError> {
    run_server("127.0.0.1:9999").await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::error::PlaygroundError;

    use super::*;

    #[tokio::test]
    async fn test_playground() -> Result<(), PlaygroundError> {
        playground().await?;
        Ok(())
    }
}
