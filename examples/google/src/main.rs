use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use socio::{
    integrations::{SocioCallback, SocioRedirect},
    oauth2::{AuthorizationCode, PkceCodeVerifier},
    Socio,
};
use socio_providers::google::{Google, GoogleClaims};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default)]
pub struct AppState {
    requests: Arc<Mutex<HashMap<String, String>>>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::default();

    let app = Router::new()
        .route("/redirect", get(redirect))
        .route("/callback", get(callback))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn redirect(State(state): State<AppState>) -> SocioRedirect {
    let authorization_request = socio().authorize().unwrap();

    let redirect = authorization_request.redirect().unwrap();

    {
        let mut requests = state.requests.lock().expect("lock poisoned");
        requests.insert(
            authorization_request.csrf_token.into_secret(),
            authorization_request.pkce_verifier.into_secret(),
        );
    }

    redirect
}

#[axum::debug_handler]
pub async fn callback(
    Query(query): Query<SocioCallback>,
    State(state): State<AppState>,
) -> Json<GoogleClaims> {
    let pkce_verifier = {
        let requests = state.requests.lock().expect("lock poisoned");

        let pkce_verifier = requests
            .get(&query.state)
            .expect("No matching CSRF Token found")
            .to_string();

        PkceCodeVerifier::new(pkce_verifier)
    };

    let code = AuthorizationCode::new(query.code);

    let token = socio()
        .exchange_and_claims(code, pkce_verifier)
        .await
        .unwrap();

    Json(token.claims)
}

fn socio() -> Socio<Google> {
    Socio::new(shared::read_config("google"), Google)
}
