use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use socio::{
    Socio,
    integrations::{Callback, axum::Redirect},
    oauth2::{AuthorizationCode, PkceCodeVerifier},
};
use socio_providers::google::{Google, GoogleUser};
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

pub async fn redirect(State(state): State<AppState>) -> Redirect {
    let authorization_request = socio().authorize().unwrap();

    let redirect = authorization_request.redirect_axum().unwrap();

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
    Query(query): Query<Callback>,
    State(state): State<AppState>,
) -> Json<GoogleUser> {
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
        .exchange_code_for_user(code, pkce_verifier)
        .await
        .unwrap();

    Json(token.user)
}

fn socio() -> Socio<Google> {
    Socio::new(shared::read_config("google"), Google)
}
