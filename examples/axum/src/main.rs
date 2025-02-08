use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Router,
};
use socio::{
    integrations::{AxumRedirect, SocioCallback},
    oauth2::{AuthorizationCode, EmptyExtraTokenFields, PkceCodeVerifier},
    Socio,
};
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

pub async fn redirect(State(state): State<AppState>) -> AxumRedirect {
    let authorization_request = socio().authorize().unwrap();

    let redirect = authorization_request.axum_redirect().unwrap();

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
) -> StatusCode {
    let pkce_verifier = {
        let requests = state.requests.lock().expect("lock poisoned");

        let pkce_verifier = requests
            .get(&query.state)
            .expect("No matching CSRF Token found")
            .to_string();

        PkceCodeVerifier::new(pkce_verifier)
    };

    let code = AuthorizationCode::new(query.code);

    socio()
        .exchange_code::<EmptyExtraTokenFields>(code, pkce_verifier)
        .await
        .unwrap();

    StatusCode::OK
}

fn socio() -> Socio<()> {
    Socio::new(shared::read_config("axum"), ())
}
