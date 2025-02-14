use axum::{
    extract::{Path, Query, State},
    response::Html,
    routing::get,
    Json, Router,
};
use socio::{
    integrations::{AxumRedirect, SocioCallback},
    oauth2::{AuthorizationCode, PkceCodeVerifier},
    providers::{Dynamic, StandardUser},
    Socio,
};
use socio_providers::{google::Google, microsoft::Microsoft};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default)]
pub struct AppState {
    requests: Arc<Mutex<HashMap<String, (String, String)>>>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::default();

    let app = Router::new()
        .route("/", get(home))
        .route("/redirect/{key}", get(redirect))
        .route("/callback", get(callback))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn home() -> Html<&'static str> {
    Html(
        r#"
    <html>
        <head>
            <title>axum</title>
        </head>
        <body>
            <h1>Multi Login Example</h1>
            <ul>
                <li><a href="/redirect/google">Login with Google</a></li>
                <li><a href="/redirect/microsoft">Login with Microsoft</a></li>
            </ul>
        </body>
    </html>
    "#,
    )
}

pub async fn redirect(State(state): State<AppState>, Path(key): Path<String>) -> AxumRedirect {
    let authorization_request = socio(key.as_str())
        .authorize()
        .expect("Failed to authorize");

    let redirect = authorization_request.axum_redirect().unwrap();

    {
        let mut requests = state.requests.lock().expect("lock poisoned");
        requests.insert(
            authorization_request.csrf_token.into_secret(),
            (key, authorization_request.pkce_verifier.into_secret()),
        );
    }

    redirect
}

#[axum::debug_handler]
pub async fn callback(
    Query(query): Query<SocioCallback>,
    State(state): State<AppState>,
) -> Json<StandardUser> {
    let (key, pkce_verifier) = {
        let requests = state.requests.lock().expect("lock poisoned");

        let (key, pkce_verifier) = requests
            .get(&query.state)
            .expect("No matching CSRF Token found");

        (key.clone(), PkceCodeVerifier::new(pkce_verifier.clone()))
    };

    let code = AuthorizationCode::new(query.code);

    let response = socio(key.as_str())
        .exchange_code_standard(code, pkce_verifier)
        .await
        .expect("Failed to exchange code");

    Json(response.user)
}

fn socio(key: &str) -> Socio<Dynamic> {
    match key {
        "google" => Socio::new(shared::read_config("google"), Box::new(Google)),
        "microsoft" => Socio::new(shared::read_config("microsoft"), Box::new(Microsoft)),
        _ => panic!("Unknown key"),
    }
}
