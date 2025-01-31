use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use socio::{
    integrations::{SocioCallback, SocioRedirect},
    oauth2::{
        AuthUrl, AuthorizationCode, ClientId, ClientSecret, EmptyExtraTokenFields,
        PkceCodeVerifier, RedirectUrl, Scope, TokenUrl,
    },
    types::OAuth2Config,
    Socio,
};

#[derive(Clone, Debug, Default)]
pub struct AppState {
    requests: Arc<Mutex<HashMap<String, String>>>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::default();

    // build our application with a single route
    let app = Router::new()
        .route("/redirect", get(redirect))
        .route("/callback", get(callback))
        .with_state(state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn redirect(State(state): State<AppState>) -> SocioRedirect {
    let client = get_socio_client();
    let authorization_request = client.authorize().unwrap();

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
pub async fn callback(Query(query): Query<SocioCallback>, State(state): State<AppState>) {
    let pkce_verifier = {
        let requests = state.requests.lock().expect("lock poisoned");

        let pkce_verifier = requests
            .get(&query.state)
            .expect("No matching CSRF Token found")
            .to_string();

        PkceCodeVerifier::new(pkce_verifier)
    };

    let code = AuthorizationCode::new(query.code);

    let client = get_socio_client();
    let token = client
        .exchange_code::<EmptyExtraTokenFields>(code, pkce_verifier)
        .await
        .unwrap();

    println!("{:?}", token);
}

pub fn get_socio_client() -> Socio {
    let config_content = std::fs::read_to_string("config.json").unwrap();
    let config = serde_json::from_str::<serde_json::Value>(&config_content).unwrap();

    let config = OAuth2Config {
        client_id: ClientId::new(config["client_id"].as_str().unwrap().to_string()),
        client_secret: ClientSecret::new(config["client_secret"].as_str().unwrap().to_string()),
        authorize_endpoint: AuthUrl::new(
            config["authorize_endpoint"].as_str().unwrap().to_string(),
        )
        .unwrap(),
        token_endpoint: TokenUrl::new(config["token_endpoint"].as_str().unwrap().to_string())
            .unwrap(),
        scopes: vec![Scope::new(config["scopes"].as_str().unwrap().to_string())],
        redirect_uri: RedirectUrl::new(config["redirect_uri"].as_str().unwrap().to_string())
            .unwrap(),
    };

    Socio::new(config)
}
