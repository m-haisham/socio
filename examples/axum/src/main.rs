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

    let app = Router::new()
        .route("/redirect", get(redirect))
        .route("/callback", get(callback))
        .with_state(state);

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

pub fn get_socio_client() -> Socio<()> {
    let config_content = std::fs::read_to_string("config.json").unwrap();
    let config = serde_json::from_str::<serde_json::Value>(&config_content).unwrap();

    fn get_config_string(config: &serde_json::Value, key: &str) -> String {
        config[key]
            .as_str()
            .expect(&format!("The key '{key}' is missing or not a string"))
            .to_string()
    }

    fn get_config_string_list(config: &serde_json::Value, key: &str) -> Vec<String> {
        config[key]
            .as_array()
            .expect(&format!("The key '{key}' is missing or not a list"))
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    fn get_config_scopes(config: &serde_json::Value, key: &str) -> Vec<Scope> {
        get_config_string_list(config, key)
            .into_iter()
            .map(|s| Scope::new(s))
            .collect()
    }

    let config = OAuth2Config {
        client_id: ClientId::new(get_config_string(&config, "client_id")),
        client_secret: ClientSecret::new(get_config_string(&config, "client_secret")),
        authorize_endpoint: AuthUrl::new(get_config_string(&config, "authorize_endpoint")).unwrap(),
        token_endpoint: TokenUrl::new(get_config_string(&config, "token_endpoint"))
            .expect("Invalid token endpoint"),
        scopes: get_config_scopes(&config, "scopes"),
        redirect_uri: RedirectUrl::new(get_config_string(&config, "redirect_uri"))
            .expect("Invalid redirect URI"),
    };

    Socio::new(config, ())
}
