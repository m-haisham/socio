use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use actix_web::{
    App, HttpResponse, HttpServer, Responder, get,
    web::{self, Query},
};
use socio::{
    Socio,
    integrations::Callback,
    oauth2::{AuthorizationCode, EmptyExtraTokenFields, PkceCodeVerifier},
};

#[derive(Clone, Debug, Default)]
pub struct AppState {
    requests: Arc<Mutex<HashMap<String, String>>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .app_data(AppState::default())
            .service(redirect)
            .service(callback)
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}

#[get("/redirect")]
async fn redirect(data: web::Data<AppState>) -> impl Responder {
    let authorization_request = socio().authorize().unwrap();

    let redirect = authorization_request.redirect_actix();

    {
        let mut requests = data.requests.lock().expect("lock poisoned");
        requests.insert(
            authorization_request.csrf_token.into_secret(),
            authorization_request.pkce_verifier.into_secret(),
        );
    }

    redirect
}

#[get("/callback")]
async fn callback(query: Query<Callback>, data: web::Data<AppState>) -> impl Responder {
    let Query(Callback { code, state }) = query;

    let pkce_verifier = {
        let requests = data.requests.lock().expect("lock poisoned");

        let pkce_verifier = requests
            .get(&state)
            .expect("No matching CSRF Token found")
            .to_string();

        PkceCodeVerifier::new(pkce_verifier)
    };

    let code = AuthorizationCode::new(code);

    socio()
        .exchange_code::<EmptyExtraTokenFields>(code, pkce_verifier)
        .await
        .unwrap();

    HttpResponse::Ok()
}

fn socio() -> Socio<()> {
    Socio::new(shared::read_config("axum"), ())
}
