#![allow(dead_code)]

use std::{collections::HashMap, sync::Mutex};

use rocket::{State, get, http::Status, launch, routes};
use socio::{
    Socio,
    integrations::rocket::Redirect,
    oauth2::{AuthorizationCode, EmptyExtraTokenFields, PkceCodeVerifier},
};

#[launch]
fn rocket() -> _ {
    let requests = Mutex::new(HashMap::<String, String>::new());

    rocket::build()
        .configure(rocket::Config::figment().merge(("port", 3000)))
        .mount("/", routes![redirect, callback])
        .manage(requests)
}

#[get("/redirect")]
async fn redirect(requests: &State<Mutex<HashMap<String, String>>>) -> Redirect {
    let authorization_request = socio().authorize().unwrap();

    {
        let mut requests = requests.lock().expect("lock poisoned");
        requests.insert(
            authorization_request.csrf_token.into_secret(),
            authorization_request.pkce_verifier.into_secret(),
        );
    }

    Redirect::new(authorization_request.url)
}

#[get("/callback?<code>&<state>")]
async fn callback(
    code: String,
    state: String,
    requests: &State<Mutex<HashMap<String, String>>>,
) -> Status {
    let pkce_verifier = {
        let requests = requests.lock().expect("lock poisoned");
        let pkce_verifier = requests.get(&state).expect("state not found").clone();
        PkceCodeVerifier::new(pkce_verifier)
    };

    let code = AuthorizationCode::new(code);

    socio()
        .exchange_code::<EmptyExtraTokenFields>(code, pkce_verifier)
        .await
        .unwrap();

    Status::Ok
}

fn socio() -> Socio<()> {
    Socio::new(shared::read_config("rocket"), ())
}
