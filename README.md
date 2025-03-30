# Socio

**Socio** is a Rust library for integrating social login authentication into web frameworks. It provides a simple and extensible way to authenticate users via third-party OAuth providers.

## Socio Providers

The `socio_providers` crate includes support for Google, Facebook, Microsoft, and OpenID authentication.

## Installation

To use `socio`, add it to your `Cargo.toml`:

```toml
[dependencies]
socio = "0.1"
```

For provider-specific authentication, also add `socio_providers`:

```toml
[dependencies]
socio_providers = "0.1"
```

## Usage

For detailed examples, check out our [GitHub repository](https://github.com/m-haisham/socio).

### Example: Axum Integration

A minimal example for handling social login redirection and callback:

```rust
use axum::{Router, extract::State, routing::get};
use socio::{
    Socio,
    integrations::axum::Redirect,
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    types::SocioClient,
};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/redirect", get(redirect))
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn redirect() -> Redirect {
    let client = SocioClient {
        client_id: env!("CLIENT_ID"),
        client_secret: ClientSecret::new(env!("CLIENT_SECRET")),
        authorize_endpoint: AuthUrl::new(env!("AUTHORIZE_ENDPOINT")).unwrap(),
        token_endpoint: TokenUrl::new(env!("TOKEN_ENDPOINT"))
            .expect("Invalid token endpoint"),
        scopes: vec!["email".to_string()],
        redirect_uri: RedirectUrl::new(env!("REDIRECT_URI"))
            .expect("Invalid redirect URI"),
    };

    let socio = Socio::new(client, ());

    socio().authorize().unwrap().redirect_axum().unwrap()
}
```

### Example: Using Socio Providers

Logging in with Facebook:

```rust
use socio_providers::facebook::FacebookUser;
use axum::{extract::Query, Json};
use socio::oauth2::AuthorizationCode;

async fn callback(Query(query): Query<Callback>) -> Json<FacebookUser> {
    let code = AuthorizationCode::new(query.code);
    let user = socio().exchange_code_for_user(code).await.unwrap();
    Json(user)
}
```

## License

This project is licensed under the MIT License.
