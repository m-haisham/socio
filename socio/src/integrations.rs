use axum_core::response::IntoResponse;
use http::{header::LOCATION, HeaderValue, StatusCode};
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::error;

#[derive(Debug, Clone)]
pub struct SocioRedirect {
    url: HeaderValue,
}

impl SocioRedirect {
    pub fn new(url: HeaderValue) -> Self {
        SocioRedirect { url }
    }
}

impl IntoResponse for SocioRedirect {
    fn into_response(self) -> axum_core::response::Response {
        (StatusCode::FOUND, [(LOCATION, self.url)]).into_response()
    }
}

#[derive(Deserialize, Debug)]
pub struct SocioCallback {
    pub code: String,
    pub state: String,
}

impl SocioCallback {
    pub fn verify_csrf_token(self, csrf_token: &CsrfToken) -> error::Result<AuthorizationCode> {
        if self.state == csrf_token.secret().as_str() {
            Ok(AuthorizationCode::new(self.code))
        } else {
            Err(error::Error::CsrfTokenMismatch)
        }
    }
}
