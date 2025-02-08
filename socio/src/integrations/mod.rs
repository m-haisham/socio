#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "rocket")]
mod rocket;

use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::error;

#[cfg(feature = "axum")]
pub use axum::AxumRedirect;
#[cfg(feature = "rocket")]
pub use rocket::RocketRedirect;

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
