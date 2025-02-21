#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "rocket")]
pub mod rocket;

use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::error;

#[derive(Deserialize, Debug)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

impl Callback {
    pub fn verify_csrf_token(self, csrf_token: &CsrfToken) -> error::Result<AuthorizationCode> {
        if self.state == csrf_token.secret().as_str() {
            Ok(AuthorizationCode::new(self.code))
        } else {
            Err(error::Error::CsrfTokenMismatch)
        }
    }
}
