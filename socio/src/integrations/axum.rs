use axum_core::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};

use crate::{error, types::AuthorizationRequest};

#[derive(Debug, Clone)]
pub struct Redirect {
    url: HeaderValue,
}

impl Redirect {
    pub fn new(url: HeaderValue) -> Self {
        Redirect { url }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        (StatusCode::FOUND, [(header::LOCATION, self.url)]).into_response()
    }
}

impl TryFrom<AuthorizationRequest> for Redirect {
    type Error = crate::error::Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        let header_value = HeaderValue::from_str(value.url.as_str())
            .map_err(|e| error::Error::HeaderValueError(e))?;
        Ok(Redirect::new(header_value))
    }
}
