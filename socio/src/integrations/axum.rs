use axum_core::response::{IntoResponse, Response};
use http::{header, HeaderValue, StatusCode};

use crate::{error, types::AuthorizationRequest};

#[derive(Debug, Clone)]
pub struct AxumRedirect {
    url: HeaderValue,
}

impl AxumRedirect {
    pub fn new(url: HeaderValue) -> Self {
        AxumRedirect { url }
    }
}

impl IntoResponse for AxumRedirect {
    fn into_response(self) -> Response {
        (StatusCode::FOUND, [(header::LOCATION, self.url)]).into_response()
    }
}

impl TryFrom<AuthorizationRequest> for AxumRedirect {
    type Error = crate::error::Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        let header_value = HeaderValue::from_str(value.url.as_str())
            .map_err(|e| error::Error::HeaderValueError(e))?;
        Ok(AxumRedirect::new(header_value))
    }
}
