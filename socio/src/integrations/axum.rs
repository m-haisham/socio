use axum_core::response::{IntoResponse, Response};
use http::{header, HeaderValue, StatusCode};

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
