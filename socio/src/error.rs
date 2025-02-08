pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    ExchangingCodeError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error(transparent)]
    HeaderValueError(#[from] http::header::InvalidHeaderValue),

    #[error("CSRF token mismatch")]
    CsrfTokenMismatch,

    #[error(transparent)]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    Custom(#[from] Box<dyn std::error::Error + Send + Sync>),
}
