use rand_core::OsError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred while trying to generate a random CSRF token.
    #[error("Failed to generate random CSRF token")]
    CsrfTokenGenerationError(#[source] OsError),
}
