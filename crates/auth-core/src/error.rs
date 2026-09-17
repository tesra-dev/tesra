//! Error types shared by the auth core.

/// Something the auth core could not do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Hashing a password, or parsing a stored hash, failed.
    #[error("password hashing failed")]
    PasswordHash(#[from] argon2::password_hash::Error),
    /// The configured Argon2 parameters or pepper are not usable.
    #[error("invalid Argon2 configuration")]
    Argon2Config(#[from] argon2::Error),
}

/// Shorthand for results carrying an auth-core [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
