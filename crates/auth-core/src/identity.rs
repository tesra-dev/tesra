//! Identifiers for the people a deployment authenticates.

use uuid::Uuid;

/// The identifier of an account.
///
/// It is random so it gives nothing away when it appears in a URL or a log
/// (ASVS V6.3.2 territory), but it is an identifier, not a secret: session
/// tokens are what prove who is calling.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct UserId(Uuid);

impl UserId {
    /// A new random identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an identifier that already exists, for example one read from a database.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// The identifier as a [`Uuid`].
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for UserId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl From<Uuid> for UserId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}
