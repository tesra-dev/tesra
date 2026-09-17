//! Session tokens and the rules that decide whether one is still good.
//!
//! Tesra uses reference tokens rather than self-contained ones: the browser
//! holds 256 bits of randomness and the backend holds the state, so ending a
//! session is a delete and cannot be undone by anyone holding an old token
//! (ASVS V7.2.2, V7.4.1). Only the SHA-256 of a token is stored, so a leaked
//! session table contains nothing that can be replayed.

use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::identity::UserId;
use crate::policy::SessionPolicy;
use crate::store::SessionStore;

/// Bytes of randomness in a session token: 256 bits, twice the 128 that ASVS
/// V7.2.3 requires.
pub const TOKEN_BYTES: usize = 32;

/// How stale a session's activity timestamp may become before it is written
/// again, so a busy session doesn't write on every request.
const TOUCH_GRANULARITY: Duration = Duration::minutes(1);

fn as_time_duration(duration: core::time::Duration) -> Duration {
    Duration::try_from(duration).unwrap_or(Duration::MAX)
}

/// The secret a client holds in its session cookie.
#[derive(Clone)]
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// Generates a token from the operating system's CSPRNG (ASVS V7.2.3).
    #[must_use]
    pub fn generate() -> Self {
        let bytes = Zeroizing::new(rand::random::<[u8; TOKEN_BYTES]>());
        Self(Zeroizing::new(Base64UrlUnpadded::encode_string(&bytes[..])))
    }

    /// Reads a token a client presented, rejecting anything that isn't shaped
    /// like one this crate issues, so malformed values never reach the store.
    #[must_use]
    pub fn parse(presented: &str) -> Option<Self> {
        let mut decoded = Zeroizing::new([0_u8; TOKEN_BYTES]);
        Base64UrlUnpadded::decode(presented, &mut decoded[..]).ok()?;
        Some(Self(Zeroizing::new(presented.to_owned())))
    }

    /// The token as a string, for putting in a cookie.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The identifier this token is stored under: its SHA-256 digest.
    #[must_use]
    pub fn id(&self) -> SessionId {
        let digest = Sha256::digest(self.expose().as_bytes());
        SessionId(Base64UrlUnpadded::encode_string(&digest[..]))
    }
}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SessionToken(redacted)")
    }
}

/// How a session is keyed in storage: the digest of its token.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct SessionId(String);

impl SessionId {
    /// Wraps an identifier read back from storage.
    #[must_use]
    pub const fn from_stored(id: String) -> Self {
        Self(id)
    }

    /// The identifier as stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A live session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// Where the session is stored: the token's digest, never the token.
    pub id: SessionId,
    /// The account the session belongs to.
    pub user: UserId,
    /// When the session started.
    pub started_at: OffsetDateTime,
    /// When it was last used, written at most once a minute.
    pub last_used_at: OffsetDateTime,
    /// When it ends regardless of activity (ASVS V7.3.2).
    pub expires_at: OffsetDateTime,
    /// A label for the session list a user can review, such as browser and
    /// rough location.
    pub device: Option<String>,
}

impl Session {
    /// Whether the session has passed its absolute lifetime or gone idle for
    /// longer than the policy allows (ASVS V7.3.1, V7.3.2).
    #[must_use]
    pub fn has_expired(&self, now: OffsetDateTime, policy: &SessionPolicy) -> bool {
        if now >= self.expires_at {
            return true;
        }
        policy
            .idle_timeout
            .is_some_and(|idle| now - self.last_used_at >= as_time_duration(idle))
    }
}

/// Starts, checks and ends sessions on top of a [`SessionStore`].
#[derive(Debug)]
pub struct Sessions<S> {
    store: S,
    policy: SessionPolicy,
    clock: Arc<dyn Clock>,
}

impl<S: SessionStore> Sessions<S> {
    /// Uses the system clock.
    #[must_use]
    pub fn new(store: S, policy: SessionPolicy) -> Self {
        Self {
            store,
            policy,
            clock: Arc::new(SystemClock),
        }
    }

    /// Uses a different clock, which tests need.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// The store behind this service.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Starts a session and returns the token to hand to the client.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the session cannot be written.
    pub async fn start(
        &self,
        user: UserId,
        device: Option<String>,
    ) -> Result<(SessionToken, Session), S::Error> {
        let token = SessionToken::generate();
        let now = self.clock.now();
        let session = Session {
            id: token.id(),
            user,
            started_at: now,
            last_used_at: now,
            expires_at: now + as_time_duration(self.policy.absolute_lifetime),
            device,
        };
        self.store.insert(session.clone()).await?;
        Ok((token, session))
    }

    /// Issues a new token and ends the previous session, which every sign-in
    /// and re-authentication must do (ASVS V7.2.4).
    ///
    /// # Errors
    ///
    /// Returns the store's error if either half cannot be written.
    pub async fn rotate(
        &self,
        previous: &SessionToken,
        user: UserId,
        device: Option<String>,
    ) -> Result<(SessionToken, Session), S::Error> {
        let started = self.start(user, device).await?;
        self.store.delete(&previous.id()).await?;
        Ok(started)
    }

    /// Checks a presented token against the store and the timeouts.
    ///
    /// Returns `None` when the token is unknown or the session has expired,
    /// deleting expired sessions as it finds them (ASVS V7.2.1, V7.3).
    ///
    /// # Errors
    ///
    /// Returns the store's error if it cannot be read or updated.
    pub async fn verify(&self, token: &SessionToken) -> Result<Option<Session>, S::Error> {
        let id = token.id();
        let Some(mut session) = self.store.get(&id).await? else {
            return Ok(None);
        };
        let now = self.clock.now();
        if session.has_expired(now, &self.policy) {
            self.store.delete(&id).await?;
            return Ok(None);
        }
        if now - session.last_used_at >= TOUCH_GRANULARITY {
            self.store.touch(&id, now).await?;
            session.last_used_at = now;
        }
        Ok(Some(session))
    }

    /// Ends one session, so its token stops working (ASVS V7.4.1).
    ///
    /// # Errors
    ///
    /// Returns the store's error if the session cannot be deleted.
    pub async fn end(&self, token: &SessionToken) -> Result<(), S::Error> {
        self.store.delete(&token.id()).await
    }

    /// Ends every session of an account, which disabling or deleting one must
    /// do (ASVS V7.4.2, V7.4.5). Returns how many ended.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the sessions cannot be deleted.
    pub async fn end_all_for(&self, user: UserId) -> Result<u64, S::Error> {
        self.store.delete_for_user(user).await
    }

    /// Ends every session of an account except the one presented, for the
    /// "sign out everywhere else" option after a credential change (ASVS
    /// V7.4.3). Returns how many ended.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the sessions cannot be deleted.
    pub async fn end_others(&self, keep: &SessionToken, user: UserId) -> Result<u64, S::Error> {
        self.store.delete_for_user_except(user, &keep.id()).await
    }

    /// Ends every session in the deployment (ASVS V7.4.5). Returns how many ended.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the sessions cannot be deleted.
    pub async fn end_everything(&self) -> Result<u64, S::Error> {
        self.store.delete_all().await
    }

    /// Lists an account's live sessions for the user to review (ASVS V7.5.2).
    /// Tokens are not stored, so they cannot appear here.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the sessions cannot be read.
    pub async fn list_for(&self, user: UserId) -> Result<Vec<Session>, S::Error> {
        self.store.list_for_user(user).await
    }
}
