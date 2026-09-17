//! Storage traits, plus an in-memory session store.
//!
//! The core never talks to a database directly. `tesra-auth-postgres` provides
//! the production implementations, and `tesra-auth-testkit` holds the
//! conformance tests every implementation must pass.

use core::future::Future;

use time::OffsetDateTime;

use crate::identity::UserId;
use crate::session::{Session, SessionId};

/// Where sessions live.
pub trait SessionStore: Send + Sync {
    /// What can go wrong talking to the storage engine.
    type Error: core::error::Error + Send + Sync + 'static;

    /// Writes a new session.
    fn insert(&self, session: Session) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Reads a session by its identifier.
    fn get(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<Session>, Self::Error>> + Send;

    /// Records that a session was just used.
    fn touch(
        &self,
        id: &SessionId,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Deletes one session if it exists.
    fn delete(&self, id: &SessionId) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Deletes every session of one account, returning how many went.
    fn delete_for_user(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Deletes every session of one account except one, returning how many went.
    fn delete_for_user_except(
        &self,
        user: UserId,
        keep: &SessionId,
    ) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Deletes every session in the deployment, returning how many went.
    fn delete_all(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Lists one account's sessions, most recently used first.
    fn list_for_user(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Vec<Session>, Self::Error>> + Send;
}

#[cfg(feature = "memory-store")]
mod memory {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::{Future, OffsetDateTime, Session, SessionId, SessionStore, UserId};

    /// A session store kept in process memory, for tests and single-process
    /// deployments. Sessions are lost when the process restarts.
    #[derive(Debug, Default)]
    pub struct MemorySessionStore {
        sessions: Mutex<HashMap<SessionId, Session>>,
    }

    impl MemorySessionStore {
        /// An empty store.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// How many sessions it holds.
        #[must_use]
        pub fn len(&self) -> usize {
            self.lock().len()
        }

        /// Whether it holds no sessions.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.lock().is_empty()
        }

        fn lock(&self) -> MutexGuard<'_, HashMap<SessionId, Session>> {
            self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn removed(before: usize, after: usize) -> u64 {
            u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)
        }
    }

    impl SessionStore for MemorySessionStore {
        type Error = Infallible;

        fn insert(&self, session: Session) -> impl Future<Output = Result<(), Infallible>> + Send {
            self.lock().insert(session.id.clone(), session);
            async { Ok(()) }
        }

        fn get(
            &self,
            id: &SessionId,
        ) -> impl Future<Output = Result<Option<Session>, Infallible>> + Send {
            let found = self.lock().get(id).cloned();
            async move { Ok(found) }
        }

        fn touch(
            &self,
            id: &SessionId,
            at: OffsetDateTime,
        ) -> impl Future<Output = Result<(), Infallible>> + Send {
            if let Some(session) = self.lock().get_mut(id) {
                session.last_used_at = at;
            }
            async { Ok(()) }
        }

        fn delete(&self, id: &SessionId) -> impl Future<Output = Result<(), Infallible>> + Send {
            self.lock().remove(id);
            async { Ok(()) }
        }

        fn delete_for_user(
            &self,
            user: UserId,
        ) -> impl Future<Output = Result<u64, Infallible>> + Send {
            let mut sessions = self.lock();
            let before = sessions.len();
            sessions.retain(|_, session| session.user != user);
            let gone = Self::removed(before, sessions.len());
            drop(sessions);
            async move { Ok(gone) }
        }

        fn delete_for_user_except(
            &self,
            user: UserId,
            keep: &SessionId,
        ) -> impl Future<Output = Result<u64, Infallible>> + Send {
            let mut sessions = self.lock();
            let before = sessions.len();
            sessions.retain(|id, session| session.user != user || id == keep);
            let gone = Self::removed(before, sessions.len());
            drop(sessions);
            async move { Ok(gone) }
        }

        fn delete_all(&self) -> impl Future<Output = Result<u64, Infallible>> + Send {
            let mut sessions = self.lock();
            let gone = Self::removed(sessions.len(), 0);
            sessions.clear();
            drop(sessions);
            async move { Ok(gone) }
        }

        fn list_for_user(
            &self,
            user: UserId,
        ) -> impl Future<Output = Result<Vec<Session>, Infallible>> + Send {
            let mut found: Vec<Session> = self
                .lock()
                .values()
                .filter(|session| session.user == user)
                .cloned()
                .collect();
            found.sort_by_key(|session| core::cmp::Reverse(session.last_used_at));
            async move { Ok(found) }
        }
    }
}

#[cfg(feature = "memory-store")]
pub use memory::MemorySessionStore;
