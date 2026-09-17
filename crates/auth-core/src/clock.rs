//! An injectable clock, so session lifetimes can be tested without waiting.

use std::sync::{Mutex, PoisonError};

use time::{Duration, OffsetDateTime};

/// The source of "now" for everything time-dependent.
///
/// Sessions, one-time codes and token lifetimes read time through this trait,
/// which keeps the checks testable and keeps client-supplied time out of the
/// decision (ASVS V6.5.8).
pub trait Clock: core::fmt::Debug + Send + Sync {
    /// The current UTC time.
    fn now(&self) -> OffsetDateTime;
}

/// The operating system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that only moves when told to, for tests.
#[derive(Debug)]
pub struct FixedClock {
    now: Mutex<OffsetDateTime>,
}

impl FixedClock {
    /// Starts at the given time.
    #[must_use]
    pub fn new(now: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// Starts at the Unix epoch.
    #[must_use]
    pub fn epoch() -> Self {
        Self::new(OffsetDateTime::UNIX_EPOCH)
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
