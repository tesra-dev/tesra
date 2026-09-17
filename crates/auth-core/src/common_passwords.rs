//! The list of common passwords used to satisfy ASVS V6.2.4.
//!
//! The bundled list is derived from SecLists and holds every entry of 8
//! characters or more, lowercased and sorted, so lookups are a binary search
//! and need no network. See `data/NOTICE.md` for its license. Deployments that
//! want a different list can pass [`CommonPasswords::from_sorted`].

use std::sync::LazyLock;

#[cfg(feature = "common-passwords")]
static BUNDLED_TEXT: &str = include_str!("../data/common-passwords.txt");
#[cfg(not(feature = "common-passwords"))]
static BUNDLED_TEXT: &str = "";

static BUNDLED: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    BUNDLED_TEXT
        .lines()
        .filter(|line| !line.is_empty())
        .collect()
});

/// A sorted, lowercase list of passwords too common to allow.
#[derive(Debug, Clone, Copy)]
pub struct CommonPasswords {
    entries: &'static [&'static str],
}

impl CommonPasswords {
    /// The list bundled with this crate, or an empty list when the
    /// `common-passwords` feature is off.
    #[must_use]
    pub fn bundled() -> Self {
        Self {
            entries: BUNDLED.as_slice(),
        }
    }

    /// An empty list, for deployments that check passwords some other way.
    #[must_use]
    pub const fn empty() -> Self {
        Self { entries: &[] }
    }

    /// A caller-supplied list, which must already be lowercase and sorted.
    #[must_use]
    pub const fn from_sorted(entries: &'static [&'static str]) -> Self {
        Self { entries }
    }

    /// Whether the list holds this password. The candidate must already be
    /// lowercased and normalized, which [`crate::password::Passwords`] does.
    #[must_use]
    pub fn contains(&self, candidate: &str) -> bool {
        self.entries.binary_search(&candidate).is_ok()
    }

    /// How many passwords the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for CommonPasswords {
    fn default() -> Self {
        Self::bundled()
    }
}
