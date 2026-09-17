//! Assurance profiles and the policies they set.
//!
//! A profile maps an OWASP ASVS verification level onto concrete settings, so a
//! deployment picks a level instead of assembling rules by hand. Defaults come
//! from ASVS 5.0 and NIST SP 800-63B revision 4; see `docs/blueprint.md` §6.3.

use core::time::Duration;

/// The ASVS verification level a deployment targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// The ASVS starting point: a password may be the only factor.
    L1,
    /// What most applications should target. Multi-factor authentication is required.
    L2,
    /// High assurance: a hardware-backed, phishing-resistant factor is required.
    L3,
}

impl Default for Profile {
    /// `L2`, because ASVS says most applications should target that level.
    fn default() -> Self {
        Self::L2
    }
}

impl Profile {
    /// Whether this profile requires multi-factor authentication (ASVS V6.3.3).
    #[must_use]
    pub const fn requires_mfa(self) -> bool {
        !matches!(self, Self::L1)
    }

    /// The password rules for this profile.
    ///
    /// The minimum length is 15 characters when a password can be the only
    /// factor, and 8 when the profile makes MFA mandatory, which is what NIST
    /// SP 800-63B revision 4 requires and ASVS V6.2.1 allows.
    #[must_use]
    pub fn password_policy(self) -> PasswordPolicy {
        PasswordPolicy {
            min_length: if self.requires_mfa() { 8 } else { 15 },
            max_length: PasswordPolicy::DEFAULT_MAX_LENGTH,
            check_common_passwords: true,
            context_words: Vec::new(),
        }
    }

    /// The session lifetimes for this profile, following the NIST SP 800-63B
    /// revision 4 limits for AAL1, AAL2 and AAL3 (ASVS V7.3).
    #[must_use]
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "Duration::from_hours and from_mins are still unstable on the pinned toolchain"
    )]
    pub const fn session_policy(self) -> SessionPolicy {
        match self {
            Self::L1 => SessionPolicy {
                absolute_lifetime: Duration::from_secs(30 * 24 * 60 * 60),
                idle_timeout: None,
                reauthentication_window: Duration::from_secs(15 * 60),
            },
            Self::L2 => SessionPolicy {
                absolute_lifetime: Duration::from_secs(24 * 60 * 60),
                idle_timeout: Some(Duration::from_secs(60 * 60)),
                reauthentication_window: Duration::from_secs(15 * 60),
            },
            Self::L3 => SessionPolicy {
                absolute_lifetime: Duration::from_secs(12 * 60 * 60),
                idle_timeout: Some(Duration::from_secs(15 * 60)),
                reauthentication_window: Duration::from_secs(5 * 60),
            },
        }
    }
}

/// Rules a candidate password must satisfy.
///
/// There are deliberately no composition rules and no expiry: ASVS V6.2.5 and
/// V6.2.10, and NIST SP 800-63B revision 4, forbid both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Minimum length in characters (ASVS V6.2.1).
    pub min_length: usize,
    /// Maximum length in characters. At least 64 must be allowed (ASVS V6.2.9).
    pub max_length: usize,
    /// Whether to reject passwords found in the common-password list (ASVS V6.2.4).
    pub check_common_passwords: bool,
    /// Words specific to this application that passwords must not contain,
    /// such as the product or organization name (ASVS V6.1.2 and V6.2.11).
    pub context_words: Vec<String>,
}

impl PasswordPolicy {
    /// The default maximum length, well past the 64 characters ASVS V6.2.9 requires.
    pub const DEFAULT_MAX_LENGTH: usize = 256;
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Profile::default().password_policy()
    }
}

/// How long sessions live (ASVS V7.3, NIST SP 800-63B revision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Maximum session lifetime, regardless of activity.
    pub absolute_lifetime: Duration,
    /// Inactivity timeout, when the profile sets one.
    pub idle_timeout: Option<Duration>,
    /// How recently the user must have authenticated before a sensitive change
    /// is allowed (ASVS V7.5.1).
    pub reauthentication_window: Duration,
}
