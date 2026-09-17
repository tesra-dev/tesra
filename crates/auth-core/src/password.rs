//! Password policy checks, hashing and verification.
//!
//! Hashing uses Argon2id with the parameters OWASP recommends: 19 MiB of
//! memory, two iterations and no parallelism (ASVS V11.4.2). Candidates are
//! normalized to Unicode NFC, which NIST SP 800-63B revision 4 recommends.
//! Nothing else about the password changes: ASVS V6.2.8 requires it to be
//! verified as received, so there is no truncation and no case folding.

use std::sync::OnceLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _, generate_salt};
use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

use crate::common_passwords::CommonPasswords;
use crate::error::Result;
use crate::policy::PasswordPolicy;

/// Argon2id memory cost in KiB, as recommended by OWASP.
pub const MEMORY_COST_KIB: u32 = 19_456;
/// Argon2id iteration count, as recommended by OWASP.
pub const TIME_COST: u32 = 2;
/// Argon2id parallelism, as recommended by OWASP.
pub const PARALLELISM: u32 = 1;

/// The password hashed to give sign-ins for unknown accounts the same cost as
/// real ones (ASVS V6.3.8). Its value is irrelevant; only the work matters.
const EQUAL_TIME_PASSWORD: &str = "tesra placeholder password for equal timing";

/// A candidate password that passed the policy, normalized to Unicode NFC.
///
/// Only [`Passwords::hash`] accepts one, so an unchecked password cannot be
/// stored by accident. The value is zeroized when dropped and never printed.
#[derive(Clone)]
pub struct NormalizedPassword(Zeroizing<String>);

impl NormalizedPassword {
    /// The normalized password.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for NormalizedPassword {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NormalizedPassword(redacted)")
    }
}

/// Why a candidate password was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordRejected {
    /// Shorter than the policy's minimum length.
    #[error("password must be at least {min} characters long")]
    TooShort {
        /// The minimum the policy allows.
        min: usize,
    },
    /// Longer than the policy's maximum length.
    #[error("password must be at most {max} characters long")]
    TooLong {
        /// The maximum the policy allows.
        max: usize,
    },
    /// Found in the common-password list (ASVS V6.2.4).
    #[error("password is one of the most commonly used passwords")]
    TooCommon,
    /// Contains a word specific to this application (ASVS V6.2.11).
    #[error("password must not contain the word {word:?}")]
    ContextWord {
        /// The matched word, lowercased.
        word: String,
    },
}

/// The outcome of checking a password against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The password matched.
    Matched {
        /// True when the stored hash uses older parameters than the current
        /// policy, so it should be replaced on this sign-in (ASVS V11.4.2).
        needs_rehash: bool,
    },
    /// The password did not match, or the stored hash could not be read.
    Failed,
}

/// Hashes and verifies passwords under a [`PasswordPolicy`].
pub struct Passwords {
    policy: PasswordPolicy,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    pepper: Option<Zeroizing<Vec<u8>>>,
    common: CommonPasswords,
    equal_time: OnceLock<String>,
}

impl core::fmt::Debug for Passwords {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Passwords")
            .field("policy", &self.policy)
            .field("memory_kib", &self.memory_kib)
            .field("iterations", &self.iterations)
            .field("parallelism", &self.parallelism)
            .field("pepper", &self.pepper.as_ref().map(|_| "redacted"))
            .field("common_passwords", &self.common.len())
            .finish_non_exhaustive()
    }
}

impl Passwords {
    /// Hashes with the OWASP-recommended Argon2id parameters and the bundled
    /// common-password list.
    #[must_use]
    pub fn new(policy: PasswordPolicy) -> Self {
        Self {
            policy,
            memory_kib: MEMORY_COST_KIB,
            iterations: TIME_COST,
            parallelism: PARALLELISM,
            pepper: None,
            common: CommonPasswords::bundled(),
            equal_time: OnceLock::new(),
        }
    }

    /// Uses different Argon2id parameters, for deployments whose hardware calls
    /// for another point on the OWASP table.
    ///
    /// # Errors
    ///
    /// Returns an error if Argon2 rejects the combination of parameters.
    pub fn with_parameters(
        policy: PasswordPolicy,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self> {
        Params::new(memory_kib, iterations, parallelism, None)?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
            ..Self::new(policy)
        })
    }

    /// Mixes a secret pepper into every hash (ASVS V13.3.1). Keep it in a
    /// vault, not in the database: it is the Argon2 secret input, so rotating
    /// it invalidates existing hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if the pepper is longer than Argon2 accepts.
    pub fn with_pepper(mut self, pepper: Vec<u8>) -> Result<Self> {
        let pepper = Zeroizing::new(pepper);
        Argon2::new_with_secret(
            &pepper,
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(self.memory_kib, self.iterations, self.parallelism, None)?,
        )?;
        self.pepper = Some(pepper);
        Ok(self)
    }

    /// Uses a different common-password list.
    #[must_use]
    pub fn with_common_passwords(mut self, common: CommonPasswords) -> Self {
        self.common = common;
        self
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// The common-password list in use.
    #[must_use]
    pub fn common_passwords(&self) -> CommonPasswords {
        self.common
    }

    /// Normalizes a candidate password and checks it against the policy.
    ///
    /// # Errors
    ///
    /// Returns the first rule the candidate breaks.
    pub fn check(
        &self,
        candidate: &str,
    ) -> core::result::Result<NormalizedPassword, PasswordRejected> {
        let normalized = Zeroizing::new(candidate.nfc().collect::<String>());
        let length = normalized.chars().count();
        if length < self.policy.min_length {
            return Err(PasswordRejected::TooShort {
                min: self.policy.min_length,
            });
        }
        if length > self.policy.max_length {
            return Err(PasswordRejected::TooLong {
                max: self.policy.max_length,
            });
        }

        let folded = Zeroizing::new(normalized.to_lowercase());
        if self.policy.check_common_passwords && self.common.contains(&folded) {
            return Err(PasswordRejected::TooCommon);
        }
        for word in &self.policy.context_words {
            let word = word.to_lowercase();
            if !word.is_empty() && folded.contains(&word) {
                return Err(PasswordRejected::ContextWord { word });
            }
        }

        Ok(NormalizedPassword(normalized))
    }

    /// Hashes a checked password into a PHC string ready for storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the Argon2 configuration is unusable or hashing fails.
    pub fn hash(&self, password: &NormalizedPassword) -> Result<String> {
        self.hash_str(password.as_str())
    }

    /// Checks a candidate against a stored PHC string.
    ///
    /// A hash that cannot be parsed fails rather than erroring, so a corrupt
    /// row can never let someone in.
    #[must_use]
    pub fn verify(&self, candidate: &str, stored: &str) -> Verification {
        let normalized = Zeroizing::new(candidate.nfc().collect::<String>());
        let (Ok(argon2), Ok(parsed)) = (self.argon2(), PasswordHash::new(stored)) else {
            return Verification::Failed;
        };
        if argon2
            .verify_password(normalized.as_bytes(), &parsed)
            .is_ok()
        {
            Verification::Matched {
                needs_rehash: !self.is_current(stored),
            }
        } else {
            Verification::Failed
        }
    }

    /// Spends the same work as [`Self::verify`] when the account does not
    /// exist, so response times don't reveal which usernames are registered
    /// (ASVS V6.3.8). Always fails.
    #[must_use]
    pub fn verify_unknown_user(&self, candidate: &str) -> Verification {
        if let Some(placeholder) = self.equal_time_hash() {
            let _outcome = self.verify(candidate, placeholder);
        }
        Verification::Failed
    }

    /// The hash used by [`Self::verify_unknown_user`], so a deployment can
    /// confirm it carries the same cost as a real one.
    #[must_use]
    pub fn equal_time_hash(&self) -> Option<&str> {
        let hash = self
            .equal_time
            .get_or_init(|| self.hash_str(EQUAL_TIME_PASSWORD).unwrap_or_default());
        (!hash.is_empty()).then_some(hash.as_str())
    }

    /// Whether a stored hash already uses the current algorithm and parameters.
    #[must_use]
    pub fn is_current(&self, stored: &str) -> bool {
        let parameters = format!(
            "$m={},t={},p={}$",
            self.memory_kib, self.iterations, self.parallelism
        );
        stored.starts_with("$argon2id$v=19$") && stored.contains(&parameters)
    }

    fn hash_str(&self, password: &str) -> Result<String> {
        let salt = generate_salt();
        let hash = self
            .argon2()?
            .hash_password_with_salt(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    fn argon2(&self) -> Result<Argon2<'_>> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, None)?;
        match &self.pepper {
            Some(pepper) => Ok(Argon2::new_with_secret(
                pepper,
                Algorithm::Argon2id,
                Version::V0x13,
                params,
            )?),
            None => Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params)),
        }
    }
}
