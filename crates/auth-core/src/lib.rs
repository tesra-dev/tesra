//! Framework-agnostic authentication core for Tesra.
//!
//! Policies, passwords, sessions, MFA, passkeys, OIDC and audit events, with no
//! HTTP dependencies. Every security control maps to an OWASP ASVS 5.0
//! requirement listed in `security/asvs-matrix.csv`, and the tests that prove
//! each one are named after it.
//!
//! ```
//! use tesra_auth_core::{Passwords, Profile, Verification};
//!
//! let passwords = Passwords::new(Profile::L2.password_policy());
//! let checked = passwords.check("a long enough passphrase")?;
//! let stored = passwords.hash(&checked)?;
//! assert!(matches!(
//!     passwords.verify("a long enough passphrase", &stored),
//!     Verification::Matched { .. }
//! ));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod common_passwords;
pub mod error;
pub mod password;
pub mod policy;

pub use common_passwords::CommonPasswords;
pub use error::{Error, Result};
pub use password::{NormalizedPassword, PasswordRejected, Passwords, Verification};
pub use policy::{PasswordPolicy, Profile, SessionPolicy};
