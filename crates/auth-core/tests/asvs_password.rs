//! ASVS conformance tests for password policy, hashing and verification.
//!
//! Every test name carries the requirement it proves, so `scripts/asvs_gate.py`
//! can match it to a row in `security/asvs-matrix.csv`.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::{ProptestConfig, prop_assume, proptest};
use tesra_auth_core::password::{MEMORY_COST_KIB, PARALLELISM, TIME_COST};
use tesra_auth_core::{CommonPasswords, PasswordRejected, Passwords, Profile, Verification};

const PASSPHRASE: &str = "a good long passphrase";

fn l1() -> Passwords {
    Passwords::new(Profile::L1.password_policy())
}

fn l2() -> Passwords {
    Passwords::new(Profile::L2.password_policy())
}

fn hash_of(passwords: &Passwords, password: &str) -> String {
    let checked = passwords.check(password).expect("password passes policy");
    passwords.hash(&checked).expect("hashing succeeds")
}

#[test]
fn v6_2_1_requires_fifteen_characters_when_the_password_is_the_only_factor() {
    let passwords = l1();
    assert_eq!(passwords.policy().min_length, 15);
    assert_eq!(
        passwords.check("fourteen chars").unwrap_err(),
        PasswordRejected::TooShort { min: 15 }
    );
    assert!(passwords.check("fifteen chars!!").is_ok());
}

#[test]
fn v6_2_1_allows_eight_characters_once_the_profile_requires_mfa() {
    let passwords = l2();
    assert!(Profile::L2.requires_mfa());
    assert_eq!(passwords.policy().min_length, 8);
    assert!(passwords.check("8 chars!").is_ok());
    assert_eq!(
        passwords.check("7 char!").unwrap_err(),
        PasswordRejected::TooShort { min: 8 }
    );
}

#[test]
fn v6_2_4_rejects_the_most_common_passwords() {
    let passwords = l2();
    assert!(
        CommonPasswords::bundled().len() >= 3000,
        "ASVS V6.2.4 asks for at least the top 3000 passwords"
    );
    assert_eq!(
        passwords.check("password123").unwrap_err(),
        PasswordRejected::TooCommon
    );
    assert_eq!(
        passwords.check("Password123").unwrap_err(),
        PasswordRejected::TooCommon,
        "the check ignores case"
    );
    assert_eq!(
        passwords.check("trustno1").unwrap_err(),
        PasswordRejected::TooCommon
    );
}

#[test]
fn v6_2_5_accepts_any_character_composition() {
    let passwords = l1();
    for candidate in [
        "all lowercase letters here",
        "ALL UPPERCASE LETTERS HERE",
        "3141592653589793238462643",
        "!@#$%^&*()!@#$%^&*()!@#$%",
        "ünïcödé pässwörd wïth mårks",
        "🔐🔑🗝 emoji passphrase 🔒",
        "   leading and trailing   ",
    ] {
        assert!(
            passwords.check(candidate).is_ok(),
            "composition rules rejected {candidate:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn v6_2_5_property_accepts_any_printable_password_within_the_length_range(
        candidate in "[a-zA-Z0-9 !@#$%^&*()_+-]{15,64}"
    ) {
        let passwords = l1();
        prop_assume!(!CommonPasswords::bundled().contains(&candidate.to_lowercase()));
        assert!(
            passwords.check(&candidate).is_ok(),
            "no composition rule may reject {candidate:?}"
        );
    }
}

#[test]
fn v6_2_8_verifies_the_password_exactly_as_received() {
    let passwords = l1();
    let long = "a-very-long-password-that-runs-past-seventy-two-bytes-so-truncation-would-show-up";
    let stored = hash_of(&passwords, long);
    assert!(matches!(
        passwords.verify(long, &stored),
        Verification::Matched { .. }
    ));
    assert_eq!(
        passwords.verify(&long[..72], &stored),
        Verification::Failed,
        "a truncated password must not match"
    );
    assert_eq!(
        passwords.verify(&long.to_uppercase(), &stored),
        Verification::Failed,
        "case must matter"
    );
}

#[test]
fn v6_2_8_normalizes_unicode_but_changes_nothing_else() {
    // NIST SP 800-63B revision 4 recommends NFC normalization, so the same
    // characters typed in decomposed form still verify.
    let passwords = l1();
    let composed = "pässwörd with mårks";
    let decomposed = "pa\u{308}sswo\u{308}rd with ma\u{30a}rks";
    let stored = hash_of(&passwords, composed);
    assert!(matches!(
        passwords.verify(decomposed, &stored),
        Verification::Matched { .. }
    ));
}

#[test]
fn v6_2_9_accepts_passwords_of_at_least_sixty_four_characters() {
    let passwords = l1();
    assert!(passwords.policy().max_length >= 64);
    let sixty_four = "correct horse battery staple correct horse battery staple long!!";
    assert_eq!(sixty_four.chars().count(), 64);
    let stored = hash_of(&passwords, sixty_four);
    assert!(matches!(
        passwords.verify(sixty_four, &stored),
        Verification::Matched { .. }
    ));
}

#[test]
fn v6_2_11_rejects_context_specific_words() {
    let mut policy = Profile::L1.password_policy();
    policy.context_words = vec!["Tesra".to_owned(), "acme-corp".to_owned()];
    let passwords = Passwords::new(policy);
    assert!(matches!(
        passwords.check("tesra is my password").unwrap_err(),
        PasswordRejected::ContextWord { .. }
    ));
    assert!(passwords.check("an unrelated passphrase").is_ok());
}

#[test]
fn v6_3_8_unknown_accounts_pay_the_same_hashing_cost() {
    let passwords = l1();
    assert_eq!(
        passwords.verify_unknown_user(PASSPHRASE),
        Verification::Failed
    );
    let placeholder = passwords
        .equal_time_hash()
        .expect("the equal-time hash is available");
    assert!(placeholder.starts_with("$argon2id$v=19$"));
    assert!(
        placeholder.contains("$m=19456,t=2,p=1$"),
        "the unknown-account path must cost the same as a real verification"
    );
}

#[test]
fn v11_4_1_hashes_with_argon2id_and_no_disallowed_hash_function() {
    let stored = hash_of(&l1(), PASSPHRASE);
    assert!(
        stored.starts_with("$argon2id$v=19$"),
        "unexpected hash format: {stored}"
    );
}

#[test]
fn v11_4_2_uses_the_owasp_parameters_and_rehashes_weaker_stored_hashes() {
    assert_eq!((MEMORY_COST_KIB, TIME_COST, PARALLELISM), (19_456, 2, 1));
    let passwords = l1();
    let stored = hash_of(&passwords, PASSPHRASE);
    assert!(stored.contains("$m=19456,t=2,p=1$"));
    assert_eq!(
        passwords.verify(PASSPHRASE, &stored),
        Verification::Matched {
            needs_rehash: false
        }
    );

    let weaker = Passwords::with_parameters(Profile::L1.password_policy(), 7168, 5, 1)
        .expect("7 MiB and five iterations is a valid OWASP option");
    let weak_hash = hash_of(&weaker, PASSPHRASE);
    assert_eq!(
        passwords.verify(PASSPHRASE, &weak_hash),
        Verification::Matched { needs_rehash: true },
        "a hash with older parameters must verify but ask to be replaced"
    );
}

#[test]
fn v11_5_1_salts_come_from_a_csprng_with_at_least_128_bits() {
    let passwords = l1();
    let first = hash_of(&passwords, PASSPHRASE);
    let second = hash_of(&passwords, PASSPHRASE);
    assert_ne!(first, second, "every hash needs a fresh salt");
    let salt = first
        .split('$')
        .nth(4)
        .expect("PHC string has a salt field");
    assert!(
        salt.len() >= 22,
        "a 128-bit salt is 22 base64 characters, got {}: {salt}",
        salt.len()
    );
}
