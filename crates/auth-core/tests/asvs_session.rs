//! ASVS conformance tests for session management.
//!
//! Every test name carries the requirement it proves, so `scripts/asvs_gate.py`
//! can match it to a row in `security/asvs-matrix.csv`.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use tesra_auth_core::clock::FixedClock;
use tesra_auth_core::session::TOKEN_BYTES;
use tesra_auth_core::store::MemorySessionStore;
use tesra_auth_core::{Profile, SessionStore as _, SessionToken, Sessions, UserId};
use time::Duration;

fn sessions_for(profile: Profile) -> (Sessions<MemorySessionStore>, Arc<FixedClock>) {
    let clock = Arc::new(FixedClock::epoch());
    let sessions = Sessions::new(MemorySessionStore::new(), profile.session_policy())
        .with_clock(clock.clone());
    (sessions, clock)
}

#[tokio::test]
async fn v7_2_1_tokens_are_only_valid_when_the_backend_holds_the_session() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let (token, _) = sessions.start(UserId::new(), None).await.unwrap();
    assert!(sessions.verify(&token).await.unwrap().is_some());

    // A well-formed token the backend never issued is not a session.
    let forged = SessionToken::generate();
    assert!(sessions.verify(&forged).await.unwrap().is_none());
    // Nor is a value that isn't even shaped like a token.
    assert!(SessionToken::parse("not-a-session-token").is_none());
}

#[tokio::test]
async fn v7_2_2_every_session_gets_a_freshly_generated_token() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let user = UserId::new();
    let (first, _) = sessions.start(user, None).await.unwrap();
    let (second, _) = sessions.start(user, None).await.unwrap();
    assert_ne!(first.expose(), second.expose(), "tokens must be dynamic");
    assert!(
        !first.expose().contains(&user.to_string()),
        "a token must not be derived from the account it belongs to"
    );
}

#[tokio::test]
async fn v7_2_3_tokens_carry_256_bits_of_entropy_and_are_stored_hashed() {
    assert_eq!(TOKEN_BYTES, 32, "ASVS V7.2.3 asks for at least 128 bits");
    let mut seen = HashSet::new();
    for _ in 0..256 {
        let token = SessionToken::generate();
        let mut decoded = [0_u8; TOKEN_BYTES];
        Base64UrlUnpadded::decode(token.expose(), &mut decoded).expect("token is base64url");
        assert!(seen.insert(decoded), "tokens must be unique");
    }

    let (sessions, _clock) = sessions_for(Profile::L2);
    let (token, session) = sessions.start(UserId::new(), None).await.unwrap();
    assert_ne!(
        session.id.as_str(),
        token.expose(),
        "the token itself must not be the storage key"
    );
    let stored = sessions
        .store()
        .get(&token.id())
        .await
        .unwrap()
        .expect("the session is stored");
    assert!(
        !format!("{stored:?}").contains(token.expose()),
        "no plaintext token may reach storage"
    );
}

#[tokio::test]
async fn v7_2_4_authenticating_again_issues_a_new_token_and_ends_the_old_one() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let user = UserId::new();
    let (first, _) = sessions.start(user, None).await.unwrap();
    let (second, _) = sessions.rotate(&first, user, None).await.unwrap();
    assert_ne!(first.expose(), second.expose());
    assert!(
        sessions.verify(&first).await.unwrap().is_none(),
        "the previous token must stop working"
    );
    assert!(sessions.verify(&second).await.unwrap().is_some());
}

#[tokio::test]
async fn v7_3_1_sessions_end_once_they_have_been_idle_too_long() {
    let (sessions, clock) = sessions_for(Profile::L2);
    let idle = sessions
        .policy()
        .idle_timeout
        .expect("L2 sets an idle timeout");
    let (token, _) = sessions.start(UserId::new(), None).await.unwrap();

    // Use it inside the window and it stays alive.
    clock.advance(Duration::minutes(30));
    assert!(sessions.verify(&token).await.unwrap().is_some());
    clock.advance(Duration::minutes(30));
    assert!(sessions.verify(&token).await.unwrap().is_some());

    // Go quiet for longer than the window and it is gone.
    clock.advance(Duration::try_from(idle).unwrap() + Duration::seconds(1));
    assert!(sessions.verify(&token).await.unwrap().is_none());
    assert!(
        sessions.store().is_empty(),
        "an expired session must be deleted from the backend"
    );
}

#[tokio::test]
async fn v7_3_2_sessions_end_at_the_absolute_lifetime_even_when_in_use() {
    let (sessions, clock) = sessions_for(Profile::L2);
    let (token, session) = sessions.start(UserId::new(), None).await.unwrap();
    assert_eq!(session.expires_at - session.started_at, Duration::hours(24));

    // Active every half hour for just under a day.
    for _ in 0..47 {
        clock.advance(Duration::minutes(30));
        assert!(sessions.verify(&token).await.unwrap().is_some());
    }
    clock.advance(Duration::minutes(30));
    assert!(
        sessions.verify(&token).await.unwrap().is_none(),
        "the absolute lifetime must end an active session"
    );
}

#[tokio::test]
async fn v7_4_1_ending_a_session_stops_its_token_from_working() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let (token, _) = sessions.start(UserId::new(), None).await.unwrap();
    sessions.end(&token).await.unwrap();
    assert!(sessions.verify(&token).await.unwrap().is_none());
    assert!(sessions.store().is_empty());
}

#[tokio::test]
async fn v7_4_2_ending_an_account_ends_every_one_of_its_sessions() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let user = UserId::new();
    let other = UserId::new();
    let (laptop, _) = sessions.start(user, None).await.unwrap();
    let (phone, _) = sessions.start(user, None).await.unwrap();
    let (untouched, _) = sessions.start(other, None).await.unwrap();

    assert_eq!(sessions.end_all_for(user).await.unwrap(), 2);
    assert!(sessions.verify(&laptop).await.unwrap().is_none());
    assert!(sessions.verify(&phone).await.unwrap().is_none());
    assert!(
        sessions.verify(&untouched).await.unwrap().is_some(),
        "other accounts keep their sessions"
    );
}

#[tokio::test]
async fn v7_4_3_a_credential_change_can_end_every_other_session() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let user = UserId::new();
    let (current, _) = sessions
        .start(user, Some("Firefox on Linux".to_owned()))
        .await
        .unwrap();
    let (elsewhere, _) = sessions
        .start(user, Some("Safari on iOS".to_owned()))
        .await
        .unwrap();

    assert_eq!(sessions.end_others(&current, user).await.unwrap(), 1);
    assert!(sessions.verify(&current).await.unwrap().is_some());
    assert!(sessions.verify(&elsewhere).await.unwrap().is_none());
}

#[tokio::test]
async fn v7_4_5_sessions_can_be_ended_for_one_account_or_for_everyone() {
    let (sessions, _clock) = sessions_for(Profile::L2);
    let first = UserId::new();
    let second = UserId::new();
    let (one, _) = sessions.start(first, None).await.unwrap();
    let (two, _) = sessions.start(second, None).await.unwrap();

    assert_eq!(sessions.end_all_for(first).await.unwrap(), 1);
    assert!(sessions.verify(&one).await.unwrap().is_none());

    assert_eq!(sessions.end_everything().await.unwrap(), 1);
    assert!(sessions.verify(&two).await.unwrap().is_none());
}

#[tokio::test]
async fn v7_5_2_an_account_can_list_its_sessions_without_exposing_tokens() {
    let (sessions, clock) = sessions_for(Profile::L2);
    let user = UserId::new();
    let (laptop, _) = sessions
        .start(user, Some("Firefox on Linux".to_owned()))
        .await
        .unwrap();
    clock.advance(Duration::minutes(5));
    let (phone, _) = sessions
        .start(user, Some("Safari on iOS".to_owned()))
        .await
        .unwrap();

    let listed = sessions.list_for(user).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed.first().and_then(|session| session.device.as_deref()),
        Some("Safari on iOS"),
        "the most recently used session comes first"
    );
    let rendered = format!("{listed:?}");
    assert!(
        !rendered.contains(laptop.expose()) && !rendered.contains(phone.expose()),
        "a session list must never carry tokens"
    );
}
