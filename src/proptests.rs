#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::crypto::{TOKEN_BYTES, issue_token, sha256, token_hash};
use crate::extract::session_cookie;
use crate::limiter::{FailureLog, RateLimiter};
use crate::seal::{Aad, DataKey};

const START: i64 = 1_800_000_000;

fn at(offset: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(START + offset).unwrap()
}

fn cookie_headers(raw: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(raw) {
        headers.insert(header::COOKIE, value);
    }
    headers
}

proptest! {
    #[test]
    fn token_hash_accepts_exactly_the_32_byte_base64url_tokens(raw in ".{0,80}") {
        let decodes_to_a_token = URL_SAFE_NO_PAD
            .decode(raw.trim())
            .is_ok_and(|bytes| bytes.len() == TOKEN_BYTES);
        prop_assert_eq!(token_hash(&raw).is_some(), decodes_to_a_token);
    }

    #[test]
    fn any_32_bytes_make_a_token_whose_hash_ignores_surrounding_whitespace(
        bytes in proptest::array::uniform32(any::<u8>()),
        before in "[ \t\r\n]{0,3}",
        after in "[ \t\r\n]{0,3}",
    ) {
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let padded = format!("{before}{token}{after}");
        prop_assert_eq!(token_hash(&padded), Some(sha256(token.as_bytes())));
    }

    #[test]
    fn issued_tokens_hash_to_what_is_stored(_round in 0u8..16) {
        let issued = issue_token();
        prop_assert_eq!(token_hash(&issued.token), Some(issued.hash));
    }

    #[test]
    fn cookie_parsing_never_panics(raw in "[ -~]{0,200}", name in "[ -~]{0,30}") {
        let _ = session_cookie(&cookie_headers(&raw), &name);
    }

    #[test]
    fn the_named_cookie_is_found_among_others(
        others in proptest::collection::vec(("[A-Za-z][A-Za-z_-]{0,20}", "[A-Za-z0-9_-]{0,44}"), 0..6),
        position in 0usize..7,
        value in "[A-Za-z0-9_-]{1,44}",
    ) {
        let name = "__Host-latchkey";
        let mut pairs: Vec<String> = others
            .iter()
            .filter(|(other, _)| other != name)
            .map(|(other, v)| format!("{other}={v}"))
            .collect();
        pairs.push(format!("__Host-latchkey_device={}", "d".repeat(43)));
        let position = position.min(pairs.len());
        pairs.insert(position, format!("{name}={value}"));
        let headers = cookie_headers(&pairs.join("; "));
        prop_assert_eq!(session_cookie(&headers, name), Some(value));
        prop_assert_eq!(
            session_cookie(&headers, "__Host-latchkey_device"),
            Some("d".repeat(43))
        );
    }

    #[test]
    fn rate_limiter_allows_exactly_the_limit_per_window(
        limit in 0u32..40,
        hits in 0u32..80,
        second in 0i64..60,
    ) {
        let limiter = RateLimiter::default();
        let window_start = START - START.rem_euclid(60);
        let now = OffsetDateTime::from_unix_timestamp(window_start + second).unwrap();
        for hit in 1..=hits {
            let verdict = limiter.hit("k", limit, now);
            if hit <= limit {
                prop_assert_eq!(verdict, None);
            } else {
                let wait = verdict.unwrap();
                prop_assert!((1..=60).contains(&wait));
                prop_assert_eq!(i64::try_from(wait).unwrap(), (60 - second).max(1));
            }
        }
        prop_assert_eq!(limiter.hit("other", limit.max(1), now), None);
        let next_window = OffsetDateTime::from_unix_timestamp(window_start + 60).unwrap();
        prop_assert_eq!(limiter.hit("k", limit.max(1), next_window), None);
    }

    #[test]
    fn rate_limiter_matches_a_fixed_window_model(
        limit in 1u32..6,
        steps in proptest::collection::vec((0usize..3, 0i64..40), 1..120),
    ) {
        let limiter = RateLimiter::default();
        let mut model: HashMap<usize, (i64, u32)> = HashMap::new();
        let mut offset = 0;
        for (key, advance) in steps {
            offset += advance;
            let now = START + offset;
            let window = now.div_euclid(60);
            let entry = model.entry(key).or_insert((window, 0));
            if entry.0 != window {
                *entry = (window, 0);
            }
            entry.1 += 1;
            let blocked = limiter.hit(&format!("k{key}"), limit, at(offset)).is_some();
            prop_assert_eq!(blocked, entry.1 > limit);
        }
    }

    #[test]
    fn failure_log_matches_a_sliding_window_model(
        max in 1u32..12,
        window_secs in 60i64..1800,
        steps in proptest::collection::vec((0usize..3, 0i64..300, any::<bool>()), 1..150),
    ) {
        let log = FailureLog::default();
        let window = Duration::seconds(window_secs);
        let mut model: HashMap<usize, Vec<i64>> = HashMap::new();
        let mut offset = 0;
        for (key, advance, record) in steps {
            offset += advance;
            let now = START + offset;
            let name = format!("k{key}");
            let recent: Vec<i64> = model
                .get(&key)
                .map(|all| all.iter().copied().filter(|t| t + window_secs > now).collect())
                .unwrap_or_default();
            let expected = (recent.len() >= max as usize).then(|| {
                let mut newest_first = recent.clone();
                newest_first.sort_unstable_by(|a, b| b.cmp(a));
                let oldest_counted = newest_first[max as usize - 1];
                u64::try_from(oldest_counted + window_secs - now).unwrap().max(1)
            });
            let blocked = log.blocked(&name, max, window, at(offset));
            prop_assert_eq!(blocked, expected);
            if record && blocked.is_none() {
                log.record(&name, max, window, at(offset));
                model.entry(key).or_default().push(now);
            }
            let accepted_in_window = model
                .get(&key)
                .map(|all| all.iter().filter(|t| **t + window_secs > now).count())
                .unwrap_or(0);
            prop_assert!(accepted_in_window <= max as usize);
        }
    }

    #[test]
    fn sealed_values_open_only_with_the_same_key_and_binding(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        key in proptest::array::uniform32(any::<u8>()),
        flip in any::<prop::sample::Index>(),
    ) {
        let data_key = DataKey::new(&key);
        let user = Uuid::new_v4();
        let sealed = data_key.seal_bytes(&Aad::Totp { user }, &plaintext).unwrap();
        prop_assert_eq!(
            data_key.open_bytes(&Aad::Totp { user }, &sealed),
            Some(plaintext.clone())
        );
        let stranger = Aad::Totp { user: Uuid::new_v4() };
        prop_assert!(data_key.open_bytes(&stranger, &sealed).is_none());
        let mut tampered = sealed.clone();
        let index = flip.index(tampered.len());
        tampered[index] ^= 0x01;
        let owner = Aad::Totp { user };
        prop_assert!(data_key.open_bytes(&owner, &tampered).is_none());
    }

    #[test]
    fn opening_garbage_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..128),
        text in ".{0,128}",
    ) {
        let data_key = DataKey::new(&[3; 32]);
        let aad = Aad::Passkey { user: Uuid::nil(), passkey: Uuid::nil() };
        prop_assert!(data_key.open_bytes(&aad, &bytes).is_none());
        prop_assert!(data_key.open_text(&aad, &text).is_none());
        let prefixed = format!("lk1:{text}");
        prop_assert!(data_key.open_text(&aad, &prefixed).is_none());
    }

    #[test]
    fn request_bodies_never_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        crate::routes::parse_bodies(&bytes);
    }

    #[test]
    fn request_bodies_never_panic_on_json_shaped_input(
        token in ".{0,64}",
        email in ".{0,64}",
        password in ".{0,64}",
        code in ".{0,16}",
        name in proptest::option::of(".{0,200}"),
    ) {
        let body = serde_json::json!({
            "token": token,
            "email": email,
            "password": password,
            "code": code,
            "name": name,
            "display_name": name,
        });
        crate::routes::parse_bodies(body.to_string().as_bytes());
    }
}
