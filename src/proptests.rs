use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use time::{Duration, OffsetDateTime};

use crate::account::{Lockout, LockoutPolicy};
use crate::http::find_cookie;
use crate::ids::UserId;
use crate::limits::{FailureWindow, FixedWindow, RateLimiter};
use crate::seal::{Aad, DataKey};
use crate::token::{self, TOKEN_BYTES, TokenHash, sha256};
use crate::totp::{self, TotpSecret, TotpStep};

const START: i64 = 1_800_000_000;

fn at(offset: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(START + offset).unwrap()
}

proptest! {
    #[test]
    fn token_hash_accepts_exactly_the_32_byte_base64url_tokens(raw in ".{0,80}") {
        let decodes_to_a_token = URL_SAFE_NO_PAD
            .decode(raw.trim())
            .is_ok_and(|bytes| bytes.len() == TOKEN_BYTES);
        prop_assert_eq!(TokenHash::of(&raw).is_some(), decodes_to_a_token);
    }

    #[test]
    fn any_32_bytes_make_a_token_whose_hash_ignores_surrounding_whitespace(
        bytes in proptest::array::uniform32(any::<u8>()),
        before in "[ \t\r\n]{0,3}",
        after in "[ \t\r\n]{0,3}",
    ) {
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let padded = format!("{before}{token}{after}");
        prop_assert_eq!(
            TokenHash::of(&padded),
            Some(TokenHash::from_bytes(sha256(token.as_bytes())))
        );
    }

    #[test]
    fn issued_tokens_hash_to_what_is_stored(seed in any::<u64>()) {
        use rand::SeedableRng;
        let issued = token::issue(&mut rand::rngs::StdRng::seed_from_u64(seed));
        prop_assert_eq!(TokenHash::of(issued.token.expose_secret()), Some(issued.hash));
        prop_assert!(issued.hash.verify(issued.token.expose_secret()));
    }

    #[test]
    fn cookie_parsing_never_panics(raw in "[ -~]{0,200}", name in "[ -~]{0,30}") {
        let _ = find_cookie([raw.as_str()], &name);
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
        let header = pairs.join("; ");
        prop_assert_eq!(find_cookie([header.as_str()], name), Some(value.as_str()));
        let device = "d".repeat(43);
        prop_assert_eq!(
            find_cookie([header.as_str()], "__Host-latchkey_device"),
            Some(device.as_str())
        );
    }

    #[test]
    fn rate_limiter_allows_exactly_the_limit_per_window(
        limit in 0u32..40,
        hits in 0u32..80,
        second in 0i64..60,
    ) {
        let mut limiter = RateLimiter::per_minute(limit);
        let window_start = START - START.rem_euclid(60);
        let now = OffsetDateTime::from_unix_timestamp(window_start + second).unwrap();
        for hit in 1..=hits {
            let verdict = limiter.check("k", now);
            if hit <= limit {
                prop_assert!(verdict.is_ok());
            } else {
                let wait = verdict.unwrap_err().retry_after_secs().unwrap();
                prop_assert_eq!(i64::try_from(wait).unwrap(), (60 - second).max(1));
            }
        }
        let mut fresh = RateLimiter::per_minute(limit.max(1));
        prop_assert!(fresh.check("other", now).is_ok());
        let next_window = OffsetDateTime::from_unix_timestamp(window_start + 60).unwrap();
        prop_assert!(limiter.check("k", next_window).is_ok() || limit == 0);
    }

    #[test]
    fn rate_limiter_matches_a_fixed_window_model(
        limit in 1u32..6,
        steps in proptest::collection::vec((0usize..3, 0i64..40), 1..120),
    ) {
        let mut limiter = RateLimiter::per_minute(limit);
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
            let blocked = limiter.check(&format!("k{key}"), at(offset)).is_err();
            prop_assert_eq!(blocked, entry.1 > limit);
        }
    }

    #[test]
    fn fixed_windows_round_trip_their_state(limit in 1u32..5, hits in 0u32..10) {
        let mut counter = FixedWindow::default();
        let mut refused = 0;
        for _ in 0..hits {
            if counter.hit(limit, Duration::MINUTE, at(0)).is_err() {
                refused += 1;
            }
        }
        prop_assert_eq!(refused, hits.saturating_sub(limit));
    }

    #[test]
    fn failure_window_matches_a_sliding_window_model(
        max in 1u32..12,
        window_secs in 60i64..1800,
        steps in proptest::collection::vec((0usize..3, 0i64..300, any::<bool>()), 1..150),
    ) {
        let window = Duration::seconds(window_secs);
        let mut logs: HashMap<usize, FailureWindow> = HashMap::new();
        let mut model: HashMap<usize, Vec<i64>> = HashMap::new();
        let mut offset = 0;
        for (key, advance, record) in steps {
            offset += advance;
            let now = START + offset;
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
            let log = logs.entry(key).or_default();
            let blocked = log.blocked(max, window, at(offset));
            prop_assert_eq!(blocked, expected);
            if record && blocked.is_none() {
                log.record(max, window, at(offset));
                model.entry(key).or_default().push(now);
            }
        }
    }

    #[test]
    fn lockout_locks_on_every_threshold_and_never_beyond_max(failures in 1u32..200) {
        let policy = LockoutPolicy::default();
        let mut state = Lockout::default();
        let mut locks = 0;
        for i in 0..failures {
            let (next, lock) = state.after_failure(&policy, at(i64::from(i)));
            if let Some(lock) = lock {
                locks += 1;
                prop_assert!(lock >= policy.base && lock <= policy.max);
                prop_assert_eq!(next.locked_until, Some(at(i64::from(i)) + lock));
                prop_assert!(next.check(at(i64::from(i))).is_err());
            }
            state = next;
        }
        prop_assert_eq!(locks, failures / policy.threshold);
        prop_assert_eq!(state.failures, failures);
    }

    #[test]
    fn totp_never_accepts_a_step_at_or_before_the_last(
        offset in 0i64..100_000,
        back in 0i64..3,
        last_delta in -2i64..3,
    ) {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(offset);
        let code_time = now - Duration::seconds(back * 30);
        let code = secret.code_at(code_time).unwrap();
        let current = u64::try_from(now.unix_timestamp() / 30).unwrap();
        let last = TotpStep::new(current.saturating_add_signed(last_delta));
        if let Ok(step) = totp::verify(&secret, &code, Some(last), now) {
            prop_assert!(step > last);
        }
    }

    #[test]
    fn sealed_values_open_only_with_the_same_key_and_binding(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        key in proptest::array::uniform32(any::<u8>()),
        flip in any::<prop::sample::Index>(),
    ) {
        let mut rng = crate::test_rng();
        let data_key = DataKey::new(&key);
        let user = UserId::random(&mut rng);
        let sealed = data_key.seal_bytes(&mut rng, &Aad::totp(user), &plaintext).unwrap();
        prop_assert_eq!(
            data_key.open_bytes(&Aad::totp(user), &sealed),
            Some(plaintext.clone())
        );
        let stranger = Aad::totp(UserId::random(&mut rng));
        prop_assert!(data_key.open_bytes(&stranger, &sealed).is_none());
        let mut tampered = sealed.clone();
        let index = flip.index(tampered.len());
        tampered[index] ^= 0x01;
        prop_assert!(data_key.open_bytes(&Aad::totp(user), &tampered).is_none());
    }

    #[test]
    fn opening_garbage_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..128),
        text in ".{0,128}",
    ) {
        let data_key = DataKey::new(&[3; 32]);
        let aad = Aad::app("x");
        prop_assert!(data_key.open_bytes(&aad, &bytes).is_none());
        prop_assert!(data_key.open_text(&aad, &text).is_none());
        let prefixed = format!("lk1:{text}");
        prop_assert!(data_key.open_text(&aad, &prefixed).is_none());
    }

    #[test]
    fn untrusted_text_never_panics_the_parsers(text in ".{0,300}") {
        let _ = crate::recovery::RecoveryCodeHash::of(&text);
        let _ = crate::account::Email::parse(&text);
        let _ = crate::password::check_policy(&text);
        let _ = crate::http::client_ip(None, [text.as_str()], true);
        let _ = text.parse::<crate::session::SignInMethod>();
        let _ = crate::flow::invite::optional_name(Some(text.clone()));
        let _ = crate::password::PasswordHash::try_from(text.as_str());
        let secret = TotpSecret::random(&mut crate::test_rng());
        let _ = totp::verify(&secret, &text, None, at(0));
    }
}
