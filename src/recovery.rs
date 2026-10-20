use crate::crypto::{random_bytes, sha256};

pub(crate) const COUNT: usize = 10;
const ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz023456789";
const GROUPS: usize = 3;
const GROUP_LEN: usize = 4;
const HASH_PREFIX: &[u8] = b"latchkey-recovery:";

pub(crate) fn generate() -> Vec<String> {
    (0..COUNT).map(|_| one()).collect()
}

fn one() -> String {
    let bytes = random_bytes::<{ GROUPS * GROUP_LEN }>();
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
        .collect();
    chars
        .chunks(GROUP_LEN)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

pub(crate) fn normalize(code: &str) -> Option<String> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let valid =
        cleaned.len() == GROUPS * GROUP_LEN && cleaned.bytes().all(|b| ALPHABET.contains(&b));
    valid.then_some(cleaned)
}

pub(crate) fn hash(code: &str) -> Option<Vec<u8>> {
    let normalized = normalize(code)?;
    let mut input = HASH_PREFIX.to_vec();
    input.extend_from_slice(normalized.as_bytes());
    Some(sha256(&input))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn issues_ten_distinct_codes_that_hash() {
        let codes = generate();
        assert_eq!(codes.len(), 10);
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 10);
        for code in &codes {
            assert_eq!(code.len(), 14);
            assert!(hash(code).is_some());
        }
    }

    #[test]
    fn formatting_does_not_change_the_hash() {
        let code = generate().remove(0);
        let shouted = code.to_uppercase().replace('-', " ");
        assert_eq!(hash(&code), hash(&shouted));
    }

    #[test]
    fn rejects_garbage() {
        assert!(hash("123456").is_none());
        assert!(hash("iiii-iiii-iiii").is_none());
    }
}
