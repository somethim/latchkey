use std::sync::Arc;

use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;

use crate::config::PasswordParams;
use crate::crypto::{hex, random_bytes};
use crate::error::Error;

pub(crate) const MIN_LEN: usize = 12;
pub(crate) const MAX_LEN: usize = 1024;

/// Argon2id with one hashing slot: concurrent sign-ins queue instead of exhausting memory.
#[derive(Clone)]
pub(crate) struct Hasher {
    params: Params,
    slot: Arc<Semaphore>,
    dummy: Arc<str>,
}

impl Hasher {
    pub(crate) async fn new(params: PasswordParams) -> Result<Self, Error> {
        let params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            None,
        )
        .map_err(|_| Error::Config("argon2 parameters"))?;
        let mut hasher = Self {
            params,
            slot: Arc::new(Semaphore::new(1)),
            dummy: Arc::from(""),
        };
        let dummy = hasher.hash(hex(&random_bytes::<32>())).await?;
        hasher.dummy = Arc::from(dummy);
        Ok(hasher)
    }

    fn argon2(params: Params) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    pub(crate) async fn hash(&self, password: String) -> Result<String, Error> {
        let _slot = self.slot.acquire().await.map_err(Error::internal)?;
        let params = self.params.clone();
        tokio::task::spawn_blocking(move || {
            Self::argon2(params)
                .hash_password(password.as_bytes())
                .map(|hash| hash.to_string())
                .map_err(Error::internal)
        })
        .await
        .map_err(Error::internal)?
    }

    /// Runs the full hash even when there is no stored hash, so timing does not tell
    /// known accounts from unknown ones.
    pub(crate) async fn verify(&self, password: &str, stored: Option<&str>) -> Result<bool, Error> {
        let _slot = self.slot.acquire().await.map_err(Error::internal)?;
        let params = self.params.clone();
        let is_real = stored.is_some();
        let stored = stored.map_or_else(|| self.dummy.to_string(), str::to_owned);
        let password = password.to_owned();
        let matched = tokio::task::spawn_blocking(move || {
            Self::argon2(params)
                .verify_password(password.as_bytes(), stored.as_str())
                .is_ok()
        })
        .await
        .map_err(Error::internal)?;
        Ok(matched && is_real)
    }
}

pub(crate) fn check_policy(password: &str) -> Result<(), Error> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(Error::InvalidRequest("password_too_short"));
    }
    if len > MAX_LEN {
        return Err(Error::InvalidRequest("password_too_long"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cheap() -> PasswordParams {
        PasswordParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[tokio::test]
    async fn hashes_verify_and_reject() {
        let hasher = Hasher::new(cheap()).await.unwrap();
        let hash = hasher.hash("correct horse battery".into()).await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(
            hasher
                .verify("correct horse battery", Some(&hash))
                .await
                .unwrap()
        );
        assert!(
            !hasher
                .verify("wrong horse battery", Some(&hash))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn missing_hash_never_verifies() {
        let hasher = Hasher::new(cheap()).await.unwrap();
        assert!(!hasher.verify("anything at all", None).await.unwrap());
    }

    #[test]
    fn default_params_match_policy() {
        let params = PasswordParams::default();
        assert_eq!(
            (params.memory_kib, params.iterations, params.parallelism),
            (65536, 3, 2)
        );
    }

    #[test]
    fn length_policy() {
        assert!(check_policy("short").is_err());
        assert!(check_policy("twelve chars").is_ok());
        assert!(check_policy(&"x".repeat(1025)).is_err());
    }
}
