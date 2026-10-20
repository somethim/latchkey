//! Argon2id password hashing, with a dummy hash for accounts that do not exist.
//!
//! Hashing is deliberately slow and memory-hungry (64 MiB by default). It is pure computation,
//! but run it on a blocking thread and limit how many run at once (latchkey 0.2 ran one at a
//! time) so a burst of sign-ins cannot exhaust memory.
//!
//! ```
//! use latchkey::password::{PasswordHasher, PasswordParams};
//!
//! # fn main() -> Result<(), latchkey::Error> {
//! let mut rng = latchkey::os_rng()?;
//! # let params = PasswordParams::new(64, 1, 1)?;
//! let hasher = PasswordHasher::new(params, &mut rng)?;
//! let stored = hasher.hash_new_password("correct horse battery", &mut rng)?;
//! assert!(hasher.verify("correct horse battery", Some(&stored)));
//! assert!(!hasher.verify("wrong horse battery", Some(&stored)));
//! // An unknown account still costs a full hash, and never verifies.
//! assert!(!hasher.verify("correct horse battery", None));
//! # Ok(())
//! # }
//! ```

use crate::error::{ConfigReason, CryptoReason, InvalidRequestReason};
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::Error;

/// The shortest password [`check_policy`] accepts, in characters.
pub const MIN_LEN: usize = 12;
/// The longest password [`check_policy`] accepts, in characters.
pub const MAX_LEN: usize = 1024;
const SALT_LEN: usize = 16;

/// Argon2id cost parameters, validated on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PasswordParams {
    /// Memory in KiB, iterations (t) and lanes (p).
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when Argon2 rejects the combination.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, Error> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        params.to_argon2()?;
        Ok(params)
    }

    /// Memory cost in KiB.
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism.
    #[must_use]
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    fn to_argon2(self) -> Result<Params, Error> {
        Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|_| Error::Config(ConfigReason::Argon2Parameters))
    }
}

impl Default for PasswordParams {
    /// 64 MiB, t=3, p=2.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 2,
        }
    }
}

/// A stored password hash in PHC string format (`$argon2id$v=19$...`).
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// The PHC string to store.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The PHC string, by value.
    #[must_use]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl PasswordHash {
    /// Accepts an Argon2 PHC string of any variant (`argon2i`, `argon2d`, `argon2id`) and
    /// version, such as one imported from another system. [`PasswordHasher::verify`] checks
    /// it with its own variant and parameters, and [`PasswordHasher::needs_rehash`] is `true`
    /// for anything but this hasher's Argon2id: rehash after the next successful sign-in.
    /// Use `try_from` for latchkey's own stored hashes.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] with [`CryptoReason::StoredPasswordHash`] for anything that is not
    /// an Argon2 PHC string with parameters, salt and hash.
    pub fn from_legacy_argon2(phc: &str) -> Result<Self, Error> {
        parse_argon2(phc, &["argon2i", "argon2d", "argon2id"], None)?;
        Ok(Self(phc.to_owned()))
    }
}

/// Parses `phc` as an Argon2 PHC string of one of `algorithms` (and `version`, if given)
/// with parameters, salt and hash.
fn parse_argon2(phc: &str, algorithms: &[&str], version: Option<u32>) -> Result<(), Error> {
    let invalid = Error::Crypto(CryptoReason::StoredPasswordHash);
    let parsed = argon2::PasswordHash::new(phc).map_err(|_| invalid.clone())?;
    let shaped = algorithms.contains(&parsed.algorithm.as_str())
        && version.is_none_or(|version| parsed.version == Some(version))
        && parsed.salt.is_some()
        && parsed.hash.is_some()
        && Params::try_from(&parsed).is_ok();
    if shaped { Ok(()) } else { Err(invalid) }
}

impl TryFrom<String> for PasswordHash {
    type Error = Error;

    /// Accepts an Argon2id (version 19) PHC string read back from storage, as latchkey
    /// writes them. For other Argon2 variants or versions, see
    /// [`PasswordHash::from_legacy_argon2`].
    fn try_from(phc: String) -> Result<Self, Error> {
        parse_argon2(&phc, &["argon2id"], Some(Version::V0x13.into()))?;
        Ok(Self(phc))
    }
}

impl TryFrom<&str> for PasswordHash {
    type Error = Error;

    fn try_from(phc: &str) -> Result<Self, Error> {
        Self::try_from(phc.to_owned())
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHash(<redacted>)")
    }
}

/// Hashes and verifies passwords with Argon2id under fixed parameters.
///
/// Cheap to clone; holds the parameters and a dummy hash.
#[derive(Clone)]
pub struct PasswordHasher {
    params: Params,
    dummy: PasswordHash,
}

impl std::fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordHasher")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl PasswordHasher {
    /// Builds the hasher and the dummy hash that [`verify`](Self::verify) checks unknown
    /// accounts against. This runs one full hash.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for unusable parameters, [`Error::Crypto`] when hashing fails.
    pub fn new<R: CryptoRng + ?Sized>(params: PasswordParams, rng: &mut R) -> Result<Self, Error> {
        let params = params.to_argon2()?;
        let mut filler = [0u8; 32];
        rng.fill_bytes(&mut filler);
        let dummy = hash_with(&params, &crate::hex(&filler), rng)?;
        filler.zeroize();
        Ok(Self { params, dummy })
    }

    /// Hashes a password with a fresh salt from `rng`, without the length policy (for
    /// importing). Prefer [`hash_new_password`](Self::hash_new_password) for passwords users
    /// choose.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when Argon2 fails.
    pub fn hash<R: CryptoRng + ?Sized>(
        &self,
        password: &str,
        rng: &mut R,
    ) -> Result<PasswordHash, Error> {
        hash_with(&self.params, password, rng)
    }

    /// Checks [`check_policy`], then hashes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `password_too_short` or `password_too_long`, or
    /// [`Error::Crypto`].
    pub fn hash_new_password<R: CryptoRng + ?Sized>(
        &self,
        password: &str,
        rng: &mut R,
    ) -> Result<PasswordHash, Error> {
        check_policy(password)?;
        self.hash(password, rng)
    }

    /// Whether `stored` was made with anything other than this hasher's parameters: another
    /// algorithm or Argon2 version, other memory, iteration or lane counts, or another output
    /// length. Unparseable values need a rehash too.
    ///
    /// Check it after [`verify`](Self::verify) succeeds, while the password is at hand: hash
    /// it again with [`hash`](Self::hash) (not
    /// [`hash_new_password`](Self::hash_new_password), whose length policy an older password
    /// may not meet) and store the new hash in place of the old one. Hashes imported from
    /// another system with weaker parameters, or made before
    /// [`ConfigBuilder::password_params`](crate::ConfigBuilder::password_params) was raised, are upgraded
    /// as their users sign in.
    ///
    /// ```
    /// use latchkey::password::{PasswordHasher, PasswordParams};
    ///
    /// # fn main() -> Result<(), latchkey::Error> {
    /// let mut rng = latchkey::os_rng()?;
    /// let old = PasswordHasher::new(PasswordParams::new(64, 1, 1)?, &mut rng)?;
    /// let stored = old.hash("correct horse battery", &mut rng)?;
    /// assert!(!old.needs_rehash(&stored));
    ///
    /// let current = PasswordHasher::new(PasswordParams::new(128, 2, 1)?, &mut rng)?;
    /// if current.verify("correct horse battery", Some(&stored)) && current.needs_rehash(&stored) {
    ///     let upgraded = current.hash("correct horse battery", &mut rng)?;
    ///     assert!(!current.needs_rehash(&upgraded));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn needs_rehash(&self, stored: &PasswordHash) -> bool {
        let Ok(parsed) = argon2::PasswordHash::new(stored.as_str()) else {
            return true;
        };
        if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str()
            || parsed.version != Some(Version::V0x13.into())
        {
            return true;
        }
        let Ok(params) = Params::try_from(&parsed) else {
            return true;
        };
        let output_len =
            |params: &Params| params.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN);
        params.m_cost() != self.params.m_cost()
            || params.t_cost() != self.params.t_cost()
            || params.p_cost() != self.params.p_cost()
            || output_len(&params) != output_len(&self.params)
    }

    /// Whether `password` matches `stored`.
    ///
    /// With `stored` = `None` (unknown account, or no password set) it still runs a full hash
    /// against the dummy and returns `false`, so timing does not tell known accounts from
    /// unknown ones. Passwords longer than four times [`MAX_LEN`] bytes are not hashed as
    /// given: the dummy is checked instead and the answer is `false`. So is a stored hash
    /// whose own parameters cost more than 1 GiB, 16 passes or 16 lanes (or the hasher's
    /// parameters, if those are higher): Argon2 verifies with the stored parameters, and an
    /// imported or tampered hash must not tie up the server.
    #[must_use]
    pub fn verify(&self, password: &str, stored: Option<&PasswordHash>) -> bool {
        let argon2 = argon2(self.params.clone());
        let too_long = password.len() > MAX_LEN * 4;
        let (candidate, real) = match stored {
            Some(stored) if !too_long && affordable(stored, &self.params) => (stored, true),
            _ => (&self.dummy, false),
        };
        let password = if too_long { "" } else { password };
        let matched = argon2
            .verify_password(password.as_bytes(), candidate.as_str())
            .is_ok();
        matched && real
    }
}

/// The most a stored hash may cost to verify, unless the hasher's own parameters cost more:
/// 1 GiB, 16 passes, 16 lanes. Argon2 verifies with the parameters in the stored string, so
/// an imported or tampered hash could otherwise make one sign-in allocate many gigabytes or
/// run for hours.
const MAX_STORED_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_STORED_ITERATIONS: u32 = 16;
const MAX_STORED_PARALLELISM: u32 = 16;

fn affordable(stored: &PasswordHash, own: &Params) -> bool {
    argon2::PasswordHash::new(stored.as_str())
        .ok()
        .and_then(|parsed| Params::try_from(&parsed).ok())
        .is_some_and(|params| {
            params.m_cost() <= MAX_STORED_MEMORY_KIB.max(own.m_cost())
                && params.t_cost() <= MAX_STORED_ITERATIONS.max(own.t_cost())
                && params.p_cost() <= MAX_STORED_PARALLELISM.max(own.p_cost())
        })
}

fn argon2(params: Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_with<R: CryptoRng + ?Sized>(
    params: &Params,
    password: &str,
    rng: &mut R,
) -> Result<PasswordHash, Error> {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    argon2(params.clone())
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|hash| PasswordHash(hash.to_string()))
        .map_err(|_| Error::Crypto(CryptoReason::PasswordHashing))
}

/// The length policy for new passwords: [`MIN_LEN`] to [`MAX_LEN`] characters.
///
/// # Errors
///
/// [`Error::InvalidRequest`] with `password_too_short` or `password_too_long`.
///
/// ```
/// use latchkey::password::check_policy;
/// assert!(check_policy("short").is_err());
/// assert!(check_policy("twelve chars").is_ok());
/// ```
pub fn check_policy(password: &str) -> Result<(), Error> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(Error::InvalidRequest(
            InvalidRequestReason::PasswordTooShort,
        ));
    }
    if len > MAX_LEN {
        return Err(Error::InvalidRequest(InvalidRequestReason::PasswordTooLong));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn cheap() -> PasswordParams {
        PasswordParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn hashes_verify_and_reject() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let hash = hasher.hash("correct horse battery", &mut rng)?;
        assert!(hash.as_str().starts_with("$argon2id$v=19$m=64,t=1,p=1$"));
        assert!(hasher.verify("correct horse battery", Some(&hash)));
        assert!(!hasher.verify("wrong horse battery", Some(&hash)));
        Ok(())
    }

    #[test]
    fn missing_hash_never_verifies() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        assert!(!hasher.verify("anything at all", None));
        assert!(!hasher.verify("", None));
        Ok(())
    }

    #[test]
    fn oversized_passwords_never_verify() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let long = "x".repeat(MAX_LEN * 4 + 1);
        let hash = hasher.hash(&long, &mut rng)?;
        assert!(!hasher.verify(&long, Some(&hash)));
        Ok(())
    }

    #[test]
    fn salts_differ_per_hash() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let a = hasher.hash("correct horse battery", &mut rng)?;
        let b = hasher.hash("correct horse battery", &mut rng)?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn stored_hashes_parse_and_garbage_does_not() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let hash = hasher.hash("correct horse battery", &mut rng)?;
        let reloaded = PasswordHash::try_from(hash.as_str())?;
        assert!(hasher.verify("correct horse battery", Some(&reloaded)));
        assert!(PasswordHash::try_from("not a hash").is_err());
        assert!(!format!("{hash:?}").contains("argon2id"));
        Ok(())
    }

    #[test]
    fn hashes_under_other_parameters_need_a_rehash() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let current = hasher.hash("correct horse battery", &mut rng)?;
        assert!(!hasher.needs_rehash(&current));
        for params in [
            PasswordParams::new(128, 1, 1)?,
            PasswordParams::new(64, 2, 1)?,
            PasswordParams::new(64, 1, 2)?,
        ] {
            let other = PasswordHasher::new(params, &mut rng)?;
            let stored = other.hash("correct horse battery", &mut rng)?;
            assert!(hasher.needs_rehash(&stored), "{params:?}");
            assert!(!other.needs_rehash(&stored));
        }
        // Same parameters, other algorithm, version or output length.
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let hash32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for phc in [
            format!("$argon2i$v=19$m=64,t=1,p=1${salt}${hash32}"),
            format!("$argon2id$v=16$m=64,t=1,p=1${salt}${hash32}"),
            format!("$argon2id$m=64,t=1,p=1${salt}${hash32}"),
            format!("$argon2id$v=19$m=64,t=1,p=1${salt}$AAAAAAAAAAAAAAAAAAAAAA"),
        ] {
            let stored = PasswordHash::from_legacy_argon2(&phc)?;
            assert!(hasher.needs_rehash(&stored), "{phc}");
        }
        let same = PasswordHash::try_from(format!("$argon2id$v=19$m=64,t=1,p=1${salt}${hash32}"))?;
        assert!(!hasher.needs_rehash(&same));
        Ok(())
    }

    #[test]
    fn only_argon2id_loads_as_latchkeys_own_and_legacy_argon2_explicitly() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let salt = [7u8; 16];
        let legacy = argon2::Argon2::new(
            Algorithm::Argon2i,
            Version::V0x10,
            Params::new(64, 1, 1, None).map_err(|_| Error::Rng)?,
        )
        .hash_password_with_salt(b"correct horse battery", &salt)
        .map_err(|_| Error::Rng)?
        .to_string();
        assert!(PasswordHash::try_from(legacy.as_str()).is_err());
        let imported = PasswordHash::from_legacy_argon2(&legacy)?;
        assert!(hasher.verify("correct horse battery", Some(&imported)));
        assert!(!hasher.verify("wrong horse battery", Some(&imported)));
        assert!(hasher.needs_rehash(&imported));
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let hash32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for bad in [
            format!("$scrypt$ln=15,r=8,p=1${salt}${hash32}"),
            format!("$argon2id$v=19$m=64,t=1,p=1${salt}"),
            "$2b$12$abcdefghijklmnopqrstuuJ4n7nVvC0rI7vJkQe2Yt8cG1aWm6r2".to_owned(),
            "not a hash".to_owned(),
        ] {
            assert!(PasswordHash::try_from(bad.as_str()).is_err(), "{bad}");
            assert!(PasswordHash::from_legacy_argon2(&bad).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn hashes_too_costly_to_verify_are_refused_without_running_them() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let hasher = PasswordHasher::new(cheap(), &mut rng)?;
        let salt = "c29tZXNhbHRzb21lc2FsdA";
        let hash32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        for params in [
            "m=4194304,t=1,p=1",
            "m=64,t=4294967295,p=1",
            "m=8192,t=1,p=1024",
        ] {
            let stored =
                PasswordHash::try_from(format!("$argon2id$v=19${params}${salt}${hash32}"))?;
            assert!(
                !hasher.verify("correct horse battery", Some(&stored)),
                "{params}"
            );
            assert!(hasher.needs_rehash(&stored));
        }
        Ok(())
    }

    #[test]
    fn default_params_match_policy() {
        let params = PasswordParams::default();
        assert_eq!(
            (
                params.memory_kib(),
                params.iterations(),
                params.parallelism()
            ),
            (65536, 3, 2)
        );
        assert!(PasswordParams::new(0, 0, 0).is_err());
    }

    #[test]
    fn length_policy() {
        assert!(check_policy("short").is_err());
        assert!(check_policy("twelve chars").is_ok());
        assert!(check_policy(&"x".repeat(1025)).is_err());
    }
}
