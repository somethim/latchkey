//! Identifier newtypes, so a user id cannot be passed where a session id is meant.

use rand_core::CryptoRng;
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $name(Uuid);

        impl $name {
            /// A random version 4 UUID drawn from `rng`.
            pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
                let mut bytes = [0u8; 16];
                rng.fill_bytes(&mut bytes);
                Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
            }

            /// Wraps an id the app already has.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// The UUID inside.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// The UUID inside, by value.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Uuid {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(raw: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(raw).map(Self)
            }
        }
    };
}

id_type!(
    /// An account. Passkeys carry it as their `WebAuthn` user handle.
    UserId
);
id_type!(
    /// A session, for listing and revoking sessions; not a secret.
    SessionId
);
id_type!(
    /// A stored passkey, used to bind its sealed data to its row.
    PasskeyId
);
id_type!(
    /// A pending passkey ceremony, for the app to store its state under.
    CeremonyId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_are_v4_and_round_trip() -> Result<(), uuid::Error> {
        let mut rng = crate::test_rng();
        let id = UserId::random(&mut rng);
        assert_eq!(id.as_uuid().get_version_num(), 4);
        assert_eq!(id.to_string().parse::<UserId>()?, id);
        assert_ne!(UserId::random(&mut rng), id);
        Ok(())
    }
}
