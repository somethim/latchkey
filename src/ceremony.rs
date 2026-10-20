use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

const TTL: Duration = Duration::minutes(5);
const MAX_PENDING: usize = 10_000;

pub(crate) enum Ceremony {
    Register {
        session: Uuid,
        user: Uuid,
        name: String,
        state: PasskeyRegistration,
    },
    /// Second factor after a password, or a step-up, for a known user.
    Verify {
        session: Uuid,
        user: Uuid,
        state: PasskeyAuthentication,
    },
    Discoverable {
        state: DiscoverableAuthentication,
    },
}

#[derive(Default)]
pub(crate) struct Ceremonies {
    pending: Mutex<HashMap<Uuid, (OffsetDateTime, Ceremony)>>,
}

impl Ceremonies {
    pub(crate) fn insert(&self, ceremony: Ceremony, now: OffsetDateTime) -> Uuid {
        let id = Uuid::new_v4();
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.retain(|_, (expires, _)| *expires > now);
        if pending.len() >= MAX_PENDING
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, (expires, _))| *expires)
                .map(|(id, _)| *id)
        {
            pending.remove(&oldest);
        }
        pending.insert(id, (now.saturating_add(TTL), ceremony));
        id
    }

    /// Single use: the ceremony is removed whether or not it is still valid.
    pub(crate) fn take(&self, id: Uuid, now: OffsetDateTime) -> Option<Ceremony> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (expires, ceremony) = pending.remove(&id)?;
        (expires > now).then_some(ceremony)
    }
}
