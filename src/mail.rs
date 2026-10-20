use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Notify;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    /// First-open owner setup.
    Setup,
    SignInLink,
    Invite,
}

/// What to send; wording and layout are up to the app's [`Mailer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub kind: MailKind,
    pub to: String,
    pub link: Url,
    pub expires_at: OffsetDateTime,
}

impl Mail {
    pub fn subject(&self) -> &'static str {
        match self.kind {
            MailKind::Setup => "Set up your sign-in",
            MailKind::SignInLink => "Your sign-in link",
            MailKind::Invite => "You have been invited",
        }
    }

    pub fn text(&self) -> String {
        let action = match self.kind {
            MailKind::Setup => "set up your sign-in",
            MailKind::SignInLink => "sign in",
            MailKind::Invite => "accept the invitation and set up your sign-in",
        };
        format!(
            "Open this link to {action}:\n\n{}\n\nIt works once and expires at {}. If you did not ask for it, ignore this email.\n",
            self.link,
            self.expires_at
                .replace_nanosecond(0)
                .unwrap_or(self.expires_at)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mail delivery failed: {0}")]
pub struct MailError(pub String);

#[async_trait]
pub trait Mailer: Send + Sync + 'static {
    async fn send(&self, mail: Mail) -> Result<(), MailError>;
}

/// Keeps every mail in memory instead of sending it.
#[derive(Debug, Default)]
pub struct TestMailer {
    sent: Mutex<Vec<Mail>>,
    notify: Notify,
}

impl TestMailer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent(&self) -> Vec<Mail> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Mails go out on a background task; this waits up to `timeout` for the `n`-th one.
    pub async fn wait_for(&self, n: usize, timeout: Duration) -> Option<Mail> {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.notify.notified();
                if let Some(mail) = self.sent().get(n.saturating_sub(1)) {
                    return mail.clone();
                }
                notified.await;
            }
        })
        .await
        .ok()
    }

    pub fn token_of(mail: &Mail) -> Option<String> {
        mail.link
            .query_pairs()
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
    }
}

#[async_trait]
impl Mailer for TestMailer {
    async fn send(&self, mail: Mail) -> Result<(), MailError> {
        match self.sent.lock() {
            Ok(mut sent) => sent.push(mail),
            Err(poisoned) => poisoned.into_inner().push(mail),
        }
        self.notify.notify_waiters();
        Ok(())
    }
}
