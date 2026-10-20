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
    /// A sign-in completed on a browser the account had not used before.
    NewDevice,
}

/// What to send; wording and layout are up to the app's [`Mailer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub kind: MailKind,
    pub to: String,
    /// The page that redeems the token, or for [`MailKind::NewDevice`] the sessions page.
    pub link: Url,
    /// When the link stops working; `None` for notifications.
    pub expires_at: Option<OffsetDateTime>,
    /// Set for [`MailKind::NewDevice`].
    pub sign_in: Option<SignInDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInDetails {
    pub at: OffsetDateTime,
    /// Such as `password+totp`, `passkey` or `email_link`.
    pub method: String,
    pub user_agent: Option<String>,
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn printable(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).collect()
}

impl Mail {
    pub fn subject(&self) -> &'static str {
        match self.kind {
            MailKind::Setup => "Set up your sign-in",
            MailKind::SignInLink => "Your sign-in link",
            MailKind::Invite => "You have been invited",
            MailKind::NewDevice => "New sign-in to your account",
        }
    }

    pub fn text(&self) -> String {
        let action = match self.kind {
            MailKind::Setup => "set up your sign-in",
            MailKind::SignInLink => "sign in",
            MailKind::Invite => "accept the invitation and set up your sign-in",
            MailKind::NewDevice => return self.new_device_text(),
        };
        format!(
            "Open this link to {action}:\n\n{}\n\nIt works once and expires at {}. If you did not ask for it, ignore this email.\n",
            self.link,
            self.expires_at.map(rfc3339).unwrap_or_default(),
        )
    }

    fn new_device_text(&self) -> String {
        let details = self
            .sign_in
            .as_ref()
            .map(|details| {
                format!(
                    "When: {}\nMethod: {}\nBrowser: {}\n\n",
                    rfc3339(details.at),
                    printable(&details.method),
                    details
                        .user_agent
                        .as_deref()
                        .map(printable)
                        .unwrap_or_else(|| "unknown".to_owned()),
                )
            })
            .unwrap_or_default();
        format!(
            "Your account was just signed in to from a browser it had not used before.\n\n{details}If this was you, there is nothing to do. If not, sign out that session and change your password:\n\n{}\n",
            self.link,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_device_text_names_the_sign_in_and_strips_control_characters() {
        let mail = Mail {
            kind: MailKind::NewDevice,
            to: "o@example.com".into(),
            link: Url::parse("https://home.example.com/settings/sessions").unwrap(),
            expires_at: None,
            sign_in: Some(SignInDetails {
                at: OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap(),
                method: "passkey".into(),
                user_agent: Some("Evil\r\nBcc: x@y".into()),
            }),
        };
        let text = mail.text();
        assert!(text.contains("Method: passkey"));
        assert!(text.contains("Browser: EvilBcc: x@y\n"));
        assert!(text.contains("https://home.example.com/settings/sessions"));
        assert!(text.contains("2030-03-17T17:46:40Z"));
    }
}
