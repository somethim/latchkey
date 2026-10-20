//! Mail content as values. The flows emit [`Effect::SendMail`](crate::flow::Effect::SendMail)
//! with a [`Mail`]; the app sends it however it likes, with [`Mail::subject`] and
//! [`Mail::text`] or its own templates built from the fields.
//!
//! ```
//! use latchkey::mail::{Mail, MailKind};
//! use latchkey::Email;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mail = Mail::new(
//!     MailKind::SignInLink,
//!     Email::parse("owner@example.com")?,
//!     "https://home.example.com/sign-in/link?token=abc",
//!     Some(time::OffsetDateTime::from_unix_timestamp(1_800_000_900)?),
//!     None,
//! );
//! assert_eq!(mail.subject(), "Your sign-in link");
//! assert!(mail.text().contains("expires at 2027-01-15T08:15:00Z"));
//! # Ok(())
//! # }
//! ```

use time::OffsetDateTime;

use crate::account::Email;
use crate::session::SignInMethod;

/// Which mail it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum MailKind {
    /// First-open owner setup link.
    Setup,
    /// Sign-in link.
    SignInLink,
    /// Invite link for a new member.
    Invite,
    /// A sign-in completed on a browser the account had not used before.
    NewDevice,
}

/// The details a new-device mail reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SignInDetails {
    /// When the sign-in completed.
    pub at: OffsetDateTime,
    /// How.
    pub method: SignInMethod,
    /// The browser's user agent.
    pub user_agent: Option<String>,
}

impl SignInDetails {
    /// The details of a sign-in at `at` by `method` from `user_agent`.
    #[must_use]
    pub fn new(at: OffsetDateTime, method: SignInMethod, user_agent: Option<String>) -> Self {
        Self {
            at,
            method,
            user_agent,
        }
    }
}

/// A mail to send. For link mails, `link` carries the token in its query string: it is a
/// bearer secret, so `Debug` leaves the link out.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Mail {
    /// Which mail.
    pub kind: MailKind,
    /// The recipient.
    pub to: Email,
    /// The page that redeems the token (`?token=`), or for [`MailKind::NewDevice`] the
    /// sessions page.
    pub link: String,
    /// When the link stops working; `None` for notifications.
    pub expires_at: Option<OffsetDateTime>,
    /// Set for [`MailKind::NewDevice`].
    pub sign_in: Option<SignInDetails>,
}

impl std::fmt::Debug for Mail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mail")
            .field("kind", &self.kind)
            .field("to", &self.to)
            .field("expires_at", &self.expires_at)
            .field("sign_in", &self.sign_in)
            .finish_non_exhaustive()
    }
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
    /// A mail, for an app that builds its own (latchkey's come in
    /// [`Effect::SendMail`](crate::flow::Effect::SendMail)).
    #[must_use]
    pub fn new(
        kind: MailKind,
        to: Email,
        link: impl Into<String>,
        expires_at: Option<OffsetDateTime>,
        sign_in: Option<SignInDetails>,
    ) -> Self {
        Self {
            kind,
            to,
            link: link.into(),
            expires_at,
            sign_in,
        }
    }

    /// The subject line.
    #[must_use]
    pub fn subject(&self) -> &'static str {
        match self.kind {
            MailKind::Setup => "Set up your sign-in",
            MailKind::SignInLink => "Your sign-in link",
            MailKind::Invite => "You have been invited",
            MailKind::NewDevice => "New sign-in to your account",
        }
    }

    /// The plain-text body. Control characters from the user agent are removed, so it
    /// cannot inject headers or lines.
    #[must_use]
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

    /// The token in the link, if any; for tests.
    #[must_use]
    pub fn link_token(&self) -> Option<String> {
        url::Url::parse(&self.link)
            .ok()?
            .query_pairs()
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.into_owned())
    }

    fn new_device_text(&self) -> String {
        let details = self
            .sign_in
            .as_ref()
            .map(|details| {
                format!(
                    "When: {}\nMethod: {}\nBrowser: {}\n\n",
                    rfc3339(details.at),
                    printable(details.method.as_str()),
                    details
                        .user_agent
                        .as_deref()
                        .map_or_else(|| "unknown".to_owned(), printable),
                )
            })
            .unwrap_or_default();
        format!(
            "Your account was just signed in to from a browser it had not used before.\n\n{details}If this was you, there is nothing to do. If not, sign out that session and change your password:\n\n{}\n",
            self.link,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_device_text_names_the_sign_in_and_strips_control_characters()
    -> Result<(), Box<dyn std::error::Error>> {
        let mail = Mail {
            kind: MailKind::NewDevice,
            to: Email::parse("o@example.com")?,
            link: "https://home.example.com/settings/sessions".to_owned(),
            expires_at: None,
            sign_in: Some(SignInDetails {
                at: OffsetDateTime::from_unix_timestamp(1_900_000_000)?,
                method: SignInMethod::Passkey,
                user_agent: Some("Evil\r\nBcc: x@y".into()),
            }),
        };
        let text = mail.text();
        assert!(text.contains("Method: passkey"));
        assert!(text.contains("Browser: EvilBcc: x@y\n"));
        assert!(text.contains("https://home.example.com/settings/sessions"));
        assert!(text.contains("2030-03-17T17:46:40Z"));
        assert_eq!(mail.subject(), "New sign-in to your account");
        Ok(())
    }

    #[test]
    fn link_mails_hide_the_token_from_debug() -> Result<(), Box<dyn std::error::Error>> {
        let mail = Mail {
            kind: MailKind::SignInLink,
            to: Email::parse("o@example.com")?,
            link: "https://home.example.com/sign-in/link?token=SECRET".to_owned(),
            expires_at: Some(OffsetDateTime::from_unix_timestamp(1_900_000_000)?),
            sign_in: None,
        };
        assert!(!format!("{mail:?}").contains("SECRET"));
        assert_eq!(mail.link_token().as_deref(), Some("SECRET"));
        assert!(mail.text().contains("expires at 2030-03-17T17:46:40Z"));
        Ok(())
    }
}
