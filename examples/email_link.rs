//! Sign-in by emailed link: request, "send" the mail, redeem the token once.
//!
//! Run with `cargo run --example email_link`.

use std::collections::HashMap;

use latchkey::account::{Account, Email, Factors, Lockout, Role};
use latchkey::flow::email_link::{EmailLink, EmailLinkEvent};
use latchkey::flow::{Client, Effect, LinkToken};
use latchkey::token::TokenHash;
use latchkey::{Config, UserId};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
    let mut rng = latchkey::os_rng()?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let account = Account {
        id: UserId::random(&mut rng),
        email: Email::parse("owner@example.com")?,
        display_name: "Owner".into(),
        role: Role::Owner,
        active: true,
        factors: Factors {
            password: true,
            totp: true,
            passkeys: 0,
        },
        lockout: Lockout::default(),
    };
    let mut links: HashMap<TokenHash, LinkToken> = HashMap::new();
    let mut outbox = Vec::new();

    // POST /sign-in/email {email}: always answer 202.
    let step = EmailLink::Start
        .advance(
            &config,
            EmailLinkEvent::Request {
                account: Some(account.clone()),
                last_sent_at: None,
                client: Client::default(),
            },
            now,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    for effect in step.effects {
        match effect {
            Effect::StoreLinkToken { token_hash, link } => {
                links.insert(token_hash, link);
            }
            Effect::SendMail(mail) => {
                println!(
                    "To: {}\nSubject: {}\n\n{}",
                    mail.to,
                    mail.subject(),
                    mail.text()
                );
                outbox.push(mail);
            }
            Effect::Audit(event) => println!("audit: {}", event.kind),
            _ => {}
        }
    }

    // POST /sign-in/email/redeem {token}: take the link out of storage (single use).
    let token = outbox
        .first()
        .and_then(latchkey::mail::Mail::link_token)
        .ok_or("no mail")?;
    let link = TokenHash::of(&token).and_then(|hash| links.remove(&hash));
    let redeem = |link| {
        EmailLink::Start.advance(
            &config,
            EmailLinkEvent::Redeem {
                link,
                account: Some(account.clone()),
                client: Client::default(),
            },
            now,
            &mut latchkey::os_rng().map_err(latchkey::flow::Refusal::from)?,
        )
    };
    let step = redeem(link).map_err(|refusal| refusal.error)?;
    if let EmailLink::SignedIn { session, .. } = step.state {
        println!(
            "signed in by {}",
            session.method.map(|m| m.to_string()).unwrap_or_default()
        );
    }
    for effect in step.effects {
        if let Effect::SendMail(mail) = effect {
            println!("also mailed: {}", mail.subject());
        }
    }

    // The same token again finds no link: refused.
    let again = TokenHash::of(&token).and_then(|hash| links.remove(&hash));
    let refused = redeem(again).err().map(|refusal| refusal.error);
    println!("second use: {refused:?}");
    Ok(())
}
