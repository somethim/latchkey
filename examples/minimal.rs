//! Run with `cargo run --example minimal`, then open http://localhost:3000.
//! Mail is printed to the terminal instead of being sent.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use latchkey::{
    Config, CurrentUser, Latchkey, Mail, MailError, Mailer, RecentAuth, SqliteStore, async_trait,
};

struct PrintMailer;

#[async_trait]
impl Mailer for PrintMailer {
    async fn send(&self, mail: Mail) -> Result<(), MailError> {
        println!(
            "To: {}\nSubject: {}\n\n{}",
            mail.to,
            mail.subject(),
            mail.text()
        );
        Ok(())
    }
}

async fn home(user: CurrentUser) -> String {
    format!("Hello, {}", user.display_name())
}

async fn settings(user: RecentAuth) -> String {
    format!("Sensitive settings for {}", user.email())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let owner = std::env::var("OWNER_EMAIL").unwrap_or_else(|_| "owner@example.com".into());
    // Fresh keys every run, so the database lives in memory too: factors sealed with one data
    // key do not open with the next.
    let config = Config::new(
        &owner,
        "http://localhost:3000",
        rand::random(),
        rand::random(),
    )?;
    let store = SqliteStore::in_memory().await?;
    let auth = Latchkey::new(config, Arc::new(store), Arc::new(PrintMailer)).await?;

    let app = Router::new()
        .route("/", get(home))
        .route("/settings", get(settings))
        .nest("/auth", auth.router())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("POST http://localhost:3000/auth/setup/start to get the owner setup link");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
