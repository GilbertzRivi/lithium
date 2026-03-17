use lithium_core::error::{LithiumError, Result};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema};
use std::env;

pub mod models;
pub mod repo;

/// Percent-encode characters that are not allowed unescaped in a URL userinfo component.
fn encode_userinfo(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '%'  => vec!['%', '2', '5'],
            '@'  => vec!['%', '4', '0'],
            ':'  => vec!['%', '3', 'A'],
            '/'  => vec!['%', '2', 'F'],
            '?'  => vec!['%', '3', 'F'],
            '#'  => vec!['%', '2', '3'],
            '+'  => vec!['%', '2', 'B'],
            ' '  => vec!['%', '2', '0'],
            c    => vec![c],
        })
        .collect()
}

fn require(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| LithiumError::env_missing(name))
}

pub async fn connect_from_env() -> Result<DatabaseConnection> {
    let host     = require("DB_HOST")?;
    let port     = env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string());
    let user     = require("DB_USER")?;
    let password = {
        // Read from the file pointed to by DB_PASSWORD_FILE (typically a Docker secret).
        let path = require("DB_PASSWORD_FILE")?;
        std::fs::read_to_string(&path)
            .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
            .map_err(LithiumError::io)?
    };
    let name     = require("DB_NAME")?;

    let url = format!(
        "postgres://{}:{}@{}:{}/{}",
        encode_userinfo(&user),
        encode_userinfo(&password),
        host,
        port,
        name,
    );

    Database::connect(url).await.map_err(LithiumError::io)
}

pub async fn connect_url(url: &str) -> Result<DatabaseConnection> {
    Database::connect(url).await.map_err(LithiumError::io)
}

/// Create all tables if they do not already exist.
pub async fn migrate(db: &DatabaseConnection) -> Result<()> {
    use models::{messages, users};

    let backend = db.get_database_backend();
    let schema = Schema::new(backend);

    for stmt in [
        schema.create_table_from_entity(users::Entity).if_not_exists().to_owned(),
        schema.create_table_from_entity(messages::Entity).if_not_exists().to_owned(),
    ] {
        db.execute(backend.build(&stmt)).await.map_err(LithiumError::io)?;
    }

    Ok(())
}
