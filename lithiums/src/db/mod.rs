// SPDX-FileCopyrightText: 2026 Lithium Project
// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashSet, env, time::Duration};

use lithium_core::secrets::SecretString;

use lithium_core::error::{LithiumError, Result};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement, TransactionTrait,
    Value,
};

pub mod models;
pub mod repo;

/// Percent-encode characters that are not allowed unescaped in a URL userinfo component.
fn encode_userinfo(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '%' => vec!['%', '2', '5'],
            '@' => vec!['%', '4', '0'],
            ':' => vec!['%', '3', 'A'],
            '/' => vec!['%', '2', 'F'],
            '?' => vec!['%', '3', 'F'],
            '#' => vec!['%', '2', '3'],
            '+' => vec!['%', '2', 'B'],
            ' ' => vec!['%', '2', '0'],
            c => vec![c],
        })
        .collect()
}

fn require(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| LithiumError::env_missing(name))
}

pub async fn connect_from_env() -> Result<DatabaseConnection> {
    let host = require("DB_HOST")?;
    let port = env::var("DB_PORT").unwrap_or_else(|_| "5432".to_string());
    let user = require("DB_USER")?;
    let password = {
        // Read from the file pointed to by DB_PASSWORD_FILE (typically a Docker secret).
        let path = require("DB_PASSWORD_FILE")?;
        std::fs::read_to_string(&path)
            .map(|s| SecretString::new(s.trim_end_matches(['\n', '\r']).to_string()))
            .map_err(LithiumError::io)?
    };
    let name = require("DB_NAME")?;

    let url = format!(
        "postgres://{}:{}@{}:{}/{}",
        encode_userinfo(&user),
        encode_userinfo(password.expose()),
        host,
        port,
        name,
    );

    let max_conn: u32 = env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let min_conn: u32 = env::var("DB_MIN_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    let mut opt = ConnectOptions::new(url);
    opt.max_connections(max_conn)
        .min_connections(min_conn)
        .connect_timeout(Duration::from_secs(10))
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .sqlx_logging(false);

    Database::connect(opt).await.map_err(LithiumError::io)
}

pub async fn connect_url(url: &str) -> Result<DatabaseConnection> {
    Database::connect(url).await.map_err(LithiumError::io)
}

struct Migration {
    name: &'static str,
    steps: &'static [&'static str],
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "0001_initial",
        steps: &[
            "CREATE TABLE IF NOT EXISTS users (
                id               BYTEA PRIMARY KEY,
                opaque_record    BYTEA NOT NULL,
                ed_key           BYTEA NOT NULL,
                dili_key         BYTEA NOT NULL,
                dek              BYTEA NOT NULL,
                delete_token_hash BYTEA NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS messages (
                id         BYTEA PRIMARY KEY,
                mailbox    BYTEA NOT NULL,
                content    BYTEA NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS messages_mailbox_idx    ON messages (mailbox)",
            "CREATE INDEX IF NOT EXISTS messages_expires_at_idx ON messages (expires_at)",
        ],
    },
    // Never modify existing entries - only append.
];

const MIGRATION_LOCK_ID: i64 = 0x4c69_7468_6975_6d00; // "Lithiu\0"

pub async fn migrate(db: &DatabaseConnection) -> Result<()> {
    let backend = db.get_database_backend();

    let txn = db.begin().await.map_err(LithiumError::io)?;

    txn.execute(Statement::from_string(
        backend,
        format!("SELECT pg_advisory_xact_lock({MIGRATION_LOCK_ID})"),
    ))
    .await
    .map_err(LithiumError::io)?;

    txn.execute(Statement::from_string(
        backend,
        "CREATE TABLE IF NOT EXISTS _migrations (
            name       TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    ))
    .await
    .map_err(LithiumError::io)?;

    let rows = txn
        .query_all(Statement::from_string(
            backend,
            "SELECT name FROM _migrations",
        ))
        .await
        .map_err(LithiumError::io)?;

    let applied: HashSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<String>("", "name").ok())
        .collect();

    for m in MIGRATIONS {
        if applied.contains(m.name) {
            continue;
        }
        for step in m.steps {
            txn.execute(Statement::from_string(backend, *step))
                .await
                .map_err(LithiumError::io)?;
        }
        txn.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO _migrations (name) VALUES ($1)",
            [Value::String(Some(Box::new(m.name.to_string())))],
        ))
        .await
        .map_err(LithiumError::io)?;
    }

    txn.commit().await.map_err(LithiumError::io)?;
    Ok(())
}
