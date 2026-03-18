# Deploying lithiums

`lithiums` is the relay server. It binds plain HTTP; put nginx, Caddy, or another TLS-terminating reverse proxy in front of it. TLS at the proxy secures the transport channel, but it is not the application-level trust anchor — clients authenticate the server via `server.identity`, which is distributed out-of-band.

## Prerequisites

- PostgreSQL 14+
- libtss2 (for TPM support, see below)
- A reverse proxy handling TLS

## Environment variables

| Variable                           | Default             | Description                                                                                |
|------------------------------------|---------------------|--------------------------------------------------------------------------------------------|
| `LITHIUM_BIND`                     | `127.0.0.1`         | Interface to listen on                                                                     |
| `LITHIUM_PORT`                     | `4108`              | Port to listen on                                                                          |
| `LITHIUM_KEYS_DIR`                 | `/var/lib/lithiums` | Directory for key material                                                                 |
| `LITHIUM_MK_ROTATE_SECS`           | `3600`              | Key rotation interval in seconds                                                           |
| `DB_HOST`                          | —                   | PostgreSQL host                                                                            |
| `DB_PORT`                          | `5432`              | PostgreSQL port                                                                            |
| `DB_USER`                          | —                   | PostgreSQL user                                                                            |
| `DB_NAME`                          | —                   | PostgreSQL database                                                                        |
| `DB_PASSWORD` / `DB_PASSWORD_FILE` | —                   | PostgreSQL password or path to file containing it; prefer `DB_PASSWORD_FILE` in production |

### TPM variables (only when using the default `tpm` feature)

| Variable                  | Default                               | Description                                                  |
|---------------------------|---------------------------------------|--------------------------------------------------------------|
| `LITHIUM_TPM_TCTI`        | `device:/dev/tpmrm0`                  | TCTI connection string passed to tss-esapi                   |
| `LITHIUM_TPM_SEALED_PATH` | `{LITHIUM_KEYS_DIR}/server/mk.sealed` | Where to store the sealed master key blob                    |
| `LITHIUM_MK_PROVIDER`     | —                                     | Set to `plain` to skip TPM and fall back to a plain key file |

## Master key providers

`lithiums` ships with two `MkProvider` implementations selected at startup:

**TpmMkProvider** (default when built with `--features tpm`): seals the 32-byte master key into the TPM as a KEYEDHASH object under an ECC P-256 restricted decryption parent derived from the owner seed. The sealed blob is written to `LITHIUM_TPM_SEALED_PATH`. On the first run the key is generated and sealed; on subsequent runs it is unsealed on demand.

Requirements:
- A TPM 2.0 accessible via the resource manager device (`/dev/tpmrm0` preferred over `/dev/tpm0`)
- `libtss2-esys` present at runtime (package `libtss2-esys-3.0.2-0` on Debian bookworm)

**PlainFileMkProvider** (fallback): writes the master key as a raw file under `{LITHIUM_KEYS_DIR}/server/mk`. Use only in environments without a TPM (CI, local dev). Set `LITHIUM_MK_PROVIDER=plain` to activate.

## Docker

A multi-stage Dockerfile is at `lithiums/Dockerfile`. It installs `libtss2-dev` in the builder and `libtss2-esys-3.0.2-0` in the runtime image.

Build:

```bash
docker build -f lithiums/Dockerfile -t lithiums .
```

Run with TPM passthrough:

```bash
docker run --device /dev/tpmrm0 \
  -e DB_HOST=... -e DB_USER=... -e DB_NAME=... -e DB_PASSWORD=... \
  -v lithium_keys:/var/lib/lithiums \
  -p 4108:4108 \
  lithiums
```

To disable TPM in Docker:

```bash
docker run \
  -e LITHIUM_MK_PROVIDER=plain \
  ...
```

## Docker Compose

Production compose should use the pre-built image from `lithiums/Dockerfile`, not a dev `cargo run` setup. Minimal example:

```yaml
services:
  postgres:
    image: postgres:17
    restart: unless-stopped
    environment:
      POSTGRES_USER: lithium
      POSTGRES_DB: lithium
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lithium -d lithium"]
      interval: 5s
      timeout: 3s
      retries: 20

  app:
    build:
      context: ..
      dockerfile: lithiums/Dockerfile
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "127.0.0.1:4108:4108"
    environment:
      DB_HOST: postgres
      DB_PORT: "5432"
      DB_USER: lithium
      DB_NAME: lithium
      DB_PASSWORD_FILE: /run/secrets/db_password
      LITHIUM_BIND: 0.0.0.0
    secrets:
      - db_password
    volumes:
      - lithium_keys:/var/lib/lithiums
    devices:
      - /dev/tpmrm0:/dev/tpmrm0
    group_add:
      - "tss"

secrets:
  db_password:
    file: ./secrets/db_password.txt

volumes:
  pgdata:
  lithium_keys:
```

`group_add: ["tss"]` gives the container access to `/dev/tpmrm0` without running as root — on Debian/Ubuntu the resource manager device is owned by group `tss`. Check the actual group on the host with `stat /dev/tpmrm0` and adjust if different.

## First run

On first startup `lithiums` will:

1. Generate and seal (or store) the master key.
2. Write `server.identity` to `{LITHIUM_KEYS_DIR}/server.identity`. This file contains the server's long-term public keys and must be distributed to clients out-of-band before they can register.

Keep `server.identity` backed up. Losing the master key or the TPM owner seed means losing the ability to rotate server keys; existing sessions will still work until the next rotation fails.

Clients pin the `server.identity` they received during provisioning. If you replace it (e.g. after key loss), all previously provisioned clients will reject the server until they are re-provisioned with the new identity file.

## Health checks

`GET /health` returns JSON with the last-success timestamps and cumulative error counts for the two background tasks (key rotation and message reaper). HTTP 200 means both have completed at least one successful run since startup; 503 means one or both are still initializing or have not run yet.

Orchestrators and reverse proxies can use this endpoint for readiness checks. There is no separate liveness endpoint — if the process is alive, the port is open.

## Building without TPM support

```bash
cargo build -p lithiums --no-default-features --release
```

This produces a binary with only `PlainFileMkProvider`. Set `LITHIUM_MK_PROVIDER=plain` when running it (or omit — there is no TPM code path in this build).