# Deploying lithiums

`lithiums` is the relay server. It binds plain HTTP; put nginx, 
Caddy, or another TLS-terminating reverse proxy in front of it. 
TLS at the proxy secures the transport channel, but it is not the 
application-level trust anchor. Clients authenticate the server 
via `server.identity`, which is distributed out-of-band.

## Reverse proxy and client IP

The DoS pre-replay guard rate-limits by the peer address of the 
incoming TCP connection (`remote_addr`). Behind a reverse proxy 
that address is the **proxy's** IP, not the client's, so without 
further configuration the guard degenerates into a single global 
counter (one abusive client can trip the limit for everyone) or a 
useless one (everyone shares the proxy address). `lithiums` does 
not read `X-Forwarded-For` itself, it must not trust a 
client-settable header.

If you run behind a proxy and want per-client throttling, 
terminate the rate-limiting at the proxy (nginx `limit_req`, Caddy 
equivalents) where the real client IP is known, or have the proxy 
enforce it and treat the application guard as a coarse backstop. 
Do not expose `lithiums` directly such that `remote_addr` is 
attacker-spoofable.

## Prerequisites

- PostgreSQL 14+
- libtss2 (for TPM support, see below)
- A reverse proxy handling TLS

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITHIUM_BIND` | `127.0.0.1` | Interface to listen on |
| `LITHIUM_PORT` | `4108` | Port to listen on |
| `LITHIUM_KEYS_DIR` | `/var/lib/lithiums` | Directory for key material |
| `LITHIUM_MK_ROTATE_SECS` | `3600` | Key rotation interval in seconds |
| `LITHIUMS_SEND_POW_BITS` | `18` | Proof-of-work difficulty (leading zero bits) required on `/msg/send` |
| `DB_HOST` | - | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | - | PostgreSQL user |
| `DB_NAME` | - | PostgreSQL database |
| `DB_PASSWORD_FILE` | - | Path to a file containing the PostgreSQL password (e.g. a Docker secret). There is no plain `DB_PASSWORD` variable, the password is only ever read from a file. |
| `DB_MAX_CONNECTIONS` | `20` | Postgres connection pool max size |
| `DB_MIN_CONNECTIONS` | `2` | Postgres connection pool min size |

### TPM variables (only when using the default `tpm` feature)

| Variable | Default | Description |
|----------|---------|-------------|
| `LITHIUM_TPM_TCTI` | `device:/dev/tpmrm0` | TCTI connection string passed to tss-esapi |
| `LITHIUM_TPM_SEALED_PATH` | `{LITHIUM_KEYS_DIR}/server/mk.sealed` | Where to store the sealed master key blob |
| `LITHIUM_MK_PROVIDER` | - | Set to `plain` to skip TPM and fall back to a plain key file |

## Master key providers

`lithiums` ships with two `MkProvider` implementations selected at 
startup:

**TpmMkProvider** (default when built with `--features tpm`): seals 
the 32-byte master key into the TPM as a KEYEDHASH object under an 
ECC P-256 restricted decryption parent derived from the owner 
seed. The sealed blob is written to `LITHIUM_TPM_SEALED_PATH`. On 
the first run the key is generated and sealed; on subsequent runs 
it is unsealed on demand.

Requirements:
- A TPM 2.0 accessible via the resource manager device 
  (`/dev/tpmrm0` preferred over `/dev/tpm0`)
- `libtss2-esys` present at runtime (package 
  `libtss2-esys-3.0.2-0` on Debian bookworm)

Trust boundary: the sealed blob carries no PCR policy and no auth 
value (it is sealed under the empty owner-hierarchy password). It 
therefore protects against **offline** compromise only, a stolen 
disk or backup is useless without the same physical TPM and owner 
seed. It does **not** protect against an attacker who already has 
root on the live host: that attacker can ask the TPM to unseal 
(and can read the process memory anyway). PCR binding is 
deliberately not used because it tends to break across 
firmware/kernel updates. If you need defense against live-root, 
that is out of scope for TPM sealing here and must come from host 
hardening.

**PlainFileMkProvider** (fallback): writes the master key as a raw 
file under `{LITHIUM_KEYS_DIR}/server/mk`. Use only in 
environments without a TPM (CI, local dev). Set 
`LITHIUM_MK_PROVIDER=plain` to activate.

## Docker

A multi-stage Dockerfile is at `lithiums/Dockerfile`. It installs 
`libtss2-dev` in the builder and `libtss2-esys-3.0.2-0` in the 
runtime image.

Build:

```bash
docker build -f lithiums/Dockerfile -t lithiums .
```

Run with TPM passthrough:

```bash
docker run --device /dev/tpmrm0 \
  -e DB_HOST=... -e DB_USER=... -e DB_NAME=... \
  -e DB_PASSWORD_FILE=/run/secrets/db_password \
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

`docker/docker-compose.yml` in this repo is a **local 
development** setup, not a production one: the `app` service runs 
`image: rust:latest` with `command: [cargo, run, --release]`, 
bind-mounts `lithium_core`/`lithiums` sources from the host, and 
keeps a `cargo_target` volume to avoid rebuilding from scratch on 
every restart. It is meant for iterating on `lithiums` against a 
real Postgres without writing a Dockerfile build each time, not 
for deploying to a server.

```yaml
services:
  postgres:
    image: postgres:17
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      POSTGRES_USER: lithium
      POSTGRES_DB: lithium
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - ./pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lithium -d lithium"]
      interval: 5s
      timeout: 3s
      retries: 20

  app:
    image: rust:latest
    working_dir: /app
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "4108:4108"
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
      - ../lithium_core:/lithium_core
      - ../lithiums:/app
      - lithium_keys:/var/lib/lithiums
      - cargo_target:/app/target
    command:
      - /usr/local/cargo/bin/cargo
      - run
      - --release
    devices:
      - /dev/tpmrm0:/dev/tpmrm0
    group_add:
      - 107

secrets:
  db_password:
    file: ./secrets/db_password.txt

volumes:
  lithium_keys:
  cargo_target:
```

`group_add: [107]` gives the container access to `/dev/tpmrm0` 
without running as root. `107` is the `tss` GID on the image this 
compose file was written against, it is **not** portable across 
distros/images. Check the actual group on the host with `stat 
/dev/tpmrm0` and replace `107` with whatever GID owns it there (or 
with the group name, e.g. `tss`, if your Compose/Docker version 
resolves names inside the container).

**Production** should not use this file as-is. Build 
`lithiums/Dockerfile` into an image ahead of time (`docker build 
-f lithiums/Dockerfile -t lithiums .`) and reference that image 
from `app` (`image: lithiums` instead of `image: rust:latest` + 
bind mounts + `command`), so the running container doesn't depend 
on a writable source checkout or a `rust:latest` toolchain at 
runtime. No such production compose file ships in this repo yet, 
adapt the dev file above if you need one.

## First run

On first startup `lithiums` will:

1. Generate and seal (or store) the master key.
2. Write `server.identity` to 
   `{LITHIUM_KEYS_DIR}/server.identity`. This file contains the 
   server's long-term public keys and must be distributed to 
   clients out-of-band before they can register.

Keep `server.identity` backed up. Losing the master key or the TPM 
owner seed means losing the ability to rotate server keys; 
existing sessions will still work until the next rotation fails.

Clients pin the `server.identity` they received during 
provisioning. If you replace it (e.g. after key loss), all 
previously provisioned clients will reject the server until they 
are re-provisioned with the new identity file.

## Health checks

`GET /health` returns JSON with the last-success timestamps and 
cumulative error counts for the two background tasks (key rotation 
and message reaper). HTTP 200 means both have completed at least 
one successful run since startup; 503 means one or both are still 
initializing or have not run yet.

Orchestrators and reverse proxies can use this endpoint for 
readiness checks. There is no separate liveness endpoint, if the 
process is alive, the port is open.

## Building without TPM support

```bash
cargo build -p lithiums --no-default-features --release
```

This produces a binary with only `PlainFileMkProvider`. Set 
`LITHIUM_MK_PROVIDER=plain` when running it (or omit it, there is 
no TPM code path in this build).

## lithiumd (client, not server-deployed)

`lithiumd` runs locally on each user's machine alongside 
`lithiumg` and talks to `lithiums` as a regular HTTPS client, it 
is not deployed to a server. Its environment variables (data dir, 
IPC socket paths, connection policy, cover-traffic cadence) are 
collected in 
[daemon-runtime.md](daemon-runtime.md#environment-variables).

The relay server address is not an environment variable, it is set 
at runtime via the IPC command `set_server_url` and persisted to 
`{LITHIUMD_DATA_DIR}/server_url` (see 
[ipc-reference.md](../protocol/ipc-reference.md#set_server_url)).
