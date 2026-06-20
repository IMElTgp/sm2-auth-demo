# SM2 Password Authentication Demo

A Go implementation of a password-authenticated login system built with Chinese commercial cryptography primitives (`SM2` / `SM3`).

This project demonstrates a client/server authentication flow where the server never receives or stores the user's plaintext password or password hash. The password is only used on the client side to deterministically derive an `SM2` private key, which is then used to sign a server-issued challenge.

## Why This Project

Traditional password systems usually store password hashes on the server. Once the database is leaked, attackers can often launch offline cracking attacks against those hashes. This project explores an alternative design:

- The client derives an `SM2` private key from `username + password + salt`
- The server stores only `username + salt + SM2 public key`
- Authentication is completed through a challenge-response signature flow
- A replayed authentication response should fail

This repository was built as a course project for Network and System Security at UCAS, but the codebase is organized as a small standalone Go application with tests, scripts, and a GUI client.

## Features

- Real client/server network interaction over HTTP
- GUI client built with `Fyne`
- Deterministic private key derivation based on `SM3`
- `SM2` signature-based challenge-response authentication
- SQLite-backed user store
- In-memory session challenge store with expiration
- Replay protection with atomic session consumption
- Basic anti-enumeration behavior for auth endpoints
- Fixed-window rate limiting on sensitive APIs
- Unit and integration tests

## Authentication Flow

```text
Register
  Client:
    username + password + salt
      -> derive SM2 private key
      -> generate SM2 public key
      -> send username, salt, public key to server

  Server:
    store username, salt, public key

Login
  Client -> Server:
    request challenge(username)

  Server -> Client:
    session_id, nonce, salt

  Client:
    re-derive SM2 private key from username + password + salt
    build auth token(version, username, session_id, nonce)
    sign token digest with SM2 private key

  Client -> Server:
    username, session_id, token, signature

  Server:
    load stored public key
    verify token and signature
    atomically consume session_id
    return authentication result
```

## Repository Layout

```text
cmd/
  client-gui/          GUI client entrypoint
  server/              HTTP server entrypoint
internal/
  api/                 HTTP handlers, DTOs, rate limiter
  crypto/              SM2/SM3 helpers and key derivation
  gui/                 Fyne app and API client
  protocol/            Canonical token encoding
  store/               SQLite user store and session store
scripts/
  run_client.sh        Launch GUI client
  run_server.sh        Launch server
  test_all.sh          Run all tests
  test_e2e.sh          Run focused end-to-end tests
tests/
  api_integration_test.go
  auth_flow_test.go
ReadMe.md              Course-submission README in Chinese
README.md              GitHub-oriented project README
```

## Quick Start

### Requirements

- Go `1.25.8`
- A Linux desktop environment if you want to run the GUI client
- System libraries required by `Fyne`

### Start the Server

```bash
./scripts/run_server.sh
```

Default listen address:

```text
:8080
```

### Start the GUI Client

```bash
./scripts/run_client.sh
```

The default server URL in the GUI is:

```text
http://127.0.0.1:8080
```

## API Endpoints

- `GET /healthz`
- `POST /api/register`
- `POST /api/auth/challenge`
- `POST /api/auth/verify`

## Testing

Run the full test suite:

```bash
go test ./...
```

Or use the helper scripts:

```bash
./scripts/test_all.sh
./scripts/test_e2e.sh
```

Covered scenarios include:

- successful register/challenge/verify flow
- wrong-password rejection
- tampered token / nonce rejection
- expired challenge rejection
- replay failure
- concurrent verify requests with single-use session semantics
- anti-enumeration behavior
- rate-limit triggering

## Security Notes

This project improves over naive password storage, but it is still a teaching/demo system rather than a production-ready authentication platform.

Current design strengths:

- the server does not store plaintext passwords
- the authentication response is bound to a fresh server nonce
- challenge reuse is blocked by one-time session consumption

Important limitations:

- without TLS, the transport channel is still exposed to active attackers
- the current derivation scheme is deterministic and not a slow password-hard KDF
- the session store is in-memory and single-node only
- the project does not implement mutual authentication or forward-secret session key agreement

## Future Work

- replace the current derivation logic with a tunable slow KDF
- add mutual authentication
- integrate ephemeral DH for forward-secure session keys
- move session state to a distributed store with atomic expiry/consume behavior
- add structured audit logging
- harden memory wiping for sensitive client-side material

## Notes for Reviewers

- `ReadMe.md` is the course-submission document written in Chinese and structured to match the assignment guideline.
- `README.md` is this GitHub-facing version, focused on onboarding and project overview.
