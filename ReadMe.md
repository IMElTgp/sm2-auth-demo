# sm2 auth demo

An assignment of Network and System Security, UCAS.

**All the .go and .sh files in this repository are vibe coded.**

Current implementation status: `M1` to `M6` completed.

Implemented:

- `M1`: buildable project skeleton, server/client entrypoints, base scripts
- `M2`: SM3-based private key derivation, SM2 sign/verify, protocol token encoding
- `M3`: SQLite user store, in-memory session store with expiration, store tests
- `M4`: real HTTP API for register/challenge/verify and integration tests
- `M5`: GUI client flow for register/login and GUI client API tests
- `M6`: expanded end-to-end tests (replay, wrong password, tampered nonce, expired challenge) and dedicated e2e test script

## Run

Start server:

```bash
./scripts/run_server.sh
```

Start GUI client:

```bash
./scripts/run_client.sh
```

## Test

Run all tests:

```bash
./scripts/test_all.sh
```

Run end-to-end focused tests:

```bash
./scripts/test_e2e.sh
```

Run integration tests only:

```bash
go test -v ./tests -count=1
```

## Notes

- Desktop dependencies for Fyne (X11/OpenGL development libraries) must be installed on Linux.
- The API contract is implemented at:
  - `POST /api/register`
  - `POST /api/auth/challenge`
  - `POST /api/auth/verify`
