<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-009: GPG via system gpg binary

**Status**: Accepted (evaluate :gpgex as alternative)

## Context

The CNA keypair is used for decrypting inbound encrypted emails, verifying inbound
signatures, signing outbound emails, and optionally encrypting outbound replies.
GPG operations require access to a keyring and the OpenPGP protocol.

## Decision

Invoke the system `gpg` binary via `System.cmd/3` with strict input sanitization
(no shell interpolation, arguments passed as a list). The CNA private key is loaded
into a dedicated GPG homedir at startup from an environment variable or secrets
manager. Sender public keys extracted from inbound emails are imported into this
homedir and also stored in the database (`User.public_gpg_key` or `ContactGpgKey`).

Evaluate `:gpgex` (Elixir NIF bindings to GPGME) as a potential replacement if the
system `gpg` approach proves fragile in containerized environments.

## Consequences

- Works with any system that has `gpg` installed (standard in most Linux/macOS
  environments)
- No native Elixir bindings required; no NIF compilation
- `System.cmd/3` with a list of arguments prevents shell injection; inputs must
  still be validated before use
- Container images must include `gpg` (adds ~10MB to image size)
- GPG homedir must be writable at runtime; use a tmpfs or mounted secret volume
- `:gpgex` migration is possible if needed without changing the public interface
