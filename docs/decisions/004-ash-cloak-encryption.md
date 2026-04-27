<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-004: Use Ash Cloak for field-level encryption of unpublished vulnerability data

**Status**: Accepted

## Context

Unpublished vulnerability details (title, description, reporter identity, CVE
content, thread bodies) are sensitive. If the database is compromised before a CVE
is published, this data must not be readable in plaintext. Encryption must be
transparent to application code and enforced consistently across all affected fields.

## Decision

Use **Ash Cloak** for field-level AES encryption on sensitive attributes of `Case`,
`CaseThread`, and `CveRecord`. Encryption is applied to all fields that contain
vulnerability details or reporter identity while the case status is not `published`.
On publish, fields can be decrypted for the public record or left encrypted depending
on whether they are included in the published CVE.

Encryption keys are stored outside the database (environment variables / secrets
manager).

## Consequences

- Sensitive data is encrypted at rest; a raw DB dump does not expose vulnerability
  details
- Key rotation requires re-encrypting existing rows (Ash Cloak supports key
  versioning)
- Queries/filtering on encrypted fields are not possible (use non-encrypted metadata
  fields for filtering)
- Adds a dependency on a secrets management solution for key storage
