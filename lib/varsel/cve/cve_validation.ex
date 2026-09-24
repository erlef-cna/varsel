# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation do
  @moduledoc """
  Stateless validation service for CVE records, exposed as an Ash resource so
  the checks are callable as actions (and via MCP).

  Validators:

  - `:schema` — the official CVE record JSON schema (vendored, see
    `Varsel.CVE.CveSchema`)
  - `:cvelint` — the `cvelint` binary (see `Varsel.CVE.Cvelint`)
  - `:hex` — every `pkg:hex/...` package URL in the affected entries must
    reference an existing package on hex.pm (see `Varsel.HexPm`)
  - `:eef` — EEF/CNA policy requirements the schema and cvelint leave
    unchecked: a title, a CVSS v4 metric, a CWE, a CAPEC, and every
    "semver"-typed version boundary parsing as SemVer
  """

  # AshGraphql.Resource is required even though this resource exposes no type
  # of its own: ash_graphql (>= 1.10) only builds a domain's `action` query
  # fields for resources that carry the extension. The generic actions here
  # are exposed as queries in Varsel.CVE, so the extension must be present.
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CVE,
    extensions: [AshGraphql.Resource]

  alias Varsel.CVE.CveValidation.Actions.Validate
  alias Varsel.CVE.CveValidation.Result

  graphql do
    # This resource has no GraphQL type of its own; it only exposes generic
    # `action` queries (whose return types, Result/Error, are the real types).
    generate_object? false
  end

  resource do
    require_primary_key? false
  end

  actions do
    action :validate, Result do
      description "Runs all CVE record validators (schema, cvelint, hex.pm packages)."
      argument :cve_json, :map, allow_nil?: false

      run {Validate, validator: :all}
    end

    action :validate_schema, Result do
      description "Validates a CVE record against the official CVE JSON schema."
      argument :cve_json, :map, allow_nil?: false

      run {Validate, validator: :schema}
    end

    action :validate_cvelint, Result do
      description "Lints a CVE record with cvelint."
      argument :cve_json, :map, allow_nil?: false

      run {Validate, validator: :cvelint}
    end

    action :validate_hex_packages, Result do
      description "Checks that all pkg:hex package URLs reference existing hex.pm packages."
      argument :cve_json, :map, allow_nil?: false

      run {Validate, validator: :hex}
    end

    action :validate_eef, Result do
      description "Checks EEF/CNA policy requirements beyond the CVE schema (a title and a CVSS v4 metric)."
      argument :cve_json, :map, allow_nil?: false

      run {Validate, validator: :eef}
    end
  end
end
