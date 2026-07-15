# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.PurlType do
  @moduledoc """
  The purl type of a distribution channel — the ecosystems the EEF CNA
  publishes through. The git/forge entry is not a channel: it renders
  automatically from the package's `repo_url`.

  The type fixes the rendered `affected[]` entry's constants (collectionURL,
  versionType) and the derivation semantics (see
  `Varsel.Cases.Render.Channel` / `Varsel.Cases.Derivation`).
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      hex: "A hex.pm registry package (pkg:hex, versionType semver).",
      otp: "An Erlang/OTP application (pkg:otp, versionType otp, per-app versions).",
      npm: "An npm registry package (pkg:npm, versionType semver).",
      oci: "A container image (pkg:oci, versionType other, per-tag flavors).",
      sid: "A software identity for tools without a registry (pkg:sid, versionType semver).",
      hosted: "A hosted service (no purl, versionType date)."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :package_channel_purl_type

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :package_channel_purl_type
end
