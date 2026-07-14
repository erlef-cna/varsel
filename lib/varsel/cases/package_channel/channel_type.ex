# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.ChannelType do
  @moduledoc """
  The distribution channel a `Varsel.Cases.PackageChannel` publishes through.

  The channel type determines the rendered `affected[]` entry's constants —
  `collectionURL`, `packageURL` purl scheme, and `versionType` — which are
  invariants per channel across all EEF records (see
  `Varsel.Cases.Render.Channel`).
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      git: "A source repository entry (pkg:github, versionType git, commit SHAs).",
      hex: "A hex.pm registry entry (pkg:hex, versionType semver).",
      otp: "An Erlang/OTP application entry (pkg:otp/<app>, versionType otp).",
      npm: "An npm registry entry (pkg:npm, versionType semver).",
      oci: "A container image entry (pkg:oci, versionType other, per-tag flavors).",
      sid: "A software-identity entry for tools without a registry (pkg:sid, versionType semver).",
      hosted: "A hosted service (no package, versionType date)."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :package_channel_type

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :package_channel_type
end
