# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.VersionType do
  @moduledoc """
  The vocabulary a channel's version bounds are written in — the CVE schema's
  `versions[].versionType`.

  Stored explicitly on the channel rather than inferred from the purl type,
  because the two are genuinely independent: `pkg:sid/erlang.org/otp` versions
  in OTP releases while `pkg:sid/gleam.run/gleam` versions in semver, and the
  same `pkg:oci` image may be tagged with either. `nil` on a channel means
  "whatever this purl type usually uses" (see
  `Varsel.Cases.PackageChannel.PurlType.default_version_type/1`).
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      semver: "Semantic versions (1.2.3), the registry default.",
      otp: "Erlang/OTP release or application versions (27.3.4).",
      git: "Commit SHAs — opaque, only equality and containment are meaningful.",
      date: "Calendar dates (YYYY-MM-DD), how services version themselves.",
      other: "Anything else, e.g. image tags that are not versions."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :package_channel_version_type

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :package_channel_version_type
end
