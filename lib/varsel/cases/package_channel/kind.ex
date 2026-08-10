# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel.Kind do
  @moduledoc """
  What a distribution channel *is* — the supertype above the purl type.

  A `:package` is identified by a Package URL (type, namespace, name,
  qualifiers) and versions itself however its ecosystem does. A `:service` has
  no package to download: it runs somewhere, is identified by the `domain` it
  answers on, and can only be versioned by date, so its channels carry no purl
  and force `versionType: "date"`.

  The split exists because the two disagree on every field that matters: a
  service has no purl type, no name, no tag decoration and no derivable
  release history, so modelling it as a purl type (the old `:hosted`) made
  every one of those fields conditionally meaningless.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      package: "A downloadable package, identified by a Package URL.",
      service: "A running service, identified by its domain and versioned by date."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :package_channel_kind

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :package_channel_kind
end
