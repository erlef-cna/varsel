# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipant.Actions.EraseHexPerson do
  @moduledoc """
  Clears the name and address hex.pm gave us for someone it has since erased,
  from the participant rows and from their versions.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE
  alias Varsel.CVE.ReportParticipant.Version

  require Ash.Query

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Ash.Context.to_opts(context)
    username = input.arguments.username

    participants =
      CVE.list_report_participants_for_hex_erasure!(username, input.arguments[:email], opts)

    Enum.each(participants, &CVE.erase_report_participant!(&1, opts))

    participants
    |> Enum.map(& &1.id)
    |> Enum.concat(spent_ids(username))
    |> Enum.uniq()
    |> scrub_versions()

    :ok
  end

  # A spent participant survives only in its versions, and only the version
  # that created it carries the handle that finds it.
  defp spent_ids(username) do
    handle = username |> to_string() |> String.downcase()

    Version
    |> Ash.Query.filter(
      fragment("?->>'strategy'", changes) == "hex" and
        fragment("lower(?->>'username')", changes) == ^handle
    )
    |> Ash.Query.select([:version_source_id])
    |> Ash.read!()
    |> Enum.map(& &1.version_source_id)
  end

  defp scrub_versions(ids) do
    Version
    |> Ash.Query.filter(version_source_id in ^ids and not is_nil(fragment("?->>'name'", changes)))
    |> Ash.read!()
    |> Enum.each(&Ash.update!(&1, %{changes: Map.delete(&1.changes, "name")}))
  end
end
