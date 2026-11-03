# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.LinkUpstreamCve do
  @moduledoc """
  Links the case to an upstream CVE ID through `Varsel.CVE.CveRecord`'s
  `:link_upstream`.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.CVE

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, &link(&1, context))
  end

  defp link(changeset, context) do
    cve_id = Changeset.get_argument(changeset, :cve_id)

    case CVE.link_upstream_cve_record(cve_id, Ash.Context.to_opts(context)) do
      {:ok, record} ->
        Changeset.force_change_attributes(changeset,
          cve_record_id: record.id,
          cve_assigned_at: DateTime.utc_now()
        )

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end
end
