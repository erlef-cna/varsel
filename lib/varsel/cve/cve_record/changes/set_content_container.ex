# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Changes.SetContentContainer do
  @moduledoc """
  Keeps `content_container` in step with `cve_json`.

  The container to show depends on this CNA's org ID, which is runtime
  configuration, so the database cannot derive it in a generated column.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.CVE.OwnContainer

  @impl Change
  def change(changeset, _opts, _context) do
    # A hook, because some actions set cve_json in their own
    # before_action hooks (link_upstream).
    Ash.Changeset.before_action(changeset, &put_content_container/1)
  end

  @impl Change
  def atomic(changeset, _opts, _context) do
    if Ash.Changeset.changing_attribute?(changeset, :cve_json) do
      {:not_atomic, "content_container is derived from cve_json in Elixir"}
    else
      :ok
    end
  end

  defp put_content_container(changeset) do
    if Ash.Changeset.changing_attribute?(changeset, :cve_json) do
      content_container =
        case Ash.Changeset.get_attribute(changeset, :cve_json) do
          %{} = cve_json -> OwnContainer.get(cve_json)
          _missing -> nil
        end

      Ash.Changeset.force_change_attribute(changeset, :content_container, content_container)
    else
      changeset
    end
  end
end
