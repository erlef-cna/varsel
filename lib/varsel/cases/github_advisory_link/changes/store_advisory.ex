# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Changes.StoreAdvisory do
  @moduledoc """
  Writes an advisory onto the link: its identity and standing as attributes,
  the whole document as the stored copy, and the time of reading.

  The advisory comes from `FetchAdvisory` through the changeset context, or
  as the `advisory` argument of an action given one directly.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases.GitHubAdvisory

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Changeset.before_action(changeset, &store/1)
  end

  defp store(%{valid?: false} = changeset), do: changeset

  defp store(changeset) do
    advisory = changeset.context[:github_advisory] || Changeset.get_argument(changeset, :advisory)

    case GitHubAdvisory.summary(advisory) do
      %{ghsa_id: ghsa_id, html_url: html_url} = summary
      when is_binary(ghsa_id) and is_binary(html_url) ->
        Changeset.force_change_attributes(changeset, %{
          ghsa_id: ghsa_id,
          owner: summary.owner,
          repo: summary.repo,
          html_url: html_url,
          state: summary.state,
          title: summary.title,
          cve_id: summary.cve_id,
          advisory: advisory,
          fetched_at: DateTime.utc_now(:second)
        })

      _incomplete ->
        Changeset.add_error(changeset,
          field: :advisory_url,
          message: "answered without a GHSA id"
        )
    end
  end
end
