# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Validations.AdvisoryIsFree do
  @moduledoc """
  Refuses an advisory that a case already holds, named by the action's
  `advisory_url` argument.

  `GitHubAdvisoryLink`'s `unique_ghsa_id` identity refuses it in any case,
  but only once the write reaches the link. That is too late for the two
  surfaces this sits on: a manual request has by then minted a one-time
  token and shown a command, and a form has no error to put on the field
  until it submits.
  """

  use Ash.Resource.Validation

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.GitHub.Advisories

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, context) do
    with url when is_binary(url) <- Changeset.get_argument(changeset, :advisory_url),
         {:ok, %{ghsa_id: ghsa_id}} <- Advisories.parse(url),
         {:ok, [_link | _rest]} <- links(ghsa_id, context) do
      {:error, field: :advisory_url, message: "is already linked to another case"}
    else
      _absent_free_or_unparsed -> :ok
    end
  end

  defp links(ghsa_id, context) do
    Cases.list_github_advisory_links(Keyword.put(Ash.Context.to_opts(context), :query, filter: [ghsa_id: ghsa_id]))
  end
end
