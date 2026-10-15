# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Validations.AnswerNamesRequest do
  @moduledoc """
  Accepts GitHub's answer to a manual request only when it is an advisory of
  the request's repository, and the request's advisory when the request names
  one. GitHub's own refusal, posted back by the command, is stated as such.
  """

  use Ash.Resource.Validation

  alias Ash.Changeset
  alias Varsel.GitHub.Advisories

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    request = changeset.data

    case Changeset.get_argument(changeset, :answer) do
      %{"ghsa_id" => ghsa_id, "html_url" => html_url}
      when is_binary(ghsa_id) and is_binary(html_url) ->
        check(request, ghsa_id, html_url)

      %{"message" => message} when is_binary(message) ->
        refuse("is not an advisory. GitHub answered: #{String.slice(message, 0, 200)}")

      _other ->
        refuse("is not an advisory")
    end
  end

  defp check(request, ghsa_id, html_url) do
    with {:ok, %{ghsa_id: answered}} <- Advisories.parse(ghsa_id),
         {:ok, %{owner: owner, repo: repo, ghsa_id: ^answered}} <- Advisories.parse(html_url) do
      cond do
        not same?(owner, request.owner) or not same?(repo, request.repo) ->
          refuse("is an advisory of #{owner}/#{repo}, not of #{request.owner}/#{request.repo}")

        request.ghsa_id && not same?(answered, request.ghsa_id) ->
          refuse("is #{answered}, not #{request.ghsa_id}")

        true ->
          :ok
      end
    else
      _unparsed -> refuse("is not an advisory of a repository")
    end
  end

  defp same?(a, b) when is_binary(a) and is_binary(b), do: String.downcase(a) == String.downcase(b)

  defp same?(_a, _b), do: false

  defp refuse(message), do: {:error, field: :answer, message: message}
end
