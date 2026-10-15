# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Changes.RecordAnswer do
  @moduledoc """
  Records GitHub's answer to a manual request the way the automatic action
  records it after its own request, as the person who prepared the request.

  A read links the advisory, or stores it on the link and then pulls the
  request's fields. A push stores the advisory on the link. A report links
  the advisory GitHub opened. The nested writes carry the
  `github_manual_answer?` stamp, which the link's attested actions demand
  next to their actor rule.

  The answer is what the person posted, attested by them. Nothing reads it
  again from GitHub.

  The request's token is revoked in the same transaction, so the recording
  and the revocation stand or fall together. Of two posts racing with the
  same token, one revocation finds the token revoked already and fails.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Error.Changes.InvalidArgument
  alias Ash.Error.Changes.StaleRecord
  alias AshAuthentication.TokenResource
  alias Varsel.Accounts.Token
  alias Varsel.Cases

  @stamp %{private: %{github_manual_answer?: true}}

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.after_action(changeset, fn changeset, request ->
      answer = Changeset.get_argument(changeset, :answer)
      token = Changeset.get_argument(changeset, :token)

      with :ok <- revoke(token, request),
           {:ok, %{user: user}} <- Ash.load(request, :user, Ash.Context.to_opts(context)),
           :ok <- record(request, answer, actor: user, context: @stamp) do
        {:ok, request}
      else
        {:error, %StaleRecord{} = stale} -> {:error, stale}
        {:error, error} -> {:error, refusal(error)}
      end
    end)
  end

  defp revoke(token, request) do
    case TokenResource.revoke(Token, token, store_all_tokens?: true) do
      :ok ->
        :ok

      {:error, _revoked_already} ->
        {:error, StaleRecord.exception(resource: request.__struct__, filter: %{id: request.id})}
    end
  end

  # The request carries no case until its answer makes one. Naming it here is
  # what lets the page that prepared the request find the case it opened.
  defp record(%{operation: :read, advisory_url: url, case_id: nil} = request, answer, opts) when is_binary(url) do
    with {:ok, case_record} <-
           Cases.open_case_from_github_advisory_attested(%{advisory: answer}, opts),
         {:ok, _request} <- Cases.name_github_manual_request_case(request, case_record.id, opts),
         do: :ok
  end

  defp record(%{operation: :read, advisory_url: url} = request, answer, opts) when is_binary(url),
    do: link(request, answer, opts)

  defp record(%{operation: :report} = request, answer, opts), do: link(request, answer, opts)

  defp record(request, answer, opts) do
    with {:ok, link} <- current_link(request, opts),
         {:ok, link} <- Cases.refresh_github_advisory_attested(link, answer, opts) do
      pull(request, link, opts)
    end
  end

  defp link(request, answer, opts) do
    with {:ok, _link} <-
           Cases.link_github_advisory_attested(
             %{case_id: request.case_id, advisory: answer},
             opts
           ),
         do: :ok
  end

  defp current_link(request, opts) do
    case Cases.list_github_advisory_links(Keyword.put(opts, :query, filter: [case_id: request.case_id])) do
      {:ok, [%{ghsa_id: ghsa_id} = link]} when ghsa_id == request.ghsa_id -> {:ok, link}
      {:ok, _none_or_other} -> {:error, "names an advisory the case is no longer linked to"}
      {:error, error} -> {:error, error}
    end
  end

  defp pull(%{operation: :read, fields: [_field | _rest] = fields}, link, opts) do
    with {:ok, _link} <- Cases.pull_github_advisory(link, fields, opts), do: :ok
  end

  defp pull(_request, _link, _opts), do: :ok

  defp refusal(message) when is_binary(message), do: invalid(message)

  defp refusal(error) do
    reasons =
      error
      |> Ash.Error.to_error_class()
      |> Map.get(:errors, [])
      |> Enum.map_join("; ", &Exception.message/1)

    invalid("could not be recorded: " <> reasons)
  end

  defp invalid(message), do: InvalidArgument.exception(field: :answer, message: message)
end
