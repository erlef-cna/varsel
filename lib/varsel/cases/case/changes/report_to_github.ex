# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.ReportToGitHub do
  @moduledoc """
  Reports the case to a repository's maintainers as a private vulnerability
  report on GitHub, before the case's `:report_to_github` update, and records
  the advisory GitHub opened for it as the case's
  `Varsel.Cases.GitHubAdvisoryLink`.

  The report carries the credential `Varsel.GitHub.Credentials` gives the
  actor for the repository, what the case states
  (`Varsel.Cases.GitHubAdvisory.Export`) and the description written for the
  maintainers. GitHub takes no private report from a person who administers
  the repository. So with the actor's own token the case first reads from
  GitHub whether the actor administers it (`Varsel.GitHub.Repositories`). An
  administrator opens a draft advisory in their name, which carries the CVE
  ID as well. With the installation token the App opens that draft directly:
  it acts inside its own installation, and GitHub takes no private report
  from it. Which of the two happened is the case's `github_report` metadata.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.Refusal
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials
  alias Varsel.GitHub.Repositories

  @not_reportable "is not a repository you can report to on GitHub"
  @not_draftable "is not a repository where you can open an advisory on GitHub"

  @fields [:title, :cvss_v4, :weaknesses, :credits, :affected]
  @draft_fields [:cve_id | @fields]

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    changeset
    |> Changeset.before_transaction(&report(&1, context))
    |> Changeset.before_action(&record/1)
    |> Changeset.after_action(fn changeset, case_record ->
      {:ok, Ash.Resource.put_metadata(case_record, :github_report, changeset.context[:github_report])}
    end)
  end

  defp report(changeset, context) do
    owner = Changeset.get_argument(changeset, :owner)
    repo = Changeset.get_argument(changeset, :repo)
    description = Changeset.get_argument(changeset, :description)

    opts = Ash.Context.to_opts(context)

    with {:ok, case_record} <-
           Cases.get_case(changeset.data.id, Keyword.put(opts, :load, Export.load())),
         {:ok, kind, advisory} <-
           send_report(context.actor, owner, repo, case_record, description) do
      changeset
      |> Changeset.put_context(:github_advisory, advisory)
      |> Changeset.put_context(:github_report, kind)
    else
      {:error, message} when is_binary(message) ->
        Changeset.add_error(changeset, field: :repo, message: message)

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end

  defp record(%{valid?: false} = changeset), do: changeset

  defp record(changeset) do
    Changeset.manage_relationship(
      changeset,
      :github_advisory_link,
      %{advisory: changeset.context[:github_advisory]},
      type: :create,
      on_no_match: {:create, :record}
    )
  end

  defp send_report(actor, owner, repo, case_record, description) do
    actor
    |> Credentials.run(owner, repo, &submit(&1, owner, repo, case_record, description), answer: &elem(&1, 1))
    |> case do
      {_kind, {step, {:ok, advisory}}} -> {:ok, step, advisory}
      {:no_credential, reason} -> {:error, Credentials.message(reason)}
      {_kind, {:draft, answer}} -> {:error, Refusal.message(answer, @not_draftable)}
      {_kind, {_step, answer}} -> {:error, Refusal.message(answer, @not_reportable)}
    end
  end

  defp submit(%{kind: :installation, token: token}, owner, repo, case_record, description) do
    {:draft, Advisories.create(owner, repo, body(case_record, :draft, description), token: token)}
  end

  defp submit(%{kind: :user, token: token}, owner, repo, case_record, description) do
    case Repositories.admin?(owner, repo, token: token) do
      {:ok, true} ->
        {:draft, Advisories.create(owner, repo, body(case_record, :draft, description), token: token)}

      {:ok, false} ->
        {:report, Advisories.report(owner, repo, body(case_record, :report, description), token: token)}

      answer ->
        {:admin, answer}
    end
  end

  @doc """
  The request body of a draft advisory or a private report of the case,
  loaded as `Varsel.Cases.GitHubAdvisory.Export.load/0` says. A draft
  carries the CVE ID as well.
  """
  @spec body(Varsel.Cases.Case.t(), :draft | :report, String.t()) :: map()
  def body(case_record, kind, description) do
    case_record
    |> Export.body(if(kind == :draft, do: @draft_fields, else: @fields))
    |> Map.fetch!(:body)
    |> Map.put("description", description)
  end
end
