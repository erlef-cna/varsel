# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.ReportToGitHub do
  @moduledoc """
  Reports the case to a repository's maintainers as a private vulnerability
  report on GitHub, before the case's `:report_to_github` update, and records
  the advisory GitHub opened for it as the case's
  `Varsel.Cases.GitHubAdvisoryLink`.

  The report carries the actor's own GitHub token, what the case states
  (`Varsel.Cases.GitHubAdvisory.Export`) and the description written for the
  maintainers. GitHub takes no private report from a person who administers
  the repository. So the case first reads from GitHub whether the actor
  administers it (`Varsel.GitHub.Repositories`). An administrator opens a
  draft advisory in their name, which carries the CVE ID as well. Which of
  the two happened is the case's `github_report` metadata.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.Refusal
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Repositories
  alias Varsel.GitHub.UserToken

  @not_reportable "is not a repository you can report to on GitHub"

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

    with {:ok, token} <- UserToken.fetch(context.actor),
         {:ok, case_record} <-
           Cases.get_case(changeset.data.id, Keyword.put(opts, :load, Export.load())),
         {:ok, admin?} <- admin?(owner, repo, token),
         {:ok, kind, advisory} <-
           send_report(admin?, owner, repo, case_record, description, token) do
      changeset
      |> Changeset.put_context(:github_advisory, advisory)
      |> Changeset.put_context(:github_report, kind)
    else
      {:error, :no_github_identity = reason} ->
        Changeset.add_error(changeset, field: :repo, message: UserToken.message(reason))

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

  defp admin?(owner, repo, token) do
    case Repositories.admin?(owner, repo, token: token) do
      {:ok, admin?} -> {:ok, admin?}
      answer -> {:error, Refusal.message(answer, @not_reportable)}
    end
  end

  defp send_report(true, owner, repo, case_record, description, token) do
    case Advisories.create(owner, repo, body(case_record, @draft_fields, description), token: token) do
      {:ok, advisory} ->
        {:ok, :draft, advisory}

      answer ->
        {:error, Refusal.message(answer, "is not a repository where you can open an advisory on GitHub")}
    end
  end

  defp send_report(false, owner, repo, case_record, description, token) do
    case Advisories.report(owner, repo, body(case_record, @fields, description), token: token) do
      {:ok, advisory} -> {:ok, :report, advisory}
      answer -> {:error, Refusal.message(answer, @not_reportable)}
    end
  end

  defp body(case_record, fields, description) do
    case_record
    |> Export.body(fields)
    |> Map.fetch!(:body)
    |> Map.put("description", description)
  end
end
