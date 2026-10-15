# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest.Changes.BuildRequest do
  @moduledoc """
  Writes onto a manual request the GitHub request that the automatic action
  would make: the method, the path, and the body that
  `Varsel.Cases.GitHubAdvisory.Export` and
  `Varsel.Cases.Case.Changes.ReportToGitHub.body/3` build for it. The case
  and the link are read as the actor.

  The path goes into a shell command that a person pastes into a terminal.
  So an owner or a repository name that GitHub would not give is refused.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Cases.Case.Changes.ReportToGitHub
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.GitHub.Advisories

  @name ~r/\A[A-Za-z0-9_.-]+\z/

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, &build(&1, Ash.Context.to_opts(context)))
  end

  defp build(%{valid?: false} = changeset, _opts), do: changeset

  defp build(%{action: %{name: :prepare_link}} = changeset, _opts) do
    case Advisories.parse(Changeset.get_argument(changeset, :advisory_url)) do
      {:ok, %{owner: owner, repo: repo, ghsa_id: ghsa_id}} ->
        changeset
        |> Changeset.force_change_attribute(
          :advisory_url,
          Changeset.get_argument(changeset, :advisory_url)
        )
        |> read(owner, repo, ghsa_id, :advisory_url)

      _global_or_invalid ->
        Changeset.add_error(changeset,
          field: :advisory_url,
          message: "is not the URL of a repository's advisory on GitHub"
        )
    end
  end

  defp build(%{action: %{name: :prepare_report}} = changeset, opts) do
    owner = Changeset.get_argument(changeset, :owner)
    repo = Changeset.get_argument(changeset, :repo)
    kind = if Changeset.get_argument(changeset, :draft), do: :draft, else: :report
    description = Changeset.get_argument(changeset, :description)
    case_id = Changeset.get_attribute(changeset, :case_id)

    with :ok <- names(owner, repo, nil, :repo),
         {:ok, case_record} <- Cases.get_case(case_id, Keyword.put(opts, :load, Export.load())) do
      Changeset.force_change_attributes(changeset, %{
        operation: :report,
        method: :post,
        path: report_path(owner, repo, kind),
        body: ReportToGitHub.body(case_record, kind, description),
        owner: owner,
        repo: repo
      })
    else
      {:error, error} -> Changeset.add_error(changeset, error)
    end
  end

  defp build(changeset, opts) do
    with {:ok, link} <-
           Cases.get_github_advisory_link(Changeset.get_argument(changeset, :link_id), opts),
         :ok <- repository(link),
         :ok <- names(link.owner, link.repo, link.ghsa_id, :link_id) do
      changeset
      |> Changeset.force_change_attribute(:case_id, link.case_id)
      |> from_link(link, opts)
    else
      {:error, error} -> Changeset.add_error(changeset, error)
    end
  end

  defp from_link(%{action: %{name: :prepare_refresh}} = changeset, link, _opts) do
    read(changeset, link.owner, link.repo, link.ghsa_id, :link_id)
  end

  defp from_link(%{action: %{name: :prepare_pull}} = changeset, link, _opts) do
    changeset
    |> read(link.owner, link.repo, link.ghsa_id, :link_id)
    |> Changeset.force_change_attribute(:fields, Changeset.get_argument(changeset, :fields))
  end

  defp from_link(%{action: %{name: :prepare_push}} = changeset, link, opts) do
    fields = Changeset.get_argument(changeset, :fields)

    case Cases.get_case(link.case_id, Keyword.put(opts, :load, Export.load())) do
      {:ok, case_record} ->
        Changeset.force_change_attributes(changeset, %{
          operation: :push,
          method: :patch,
          path: advisory_path(link.owner, link.repo, link.ghsa_id),
          body: Export.body(case_record, fields, link.advisory).body,
          fields: fields,
          owner: link.owner,
          repo: link.repo,
          ghsa_id: link.ghsa_id
        })

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end

  defp read(changeset, owner, repo, ghsa_id, field) do
    case names(owner, repo, ghsa_id, field) do
      :ok ->
        Changeset.force_change_attributes(changeset, %{
          operation: :read,
          method: :get,
          path: advisory_path(owner, repo, ghsa_id),
          owner: owner,
          repo: repo,
          ghsa_id: ghsa_id
        })

      {:error, error} ->
        Changeset.add_error(changeset, error)
    end
  end

  defp repository(%{owner: owner, repo: repo}) when is_binary(owner) and is_binary(repo), do: :ok

  defp repository(_global_entry) do
    {:error, field: :link_id, message: "names a global database entry, which belongs to no repository"}
  end

  defp names(owner, repo, ghsa_id, field) do
    if name?(owner) and name?(repo) and ghsa_id?(ghsa_id),
      do: :ok,
      else: {:error, field: field, message: "names no repository GitHub could have"}
  end

  defp name?(name) when name in [".", ".."], do: false
  defp name?(name) when is_binary(name), do: Regex.match?(@name, name)
  defp name?(_name), do: false

  defp ghsa_id?(nil), do: true
  defp ghsa_id?(ghsa_id), do: match?({:ok, %{ghsa_id: ^ghsa_id}}, Advisories.parse(ghsa_id))

  defp advisory_path(owner, repo, ghsa_id), do: "/repos/#{owner}/#{repo}/security-advisories/#{ghsa_id}"

  defp report_path(owner, repo, :draft), do: "/repos/#{owner}/#{repo}/security-advisories"

  defp report_path(owner, repo, :report), do: "/repos/#{owner}/#{repo}/security-advisories/reports"
end
