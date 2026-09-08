# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory do
  @moduledoc """
  The identity of a GitHub security advisory, as a case needs it.

  `Varsel.Cases.GitHubAdvisory.Import` reads an advisory into case params.
  `Varsel.Cases.GitHubAdvisory.Export` writes a case as advisory fields.
  `Varsel.Cases.GitHubAdvisory.Diff` compares the two, field by field.
  `Varsel.Cases.GitHubAdvisory.Ranges` reads and writes GitHub's version
  ranges. This module holds what all of them share: which advisory a
  document is, which repository it lives on, and what state it is in.
  """

  alias Varsel.Cases.GitHubAdvisory.State

  @typedoc "An advisory as GitHub's REST API returns it."
  @type t :: %{String.t() => term()}

  @type state :: State.t()

  @type summary :: %{
          ghsa_id: String.t() | nil,
          cve_id: String.t() | nil,
          state: state(),
          html_url: String.t() | nil,
          title: String.t() | nil,
          owner: String.t() | nil,
          repo: String.t() | nil,
          collaborators: [String.t()],
          teams: [String.t()]
        }

  @doc "The advisory's identity and standing, without its content."
  @spec summary(t()) :: summary()
  def summary(advisory) when is_map(advisory) do
    {owner, repo} = repository(advisory) || {nil, nil}

    %{
      ghsa_id: advisory["ghsa_id"],
      cve_id: advisory["cve_id"],
      state: state(advisory["state"]),
      html_url: advisory["html_url"],
      title: advisory["summary"],
      owner: owner,
      repo: repo,
      collaborators: for(%{"login" => login} <- List.wrap(advisory["collaborating_users"]), do: login),
      teams: for(%{"slug" => slug} <- List.wrap(advisory["collaborating_teams"]), do: slug)
    }
  end

  @doc "The advisory's state as an atom. A state this code does not know is `:unknown`."
  @spec state(term()) :: state()
  def state(state) when is_binary(state) do
    case State.cast_input(state, []) do
      {:ok, known} -> known
      _unknown -> :unknown
    end
  end

  def state(_state), do: :unknown

  @doc """
  The repository the advisory belongs to. A repository advisory names it in
  its `html_url`. A global database entry names it in `source_code_location`
  when that points at GitHub. nil when neither does.
  """
  @spec repository(t()) :: {String.t(), String.t()} | nil
  def repository(advisory) when is_map(advisory) do
    case segments(advisory["html_url"]) do
      [owner, repo, "security", "advisories", _ghsa_id] -> {owner, repo}
      _global_or_other -> source_repository(segments(advisory["source_code_location"]))
    end
  end

  defp source_repository([owner, repo]), do: {owner, repo}
  defp source_repository(_other), do: nil

  defp segments(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: "github.com", path: path} when is_binary(path) ->
        String.split(path, "/", trim: true)

      _other_host ->
        []
    end
  end

  defp segments(_url), do: []

  @doc "The `https://github.com/<owner>/<repo>` URL of the advisory's repository, or nil."
  @spec repo_url(t()) :: String.t() | nil
  def repo_url(advisory) do
    case repository(advisory) do
      {owner, repo} -> "https://github.com/#{owner}/#{repo}"
      nil -> nil
    end
  end

  @doc "An ISO 8601 timestamp of the advisory as a `DateTime` in whole seconds, or nil."
  @spec time(term()) :: DateTime.t() | nil
  def time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> DateTime.truncate(time, :second)
      {:error, _reason} -> nil
    end
  end

  def time(_value), do: nil
end
