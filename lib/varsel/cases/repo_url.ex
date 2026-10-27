# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.RepoUrl do
  @moduledoc """
  A source repository's forge and `owner/repo` path, parsed once from a
  package's `repo_url` so forge detection and `.git`-suffix stripping live in
  one place rather than wherever a repo URL is read or a forge-specific link
  into it is built.

  `repo_url` is `Varsel.Types.URI`-constrained to an absolute `https://` URL
  with a public host (see `Varsel.Cases.AffectedPackage`), so parsing a
  non-nil value never fails.
  """

  @enforce_keys [:host, :path, :forge]
  defstruct [:host, :path, :forge]

  @type forge :: :github | :gitlab | :bitbucket | :codeberg | :sourcehut | :gitee | :unknown
  @type t :: %__MODULE__{host: String.t(), path: String.t(), forge: forge()}

  # Forges whose commit-URL shape this module knows. Anything else is
  # :unknown rather than a guess at a path shape some other forge might not
  # use.
  @forges %{
    "github.com" => :github,
    "gitlab.com" => :gitlab,
    "bitbucket.org" => :bitbucket,
    "codeberg.org" => :codeberg,
    "git.sr.ht" => :sourcehut,
    "gitee.com" => :gitee
  }

  @doc "Parses an absolute `https://` repo URL into its forge and path."
  @spec parse(String.t()) :: t()
  def parse(repo_url) do
    %URI{host: host, path: path} = URI.new!(repo_url)

    %__MODULE__{
      host: host,
      path: path |> to_string() |> String.trim("/") |> String.trim_trailing(".git"),
      forge: Map.get(@forges, String.downcase(host, :ascii), :unknown)
    }
  end

  @doc """
  The commit URL for `sha` on this repo's forge, or `nil` for a forge whose
  commit-path shape is unknown rather than guessing at one.
  """
  @spec commit_url(t(), String.t()) :: String.t() | nil
  def commit_url(%__MODULE__{forge: forge} = repo, sha) do
    case forge do
      forge when forge in [:github, :codeberg, :sourcehut, :gitee] ->
        "#{web_url(repo)}/commit/#{sha}"

      :gitlab ->
        "#{web_url(repo)}/-/commit/#{sha}"

      :bitbucket ->
        "#{web_url(repo)}/commits/#{sha}"

      :unknown ->
        nil
    end
  end

  @doc "The repository's own page."
  @spec web_url(t()) :: String.t()
  def web_url(%__MODULE__{host: host, path: path}), do: "https://#{host}/#{path}"

  @doc "`owner/repo` for a known forge path, the bare host when there is none."
  @spec label(t()) :: String.t()
  def label(%__MODULE__{path: ""} = repo), do: repo.host
  def label(%__MODULE__{path: path}), do: path
end
